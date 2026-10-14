from bcc import BPF
import time
import socket
import struct
import json
import os
import subprocess
import threading
import queue
from collections import defaultdict, deque
import torch
import joblib
import numpy as np
from GRU_ML_model import GRUDDoSClassifier
import ban_events
import l7_ingest

# Limit PyTorch internal thread pool to 1 to prevent GIL contention
# between PyTorch's intra-op parallelism and our Python threads.
torch.set_num_threads(1)

INTERFACE = "veth_server"
BPF_SOURCE_FILE = "xdp_ddos_filter.c"
NGINX_LOG_FILE = "/var/log/nginx/ddos_ml_access.log"
NGINX_ERROR_LOG = "/var/log/nginx/error.log"
# Phase P1 L7 ingestion (docs/L7_GRU_DESIGN.md). Shadow mode only: observe the
# extended Nginx request log over a Unix-domain datagram socket and keep per-(IP,
# User-Agent) request windows, but never ban. OFF unless L7_SHADOW=1, so the live
# detection paths are byte-for-byte unchanged by default.
L7_SHADOW = os.environ.get("L7_SHADOW", "0") == "1"
L7_SOCKET_PATH = os.environ.get("L7_SOCKET_PATH", l7_ingest.DEFAULT_SOCKET_PATH)
L7_SHADOW_REPORT_INTERVAL = 5.0
# GRU inference is driven by the Tier-1 (testbed-native) model. Its feature set,
# sequence length and layer sizes are read from the training config so inference
# can never silently drift from training. The 8 per-FLOW forward features (and
# their exact order) are defined once by the trainer (train_testbed_gru.py) and
# the capture tool (capture_testbed_dataset.py); here we only consume them:
#   [0] Init_Win_bytes_forward       — XDP: init_win (first fwd pkt TCP window)
#   [1] Fwd IAT Total (µs)           — XDP: last_seen - first_seen
#   [2] Fwd Header Length (bytes)    — XDP: sum of L4 header bytes
#   [3] Fwd IAT Max (µs)             — XDP: iat_max_ns
#   [4] Fwd Packet Length Max        — XDP: fwd_pkt_len_max (L4 payload)
#   [5] Fwd IAT Mean (µs)            — computed: IAT total / (pkts - 1)
#   [6] Fwd Packets/s                — computed: pkts / duration_s
#   [7] Total Length of Fwd Packets  — XDP: fwd_payload_bytes
GRU_CONFIG_PATH = "training_results/feature_config_testbed.json"
with open(GRU_CONFIG_PATH) as _f:
    _gru_cfg = json.load(_f)
GRU_FEATURES = _gru_cfg["features"]
MODEL_PATH = _gru_cfg["model"]
SCALER_PATH = _gru_cfg["scaler"]
SEQUENCE_LENGTH = int(_gru_cfg["seq_length"])
INPUT_SIZE = int(_gru_cfg["input_size"])
HIDDEN_SIZE = int(_gru_cfg["hidden_size"])
NUM_LAYERS = int(_gru_cfg["num_layers"])

PREDICTION_THRESHOLD = 0.95
GRU_CONSECUTIVE_THRESH = 3
# F-45 fix: hard cap on flow_map entries visited per poll in the GRU feed. A TCP flood
# (e.g. ACK with incrementing source ports) fills the 262k-entry LRU flow_map; iterating and
# scaling all of it stalled the telemetry loop ~10 s and delayed the L4 bans. Legit traffic has
# only tens of active flows per poll, so this never affects it.
MAX_GRU_FLOWS_PER_POLL = 2000

# Test-only isolation switch (T1d/Option B). When GRU_ONLY=1, every NON-GRU ban
# path (L4 SYN/volumetric/slow-conn, aggregate SYN cookies, L7 rate heuristic,
# R.U.D.Y. log detector) is disabled so the GRU engine can be validated end-to-
# end on its own. Default off → production behaviour is unchanged.
GRU_ONLY = os.environ.get("GRU_ONLY", "0") == "1"
L4_POLL_INTERVAL = 1.0
SYN_FLOOD_THRESHOLD = 200
UDP_FLOOD_THRESHOLD = 5000
RUDY_TIMEOUT_THRESHOLD = 3     # Ban after 3 body-read timeouts in the window
RUDY_WINDOW = 60.0             # Sliding window for counting timeouts (seconds)

# L4 slow-connection abuse (Slowloris/R.U.D.Y.) — drift-free detection sourced
# from the kernel socket table (ss), NOT a hand-rolled XDP gauge. An IP is
# flagged only when it holds many concurrent ESTABLISHED connections AND sends
# near-zero data this interval AND does so for several consecutive intervals.
SLOWCONN_CONN_THRESHOLD = 8    # Concurrent ESTABLISHED conns from one IP
SLOWCONN_IDLE_BYTES = 250      # Per-interval ingress bytes below which it's "idle"
SLOWCONN_CONSECUTIVE = 3       # Sustained intervals before banning (FP guard)
PUBLIC_PORTS = (":80", ":443") # nginx public listeners (local port in ss output)

# L4 low-and-slow SYN (half-open / SYN-without-completion). A distributed SYN
# attack kept UNDER the per-IP (SYN_FLOOD_THRESHOLD) and global (GLOBAL_SYN_
# THRESHOLD) rate limits still exhausts the SYN backlog. Its defining trait: the
# source sends SYNs but NEVER completes a handshake (never shows an ESTABLISHED
# connection). A real client — even a lossy one — establishes connections
# constantly, so we ban only a source that SYNs while establishing *nothing*.
LOWSYN_SYN_MIN = 3             # Min SYNs/interval to consider (legit reconnect is 1-2)
LOWSYN_ESTABLISH_GRACE = 15.0  # An IP that completed a handshake within this window
                               # is a real client, exempt (its SYNs are reconnects)
LOWSYN_CONSECUTIVE = 4         # Sustained suspect intervals before banning (FP guard)

# Auto-unblock IPs after TTL expires (seconds)
BAN_TTL_SECONDS = 300

# Aggregate SYN rate threshold for spoofed-IP flood detection
GLOBAL_SYN_THRESHOLD = 5000

# Load-aware GRU suppression. While a volumetric flood is active, legit TCP flows
# stall/retransmit and start to resemble low-and-slow L7 attacks to the GRU — so
# an attacker could weaponize a flood into GRU-banning legit clients. During a
# flood the L4 engine already owns the threat, so we PAUSE GRU bans for a short
# cooldown and resume once it subsides. Slowloris/R.U.D.Y. persist far longer than
# a flood (which L4 kills in ~1s), so the GRU still catches them afterwards.
GLOBAL_PPS_THRESHOLD = 50000   # aggregate fwd pkts/interval ⇒ "under volumetric flood"
VOLUMETRIC_COOLDOWN = 15.0     # keep GRU paused after flood activity; must outlast
                               # the client request timeout (~10 s) so legit flows
                               # that stalled *through* the flood die and get LRU-
                               # evicted before the GRU resumes — otherwise their
                               # cumulative (flood-contaminated) features linger and
                               # trigger a post-flood false positive.

# Early detection heuristic thresholds (triggers before GRU's 15-request minimum)
HEURISTIC_WINDOW = 10.0        # Sliding window in seconds
HEURISTIC_MAX_RPS = 50         # Max requests per second before blocking
HEURISTIC_ERROR_RATIO = 0.8    # Block if >80% of requests return 4xx/5xx
HEURISTIC_MIN_REQUESTS = 5     # Minimum requests in window before evaluating

# Eviction timeout for idle client tracking data (seconds)
CLIENT_IDLE_TIMEOUT = 60.0

# Machine-readable ban / unban / suppression events (see ban_events.py). The test
# harness points BAN_EVENTS at its per-run results directory; "" disables the log.
EVENTS = ban_events.EventLog(os.environ.get("BAN_EVENTS", ban_events.DEFAULT_PATH))

print(f"[*] Compiling and loading eBPF code from file: {BPF_SOURCE_FILE}...")
bpf = BPF(src_file=BPF_SOURCE_FILE)
bpf_function = bpf.load_func("xdp_ddos_mitigation", BPF.XDP)
bpf.attach_xdp(INTERFACE, bpf_function, 0)
print(f"[+] Successfully attached XDP program to interface {INTERFACE}.")

blacklist_map = bpf.get_table("blacklist_map")
telemetry_map = bpf.get_table("telemetry_map")
flow_map = bpf.get_table("flow_map")   # per-flow 5-tuple fwd features (drives GRU)

print(f"[*] Loading data scaler ({SCALER_PATH})...")
scaler = joblib.load(SCALER_PATH)
assert scaler.n_features_in_ == INPUT_SIZE, (
    f"Scaler expects {scaler.n_features_in_} features but INPUT_SIZE is {INPUT_SIZE}. "
    f"Ensure the features in {GRU_CONFIG_PATH} match what control_plane extracts."
)

print(f"[*] Loading trained GRU model ({MODEL_PATH}, input_size={INPUT_SIZE})...")
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
gru_model = GRUDDoSClassifier(input_size=INPUT_SIZE, hidden_size=HIDDEN_SIZE, num_layers=NUM_LAYERS)
gru_model.load_state_dict(torch.load(MODEL_PATH, map_location=device))
gru_model.to(device)
gru_model.eval()

# Pre-allocate a reusable tensor buffer for inference instead of
# creating a new torch.tensor() on every evaluation.
_inference_buffer_np = np.zeros((1, SEQUENCE_LENGTH, INPUT_SIZE), dtype=np.float32)
_inference_tensor = torch.zeros(1, SEQUENCE_LENGTH, INPUT_SIZE,
                                dtype=torch.float32, device=device)

# GRU sequence tracking, keyed by Source IP. Each step is the 8-feature vector of
# ONE active flow snapshot (per-flow, from flow_map), appended in poll order —
# exactly how the Tier-1 training sequences were built (within a Source IP).
client_sequences = defaultdict(lambda: deque(maxlen=SEQUENCE_LENGTH))
banned_ips = set()
banned_ips_lock = threading.Lock()
stop_event = threading.Event()
# GRU consecutive violations tracker
gru_violation_counts = defaultdict(int)

# Protects the cross-thread per-IP dicts: client_sequences, gru_violation_counts,
# request_tracker, client_last_seen. The telemetry monitor thread and the main
# Nginx-log loop both mutate these, so every access must hold this lock.
# Rule: NEVER hold this lock across ban_ip()/kill_zombie_connections()/subprocess/
# BPF calls — that keeps state_lock and banned_ips_lock from ever nesting.
state_lock = threading.Lock()

# Userspace snapshot of cumulative XDP counters, used to compute per-interval
# deltas by subtraction (read-and-swap). Touched ONLY by the telemetry thread
# (monitor loop + evict_idle_clients + drain_inference_results, which is now a
# single consumer running in that thread), so it needs no lock.
prev_telemetry = {}   # {ip_str: (cum_pkts, cum_syn, cum_bytes)}

# Last fwd_packets count seen per FLOW (5-tuple). We feed the GRU a new sequence
# step only when a flow actually advanced this interval — the exact "active flow"
# unit the training capture emitted (stale flows are not re-emitted). This keeps
# inference faithful to training and bounds how fast sequences fill. Touched ONLY
# by the telemetry thread (monitor loop + evict + drain), so it needs no lock.
prev_flow_pk = {}     # {(src_ip, src_port, dst_port, proto): fwd_packets}

# Consecutive intervals an IP has looked like slow-connection abuse (many held
# connections + near-idle data). Telemetry-thread-only, like prev_telemetry.
slowconn_counts = defaultdict(int)

# Low-and-slow SYN tracking (telemetry-thread-only). lowsyn_counts: consecutive
# suspect intervals (SYNs but no established connection); last_established_seen:
# last wall-time an IP showed >=1 ESTABLISHED connection (completed handshake).
lowsyn_counts = defaultdict(int)
last_established_seen = {}

# Track ban timestamps for TTL-based expiry
ban_timestamps = {}

# Track per-IP request metadata for rate/error heuristic (from Nginx logs)
request_tracker = defaultdict(deque)

# Alongside existing request_tracker
rudy_tracker = defaultdict(deque)  # {ip: deque of (timestamp,)]}

# Track whether SYN cookies have been activated
syn_cookies_enabled = False

# Wall-time until which GRU bans are paused because a volumetric flood is active
# (see GLOBAL_PPS_THRESHOLD / VOLUMETRIC_COOLDOWN). Set in the telemetry monitor
# and read in drain_inference_results — both run in the telemetry thread, so no
# lock is needed.
volumetric_active_until = 0.0

# Track last-seen timestamp per client for idle eviction
client_last_seen = {}

# Queue for offloading ML inference to a dedicated thread
inference_queue = queue.Queue()
inference_result_queue = queue.Queue()


def ip_to_network_bytes(ip_str):
    return struct.unpack("=I", socket.inet_aton(ip_str))[0]

def network_bytes_to_ip(ip_int):
    return socket.inet_ntoa(struct.pack("=I", ip_int))

def flow_features(ff):
    """Build the 8 forward features (in training order) from a flow_feat record.

    MUST stay byte-for-byte identical to capture_testbed_dataset.py so that
    inference == training (no domain gap). Durations are nanoseconds in the map
    and converted to microseconds here, matching the capture tool.
    """
    dur_ns = ff.last_seen_ns - ff.first_seen_ns
    pk = ff.fwd_packets
    dur_us = dur_ns / 1000.0
    return [
        float(ff.init_win),                                   # Init_Win_bytes_forward
        dur_us,                                               # Fwd IAT Total (µs)
        float(ff.fwd_hdr_bytes),                              # Fwd Header Length
        ff.iat_max_ns / 1000.0,                               # Fwd IAT Max (µs)
        float(ff.fwd_pkt_len_max),                            # Fwd Packet Length Max
        (dur_us / (pk - 1)) if pk > 1 else 0.0,               # Fwd IAT Mean (µs)
        (pk / (dur_ns / 1e9)) if dur_ns > 0 else 0.0,         # Fwd Packets/s
        float(ff.fwd_payload_bytes),                          # Total Length of Fwd Packets
    ]

def block_ip_in_xdp(ip_str):
    ip_int = ip_to_network_bytes(ip_str)
    blacklist_map[blacklist_map.Key(ip_int)] = blacklist_map.Leaf(0)
    print(f"[XDP] BLOCKED IP: {ip_str}. Rule is active on hardware.")


def ban_ip(ip_str, reason="unknown", engine="unknown", **detail):
    """Block IP in XDP and record ban timestamp for TTL-based expiry.

    Centralizes the ban logic so every code path (GRU, heuristic, L4)
    consistently updates both the XDP blacklist and the internal tracking sets.
    `engine` (one of ban_events.ENGINES) and `detail` (the measured value, its
    threshold, ...) go only to the ban-event log; the [BAN] console line is
    unchanged because the test harness parses it.
    """
    backend = os.environ.get("MITIGATION_BACKEND", "xdp")
    enforced = True
    if backend == "iptables":
        try:
            subprocess.run(["ip", "netns", "exec", "server_ns", "iptables", "-A", "INPUT", "-s", ip_str, "-j", "DROP"], check=True)
            print(f"[IPTABLES] BLOCKED IP: {ip_str}. Rule is active on software firewall.")
        except Exception as e:
            enforced = False
            print(f"[-] Failed to block {ip_str} via iptables: {e}")
    else:
        block_ip_in_xdp(ip_str)
        
    with banned_ips_lock:
        banned_ips.add(ip_str)
        ban_timestamps[ip_str] = time.time()
    print(f"[BAN] {ip_str} banned for {BAN_TTL_SECONDS}s. Reason: {reason}")
    EVENTS.emit("ban", ip=ip_str, engine=engine, reason=reason, backend=backend,
                enforced=enforced, ttl_s=BAN_TTL_SECONDS, **detail)


def unblock_expired_bans():
    """Remove expired bans from XDP blacklist and internal tracking sets.

    Called periodically from the L4 telemetry monitor thread.
    """
    now = time.time()
    unbanned = []   # (ip, backend, ban age) — events are written after the lock is released
    with banned_ips_lock:
        expired = [ip for ip, ts in ban_timestamps.items()
                   if now - ts > BAN_TTL_SECONDS]
        for ip_str in expired:
            backend = os.environ.get("MITIGATION_BACKEND", "xdp")
            if backend == "iptables":
                try:
                    subprocess.run(["ip", "netns", "exec", "server_ns", "iptables", "-D", "INPUT", "-s", ip_str, "-j", "DROP"], check=False)
                    print(f"[TTL] Unblocked IP: {ip_str} (iptables ban expired after {BAN_TTL_SECONDS}s)")
                except Exception:
                    pass
            else:
                try:
                    ip_int = ip_to_network_bytes(ip_str)
                    del blacklist_map[blacklist_map.Key(ip_int)]
                    print(f"[TTL] Unblocked IP: {ip_str} (ban expired after {BAN_TTL_SECONDS}s)")
                except KeyError:
                    pass
            unbanned.append((ip_str, backend, now - ban_timestamps[ip_str]))
            banned_ips.discard(ip_str)
            del ban_timestamps[ip_str]
    for ip_str, backend, age in unbanned:
        EVENTS.emit("unban", ip=ip_str, backend=backend, age_s=round(age, 3))


def evict_idle_clients():
    """Remove tracking data for clients that have been idle too long.

    Without this, every unique IP that sends at least one request accumulates
    a deque entry in client_sequences and request_tracker forever.

    Called periodically from the L4 telemetry monitor thread.
    """
    now = time.time()
    # Snapshot + pop under state_lock so a concurrent append/pop from the main
    # loop can't trigger "dictionary changed size during iteration".
    with state_lock:
        stale_ips = [ip for ip, ts in client_last_seen.items()
                     if now - ts > CLIENT_IDLE_TIMEOUT]
        for ip_str in stale_ips:
            client_sequences.pop(ip_str, None)
            request_tracker.pop(ip_str, None)
            gru_violation_counts.pop(ip_str, None)
            del client_last_seen[ip_str]
    # BPF telemetry map + snapshot cleanup. Now that the monitor no longer wipes
    # the whole map every interval, idle eviction is what bounds its growth.
    # Telemetry-thread-only state (prev_telemetry / telemetry_map) → no state_lock.
    for ip_str in stale_ips:
        prev_telemetry.pop(ip_str, None)
        slowconn_counts.pop(ip_str, None)
        lowsyn_counts.pop(ip_str, None)
        last_established_seen.pop(ip_str, None)
        try:
            del telemetry_map[telemetry_map.Key(ip_to_network_bytes(ip_str))]
        except KeyError:
            pass
    if stale_ips:
        # Drop per-flow active-tracking for the evicted IPs (flow_map itself is
        # LRU-bounded in the kernel; this just reclaims the userspace shadow).
        stale_ints = {ip_to_network_bytes(ip) for ip in stale_ips}
        for fid in [f for f in prev_flow_pk if f[0] in stale_ints]:
            prev_flow_pk.pop(fid, None)
        print(f"[GC] Evicted tracking data for {len(stale_ips)} idle client(s).")


def kill_zombie_connections(ip_str):
    try:
        subprocess.run(["ss", "-K", "dst", ip_str], check=True, capture_output=True)
        print(f"[OS] Killed hanging TCP sessions for address {ip_str}.")
    except subprocess.CalledProcessError as e:
        print(f"[-] Error while killing sessions for {ip_str}: {e.stderr.decode().strip()}")
    except FileNotFoundError:
        print("[-] The 'ss' tool is not installed (iproute2 package).")


def get_established_conns_by_ip():
    """Per-source-IP count of ESTABLISHED client connections, read from the
    kernel socket table (authoritative and drift-free, unlike an XDP gauge).

    The daemon runs inside server_ns, so plain `ss` sees the client<->nginx
    sockets. We keep only connections whose LOCAL port is a public listener
    (80/443) and group by the remote peer IP. Returns {ip_str: count}.
    """
    counts = defaultdict(int)
    try:
        res = subprocess.run(["ss", "-tan", "state", "established"],
                             capture_output=True, text=True, timeout=2)
    except (subprocess.SubprocessError, FileNotFoundError):
        return counts
    for line in res.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        # Parse from the right so we're robust to whether ss prints the State
        # column: the last two tokens are always Local and Peer "addr:port".
        local, peer = parts[-2], parts[-1]
        if not local.endswith(PUBLIC_PORTS):
            continue
        peer_ip = peer.rsplit(":", 1)[0].strip("[]")
        counts[peer_ip] += 1
    return counts


def tail_nginx_logs(file_path):
    """Tail a log file, automatically reopening on log rotation (inode change)."""
    while not stop_event.is_set():
        try:
            current_inode = os.stat(file_path).st_ino
            with open(file_path, 'r') as f:
                f.seek(0, os.SEEK_END)
                stale_count = 0
                while not stop_event.is_set():
                    line = f.readline()
                    if not line:
                        time.sleep(0.05)
                        stale_count += 1
                        # Check for log rotation every ~5s (100 × 50ms)
                        if stale_count >= 100:
                            stale_count = 0
                            try:
                                new_inode = os.stat(file_path).st_ino
                                if new_inode != current_inode:
                                    print("[*] Log rotation detected, reopening log file...")
                                    break
                            except FileNotFoundError:
                                break
                        continue
                    stale_count = 0
                    yield line
        except FileNotFoundError:
            print(f"[-] Log file {file_path} not found, retrying in 1s...")
            time.sleep(1)

def tail_nginx_error_logs(file_path):
    """Tail the Nginx error log for client body timeout events.

    R.U.D.Y. attacks cause Nginx to eventually time out waiting for the
    POST body. These timeouts are logged in the error log, not the access
    log. This function detects the pattern and bans repeat offenders.
    """
    import re
    # Pattern matches: "client timed out ... while reading client request body, client: <IP>"
    timeout_pattern = re.compile(
        r'client timed out.*while reading client request body.*client:\s*(\d+\.\d+\.\d+\.\d+)'
    )

    while not stop_event.is_set():
        try:
            current_inode = os.stat(file_path).st_ino
            with open(file_path, 'r') as f:
                f.seek(0, os.SEEK_END)
                stale_count = 0
                while not stop_event.is_set():
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        stale_count += 1
                        if stale_count >= 50:  # Check rotation every ~5s
                            stale_count = 0
                            try:
                                if os.stat(file_path).st_ino != current_inode:
                                    break
                            except FileNotFoundError:
                                break
                        continue
                    stale_count = 0

                    match = timeout_pattern.search(line)
                    if match:
                        client_ip = match.group(1)

                        with banned_ips_lock:
                            if client_ip in banned_ips:
                                continue

                        now = time.time()
                        rudy_tracker[client_ip].append(now)

                        # Evict old entries outside the window
                        while (rudy_tracker[client_ip] and
                               now - rudy_tracker[client_ip][0] > RUDY_WINDOW):
                            rudy_tracker[client_ip].popleft()

                        timeout_count = len(rudy_tracker[client_ip])
                        if timeout_count >= RUDY_TIMEOUT_THRESHOLD and not GRU_ONLY:
                            print(f"\n[RUDY-DETECT] Slow POST attack detected - IP: {client_ip} | "
                                  f"Body timeouts: {timeout_count} in {RUDY_WINDOW}s")
                            ban_ip(client_ip,
                                   reason=f"Heuristic R.U.D.Y. ({timeout_count} body timeouts)",
                                   engine="l7_rudy", value=timeout_count,
                                   threshold=RUDY_TIMEOUT_THRESHOLD)
                            kill_zombie_connections(client_ip)
                            rudy_tracker.pop(client_ip, None)

        except FileNotFoundError:
            print(f"[-] Error log {file_path} not found, retrying in 1s...")
            time.sleep(1)


def l7_shadow_monitor(socket_path):
    """Phase P1 shadow ingestion (docs/L7_GRU_DESIGN.md §8).

    Read the extended Nginx access log from the Unix-domain datagram socket, keep
    per-(IP, User-Agent) request windows, and emit a periodic 'l7_shadow'
    telemetry event with the ingest counters and window stats. It NEVER bans and
    never touches the live detection state (banned_ips, client_sequences, the
    request_tracker rate rule) — it only observes, so the socket transport and the
    windowing can be measured before the GRU is wired to it (P2). The durable file
    access_log remains the ground truth for the P1 drop measurement (§4.3).
    """
    try:
        reader = l7_ingest.SyslogDatagramReader(socket_path)
    except OSError as e:
        print(f"[-] L7 shadow: cannot bind {socket_path}: {e}")
        return
    print(f"[*] L7 shadow ingestion on {socket_path} (SO_RCVBUF={reader.rcvbuf}).")
    counters = l7_ingest.L7Counters()
    store = l7_ingest.L7WindowStore()
    last_report = time.time()
    try:
        for data in reader.messages(stop=stop_event.is_set, timeout=0.5,
                                    yield_timeouts=True):
            if data is not None:
                counters.received += 1
                counters.bytes_total += len(data)
                obj = l7_ingest.parse_l7_line(data)
                if obj is None:
                    counters.parse_errors += 1
                    if l7_ingest.looks_truncated(data):
                        counters.truncated += 1
                else:
                    rec = l7_ingest.normalise(obj)
                    if rec is not None:
                        counters.parsed += 1
                        store.add(rec)
            now = time.time()
            if now - last_report >= L7_SHADOW_REPORT_INTERVAL:
                store.evict(now)
                EVENTS.emit("l7_shadow", **counters.as_dict(), **store.stats())
                last_report = now
    finally:
        reader.close()


def inference_worker():
    """Dedicated inference thread to decouple GRU computation from telemetry polling.

    The telemetry thread extracts features from XDP and submits scaled sequences.
    This thread runs GRU inference (CPU-bound) and posts results back.

    Communication uses two thread-safe queues:
      inference_queue:        telemetry → worker  (client_ip, scaled_sequence)
      inference_result_queue: worker → telemetry  (client_ip, probability)
    """
    while not stop_event.is_set():
        try:
            client_ip, scaled_sequence = inference_queue.get(timeout=0.5)
        except queue.Empty:
            continue

        try:
            # Reuse pre-allocated tensor buffer
            _inference_buffer_np[0] = scaled_sequence
            _inference_tensor.copy_(torch.from_numpy(_inference_buffer_np))

            with torch.no_grad():
                logits = gru_model(_inference_tensor)
                probability = torch.sigmoid(logits).item()

            inference_result_queue.put((client_ip, probability))
        except Exception as e:
            print(f"[-] Inference error for {client_ip}: {e}")
        finally:
            inference_queue.task_done()


def drain_inference_results():
    """Drain all pending results from the inference worker thread.

    SINGLE CONSUMER: called ONLY from the L4 telemetry monitor thread. This is
    what makes the gru_violation_counts read-modify-write below safe from the
    lost-update race (and prevents the same IP being banned twice, which in
    iptables mode used to leave a duplicate DROP rule → ban outliving its TTL).
    """
    while True:
        try:
            client_ip, probability = inference_result_queue.get_nowait()
        except queue.Empty:
            break

        with banned_ips_lock:
            if client_ip in banned_ips:
                continue

        # Counter logic under state_lock; ban/kill done OUTSIDE the lock so we
        # never hold state_lock across a subprocess/BPF call.
        should_ban = False
        hits = 0
        with state_lock:
            if probability > PREDICTION_THRESHOLD:
                gru_violation_counts[client_ip] += 1
                # require GRU_CONSECUTIVE_THRESH detections in a row (FP guard)
                if gru_violation_counts[client_ip] >= GRU_CONSECUTIVE_THRESH:
                    should_ban = True
                    hits = gru_violation_counts[client_ip]
            else:
                gru_violation_counts.pop(client_ip, None)

        if not should_ban:
            continue

        # Load-aware suppression: don't GRU-ban while a volumetric flood is active.
        # Legit flows are stalled/distorted then (false-positive risk), and the L4
        # engine already handles the flood. Reset the counter so a post-flood ban
        # needs fresh consecutive detections, not stale distorted ones.
        if time.time() < volumetric_active_until:
            with state_lock:
                gru_violation_counts.pop(client_ip, None)
            EVENTS.emit("gru_suppressed", ip=client_ip, value=round(probability, 6), hits=hits)
            continue

        print(f"\n[GRU] DETECTED ATTACK — IP: {client_ip} | "
              f"Confidence: {probability * 100:.1f}%")
        ban_ip(client_ip,
               reason=f"GRU classifier ({probability * 100:.1f}% confidence)",
               engine="gru", value=round(probability, 6),
               threshold=PREDICTION_THRESHOLD, hits=hits)
        kill_zombie_connections(client_ip)
        with state_lock:
            client_sequences.pop(client_ip, None)
            request_tracker.pop(client_ip, None)
            client_last_seen.pop(client_ip, None)
            gru_violation_counts.pop(client_ip, None)
        prev_telemetry.pop(client_ip, None)   # telemetry-thread-only
        slowconn_counts.pop(client_ip, None)  # telemetry-thread-only
        _ip_int = ip_to_network_bytes(client_ip)   # drop per-flow tracking
        for fid in [f for f in prev_flow_pk if f[0] == _ip_int]:
            prev_flow_pk.pop(fid, None)

def l3_l4_telemetry_monitor():
    """L3/L4 telemetry monitor — now also drives GRU inference.

    Every L4_POLL_INTERVAL (1s), this thread:
      1. Sweeps expired bans and idle client data
      2. Drains completed inference results
      3. Reads per-IP telemetry from the XDP map
      4. Runs the per-IP SYN flood heuristic
      5. Reads the per-FLOW table and, for each flow that advanced this interval,
         extracts the 8 forward features and appends them to its Source IP's
         rolling sequence
      6. Submits full (len==SEQUENCE_LENGTH) sequences to the inference thread
      7. Detects aggregate SYN floods and enables SYN cookies

    The GRU runs on the SAME per-flow pipeline used to build the Tier-1 training
    set (capture_testbed_dataset.py), so train == inference with no domain gap.
    """
    global syn_cookies_enabled, volumetric_active_until
    print(f"[*] Starting L3/L4 telemetry monitor (Interval: {L4_POLL_INTERVAL}s)")
    # Flow-age gating (audit §4e FP fix): after a volumetric flood clears, only let
    # the GRU score flows that STARTED afterwards. A flow that spanned the
    # suppression window carries flood-contaminated cumulative features (stalled
    # IAT, distorted lengths) and gets false-positived at ~99% the instant the
    # cooldown expires. These two vars are telemetry-thread-local — they persist
    # across the poll loop below and need no lock.
    gru_trust_flows_after_ns = 0   # monotonic-ns baseline; 0 = no flood seen yet, trust all flows
    was_suppressing = False
    while not stop_event.is_set():
        time.sleep(L4_POLL_INTERVAL)

        # Periodic maintenance
        unblock_expired_bans()
        evict_idle_clients()
        drain_inference_results()

        total_global_syn_delta = 0
        total_global_pkt_delta = 0

        # Kernel-authoritative per-IP concurrent connection counts for the
        # drift-free slow-connection heuristic (fetched once per poll).
        established_by_ip = get_established_conns_by_ip()

        # Read-and-swap: the XDP counters are cumulative and are NOT wiped here.
        # We keep a userspace snapshot (prev_telemetry) and compute per-interval
        # DELTAS by subtraction. Deltas drive the rate heuristics (unchanged
        # semantics); cumulative values give true flow duration + live connection
        # counts. Idle keys are reclaimed in evict_idle_clients(), not here, so a
        # packet XDP counts between our read and a delete can no longer be lost.
        for key, per_cpu_values in telemetry_map.items():
            ip_str = network_bytes_to_ip(key.value)

            # Cumulative per-CPU aggregation
            cum_pkts = sum(cpu.packet_count for cpu in per_cpu_values)
            cum_syn = sum(cpu.syn_count for cpu in per_cpu_values)
            cum_bytes = sum(cpu.byte_count for cpu in per_cpu_values)

            # Per-interval deltas vs the previous snapshot. A value below the
            # previous snapshot means the key was evicted and re-created (IP
            # reuse / counter reset) -> treat the cumulative value as the delta.
            prev = prev_telemetry.get(ip_str)
            if prev is None or cum_pkts < prev[0]:
                d_pkts, d_syn, d_bytes = cum_pkts, cum_syn, cum_bytes
            else:
                d_pkts = cum_pkts - prev[0]
                d_syn = cum_syn - prev[1]
                d_bytes = cum_bytes - prev[2]
            prev_telemetry[ip_str] = (cum_pkts, cum_syn, cum_bytes)

            with banned_ips_lock:
                if ip_str in banned_ips:
                    # snapshot already advanced -> deltas stay correct post-unban
                    continue

            total_global_syn_delta += d_syn
            total_global_pkt_delta += d_pkts

            # --- L4 SYN flood heuristic (per-IP, per-interval rate) ---
            if d_syn > SYN_FLOOD_THRESHOLD and not GRU_ONLY:
                print(f"\n[L4-DETECT] SYN FLOOD ATTACK - IP: {ip_str} | "
                      f"Rate: {d_syn} SYN/s")
                ban_ip(ip_str, reason=f"Per-IP SYN flood ({d_syn} SYN/s)",
                       engine="l4_syn", value=d_syn, threshold=SYN_FLOOD_THRESHOLD)
                volumetric_active_until = time.time() + VOLUMETRIC_COOLDOWN
                continue

            # --- L4 UDP / Volumetric flood heuristic (per-IP, per-interval rate) ---
            non_syn_pkts = d_pkts - d_syn
            if non_syn_pkts > UDP_FLOOD_THRESHOLD and not GRU_ONLY:
                print(f"\n[L4-DETECT] VOLUMETRIC PACKET FLOOD ATTACK - IP: {ip_str} | "
                      f"Rate: {non_syn_pkts} pkts/s")
                ban_ip(ip_str, reason=f"Volumetric packet flood ({non_syn_pkts} pkts/s)",
                       engine="l4_volumetric", value=non_syn_pkts, threshold=UDP_FLOOD_THRESHOLD)
                volumetric_active_until = time.time() + VOLUMETRIC_COOLDOWN
                continue

            # --- L4 slow-connection abuse (Slowloris/R.U.D.Y.), drift-free ---
            # Concurrent ESTABLISHED connections come from the kernel socket
            # table (authoritative), combined with a near-idle ingress byte rate
            # this interval and sustained over several intervals. Legit clients
            # fail at least one leg (they don't hoard idle connections), so this
            # cannot false-ban them the way the old cumulative XDP gauge did.
            # Runs regardless of d_pkts: a true Slowloris may send nothing here.
            conns = established_by_ip.get(ip_str, 0)
            if conns >= SLOWCONN_CONN_THRESHOLD and d_bytes < SLOWCONN_IDLE_BYTES and not GRU_ONLY:
                slowconn_counts[ip_str] += 1
                if slowconn_counts[ip_str] >= SLOWCONN_CONSECUTIVE:
                    print(f"\n[L4-DETECT] SLOW CONNECTION ABUSE - IP: {ip_str} | "
                          f"Est. conns: {conns} | Bytes/interval: {d_bytes}")
                    ban_ip(ip_str, reason=f"Slow connection abuse ({conns} conns)",
                           engine="l4_slowconn", value=conns,
                           threshold=SLOWCONN_CONN_THRESHOLD, bytes=d_bytes)
                    kill_zombie_connections(ip_str)
                    slowconn_counts.pop(ip_str, None)
                    continue
            else:
                slowconn_counts.pop(ip_str, None)

            # --- L4 low-and-slow SYN (sub-threshold SYN flood, no handshake) ---
            # An IP that keeps SYN-ing but never completes a handshake (no ESTABLISHED
            # connection) is exhausting the SYN backlog low-and-slow, beneath the per-IP
            # and global SYN rate limits. A real client — even a lossy one — establishes
            # connections, so a recent-handshake grace exempts it; only a source that
            # establishes NOTHING for several consecutive intervals while SYN-ing is banned.
            now_wall = time.time()
            if conns > 0:
                last_established_seen[ip_str] = now_wall
            recently_established = (now_wall - last_established_seen.get(ip_str, 0.0)
                                    <= LOWSYN_ESTABLISH_GRACE)
            if (not recently_established and conns == 0
                    and d_syn >= LOWSYN_SYN_MIN and not GRU_ONLY):
                lowsyn_counts[ip_str] += 1
                if lowsyn_counts[ip_str] >= LOWSYN_CONSECUTIVE:
                    print(f"\n[L4-DETECT] LOW-AND-SLOW SYN - IP: {ip_str} | "
                          f"{d_syn} SYN/s, 0 established, no handshake in "
                          f"{LOWSYN_ESTABLISH_GRACE:.0f}s")
                    ban_ip(ip_str, reason=f"Low-and-slow SYN ({d_syn} SYN/s, no handshake)",
                           engine="l4_lowsyn", value=d_syn, threshold=LOWSYN_SYN_MIN)
                    lowsyn_counts.pop(ip_str, None)
                    continue
            else:
                lowsyn_counts.pop(ip_str, None)

            # Mark liveness (drives idle eviction) -- shared dict, under state_lock.
            if d_pkts > 0:
                with state_lock:
                    client_last_seen[ip_str] = time.time()

        # NOTE: no blanket delete of the telemetry map here any more. Keys are
        # cumulative and are reclaimed only when an IP goes idle (see
        # evict_idle_clients) -- that is what preserves flow duration + counts.

        # --- GRU inference on per-FLOW forward features (Tier-1 pipeline) ---
        # Read the per-flow 5-tuple table the XDP program fills. For every TCP
        # flow that advanced since last poll (an ACTIVE flow — the same unit the
        # training capture emitted), compute the 8 forward features and append
        # them to that Source IP's rolling sequence, then submit full sequences.
        # (TCP only: the Tier-1 training domain is HTTP/L7; UDP/volumetric floods
        # are the L4 threshold engine's job above, not the GRU's.) False-positive
        # safety rests on the model itself — benign flows score ~0 even under heavy
        # packet loss/corruption (validated) — plus the 0.95 threshold and the
        # GRU_CONSECUTIVE_THRESH consecutive-detection requirement.
        # Detect the flood→clear transition and stamp the clean baseline: from this
        # instant the GRU only trusts flows that START afterwards (see loop header).
        # F-45 fix: arm volumetric suppression from THIS poll's aggregate deltas BEFORE the feed,
        # not only from the previous poll's — so a flood that begins mid-poll skips the feed now.
        if (total_global_syn_delta > GLOBAL_SYN_THRESHOLD
                or total_global_pkt_delta > GLOBAL_PPS_THRESHOLD):
            volumetric_active_until = time.time() + VOLUMETRIC_COOLDOWN
        suppressing = time.time() < volumetric_active_until
        if was_suppressing and not suppressing:
            gru_trust_flows_after_ns = time.monotonic_ns()  # same clock as ff.first_seen_ns (bpf_ktime, §6e)
        if suppressing != was_suppressing:   # observed once per poll
            EVENTS.emit("suppress_on" if suppressing else "suppress_off",
                        syn_delta=total_global_syn_delta, pkt_delta=total_global_pkt_delta)
        was_suppressing = suppressing

        if suppressing:
            # Volumetric flood active: legit flows are stalled/distorted. Don't feed
            # the GRU, and PURGE accumulated snapshots so that once the flood passes
            # the per-IP sequences rebuild from clean (short-lived) legit flows.
            # Otherwise flood-era distorted snapshots linger in the 15-deque and the
            # GRU bans legit clients the moment the cooldown expires (observed).
            with state_lock:
                client_sequences.clear()
        else:
            with banned_ips_lock:
                banned_snapshot = set(banned_ips)
            visited = 0
            for fk, ff in flow_map.items():
                visited += 1
                if visited > MAX_GRU_FLOWS_PER_POLL:
                    break   # F-45: bound per-poll work (flood fills flow_map)
                if fk.proto != socket.IPPROTO_TCP:
                    continue
                ip_str = network_bytes_to_ip(fk.src_ip)
                if ip_str in banned_snapshot:
                    continue
                # Flow-age gate: a flow that began on/before the last flood's clear
                # point carries flood-contaminated cumulative features — skip it for
                # GRU scoring (it would false-positive). Fresh post-flood flows are
                # clean; a real attacker reopens new flows that ARE scored, and the
                # L4/L7/SlowConn/RUDY engines still cover these flows regardless.
                if ff.first_seen_ns < gru_trust_flows_after_ns:
                    continue
                pk = ff.fwd_packets
                flow_id = (fk.src_ip, fk.src_port, fk.dst_port, fk.proto)
                if prev_flow_pk.get(flow_id, 0) >= pk:
                    continue                       # stale flow: no new fwd packets
                prev_flow_pk[flow_id] = pk

                feats = flow_features(ff)
                # Append + readiness under state_lock; the heavy work (scaler
                # transform + queue put) is done OUTSIDE the lock.
                with state_lock:
                    client_sequences[ip_str].append(feats)
                    seq_ready = len(client_sequences[ip_str]) == SEQUENCE_LENGTH
                    raw_sequence = (np.array(list(client_sequences[ip_str]))
                                    if seq_ready else None)
                if seq_ready:
                    inference_queue.put((ip_str, scaler.transform(raw_sequence)))

        # (volumetric suppression is now armed BEFORE the feed, above — F-45 fix)

        # Detect spoofed-IP SYN floods via aggregate rate
        if total_global_syn_delta > GLOBAL_SYN_THRESHOLD and not syn_cookies_enabled and not GRU_ONLY:
            try:
                subprocess.run(
                    ["sysctl", "-w", "net.ipv4.tcp_syncookies=1"],
                    check=True, capture_output=True
                )
                print(f"[L4-GLOBAL] Aggregate SYN rate {total_global_syn_delta}/s exceeds "
                      f"threshold. SYN cookies ENABLED.")
                syn_cookies_enabled = True
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                print(f"[-] Failed to enable SYN cookies: {e}")
        elif total_global_syn_delta <= GLOBAL_SYN_THRESHOLD // 2 and syn_cookies_enabled:
            syn_cookies_enabled = False
            print(f"[L4-GLOBAL] Aggregate SYN rate {total_global_syn_delta}/s back to normal. "
                  f"SYN cookies flag reset.")


try:
    print("[*] Starting tri-engine Anti-DDoS integration "
          "(XDP Telemetry + GRU ML + L7 Heuristics)...")
    if GRU_ONLY:
        print("[!] GRU_ONLY=1 — all non-GRU ban paths DISABLED (test isolation mode).")
    EVENTS.emit("start", pid=os.getpid(), backend=os.environ.get("MITIGATION_BACKEND", "xdp"),
                gru_only=GRU_ONLY, interface=INTERFACE, model=MODEL_PATH,
                model_sha256=ban_events.file_sha256(MODEL_PATH),
                scaler_sha256=ban_events.file_sha256(SCALER_PATH),
                xdp_sha256=ban_events.file_sha256(BPF_SOURCE_FILE),
                thresholds={
                    "syn_flood": SYN_FLOOD_THRESHOLD, "volumetric": UDP_FLOOD_THRESHOLD,
                    "slowconn_conns": SLOWCONN_CONN_THRESHOLD,
                    "slowconn_idle_bytes": SLOWCONN_IDLE_BYTES,
                    "slowconn_consecutive": SLOWCONN_CONSECUTIVE,
                    "lowsyn_syn_min": LOWSYN_SYN_MIN, "lowsyn_consecutive": LOWSYN_CONSECUTIVE,
                    "l7_max_rps": HEURISTIC_MAX_RPS, "l7_error_ratio": HEURISTIC_ERROR_RATIO,
                    "rudy_timeouts": RUDY_TIMEOUT_THRESHOLD, "gru_p": PREDICTION_THRESHOLD,
                    "gru_consecutive": GRU_CONSECUTIVE_THRESH,
                    "global_syn": GLOBAL_SYN_THRESHOLD, "global_pps": GLOBAL_PPS_THRESHOLD,
                    "volumetric_cooldown_s": VOLUMETRIC_COOLDOWN, "ban_ttl_s": BAN_TTL_SECONDS,
                    "poll_interval_s": L4_POLL_INTERVAL})

    telemetry_thread = threading.Thread(target=l3_l4_telemetry_monitor, daemon=True)
    telemetry_thread.start()

    # Start dedicated inference worker thread
    inference_thread = threading.Thread(target=inference_worker, daemon=True)
    inference_thread.start()

    print("[+] Inference worker thread started.")
    # Start error log monitor for R.U.D.Y. / slow POST detection
    error_log_thread = threading.Thread(
        target=tail_nginx_error_logs,
        args=(NGINX_ERROR_LOG,),
        daemon=True
    )
    error_log_thread.start()
    print(f"[*] Listening for Nginx error logs (RUDY detection): {NGINX_ERROR_LOG}")
    print("[+] RUDY detection thread started.")

    # Phase P1 L7 shadow ingestion (docs/L7_GRU_DESIGN.md §8). Observe-only; OFF
    # unless L7_SHADOW=1, so the default daemon behaviour is unchanged.
    if L7_SHADOW:
        l7_shadow_thread = threading.Thread(
            target=l7_shadow_monitor, args=(L7_SOCKET_PATH,), daemon=True)
        l7_shadow_thread.start()
        print(f"[+] L7 shadow ingestion thread started (socket {L7_SOCKET_PATH}).")
    
    print(f"[*] Listening for Nginx logs (heuristic engine): {NGINX_LOG_FILE}")

    # The main loop now handles ONLY the L7 heuristic (rate + error ratio).
    # GRU inference has moved to the telemetry monitor thread where it reads
    # CICFlowMeter-aligned features directly from the XDP telemetry map.
    for log_line in tail_nginx_logs(NGINX_LOG_FILE):
        try:
            log_data = json.loads(log_line)
            client_ip = log_data.get("client_ip")

            with banned_ips_lock:
                if client_ip in banned_ips:
                    continue

            # --- L7 Heuristic: rate + error ratio detection ---
            now = time.time()
            status = int(log_data.get("status", 200))
            # 503 is the backend saying it's overloaded, so we don't count that as an attack from the client
            is_error = status >= 400 and status != 503

            # request_tracker is shared with the telemetry thread's eviction, so
            # every read/write happens under state_lock. We only DECIDE here; the
            # ban/kill (subprocess/BPF) runs after the lock is released.
            should_ban = False
            ban_rps = 0.0
            ban_err = 0.0
            with state_lock:
                request_tracker[client_ip].append((now, is_error))

                # Evict entries outside the sliding window
                while (request_tracker[client_ip] and
                       now - request_tracker[client_ip][0][0] > HEURISTIC_WINDOW):
                    request_tracker[client_ip].popleft()

                entries = request_tracker[client_ip]
                if len(entries) >= HEURISTIC_MIN_REQUESTS:
                    window_duration = now - entries[0][0]
                    if window_duration > 0:
                        # Clamp the denominator to >=1s so a small burst in a
                        # tiny elapsed window (e.g. 5 reqs in 50ms) can't explode
                        # into a huge rps and false-ban a bursty legit client (§3).
                        rps = len(entries) / max(window_duration, 1.0)
                        error_count = sum(1 for _, err in entries if err)
                        error_ratio = error_count / len(entries)
                        if rps > HEURISTIC_MAX_RPS or (error_ratio > HEURISTIC_ERROR_RATIO and rps > 10):
                            should_ban = True
                            ban_rps = rps
                            ban_err = error_ratio

            if should_ban and not GRU_ONLY:
                print(f"\n[HEURISTIC] L7 anomaly detected - IP: {client_ip} | "
                      f"RPS: {ban_rps:.1f} | Error ratio: {ban_err:.0%}")
                ban_ip(client_ip,
                       reason=f"Heuristic (RPS={ban_rps:.1f}, errors={ban_err:.0%})",
                       engine="l7_rate", value=round(ban_rps, 3),
                       threshold=HEURISTIC_MAX_RPS, error_ratio=round(ban_err, 4))
                kill_zombie_connections(client_ip)
                with state_lock:
                    client_sequences.pop(client_ip, None)
                    request_tracker.pop(client_ip, None)
                    client_last_seen.pop(client_ip, None)
                continue

        except json.JSONDecodeError:
            continue
        except Exception as e:
            print(f"[-] Loop error: {e}")

except KeyboardInterrupt:
    print("\n[*] Execution interrupted by user. Cleaning up environment...")
finally:
    stop_event.set()
    bpf.remove_xdp(INTERFACE, 0)
    print(f"[+] XDP program detached from {INTERFACE}. Finished.")