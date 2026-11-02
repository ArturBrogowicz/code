from bcc import BPF
import time
import socket
import struct
import json
import os
import subprocess
import threading
import queue
import signal
from collections import defaultdict, deque
import torch
import joblib
import numpy as np
from GRU_ML_model import GRUDDoSClassifier
import ban_events
import l7_arms
import l7_denymap
import l7_enforce
import l7_engine
import l7_ingest
import slow_pc

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
# Phase P2: the shadow engine scores (IP, User-Agent) request windows once per poll,
# in one batch, with the model package in L7_MODEL (unset = features-only), and logs
# would-ban decisions; it never bans. L7_RECORD appends the engine's exact input
# stream (records + poll ticks) to a JSONL file, for deterministic offline replay
# (ml/replay_l7.py).
L7_MODEL = os.environ.get("L7_MODEL", "")
L7_RECORD = os.environ.get("L7_RECORD", "")
L7_POLL_INTERVAL = 1.0
# L7 v2 enforcing arm (docs/L7V2_DESIGN.md 9; l7_enforce.py, l7_denymap.py). OFF unless L7_ENFORCE=1, so by default the
# daemon runs exactly as before. It acts on the L7 engine's would-ban decisions (so it needs L7_SHADOW=1), in its own
# supervised thread: level 1 denies the (IP, UA, sid) key at nginx through L7_ENFORCE_DIR/deny.map and a graceful reload
# of the nginx that runs L7_NGINX_CONF; level 2 XDP-bans a single-key IP (engine l7v2). L7_ALLOWLIST adds
# comma-separated IPv4 addresses or networks (the runner's monitoring identities) to the server's own addresses.
L7_ENFORCE = os.environ.get("L7_ENFORCE", "0") == "1"
L7_ENFORCE_DIR = os.environ.get("L7_ENFORCE_DIR", "/run/l7v2")
L7_NGINX_CONF = os.environ.get("L7_NGINX_CONF", "")
L7_ALLOWLIST = os.environ.get("L7_ALLOWLIST", "")
# The arm's kill switch, read every step: while this file exists it takes no action, and when it appears the deny map
# is emptied (one reload) and the arm's XDP bans are lifted. The default is SLOW_PC_KILL_FILE's, so one file stops both.
L7_KILL_FILE = os.environ.get("L7_KILL_FILE", "/run/l7v2/kill")
# With the arm on, a datagram on the L7 socket can drive a ban, so the socket is bound 0660 with nginx's group instead of
# 0666 (T-042 E06). nginx's workers run as nobody:nogroup here: the installed nginx 1.28.3 was built without --user or
# --group, and nginx.conf (and the runner's copy) sets no `user`. With another `user` directive, name its group here.
L7_SOCKET_GROUP = os.environ.get("L7_SOCKET_GROUP", "nogroup")
# One path for every arm (9.5; l7_arms.py): the arm's detector, any of the view GRU, the HGB, the LR or a rule, and its
# own operating point come from the frozen selection L7_SELECTION, whose sha256 the runner gives in L7_SELECTION_SHA256,
# by the arm's name L7_ARM. L7_MODEL is the shadow's model only: with L7_ENFORCE=1 it must be unset.
L7_SELECTION = os.environ.get("L7_SELECTION", "")
L7_SELECTION_SHA256 = os.environ.get("L7_SELECTION_SHA256", "")
L7_ARM = os.environ.get("L7_ARM", "")
L7_ENFORCE_POLL_INTERVAL = 1.0
if L7_ENFORCE and not (L7_SHADOW and L7_NGINX_CONF and L7_SELECTION and L7_SELECTION_SHA256 and L7_ARM):
    raise SystemExit("[-] L7_ENFORCE=1 needs L7_SHADOW=1 (the arm acts on the L7 engine's decisions), L7_NGINX_CONF "
                     "(the configuration of the nginx it reloads) and L7_SELECTION, L7_SELECTION_SHA256, L7_ARM "
                     "(the arm's detector and its operating point)")
if L7_ENFORCE and L7_MODEL:
    raise SystemExit("[-] L7_ENFORCE=1: the arm's model comes from L7_SELECTION; L7_MODEL must be unset")
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
# The XDP-fed GRU (flow_map snapshots → GRU). OFF by default since the 2026-10-19 audit
# (G-16): across the published ban-event logs it made 0 true bans and 1 false ban (legit
# 10.0.1.6, P1 smoke; counts: results/2026-10-20_audit-derived/events_census.md). XDP_GRU=1
# opts in and runs the feed and the drain as before. GRU_ONLY=1 implies it (that mode exists
# to test this engine alone) unless XDP_GRU is set explicitly.
XDP_GRU = os.environ.get("XDP_GRU", "1" if GRU_ONLY else "0") == "1"
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

# P5c.2 (docs/L7_GRU_DESIGN.md §7.3.3). HEURISTIC_PROFILE=tolerant relaxes ONLY the
# thresholds that realistic benign traffic (60-asset page loads, CGNAT keep-alive pools)
# exceeds: the simulated benign worst case x 1.3, frozen in ml/l7_traffic.THRESHOLDS_TOLERANT
# (a test cross-checks these values). The L3/L4 flood engines and the error-ratio branch are
# never relaxed. Default: unchanged.
HEURISTIC_PROFILE = os.environ.get("HEURISTIC_PROFILE", "default")
TOLERANT_OVERRIDES = {"HEURISTIC_MAX_RPS": 108, "SLOWCONN_CONN_THRESHOLD": 180}
if HEURISTIC_PROFILE == "tolerant":
    HEURISTIC_MAX_RPS = TOLERANT_OVERRIDES["HEURISTIC_MAX_RPS"]
    SLOWCONN_CONN_THRESHOLD = TOLERANT_OVERRIDES["SLOWCONN_CONN_THRESHOLD"]
elif HEURISTIC_PROFILE != "default":
    raise SystemExit(f"[-] unknown HEURISTIC_PROFILE {HEURISTIC_PROFILE!r} (default|tolerant)")

# P4 per-connection slow rule (docs/P4_SLOW_DESIGN.md §6-§7; the rule itself is slow_pc.py). OFF
# unless SLOW_PC=1, so by default the daemon runs exactly as before. SLOW_PC=1 runs it in shadow, in
# its own supervised thread (P4-07): once a second it reads `ss -tinpH` and logs the connections it
# would close and the
# addresses it would ban (slow_pc_close / slow_pc_would_ban events). It enforces (§7: `ss -K` on
# each connection, an XDP ban of the address, engine l4_slowconn_pc) only with SLOW_PC_ENFORCE=1
# as well; the kill file, checked every poll, and GRU_ONLY=1 send it back to shadow.
# SLOW_PC_RECORD appends every poll's input to a gzip file for the offline replay (§6.1). T, F
# and K must be a point of the frozen grid; the defaults are its most conservative point until
# the validation runs choose one.
SLOW_PC = os.environ.get("SLOW_PC", "0") == "1"
SLOW_PC_ENFORCE = os.environ.get("SLOW_PC_ENFORCE", "0") == "1"
SLOW_PC_KILL_FILE = os.environ.get("SLOW_PC_KILL_FILE", "/run/l7v2/kill")
SLOW_PC_RECORD = os.environ.get("SLOW_PC_RECORD", "")
SLOW_PC_T = int(os.environ.get("SLOW_PC_T", "20"))
SLOW_PC_F = int(os.environ.get("SLOW_PC_F", "16"))
SLOW_PC_K = int(os.environ.get("SLOW_PC_K", "6"))
if SLOW_PC and (SLOW_PC_T, SLOW_PC_F, SLOW_PC_K) not in slow_pc.GRID:
    raise SystemExit(f"[-] SLOW_PC_T/F/K = ({SLOW_PC_T}, {SLOW_PC_F}, {SLOW_PC_K}) is not a point "
                     "of the frozen grid (slow_pc.GRID)")
SLOW_PC_REPORT_INTERVAL = 5.0
SLOW_PC_POLL_INTERVAL = 1.0

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

# P4 per-connection slow rule (SLOW_PC=1). The detector and the record file belong to the rule's own
# thread (slow_pc_monitor), which creates them at its first poll. The access-log loop hands it (ip,
# port, UA key, t) of every logged request through the inbox; a full inbox drops the item and counts
# it.
slow_pc_engine = None
slow_pc_inbox = queue.Queue(maxsize=100000)
slow_pc_counts = defaultdict(int)   # inbox_dropped, note_errors: written by the access-log loop
slow_pc_record_fh = None            # the SLOW_PC_RECORD file; False once a write failed
slow_pc_last_report = 0.0

# The L7 v2 enforcing arm (L7_ENFORCE=1), its detector and the L7 socket's group: set by l7_enforce_init() before the
# threads start.
l7_arm = None
l7_detector = None
l7_socket_gid = None

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
    `engine` (one of ban_events.ENGINES, or ban_events.L7V2_ENGINE when the L7 v2
    enforcing arm calls it through its injected `ban`) and `detail` (the measured value, its
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
        ban_timestamps[ip_str] = banned_at = time.time()
    print(f"[BAN] {ip_str} banned for {BAN_TTL_SECONDS}s. Reason: {reason}")
    EVENTS.emit("ban", ip=ip_str, engine=engine, reason=reason, backend=backend,
                enforced=enforced, ttl_s=BAN_TTL_SECONDS, **detail)
    return banned_at


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
    # timeout: the per-connection rule's thread calls this after each of its bans, and a hung
    # `ss -K` must not stall that thread (review T-039 V-08); the address is banned either way.
    try:
        subprocess.run(["ss", "-K", "dst", ip_str], check=True, capture_output=True, timeout=2)
        print(f"[OS] Killed hanging TCP sessions for address {ip_str}.")
    except subprocess.CalledProcessError as e:
        print(f"[-] Error while killing sessions for {ip_str}: {e.stderr.decode().strip()}")
    except subprocess.TimeoutExpired:
        print(f"[-] Killing the sessions of {ip_str} took more than 2 s: given up.")
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


def slow_pc_note(log_data):
    """The access-log side of the P4 per-connection rule (main thread): hand (ip, port, UA key,
    t) of one logged request to the telemetry thread, for the shared-address guard and, on :443,
    the answered connections. It cannot raise, so the L7 rate rule after it runs as before."""
    try:
        item = slow_pc.l7_item(log_data, time.time())
        if item is not None:
            slow_pc_inbox.put_nowait(item)
    except queue.Full:
        slow_pc_counts["inbox_dropped"] += 1
    except Exception:  # noqa: BLE001 - the L7 rate rule after this call must run as before
        slow_pc_counts["note_errors"] += 1


def slow_pc_read():
    """(text, error) of one `ss -tinpH` read in server_ns; text is None when the call failed.
    Bytes that are not UTF-8 are read as U+FFFD (H-01)."""
    try:
        res = subprocess.run(slow_pc.SS_ARGV, capture_output=True, timeout=2, check=False)
    except (subprocess.SubprocessError, OSError) as e:
        return None, e
    if res.returncode != 0:
        err = res.stderr.decode("utf-8", "replace").strip()[:200]
        return None, f"ss exited {res.returncode}: {err}"
    return res.stdout.decode("utf-8", "replace"), None


def slow_pc_record(now, text, items, banned, enforce):
    """Append this poll's input to SLOW_PC_RECORD as one gzip member, for the offline replay
    (§6.1; slow_pc.read_record). A failed write stops the recording, never the rule."""
    global slow_pc_record_fh
    if not SLOW_PC_RECORD or slow_pc_record_fh is False:
        return
    try:
        if slow_pc_record_fh is None:
            slow_pc_record_fh = open(SLOW_PC_RECORD, "ab")  # noqa: SIM115 - held for the run
        slow_pc_record_fh.write(slow_pc.record_member(now, text, items, banned, enforce))
        slow_pc_record_fh.flush()
    except (OSError, ValueError) as e:
        slow_pc_record_fh = False
        report_daemon_error("slow_pc_record", e, "recording stopped")


def slow_pc_close(conns):
    """Close these connections, (client address, client port, server port) each, every one by
    its own filter, at most slow_pc.CLOSE_BATCH per `ss -K` call (§7.1). An empty list makes no
    call: `ss -K` without a filter would close every socket. Whether each socket went is checked
    at the next poll, which retries the ones still there (P4-06): ss -K skips silently what the
    kernel cannot close, and a connection that ended between the read and the kill is simply
    gone, so the exit status of the call decides nothing. Returns the number of calls that could
    not run at all (ss missing, a timeout)."""
    errors = 0
    for i in range(0, len(conns), slow_pc.CLOSE_BATCH):
        expr = " or ".join(f"( dst {ip} and dport = :{port} and sport = :{sport} )"
                           for ip, port, sport in conns[i:i + slow_pc.CLOSE_BATCH])
        try:
            subprocess.run(["ss", "-K", "-t", "state", "established", expr],
                           capture_output=True, timeout=2, check=False)
        except (subprocess.SubprocessError, OSError):
            errors += 1
    return errors


def slow_pc_act(result, enforce):
    """Carry out one poll's decisions (§7), or in shadow only log them: close each connection,
    then ban each address the aggregate names, through ban_ip (TTL BAN_TTL_SECONDS) and, as every
    engine does after a ban, close the rest of its sockets."""
    for c in result.closes:
        EVENTS.emit("slow_pc_close", enforced=enforce, **c._asdict())
    if enforce and (result.closes or result.retries):
        errors = slow_pc_close([(c.ip, c.port, c.sport) for c in result.closes]
                               + [(ip, port, sport) for (ip, port, _l, sport), _a in result.retries])
        slow_pc_engine.closed([(c.ip, c.port, c.local, c.sport) for c in result.closes])
        for key, attempt in result.retries:
            slow_pc_engine.closed([key], attempt)
        if errors:
            report_daemon_error("slow_pc", f"{errors} ss -K call(s) could not run",
                                "retried at the next poll")
    for (ip, port, local, sport), attempt in result.retries if enforce else ():
        EVENTS.emit("slow_pc_close_retry", ip=ip, port=port, local=local, sport=sport,
                    attempt=attempt, gave_up=False)
    for ip, port, local, sport in result.gave_up:
        EVENTS.emit("slow_pc_close_retry", ip=ip, port=port, local=local, sport=sport,
                    attempt=slow_pc.CLOSE_RETRIES + 1, gave_up=True)
    if result.capped_closes:
        EVENTS.emit("slow_pc_capped", what="close", n=result.capped_closes,
                    cap=slow_pc.MAX_CLOSES_PER_POLL)
    for b in result.bans:
        if not enforce:
            EVENTS.emit("slow_pc_would_ban", ip=b.ip, value=b.closes, threshold=SLOW_PC_K,
                        ua_keys=b.ua_keys)
            continue
        with banned_ips_lock:
            if b.ip in banned_ips:
                continue
        print(f"\n[L4-DETECT] SLOW CONNECTIONS, PER CONNECTION - IP: {b.ip} | "
              f"{b.closes} closed in {slow_pc.BAN_WINDOW_S:g}s | UA keys: {b.ua_keys}")
        ban_ip(b.ip, reason=f"Per-connection slow rule ({b.closes} connections closed in "
                            f"{slow_pc.BAN_WINDOW_S:g} s)",
               engine="l4_slowconn_pc", value=b.closes, threshold=SLOW_PC_K, ua_keys=b.ua_keys)
        kill_zombie_connections(b.ip)
    if result.capped_bans:
        EVENTS.emit("slow_pc_capped", what="ban", n=len(result.capped_bans),
                    cap=slow_pc.MAX_BANS_PER_MIN, ips=result.capped_bans[:50])


def slow_pc_monitor():
    """The P4 per-connection rule's own thread (P4-07), under supervise() like every worker
    thread (H-02): once per SLOW_PC_POLL_INTERVAL it reads `ss -tinpH` and carries out the
    decisions. A slow or stuck `ss` (2 s per call at most, and one call per batch of closes)
    therefore delays this rule only, never the L4 rules, the TTL sweep or the GRU feed of the
    telemetry thread."""
    while not stop_event.is_set():
        time.sleep(SLOW_PC_POLL_INTERVAL)
        slow_pc_poll()


def slow_pc_poll():
    """One poll of the P4 per-connection rule (SLOW_PC=1; docs/P4_SLOW_DESIGN.md §6-§7), in its own
    thread (slow_pc_monitor). A failed `ss` call skips the poll and resets no streak (§6.3). It enforces only with SLOW_PC_ENFORCE=1, without GRU_ONLY and while the kill
    file does not exist. It cannot raise: an error skips this poll only."""
    global slow_pc_engine, slow_pc_last_report
    try:
        now = time.time()
        if slow_pc_engine is None:
            slow_pc_engine = slow_pc.Detector(SLOW_PC_T, SLOW_PC_F, SLOW_PC_K, BAN_TTL_SECONDS)
        items = []
        while True:
            try:
                items.append(slow_pc_inbox.get_nowait())
            except queue.Empty:
                break
        with banned_ips_lock:
            banned = set(banned_ips)
        enforce = SLOW_PC_ENFORCE and not GRU_ONLY and not os.path.exists(SLOW_PC_KILL_FILE)
        text, err = slow_pc_read()
        slow_pc_record(now, text, items, banned, enforce)
        if text is None:
            slow_pc_engine.skip(now, items)
            report_daemon_error("slow_pc", err, "poll skipped, streaks kept")
        else:
            slow_pc_act(slow_pc_engine.poll(now, text, items, banned), enforce)
        if now - slow_pc_last_report >= SLOW_PC_REPORT_INTERVAL:
            EVENTS.emit("slow_pc_poll", mode="enforce" if enforce else "shadow",
                        **slow_pc_engine.take_stats(),
                        inbox_dropped=slow_pc_counts.get("inbox_dropped", 0),
                        note_errors=slow_pc_counts.get("note_errors", 0))
            slow_pc_last_report = now
    except Exception as e:  # noqa: BLE001 - the rest of the telemetry poll must run
        report_daemon_error("slow_pc", e, "poll skipped")


def l7_nginx_reload():
    """The arm's graceful reload of the run's nginx: `nginx -c L7_NGINX_CONF -s reload`. The signaller parses the whole
    configuration, deny map included, before it signals, and exits non-zero without signalling when it does not load
    (src/core/nginx.c:293-330, src/core/ngx_cycle.c:314 of nginx 1.28.3), so the exit status says whether the new map
    can take effect. Returns (ok, detail)."""
    try:
        res = subprocess.run(["nginx", "-c", L7_NGINX_CONF, "-s", "reload"], capture_output=True, timeout=10,
                             check=False)
    except (subprocess.SubprocessError, OSError) as e:
        return False, f"{type(e).__name__}: {e}"
    if res.returncode != 0:
        return False, f"nginx exited {res.returncode}: {res.stderr.decode('utf-8', 'replace').strip()}"
    return True, ""


def l7_lift_bans(bans):
    """The arm's kill switch: lift its XDP bans, (ip, the time ban_ip recorded) each, that are still the bans it made.
    A ban that expired, or that another engine made since, is left alone, and so is every other engine's ban (L3/L4,
    slow_pc, the L7 rate rule). Each lift is an `unban` event with lifted_by "l7_kill". Returns the IPs lifted."""
    backend = os.environ.get("MITIGATION_BACKEND", "xdp")
    now = time.time()
    lifted = []
    with banned_ips_lock:
        for ip_str, banned_at in bans:
            if banned_at is None or ban_timestamps.get(ip_str) != banned_at:
                continue
            if backend == "iptables":
                subprocess.run(["ip", "netns", "exec", "server_ns", "iptables", "-D", "INPUT", "-s", ip_str,
                                "-j", "DROP"], check=False)
            else:
                try:
                    del blacklist_map[blacklist_map.Key(ip_to_network_bytes(ip_str))]
                except KeyError:
                    pass
            banned_ips.discard(ip_str)
            del ban_timestamps[ip_str]
            lifted.append((ip_str, now - banned_at))
    for ip_str, age in lifted:
        EVENTS.emit("unban", ip=ip_str, backend=backend, age_s=round(age, 3), lifted_by="l7_kill")
    return [ip_str for ip_str, _age in lifted]


def l7_killed():
    return os.path.exists(L7_KILL_FILE)


def l7_enforce_stop():
    """At the daemon's stop (the main statement's finally, after XDP is detached): the arm empties the deny map with
    one reload, so no deny outlives the daemon. It cannot raise."""
    try:
        if l7_arm is not None:
            l7_arm.stop(time.time())
    except Exception as e:  # noqa: BLE001 - the stop must finish
        report_daemon_error("l7_enforce", e, "deny map not emptied at stop")


def l7_ip_banned(ip_str):
    with banned_ips_lock:
        return ip_str in banned_ips


def l7_enforce_init():
    """Build the L7 v2 enforcing arm (L7_ENFORCE=1); the main statement calls it before any thread starts. A run
    directory the daemon may not use, a malformed L7_ALLOWLIST, or a detector l7_arms refuses (a placeholder operating
    point, an ablation, an altered artifact, a selection that is not the recorded one) stops the daemon."""
    global l7_arm, l7_detector, l7_socket_gid
    try:
        l7_socket_gid = l7_ingest.group_id(L7_SOCKET_GROUP)
        allow = l7_enforce.allowlist(L7_ALLOWLIST)
        l7_detector = l7_arms.load(L7_SELECTION, L7_SELECTION_SHA256, L7_ARM)
        key_level = getattr(l7_detector, "level", "view") == "rule"       # R* denies (IP, UA) keys: its own map
        l7_denymap.prepare_run_dir(L7_ENFORCE_DIR, key_level=key_level)
    except (OSError, ValueError) as e:                  # l7_arms.DetectorError is a ValueError
        report_daemon_error("l7_enforce", e, "the daemon stops: nothing is enforced")   # why, in the event log
        raise SystemExit(f"[-] L7_ENFORCE=1: {e}") from e
    l7_arm = l7_enforce.Arm(l7_denymap.DenyMap(L7_ENFORCE_DIR, key_level=key_level), reload=l7_nginx_reload, ban=ban_ip,
                            close=kill_zombie_connections, banned=l7_ip_banned, events=EVENTS, lift=l7_lift_bans,
                            killed=l7_killed, allow=allow, clock=time.time)
    l7_arm.start(time.time())
    print(f"[*] L7 v2 enforcing arm: deny map {l7_arm.denies.path}, reloads nginx -c {L7_NGINX_CONF}, "
          f"kill switch {L7_KILL_FILE}.")


def l7_enforce_monitor():
    """The enforcing arm's own thread (L7_ENFORCE=1), under supervise() like every worker thread: one Arm.step per
    L7_ENFORCE_POLL_INTERVAL. A slow reload or ban delays the arm only, never the L7 ingestion or the L4 rules."""
    while not stop_event.is_set():
        time.sleep(L7_ENFORCE_POLL_INTERVAL)
        l7_enforce_poll()


def l7_enforce_poll():
    """One step of the arm. It cannot raise: an error skips this step only."""
    try:
        l7_arm.step(time.time())
    except Exception as e:  # noqa: BLE001 - the next step must run
        report_daemon_error("l7_enforce", e, "step skipped")


# Robustness (review of 2026-10-29, H-01/H-02): an error the daemon survives is reported on
# the console and as a `daemon_error` event, and the failed part is retried after this backoff.
ERROR_BACKOFF_S = 1.0


def report_daemon_error(where, err, action):
    """One console line and one `daemon_error` event (where, error, action) for an error the
    daemon survives. It cannot raise (D-06): it runs in the handlers that keep the daemon
    alive. An exception whose str() fails is named by its type, and a failed write (stdout
    closed or full, a re-entrant write) is dropped."""
    try:
        error = err if isinstance(err, str) else f"{type(err).__name__}: {err}"
    except Exception:  # noqa: BLE001 - str(err) itself raised
        error = f"{type(err).__name__}: <str() failed>"
    try:
        EVENTS.emit("daemon_error", where=where, error=error[:300], action=action)
        print(f"[-] {where}: {error} ({action})")
    except Exception:  # noqa: BLE001, S110 - a failed report must not end the daemon
        pass


def request_stop(_signum, _frame):
    """SIGTERM handler: an intentional stop, like Ctrl-C. The loops see stop_event and end,
    and the main statement's finally detaches XDP, which lifts every ban.

    SIGTERM is ignored from here on (D-02): stop_event.set() holds the Event's non-reentrant
    lock, and a second SIGTERM handled inside it would call set() again and deadlock, so the
    finally would never detach XDP."""
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    stop_event.set()


def supervise(name, target, *args):
    """Body of every worker thread: the liveness supervisor of one thread (H-02).

    target(*args) runs until it returns. If it raises, the error is reported (console and a
    `daemon_error` event) and the target runs again after ERROR_BACKOFF_S, so a detection
    thread can no longer die silently while the daemon runs. A target that returns while the
    daemon still runs (the L7 shadow without its socket) is reported once, not restarted."""
    while not stop_event.is_set():
        try:
            target(*args)
        except Exception as e:  # noqa: BLE001 - a worker must not die silently (H-02)
            report_daemon_error(f"thread:{name}", e, f"restarted in {ERROR_BACKOFF_S:g} s")
            time.sleep(ERROR_BACKOFF_S)
            continue
        if not stop_event.is_set():
            report_daemon_error(f"thread:{name}", "returned", "not restarted")
        return


def tail_nginx_logs(file_path):
    """Tail a log file, automatically reopening on log rotation (inode change).

    Undecodable bytes are read as U+FFFD (H-01): nginx's escape=json writes bytes >= 0x80
    as they are, so one request with a non-UTF-8 header used to raise UnicodeDecodeError
    here and end the daemon. A line with U+FFFD is parsed or skipped like any other."""
    while not stop_event.is_set():
        try:
            current_inode = os.stat(file_path).st_ino
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
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
    Undecodable bytes (a raw request line, for one) are read as U+FFFD, as in
    tail_nginx_logs (H-01).

    Only nginx's own client field is counted and banned (H-26). nginx writes
    `<time> [info] <pid>#<tid>: *<conn> client timed out (110: Connection timed out)
    while reading client request body, client: <addr>, server: <name>, request: "...",
    host: "..."`: its prefix, message and action, then at once the client field, and only
    after it the request line and the Host header, which the client writes
    (ngx_http_log_error, src/http/ngx_http_request.c of nginx 1.28). So the pattern is
    anchored at the start of the line, lines end at LF only, as nginx ends them (a CR in
    a field cannot start a line), and the field ends at the `, server: ` that nginx
    writes next. The old pattern took the last `client:` of the line, which a URI or a
    Host header could name. A field that is not an IPv4 address (the only family the XDP
    ban path takes) is skipped and reported.
    """
    import ipaddress
    import re
    timeout_pattern = re.compile(
        r'[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[[a-z]+\] [0-9]+#[0-9]+: '
        r'(?:\*[0-9]+ )?client timed out(?: \([0-9]+: [^)]*\))? '
        r'while reading client request body, client: (.*?)(?:, server: |$)'
    )

    while not stop_event.is_set():
        try:
            current_inode = os.stat(file_path).st_ino
            with open(file_path, 'r', encoding='utf-8', errors='replace', newline='\n') as f:
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

                    match = timeout_pattern.match(line)
                    if match:
                        client_ip = match.group(1)
                        try:
                            # ASCII digits only, four octets of at most 255, no leading zeros
                            ipaddress.IPv4Address(client_ip)
                        except ValueError:
                            report_daemon_error(
                                "error_log", f"R.U.D.Y. client field {client_ip[:64]!r} is "
                                "not an IPv4 address", "line skipped")
                            continue

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
    """L7 shadow ingestion and scoring (docs/L7_GRU_DESIGN.md §8, phases P1–P2).

    Read the extended Nginx access log from the Unix-domain datagram socket, keep
    per-(IP, User-Agent) request windows, and once per poll score every updated
    window in one batch (l7_engine; features-only without L7_MODEL). Emits:
      * 'l7_shadow'    every 5 s: ingest counters and window stats (P1);
      * 'l7_gru_poll'  every 5 s and at exit: engine aggregate (windows scored,
                       gated, max p, top keys, suppressed polls);
      * 'l7_would_ban' when a key meets the decision policy.
    It NEVER bans and never touches the live detection state (banned_ips is only
    read, to annotate would-ban events). With L7_RECORD set it also appends the
    engine's exact input stream, for deterministic replay (ml/replay_l7.py). With
    L7_ENFORCE=1 it also shows the enforcing arm (l7_arm) the engine, every ingested
    request and every would-ban; the arm acts in its own thread (l7_enforce_monitor).
    """
    try:
        if L7_ENFORCE:
            # 0660 with nginx's group, not 0666: with the arm on a datagram here can drive a ban (T-042 E06)
            reader = l7_ingest.SyslogDatagramReader(socket_path, mode=0o660, group=l7_socket_gid)
        else:
            reader = l7_ingest.SyslogDatagramReader(socket_path)
    except OSError as e:
        print(f"[-] L7 shadow: cannot bind {socket_path}: {e}")
        return
    try:
        if L7_ENFORCE:
            engine = l7_engine.build_engine(scorer=l7_detector)   # the arm's detector, loaded and checked at start
        else:
            engine = l7_engine.build_engine(L7_MODEL or None)
    except (ValueError, OSError) as e:      # l7_scorer.PackageError is a ValueError
        print(f"[-] L7 shadow: model package {L7_MODEL!r} rejected ({e}); features-only.")
        engine = l7_engine.build_engine(None)
    recorder = None
    if L7_RECORD:
        try:
            recorder = l7_engine.EngineRecorder(L7_RECORD)
        except OSError as e:
            print(f"[-] L7 shadow: cannot record to {L7_RECORD}: {e}")
    if L7_ENFORCE:
        l7_arm.attach(engine, refuse="GRU_ONLY=1" if GRU_ONLY else None)
    mode = (f"model {engine.scorer.sha256[:12]}" if engine.scorer else "features-only")
    print(f"[*] L7 shadow ingestion on {socket_path} (SO_RCVBUF={reader.rcvbuf}, {mode}, "
          f"record={'on' if recorder else 'off'}).")
    counters = l7_ingest.L7Counters()
    last_poll = last_report = time.time()
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
                        if recorder:
                            recorder.record(obj, time.time())
                        engine.on_record(rec)
                        if L7_ENFORCE:
                            l7_arm.observe(obj, rec)
            now = time.time()
            if now - last_poll >= L7_POLL_INTERVAL:
                suppressing = now < volumetric_active_until
                with banned_ips_lock:
                    banned = tuple(banned_ips)
                if recorder:
                    recorder.poll(now, suppressing, banned)
                for ev in engine.poll(now, suppressing, banned):
                    if ev.pop("kind") == "l7_would_ban":
                        EVENTS.emit("l7_would_ban", **ev)
                        if L7_ENFORCE:
                            l7_arm.submit(ev)
                last_poll = now
            if now - last_report >= L7_SHADOW_REPORT_INTERVAL:
                # L7 v2's key store counts its truncated keys under the name the ingest counters give truncated
                # datagrams; the duplicate keyword raised TypeError here, which restarted this thread every 5 s
                # and threw the engine's state away. The store's count is reported as store_truncated.
                store = engine.store.stats()
                if "truncated" in store:
                    store["store_truncated"] = store.pop("truncated")
                EVENTS.emit("l7_shadow", **counters.as_dict(), **store)
                EVENTS.emit("l7_gru_poll", **engine.take_summary())
                last_report = now
    finally:
        EVENTS.emit("l7_gru_poll", final=True, **engine.take_summary())
        if recorder:
            recorder.close()
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
    # D-01: set by a failed poll. The snapshots it did not advance (all of them when it failed
    # before the map was read) would let the next poll read the whole outage as one interval.
    rebaseline = False
    while not stop_event.is_set():
        time.sleep(L4_POLL_INTERVAL)

        # H-02: an error in one poll (bcc raises a bare Exception when a BPF map update
        # fails, e.g. a full blacklist_map in ban_ip) is reported, and the next poll runs:
        # it used to end this thread, and with it L4 detection, the TTL sweep and the idle
        # eviction, silently. The sleep above is the backoff, and the poll after a failure
        # only re-takes the snapshots (D-01, `rebaseline`).
        try:
            # Periodic maintenance
            unblock_expired_bans()
            evict_idle_clients()
            if XDP_GRU:
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
                if rebaseline:
                    continue    # D-01: a fresh snapshot only; no rule reads this delta

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

            if rebaseline:
                # D-01: this poll only re-took the snapshots that the failed poll(s) left
                # behind. Read now, their deltas would span the whole outage and ban sources at
                # their normal rate. The rules, the GRU feed and the SYN-cookie check apply
                # again from the next poll, to a one-poll delta.
                rebaseline = False
                continue

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
            elif XDP_GRU:
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
        except Exception as e:  # noqa: BLE001 - one failing poll must not end the thread
            rebaseline = True
            report_daemon_error("telemetry", e, "the next poll re-takes the snapshots")


try:
    # SIGTERM stops the daemon like Ctrl-C: through the finally below, which detaches XDP.
    signal.signal(signal.SIGTERM, request_stop)
    print("[*] Starting tri-engine Anti-DDoS integration "
          "(XDP Telemetry + GRU ML + L7 Heuristics)...")
    if GRU_ONLY:
        print("[!] GRU_ONLY=1 — all non-GRU ban paths DISABLED (test isolation mode).")
    EVENTS.emit("start", pid=os.getpid(), backend=os.environ.get("MITIGATION_BACKEND", "xdp"),
                gru_only=GRU_ONLY, xdp_gru=XDP_GRU, l7_shadow=L7_SHADOW,
                heuristic_profile=HEURISTIC_PROFILE, slow_pc=SLOW_PC,
                slow_pc_enforce=SLOW_PC_ENFORCE,
                l7_enforce=L7_ENFORCE, l7_enforce_sha256=ban_events.file_sha256("l7_enforce.py"),
                l7_arm=L7_ARM or None, l7_selection_sha256=L7_SELECTION_SHA256 or None,
                slow_pc_sha256=ban_events.file_sha256("slow_pc.py"),
                l7_model=L7_MODEL or None, l7_record=bool(L7_RECORD),
                interface=INTERFACE, model=MODEL_PATH,
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
                    "poll_interval_s": L4_POLL_INTERVAL,
                    "slow_pc_t_s": SLOW_PC_T, "slow_pc_f_bps": SLOW_PC_F, "slow_pc_k": SLOW_PC_K})

    # Every worker runs under supervise() (H-02): an exception is reported and retried.
    telemetry_thread = threading.Thread(
        target=supervise, args=("telemetry", l3_l4_telemetry_monitor), daemon=True)
    telemetry_thread.start()

    # Start dedicated inference worker thread
    inference_thread = threading.Thread(
        target=supervise, args=("inference", inference_worker), daemon=True)
    inference_thread.start()

    print("[+] Inference worker thread started.")
    # Start error log monitor for R.U.D.Y. / slow POST detection
    error_log_thread = threading.Thread(
        target=supervise,
        args=("rudy", tail_nginx_error_logs, NGINX_ERROR_LOG),
        daemon=True
    )
    error_log_thread.start()
    print(f"[*] Listening for Nginx error logs (RUDY detection): {NGINX_ERROR_LOG}")
    print("[+] RUDY detection thread started.")

    # L7 v2 enforcing arm (L7_ENFORCE=1): built before the L7 shadow thread shows it the engine, and run in its own
    # supervised thread. OFF by default.
    if L7_ENFORCE:
        l7_enforce_init()
        l7_enforce_thread = threading.Thread(
            target=supervise, args=("l7_enforce", l7_enforce_monitor), daemon=True)
        l7_enforce_thread.start()
        print("[+] L7 v2 enforcing arm thread started.")

    # Phase P1 L7 shadow ingestion (docs/L7_GRU_DESIGN.md §8). Observe-only; OFF
    # unless L7_SHADOW=1, so the default daemon behaviour is unchanged.
    if L7_SHADOW:
        l7_shadow_thread = threading.Thread(
            target=supervise, args=("l7_shadow", l7_shadow_monitor, L7_SOCKET_PATH),
            daemon=True)
        l7_shadow_thread.start()
        print(f"[+] L7 shadow ingestion thread started (socket {L7_SOCKET_PATH}).")

    # P4 per-connection slow rule (SLOW_PC=1): its own supervised thread (P4-07). OFF by default.
    if SLOW_PC:
        slow_pc_thread = threading.Thread(
            target=supervise, args=("slow_pc", slow_pc_monitor), daemon=True)
        slow_pc_thread.start()
        print("[+] Per-connection slow rule thread started.")
    
    print(f"[*] Listening for Nginx logs (heuristic engine): {NGINX_LOG_FILE}")

    # The main loop now handles ONLY the L7 heuristic (rate + error ratio).
    # GRU inference has moved to the telemetry monitor thread where it reads
    # CICFlowMeter-aligned features directly from the XDP telemetry map.
    # H-01: an error that escapes the tailer (or this loop) is reported and the tailer
    # recreated after ERROR_BACKOFF_S. Only an intentional stop, Ctrl-C or SIGTERM
    # (stop_event), leaves the loop for the finally below, which detaches XDP and so
    # lifts every ban.
    while not stop_event.is_set():
        try:
            for log_line in tail_nginx_logs(NGINX_LOG_FILE):
                try:
                    log_data = json.loads(log_line)
                    client_ip = log_data.get("client_ip")
                    if SLOW_PC:
                        slow_pc_note(log_data)   # P4: cannot raise; the rule below is unchanged

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
        except Exception as e:  # noqa: BLE001 - nothing but a stop may detach XDP (H-01)
            report_daemon_error("access_log", e,
                                f"tailer recreated in {ERROR_BACKOFF_S:g} s")
            time.sleep(ERROR_BACKOFF_S)

except KeyboardInterrupt:
    print("\n[*] Execution interrupted by user. Cleaning up environment...")
finally:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)   # D-02: no handler may re-enter set() below
    stop_event.set()
    bpf.remove_xdp(INTERFACE, 0)
    print(f"[+] XDP program detached from {INTERFACE}. Finished.")
    if L7_ENFORCE:
        l7_enforce_stop()