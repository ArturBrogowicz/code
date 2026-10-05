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

# Limit PyTorch internal thread pool to 1 to prevent GIL contention
# between PyTorch's intra-op parallelism and our Python threads.
torch.set_num_threads(1)

INTERFACE = "veth_server"
BPF_SOURCE_FILE = "xdp_ddos_filter.c"
NGINX_LOG_FILE = "/var/log/nginx/ddos_ml_access.log"
NGINX_ERROR_LOG = "/var/log/nginx/error.log"
MODEL_PATH = "training_results/gru_ddos_model.pth"
SCALER_PATH = "training_results/scaler.save"

SEQUENCE_LENGTH = 15
PREDICTION_THRESHOLD = 0.95
GRU_CONSECUTIVE_THRESH = 3
# 6 ingress-observable features aligned with CICFlowMeter training data:
#   [0] Flow Duration (µs)           — from XDP: ktime_ns delta
#   [1] Total Fwd Packet (count)     — from XDP: packet_count
#   [2] Total Length of Fwd Packet   — from XDP: byte_count
#   [3] Fwd Packet Length Mean       — computed: byte_count / packet_count
#   [4] Flow Packets/s              — computed: packet_count / flow_duration_s
#   [5] SYN Flag Count              — from XDP: syn_count
INPUT_SIZE = 6
HIDDEN_SIZE = 64
NUM_LAYERS = 2
L4_POLL_INTERVAL = 1.0
SYN_FLOOD_THRESHOLD = 200
UDP_FLOOD_THRESHOLD = 5000
RUDY_TIMEOUT_THRESHOLD = 3     # Ban after 3 body-read timeouts in the window
RUDY_WINDOW = 60.0             # Sliding window for counting timeouts (seconds)

# Auto-unblock IPs after TTL expires (seconds)
BAN_TTL_SECONDS = 300

# Aggregate SYN rate threshold for spoofed-IP flood detection
GLOBAL_SYN_THRESHOLD = 5000

# Early detection heuristic thresholds (triggers before GRU's 15-request minimum)
HEURISTIC_WINDOW = 10.0        # Sliding window in seconds
HEURISTIC_MAX_RPS = 50         # Max requests per second before blocking
HEURISTIC_ERROR_RATIO = 0.8    # Block if >80% of requests return 4xx/5xx
HEURISTIC_MIN_REQUESTS = 5     # Minimum requests in window before evaluating

# Eviction timeout for idle client tracking data (seconds)
CLIENT_IDLE_TIMEOUT = 60.0

print(f"[*] Compiling and loading eBPF code from file: {BPF_SOURCE_FILE}...")
bpf = BPF(src_file=BPF_SOURCE_FILE)
bpf_function = bpf.load_func("xdp_ddos_mitigation", BPF.XDP)
bpf.attach_xdp(INTERFACE, bpf_function, 0)
print(f"[+] Successfully attached XDP program to interface {INTERFACE}.")

blacklist_map = bpf.get_table("blacklist_map")
telemetry_map = bpf.get_table("telemetry_map")

print("[*] Loading data scaler...")
scaler = joblib.load(SCALER_PATH)
assert scaler.n_features_in_ == INPUT_SIZE, (
    f"Scaler expects {scaler.n_features_in_} features but INPUT_SIZE is {INPUT_SIZE}. "
    "Ensure the training features in GRU_ML_init.py match the inference features."
)

print("[*] Loading trained GRU model...")
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

# GRU per-IP sequence tracking — now populated from XDP telemetry, not Nginx logs
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

# Track ban timestamps for TTL-based expiry
ban_timestamps = {}

# Track per-IP request metadata for rate/error heuristic (from Nginx logs)
request_tracker = defaultdict(deque)

# Alongside existing request_tracker
rudy_tracker = defaultdict(deque)  # {ip: deque of (timestamp,)]}

# Track whether SYN cookies have been activated
syn_cookies_enabled = False

# Track last-seen timestamp per client for idle eviction
client_last_seen = {}

# Queue for offloading ML inference to a dedicated thread
inference_queue = queue.Queue()
inference_result_queue = queue.Queue()


def ip_to_network_bytes(ip_str):
    return struct.unpack("=I", socket.inet_aton(ip_str))[0]

def network_bytes_to_ip(ip_int):
    return socket.inet_ntoa(struct.pack("=I", ip_int))

def block_ip_in_xdp(ip_str):
    ip_int = ip_to_network_bytes(ip_str)
    blacklist_map[blacklist_map.Key(ip_int)] = blacklist_map.Leaf(0)
    print(f"[XDP] BLOCKED IP: {ip_str}. Rule is active on hardware.")


def ban_ip(ip_str, reason="unknown"):
    """Block IP in XDP and record ban timestamp for TTL-based expiry.

    Centralizes the ban logic so every code path (GRU, heuristic, L4)
    consistently updates both the XDP blacklist and the internal tracking sets.
    """
    backend = os.environ.get("MITIGATION_BACKEND", "xdp")
    if backend == "iptables":
        try:
            subprocess.run(["ip", "netns", "exec", "server_ns", "iptables", "-A", "INPUT", "-s", ip_str, "-j", "DROP"], check=True)
            print(f"[IPTABLES] BLOCKED IP: {ip_str}. Rule is active on software firewall.")
        except Exception as e:
            print(f"[-] Failed to block {ip_str} via iptables: {e}")
    else:
        block_ip_in_xdp(ip_str)
        
    with banned_ips_lock:
        banned_ips.add(ip_str)
        ban_timestamps[ip_str] = time.time()
    print(f"[BAN] {ip_str} banned for {BAN_TTL_SECONDS}s. Reason: {reason}")


def unblock_expired_bans():
    """Remove expired bans from XDP blacklist and internal tracking sets.

    Called periodically from the L4 telemetry monitor thread.
    """
    now = time.time()
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
            banned_ips.discard(ip_str)
            del ban_timestamps[ip_str]


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
        try:
            del telemetry_map[telemetry_map.Key(ip_to_network_bytes(ip_str))]
        except KeyError:
            pass
    if stale_ips:
        print(f"[GC] Evicted tracking data for {len(stale_ips)} idle client(s).")


def kill_zombie_connections(ip_str):
    try:
        subprocess.run(["ss", "-K", "dst", ip_str], check=True, capture_output=True)
        print(f"[OS] Killed hanging TCP sessions for address {ip_str}.")
    except subprocess.CalledProcessError as e:
        print(f"[-] Error while killing sessions for {ip_str}: {e.stderr.decode().strip()}")
    except FileNotFoundError:
        print("[-] The 'ss' tool is not installed (iproute2 package).")


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
                        if timeout_count >= RUDY_TIMEOUT_THRESHOLD:
                            print(f"\n[RUDY-DETECT] Slow POST attack detected - IP: {client_ip} | "
                                  f"Body timeouts: {timeout_count} in {RUDY_WINDOW}s")
                            ban_ip(client_ip,
                                   reason=f"Heuristic R.U.D.Y. ({timeout_count} body timeouts)")
                            kill_zombie_connections(client_ip)
                            rudy_tracker.pop(client_ip, None)

        except FileNotFoundError:
            print(f"[-] Error log {file_path} not found, retrying in 1s...")
            time.sleep(1)

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
        with state_lock:
            if probability > PREDICTION_THRESHOLD:
                gru_violation_counts[client_ip] += 1
                # require GRU_CONSECUTIVE_THRESH detections in a row (FP guard)
                if gru_violation_counts[client_ip] >= GRU_CONSECUTIVE_THRESH:
                    should_ban = True
            else:
                gru_violation_counts.pop(client_ip, None)

        if not should_ban:
            continue

        print(f"\n[GRU] DETECTED ATTACK — IP: {client_ip} | "
              f"Confidence: {probability * 100:.1f}%")
        ban_ip(client_ip,
               reason=f"GRU classifier ({probability * 100:.1f}% confidence)")
        kill_zombie_connections(client_ip)
        with state_lock:
            client_sequences.pop(client_ip, None)
            request_tracker.pop(client_ip, None)
            client_last_seen.pop(client_ip, None)
            gru_violation_counts.pop(client_ip, None)
        prev_telemetry.pop(client_ip, None)   # telemetry-thread-only

def l3_l4_telemetry_monitor():
    """L3/L4 telemetry monitor — now also drives GRU inference.

    Every L4_POLL_INTERVAL (1s), this thread:
      1. Sweeps expired bans and idle client data
      2. Drains completed inference results
      3. Reads per-IP telemetry from the XDP map
      4. Runs the per-IP SYN flood heuristic
      5. Extracts 6 CICFlowMeter-aligned features from XDP telemetry
      6. Builds per-IP sequences and submits full sequences to the inference thread
      7. Detects aggregate SYN floods and enables SYN cookies

    The GRU now operates on the SAME measurement plane (L3/L4 flow statistics)
    as its training data — eliminating the Nginx/CICFlowMeter feature mismatch.
    """
    global syn_cookies_enabled
    print(f"[*] Starting L3/L4 telemetry monitor (Interval: {L4_POLL_INTERVAL}s)")
    while not stop_event.is_set():
        time.sleep(L4_POLL_INTERVAL)

        # Periodic maintenance
        unblock_expired_bans()
        evict_idle_clients()
        drain_inference_results()

        total_global_syn_delta = 0
        now_ns = time.monotonic_ns()

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
            cum_conns = sum(cpu.active_connections for cpu in per_cpu_values)
            # first_seen_ns: earliest non-zero across CPUs -> true flow start
            first_ns_values = [cpu.first_seen_ns for cpu in per_cpu_values
                               if cpu.first_seen_ns > 0]
            first_ns = min(first_ns_values) if first_ns_values else 0

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

            # --- L4 SYN flood heuristic (per-IP, per-interval rate) ---
            if d_syn > SYN_FLOOD_THRESHOLD:
                print(f"\n[L4-DETECT] SYN FLOOD ATTACK - IP: {ip_str} | "
                      f"Rate: {d_syn} SYN/s")
                ban_ip(ip_str, reason=f"Per-IP SYN flood ({d_syn} SYN/s)")
                continue

            # --- L4 UDP / Volumetric flood heuristic (per-IP, per-interval rate) ---
            non_syn_pkts = d_pkts - d_syn
            if non_syn_pkts > UDP_FLOOD_THRESHOLD:
                print(f"\n[L4-DETECT] VOLUMETRIC PACKET FLOOD ATTACK - IP: {ip_str} | "
                      f"Rate: {non_syn_pkts} pkts/s")
                ban_ip(ip_str, reason=f"Volumetric packet flood ({non_syn_pkts} pkts/s)")
                continue

            # Mark liveness (drives idle eviction) -- shared dict, under state_lock.
            if d_pkts > 0:
                with state_lock:
                    client_last_seen[ip_str] = time.time()

            # --- GRU feature extraction from XDP telemetry ---
            if d_pkts > 0 and first_ns > 0:
                # TRUE cumulative flow duration — now correct and preserved for
                # the de-confounded retrain (P0). The current (confounded) model
                # was effectively tuned on per-interval (<=1s) durations, so we
                # CAP what we actually feed it; remove this cap on retrain.
                flow_duration_us = max((now_ns - first_ns) / 1000, 1.0)
                gru_duration_us = min(flow_duration_us, L4_POLL_INTERVAL * 1e6)
                gru_duration_s = gru_duration_us / 1e6
                fwd_pkt_len_mean = d_bytes / d_pkts
                flow_pps = d_pkts / gru_duration_s

                # --- L4 slow-connection (Slowloris/R.U.D.Y.) heuristic: DEFERRED ---
                # Reviving this naively with the cumulative active_connections
                # counter false-bans legit clients: ingress-only XDP never sees
                # server-side teardown, so the gauge drifts upward without bound
                # (observed: every legit client pinned at "8 conns"). A drift-free
                # design (per-interval conn gauge, C-side) is its own iteration.
                # Slowloris/R.U.D.Y. remain covered by the L7 heuristic engine.

                # Normalize per-interval stats to per-flow averages (CICFlowMeter-aligned)
                num_flows = max(float(d_syn), 1.0)

                avg_flow_duration_us = gru_duration_us / num_flows
                avg_pkts_per_flow = float(d_pkts) / num_flows
                avg_bytes_per_flow = float(d_bytes) / num_flows
                avg_syn_per_flow = float(d_syn) / num_flows

                # SYN-flood-shaped flows: force minimal duration / very high PPS
                if avg_pkts_per_flow <= 2.5 and avg_syn_per_flow >= 0.8 and d_syn >= 3:
                    avg_flow_duration_us = 1.0
                    avg_flow_pps = avg_pkts_per_flow / 0.000001
                else:
                    avg_flow_pps = flow_pps / num_flows

                features = [
                    avg_flow_duration_us,       # Flow Duration (us)
                    avg_pkts_per_flow,          # Total Fwd Packet
                    avg_bytes_per_flow,         # Total Length of Fwd Packet
                    fwd_pkt_len_mean,           # Fwd Packet Length Mean
                    avg_flow_pps,               # Flow Packets/s
                    avg_syn_per_flow,           # SYN Flag Count
                ]

                # Append + readiness check under state_lock; the heavy work
                # (scaler transform + queue put) is done OUTSIDE the lock.
                with state_lock:
                    client_sequences[ip_str].append(features)
                    seq_ready = len(client_sequences[ip_str]) == SEQUENCE_LENGTH
                    raw_sequence = (np.array(list(client_sequences[ip_str]))
                                    if seq_ready else None)
                if seq_ready:
                    inference_queue.put((ip_str, scaler.transform(raw_sequence)))

        # NOTE: no blanket delete of the telemetry map here any more. Keys are
        # cumulative and are reclaimed only when an IP goes idle (see
        # evict_idle_clients) -- that is what preserves flow duration + counts.

        # Detect spoofed-IP SYN floods via aggregate rate
        if total_global_syn_delta > GLOBAL_SYN_THRESHOLD and not syn_cookies_enabled:
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
                        rps = len(entries) / window_duration
                        error_count = sum(1 for _, err in entries if err)
                        error_ratio = error_count / len(entries)
                        if rps > HEURISTIC_MAX_RPS or (error_ratio > HEURISTIC_ERROR_RATIO and rps > 10):
                            should_ban = True
                            ban_rps = rps
                            ban_err = error_ratio

            if should_ban:
                print(f"\n[HEURISTIC] L7 anomaly detected - IP: {client_ip} | "
                      f"RPS: {ban_rps:.1f} | Error ratio: {ban_err:.0%}")
                ban_ip(client_ip,
                       reason=f"Heuristic (RPS={ban_rps:.1f}, errors={ban_err:.0%})")
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