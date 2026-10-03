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

INTERFACE = "enp0s8"
BPF_SOURCE_FILE = "./xdp_ddos_filter.c"
NGINX_LOG_FILE = "/var/log/nginx/ddos_ml_access.log"
NGINX_ERROR_LOG = "/var/log/nginx/error.log"
MODEL_PATH = "../training_results/gru_ddos_model.pth"
SCALER_PATH = "../training_results/scaler.save"

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
    stale_ips = [ip for ip, ts in client_last_seen.items()
                 if now - ts > CLIENT_IDLE_TIMEOUT]
    for ip_str in stale_ips:
        client_sequences.pop(ip_str, None)
        request_tracker.pop(ip_str, None)
        gru_violation_counts.pop(ip_str, None)
        del client_last_seen[ip_str]
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

    Called from both the telemetry monitor and main loop to process any
    GRU verdicts that have completed asynchronously.
    """
    while True:
        try:
            client_ip, probability = inference_result_queue.get_nowait()
        except queue.Empty:
            break

        with banned_ips_lock:
            if client_ip in banned_ips:
                continue

        if probability > PREDICTION_THRESHOLD:
            gru_violation_counts[client_ip] += 1
            violations = gru_violation_counts[client_ip]
            # verify if collected 3 sequences in a row to prevent false positives
            if violations >= GRU_CONSECUTIVE_THRESH:
                print(f"\n[GRU] DETECTED ATTACK — IP: {client_ip} | "
                      f"Confidence: {probability * 100:.1f}%")
                ban_ip(client_ip,
                    reason=f"GRU classifier ({probability * 100:.1f}% confidence)")
                kill_zombie_connections(client_ip)
                client_sequences.pop(client_ip, None)
                request_tracker.pop(client_ip, None)
                client_last_seen.pop(client_ip, None)
                gru_violation_counts.pop(client_ip, None)
        else:
            if client_ip in gru_violation_counts:
                gru_violation_counts.pop(client_ip, None)

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

        total_global_syn = 0

        # Collect keys during iteration, delete individually after processing
        # to avoid the TOCTOU race where clear() drops newly-added entries.
        processed_keys = []
        now_ns = time.monotonic_ns()

        for key, per_cpu_values in telemetry_map.items():
            ip_str = network_bytes_to_ip(key.value)
            processed_keys.append(key)

            with banned_ips_lock:
                if ip_str in banned_ips:
                    continue

            # Aggregate per-CPU counters
            total_pkts = sum(cpu.packet_count for cpu in per_cpu_values)
            total_syn = sum(cpu.syn_count for cpu in per_cpu_values)
            total_bytes = sum(cpu.byte_count for cpu in per_cpu_values)
            total_connections = sum(cpu.active_connections for cpu in per_cpu_values)
            # first_seen_ns: take the earliest non-zero value across CPUs
            first_ns_values = [cpu.first_seen_ns for cpu in per_cpu_values
                               if cpu.first_seen_ns > 0]
            first_ns = min(first_ns_values) if first_ns_values else 0

            total_global_syn += total_syn

            # --- L4 SYN flood heuristic (per-IP) ---
            if total_syn > SYN_FLOOD_THRESHOLD:
                print(f"\n[L4-DETECT] SYN FLOOD ATTACK - IP: {ip_str} | "
                      f"Rate: {total_syn} SYN/s")
                ban_ip(ip_str, reason=f"Per-IP SYN flood ({total_syn} SYN/s)")
                continue

            # --- L4 UDP / Volumetric flood heuristic (per-IP) ---
            non_syn_pkts = total_pkts - total_syn
            if non_syn_pkts > UDP_FLOOD_THRESHOLD:
                print(f"\n[L4-DETECT] VOLUMETRIC PACKET FLOOD ATTACK - IP: {ip_str} | "
                      f"Rate: {non_syn_pkts} pkts/s")
                ban_ip(ip_str, reason=f"Volumetric packet flood ({non_syn_pkts} pkts/s)")
                continue

            # --- GRU feature extraction from XDP telemetry ---
            # print(f"[DEBUG-TELEMETRY] IP={ip_str} pkts={total_pkts} syn={total_syn} bytes={total_bytes} conns={total_connections} first_ns={first_ns}")
            if total_pkts > 0 and first_ns > 0:
                flow_duration_us = max((now_ns - first_ns) / 1000, 1.0)
                flow_duration_s = flow_duration_us / 1e6
                fwd_pkt_len_mean = total_bytes / total_pkts
                flow_pps = total_pkts / flow_duration_s

                # --- Layer 3: eBPF connection-count heuristic (R.U.D.Y./Slowloris) ---
                # If an IP has many active connections but very low packet rate,
                # it's likely holding connections open without sending data.
                # NOTE: Use total_pkts / L4_POLL_INTERVAL (stable per-interval
                # rate) instead of flow_pps (which depends on sub-second timing
                # within the interval and can be artificially inflated).
                interval_pps = total_pkts / L4_POLL_INTERVAL
                if total_connections > 7 and interval_pps < 20.0:
                    print(f"\n[L4-DETECT] SLOW CONNECTION ABUSE - IP: {ip_str} | "
                          f"Connections: {total_connections} | PPS: {interval_pps:.1f}")
                    ban_ip(ip_str, reason=f"Slow connection abuse ({total_connections} conns, {interval_pps:.1f} pps)")
                    kill_zombie_connections(ip_str)
                    continue

                # Normalize per-IP interval stats to per-flow averages to match CICFlowMeter training data
                num_flows = max(float(total_syn), 1.0)
                
                avg_flow_duration_us = flow_duration_us / num_flows
                avg_pkts_per_flow = float(total_pkts) / num_flows
                avg_bytes_per_flow = float(total_bytes) / num_flows
                avg_syn_per_flow = float(total_syn) / num_flows
                
                # We retain fwd_pkt_len_mean and flow_pps as they are rate/mean metrics.
                # However, for flow_pps, CICFlowMeter often reports very high PPS for short flows.
                # If num_flows > 1 (e.g. SYN flood), the individual flows are much shorter.
                # A heuristic: if it's a SYN flood, the flow duration is minimal, so PPS should be high.
                if avg_pkts_per_flow <= 2.5 and avg_syn_per_flow >= 0.8 and total_syn >= 3:
                    avg_flow_duration_us = 1.0
                    avg_flow_pps = avg_pkts_per_flow / 0.000001
                else:
                    avg_flow_pps = flow_pps / num_flows

                features = [
                    avg_flow_duration_us,       # Flow Duration (µs)
                    avg_pkts_per_flow,          # Total Fwd Packet
                    avg_bytes_per_flow,         # Total Length of Fwd Packet
                    fwd_pkt_len_mean,           # Fwd Packet Length Mean
                    avg_flow_pps,               # Flow Packets/s
                    avg_syn_per_flow,           # SYN Flag Count
                ]

                client_last_seen[ip_str] = time.time()
                client_sequences[ip_str].append(features)

                if len(client_sequences[ip_str]) == SEQUENCE_LENGTH:
                    raw_sequence = np.array(list(client_sequences[ip_str]))
                    scaled_sequence = scaler.transform(raw_sequence)
                    # print(f"[DEBUG-ML] IP={ip_str} submitting seq to GRU. Features: {features}")
                    inference_queue.put((ip_str, scaled_sequence))

        # Delete only processed keys — new entries added by XDP between
        # our iteration start and now are preserved for the next cycle.
        for key in processed_keys:
            try:
                del telemetry_map[key]
            except KeyError:
                pass

        # Detect spoofed-IP SYN floods via aggregate rate
        if total_global_syn > GLOBAL_SYN_THRESHOLD and not syn_cookies_enabled:
            try:
                subprocess.run(
                    ["sysctl", "-w", "net.ipv4.tcp_syncookies=1"],
                    check=True, capture_output=True
                )
                print(f"[L4-GLOBAL] Aggregate SYN rate {total_global_syn}/s exceeds "
                      f"threshold. SYN cookies ENABLED.")
                syn_cookies_enabled = True
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                print(f"[-] Failed to enable SYN cookies: {e}")
        elif total_global_syn <= GLOBAL_SYN_THRESHOLD // 2 and syn_cookies_enabled:
            syn_cookies_enabled = False
            print(f"[L4-GLOBAL] Aggregate SYN rate {total_global_syn}/s back to normal. "
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
            # Drain any completed GRU inference results (non-blocking)
            drain_inference_results()

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
                    
                    # print(f"[DEBUG-HEURISTIC] IP={client_ip} RPS={rps:.1f} err_ratio={error_ratio:.2f} entries={len(entries)}")

                    if rps > HEURISTIC_MAX_RPS or (error_ratio > HEURISTIC_ERROR_RATIO and rps > 10):
                        print(f"\n[HEURISTIC] L7 anomaly detected - IP: {client_ip} | "
                              f"RPS: {rps:.1f} | Error ratio: {error_ratio:.0%}")
                        ban_ip(client_ip,
                               reason=f"Heuristic (RPS={rps:.1f}, errors={error_ratio:.0%})")
                        kill_zombie_connections(client_ip)
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