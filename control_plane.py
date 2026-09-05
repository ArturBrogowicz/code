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

# Fix 13: Limit PyTorch internal thread pool to 1 to prevent GIL contention
# between PyTorch's intra-op parallelism and our Python threads.
torch.set_num_threads(1)

INTERFACE = "veth_server"
BPF_SOURCE_FILE = "xdp_ddos_filter.c"
NGINX_LOG_FILE = "/var/log/nginx/ddos_ml_access.log"
MODEL_PATH = "training_results/gru_ddos_model.pth"
SCALER_PATH = "training_results/scaler.save"

SEQUENCE_LENGTH = 15
PREDICTION_THRESHOLD = 0.85
INPUT_SIZE = 3
HIDDEN_SIZE = 64
NUM_LAYERS = 2
L4_POLL_INTERVAL = 1.0
SYN_FLOOD_THRESHOLD = 200

# Fix 5: Auto-unblock IPs after TTL expires (seconds)
BAN_TTL_SECONDS = 300

# Fix 6: Aggregate SYN rate threshold for spoofed-IP flood detection
GLOBAL_SYN_THRESHOLD = 5000

# Fix 7: Early detection heuristic thresholds (triggers before GRU's 15-request minimum)
HEURISTIC_WINDOW = 10.0        # Sliding window in seconds
HEURISTIC_MAX_RPS = 50         # Max requests per second before blocking
HEURISTIC_ERROR_RATIO = 0.8    # Block if >80% of requests return 4xx/5xx
HEURISTIC_MIN_REQUESTS = 5     # Minimum requests in window before evaluating

# Fix 10: Eviction timeout for idle client tracking data (seconds)
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

# Fix 11: Pre-allocate a reusable tensor buffer for inference instead of
# creating a new torch.tensor() on every evaluation. We copy data into this
# buffer using numpy, avoiding repeated memory allocation and GC pressure.
_inference_buffer_np = np.zeros((1, SEQUENCE_LENGTH, INPUT_SIZE), dtype=np.float32)
_inference_tensor = torch.zeros(1, SEQUENCE_LENGTH, INPUT_SIZE,
                                dtype=torch.float32, device=device)

client_sequences = defaultdict(lambda: deque(maxlen=SEQUENCE_LENGTH))
banned_ips = set()
banned_ips_lock = threading.Lock()
stop_event = threading.Event()

# Fix 5: Track ban timestamps for TTL-based expiry
ban_timestamps = {}

# Fix 7: Track per-IP request metadata for rate/error heuristic
request_tracker = defaultdict(deque)

# Fix 6: Track whether SYN cookies have been activated
syn_cookies_enabled = False

# Fix 10: Track last-seen timestamp per client for idle eviction
client_last_seen = {}

# Fix 13: Queue for offloading ML inference to a dedicated thread
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
            try:
                ip_int = ip_to_network_bytes(ip_str)
                del blacklist_map[blacklist_map.Key(ip_int)]
                print(f"[TTL] Unblocked IP: {ip_str} (ban expired after {BAN_TTL_SECONDS}s)")
            except KeyError:
                pass
            banned_ips.discard(ip_str)
            del ban_timestamps[ip_str]


def evict_idle_clients():
    """Fix 10: Remove tracking data for clients that have been idle too long.

    Without this, every unique IP that sends at least one request accumulates
    a deque entry in client_sequences and request_tracker forever. Under a
    subnet scan (e.g., /16 = 65K IPs each sending 1 request), this becomes
    an unbounded memory leak.

    Called periodically from the L4 telemetry monitor thread.
    """
    now = time.time()
    stale_ips = [ip for ip, ts in client_last_seen.items()
                 if now - ts > CLIENT_IDLE_TIMEOUT]
    for ip_str in stale_ips:
        client_sequences.pop(ip_str, None)
        request_tracker.pop(ip_str, None)
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
    """Tail a log file, automatically reopening on log rotation (inode change).

    Fix 8: The original implementation held a single file descriptor open
    forever. If logrotate renamed or truncated the file, the generator would
    silently read nothing. This version checks the inode every ~5 seconds
    and reopens the file when rotation is detected.
    """
    while True:
        try:
            current_inode = os.stat(file_path).st_ino
            with open(file_path, 'r') as f:
                f.seek(0, os.SEEK_END)
                stale_count = 0
                while True:
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


def inference_worker():
    """Fix 13: Dedicated inference thread to decouple GRU computation from log parsing.

    The main thread parses log lines and builds feature sequences (I/O-bound).
    This thread runs GRU inference (CPU-bound). By separating them, the main
    thread can continue parsing logs during inference, and the L4 telemetry
    thread gets more GIL time for SYN flood detection.

    Communication uses two thread-safe queues:
      inference_queue:        main → worker  (client_ip, scaled_sequence)
      inference_result_queue: worker → main  (client_ip, probability)
    """
    while not stop_event.is_set():
        try:
            client_ip, scaled_sequence = inference_queue.get(timeout=0.5)
        except queue.Empty:
            continue

        try:
            # Fix 11: Reuse pre-allocated tensor buffer
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


def l3_l4_telemetry_monitor():
    global syn_cookies_enabled
    print(f"[*] Starting L3/L4 telemetry monitor (Interval: {L4_POLL_INTERVAL}s)")
    while not stop_event.is_set():
        time.sleep(L4_POLL_INTERVAL)

        # Fix 5: Sweep expired bans each cycle
        unblock_expired_bans()

        # Fix 10: Evict idle client tracking data each cycle
        evict_idle_clients()

        total_global_syn = 0

        # Fix 12: Collect keys during iteration, delete individually after
        # processing instead of telemetry_map.clear(). This eliminates the
        # TOCTOU race where new XDP-counted packets between the iteration
        # and clear() were silently lost.
        processed_keys = []

        for key, per_cpu_values in telemetry_map.items():
            ip_str = network_bytes_to_ip(key.value)
            processed_keys.append(key)

            with banned_ips_lock:
                if ip_str in banned_ips:
                    continue

            total_syn = sum(cpu.syn_count for cpu in per_cpu_values)
            total_global_syn += total_syn

            if total_syn > SYN_FLOOD_THRESHOLD:
                print(f"\n[L4-DETECT] SYN FLOOD ATTACK - IP: {ip_str} | Rate: {total_syn} SYN/s")
                ban_ip(ip_str, reason=f"Per-IP SYN flood ({total_syn} SYN/s)")

        # Fix 12: Delete only the keys we processed — new entries added by
        # XDP between our iteration start and now are preserved for the next cycle.
        for key in processed_keys:
            try:
                del telemetry_map[key]
            except KeyError:
                pass

        # Fix 6: Detect spoofed-IP SYN floods via aggregate rate
        if total_global_syn > GLOBAL_SYN_THRESHOLD and not syn_cookies_enabled:
            try:
                subprocess.run(
                    ["sysctl", "-w", "net.ipv4.tcp_syncookies=1"],
                    check=True, capture_output=True
                )
                print(f"[L4-GLOBAL] Aggregate SYN rate {total_global_syn}/s exceeds threshold. "
                      f"SYN cookies ENABLED.")
                syn_cookies_enabled = True
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                print(f"[-] Failed to enable SYN cookies: {e}")
        elif total_global_syn <= GLOBAL_SYN_THRESHOLD // 2 and syn_cookies_enabled:
            syn_cookies_enabled = False
            print(f"[L4-GLOBAL] Aggregate SYN rate {total_global_syn}/s back to normal. "
                  f"SYN cookies flag reset.")


def drain_inference_results():
    """Drain all pending results from the inference worker thread.

    Called from the main loop after each log line to process any GRU
    verdicts that have completed asynchronously.
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
            print(f"\n[GRU] DETECTED L7 ATTACK (Slowloris/DoS) - IP: {client_ip} | "
                  f"Confidence: {probability * 100:.1f}%")
            ban_ip(client_ip,
                   reason=f"GRU classifier ({probability * 100:.1f}% confidence)")
            kill_zombie_connections(client_ip)
            client_sequences.pop(client_ip, None)
            request_tracker.pop(client_ip, None)
            client_last_seen.pop(client_ip, None)


try:
    print("[*] Starting Nginx -> GRU -> XDP integration...")
    print("[*] Starting dual-engine Anti-DDoS integration (GRU + Heuristics)...")

    telemetry_thread = threading.Thread(target=l3_l4_telemetry_monitor, daemon=True)
    telemetry_thread.start()

    # Fix 13: Start dedicated inference worker thread
    inference_thread = threading.Thread(target=inference_worker, daemon=True)
    inference_thread.start()
    print("[+] Inference worker thread started.")

    print(f"[*] Listening for logs in file: {NGINX_LOG_FILE}")

    for log_line in tail_nginx_logs(NGINX_LOG_FILE):
        try:
            # Fix 13: Drain any completed inference results before processing
            # the next log line. This is non-blocking.
            drain_inference_results()

            log_data = json.loads(log_line)
            client_ip = log_data.get("client_ip")

            with banned_ips_lock:
                if client_ip in banned_ips:
                    continue

            # Fix 10: Update last-seen timestamp for idle eviction
            client_last_seen[client_ip] = time.time()

            # --- Fix 7: Early detection heuristic (rate + error ratio) ---
            now = time.time()
            status = int(log_data.get("status", 200))
            is_error = status >= 400

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

                    if rps > HEURISTIC_MAX_RPS or error_ratio > HEURISTIC_ERROR_RATIO:
                        print(f"\n[HEURISTIC] L7 anomaly detected - IP: {client_ip} | "
                              f"RPS: {rps:.1f} | Error ratio: {error_ratio:.0%}")
                        ban_ip(client_ip,
                               reason=f"Heuristic (RPS={rps:.1f}, errors={error_ratio:.0%})")
                        kill_zombie_connections(client_ip)
                        client_sequences.pop(client_ip, None)
                        request_tracker.pop(client_ip, None)
                        client_last_seen.pop(client_ip, None)
                        continue

            # Feature mapping (Nginx log → CICFlowMeter training equivalent):
            #   request_time * 1e6  ≈ Flow Duration (µs)
            #   request_length      ≈ Fwd Packets Length Total (bytes)
            #   bytes_sent          ≈ Bwd Packets Length Total (bytes)
            # NOTE: These are semantic approximations. For production accuracy,
            # retrain the model on a dataset collected from Nginx JSON logs.
            features = [
                float(log_data.get("request_time", 0.0)) * 1000000,
                float(log_data.get("request_length", 0)),
                float(log_data.get("bytes_sent", 0))
            ]

            client_sequences[client_ip].append(features)

            if len(client_sequences[client_ip]) == SEQUENCE_LENGTH:
                # Fix 11 + 13: Build scaled sequence and submit to inference thread
                raw_sequence = np.array(list(client_sequences[client_ip]))
                scaled_sequence = scaler.transform(raw_sequence)
                inference_queue.put((client_ip, scaled_sequence))

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