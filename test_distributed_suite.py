#!/usr/bin/env python3

import subprocess
import time
import sys
import os
import threading
import random
import concurrent.futures

# --- CONFIGURATION ---
SERVER_IP = "10.0.0.1"
BRIDGE_NS = "bridge_ns"
SERVER_NS = "server_ns"

# Adjust sizes for practical simulation (total of 55 namespaces)
NUM_BOTS = 15
NUM_LEGIT = 40

BOT_IP_BASE = "10.0.1"
LEGIT_IP_BASE = "10.0.2"

# ANSI Colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

results = []

def run_cmd(cmd, ns=None, bg=False, timeout=None):
    """Run a shell command, optionally within a namespace."""
    full_cmd = []
    if ns:
        full_cmd.extend(["ip", "netns", "exec", ns])
    
    if isinstance(cmd, list):
        full_cmd.extend(cmd)
    else:
        full_cmd.extend(cmd.split())

    if bg:
        return subprocess.Popen(full_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        try:
            return subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as e:
            return e

def cleanup_topology():
    print("[*] Cleaning up topology and lingering processes...")
    subprocess.run(["pkill", "-f", "control_plane.py"], stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "netns", "exec", SERVER_NS, "pkill", "-f", "nginx"], stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "netns", "exec", SERVER_NS, "pkill", "-f", "gunicorn"], stderr=subprocess.DEVNULL)
    
    res = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True)
    for line in res.stdout.splitlines():
        ns = line.split()[0]
        if ns.startswith("bot_ns_") or ns.startswith("legit_ns_") or ns in [SERVER_NS, BRIDGE_NS, "attacker_ns"]:
            subprocess.run(["ip", "netns", "del", ns])

def setup_topology():
    cleanup_topology()
    print("[*] Setting up bridge and server namespaces...")
    run_cmd("ip netns add server_ns")
    run_cmd("ip netns add bridge_ns")
    
    run_cmd("ip link add veth_server type veth peer name veth_router")
    run_cmd("ip link set veth_server netns server_ns")
    run_cmd("ip link set veth_router netns bridge_ns")
    
    # Server setup
    run_cmd(f"ip addr add {SERVER_IP}/16 dev veth_server", ns=SERVER_NS)
    run_cmd("ip link set veth_server up", ns=SERVER_NS)
    run_cmd("ip link set lo up", ns=SERVER_NS)
    run_cmd("ethtool -K veth_server tx off rx off", ns=SERVER_NS)
    
    # Bridge setup
    run_cmd("ip link add name br0 type bridge", ns=BRIDGE_NS)
    run_cmd("ip link set veth_router master br0", ns=BRIDGE_NS)
    run_cmd("ip link set veth_router up", ns=BRIDGE_NS)
    run_cmd("ip link set br0 up", ns=BRIDGE_NS)
    
    project_dir = os.path.dirname(os.path.abspath(__file__))
    venv_python = os.path.join(project_dir, "venv", "bin", "python")
    
    dummy_app_path = os.path.join(project_dir, "dummy_app.py")
    if not os.path.exists(dummy_app_path):
        with open(dummy_app_path, "w") as f:
            f.write("def app(environ, start_response):\n    data = b'Backend is running flawlessly!\\n'\n    start_response('200 OK', [('Content-Type', 'text/plain'), ('Content-Length', str(len(data)))])\n    return iter([data])\n")
            
    print("[*] Starting Nginx and Gunicorn in server_ns...")
    run_cmd(["bash", "-c", f"{venv_python} -m gunicorn --chdir {project_dir} --workers 4 --threads 10 -b 0.0.0.0:8080 dummy_app:app >/dev/null 2>&1"], ns=SERVER_NS, bg=True)
    time.sleep(1)
    nginx_conf = os.path.join(project_dir, "nginx.conf")
    run_cmd(["nginx", "-c", nginx_conf], ns=SERVER_NS)
    
    # Bots
    print(f"[*] Creating {NUM_BOTS} botnet namespaces...")
    for i in range(1, NUM_BOTS + 1):
        ns_name = f"bot_ns_{i}"
        ip = f"{BOT_IP_BASE}.{i}"
        run_cmd(f"ip netns add {ns_name}")
        run_cmd(f"ip link add vb_{i} type veth peer name vbr_{i}")
        run_cmd(f"ip link set vb_{i} netns {ns_name}")
        run_cmd(f"ip link set vbr_{i} netns {BRIDGE_NS}")
        
        run_cmd(f"ip link set vbr_{i} master br0", ns=BRIDGE_NS)
        run_cmd(f"ip link set vbr_{i} up", ns=BRIDGE_NS)
        
        run_cmd(f"ip addr add {ip}/16 dev vb_{i}", ns=ns_name)
        run_cmd(f"ip link set vb_{i} up", ns=ns_name)
        run_cmd(f"ip link set lo up", ns=ns_name)
        
    # Legit
    print(f"[*] Creating {NUM_LEGIT} legitimate user namespaces (simulating mobile networks)...")
    for i in range(1, NUM_LEGIT + 1):
        ns_name = f"legit_ns_{i}"
        ip = f"{LEGIT_IP_BASE}.{i}"
        run_cmd(f"ip netns add {ns_name}")
        run_cmd(f"ip link add vl_{i} type veth peer name vlr_{i}")
        run_cmd(f"ip link set vl_{i} netns {ns_name}")
        run_cmd(f"ip link set vlr_{i} netns {BRIDGE_NS}")
        
        run_cmd(f"ip link set vlr_{i} master br0", ns=BRIDGE_NS)
        run_cmd(f"ip link set vlr_{i} up", ns=BRIDGE_NS)
        
        run_cmd(f"ip addr add {ip}/16 dev vl_{i}", ns=ns_name)
        run_cmd(f"ip link set vl_{i} up", ns=ns_name)
        run_cmd(f"ip link set lo up", ns=ns_name)
        
        # 50% chance to simulate a bad mobile connection (100ms latency, 1% packet loss)
        if random.choice([True, False]):
            run_cmd(f"tc qdisc add dev vl_{i} root netem delay 100ms 20ms loss 1%", ns=ns_name)

def start_mitigation():
    """Restarts the Python control plane to flush eBPF maps and states."""
    run_cmd("pkill -f control_plane.py", ns=SERVER_NS)
    time.sleep(1)
    project_dir = os.path.dirname(os.path.abspath(__file__))
    venv_python = os.path.join(project_dir, "venv", "bin", "python")
    control_plane_py = os.path.join(project_dir, "control_plane.py")
    cmd = ["bash", "-c", f"{venv_python} {control_plane_py} > /tmp/mitigation_test.log 2>&1"]
    run_cmd(cmd, ns=SERVER_NS, bg=True)
    time.sleep(4) 

# --- Background Traffic Generation ---
stop_legit_traffic = threading.Event()
legit_stats = {"success": 0, "fail": 0, "banned": 0}

def legit_user_worker(ns_name, ip):
    while not stop_legit_traffic.is_set():
        time.sleep(random.uniform(0.5, 2.0))
        
        # Check if banned via ping (XDP drop verification)
        ping_res = subprocess.run(["ip", "netns", "exec", ns_name, "ping", "-c", "1", "-W", "1", SERVER_IP], capture_output=True)
        if ping_res.returncode != 0:
            legit_stats["banned"] += 1
            continue
            
        curl_res = subprocess.run(["ip", "netns", "exec", ns_name, "curl", "-s", "--max-time", "2", f"http://{SERVER_IP}/"], capture_output=True)
        if curl_res.returncode == 0:
            legit_stats["success"] += 1
        else:
            legit_stats["fail"] += 1

def start_legit_traffic():
    stop_legit_traffic.clear()
    legit_stats["success"] = 0
    legit_stats["fail"] = 0
    legit_stats["banned"] = 0
    threads = []
    for i in range(1, NUM_LEGIT + 1):
        t = threading.Thread(target=legit_user_worker, args=(f"legit_ns_{i}", f"{LEGIT_IP_BASE}.{i}"))
        t.daemon = True
        t.start()
        threads.append(t)
    return threads

def stop_botnet(procs):
    """Aggressive cleanup of all botnet processes."""
    for p in procs:
        try:
            p.kill()
        except:
            pass
    for i in range(1, NUM_BOTS + 1):
        ns = f"bot_ns_{i}"
        subprocess.run(["ip", "netns", "exec", ns, "pkill", "-9", "-f", "hping3"], stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "netns", "exec", ns, "pkill", "-9", "-f", "slowloris.py"], stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "netns", "exec", ns, "pkill", "-9", "-f", "rudy_script.py"], stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "netns", "exec", ns, "pkill", "-9", "-f", "curl"], stderr=subprocess.DEVNULL)

def run_scenario(name, bot_cmd, duration, expected_engine=None):
    print(f"\n{YELLOW}--- Scenario: {name} ---{RESET}")
    start_mitigation()
    
    threads = start_legit_traffic()
    print("[*] Generating legitimate background traffic... waiting for baseline.")
    time.sleep(3)
    
    print(f"[*] Launching Distributed Botnet attack across {NUM_BOTS} nodes...")
    procs = []
    for i in range(1, NUM_BOTS + 1):
        ns = f"bot_ns_{i}"
        cmd = bot_cmd if isinstance(bot_cmd, str) else bot_cmd.copy()
        p = run_cmd(cmd, ns=ns, bg=True)
        procs.append(p)
    
    start_time = time.time()
    banned_bots = set()
    first_ttm = None
    engine_detected = "None"
    
    while time.time() - start_time < duration:
        try:
            with open("/tmp/mitigation_test.log", "r") as f:
                logs = f.read().splitlines()
                for line in logs:
                    if "[BAN]" in line:
                        for i in range(1, NUM_BOTS + 1):
                            bot_ip = f"{BOT_IP_BASE}.{i}"
                            if bot_ip in line and bot_ip not in banned_bots:
                                banned_bots.add(bot_ip)
                                if first_ttm is None:
                                    first_ttm = time.time() - start_time
                                    if "SYN flood" in line: engine_detected = "L4 SYN Flood"
                                    elif "Heuristic" in line: engine_detected = "L7 Heuristic"
                                    elif "GRU" in line: engine_detected = "GRU ML"
        except FileNotFoundError:
            pass
        
        if len(banned_bots) >= NUM_BOTS * 0.8:
            break
            
        time.sleep(0.5)
        
    print(f"[*] Stopping attack. Detected {len(banned_bots)}/{NUM_BOTS} bots.")
    stop_botnet(procs)
    
    time.sleep(2)
    stop_legit_traffic.set()
    for t in threads:
        t.join(timeout=1.0)
        
    print(f"[*] Legit User Stats: {legit_stats['success']} successful, {legit_stats['fail']} timeouts, {legit_stats['banned']} BANNED")
    
    passed = True
    if len(banned_bots) < NUM_BOTS * 0.5:
        print(f"{RED}[-] Failed: Less than 50% of the botnet was mitigated.{RESET}")
        passed = False
        
    if legit_stats["banned"] > 0:
        print(f"{RED}[-] Failed: Collateral damage detected! {legit_stats['banned']} legit users were banned (False Positives).{RESET}")
        passed = False
        
    status = f"{GREEN}PASS{RESET}" if passed else f"{RED}FAIL{RESET}"
    results.append([name, engine_detected, f"{first_ttm:.2f}s" if first_ttm else "N/A", f"{len(banned_bots)}/{NUM_BOTS}", legit_stats['banned'], status])
    print(f"[{status}] {name}")

def main():
    if os.geteuid() != 0:
        print(f"{RED}[-] Please run this script with sudo/root privileges.{RESET}")
        sys.exit(1)

    print(f"[*] Initializing Advanced Distributed DDoS Test Suite...")
    setup_topology()
    
    project_dir = os.path.dirname(os.path.abspath(__file__))
    venv_python = os.path.join(project_dir, "venv", "bin", "python")
    slowloris_script = os.path.join(project_dir, "slowloris.py")
    rudy_script = os.path.join(project_dir, "rudy_script.py")

    try:
        # 100 SYN/s per bot -> 15 bots = 1500 SYN/s. Bypasses L4 Per-IP threshold (200), hits ML or Global.
        run_scenario("Distributed Low & Slow SYN Flood", f"hping3 -S -p 80 -i u10000 {SERVER_IP}", duration=15)
        
        # 200 UDP/s per bot. Bypasses SYN metrics, purely volumetric. GRU ML should catch this based on PPS.
        run_scenario("Distributed UDP Flood", f"hping3 --udp -p 80 -i u5000 {SERVER_IP}", duration=15)
        
        # Slowloris. Bypasses limit_conn (50) by opening 8 connections per bot. Total = 120 sockets holding state.
        run_scenario("Distributed Slowloris", [venv_python, slowloris_script], duration=25)
        
        # R.U.D.Y. Exactly 49 sockets per bot, perfectly bypassing limit_conn (50). Very evasive L7 attack.
        run_scenario("Distributed R.U.D.Y.", [venv_python, rudy_script], duration=25)
        
        # Basic HTTP Flood via curl loops
        run_scenario("Distributed HTTP Flood", ["bash", "-c", f"while true; do curl -s http://{SERVER_IP}/ > /dev/null; done"], duration=15)
    
    except KeyboardInterrupt:
        print("\n[*] Tests interrupted by user.")
    finally:
        cleanup_topology()

    print(f"\n{YELLOW}=== DISTRIBUTED TEST SUMMARY ==={RESET}")
    print(f"{'Scenario':<34} | {'Detection Engine':<16} | {'TTM':<10} | {'Bots Banned':<12} | {'Legit Banned':<13} | {'Result':<6}")
    print("-" * 103)
    for row in results:
        scenario, engine, ttm, bots, legit, status = row
        print(f"{scenario:<34} | {engine:<16} | {ttm:<10} | {bots:<12} | {legit:<13} | {status:<6}")

if __name__ == "__main__":
    main()
