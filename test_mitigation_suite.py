#!/usr/bin/env python3

import subprocess
import time
import sys
import os
import threading
import json

# --- CONFIGURATION ---
SERVER_IP = "10.0.0.1"
ATTACKER_IP = "10.0.0.2"
ATTACKER_NS = "attacker_ns"
SERVER_NS = "server_ns"
HTTP_URL = f"http://{SERVER_IP}/"
BAN_TTL_SECONDS = 300  # Default from control_plane.py, but tests might use unban checks

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
    
    if isinstance(cmd, str):
        full_cmd.extend(cmd.split())
    else:
        full_cmd.extend(cmd)

    if bg:
        return subprocess.Popen(full_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        try:
            return subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as e:
            return e

def is_ip_banned(ip):
    """Check if the IP is in the BPF blacklist_map using bpftool."""
    # Assuming the map name is blacklist_map and it's loaded in the system
    res = run_cmd("bpftool map dump name blacklist_map", ns=SERVER_NS)
    if isinstance(res, subprocess.TimeoutExpired):
        return False
    
    # The most bulletproof verification is pinging from attacker_ns to server_ns
    # If blocked at XDP, ping will fail.
    ping_res = run_cmd(f"ping -c 1 -W 1 {SERVER_IP}", ns=ATTACKER_NS)
    return ping_res.returncode != 0

def check_syncookies():
    """Check if SYN cookies are enabled globally in the server namespace."""
    res = run_cmd("sysctl -n net.ipv4.tcp_syncookies", ns=SERVER_NS)
    if isinstance(res, subprocess.TimeoutExpired) or not res:
        return False
    return res.stdout.strip() == "1"

def reset_environment():
    """Clean up state between tests by calling setup.sh."""
    print("[*] Rebuilding the entire environment for the next test...")
    
    project_dir = os.path.dirname(os.path.abspath(__file__))
    setup_sh = os.path.join(project_dir, "setup.sh")
    
    # Uruchamiamy Twój oryginalny skrypt setup.sh w tle na prawach roota
    # Logi kierujemy do pliku, z którego test_mitigation_suite.py je odczytuje
    cmd = ["bash", "-c", f"sudo bash {setup_sh} > /tmp/mitigation_test.log 2>&1"]
    run_cmd(cmd, bg=True)
    
    # Dajemy setup.sh 10 sekund na usunięcie starych namespace'ów, 
    # kompilację XDP i pełne uruchomienie środowiska.
    time.sleep(10)

def tail_logs_for_ban(target_ip, timeout=15):
    """Tail the control plane log to find the ban reason and TTM."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with open("/tmp/mitigation_test.log", "r") as f:
                logs = f.read()
                for line in logs.split('\n'):
                    if "[BAN]" in line and target_ip in line:
                        if "SYN flood" in line:
                            return "L4 SYN Flood", time.time() - start_time
                        elif "Heuristic" in line:
                            return "L7 Heuristic", time.time() - start_time
                        elif "GRU" in line:
                            return "GRU ML", time.time() - start_time
        except FileNotFoundError:
            pass
        time.sleep(0.5)
    return "None", None

def report(scenario, engine, ttm, status):
    print(f"[{status}] {scenario} | Engine: {engine} | TTM: {ttm if ttm else 'N/A'}")
    results.append([scenario, engine, f"{ttm:.2f}s" if ttm else "N/A", status])

def test_l4_syn_flood():
    print(f"\n{YELLOW}--- Scenario A: High-Rate L4 SYN Flood ---{RESET}")
    reset_environment()
    
    # Launch hping3
    proc = run_cmd(f"hping3 -S -p 80 -i u1000 {SERVER_IP}", ns=ATTACKER_NS, bg=True)
    
    engine, ttm = tail_logs_for_ban(ATTACKER_IP, timeout=5)
    proc.kill()
    
    is_dropped = is_ip_banned(ATTACKER_IP)
    
    if engine == "L4 SYN Flood" and is_dropped:
        report("A: L4 SYN Flood", engine, ttm, f"{GREEN}PASS{RESET}")
    else:
        report("A: L4 SYN Flood", engine, ttm, f"{RED}FAIL{RESET}")

def test_l7_http_flood():
    print(f"\n{YELLOW}--- Scenario B: L7 High-Frequency HTTP Flood ---{RESET}")
    reset_environment()
    
    # Launch wrk
    proc = run_cmd(f"wrk -t4 -c100 -d10s {HTTP_URL}", ns=ATTACKER_NS, bg=True)
    
    engine, ttm = tail_logs_for_ban(ATTACKER_IP, timeout=12)
    proc.kill()
    
    if engine == "L7 Heuristic" and is_ip_banned(ATTACKER_IP):
        report("B: L7 HTTP Flood", engine, ttm, f"{GREEN}PASS{RESET}")
    else:
        report("B: L7 HTTP Flood", engine, ttm, f"{RED}FAIL{RESET}")

def test_l7_error_flood():
    print(f"\n{YELLOW}--- Scenario C: L7 Error Flooding (404) ---{RESET}")
    reset_environment()
    
    # Launch wrk against nonexistent URL
    proc = run_cmd(f"wrk -t4 -c20 -d10s {HTTP_URL}nonexistent", ns=ATTACKER_NS, bg=True)
    
    engine, ttm = tail_logs_for_ban(ATTACKER_IP, timeout=12)
    proc.kill()
    
    if engine == "L7 Heuristic" and is_ip_banned(ATTACKER_IP):
        report("C: L7 Error Flood", engine, ttm, f"{GREEN}PASS{RESET}")
    else:
        report("C: L7 Error Flood", engine, ttm, f"{RED}FAIL{RESET}")

def test_benign_traffic():
    print(f"\n{YELLOW}--- Scenario F: Benign Baseline ---{RESET}")
    reset_environment()
    
    # Send normal traffic, 1 RPS
    for _ in range(10):
        run_cmd(f"curl -s {HTTP_URL}", ns=ATTACKER_NS)
        time.sleep(1)
        
    engine, ttm = tail_logs_for_ban(ATTACKER_IP, timeout=2)
    banned = is_ip_banned(ATTACKER_IP)
    
    if engine == "None" and not banned:
        report("F: Benign Traffic", "None", None, f"{GREEN}PASS{RESET}")
    else:
        report("F: Benign Traffic", engine, ttm, f"{RED}FAIL{RESET}")

def test_global_spoofed_syn():
    print(f"\n{YELLOW}--- Scenario H: Distributed Spoofed SYN Flood ---{RESET}")
    reset_environment()
    
    # Hping3 with random source
    proc = run_cmd(f"hping3 -S -p 80 --rand-source --flood {SERVER_IP}", ns=ATTACKER_NS, bg=True)
    
    # Check if SYN cookies get enabled
    time.sleep(3)
    syncookies_on = check_syncookies()
    
    proc.kill()
    
    if syncookies_on:
        report("H: Global SYN Flood", "L4 Global", 3.0, f"{GREEN}PASS{RESET}")
    else:
        report("H: Global SYN Flood", "None", None, f"{RED}FAIL{RESET}")

def run_all():
    if os.geteuid() != 0:
        print(f"{RED}[-] Please run this script with sudo/root privileges.{RESET}")
        sys.exit(1)
        
    print("[*] Starting DDoS Mitigation Testing Suite...")
    
    # Check for required tools
    tools = ["hping3", "wrk", "curl", "ping", "bpftool"]
    for t in tools:
        if run_cmd(f"which {t}").returncode != 0:
            print(f"{YELLOW}[!] Warning: {t} not found. Some tests may fail.{RESET}")

    test_l4_syn_flood()
    test_l7_http_flood()
    test_l7_error_flood()
    test_benign_traffic()
    test_global_spoofed_syn()
    
    # Clean up at the end
    run_cmd("pkill -f control_plane.py", ns=SERVER_NS)
    
    print(f"\n{YELLOW}=== TEST SUMMARY ==={RESET}")
    print(f"{'Scenario':<30} | {'Detection Engine':<18} | {'Time-To-Mitigate (TTM)':<22} | {'Result':<6}")
    print("-" * 85)
    for row in results:
        scenario, engine, ttm, status = row
        print(f"{scenario:<30} | {engine:<18} | {ttm:<22} | {status:<6}")

if __name__ == "__main__":
    run_all()
