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
    """Check if the IP is banned by pinging from that specific source IP."""
    # Pingujemy serwer, zmuszając ping do wyjścia z konkretnego adresu IP (-I ip)
    ping_res = run_cmd(f"ping -c 1 -W 1 -I {ip} {SERVER_IP}", ns=ATTACKER_NS)
    # Jeśli pakiet nie wrócił (kod błędu inny niż 0), oznacza to, że XDP go zablokowało
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
                        elif "UDP" in line:
                            return "L4 UDP Flood", time.time() - start_time
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

def test_gru_stealth_syn():
    print(f"\n{YELLOW}--- Scenario D: Low & Slow SYN Flood (GRU ML Target) ---{RESET}")
    reset_environment()
    
    # Wysyłamy 10 pakietów SYN na sekundę (-i u100000)
    # To celowo omija heurystykę L4, by wymusić analizę przez model GRU
    proc = run_cmd(f"hping3 -a {ATTACKER_IP} -S -p 80 -i u100000 {SERVER_IP}", ns=ATTACKER_NS, bg=True)
    
    # Model potrzebuje 15 sekund na zebranie sekwencji, dajemy timeout 25s
    engine, ttm = tail_logs_for_ban(ATTACKER_IP, timeout=25)
    proc.kill()
    
    is_dropped = is_ip_banned(ATTACKER_IP)
    
    if engine == "GRU ML" and is_dropped:
        report("D: Low & Slow SYN", engine, ttm, f"{GREEN}PASS{RESET}")
    else:
        report("D: Low & Slow SYN", engine, ttm, f"{RED}FAIL{RESET}")

def test_l7_slowloris():
    print(f"\n{YELLOW}--- Scenario E: L7 Slowloris Attack ---{RESET}")
    reset_environment()
    
    slowloris_script = "/tmp/slowloris_test.py"
    
    # Dynamiczne generowanie skryptu ataku dla namespace'a
    with open(slowloris_script, "w") as f:
        f.write("""import socket, random, time
TARGET_IP = "10.0.0.1"
PORT = 80
SOCKET_COUNT = 150
SLEEP_TIME = 10
sockets = []

def create_socket():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((TARGET_IP, PORT))
        s.send(f"GET /?rand={random.randint(0, 2000)} HTTP/1.1\\r\\n".encode("utf-8"))
        s.send(f"Host: {TARGET_IP}\\r\\n".encode("utf-8"))
        s.send("User-Agent: Slowloris-Testing\\r\\n".encode("utf-8"))
        s.send("Accept-language: en-US,en,q=0.5\\r\\n".encode("utf-8"))
        return s
    except socket.error:
        return None

for _ in range(SOCKET_COUNT):
    s = create_socket()
    if s: sockets.append(s)

while True:
    for s in list(sockets):
        try:
            s.send(f"X-Keep-Alive: {random.randint(1, 5000)}\\r\\n".encode("utf-8"))
        except socket.error:
            sockets.remove(s)
    for _ in range(SOCKET_COUNT - len(sockets)):
        s = create_socket()
        if s: sockets.append(s)
    time.sleep(SLEEP_TIME)
""")
    
    # Uruchomienie wygenerowanego skryptu wewnątrz attacker_ns
    proc = run_cmd(f"python3 {slowloris_script}", ns=ATTACKER_NS, bg=True)
    
    # Slowloris potrzebuje czasu na wysycenie limitów i wyzwolenie detekcji. Dajemy max 35 sekund.
    engine, ttm = tail_logs_for_ban(ATTACKER_IP, timeout=35)
    proc.kill()
    
    is_dropped = is_ip_banned(ATTACKER_IP)
    
    # Zaliczamy test, jeśli atakujący został zablokowany (zazwyczaj przez L7 Heuristic lub GRU)
    if engine != "None" and is_dropped:
        report("E: L7 Slowloris", engine, ttm, f"{GREEN}PASS{RESET}")
    else:
        report("E: L7 Slowloris", engine, ttm, f"{RED}FAIL{RESET}")

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

def test_l4_udp_flood():
    print(f"\n{YELLOW}--- Scenario G: High-Rate L4 UDP Flood ---{RESET}")
    reset_environment()
    
    # Narzędzie hping3 zalewa serwer pakietami UDP (--udp --flood)
    # Atak ten jest całkowicie niewidoczny dla serwera Nginx!
    proc = run_cmd(f"hping3 --udp -p 80 --flood {SERVER_IP}", ns=ATTACKER_NS, bg=True)
    
    # Dajemy systemowi 25 sekund. Jeśli nie ma sztywnej reguły UDP, 
    # model GRU będzie potrzebował 15 sekund na analizę sekwencji.
    engine, ttm = tail_logs_for_ban(ATTACKER_IP, timeout=25)
    proc.kill()
    
    is_dropped = is_ip_banned(ATTACKER_IP)
    
    # Test zaliczony, jeśli jakikolwiek silnik podjął decyzję o blokadzie na poziomie XDP
    if engine != "None" and is_dropped:
        report("G: L4 UDP Flood", engine, ttm, f"{GREEN}PASS{RESET}")
    else:
        report("G: L4 UDP Flood", engine, ttm, f"{RED}FAIL{RESET}")

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

def test_mixed_traffic():
    print(f"\n{YELLOW}--- Scenario I: Mixed Traffic (Attacker + Legitimate) ---{RESET}")
    reset_environment()
    
    LEGIT_IP = "10.0.0.3"
    
    # Przypisujemy drugi adres IP do interfejsu w attacker_ns, aby symulować drugiego klienta
    run_cmd(f"ip addr add {LEGIT_IP}/24 dev veth_attacker", ns=ATTACKER_NS)
    
    # Uruchamiamy w tle legalnego klienta: wysyła 1 zapytanie na sekundę przez 25 sekund
    cmd_legit = f"bash -c 'for i in {{1..25}}; do curl -s --interface {LEGIT_IP} {HTTP_URL} > /dev/null; sleep 1; done'"
    proc_legit = run_cmd(cmd_legit, ns=ATTACKER_NS, bg=True)
    
    # Uruchamiamy atak z oryginalnego IP (10.0.0.2) 
    proc_attacker = run_cmd(f"hping3 -a {ATTACKER_IP} -S -p 80 -i u100000 {SERVER_IP}", ns=ATTACKER_NS, bg=True)
    
    # Czekamy na zablokowanie atakującego
    engine, ttm = tail_logs_for_ban(ATTACKER_IP, timeout=25)
    
    proc_attacker.kill()
    proc_legit.kill()
    
    # Sprawdzamy status obu adresów IP na zaporze XDP
    attacker_banned = is_ip_banned(ATTACKER_IP)
    legit_banned = is_ip_banned(LEGIT_IP)
    
    # Jeśli atakujący jest zablokowany, a legalny użytkownik NIE JEST zablokowany - test zaliczony
    if attacker_banned and not legit_banned:
        report("I: Mixed Traffic", engine, ttm, f"{GREEN}PASS{RESET}")
    else:
        report("I: Mixed Traffic", engine, ttm, f"{RED}FAIL{RESET}")

def test_l4_ack_flood():
    print(f"\n{YELLOW}--- Scenario J: TCP State Exhaustion (ACK Flood) ---{RESET}")
    reset_environment()
    
    # Narzędzie hping3 wysyła pakiety z samą flagą ACK (-A) z maksymalną prędkością (--flood)
    # Pakiety te mają za zadanie ominąć limity SYN_FLOOD_THRESHOLD i zmęczyć zaporę
    proc = run_cmd(f"hping3 -A -p 80 --flood {SERVER_IP}", ns=ATTACKER_NS, bg=True)
    
    # Atak wolumetryczny zostanie ucięty błyskawicznie przez heurystykę "non_syn_pkts".
    # Dajemy systemowi 5 sekund na mitygację.
    engine, ttm = tail_logs_for_ban(ATTACKER_IP, timeout=5)
    proc.kill()
    
    is_dropped = is_ip_banned(ATTACKER_IP)
    
    # Twój parser logów tail_logs_for_ban zakwalifikuje ten ban jako "L4 UDP Flood", 
    # ponieważ w control_plane.py użyliśmy słowa "UDP" w reason stringu dla tej reguły.
    if engine == "L4 UDP Flood" and is_dropped:
        # Wypisujemy "L4 Non-SYN Flood" dla lepszej czytelności w ostatecznej tabeli
        report("J: ACK Flood", "L4 Non-SYN Flood", ttm, f"{GREEN}PASS{RESET}")
    else:
        report("J: ACK Flood", engine, ttm, f"{RED}FAIL{RESET}")

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
    test_gru_stealth_syn()
    test_l7_slowloris()
    test_benign_traffic()
    test_l4_udp_flood()
    test_global_spoofed_syn()
    test_mixed_traffic()
    test_l4_ack_flood()
    
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
