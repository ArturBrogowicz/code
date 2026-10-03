#!/usr/bin/env python3
import http.server
import json
import psutil
import time
import datetime
import subprocess
import csv
import os

INTERFACE = "enp0s8"
CSV_FILE = "/tmp/mitigation_performance.csv"

def _read_softirqs_net_rx():
    try:
        with open("/proc/softirqs", "r") as f:
            for line in f:
                if line.strip().startswith("NET_RX:"):
                    return [int(x) for x in line.split()[1:]]
    except Exception:
        pass
    return []

def run_cmd(cmd):
    try:
        return subprocess.run(cmd.split(), capture_output=True, text=True).stdout
    except Exception:
        return ""

def capture_metrics_task(scenario, phase):
    # 1. Prime CPU metrics for target processes
    daemon_cpu, daemon_ram, nginx_cpu = 0.0, 0.0, 0.0
    daemon_procs, nginx_procs = [], []
    
    for p in psutil.process_iter(['name', 'cmdline']):
        try:
            cmdline = ' '.join(p.info['cmdline'] or [])
            if "control_plane.py" in cmdline:
                p.cpu_percent(interval=None)
                daemon_procs.append(p)
            elif "nginx" in p.info['name'] or "nginx" in cmdline:
                p.cpu_percent(interval=None)
                nginx_procs.append(p)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    def read_stats():
        try:
            with open(f"/sys/class/net/{INTERFACE}/statistics/rx_packets") as f:
                rx_p = int(f.read().strip())
            with open(f"/sys/class/net/{INTERFACE}/statistics/rx_bytes") as f:
                rx_b = int(f.read().strip())
            return rx_p, rx_b
        except Exception:
            return 0, 0

    # 2. Start snapshot
    softirq_before = _read_softirqs_net_rx()
    rx_p1, rx_b1 = read_stats()
    
    # Okno pomiarowe trwające dokładnie 1 sekundę
    cpu_total = psutil.cpu_percent(interval=1.0)
    per_core = psutil.cpu_percent(interval=0, percpu=True)
    
    # 3. End snapshot
    rx_p2, rx_b2 = read_stats()
    softirq_after = _read_softirqs_net_rx()

    # 4. Obliczanie przerwań sprzętowych
    if softirq_before and softirq_after and len(softirq_before) == len(softirq_after):
        softirq_delta = [a - b for a, b in zip(softirq_after, softirq_before)]
        softirq_total = sum(softirq_delta)
        hot_core_id = softirq_delta.index(max(softirq_delta)) if softirq_total > 0 else 0
        hot_core_softirq = softirq_delta[hot_core_id]
        hot_core_cpu = per_core[hot_core_id] if hot_core_id < len(per_core) else 0.0
    else:
        softirq_total, hot_core_softirq, hot_core_id, hot_core_cpu = 0, 0, -1, 0.0

    # 5. Odczyt CPU/RAM procesów po 1-sekundowym oknie
    for p in daemon_procs:
        try:
            daemon_cpu += p.cpu_percent(interval=None)
            daemon_ram += p.memory_info().rss / (1024 * 1024)
        except: pass
    for p in nginx_procs:
        try:
            nginx_cpu += p.cpu_percent(interval=None)
        except: pass

    mem_total = psutil.virtual_memory().used / (1024 * 1024)
    
    # 6. TCP States
    ss_res = run_cmd("ss -tan")
    tcp_estab = ss_res.count("ESTAB")
    tcp_tw = ss_res.count("TIME-WAIT")
    tcp_syn = ss_res.count("SYN-RECV")

    pps = rx_p2 - rx_p1
    bps = rx_b2 - rx_b1

    # 7. Zapis do CSV
    file_exists = os.path.isfile(CSV_FILE)
    with open(CSV_FILE, "a", newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["Timestamp", "Scenario", "Phase", "CPU_Total_Pct", 
                            "CPU_Daemon_Pct", "CPU_Nginx_Pct", "RAM_Total_MB", 
                            "RAM_Daemon_MB", "TCP_Estab", "TCP_TimeWait", 
                            "TCP_SynRecv", "PPS_Rx", "Bps_Rx",
                            "SoftIRQ_NET_RX_Total", "SoftIRQ_NET_RX_HotCore",
                            "HotCore_ID", "HotCore_CPU_Pct"])
        writer.writerow([
            datetime.datetime.now().isoformat(),
            scenario, phase,
            f"{cpu_total:.1f}", f"{daemon_cpu:.1f}", f"{nginx_cpu:.1f}",
            f"{mem_total:.1f}", f"{daemon_ram:.1f}",
            tcp_estab, tcp_tw, tcp_syn, pps, bps,
            softirq_total, hot_core_softirq,
            hot_core_id, f"{hot_core_cpu:.1f}"
        ])
    print(f"[+] Zapisano metryki: {scenario} - {phase} (PPS: {pps}, BPS: {bps})")

class MetricsHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        data = json.loads(post_data)
        
        scenario = data.get("scenario", "Unknown")
        phase = data.get("phase", "Unknown")
        
        # Wykonanie pomiaru synchronicznie, zablokuje HTTP na 1 sekundę
        capture_metrics_task(scenario, phase)
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"status": "ok"}')
        
    def log_message(self, format, *args):
        pass # Wyłączenie logów dostępu na konsoli

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[-] Uruchom z uprawnieniami root (aby poprawnie czytać procesy i ss)")
        exit(1)
    server = http.server.HTTPServer(('0.0.0.0', 9999), MetricsHandler)
    print(f"[*] API Metryk nasłuchuje na 0.0.0.0:9999...")
    print(f"[*] Plik docelowy: {CSV_FILE}")
    server.serve_forever()