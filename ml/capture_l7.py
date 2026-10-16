#!/usr/bin/env python3
"""Capture a labelled L7 request dataset (docs/L7_GRU_DESIGN.md §6; Phase P3).

Stands up the testbed with the multi-path origin app (l7_webapp) behind the capture
nginx (nginx_l7capture.conf — request handling identical to the deployed nginx.conf,
but the l7json access log goes to a lossless FILE), and drives it with diverse benign
clients and calibrated sub-threshold + held-out attacks (ml/l7_traffic, ml/l7_gen).
Writes a dataset directory (l7_dataset): manifest.json (provenance, seeds, the
IP->label map, the ground-truth attack schedule) + access.log. The trainer (P4) reads
it; labels come from the namespace plan, never from a model.

No control_plane daemon runs during capture: attacks are recorded unmitigated and the
log is lossless. The sub-threshold calibration (§7) is enforced so that WHEN the daemon
is on (P5) these scenarios are genuine heuristic-misses; a test cross-checks it offline.

This IS a VM workload (namespaces, veths, XDP-free, nginx + gunicorn in server_ns,
traffic). Run with sudo. `--plan` prints the calibrated plan and exits WITHOUT touching
the system (offline review).

    sudo ./venv/bin/python ml/capture_l7.py --duration 300 --benign 12 --seed 1
    ./venv/bin/python ml/capture_l7.py --plan --duration 300 --benign 12 --seed 1
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "ml"))
import l7_traffic

import l7_dataset

DEFAULT_OUT = "/var/tmp/ddos_l7_datasets"
CAPTURE_CONF = os.path.join(REPO, "nginx_l7capture.conf")
WEBAPP = "l7_webapp:app"
GEN = os.path.join(REPO, "ml", "l7_gen.py")
NETEM_PROFILES = ["perfect", "broadband", "mobile_3g", "mobile_bad"]
PROVENANCE_INPUTS = ["l7_webapp.py", "nginx_l7capture.conf", "ml/l7_gen.py",
                     "ml/l7_traffic.py", "l7_dataset.py", "control_plane.py", "nginx.conf",
                     "ml/l7_benign.py", "ml/l7_admissibility.py"]


def sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def assign_profiles(benign_clients, seed):
    """Balanced, seeded netem profile per benign client (lossy benign matters —
    the GRU_ONLY lossy FP lesson, tier1-gru-deployment memory)."""
    import random
    rng = random.Random(seed ^ 0x9E3779B9)
    order = list(range(len(benign_clients)))
    rng.shuffle(order)
    for rank, idx in enumerate(order):
        benign_clients[idx]["profile"] = NETEM_PROFILES[rank % len(NETEM_PROFILES)]
    return benign_clients


def render_conf(access_log_path):
    """A copy of the capture nginx conf with the l7json access_log pointed at this
    dataset's access.log (absolute path). Returns the conf text."""
    with open(CAPTURE_CONF, encoding="utf-8") as fh:
        conf = fh.read()
    old = "access_log /var/log/nginx/l7_capture.log l7json;"
    new = f"access_log {access_log_path} l7json;"
    if old not in conf:
        raise RuntimeError(f"{CAPTURE_CONF} missing expected access_log line")
    return conf.replace(old, new)


L7_NS_RE = re.compile(r"^[ab]_10_0_\d{1,3}_\d{1,3}$")
L7_VETH_RE = re.compile(r"^vo_[ab]_10_0_\d{1,3}_\d{1,3}$")


def l7_leftovers(netns_listing, link_names):
    """Pure: the namespaces and root-side veths that belong to an L7 capture/eval run
    (`b_<ip>` benign, `a_<ip>` attacker; veth `vo_<ns>`). The suite's cleanup_all() only
    knows `server_ns`/`legit_*`/`bot_*`, so without this every run leaked its clients."""
    ns = [line.split()[0] for line in netns_listing.splitlines()
          if line.strip() and L7_NS_RE.match(line.split()[0])]
    links = [n for n in link_names if L7_VETH_RE.match(n)]
    return ns, links


def cleanup_l7_topology():
    """Delete this runner's own client namespaces and veths. Returns (ns, veths) counts."""
    r = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True, check=False)
    lk = subprocess.run(["ip", "-br", "link", "show"], capture_output=True, text=True,
                        check=False)
    names = [x.split()[0].split("@")[0] for x in lk.stdout.splitlines() if x.strip()]
    ns, links = l7_leftovers(r.stdout, names)
    for n in ns:
        subprocess.run(["ip", "netns", "del", n], capture_output=True, check=False, timeout=10)
    for v in links:                    # usually gone with their namespace; harmless if so
        subprocess.run(["ip", "link", "del", v], capture_output=True, check=False, timeout=5)
    return len(ns), len(links)


def git_commit():
    res = subprocess.run(["git", "-C", REPO, "rev-parse", "HEAD"], check=False,
                         capture_output=True, text=True)
    return res.stdout.strip() or None


def build_plan(args):
    mix = getattr(args, "mix", "p5")
    benign, attackers, schedule, calib = l7_traffic.build_plan(
        args.seed, args.benign, args.duration,
        include_held_out=not args.no_held_out, include_flood=not args.no_flood,
        benign_mix=mix, gate_seeds=getattr(args, "gate_seeds", l7_traffic.GATE_SEEDS),
        launch_inadmissible=getattr(args, "launch_inadmissible", False))
    # The P5 clients get exactly the P5 profiles; P5b's added clients are balanced
    # among themselves (their own seed), so adding them changes nothing above.
    base = [c for c in benign if c.get("mix") != "overlap"]
    added = [c for c in benign if c.get("mix") == "overlap"]
    assign_profiles(base, args.seed)
    if added:
        assign_profiles(added, args.seed + 7919)
    return benign, attackers, schedule, calib


def gate_lines(gate):
    """The P5b benign admissibility gate as text (§7.2, §7.2.1), for --plan review."""
    title = (f"P5b benign admissibility gate ({gate['seeds']} simulated seeds x "
             f"{gate['duration_s']:.0f} s, service {gate['service_s'] * 1000:.0f} ms/request, "
             f"fastest profile):")
    header = (f"  {'kind':15s} {'params':34s} {'admissible':10s} {'peak1s':>6s} {'sus10':>6s} "
              f"{'sus60':>6s} {'rule_rps':>8s} {'inflight':>8s} {'estab':>5s}  trips (of seeds)")
    out = [title, header]
    for r in gate["benign"]:
        prm = ",".join(f"{k}={v}" for k, v in r["params"].items() if k != "first_visit_s")
        m, w = r["median"], r["worst"]
        out.append(f"  {r['kind']:15s} {prm[:34]:34s} {r['admissible']!s:10s} {m['peak_1s']:6d} "
                   f"{m['sustained_10s']:6.1f} {m['sustained_60s']:6.1f} "
                   f"{w['rule_rps_max']:8.1f} {w['inflight_max']:8d} {w['established_max']:5d}  "
                   f"{r['trips'] or '-'}" + ("  [held out]" if r.get("held_out") else ""))
    out.append("  fast attackers (closed-loop, same timing model):")
    for name, p in gate["fast_attackers"].items():
        out.append(f"    {name:24s} peak1s={p['peak_1s']:4d} sus10={p['sustained_10s']:5.1f} "
                   f"sus60={p['sustained_60s']:5.1f}")
    for name, o in gate["overlap"].items():
        out.append(f"  {name}: highest admissible benign {o['highest_admissible_benign']} vs "
                   f"lowest fast attacker {o['lowest_fast_attacker']} -> overlap={o['overlap']}")
    return out


def print_plan(args):
    benign, attackers, schedule, calib = build_plan(args)
    print(l7_traffic.summary())
    print(f"\ncalibrated: {calib['calibrated']}  (trained attacks all sub-threshold)")
    if "benign_gate" in calib:
        print()
        print("\n".join(gate_lines(calib["benign_gate"])))
        launched_bad = calib.get("launch_inadmissible")
        for d in calib["benign_dropped"]:
            verb = ("LAUNCHED despite gate (P5c.1 — the ban IS the evidence, §7.3.2)"
                    if launched_bad else "DROPPED (not launched; deterministic-layer FP, §7.2)")
            print(f"  {verb}: {d['kind']} {d['params']}")
    print(f"\nbenign clients ({len(benign)}):")
    for c in benign:
        tag = " [held out]" if c.get("held_out") else ""
        if c.get("gate_admissible") is False:
            tag += " [gate: inadmissible — expect a deterministic ban]"
        print(f"  {c['ip']:12s} {c['kind']:14s} :{c['port']} netem={c['profile']}{tag}")
    print(f"\nattackers ({len(attackers)}):")
    for a, s in zip(attackers, schedule):
        print(f"  {a['ip']:12s} {a['family']:20s} held_out={a['held_out']!s:5} "
              f"mech={a['mechanism']:6s} window=[{s['start_s']:.1f},{s['stop_s']:.1f}]s "
              f"params={a['params']}")
    return 0


class Capture:
    def __init__(self, args, out_dir):
        self.args = args
        self.out_dir = out_dir
        self.access_log = os.path.join(out_dir, l7_dataset.ACCESS_LOG)
        self.conf_path = os.path.join(out_dir, "nginx_l7capture.conf")
        self.procs = []           # (name, Popen) background generators/servers

    # ---- server stack: gunicorn(l7_webapp) + capture nginx in server_ns, NO daemon ----
    def start_stack(self, S):
        subprocess.run(["mkdir", "-p", "/var/log/nginx"], capture_output=True, check=False)
        open(self.access_log, "w").close()
        os.chmod(self.access_log, 0o666)          # nginx worker (nobody) writes it
        if not os.path.isfile("/etc/ssl/certs/nginx-selfsigned.crt"):
            subprocess.run(["openssl", "req", "-x509", "-nodes", "-days", "365",
                            "-newkey", "rsa:2048", "-keyout",
                            "/etc/ssl/private/nginx-selfsigned.key",
                            "-out", "/etc/ssl/certs/nginx-selfsigned.crt",
                            "-subj", "/C=PL/ST=Masovian/L=Warsaw/O=PoC/CN=twojadomena.pl"],
                           capture_output=True, check=False)
        with open(self.conf_path, "w", encoding="utf-8") as fh:
            fh.write(render_conf(self.access_log))
        self.procs.append(("gunicorn", S.run(
            S._srv([S.PYTHON_VENV, "-m", "gunicorn", "--chdir", REPO,
                    "--workers", "4", "--threads", "4", "-b", "0.0.0.0:8080", WEBAPP]),
            ns=S.SERVER_NS, bg=True)))
        time.sleep(1.5)
        self.procs.append(("nginx", S.run(S._srv(["nginx", "-c", self.conf_path]),
                                          ns=S.SERVER_NS, bg=True)))
        time.sleep(1.0)
        # Readiness: curl the origin from inside server_ns.
        for _ in range(40):
            r = S.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                       "--max-time", "2", S.HTTP_URL], ns=S.SERVER_NS, timeout=4)
            if r is not None and r.stdout.strip() in ("200", "301", "302"):
                return True
            time.sleep(0.5)
        return False

    def gen_cmd(self, S, node, role, duration):
        """The l7_gen command for one node. S is the suite module (passed in, never a
        module global: eval_l7 reuses this class from another module)."""
        params = dict(node.get("params", {}))
        name = node["kind"] if role == "benign" else node["family"]
        cmd = [S.PYTHON_VENV, GEN, "--role", role, "--host", S.SERVER_IP,
               "--port", str(node.get("port", 80)), "--duration", f"{duration:.1f}",
               "--seed", str(node.get("seed", 0)), "--params", json.dumps(params)]
        cmd += ["--kind", name] if role == "benign" else ["--family", name]
        return cmd

    def run_capture(self, S, benign, attackers, schedule):
        t0 = time.time()
        for c in benign:                          # benign run the whole capture
            self.procs.append((f"benign:{c['ip']}",
                               S.run(self.gen_cmd(S, c, "benign", self.args.duration),
                                     ns=f"b_{c['ip'].replace('.', '_')}", bg=True)))
        pending = sorted(zip(attackers, schedule), key=lambda x: x[1]["start_s"])
        launched = []
        while time.time() - t0 < self.args.duration:
            now = time.time() - t0
            while pending and pending[0][1]["start_s"] <= now:
                a, s = pending.pop(0)
                dur = max(1.0, s["stop_s"] - s["start_s"])
                ns = f"a_{a['ip'].replace('.', '_')}"
                role = "attack"
                self.procs.append((f"attack:{a['family']}:{a['ip']}",
                                   S.run(self.gen_cmd(S, a, role, dur), ns=ns, bg=True)))
                launched.append(a["family"])
                print(f"  [{now:6.1f}s] launched {a['family']} from {a['ip']} ({dur:.0f}s)")
            time.sleep(1.0)
        return t0, launched

    def kill_all(self):
        for name, p in self.procs:
            if p is not None and p.poll() is None:
                p.terminate()
        time.sleep(0.5)
        for name, p in self.procs:
            if p is not None and p.poll() is None:
                p.kill()


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--duration", type=float, default=300.0)
    ap.add_argument("--benign", type=int, default=12)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--no-held-out", action="store_true", help="omit held-out families")
    ap.add_argument("--no-flood", action="store_true", help="omit the mid-capture SYN flood")
    ap.add_argument("--mix", choices=("p5", "overlap"), default="p5",
                    help="benign mix: P5's 12 kinds, or + the P5b overlap kinds (§7.2)")
    ap.add_argument("--plan", action="store_true", help="print the plan and exit (offline)")
    args = ap.parse_args()

    if args.plan:
        return print_plan(args)

    if os.geteuid() != 0:
        sys.exit("[-] Must run as root (namespaces). Use sudo. (Use --plan for offline review.)")
    if not os.access(os.path.join(REPO, "venv/bin/python"), os.X_OK):
        sys.exit("[-] No venv at venv/bin/python in this checkout.")

    global S
    import test_distributed_suite as S

    benign, attackers, schedule, calib = build_plan(args)
    out_dir = os.path.join(args.out, time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
    os.makedirs(out_dir, exist_ok=True)
    print(f"[*] L7 capture → {out_dir}  (seed={args.seed}, {len(benign)} benign, "
          f"{len(attackers)} attackers, {args.duration:.0f}s)")

    cap = Capture(args, out_dir)
    ok = ready = False
    launched = []
    t0 = None
    try:
        S.cleanup_all()
        cleanup_l7_topology()           # leftovers of a crashed earlier run
        S.create_host_bridge()
        S.create_server_ns()
        for c in benign:
            S.create_client_ns(f"b_{c['ip'].replace('.', '_')}", c["ip"])
            S.apply_tc(f"b_{c['ip'].replace('.', '_')}", c["profile"])
        for a in attackers:
            S.create_client_ns(f"a_{a['ip'].replace('.', '_')}", a["ip"])
        ready = cap.start_stack(S)
        print(f"[{'+' if ready else '-'}] origin {'ready' if ready else 'NOT ready (continuing)'}.")
        t0, launched = cap.run_capture(S, benign, attackers, schedule)
        ok = True
    finally:
        cap.kill_all()
        lines = 0
        if os.path.isfile(cap.access_log):
            with open(cap.access_log, "rb") as fh:
                lines = sum(1 for _ in fh)
        S.cleanup_all()
        cleanup_l7_topology()
        print(f"[+] Topology cleaned up. access.log lines: {lines}")

    ip_map = l7_dataset.build_ip_map(benign, attackers)
    provenance = {
        "git_commit": git_commit(), "t0_wall": t0, "host": os.uname().nodename,
        "duration_s": args.duration, "n_benign": len(benign), "n_attackers": len(attackers),
        "benign_mix": args.mix,
        "operating_point": os.environ.get("OPERATING_POINT", "default"),
        "ready": ready, "completed": ok, "launched_families": launched,
        "inputs_sha256": {f: sha256(os.path.join(REPO, f)) for f in PROVENANCE_INPUTS},
        "calibration": calib,
    }
    manifest = l7_dataset.make_manifest(
        seed=args.seed, duration_s=args.duration, ip_map=ip_map, schedule=schedule,
        provenance=provenance, notes="L7 capture dataset (P3)")
    l7_dataset.write_dataset_manifest(os.path.join(out_dir, l7_dataset.MANIFEST_FILE), manifest)
    print(f"[+] Wrote {os.path.join(out_dir, l7_dataset.MANIFEST_FILE)}")
    print(f"[{'+' if ok and ready and lines > 0 else '!'}] capture "
          f"{'OK' if ok and ready and lines > 0 else 'REVIEW'}: "
          f"{lines} access-log lines, {len(launched)} attack windows launched.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
