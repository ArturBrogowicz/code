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

    sudo ./venv/bin/python ml/capture_l7.py --pipeline legacy --duration 300 --benign 12 --seed 1
    ./venv/bin/python ml/capture_l7.py --pipeline legacy --plan --duration 300 --benign 12 --seed 1

A run refuses to start on uncommitted changes to tracked files (--allow-dirty overrides);
the manifest records the commit, branch and dirty state.

Two pipelines. `--pipeline p3` (the default, docs/P3_DATASET_DESIGN.md §4) draws a per-seed
address pool from 10.0.16.0/20 with a seeded role map, netem for every entity and per-entity
parameters (ml/l7_pools.py); the seed must be pre-registered for its role (ml/p3_prereg.json):

    ./venv/bin/python ml/capture_l7.py --plan --version 2026-11-v1 --seed 9201 --seed-role pilot

`--pipeline legacy` is the capture of 2026-10 (P3, P5, P5c: benign at 10.0.1.{i+1}, attackers
at 10.0.2.{j+1}, the same map for every seed), kept so that those runs can be reproduced.
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
DEPLOYED_CONF = os.path.join(REPO, "nginx.conf")
L7_SINK_MARKER = "# L7-SYSLOG-SINK"      # stands for the sink line in the deployed confs
WEBAPP = "l7_webapp:app"
GEN = os.path.join(REPO, "ml", "l7_gen.py")
NETEM_PROFILES = ["perfect", "broadband", "mobile_3g", "mobile_bad"]
PROVENANCE_INPUTS = ["l7_webapp.py", "nginx_l7capture.conf", "ml/l7_gen.py",
                     "ml/l7_traffic.py", "l7_dataset.py", "control_plane.py", "nginx.conf",
                     "ml/l7_benign.py", "ml/l7_admissibility.py"]
P3_INPUTS = ["ml/l7_pools.py", "ml/l7_store.py", "ml/p3_prereg.json", "ml/capture_l7.py"]


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


LIMIT_LINES = {               # the deployed default lines, in nginx.conf and the capture conf
    "nginx_limit_req_rps": ("rate=30r/s", "rate={}r/s"),
    "nginx_limit_req_burst": ("burst=100 nodelay", "burst={} nodelay"),
    "nginx_limit_conn": ("limit_conn connlimit 50;", "limit_conn connlimit {};"),
}


def render_limits(conf, heuristics="default"):
    """The conf text with nginx's limit_req / limit_conn set from a threshold profile
    (P5c.2, §7.3.3). Each default line must occur exactly once; everything else is
    untouched, and the default profile returns the text unchanged."""
    lim = l7_traffic.PROFILES[heuristics]
    for key, (old, fmt) in LIMIT_LINES.items():
        if conf.count(old) != 1:
            raise RuntimeError(f"nginx conf: expected exactly one {old!r}")
        conf = conf.replace(old, fmt.format(lim[key]))
    return conf


def render_conf(access_log_path, heuristics="default", error_log_path=None):
    """A copy of the capture nginx conf with the l7json access_log pointed at this
    dataset's access.log (absolute path), and nginx's limits from the `heuristics`
    profile. With error_log_path (P3) the error log moves there too. Returns the conf text."""
    with open(CAPTURE_CONF, encoding="utf-8") as fh:
        conf = fh.read()
    old = "access_log /var/log/nginx/l7_capture.log l7json;"
    new = f"access_log {access_log_path} l7json;"
    if old not in conf:
        raise RuntimeError(f"{CAPTURE_CONF} missing expected access_log line")
    conf = conf.replace(old, new)
    if error_log_path is not None:
        old_err = "error_log /var/log/nginx/error.log info;"
        if conf.count(old_err) != 1:
            raise RuntimeError(f"{CAPTURE_CONF}: expected exactly one {old_err!r}")
        conf = conf.replace(old_err, f"error_log {error_log_path} info;")
    return render_limits(conf, heuristics)


def render_l7_sink(conf, socket_path):
    """A deployed nginx conf with the syslog access_log for the daemon's L7 socket written
    in at its marker line. The default confs carry no sink (audit G-23): with no daemon bound
    to the socket nginx logs one "[warn] send() to syslog failed" per request, so only a runner
    that starts the daemon with L7_SHADOW=1 adds it. Exactly one marker line must occur and
    everything else is untouched."""
    if not re.fullmatch(r"/[\w./-]+", socket_path):
        raise ValueError(f"unusable L7 socket path {socket_path!r}")
    lines = conf.splitlines(keepends=True)
    hits = [i for i, line in enumerate(lines) if line.strip().startswith(L7_SINK_MARKER)]
    if len(hits) != 1:
        raise RuntimeError(f"nginx conf: expected exactly one {L7_SINK_MARKER!r} line, "
                           f"found {len(hits)}")
    i = hits[0]
    indent = lines[i][:len(lines[i]) - len(lines[i].lstrip())]
    lines[i] = f"{indent}access_log syslog:server=unix:{socket_path},nohostname,tag=l7 l7json;\n"
    return "".join(lines)


def write_deployed_conf(path, heuristics, socket_path):
    """Write the deployed nginx.conf as a runner with the L7 shadow engine serves it: the
    `heuristics` profile's limits (P5c.2; unchanged for `default`) plus the L7 sink.
    Returns `path`."""
    with open(DEPLOYED_CONF, encoding="utf-8") as fh:
        text = render_l7_sink(render_limits(fh.read(), heuristics), socket_path)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


L7_NS_RE = re.compile(r"^([ab]_10_0_\d{1,3}_\d{1,3}|l7n\d+_(perfect|broadband|mobile_3g|mobile_bad))$")
L7_VETH_RE = re.compile(r"^vo_([ab]_10_0_\d{1,3}_\d{1,3}|l7n\d+_[a-z0-9_]{0,10})$")


def l7_leftovers(netns_listing, link_names):
    """Pure: the namespaces and root-side veths that belong to an L7 capture/eval run
    (`b_<ip>` benign, `a_<ip>` attacker, `l7n<k>_<profile>` P3; veth `vo_<ns[:12]>`). The
    suite's cleanup_all() only knows `server_ns`/`legit_*`/`bot_*`, so without this every
    run leaked its clients."""
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


def _git(repo, *args):
    """Output of `git <args>` in `repo`, or None. Marked safe for this call: the runners run
    as root in a checkout owned by the user, which git refuses otherwise."""
    try:
        res = subprocess.run(["git", "-c", f"safe.directory={repo}", "-C", repo, *args],
                             capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return res.stdout.rstrip("\n") if res.returncode == 0 else None


def git_commit(repo=REPO):
    return _git(repo, "rev-parse", "HEAD") or None


def git_state(repo=REPO):
    """The code a run used, in the schema of the suite's provenance.json (audit G-14): commit,
    branch, dirty (uncommitted changes to tracked files) and the first 50 such files. Empty
    when `repo` is not a git checkout."""
    dirty = _git(repo, "status", "--porcelain", "--untracked-files=no")
    return {"commit": _git(repo, "rev-parse", "HEAD") or None,
            "branch": _git(repo, "rev-parse", "--abbrev-ref", "HEAD") or None,
            "dirty": None if dirty is None else bool(dirty),
            "dirty_files": dirty.splitlines()[:50] if dirty else []}


def require_clean_tree(allow_dirty, repo=REPO):
    """git_state(), or exit when tracked files have uncommitted changes (as
    eval/run_campaign.py does): a recorded run must name the code it ran. Returns the state
    to record in the run's manifest."""
    state = git_state(repo)
    if state["dirty"] and not allow_dirty:
        sys.exit("[-] uncommitted changes to tracked files:\n    "
                 + "\n    ".join(state["dirty_files"])
                 + "\n    commit them (a run must map to a commit) or pass --allow-dirty")
    return state


def build_plan(args):
    mix = getattr(args, "mix", "p5")
    benign, attackers, schedule, calib = l7_traffic.build_plan(
        args.seed, args.benign, args.duration,
        include_held_out=not args.no_held_out, include_flood=not args.no_flood,
        benign_mix=mix, gate_seeds=getattr(args, "gate_seeds", l7_traffic.GATE_SEEDS),
        launch_inadmissible=getattr(args, "launch_inadmissible", False),
        heuristics=getattr(args, "heuristics", "default"))
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


def p3_plan(args):
    """The P3 plan for these arguments (ml/l7_pools.build_plan), or exit with the reason."""
    import l7_pools
    try:
        return l7_pools.build_plan(args.version, args.seed, args.seed_role, args.population,
                                   heuristics=args.heuristics, scale=args.scale,
                                   gate_seeds=tuple(range(args.p3_gate_seeds)))
    except l7_pools.PlanError as exc:
        sys.exit(f"[-] P3 plan refused: {exc}")


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
            fh.write(render_conf(self.access_log, getattr(self.args, "heuristics", "default")))
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


def alias_batch(addresses, mask="/16", dev="veth_in"):
    """`ip -batch` input adding each address as an alias of a P3 client namespace's veth."""
    return "".join(f"addr add {a}{mask} dev {dev}\n" for a in addresses)


def host_record(workers, threads, conf_sha256):
    """The host block of a P3 manifest, in the shape of bench/calibration.py HOST_SHAPE as far as it
    applies to l7_webapp (origin and loadgen fields are None here)."""
    def out(cmd):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
            return (r.stdout + r.stderr).strip().splitlines()[0] if (r.stdout + r.stderr).strip() else None
        except (OSError, subprocess.SubprocessError):
            return None
    mem = None
    try:
        with open("/proc/meminfo", encoding="ascii") as fh:
            mem = int(fh.readline().split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    return {"uname": " ".join(os.uname()), "cpus": os.cpu_count(), "mem_mib": mem,
            "origin_seed": None, "origin_sha256": None, "loadgen_sha256": None, "pins": None,
            "gunicorn": {"version": out([sys.executable, "-m", "gunicorn", "--version"]),
                         "workers": workers, "threads": threads, "nofile": None},
            "nginx": {"version": out(["nginx", "-v"]), "conf_sha256": conf_sha256}}


class P3Capture(Capture):
    """The P3 capture (docs/P3_DATASET_DESIGN.md §4): one namespace per netem profile carrying its
    entities' addresses as aliases, every generator bound to its entity's address (l7_gen --source),
    the logs staged in the capture's own staging directory (no chmod: nginx's master opens them as
    root), gunicorn from the seed's server configuration."""

    def __init__(self, args, out_dir, staging, plan):
        super().__init__(args, out_dir)
        self.plan, self.staging = plan, staging
        self.access_log = os.path.join(staging, "access.log")
        self.error_log = os.path.join(staging, "error.log")

    def topology(self, S):
        for ns in self.plan["namespaces"]:
            S.create_client_ns(ns["name"], ns["addresses"][0])
            if ns["addresses"][1:]:
                subprocess.run(["ip", "netns", "exec", ns["name"], "ip", "-batch", "-"],
                               input=alias_batch(ns["addresses"][1:], S.SUBNET_MASK), text=True,
                               capture_output=True, check=False)
            S.apply_tc(ns["name"], ns["profile"])

    def start_stack(self, S):
        server = self.plan["server"]
        subprocess.run(["mkdir", "-p", "/var/log/nginx"], capture_output=True, check=False)
        if not os.path.isfile("/etc/ssl/certs/nginx-selfsigned.crt"):
            subprocess.run(["openssl", "req", "-x509", "-nodes", "-days", "365",
                            "-newkey", "rsa:2048", "-keyout",
                            "/etc/ssl/private/nginx-selfsigned.key",
                            "-out", "/etc/ssl/certs/nginx-selfsigned.crt",
                            "-subj", "/C=PL/ST=Masovian/L=Warsaw/O=PoC/CN=twojadomena.pl"],
                           capture_output=True, check=False)
        with open(self.conf_path, "w", encoding="utf-8") as fh:
            fh.write(render_conf(self.access_log, self.plan["heuristics"], self.error_log))
        self.procs.append(("gunicorn", S.run(
            S._srv([S.PYTHON_VENV, "-m", "gunicorn", "--chdir", REPO,
                    "--workers", str(server["gunicorn_workers"]),
                    "--threads", str(server["gunicorn_threads"]), "-b", "0.0.0.0:8080", WEBAPP]),
            ns=S.SERVER_NS, bg=True)))
        time.sleep(1.5)
        self.procs.append(("nginx", S.run(S._srv(["nginx", "-c", self.conf_path]),
                                          ns=S.SERVER_NS, bg=True)))
        time.sleep(1.0)
        for _ in range(40):
            r = S.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                       "--max-time", "2", S.HTTP_URL], ns=S.SERVER_NS, timeout=4)
            if r is not None and r.stdout.strip() in ("200", "301", "302"):
                return True
            time.sleep(0.5)
        return False

    def entity_cmd(self, S, e, duration):
        """The l7_gen command of one entity: its drawn params and client seed, bound to its address."""
        role = "benign" if e["role"] == "benign" else "attack"
        cmd = [S.PYTHON_VENV, GEN, "--role", role, "--host", S.SERVER_IP, "--port", str(e["port"]),
               "--duration", f"{duration:.1f}", "--seed", str(e["client_seed"]),
               "--params", json.dumps(e["params"], sort_keys=True), "--source", e["address"]]
        return cmd + (["--kind", e["kind_or_family"]] if role == "benign"
                      else ["--family", e["kind_or_family"]])

    def run_capture(self, S):
        t0 = time.time()
        pending = sorted(self.plan["entities"], key=lambda e: (e["schedule"]["start_s"], e["index"]))
        launched = 0
        while time.time() - t0 < self.plan["duration_s"]:
            now = time.time() - t0
            while pending and pending[0]["schedule"]["start_s"] <= now:
                e = pending.pop(0)
                dur = max(1.0, e["schedule"]["stop_s"] - e["schedule"]["start_s"])
                self.procs.append((e["entity_id"], S.run(self.entity_cmd(S, e, dur), ns=e["namespace"], bg=True)))
                launched += 1
            time.sleep(0.2)
        return t0, launched


def utc_iso(st):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", st)


def run_p3(args, plan):
    """The P3 capture: store checks, topology, stack, traffic, then the logs gzipped into the store,
    the schema-2 manifest, SHA256SUMS, and the files handed back to the store's owner."""
    import l7_store

    import l7_dataset as D
    try:
        vdir = l7_store.version_dir(args.store, args.version, l7_store.refused_roots(REPO))
    except l7_store.StoreError as exc:
        sys.exit(f"[-] {exc}")
    if os.geteuid() != 0:
        sys.exit("[-] Must run as root (namespaces). Use sudo. (Use --plan for offline review.)")
    if not os.access(os.path.join(REPO, "venv/bin/python"), os.X_OK):
        sys.exit("[-] No venv at venv/bin/python in this checkout.")
    git0 = require_clean_tree(False)
    if git0["dirty"] is not False:
        sys.exit("[-] a P3 capture needs a clean git checkout (code.dirty must be false)")
    try:
        uid, gid = l7_store.store_owner(args.store)
    except l7_store.StoreError as exc:
        sys.exit(f"[-] {exc}")
    global S
    import test_distributed_suite as S
    started = time.gmtime()
    cid = l7_store.capture_id(plan["seed"], started)
    out_dir, staging = l7_store.make_capture_dir(vdir, cid)
    print(f"[*] P3 capture -> {out_dir}  (seed={plan['seed']} {plan['seed_role']}, "
          f"{len(plan['entities'])} entities, {plan['duration_s']:.0f}s)")
    cap = P3Capture(args, out_dir, staging, plan)
    ok = ready = False
    t0, launched = None, 0
    try:
        S.cleanup_all()
        cleanup_l7_topology()
        S.create_host_bridge()
        S.create_server_ns()
        cap.topology(S)
        ready = cap.start_stack(S)
        print(f"[{'+' if ready else '-'}] origin {'ready' if ready else 'NOT ready (continuing)'}.")
        t0, launched = cap.run_capture(S)
        ok = True
    finally:
        cap.kill_all()
        S.cleanup_all()
        cleanup_l7_topology()
    ended = time.gmtime()
    files = l7_store.finalize_logs(staging, out_dir)
    files.append(D.file_record(cap.conf_path, os.path.basename(cap.conf_path)))
    conf_sha = files[-1]["sha256"]
    server = dict(plan["server"], heuristics=plan["heuristics"], nginx_conf_sha256=conf_sha,
                  calibration={"path": None, "sha256": None, "status": "absent"})
    manifest = D.make_manifest_v2(
        dataset_version=plan["dataset_version"], capture_id=cid, seed=plan["seed"],
        seed_role=plan["seed_role"], started_utc=utc_iso(started), ended_utc=utc_iso(ended),
        duration_s=plan["duration_s"],
        code={**git0, "inputs_sha256": {f: sha256(os.path.join(REPO, f))
                                        for f in PROVENANCE_INPUTS + P3_INPUTS}},
        server=server, host=host_record(plan["server"]["gunicorn_workers"],
                                        plan["server"]["gunicorn_threads"], conf_sha),
        pool=plan["pool"],
        timeline=dict(plan["timeline"], t0_wall=t0, ready=ready, completed=ok, launched=launched,
                      population=plan["population"], scale=plan["scale"], dropped=plan["dropped"]),
        entities=plan["entities"], files=files, notes="P3 capture (docs/P3_DATASET_DESIGN.md)",
        schema=plan.get("schema", 2))
    D.write_dataset_manifest(os.path.join(out_dir, D.MANIFEST_FILE), manifest)
    l7_store.write_sha256sums(vdir, cid)
    n = l7_store.hand_back(out_dir, uid, gid) + l7_store.hand_back(os.path.join(vdir, l7_store.SUMS), uid, gid)
    acc = next(f for f in files if f["path"] == D.ACCESS_LOG_GZ)
    good = ok and ready and acc["lines"] > 0
    print(f"[{'+' if good else '!'}] capture {'OK' if good else 'REVIEW'}: {acc['lines']} access-log lines, "
          f"{launched} entities launched, {n} paths handed back; manifest {manifest['manifest_sha256'][:12]}")
    return 0 if good else 1


def main_p3(args):
    import l7_pools
    if args.version is None or args.seed_role is None:
        sys.exit("[-] --pipeline p3 needs --version and --seed-role (see ml/p3_prereg.json)")
    plan = p3_plan(args)
    if args.plan:
        print("\n".join(l7_pools.summary_lines(plan)))
        return 0
    return run_p3(args, plan)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--duration", type=float, default=300.0)
    ap.add_argument("--benign", type=int, default=12)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--no-held-out", action="store_true", help="omit held-out families")
    ap.add_argument("--no-flood", action="store_true", help="omit the mid-capture SYN flood")
    ap.add_argument("--heuristics", choices=tuple(l7_traffic.PROFILES), default=None,
                    help="threshold profile for nginx limits and the benign gate (P5c.2); "
                         "default: 'default' (legacy), 'tolerant' (p3, as P5c.3)")
    ap.add_argument("--mix", choices=("p5", "overlap"), default="p5",
                    help="benign mix: P5's 12 kinds, or + the P5b overlap kinds (§7.2)")
    ap.add_argument("--plan", action="store_true", help="print the plan and exit (offline)")
    ap.add_argument("--allow-dirty", action="store_true",
                    help="run although tracked files have uncommitted changes (the manifest "
                         "then records them; legacy only)")
    ap.add_argument("--pipeline", choices=("p3", "legacy"), default="p3",
                    help="p3 (default): per-seed pools, netem for every entity, manifest schema 2; "
                         "legacy: the 2026-10 capture with its fixed map, to reproduce P3/P5/P5c")
    ap.add_argument("--version", help="p3: dataset version, <yyyy-mm>-<tag>")
    ap.add_argument("--seed-role", choices=("train", "val", "eval", "pilot"),
                    help="p3: the role the seed is pre-registered for (ml/p3_prereg.json)")
    ap.add_argument("--population", default="smoke", help="p3: population (ml/l7_pools.POPULATIONS)")
    ap.add_argument("--scale", type=int, default=1, help="p3: every entity count times this")
    ap.add_argument("--gate-seeds", type=int, default=len(l7_traffic.GATE_SEEDS), dest="p3_gate_seeds",
                    help="p3: simulated seeds of the benign admissibility gate")
    ap.add_argument("--store", default="/home/artur/datasets/l7",
                    help="p3: the dataset store; the capture goes to <store>/<version>/<capture_id>/ "
                         "(refused under /var/tmp, /tmp or the repository)")
    args = ap.parse_args()
    if args.heuristics is None:
        args.heuristics = "tolerant" if args.pipeline == "p3" else "default"
    if args.pipeline == "p3":
        return main_p3(args)

    if args.plan:
        return print_plan(args)

    if os.geteuid() != 0:
        sys.exit("[-] Must run as root (namespaces). Use sudo. (Use --plan for offline review.)")
    if not os.access(os.path.join(REPO, "venv/bin/python"), os.X_OK):
        sys.exit("[-] No venv at venv/bin/python in this checkout.")
    git0 = require_clean_tree(args.allow_dirty)

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
        "git_commit": git0["commit"], "git": git0, "t0_wall": t0, "host": os.uname().nodename,
        "duration_s": args.duration, "n_benign": len(benign), "n_attackers": len(attackers),
        "benign_mix": args.mix, "heuristics": args.heuristics,
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
