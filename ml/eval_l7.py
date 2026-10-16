#!/usr/bin/env python3
"""Online evaluation of the L7 GRU in SHADOW mode (docs/L7_GRU_DESIGN.md §7, §8; Phase P5).

Brings up the deployed stack — the multi-path origin behind the real nginx.conf, with the
control_plane daemon running `XDP_GRU=0` and the L7 shadow engine loaded with a model
package (`L7_MODEL`) — and drives it with the calibrated sub-threshold + held-out + slow
attacks and diverse benign clients (ml/l7_traffic, ml/l7_gen, reused from P3). The L7 GRU
NEVER bans here (shadow): the deterministic engines do the real banning, and we measure
whether the GRU *would* ban the sub-threshold abusers the heuristics miss, at what benign
cost, versus what a lower static threshold could do.

Measured from the daemon's own events (ban_events.jsonl) and its recorded engine input
(l7_record.jsonl), both lossless:
  * deterministic bans vs L7 `l7_would_ban`, per attacker family, with time-to-detect;
  * benign `l7_would_ban` (the false-positive rate);
  * flood suppression / age-gating while a volumetric flood runs;
  * H1b: a static-rps-threshold sweep on the recorded requests — could a lower threshold
    match the GRU without false-banning benign?
  * P5b (§7.2): baselines B0-B4 on the same recording (ml/l7_baselines), written to
    baselines.json after summary.json; ml/p5b_report.py applies the pre-registered verdict.

This IS a VM workload (namespaces, XDP via the real daemon, nginx+gunicorn, traffic,
one short SYN flood). Run with sudo. `--plan` prints the config and exits offline.

    sudo ./venv/bin/python ml/eval_l7.py --model results/2026-10-15_l7-p4-train/model \
        --duration 360 --benign 12 --seed 1
    sudo ./venv/bin/python ml/eval_l7.py --model <pkg> --soak --duration 600   # H3 benign soak
"""
import argparse
import collections
import json
import os
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "ml"))
import capture_l7
import l7_baselines
import l7_traffic

import l7_dataset
import l7_ingest

DEFAULT_OUT = "/var/tmp/ddos_l7_eval"
DETERMINISTIC = {"l4_syn", "l4_volumetric", "l4_slowconn", "l4_lowsyn", "l7_rate", "l7_rudy"}


class EvalRunner(capture_l7.Capture):
    """Capture runner, but the server stack also starts the daemon (XDP_GRU=0, L7 shadow
    with a model), and nginx uses the real nginx.conf (socket + file), as deployed."""

    def __init__(self, args, out_dir, model_path):
        super().__init__(args, out_dir)
        self.model_path = model_path
        self.events_path = os.path.join(out_dir, "ban_events.jsonl")
        self.record_path = os.path.join(out_dir, "l7_record.jsonl")
        self.daemon_log = os.path.join(out_dir, "daemon.log")
        self.daemon_proc = None

    def start_stack(self, S):
        subprocess.run(["mkdir", "-p", "/var/log/nginx"], capture_output=True, check=False)
        for lf in ("/var/log/nginx/ddos_ml_access.log", "/var/log/nginx/error.log"):
            open(lf, "w").close()
        if not os.path.isfile("/etc/ssl/certs/nginx-selfsigned.crt"):
            subprocess.run(["openssl", "req", "-x509", "-nodes", "-days", "365",
                            "-newkey", "rsa:2048", "-keyout",
                            "/etc/ssl/private/nginx-selfsigned.key",
                            "-out", "/etc/ssl/certs/nginx-selfsigned.crt",
                            "-subj", "/C=PL/ST=Masovian/L=Warsaw/O=PoC/CN=twojadomena.pl"],
                           capture_output=True, check=False)
        # Multi-path origin (so URIs carry signal), then the REAL nginx.conf (socket+file).
        self.procs.append(("gunicorn", S.run(
            S._srv([S.PYTHON_VENV, "-m", "gunicorn", "--chdir", REPO,
                    "--workers", "4", "--threads", "4", "-b", "0.0.0.0:8080",
                    capture_l7.WEBAPP]), ns=S.SERVER_NS, bg=True)))
        time.sleep(1.5)
        self.procs.append(("nginx", S.run(S._srv(["nginx", "-c", os.path.join(REPO, "nginx.conf")]),
                                          ns=S.SERVER_NS, bg=True)))
        time.sleep(1.0)
        # The daemon: real control_plane, XDP_GRU=0, L7 shadow engine with the candidate
        # model, events + engine-input recorded to this run's dir.
        env = ["env", "L7_SHADOW=1", "XDP_GRU=0", f"L7_MODEL={self.model_path}",
               f"BAN_EVENTS={self.events_path}", f"L7_RECORD={self.record_path}",
               f"L7_SOCKET_PATH={os.environ.get('L7_SOCKET_PATH', '/run/ddos_l7.sock')}"]
        cmd = ["ip", "netns", "exec", S.SERVER_NS, *env, S.PYTHON_VENV, "-u", S.CONTROL_PLANE]
        log_fd = open(self.daemon_log, "w")      # noqa: SIM115 (lives for the daemon's life)
        self.daemon_proc = subprocess.Popen(cmd, stdout=log_fd, stderr=subprocess.STDOUT)
        self.procs.append(("daemon", self.daemon_proc))
        for _ in range(120):
            try:
                with open(self.daemon_log, encoding="utf-8", errors="replace") as fh:
                    if "L7 shadow ingestion on" in fh.read():
                        return True
            except OSError:
                pass
            if self.daemon_proc.poll() is not None:
                return False
            time.sleep(0.5)
        return False


# ───────────────────────────── analysis (offline, testable) ─────────────────────────────

def read_events(path):
    out = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        pass
    return out


def analyse(events, manifest, t0):
    """Per-family: deterministic bans vs L7 would-bans and their time-to-detect from the
    attacker's scheduled start; benign would-ban FP; suppression/gating totals."""
    ip_map = manifest["ip_map"]
    sched_start = {s["ip"]: s["start_s"] for s in manifest["schedule"]}

    det_ban = {}        # ip -> (engine, t_rel)
    would = {}          # ip -> earliest t_rel of an l7_would_ban
    benign_would = collections.Counter()
    gru = collections.Counter()
    suppress_on = 0
    for e in events:
        k = e.get("kind")
        if k == "ban" and e.get("engine") in DETERMINISTIC:
            ip = e.get("ip")
            det_ban.setdefault(ip, (e["engine"], round(e["t_wall"] - t0, 2)))
        elif k == "l7_would_ban":
            ip = e.get("ip")
            cls, _, _ = l7_dataset.label_for(ip, ip_map)
            t_rel = round(e.get("t_poll", e.get("t_wall", t0)) - t0, 2)
            if cls == l7_dataset.BENIGN:
                benign_would[ip] += 1
            if ip not in would:
                would[ip] = t_rel
        elif k == "l7_gru_poll":
            for key in ("windows", "over", "would_bans", "gated_age", "suppressed_polls"):
                gru[key] += e.get(key, 0) or 0
        elif k == "suppress_on":
            suppress_on += 1

    families = {}
    for ip, ent in ip_map.items():
        if ent.get("class") != l7_dataset.ATTACK:
            continue
        fam = ent.get("family")
        f = families.setdefault(fam, {"ips": 0, "det_banned": 0, "would_banned": 0,
                                      "det_engines": set(), "ttd_would": [], "ttd_det": []})
        f["ips"] += 1
        start = sched_start.get(ip, 0.0)
        if ip in det_ban:
            f["det_banned"] += 1
            f["det_engines"].add(det_ban[ip][0])
            f["ttd_det"].append(round(det_ban[ip][1] - start, 2))
        if ip in would:
            f["would_banned"] += 1
            f["ttd_would"].append(round(would[ip] - start, 2))
    for f in families.values():
        f["det_engines"] = sorted(f["det_engines"])
        f["median_ttd_would_s"] = _median(f.pop("ttd_would"))
        f["median_ttd_det_s"] = _median(f.pop("ttd_det"))

    benign_ips = [ip for ip, e in ip_map.items() if e.get("class") == l7_dataset.BENIGN]
    return {"by_family": families,
            "would_ban_ips": sorted(would),
            "det_banned_ips": {ip: v[0] for ip, v in sorted(det_ban.items())},
            "benign_would_ban_ips": dict(benign_would),
            "benign_would_ban_count": int(sum(benign_would.values())),
            "benign_ips_total": len(benign_ips),
            "gru_totals": dict(gru), "suppress_on_events": suppress_on}


def _median(xs):
    if not xs:
        return None
    s = sorted(xs)
    n = len(s)
    return round((s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2), 2)


def select_attacks(attackers, schedule, *, soak=False, benign_only=False):
    """Which (attacker, schedule) entries actually run. Pure, so it is unit-tested.

    benign_only (P5c.1, docs/L7_GRU_DESIGN.md §7.3.2): drop ALL attackers — the
    realistic-benign false-positive baseline against the default heuristics, no attacks
    and no flood. soak: keep only the volumetric flood. Otherwise: everything runs.
    benign_only wins over soak if both are set.
    """
    if benign_only:
        return [], []
    if soak:
        keep = [(a, s) for a, s in zip(attackers, schedule, strict=True)
                if a["family"] == "volumetric_flood"]
        return [a for a, _ in keep], [s for _, s in keep]
    return attackers, schedule


def threshold_sweep(record_path, manifest, t0, window_s=1.0, thresholds=(10, 15, 20, 25, 30, 40, 50)):
    """H1b: for each static per-IP rps threshold, how many attacker IPs it would ban and
    how many benign IPs it would false-ban — from the recorded requests. A fair, offline
    'could a lower threshold do it?' baseline against the GRU's would-bans."""
    ip_map = manifest["ip_map"]
    times = collections.defaultdict(list)
    for item in read_events(record_path):            # records are {"rx":..,"obj":{...}}
        obj = item.get("obj") if isinstance(item, dict) else None
        if not obj:
            continue
        rec = l7_ingest.normalise(obj)
        if rec:
            times[rec["ip"]].append(rec["msec"])
    peak = {}
    for ip, ts in times.items():
        ts.sort()
        best = j = 0
        for i in range(len(ts)):
            while ts[i] - ts[j] > window_s:
                j += 1
            best = max(best, i - j + 1)
        peak[ip] = best / window_s
    rows = []
    for thr in thresholds:
        atk = sum(1 for ip, r in peak.items()
                  if r > thr and l7_dataset.label_for(ip, ip_map)[0] == l7_dataset.ATTACK)
        ben = sum(1 for ip, r in peak.items()
                  if r > thr and l7_dataset.label_for(ip, ip_map)[0] == l7_dataset.BENIGN)
        rows.append({"rps_threshold": thr, "attacker_ips_caught": atk, "benign_ips_flagged": ben})
    return {"deployed_l7_rate_ban_rps": l7_traffic.THRESHOLDS["l7_rate_ban_rps"],
            "per_ip_peak_rps": {ip: round(r, 1) for ip, r in sorted(peak.items())},
            "sweep": rows}


def build_report(out_dir, manifest, t0, model_path, args):
    events = read_events(os.path.join(out_dir, "ban_events.jsonl"))
    rep = {"out_dir": out_dir, "model": model_path, "soak": bool(args.soak),
           "duration_s": args.duration, "seed": args.seed, "t0_wall": t0,
           "git_commit": capture_l7.git_commit(),
           "model_sha256": capture_l7.sha256(os.path.join(model_path, "config.json")),
           "analysis": analyse(events, manifest, t0),
           "threshold_sweep": threshold_sweep(os.path.join(out_dir, "l7_record.jsonl"),
                                              manifest, t0)}
    return rep


# ───────────────────────────── orchestration ─────────────────────────────

def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--model", required=True, help="model package dir (L7_MODEL)")
    ap.add_argument("--duration", type=float, default=360.0)
    ap.add_argument("--benign", type=int, default=12)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--soak", action="store_true",
                    help="benign (+ one mid-run SYN flood): the H3 FP/suppression run")
    ap.add_argument("--benign-only", action="store_true",
                    help="P5c.1 (§7.3.2): benign generators ONLY — no attacks, no flood. The "
                         "realistic-benign false-positive baseline against the default heuristics")
    ap.add_argument("--no-held-out", action="store_true", help="omit held-out families")
    ap.add_argument("--no-flood", action="store_true", help="omit the mid-run SYN flood")
    ap.add_argument("--mix", choices=("p5", "overlap"), default="p5",
                    help="benign mix: P5's 12 kinds, or + the P5b overlap kinds (§7.2)")
    ap.add_argument("--hgb", help="package dir with baseline_hgb.* for B4 (default: --model)")
    ap.add_argument("--plan", action="store_true", help="print config and exit (offline)")
    args = ap.parse_args()

    if not os.path.isdir(args.model):
        sys.exit(f"[-] model package not found: {args.model}")

    # P5c.1 (§7.3.2): a benign-only run exists to document the DEFAULT heuristics banning
    # realistic benign, so it must LAUNCH the gate-inadmissible overlap kinds (the 60-asset
    # page, the CGNAT gateways) that a capture would otherwise drop. No attacks => no
    # dataset => no contamination risk from launching them.
    args.launch_inadmissible = args.benign_only and args.mix == "overlap"

    # benign_only drops every attacker (P5c.1); soak keeps only the volumetric flood.
    benign, attackers, schedule, _calib = capture_l7.build_plan(args)
    attackers, schedule = select_attacks(attackers, schedule, soak=args.soak,
                                         benign_only=args.benign_only)

    if args.plan:
        capture_l7.print_plan(args)
        print(f"\neval model: {args.model}  soak={args.soak}  benign_only={args.benign_only}  "
              f"XDP_GRU=0  L7 shadow (never bans)")
        print(f"attackers after filter: {[a['family'] for a in attackers]}")
        if args.benign_only:
            print("[P5c.1] benign-only: default heuristics may ban realistic benign IPs "
                  "(l4_slowconn / l7_rate) — that is the evidence being documented.")
        return 0

    if os.geteuid() != 0:
        sys.exit("[-] Must run as root. Use sudo. (Use --plan for offline review.)")

    global S
    import test_distributed_suite as S
    out_dir = os.path.join(args.out, time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
    os.makedirs(out_dir, exist_ok=True)
    os.environ.setdefault("L7_SOCKET_PATH", "/run/ddos_l7.sock")

    runner = EvalRunner(args, out_dir, args.model)
    t0 = ready = None
    print(f"[*] L7 eval → {out_dir}  (model {os.path.basename(args.model)}, "
          f"{len(benign)} benign, {len(attackers)} attackers, soak={args.soak})")
    try:
        S.cleanup_all()
        capture_l7.cleanup_l7_topology()   # leftovers of a crashed earlier run
        S.create_host_bridge()
        S.create_server_ns()
        for c in benign:
            S.create_client_ns(f"b_{c['ip'].replace('.', '_')}", c["ip"])
            S.apply_tc(f"b_{c['ip'].replace('.', '_')}", c["profile"])
        for a in attackers:
            S.create_client_ns(f"a_{a['ip'].replace('.', '_')}", a["ip"])
        ready = runner.start_stack(S)
        print(f"[{'+' if ready else '-'}] daemon + L7 shadow {'ready' if ready else 'NOT ready'}.")
        t0, _ = runner.run_capture(S, benign, attackers, schedule)
    finally:
        runner.kill_all()
        S.cleanup_all()
        capture_l7.cleanup_l7_topology()
        print("[+] Topology cleaned up.")

    ip_map = l7_dataset.build_ip_map(benign, attackers)
    note = ("L7 eval P5c.1 baseline: realistic benign only, default heuristics (shadow GRU)"
            if args.benign_only else "L7 eval (P5, shadow)")
    manifest = l7_dataset.make_manifest(seed=args.seed, duration_s=args.duration,
                                        ip_map=ip_map, schedule=schedule,
                                        provenance={"t0_wall": t0, "model": args.model,
                                                    "benign_mix": args.mix,
                                                    "benign_only": args.benign_only},
                                        notes=note)
    l7_dataset.write_dataset_manifest(os.path.join(out_dir, "manifest.json"), manifest)
    report = build_report(out_dir, manifest, t0 or 0.0, args.model, args)
    report["ready"] = ready
    with open(os.path.join(out_dir, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1, default=str)
        fh.write("\n")

    a = report["analysis"]
    print("\n=== L7 eval summary ===")
    for fam, f in sorted(a["by_family"].items()):
        print(f"  {fam:20s} ips={f['ips']} det_banned={f['det_banned']}{f['det_engines']} "
              f"would_banned={f['would_banned']} ttd_would={f['median_ttd_would_s']}s")
    print(f"  benign would-ban IPs: {a['benign_would_ban_count']} / {a['benign_ips_total']} "
          f"({a['benign_would_ban_ips']})")
    print(f"  GRU totals: {a['gru_totals']}  suppress_on: {a['suppress_on_events']}")
    print(f"[+] Wrote {os.path.join(out_dir, 'summary.json')}")
    try:                                  # never at the cost of the summary above
        bl = l7_baselines.compute(out_dir, args.hgb or args.model)
        with open(os.path.join(out_dir, "baselines.json"), "w", encoding="utf-8") as fh:
            json.dump(bl, fh, indent=1)
            fh.write("\n")
        print(f"[+] Wrote baselines.json (families {sorted(bl['families'])}); "
              f"benign shaped by nginx: {[ip for ip in bl['shaped_ips'] if ip_map.get(ip, {}).get('class') == 'benign']}")
    except (OSError, ValueError, KeyError) as exc:
        print(f"[!] baselines not computed ({exc}); rerun ml/l7_baselines.py {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
