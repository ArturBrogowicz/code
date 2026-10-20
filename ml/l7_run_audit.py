#!/usr/bin/env python3
"""Descriptive audits of recorded L7 evaluation runs (audit G-01, G-05, G-08).

Offline and read-only: no nginx, no sockets, no traffic, no XDP. Each RUN_DIR is an eval
run (manifest.json, summary.json, baselines.json, l7_record.jsonl[.gz]), e.g.
results/2026-10-16_l7-p5c4-eval/runA1.

  harm   Do the labelled attackers harm anyone? Server-side time ($request_time, ms) and
         success of BENIGN requests that started while at least one fast attacker
         (ml/p5b_report.FAST_FAMILIES) was active, against those that started while none
         was. Requests inside a volumetric-flood window (plus FLOOD_TAIL_S) are left out.
         docs/L7_GRU_DESIGN.md section 7 admits a scenario only if it causes measurable harm.
  roles  Who the GRU and the baselines flag, per run and per ROLE. A role is an IP with its
         kind (benign) or family (attack) and its netem profile; the same roles come back in
         every seed, so "20 attackers / 100 benign IPs" are 4 and 20 roles x seeds.
  rates  Realised request rate per client from the recording: requests, 1-s peak and the
         highest 60-s mean, to compare with what the plan specified.

    ./venv/bin/python ml/l7_run_audit.py harm|roles|rates RUN_DIR [RUN_DIR ...]
        [--md FILE] [--json FILE] [--all]
"""
import argparse
import collections
import gzip
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "ml"))
import p5b_report

import l7_engine as E

FLOOD_TAIL_S = 15.0
# The oracle settings the P5c.4 verdict chose (results/2026-10-16_l7-p5c4-eval/p5c4_report.md),
# plus B4 at the deployed policy threshold.
P5C4_SETTINGS = (("B2", "B2", "key:mean60s>10"), ("B3", "B3", "key:r=10,b=100"),
                 ("B4", "B4", "p>0.99x3"), ("B4@0.95", "B4", "p>0.95x3"))
HIGH_RATE_KINDS = ("browser_page", "cgnat_browsers", "api_bulk", "crawler_polite")


def _json(run_dir, name):
    with open(os.path.join(run_dir, name), encoding="utf-8") as fh:
        return json.load(fh)


def iter_objects(run_dir):
    """The l7json objects of a run's recording, in order."""
    for name in ("l7_record.jsonl.gz", "l7_record.jsonl"):
        path = os.path.join(run_dir, name)
        if os.path.isfile(path):
            opener = gzip.open if name.endswith(".gz") else open
            with opener(path, "rt", encoding="utf-8") as fh:
                for item in E.read_stream(fh):
                    if item[0] == "record":
                        yield item[1]
            return
    raise FileNotFoundError(f"no l7_record.jsonl[.gz] in {run_dir}")


def _pctl(values, q):
    v = sorted(values)
    return v[min(len(v) - 1, int(q * len(v)))] if v else None


def _r(x, nd=1):
    return None if x is None else round(float(x), nd)


def _run_name(run_dir):
    return os.path.basename(os.path.normpath(run_dir))


# ───────────────────────────────── harm ─────────────────────────────────

def harm(run_dir):
    manifest = _json(run_dir, "manifest.json")
    t0 = manifest["provenance"]["t0_wall"]
    sched = manifest["schedule"]
    fast = [(t0 + s["start_s"], t0 + s["stop_s"]) for s in sched
            if s.get("family") in p5b_report.FAST_FAMILIES]
    flood = [(t0 + s["start_s"], t0 + s["stop_s"] + FLOOD_TAIL_S) for s in sched
             if s.get("family") == "volumetric_flood"]
    benign = {ip for ip, e in manifest["ip_map"].items() if e.get("class") == "benign"}
    times = {"attackers_active": [], "no_attacker": []}
    ok = {k: [0, 0] for k in times}
    for obj in iter_objects(run_dir):
        if obj.get("ip") not in benign:
            continue
        start = float(obj["msec"]) - float(obj["rt"])
        if any(a <= start <= b for a, b in flood):
            continue
        key = "attackers_active" if any(a <= start <= b for a, b in fast) else "no_attacker"
        times[key].append(float(obj["rt"]) * 1000.0)
        ok[key][0] += 200 <= int(obj["status"]) < 400
        ok[key][1] += 1
    out = {"run": _run_name(run_dir)}
    for key, vals in times.items():
        out[key] = {"n": len(vals), "p50_ms": _r(_pctl(vals, 0.5)), "p95_ms": _r(_pctl(vals, 0.95)),
                    "p99_ms": _r(_pctl(vals, 0.99)),
                    "success": _r(ok[key][0] / ok[key][1], 4) if ok[key][1] else None}
    return out


def render_harm(rows):
    title = "**Benign server-side time and success, with and without a fast attacker active**"
    header = ("| Run | Attackers active: n, p50 / p95 / p99 (ms), success "
              "| No attacker: n, p50 / p95 / p99 (ms), success |")
    lines = [title, "", header, "|---|---|---|"]

    def cell(c):
        return (f"{c['n']}, {c['p50_ms']} / {c['p95_ms']} / {c['p99_ms']}, "
                f"{c['success']}") if c["n"] else "none"
    for r in rows:
        lines.append(f"| {r['run']} | {cell(r['attackers_active'])} | {cell(r['no_attacker'])} |")
    return "\n".join(lines) + "\n"


# ───────────────────────────────── roles ─────────────────────────────────

def roles(run_dir, settings=P5C4_SETTINGS):
    manifest = _json(run_dir, "manifest.json")
    summary = _json(run_dir, "summary.json")
    baselines = _json(run_dir, "baselines.json")
    ip_map = manifest["ip_map"]
    comp = {ip for ip, e in ip_map.items()
            if e.get("class") == "attack" and e.get("family") in p5b_report.FAST_FAMILIES}
    benign = {ip for ip, e in ip_map.items() if e.get("class") == "benign"}
    an = summary["analysis"]
    flagged = {"GRU": set(an.get("would_ban_ips", []))}
    for label, family, key in settings:
        flagged[label] = set(baselines["families"][family].get(key, []))
    det = set(an.get("det_banned_ips", {}))
    out = {"run": _run_name(run_dir), "seed": manifest.get("seed"),
           "comparison_attackers": len(comp), "benign_ips": len(benign),
           "deterministic_caught": len(det & comp), "detectors": {}}
    for label, ips in flagged.items():
        out["detectors"][label] = {
            "caught": len(ips & comp), "benign_flagged": len(ips & benign),
            "benign_roles": sorted(f"{ip} {ip_map[ip].get('kind')}/{ip_map[ip].get('profile')}"
                                   for ip in ips & benign)}
    return out


def roles_summary(rows):
    """Pooled counts and the benign flags per role (IP, kind, netem) over the runs."""
    labels = list(rows[0]["detectors"]) if rows else []
    pooled = {lab: {"caught": sum(r["detectors"][lab]["caught"] for r in rows),
                    "benign_flagged": sum(r["detectors"][lab]["benign_flagged"] for r in rows)}
              for lab in labels}
    by_role = {lab: collections.Counter(role for r in rows
                                        for role in r["detectors"][lab]["benign_roles"])
               for lab in labels}
    return {"runs": len(rows), "comparison_attackers": sum(r["comparison_attackers"] for r in rows),
            "benign_ips": sum(r["benign_ips"] for r in rows), "pooled": pooled,
            "benign_flags_by_role": {lab: dict(sorted(c.items())) for lab, c in by_role.items()}}


def render_roles(rows):
    if not rows:
        return ""
    labels = list(rows[0]["detectors"])
    lines = ["**Attackers caught / benign flagged, per run and detector**", "",
             "| Run | Seed | Deterministic engines | " + " | ".join(labels) + " |",
             "|---|---|---|" + "---|" * len(labels)]
    for r in rows:
        cells = " | ".join(f"{r['detectors'][lab]['caught']}/{r['comparison_attackers']} "
                           f"· {r['detectors'][lab]['benign_flagged']} benign" for lab in labels)
        lines.append(f"| {r['run']} | {r['seed']} | {r['deterministic_caught']}/"
                     f"{r['comparison_attackers']} | {cells} |")
    s = roles_summary(rows)
    lines += ["", "Pooled: " + "; ".join(
        f"{lab} {p['caught']}/{s['comparison_attackers']} attackers, {p['benign_flagged']}/"
        f"{s['benign_ips']} benign" for lab, p in s["pooled"].items()), "",
        "Benign flags by role (IP, kind/netem), number of runs:", ""]
    for lab, roles_ in s["benign_flags_by_role"].items():
        lines.append(f"* {lab}: " + ("; ".join(f"{k} x{v}" for k, v in roles_.items()) or "none"))
    return "\n".join(lines) + "\n"


# ───────────────────────────────── rates ─────────────────────────────────

def _max_in_window(times, width):
    best, j = 0, 0
    for i, t in enumerate(times):
        while t - times[j] > width:
            j += 1
        best = max(best, i - j + 1)
    return best


def rates(run_dir, everything=False):
    manifest = _json(run_dir, "manifest.json")
    ip_map = manifest["ip_map"]
    starts = collections.defaultdict(list)
    for obj in iter_objects(run_dir):
        try:
            starts[obj.get("ip")].append(float(obj["msec"]) - float(obj["rt"]))
        except (KeyError, TypeError, ValueError):
            continue
    rows = []
    for ip in sorted(ip_map, key=lambda s: tuple(int(x) for x in s.split("."))):
        e = ip_map[ip]
        keep = (e.get("class") == "attack" and e.get("family") in p5b_report.FAST_FAMILIES) \
            or e.get("kind") in HIGH_RATE_KINDS
        if not (everything or keep) or not starts.get(ip):
            continue
        t = sorted(starts[ip])
        rows.append({"ip": ip, "role": e.get("kind") or e.get("family"), "netem": e.get("profile"),
                     "requests": len(t), "peak_1s": _max_in_window(t, 1.0),
                     "max_60s_mean_rps": _r(_max_in_window(t, 60.0) / 60.0)})
    return {"run": _run_name(run_dir), "seed": manifest.get("seed"), "clients": rows}


def render_rates(rows):
    lines = ["**Realised request rates** (1-s peak; highest 60-s mean)", "",
             "| Run | IP | Role / netem | Requests | 1-s peak | 60-s mean (rps) |",
             "|---|---|---|---|---|---|"]
    for r in rows:
        for c in r["clients"]:
            lines.append(f"| {r['run']} | {c['ip']} | {c['role']} / {c['netem']} | {c['requests']} "
                         f"| {c['peak_1s']} | {c['max_60s_mean_rps']} |")
    return "\n".join(lines) + "\n"


VIEWS = {"harm": (harm, render_harm), "roles": (roles, render_roles), "rates": (rates, render_rates)}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("view", choices=sorted(VIEWS))
    ap.add_argument("runs", nargs="+", help="eval run directories")
    ap.add_argument("--md", help="write the table as Markdown")
    ap.add_argument("--json", help="write the data as JSON")
    ap.add_argument("--all", action="store_true", help="rates: every client, not just the "
                    "fast attackers and the high-rate benign kinds")
    args = ap.parse_args(argv)
    fn, render = VIEWS[args.view]
    rows = [fn(d, everything=args.all) if args.view == "rates" else fn(d) for d in args.runs]
    text = render(rows)
    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(text)
    if args.json:
        data = {"view": args.view, "runs": rows}
        if args.view == "roles":
            data["summary"] = roles_summary(rows)
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1)
            fh.write("\n")
    print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
