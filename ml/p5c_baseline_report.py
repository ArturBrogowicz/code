#!/usr/bin/env python3
"""P5c.1 baseline report (docs/L7_GRU_DESIGN.md §7.3.2): what the DEFAULT deterministic
heuristics did to realistic benign traffic, from one benign-only evaluation run.

Reads the run directory written by `ml/eval_l7.py --mix overlap --benign-only`:
manifest.json, summary.json, ban_events.jsonl, l7_record.jsonl[.gz]. Per benign IP it
reports the client spec (rebuilt from the run's seeded plan and checked against the
manifest), the admissibility gate's prediction, the deterministic ban (engine, time,
measured value), nginx rejections, the measured rate profile up to the ban, and the
shadow GRU's would-bans. Then it compares the gate's predictions with what happened.

The measured profile is the input to the P5c.2 re-calibration (§7.3.3). Note: a banned
IP's traffic is dropped by XDP for the ban TTL, so its profile ends at the ban.

--timing-counterfactual MODEL replays the recorded engine input through MODEL twice: as
recorded, and with every request's server-side timing ($request_time,
$upstream_response_time) set to an unloaded server's (1 ms). If shadow would-bans vanish
in the second replay, the model's decisions depend on origin load, not on the client (R17).

    ./venv/bin/python ml/p5c_baseline_report.py RUN_DIR [--out report.json] [--md report.md] \
        [--timing-counterfactual MODEL_DIR]
"""
import argparse
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "ml"))
import l7_admissibility
import l7_baselines
import l7_traffic

import l7_engine

DETERMINISTIC = ("l4_syn", "l4_volumetric", "l4_slowconn", "l4_lowsyn", "l7_rate", "l7_rudy")


def _load(run_dir, name):
    with open(os.path.join(run_dir, name), encoding="utf-8") as fh:
        return json.load(fh)


def read_events(path):
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    return out


def plan_specs(manifest, n_benign):
    """IP -> (kind, params) for the overlap clients, rebuilt from the run's seeded plan
    (the manifest does not carry benign params). Checked against the manifest's kinds."""
    benign, _, _, calib = l7_traffic.build_plan(
        manifest["seed"], n_benign, manifest["duration_s"], benign_mix="overlap",
        launch_inadmissible=True)
    specs = {c["ip"]: (c["kind"], c.get("params", {})) for c in benign}
    for ip, e in manifest["ip_map"].items():
        if e.get("class") == "benign" and ip in specs and specs[ip][0] != e.get("kind"):
            raise ValueError(f"plan/manifest mismatch for {ip}: {specs[ip][0]} vs {e.get('kind')}")
    trips = {(r["kind"], json.dumps(r["params"], sort_keys=True)): r["trips"]
             for r in calib["benign_gate"]["benign"]}
    return specs, trips


def per_ip_requests(record_path):
    """IP -> list of normalised records (from the recorded engine input)."""
    out = {}
    for ip, ua, t, lreq in l7_baselines.load_requests(record_path):
        out.setdefault(ip, []).append({"ua": ua, "t": t, "lreq": lreq})
    return out


def first_bans(events, t0):
    bans = {}
    for e in events:
        if e.get("kind") == "ban" and e.get("engine") in DETERMINISTIC and e.get("ip") not in bans:
            bans[e["ip"]] = {"engine": e["engine"], "t_rel_s": round(e["t_wall"] - t0, 1),
                             "value": e.get("value"), "threshold": e.get("threshold"),
                             "bytes": e.get("bytes"), "error_ratio": e.get("error_ratio")}
    return bans


def lconn_rejects(record_path):
    """IP -> count of requests nginx's limit_conn rejected (raw `lconn` field)."""
    out = {}
    with l7_baselines._open(record_path) as fh:
        for item in l7_engine.read_stream(fh):
            if item[0] == "record" and (item[1].get("lconn") or "") == "REJECTED":
                ip = item[1].get("ip")
                out[ip] = out.get(ip, 0) + 1
    return out


def build(run_dir, n_benign=12):
    manifest = _load(run_dir, "manifest.json")
    summary = _load(run_dir, "summary.json")
    t0 = summary.get("t0_wall") or manifest["provenance"].get("t0_wall") or 0.0
    events = read_events(os.path.join(run_dir, "ban_events.jsonl"))
    record = l7_baselines.record_path(run_dir)
    specs, trips = plan_specs(manifest, n_benign)
    reqs = per_ip_requests(record)
    bans = first_bans(events, t0)
    lconn = lconn_rejects(record)
    would = summary["analysis"].get("benign_would_ban_ips", {})
    rows = []
    for ip, e in sorted(manifest["ip_map"].items(), key=lambda kv: tuple(map(int, kv[0].split(".")))):
        if e.get("class") != "benign":
            continue
        kind, params = specs.get(ip, (e.get("kind"), {}))
        rs = reqs.get(ip, [])
        times = [r["t"] for r in rs]
        prof = l7_admissibility.rate_profile(times) if times else {}
        key = (kind, json.dumps(params, sort_keys=True))
        rows.append({
            "ip": ip, "kind": kind,
            "spec": {k: v for k, v in params.items() if k in ("level", "users", "rps")},
            "netem": e.get("profile"), "held_out": bool(e.get("held_out")),
            "gate_admissible": e.get("gate_admissible", True),
            "gate_trips": trips.get(key, {}) if e.get("gate_admissible") is False else {},
            "det_ban": bans.get(ip),
            "requests": len(rs), "distinct_uas": len({r["ua"] for r in rs}),
            "limit_req_rejected": sum(1 for r in rs if r["lreq"] == "REJECTED"),
            "limit_conn_rejected": lconn.get(ip, 0),
            "profile": prof,
            "gru_would_bans": would.get(ip, 0)})
    banned = {r["ip"] for r in rows if r["det_ban"]}
    pred_bad = {r["ip"] for r in rows if r["gate_admissible"] is False}
    confusion = {"predicted_ban_and_banned": sorted(pred_bad & banned),
                 "predicted_ban_not_banned": sorted(pred_bad - banned),
                 "predicted_ok_but_banned": sorted(banned - pred_bad),
                 "predicted_ok_not_banned": sorted({r["ip"] for r in rows} - pred_bad - banned)}
    return {"run": os.path.basename(run_dir.rstrip("/")), "seed": manifest["seed"],
            "duration_s": manifest["duration_s"], "t0_wall": t0,
            "benign_ips": len(rows), "det_banned_benign": len(banned),
            "rows": rows, "gate_vs_live": confusion}


UNLOADED_S = 0.001


def unloaded_timing(item):
    """A stream item with the record's server-side timing set to an unloaded server's."""
    if item[0] != "record":
        return item
    obj = dict(item[1])
    obj["rt"], obj["urt"] = UNLOADED_S, str(UNLOADED_S)
    return ("record", obj)


def timing_counterfactual(record, model_dir):
    """Replay `record` through `model_dir` as recorded and with unloaded server timing.
    Returns {variant: {windows, over, would_bans, ips: {ip: count}}}."""
    import replay_l7
    import torch
    torch.set_num_threads(1)                       # as the daemon: bit-identical scores
    with l7_baselines._open(record) as fh:
        items = list(l7_engine.read_stream(fh))
    out = {}
    for name, its in (("as_recorded", items),
                      ("unloaded_timing", [unloaded_timing(i) for i in items])):
        events = replay_l7.replay(its, l7_engine.build_engine(model_dir))
        wb = [e for e in events if e.get("kind") == "l7_would_ban"]
        ips = {}
        for e in wb:
            ips[e["ip"]] = ips.get(e["ip"], 0) + 1
        sums = replay_l7._sums(events)
        out[name] = {"windows": sums["windows"], "over": sums["over"], "would_bans": len(wb),
                     "ips": dict(sorted(ips.items()))}
    return out


def to_markdown(rep):
    title = (f"Run `{rep['run']}` (seed {rep['seed']}, {rep['duration_s']:.0f} s): "
             f"{rep['det_banned_benign']} of {rep['benign_ips']} benign IPs banned by the "
             "default deterministic heuristics.")
    header = ("| IP | Kind | Spec | Netem | Gate | Deterministic ban | Requests | Peak 1 s | "
              "Sus 10 s | Sus 60 s | nginx 503 (req/conn) | GRU would-bans |")
    lines = [title, "", header, "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in rep["rows"]:
        b = r["det_ban"]
        ban = (f"**{b['engine']}** @ {b['t_rel_s']} s (value {b['value']}"
               + (f", bytes {b['bytes']}" if b.get("bytes") is not None else "") + ")") if b else "—"
        gate = "ok" if r["gate_admissible"] else f"trips {r['gate_trips'] or '?'}"
        p = r["profile"] or {}
        spec = ",".join(f"{k}={v}" for k, v in r["spec"].items()) or "—"
        lines.append(f"| {r['ip']} | {r['kind']} | {spec} | {r['netem']} | {gate} | {ban} | "
                     f"{r['requests']} | {p.get('peak_1s', '—')} | {p.get('sustained_10s', '—')} | "
                     f"{p.get('sustained_60s', '—')} | {r['limit_req_rejected']}/"
                     f"{r['limit_conn_rejected']} | {r['gru_would_bans']} |")
    c = rep["gate_vs_live"]
    lines += ["", "Gate prediction vs live:",
              f"- predicted ban, banned: {c['predicted_ban_and_banned']}",
              f"- predicted ban, NOT banned: {c['predicted_ban_not_banned']}",
              f"- predicted ok, but banned: {c['predicted_ok_but_banned']}",
              f"- predicted ok, not banned: {len(c['predicted_ok_not_banned'])} IPs"]
    cf = rep.get("timing_counterfactual")
    if cf:
        lines += ["", "Shadow GRU, server-timing counterfactual (R17):",
                  "| Replay | Windows | Over threshold | Would-bans | IPs flagged |",
                  "|---|---|---|---|---|"]
        for name, v in cf.items():
            lines.append(f"| {name} | {v['windows']} | {v['over']} | {v['would_bans']} | "
                         f"{len(v['ips'])}: {v['ips']} |")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("run_dir")
    ap.add_argument("--benign", type=int, default=12, help="P5 benign clients in the plan")
    ap.add_argument("--out")
    ap.add_argument("--md")
    ap.add_argument("--timing-counterfactual", metavar="MODEL_DIR",
                    help="replay the run through MODEL_DIR as recorded and with unloaded timing")
    args = ap.parse_args()
    rep = build(args.run_dir, args.benign)
    if args.timing_counterfactual:
        rep["timing_counterfactual"] = timing_counterfactual(
            l7_baselines.record_path(args.run_dir), args.timing_counterfactual)
        rep["timing_counterfactual_model"] = args.timing_counterfactual
    md = to_markdown(rep)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(rep, fh, indent=1)
            fh.write("\n")
    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(md + "\n")
    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
