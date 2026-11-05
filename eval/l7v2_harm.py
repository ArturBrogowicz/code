#!/usr/bin/env python3
"""The L7 v2 client-side harm metric, harm admission per class, and the server-side cross-check (docs/L7V2_DESIGN.md
section 5, D-V2; frozen in ml/l7v2_prereg.json "harm").

Pure analysis over what a run wrote; it starts nothing and sends nothing. The rules are the harm gate's
(eval/harm_gate.py: criterion, control_health, time_resolved, the floors and constants of the calibration record),
applied to closed-loop benign clients:

  * every benign client writes one row per request (ml/l7_gen.py --records): t_intended, t_sent, t_done, status, err,
    route_class, user, view, wave, t_nominal, t_origin (wall-clock seconds). A closed-loop client has no schedule
    within a view, so a sent request has t_intended = t_sent;
  * the never-sent guard, on each device's own closed-loop schedule (re-registered 2026-10-31, T-030 L7V2-01/02): a
    view's intended start is the completion of the device's previous view plus that one's pause, so one stall fails
    only the views that were slow and a paced kind's latency books no failure; a view whose intended start falls in the
    attack window and that has not started `never_sent_after_s` (10 s) after it counts every request it planned as
    failed (err never_sent) at that intended start. The plan is recomputed from the manifest (l7_benign.plan_client
    with the entity's kind, params and client seed), so a client that stalled, died or never started cannot hide its
    omissions;
  * Q is the share of the judged requests (a benign entity on a judged link profile, a route class with an SLO)
    whose t_intended is in the attack window and that returned 2xx within the class's SLO; p95 is over the
    successful ones. Per block: dQ = Q(C) - Q(U_k), dL = log2(p95(U_k) / p95(C)), and the same against the placebo C';
  * the server-side cross-check recomputes Q from nginx's $request_time for the same benign entities (access log,
    labelled by the manifest in time). A block is invalid for class k as a client-side artefact when its client-side
    dQ_k reaches 10 pp but the server-side Q(U_k) is at least 99 %;
  * harm admission: class k enters the P1 verdicts only if, over at least min_blocks valid blocks, U_k passes the
    criterion against C (dQ or dL), the placebo C' does not, and the record is frozen. A FAIL is V-D "no harm".

A run directory holds manifest.json (schema 2 or 3, with timeline.t0_wall and the entities' netem), records/
<entity_id>.csv[.gz] for the benign entities (a P3 capture
stores them flat, records_<entity_id>.csv.gz), access.log[.gz], and run.json {"role", "class", "checks": {"ok",
"reasons"}}. A block holds block.json {"block", "attempt", "seed", "calibration_sha256", "timeline": {"baseline_s",
"attack_s", "recovery_s"}, "order"} and the runs C, Cp, U_<class> (and M_<arm>_<class>).

    ./venv/bin/python eval/l7v2_harm.py CAMPAIGN --calibration FILE --class C3b [--dry-run] [--json OUT]
"""
import argparse
import collections
import csv
import gzip
import json
import math
import os
import random
import sys

import numpy as np

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(REPO, "ml"), os.path.join(REPO, "eval"), REPO):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import harm_gate as HG
import l7_benign
import l7v2_prereg

import l7_backend
import l7_dataset
import l7_ingest
import l7_webapp

RECORD_COLUMNS = ("t_intended", "t_sent", "t_done", "status", "err", "route_class", "user", "view", "wave",
                  "t_nominal", "t_origin")
NEVER_SENT = "never_sent"
PLAN_KINDS = tuple(l7_benign.KINDS) + tuple(l7_benign.L7V2_KINDS)   # the kinds whose generators record and whose plans
                                                                    # the guard recomputes (T-030 L7V2-05)
CONTROL, PLACEBO, ATTACK_PREFIX, MITIGATED_PREFIX = "C", "Cp", "U_", "M_"


class HarmError(ValueError):
    """The run or block does not follow the contract above."""


CONTROL_CLASS_MIN_N = 20        # D-058: the class floor of a control applies from this many judged requests (ml/p1_prereg_4.json)


def _rule():
    return l7v2_prereg.load()["harm"]


# --- the rows of one run ---------------------------------------------------------------------------------------------

def read_client_records(path):
    """A client's rows as a list of dicts (times as floats, nan for never)."""
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    out = []
    for r in rows:
        try:
            out.append({"t_intended": float(r["t_intended"]), "t_sent": float(r["t_sent"]), "t_done": float(r["t_done"]),
                        "status": float(r["status"]), "err": r["err"], "route_class": r["route_class"],
                        "user": int(r["user"]), "view": int(r["view"]), "wave": int(r["wave"]),
                        "t_nominal": float(r["t_nominal"]), "t_origin": float(r["t_origin"])})
        except (KeyError, ValueError) as exc:
            raise HarmError(f"{path}: {exc}") from exc
    return out


def planned_views(entity, duration_s):
    """{(user, view): (t_nominal_rel, [route classes of the planned requests], pause_s)} of a benign entity, recomputed
    from its manifest row exactly as its generator built it. A paced request is a one-request view whose pause is its
    gap."""
    plan = l7_benign.plan_client(entity["kind_or_family"], entity["params"], duration_s,
                                 random.Random(entity["client_seed"]))
    out = {}
    for u, user in enumerate(plan["users"]):
        if "views" in user:
            for v, view in enumerate(user["views"]):
                out[(u, v)] = (view["t"], [l7_webapp.route_class("GET", p) or "" for w in view["waves"] for p in w],
                               view["pause_s"])
        else:
            t = 0.0
            for v, (path, gap, *_rest) in enumerate(user["requests"]):
                out[(u, v)] = (t, [l7_webapp.route_class("GET", path) or ""], gap)
                t += gap
    return out


def _failed(t, klass, key, origin):
    return {"t_intended": t, "t_sent": math.nan, "t_done": math.nan, "status": math.nan, "err": NEVER_SENT,
            "route_class": klass, "user": key[0], "view": key[1], "wave": -1, "t_nominal": t, "t_origin": origin}


def with_never_sent(rows, planned, origin, window_abs, after_s=None, slips=None):
    """`rows` with the never-sent guard on each device's own closed-loop schedule (ml/l7v2_prereg.json harm, re-registered
    2026-10-31): a view's intended start is the completion of the device's previous view plus that one's pause (the first
    view's is its nominal start, origin + t; a view that never completed hands its intended start on). A view whose
    intended start is in window_abs and that did not start within `after_s` of it fails every request it planned, at that
    start; a started view's planned requests that have no row fail the same way. A paced request is a one-request view. With a list
    `slips`, each started view adds (actual start - intended start, intended start): a stall in mid-life shows there (T050-11)."""
    after_s = _rule()["never_sent_after_s"] if after_s is None else after_s
    lo, hi = window_abs
    by_view = {}
    for r in rows:
        by_view.setdefault((r["user"], r["view"]), []).append(r)
    out, judged = [], set()
    for user in sorted({u for u, _v in planned}):
        intended = None
        for key in sorted(k for k in planned if k[0] == user):
            t_rel, classes, pause = planned[key]
            intended = origin + t_rel if intended is None else intended
            got = by_view.get(key, [])
            judged.add(key)
            sent = [r["t_sent"] for r in got if not math.isnan(r["t_sent"])]
            if slips is not None and sent:
                slips.append((min(sent) - intended, intended))
            if lo <= intended < hi:
                if not sent or min(sent) - intended > after_s:
                    out += [_failed(intended, c, key, origin) for c in classes]
                    got = []
                else:
                    missing = collections.Counter(classes) - collections.Counter(r["route_class"] for r in got)
                    out += [_failed(intended, c, key, origin) for c in sorted(missing.elements())]
            out += got
            done = [r["t_done"] for r in by_view.get(key, []) if not math.isnan(r["t_done"])]
            intended = (max(done) if classes and len(done) >= len(classes) else intended) + pause
    out += [r for k, g in by_view.items() if k not in judged for r in g]
    return out


def run_rows(run_dir, manifest, window_rel, duration_s=None):
    """Every benign row of a run, with its entity's netem, after the never-sent guard, and which entities it covers:
    (rows, t0, {"recorded": [entity ids], "unrecorded": {kind: count}, "view_slip": the largest gap between a device's intended view
    start and its actual one, over the whole run, with its entity and its time from the run's start}). A kind without a plan (the P5
    kinds) writes no records and is left out, by name, here and in the server-side cross-check (T-030 L7V2-05, L7V2-10)."""
    t0 = l7_dataset.time_origin(manifest)
    if t0 is None:
        raise HarmError(f"{run_dir}: manifest timeline.t0_wall missing")
    window_abs = (t0 + window_rel[0], t0 + window_rel[1])
    out, cover = [], {"recorded": [], "unrecorded": {}, "view_slip": {"largest_s": 0.0, "entity": None, "at_s": None, "views": 0}}
    for e in manifest["entities"]:
        if e["role"] != "benign":
            continue
        if e["kind_or_family"] not in PLAN_KINDS:
            cover["unrecorded"][e["kind_or_family"]] = cover["unrecorded"].get(e["kind_or_family"], 0) + 1
            continue
        cover["recorded"].append(e["entity_id"])
        rows = []
        stem = e["entity_id"].replace(":", "_")
        for path in (os.path.join(run_dir, "records", stem + ".csv.gz"), os.path.join(run_dir, "records", stem + ".csv"),
                     os.path.join(run_dir, f"records_{stem}.csv.gz"), os.path.join(run_dir, f"records_{stem}.csv")):
            if os.path.isfile(path):
                rows = read_client_records(path)
                break
        dur = duration_s or (e["schedule"]["stop_s"] - e["schedule"]["start_s"])
        origin = rows[0]["t_origin"] if rows else t0 + e["schedule"]["start_s"]
        slips = []
        for r in with_never_sent(rows, planned_views(e, dur), origin, window_abs, slips=slips):
            r["netem"], r["entity"] = e["netem"], e["entity_id"]
            out.append(r)
        cover["view_slip"]["views"] += len(slips)
        for slip, intended in slips:
            if slip > cover["view_slip"]["largest_s"]:
                cover["view_slip"].update(largest_s=round(slip, 3), entity=e["entity_id"], at_s=round(intended - t0, 3))
    return out, t0, cover


# --- the figures of one run ------------------------------------------------------------------------------------------

def metrics(rows, cal, window_abs, t0, total_s):
    """Q, p95, failures by cause, per class and per link profile, and the 1-s bins, over the judged rows (harm_gate's
    definitions with a route class per row)."""
    slo = {k: v / 1000.0 for k, v in cal["slo_ms"].items()}
    judged_profiles = set(cal["judged_profiles"])
    lo, hi = window_abs
    col = {k: np.array([r[k] for r in rows], dtype=float) for k in ("t_intended", "t_sent", "t_done", "status")}
    err = np.array([r["err"] for r in rows], dtype=object)
    klass = np.array([r["route_class"] for r in rows], dtype=object)
    netem = np.array([r["netem"] for r in rows], dtype=object)
    has_slo = np.isin(klass, list(slo))
    limit = np.array([slo.get(k, 0.0) for k in klass])
    with np.errstate(invalid="ignore"):
        service = col["t_done"] - col["t_sent"]
        answered = (err == "") & ~np.isnan(col["t_sent"]) & ~np.isnan(col["t_done"])
        twoxx = (col["status"] >= 200) & (col["status"] < 300)
        ok = answered & twoxx & (service <= limit)
        in_window = (col["t_intended"] >= lo) & (col["t_intended"] < hi)
    judged = np.isin(netem, list(judged_profiles)) & has_slo
    wj = in_window & judged
    n, k_ok = int(wj.sum()), int((wj & ok).sum())
    failed = wj & ~ok
    causes = {"never_sent": int((failed & (err == NEVER_SENT)).sum()),
              "non_2xx": int((failed & answered & ~twoxx).sum()),
              "slow": int((failed & answered & twoxx).sum())}
    for name in sorted({str(e) for e in err[failed]} - {"", NEVER_SENT}):
        causes[name] = int((failed & (err == name)).sum())
    by_class = {}
    for c in sorted(set(klass[wj])):
        m = wj & (klass == c)
        by_class[c] = {"n": int(m.sum()), "ok": int((m & ok).sum()), "Q": 100.0 * int((m & ok).sum()) / int(m.sum()),
                       "p95_s": HG._q(service[m & ok], 0.95)}
    by_profile = {}
    for p in sorted(set(netem[in_window & has_slo])):
        m = in_window & has_slo & (netem == p)
        by_profile[p] = {"n": int(m.sum()), "ok": int((m & ok).sum()), "Q": 100.0 * int((m & ok).sum()) / int(m.sum()),
                         "p95_s": HG._q(service[m & ok], 0.95), "judged": p in judged_profiles}
    nb, okb = HG._bins(col["t_intended"][judged] - t0, ok[judged], math.ceil(total_s))
    return {"requests": n, "ok": k_ok, "Q": 100.0 * k_ok / n if n else None,
            "p95_s": HG._q(service[wj & ok], 0.95), "failures": {k: v for k, v in causes.items() if v},
            "unjudged_route": int((in_window & ~has_slo).sum()), "by_class": by_class, "by_profile": by_profile,
            **HG.time_resolved(nb, okb, lo - t0, hi - t0)}


def server_q(access_log, manifest, cal, window_rel, entities=None):
    """Q from nginx's $request_time for the benign entities on judged links, labelled by the manifest in time; with
    `entities`, only those (the client side's recorded entities, so both sides judge the same requests)."""
    t0 = l7_dataset.time_origin(manifest)
    label = l7_dataset.labeler(manifest)
    netem = {e["entity_id"]: e["netem"] for e in manifest["entities"]}
    slo = {k: v / 1000.0 for k, v in cal["slo_ms"].items()}
    judged = set(cal["judged_profiles"])
    n = ok = 0
    with l7_dataset.open_log(access_log) as fh:
        for line in fh:
            obj = l7_ingest.parse_l7_line(line)
            if obj is None or not obj.get("ip"):
                continue
            rt = l7_ingest._num(obj.get("rt"))
            t_rel = l7_ingest._num(obj.get("msec")) - rt - t0
            if not window_rel[0] <= t_rel < window_rel[1]:
                continue
            cls, _fam, _held, entity = label(obj["ip"], t_rel)
            klass = l7_webapp.route_class(obj.get("method") or "GET", obj.get("uri") or "")
            if cls != l7_dataset.BENIGN or netem.get(entity) not in judged or klass not in slo:
                continue
            if entities is not None and entity not in entities:
                continue
            status = int(l7_ingest._num(obj.get("status")))
            n += 1
            ok += 200 <= status < 300 and rt <= slo[klass]
    return {"requests": n, "ok": ok, "Q": 100.0 * ok / n if n else None}


# --- runs, blocks and admission --------------------------------------------------------------------------------------

def _json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError) as exc:
        raise HarmError(f"{path}: {exc}") from exc


def assess_run(run_dir, cal, timeline):
    """One run's client-side and server-side figures over the attack window of `timeline`."""
    manifest = _json(os.path.join(run_dir, l7_dataset.MANIFEST_FILE))
    meta = _json(os.path.join(run_dir, "run.json"))
    window = (float(timeline["baseline_s"]), float(timeline["baseline_s"]) + float(timeline["attack_s"]))
    total = sum(float(timeline[k]) for k in ("baseline_s", "attack_s", "recovery_s"))
    rows, t0, cover = run_rows(run_dir, manifest, window)
    m = metrics(rows, cal, (t0 + window[0], t0 + window[1]), t0, total)
    m["unrecorded"] = cover["unrecorded"]
    m["view_slip"] = cover["view_slip"]
    log = next((os.path.join(run_dir, n) for n in (l7_dataset.ACCESS_LOG_GZ, l7_dataset.ACCESS_LOG)
                if os.path.isfile(os.path.join(run_dir, n))), None)
    checks = meta.get("checks") if isinstance(meta.get("checks"), dict) else {"ok": False, "reasons": ["no checks"]}
    return {"name": os.path.basename(run_dir), "role": meta.get("role"), "class": meta.get("class"), "metrics": m,
            "server": server_q(log, manifest, cal, window, set(cover["recorded"])) if log else None, "checks": checks}


def window_figures(run_dir, cal, timeline, window_rel):
    """One run's client-side figures over a window of its own, in seconds from its start (P1's level window, D-053): the rows, the never-sent
    guard and the definitions of assess_run, which reads the attack window."""
    manifest = _json(os.path.join(run_dir, l7_dataset.MANIFEST_FILE))
    total = sum(float(timeline[k]) for k in ("baseline_s", "attack_s", "recovery_s"))
    rows, t0, _cover = run_rows(run_dir, manifest, window_rel)
    return metrics(rows, cal, (t0 + window_rel[0], t0 + window_rel[1]), t0, total)


def control_health(metrics, cal):
    """P1's control health (D-058, T050-10; ml/p1_prereg_4.json control_health): (reasons, small classes). eval/harm_gate.control_health,
    unchanged, on Q(C) and on the route classes with at least CONTROL_CLASS_MIN_N judged requests; a smaller class, where one slow export would
    decide the block (C5 holds 1-8 judged requests in a control), is reported, not judged."""
    classes = metrics["by_class"]
    judged = {k: c for k, c in classes.items() if c["n"] >= CONTROL_CLASS_MIN_N}
    small = {k: {f: c[f] for f in ("n", "ok", "Q")} for k, c in classes.items() if c["n"] < CONTROL_CLASS_MIN_N}
    return HG.control_health({**metrics, "by_class": judged}, cal), small


def assess_block(block_dir, cal):
    """Every class's block-level figures: dQ, dL against C and the placebo, validity and its reasons."""
    meta = _json(os.path.join(block_dir, "block.json"))
    for key in ("block", "attempt", "seed", "calibration_sha256", "timeline"):
        if key not in meta:
            raise HarmError(f"{block_dir}/block.json: needs {key}")
    runs = {n: assess_run(os.path.join(block_dir, n), cal, meta["timeline"]) for n in sorted(os.listdir(block_dir))
            if os.path.isfile(os.path.join(block_dir, n, "run.json"))}
    shared = [f"run {n} is missing" for n in (CONTROL, PLACEBO) if n not in runs]
    if CONTROL in runs:
        shared += [f"control: {r}" for r in control_health(runs[CONTROL]["metrics"], cal)[0]]
    for n in (CONTROL, PLACEBO):
        if n in runs and not runs[n]["checks"].get("ok"):
            shared += [f"{n}: {r}" for r in runs[n]["checks"].get("reasons", [])] or [f"{n}: not sound"]
    c = runs.get(CONTROL, {}).get("metrics")
    cp = runs.get(PLACEBO, {}).get("metrics")
    rule = _rule()["cross_check"]
    classes = {}
    for n, run in runs.items():
        if not n.startswith(ATTACK_PREFIX):
            continue
        k, u = n[len(ATTACK_PREFIX):], run["metrics"]
        reasons = list(shared)
        if not run["checks"].get("ok"):
            reasons += [f"{n}: {r}" for r in run["checks"].get("reasons", [])] or [f"{n}: not sound"]
        dq = HG._diff(c and c["Q"], u["Q"])
        server = run["server"]
        if dq is not None and dq >= rule["client_dq_pp"] and server and server["Q"] is not None \
                and server["Q"] >= rule["server_q_min"]:
            reasons.append(f"{n}: client-side dQ {dq:.1f} pp but server-side Q {server['Q']:.1f} %: "
                           "a client-side artefact")
        classes[k] = {"valid": not reasons, "reasons": reasons, "dQ": dq,
                      "dL": HG._log2_ratio(u["p95_s"], c and c["p95_s"]),
                      "dQ_placebo": HG._diff(c and c["Q"], cp and cp["Q"]),
                      "dL_placebo": HG._log2_ratio(cp and cp["p95_s"], c and c["p95_s"]),
                      "server_Q_U": server and server["Q"]}
    missing = sorted(set(meta.get("order") or ()) - set(runs))
    valid_all = not shared and not missing and all(r["checks"].get("ok") for r in runs.values()) and all(c["valid"] for c in classes.values())
    return {"dir": os.path.basename(block_dir), "block": meta["block"], "attempt": meta["attempt"],
            "seed": meta["seed"], "calibration_sha256": meta["calibration_sha256"], "runs": runs, "classes": classes,
            "valid_all": valid_all, "shared_reasons": shared}


def admission(blocks, cal, klass, dry_run=False):
    """Harm admission of class `klass` over assessed blocks (the last attempt of each block counts). Refuses a record
    that is not frozen unless dry_run, which labels the result."""
    if not dry_run:
        l7_backend.require_frozen(cal)
    gate = cal["gate"]
    reasons = []
    attempts = [{"scenario": f"l7v2-{klass}", "seed_namespace": "p1_live_eval", "block": b["block"],
                 "attempt": b["attempt"], "seed": b["seed"], "calibration_sha256": b["calibration_sha256"],
                 "valid": b["classes"].get(klass, {}).get("valid", False), "valid_all": b.get("valid_all", False)} for b in blocks]
    problems, reruns = HG.protocol_problems(attempts, cal)
    reasons += problems
    final = {}
    for b in sorted(blocks, key=lambda b: (b["block"], b["attempt"])):
        final[b["block"]] = b
    rows = [b["classes"][klass] for b in final.values() if klass in b["classes"]]
    valid = [r for r in rows if r["valid"]]
    if len(valid) < gate["min_blocks"]:
        reasons.append(f"{len(valid)} valid blocks for {klass}, fewer than {gate['min_blocks']}")
    crit = HG._criteria(valid, gate, HG.METRICS, "dQ", "dL")
    placebo = HG._criteria(valid, gate, HG.METRICS, "dQ_placebo", "dL_placebo")
    placebo_passed = any(x["passed"] for x in placebo.values())
    if placebo_passed:
        reasons.append("the placebo passed: the gate is not specific on these data")
    if reasons:
        verdict = "INVALID"
    elif any(x["passed"] for x in crit.values()):
        verdict = "ADMITTED"
    else:
        verdict = "V-D: no harm"
    return {"class": klass, "verdict": verdict, "admitted": verdict == "ADMITTED", "reasons": reasons,
            "label": l7_backend.label(cal), "dry_run": cal.get("status") != "frozen",
            "blocks_valid": len(valid), "blocks_total": len(rows), "reruns": reruns, "criteria": crit,
            "placebo": {"criteria": placebo, "passed": placebo_passed}}


def analyse(root, cal, klass, dry_run=False):
    dirs = [os.path.join(root, d) for d in sorted(os.listdir(root)) if os.path.isfile(os.path.join(root, d, "block.json"))]
    if not dirs:
        raise HarmError(f"{root}: no block.json under it")
    return admission([assess_block(d, cal) for d in dirs], cal, klass, dry_run)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("campaign")
    ap.add_argument("--calibration", required=True, help="the record the blocks ran under (frozen for a verdict)")
    ap.add_argument("--class", dest="klass", required=True, help="C2, C3a or C3b")
    ap.add_argument("--dry-run", action="store_true", help="allow a placeholder or measured record; labelled")
    ap.add_argument("--json")
    args = ap.parse_args(argv)
    try:
        cal, _status, _tag = l7_backend.load_record(args.calibration)
        res = analyse(args.campaign, cal, args.klass, args.dry_run)
    except (HarmError, l7_backend.RecordError, OSError) as exc:
        print(exc, file=sys.stderr)
        return 1
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(res, fh, indent=1, sort_keys=True)
            fh.write("\n")
    head = f"{res['label']}: " if res["label"] != "frozen" else ""
    print(f"{head}{res['class']} {res['verdict']}: {res['blocks_valid']} valid blocks of {res['blocks_total']}"
          + ("; " + "; ".join(res["reasons"]) if res["reasons"] else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
