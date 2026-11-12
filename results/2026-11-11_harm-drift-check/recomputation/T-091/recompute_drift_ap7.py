"""T-088 (W-VERIFY): Q and p95 of every run of the five raw drift directories, from the per-request records.

Route 1 calls the committed functions of the worktree given as argv[1] (1cdda9b): harm_gate.read_run / run_metrics through
calibrate.probe_metrics and calibrate.attack_metrics, and calibrate.drift_check for the D-062 single check.
Route 2 is this file's own few lines over the same loadgen.records.csv.gz files (stdlib only, no repository function).
Reads the raw directories and the frozen record; writes ONLY the JSON named by argv[3] and symlinks under argv[4].
It opens no drift.json, no summary and no producer file.

usage: python -I recompute_drift.py WORKTREE RAW_ROOT OUT_JSON LINK_DIR
"""
import csv
import gzip
import json
import math
import os
import statistics
import sys
import types

WT, RAW, OUT, LINKS = sys.argv[1:5]
sys.path.insert(0, os.path.join(WT, "bench"))
sys.path.insert(0, os.path.join(WT, "eval"))
import calibration as C          # noqa: E402  (committed code, route 1)
import calibrate as K            # noqa: E402
import harm_gate as H            # noqa: E402

REC = os.path.join(WT, "bench", "calibration", "ddos-mitigation-2026-11-04.json")
cal = C.load(REC)
with open(REC, encoding="utf-8") as fh:
    raw_cal = json.load(fh)      # route 2 reads the record as plain JSON
ref = raw_cal["drift_reference"]
FAMILIES = ("cheap_static_flood", "costly_export_flood", "costly_search_flood")
ATTEMPTS = [("AP-4 attempt 1", "drift_20261108"), ("AP-4 attempt 2", "drift_20261108.second"),
            ("AP-5 q1 attempt 1", "drift_20261108_q1"), ("AP-5 q1 attempt 2", "drift_20261108_q1.second"),
            ("AP-5b q1 attempt 1", "drift_20261110b_q1"),
            ("AP-7 q1 attempt 1", "drift_20261111c_q1"), ("AP-7 q1 attempt 2", "drift_20261111c_q1.second"),
            ("AP-7 q2 attempt 1", "drift_20261111c_q2")]


def jload(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def quantile_linear(sorted_values, q):
    """numpy's default ('linear') quantile, written out: the value at the virtual index q*(n-1)."""
    n = len(sorted_values)
    if not n:
        return None
    pos = q * (n - 1)
    lo = math.floor(pos)
    hi = min(lo + 1, n - 1)
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (pos - lo)


def own_metrics(run_dir, window):
    """Route 2: Q and p95 over the judged links' legit requests whose intended time on the run's axis is in [lo, hi)."""
    run = jload(os.path.join(run_dir, "run.json"))
    lo, hi = window
    n = ok_n = 0
    good, causes = [], {}
    for s in run["streams"]:
        if s["kind"] != "legit":
            continue
        limit = raw_cal["slo_ms"][s["route_class"]] / 1000.0
        judged = s["netem"] in raw_cal["judged_profiles"]
        with gzip.open(os.path.join(run_dir, s["records"]), "rt", newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                t_run = float(row["t_intended"]) + float(s["offset_s"])
                if not (judged and lo <= t_run < hi):
                    continue
                n += 1
                t_sent, t_done, status = float(row["t_sent"]), float(row["t_done"]), float(row["status"])
                answered = row["err"] == "" and not math.isnan(t_sent) and not math.isnan(t_done)
                service = t_done - t_sent
                if answered and 200 <= status < 300 and service <= limit:
                    ok_n += 1
                    good.append(service)
                else:
                    why = ("dropped" if row["err"] == "dropped" else "never_sent" if math.isnan(t_sent) else
                           "non_2xx" if answered and not 200 <= status < 300 else "slow" if answered else row["err"] or "other")
                    causes[why] = causes.get(why, 0) + 1
    good.sort()
    return {"requests": n, "ok": ok_n, "Q": 100.0 * ok_n / n if n else None, "p95_s": quantile_linear(good, 0.95), "failures": causes}


def facts_of(run_dir):
    """What the run directory itself records about the host and the layout (no figure of merit)."""
    out = {}
    env_p, plan_p, done_p, run_p = (os.path.join(run_dir, n) for n in ("environment.json", "plan.json", "DONE", "run.json"))
    if os.path.exists(env_p) and os.path.getsize(env_p):
        env = jload(env_p)
        out["env"] = {"facts": env.get("facts"), "gate": env.get("gate"), "gate_mode": env.get("gate_mode"), "git": env.get("git"),
                      "steal_jiffies": env.get("steal_jiffies"), "timer_probes": env.get("timer_probes"),
                      "timer_refused_probes": env.get("timer_refused_probes"), "timer_waited_s": env.get("timer_waited_s"),
                      "stack_cpus": {k: v.get("cpus_allowed") for k, v in (env.get("stack") or {}).items()},
                      "checked_utc": env.get("checked_utc"), "load1_after_timer_gate": env.get("load1_after_timer_gate")}
    if os.path.exists(plan_p) and os.path.getsize(plan_p):
        plan = jload(plan_p)
        out["plan"] = {"timeline": plan.get("timeline"), "pins": plan.get("pins"), "seed": plan.get("seed"), "kind": plan.get("kind"),
                       "scenario": plan.get("scenario"), "level": plan.get("level"), "calibration_sha256": plan.get("calibration_sha256"),
                       "streams": len(plan.get("streams") or [])}
    else:
        out["plan"] = None
        out["plan_json_bytes"] = os.path.getsize(plan_p) if os.path.exists(plan_p) else None
    out["DONE"] = jload(done_p) if os.path.exists(done_p) else None
    if os.path.exists(run_p) and os.path.getsize(run_p):
        run = jload(run_p)
        ex = run["executor"]
        out["run"] = {"role": run.get("role"), "scenario": run.get("scenario"), "seed": run.get("seed"), "level": run.get("level"),
                      "started_utc": run.get("started_utc"), "executor_ok": ex.get("ok"), "executor_reasons": ex.get("reasons"),
                      "setup_retries": ex.get("setup_retries"), "timer_refused_probes": ex.get("timer_refused_probes"),
                      "timer_waited_s": ex.get("timer_waited_s"), "legit_streams": sum(s["kind"] == "legit" for s in run["streams"]),
                      "attack_streams": sum(s["kind"] == "attack" for s in run["streams"])}
    else:
        out["run"] = None
    out["files"] = sorted(os.listdir(run_dir))
    return out


def as_named(run_dir, name):
    """harm_gate.read_run refuses a directory not called C or U; a run kept aside as U.failed1 is read through a symlink called U."""
    if os.path.basename(run_dir) == name:
        return run_dir
    link_parent = os.path.join(LINKS, run_dir.strip("/").replace("/", "__"))
    os.makedirs(link_parent, exist_ok=True)
    link = os.path.join(link_parent, name)
    if not os.path.islink(link):
        os.symlink(run_dir, link)
    return link


def measure(run_dir, kind):
    """Both routes for one run directory that has a run.json. kind: 'legit' or 'attack'."""
    facts = facts_of(run_dir)
    if facts["run"] is None:
        return {"dir": run_dir, "complete": False, "facts": facts}
    named = as_named(run_dir, "C" if kind == "legit" else "U")
    if kind == "legit":
        window = K.PROBE_WINDOW
        full = H.run_metrics(H.read_run(named), cal, {"baseline_s": K.PROBE_S, "attack_s": 1.0, "recovery_s": 1.0}, window=window)
        m1 = K.probe_metrics(H.read_run(named), cal)
    else:
        t = facts["plan"]["timeline"]
        window = (t["baseline_s"], t["baseline_s"] + t["attack_s"])
        full = H.run_metrics(H.read_run(named), cal, {k: t[k] for k in ("baseline_s", "attack_s", "recovery_s")})
        m1 = K.attack_metrics(types.SimpleNamespace(out=named, timeline=t), cal)
    m2 = own_metrics(run_dir, window)
    agree = (m1["requests"] == m2["requests"] and (m1["Q"] == m2["Q"] or abs(m1["Q"] - m2["Q"]) < 1e-9)
             and (m1["p95_s"] is None) == (m2["p95_s"] is None) and (m1["p95_s"] is None or abs(m1["p95_s"] - m2["p95_s"]) < 1e-9))
    return {"dir": run_dir, "complete": facts["DONE"] is not None, "sound": bool(facts["run"]["executor_ok"]), "window_s": list(window),
            "route1_committed": m1, "route2_own": m2, "routes_agree": agree,
            "route1_more": {k: full[k] for k in ("ok", "lost", "failures", "p50_s", "p99_s", "slip_p99_s", "judged_share", "by_class", "by_profile")},
            "facts": facts}


def single_check(legit, attacks):
    """D-062 as the tool applies it (calibrate.drift_check) and written out with the margins."""
    tool = K.drift_check(cal, legit, attacks)
    rows = {"legit": {"Q": legit["Q"], "ref_Q": ref["q_pct"], "dQ_pp": legit["Q"] - ref["q_pct"], "tol_pp": C.DRIFT_Q_PP,
                      "p95_s": legit["p95_s"], "ref_p95_s": ref["p95_s"], "p95_rel": legit["p95_s"] / ref["p95_s"] - 1.0, "tol_rel": C.DRIFT_P95}}
    rows["legit"]["ok"] = abs(rows["legit"]["dQ_pp"]) <= 2.0 + 1e-9 and abs(rows["legit"]["p95_rel"]) <= 0.25 + 1e-9
    for f, m in attacks.items():
        r = ref["attack"][f]
        row = {"Q": m["Q"], "ref_Q": r["q_pct"], "dQ_pp": m["Q"] - r["q_pct"], "tol_pp": raw_cal["gate"]["floor_pp"],
               "p95_s": m["p95_s"], "ref_p95_s": r["p95_s"], "log2_p95_ratio": math.log2(m["p95_s"] / r["p95_s"]),
               "tol_log2": raw_cal["gate"]["floor_log2_p95"]}
        row["ok_Q"] = abs(row["dQ_pp"]) <= row["tol_pp"] + 1e-9
        row["ok_p95"] = abs(row["log2_p95_ratio"]) <= row["tol_log2"] + 1e-9
        row["ok"] = row["ok_Q"] and row["ok_p95"]
        rows[f] = row
    own_ok = all(r["ok"] for r in rows.values())
    return {"tool_ok": tool["ok"], "tool_reasons": tool["reasons"], "own_ok": own_ok, "tool_and_own_agree": tool["ok"] == own_ok, "rows": rows}


def describe(values):
    values = [v for v in values if v is not None]
    n = len(values)
    return {"n": n, "mean": statistics.fmean(values) if n else None, "sd_sample": statistics.stdev(values) if n > 1 else None,
            "sd_population": statistics.pstdev(values) if n else None, "min": min(values) if n else None, "max": max(values) if n else None,
            "values": values}


result = {"task": "T-088", "worker": "W-VERIFY", "code": {"worktree": WT, "commit_expected": "1cdda9b"},
          "record": {"path": REC, "sha256_field": raw_cal["sha256"], "drift_reference": ref, "gate": raw_cal["gate"],
                     "slo_ms": raw_cal["slo_ms"], "judged_profiles": raw_cal["judged_profiles"], "host": raw_cal["host"]},
          "constants": {"PROBE_S": K.PROBE_S, "PROBE_WINDOW": list(K.PROBE_WINDOW), "DRIFT_Q_PP": C.DRIFT_Q_PP, "DRIFT_P95": C.DRIFT_P95,
                        "SEEDS_drift": K.SEEDS["drift"]},
          "attempts": {}}
for label, name in ATTEMPTS:
    base = os.path.join(RAW, name, "drift")
    att = {"dir": os.path.join(RAW, name), "runs": {}, "aside": {}, "drift_json_exists": os.path.exists(os.path.join(base, "drift.json"))}
    for part, kind, run_name in [("legit", "legit", "C")] + [(f"attack_{f}", "attack", "U") for f in FAMILIES]:
        key = "legit" if kind == "legit" else part[len("attack_"):]
        d = os.path.join(base, part, run_name)
        if os.path.isdir(d):
            att["runs"][key] = measure(d, kind)
        else:
            att["runs"][key] = {"dir": d, "complete": False, "exists": False}
        parent = os.path.join(base, part)
        if os.path.isdir(parent):
            for other in sorted(os.listdir(parent)):
                if other != run_name:
                    att["aside"][f"{key}/{other}"] = measure(os.path.join(parent, other), kind)
    runs = att["runs"]
    att["complete"] = all(r.get("complete") and r.get("sound") for r in runs.values())
    if att["complete"]:
        legit = runs["legit"]["route1_committed"]
        attacks = {f: runs[f]["route1_committed"] for f in FAMILIES}
        att["single_check_D062"] = single_check(legit, attacks)
    result["attempts"][label] = att

complete = [k for k, a in result["attempts"].items() if a["complete"]]
result["complete_attempts"] = complete
desc = {"note": "DESCRIPTIVE ONLY over the complete attempts; whether this is a pre-registered reading is decided by rule 5, not here",
        "Q": {}, "p95_s": {}, "log2_p95_ratio": {}}
for key in ("legit",) + FAMILIES:
    rows = [result["attempts"][k]["runs"][key]["route1_committed"] for k in complete]
    desc["Q"][key] = describe([r["Q"] for r in rows])
    desc["p95_s"][key] = describe([r["p95_s"] for r in rows])
    rp = ref["p95_s"] if key == "legit" else ref["attack"][key]["p95_s"]
    desc["log2_p95_ratio"][key] = describe([math.log2(r["p95_s"] / rp) for r in rows])
result["descriptive_complete_attempts"] = desc
# rule 1 of ap5_prereg.md written out over the complete attempts, as arithmetic only (labelled; see the report for whether it is a reading)
rule1 = {}
for f in FAMILIES:
    r = ref["attack"][f]
    rule1[f] = {"mean_Q": desc["Q"][f]["mean"], "ref_Q": r["q_pct"], "mean_dQ_pp": desc["Q"][f]["mean"] - r["q_pct"],
                "within_floor_pp_10": abs(desc["Q"][f]["mean"] - r["q_pct"]) <= raw_cal["gate"]["floor_pp"],
                "mean_log2_p95_ratio": desc["log2_p95_ratio"][f]["mean"],
                "within_floor_log2_1": abs(desc["log2_p95_ratio"][f]["mean"]) <= raw_cal["gate"]["floor_log2_p95"],
                "sd_sample_Q": desc["Q"][f]["sd_sample"], "sd_over_5pp": (desc["Q"][f]["sd_sample"] or 0) > 5.0}
rule1["legit"] = {"mean_Q": desc["Q"]["legit"]["mean"], "ref_Q": ref["q_pct"], "within_2pp": abs(desc["Q"]["legit"]["mean"] - ref["q_pct"]) <= 2.0,
                  "mean_p95_s": desc["p95_s"]["legit"]["mean"], "ref_p95_s": ref["p95_s"],
                  "mean_p95_rel": desc["p95_s"]["legit"]["mean"] / ref["p95_s"] - 1.0,
                  "within_25pct": abs(desc["p95_s"]["legit"]["mean"] / ref["p95_s"] - 1.0) <= 0.25}
result["rule1_arithmetic_over_complete_attempts_NOT_A_READING"] = rule1
with open(OUT, "w", encoding="utf-8") as fh:
    json.dump(result, fh, indent=1, sort_keys=True)
    fh.write("\n")

# a short table on stdout
for label, att in result["attempts"].items():
    print(f"== {label}  ({att['dir']})  complete={att['complete']}  drift.json present={att['drift_json_exists']}")
    for group in ("runs", "aside"):
        for key, r in att[group].items():
            if "route1_committed" not in r:
                print(f"   {group[:-1]:5s} {key:34s} INCOMPLETE files={r.get('facts', {}).get('files')}")
                continue
            m1, m2 = r["route1_committed"], r["route2_own"]
            print(f"   {group[:-1]:5s} {key:34s} sound={r['sound']!s:5s} n={m1['requests']:5d} Q={m1['Q']:.4f} p95={m1['p95_s']:.6f}"
                  f" | own n={m2['requests']:5d} Q={m2['Q']:.4f} p95={m2['p95_s']:.6f} agree={r['routes_agree']}"
                  f" | fail={r['route1_more']['failures']} wall={((r['facts'].get('DONE') or {}).get('seconds'))}")
            if not r["sound"]:
                print("         reasons:", r["facts"]["run"]["executor_reasons"])
    sc = att.get("single_check_D062")
    if sc:
        print(f"   D-062 single check: tool_ok={sc['tool_ok']} own_ok={sc['own_ok']} reasons={sc['tool_reasons']}")
        for k, row in sc["rows"].items():
            print("      ", k, {a: (round(b, 4) if isinstance(b, float) else b) for a, b in row.items()})
print("complete attempts:", complete)
print(json.dumps(result["descriptive_complete_attempts"]["Q"], indent=1))
print(json.dumps(rule1, indent=1))
