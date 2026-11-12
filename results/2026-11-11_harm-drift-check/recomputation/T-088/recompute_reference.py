"""T-088 (W-VERIFY), extra check: the frozen record's drift reference recomputed from its own raw runs (hg2_3/reference), and the two
ladder repeats at each family's knee (hg2_3/ladder_<family>), by the committed functions at argv[1] and by my own lines. Reads only;
writes the JSON named by argv[3]. usage: python -I -B recompute_reference.py WORKTREE RAW_SESSION OUT_JSON"""
import csv, glob, gzip, json, math, os, statistics, sys, types
WT, RAW, OUT = sys.argv[1:4]
sys.path.insert(0, os.path.join(WT, "bench")); sys.path.insert(0, os.path.join(WT, "eval"))
import calibration as C
import calibrate as K
import harm_gate as H
REC = os.path.join(WT, "bench", "calibration", "ddos-mitigation-2026-11-04.json")
cal = C.load(REC)
raw_cal = json.load(open(REC, encoding="utf-8"))
ref = raw_cal["drift_reference"]

def jload(p):
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)

def own(run_dir, window):
    run = jload(os.path.join(run_dir, "run.json")); lo, hi = window; n = 0; good = []
    for s in run["streams"]:
        if s["kind"] != "legit" or s["netem"] not in raw_cal["judged_profiles"]:
            continue
        limit = raw_cal["slo_ms"][s["route_class"]] / 1000.0
        with gzip.open(os.path.join(run_dir, s["records"]), "rt", newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                if not lo <= float(row["t_intended"]) + float(s["offset_s"]) < hi:
                    continue
                n += 1
                a, b, st = float(row["t_sent"]), float(row["t_done"]), float(row["status"])
                if row["err"] == "" and not math.isnan(a) and not math.isnan(b) and 200 <= st < 300 and b - a <= limit:
                    good.append(b - a)
    good.sort(); pos = 0.95 * (len(good) - 1); i = math.floor(pos); j = min(i + 1, len(good) - 1)
    return {"requests": n, "Q": 100.0 * len(good) / n, "p95_s": good[i] + (good[j] - good[i]) * (pos - i)}

def one(run_dir, kind):
    plan, env, runj = jload(os.path.join(run_dir, "plan.json")), jload(os.path.join(run_dir, "environment.json")), jload(os.path.join(run_dir, "run.json"))
    if kind == "legit":
        m1, window = K.probe_metrics(H.read_run(run_dir), cal), K.PROBE_WINDOW
    else:
        t = plan["timeline"]; window = (t["baseline_s"], t["baseline_s"] + t["attack_s"])
        m1 = K.attack_metrics(types.SimpleNamespace(out=run_dir, timeline=t), cal)
    m2 = own(run_dir, window)
    return {"dir": run_dir, "committed": m1, "own": m2,
            "agree": m1["requests"] == m2["requests"] and abs(m1["Q"] - m2["Q"]) < 1e-9 and abs(m1["p95_s"] - m2["p95_s"]) < 1e-9,
            "seed": plan.get("seed"), "level": plan.get("level"), "pins": plan.get("pins"), "sound": runj["executor"]["ok"],
            "started_utc": runj.get("started_utc"), "mem_mib": env["facts"]["mem_mib"], "cpus": env["facts"]["cpus"],
            "kernel": env["facts"]["uname"].split(" ")[2], "commit": (env.get("git") or {}).get("commit", "")[:7], "dirty": (env.get("git") or {}).get("dirty")}

out = {"reference_from_raw": {}, "knee_ladder_repeats": {}}
legit = [one(os.path.join(RAW, "reference", f"legit_{j}", "C"), "legit") for j in (1, 2, 3)]
out["reference_from_raw"]["legit_runs"] = legit
med_q = statistics.median(m["committed"]["Q"] for m in legit); med_p = statistics.median(m["committed"]["p95_s"] for m in legit)
out["reference_from_raw"]["legit_median"] = {"Q": med_q, "p95_s": med_p, "record_Q": ref["q_pct"], "record_p95_s": ref["p95_s"],
                                             "same": med_q == ref["q_pct"] and med_p == ref["p95_s"]}
print("legit probes:", [(m["seed"], round(m["committed"]["Q"], 4), round(m["committed"]["p95_s"], 6), m["agree"]) for m in legit],
      "median", med_q, med_p, "record", ref["q_pct"], ref["p95_s"], "SAME" if out["reference_from_raw"]["legit_median"]["same"] else "DIFFERENT")
for f in sorted(ref["attack"]):
    r = one(os.path.join(RAW, "reference", f"attack_{f}", "U"), "attack")
    rec = ref["attack"][f]
    r["record"] = rec; r["same_as_record"] = r["committed"]["Q"] == rec["q_pct"] and r["committed"]["p95_s"] == rec["p95_s"] and r["level"] == rec["level"]
    out["reference_from_raw"][f] = r
    print(f"reference {f}: seed {r['seed']} level {r['level']} Q {r['committed']['Q']:.4f} p95 {r['committed']['p95_s']:.6f} own-agree {r['agree']} "
          f"record {rec['q_pct']:.4f}/{rec['p95_s']:.6f} {'SAME' if r['same_as_record'] else 'DIFFERENT'} | mem {r['mem_mib']} kernel {r['kernel']} pins {r['pins']} commit {r['commit']} dirty {r['dirty']} {r['started_utc']}")
    reps = []
    for d in sorted(glob.glob(os.path.join(RAW, f"ladder_{f}", f"*_L{rec['level']:g}_r*", "U"))):
        x = one(d, "attack"); x["label"] = d.split(os.sep)[-2]; reps.append(x)
        print(f"   ladder {x['label']}: seed {x['seed']} sound {x['sound']} Q {x['committed']['Q']:.4f} p95 {x['committed']['p95_s']:.6f} own-agree {x['agree']} mem {x['mem_mib']} kernel {x['kernel']} {x['started_utc']}")
    out["knee_ladder_repeats"][f] = reps
    aside = sorted(glob.glob(os.path.join(RAW, f"ladder_{f}", f"*_L{rec['level']:g}_r*", "U.*")))
    if aside:
        print("   set aside:", aside)
print("legit host facts:", [(m["seed"], m["mem_mib"], m["kernel"], m["started_utc"], m["commit"], m["dirty"]) for m in legit])
json.dump(out, open(OUT, "w", encoding="utf-8"), indent=1, sort_keys=True)
