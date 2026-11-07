"""P1's premise check (ml/p1_prereg_5.json premise, D-073): on the pilot plans at nominal times, each ladder level's sources against the
benign per-key window maxima. It writes ml/p1_premise.json before any ladder run; the analysis keeps a level marked 'crosses' from ever
becoming a knee.

A key is an (address, UA) pair, as the rule arms key (docs/L7V2_DESIGN.md section 19). Its window maximum over w seconds is the largest
number of its requests in any w-second window, over w. The benign side pools every pilot seed's benign keys (the full mix, no halving) and
takes the registered quantile of their maxima per window; a level's side takes the largest maximum of its primary family's sources over the
two ladder blocks the seed map gives it. A level 'evades' when that stays below the benign quantile on every window, and 'crosses' otherwise,
naming the windows. Plans only: nothing is sent, and no knee or harm is read.

    python eval/p1_premise.py --calibration bench/calibration/ddos-mitigation-2026-11-04.json --date 2026-11-07 --out ml/p1_premise.json
"""
import argparse
import json
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
for _p in (os.path.join(REPO, "ml"), os.path.join(REPO, "bench"), REPO):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import l7_pools as LP
import p1_traffic as PT

PREMISE_FILE = os.path.join(REPO, "ml", "p1_premise.json")
FORMAT = "p1-premise/1"


def key_times(rows):
    """{(address, UA): sorted request times at nominal times} of the rows that have a plan; and how many rows have none."""
    out, planless = {}, 0
    for e in rows:
        plan = LP._plan_of(e)
        if plan is None:
            planless += 1
            continue
        start = e["schedule"]["start_s"]
        for u in plan["users"]:
            for t, _path in LP.nominal_requests(u):
                out.setdefault((e["address"], u.get("ua")), []).append(start + t)
    return {k: sorted(v) for k, v in out.items()}, planless


def window_max(times, w):
    """The largest number of requests in any w-second window, over w (req/s)."""
    best, lo = 0, 0
    for hi, t in enumerate(times):
        while t - times[lo] >= w:
            lo += 1
        best = max(best, hi - lo + 1)
    return best / w


def quantile(values, q):
    """The q quantile as the ceil(q n)-th smallest value; None of nothing."""
    v = sorted(values)
    return v[max(0, math.ceil(q * len(v)) - 1)] if v else None


def premise(record_path, *, seeds=None, benign_specs=None, max_sources=None):
    """The marks of every registered ladder level, as data (see the module docstring)."""
    import p3_prereg

    import l7_backend
    rule = PT.prereg_5()["premise"]
    windows, q = rule["windows_s"], rule["quantile"]
    seeds = list(seeds or p3_prereg.load()["seeds"][PT.ROLES["pilot"]])
    rec = l7_backend.load_record(record_path)[0]
    benign = {w: [] for w in windows}
    keys = planless = 0
    for seed in seeds:
        b = PT.build_block(seed, "pilot", {}, record_path=record_path, benign_specs=benign_specs)
        times, none = key_times(b["benign"])
        keys, planless = keys + len(times), planless + none
        for ts in times.values():
            for w in windows:
                benign[w].append(window_max(ts, w))
    floor = {w: quantile(benign[w], q) for w in windows}
    levels = {}
    for cls in sorted(PT.PRIMARY):
        levels[cls] = {}
        for lv in PT.ladder_levels(cls):
            row = {"seeds": [PT.ladder_seed(cls, lv, r) for r in range(1, PT.ladder_repeats() + 1)]}
            maxima, n = {w: [] for w in windows}, 0
            try:
                for seed in row["seeds"]:
                    b = PT.build_block(seed, "pilot", {cls: lv}, record_path=record_path, benign_specs=benign_specs, max_sources=max_sources)
                    times, _none = key_times([e for e in b["attack"][cls] if e["kind_or_family"] == PT.PRIMARY[cls]])
                    n += len(times)
                    for ts in times.values():
                        for w in windows:
                            maxima[w].append(window_max(ts, w))
            except PT.PlanError as exc:
                levels[cls][f"{lv:g}"] = {**row, "mark": "not computed", "why": str(exc)}
                continue
            top = {w: max(maxima[w]) for w in windows}
            crosses = [w for w in windows if top[w] >= floor[w]]
            levels[cls][f"{lv:g}"] = {**row, "keys": n, "max_req_s": {str(w): round(top[w], 4) for w in windows},
                                      "mark": "crosses" if crosses else "evades", "crosses_s": crosses}
    return {"format": FORMAT, "rule": "ml/p1_prereg_5.json premise", "windows_s": windows, "quantile": q,
            "record": {"path": os.path.relpath(os.path.abspath(record_path), REPO), "sha256": rec.get("sha256")},
            "benign": {"seeds": seeds, "keys": keys, "rows_without_a_plan": planless,
                       "quantile_req_s": {str(w): round(floor[w], 4) for w in windows}},
            "levels": levels}


def marks(path=None):
    """{(class, level): mark} of the pinned file; empty when it is missing."""
    path = path or PREMISE_FILE
    if not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as fh:
        got = json.load(fh)
    return {(cls, float(lv)): row["mark"] for cls, rows in got["levels"].items() for lv, row in rows.items()}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--calibration", required=True)
    ap.add_argument("--date", required=True, help="the day it is written, before any ladder run")
    ap.add_argument("--out", default=PREMISE_FILE)
    args = ap.parse_args(argv)
    res = {**premise(args.calibration), "date": args.date}
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=1, sort_keys=True)
        fh.write("\n")
    for cls, rows in res["levels"].items():
        print(f"{cls}: " + "; ".join(f"{lv} {row['mark']}" + (f" ({row['crosses_s']})" if row.get("crosses_s") else "")
                                     for lv, row in rows.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
