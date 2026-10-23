#!/usr/bin/env python3
"""Tabulate the runs of an EXP-C probe (docs/EXPC_ATTACKER_SETTING_DESIGN.md): for each run what the
server received from the bots (server_requests.csv, by the second a request arrived), what it
answered, and what the legit clients saw in the same window.

The legit figures come from the per-request records (availability_raw.csv) and the attack's real start
(scenario_results.csv), not from the period labels of availability.csv: the suite's two-second launch
check of an open-loop flood runs before the label changes to "during", so the first seconds of such a
flood fall into "before". The window is the first --window seconds from that start (default 30, the
attack's duration), for the bots and the legit clients alike.

    python3 eval/expc_probe.py RUN_OR_CAMPAIGN_DIR... [--window 30] [--r50] [--md OUT.md] [--json OUT.json]

A directory is a run (it holds provenance.json) or holds runs at any depth below it. --r50 adds R50 of
amendment A (docs/EXPC_ATTACKER_SETTING_DESIGN.md, section 6) from the open-loop runs of all the
directories given. Read-only; standard library only.
"""
import argparse
import collections
import csv
import glob
import json
import math
import os
import statistics
import sys

MIN_OK_FOR_PERCENTILES = 10     # a percentile of fewer successes than this says nothing
CELL_FACTORS = (0.5, 1, 2)      # EXP-C's default proposal: these multiples of R50


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def quantile(values, q):
    values = sorted(values)
    if not values:
        return None
    k = (len(values) - 1) * q
    lo = int(k)
    hi = min(lo + 1, len(values) - 1)
    return values[lo] + (values[hi] - values[lo]) * (k - lo)


def find_runs(paths):
    """The run directories at or below `paths` (a run holds provenance.json)."""
    runs = []
    for path in paths:
        if os.path.isfile(os.path.join(path, "provenance.json")):
            runs.append(path)
        else:
            found = glob.glob(os.path.join(path, "**", "provenance.json"), recursive=True)
            runs += sorted(os.path.dirname(p) for p in found)
    return runs


def _legit(records):
    """Requests, successes, timeouts and the latencies in ms of the successful ones."""
    ok = [r for r in records if r["OK"] == "1"]
    return {"n": len(records), "ok": len(ok),
            "success": 100.0 * len(ok) / len(records) if records else None,
            "timeout": 100.0 * sum(r["HTTP_Code"] == "000" for r in records) / len(records) if records else None,
            "p50_ms": quantile([float(r["Latency_ms"]) for r in ok], .5) if len(ok) >= MIN_OK_FOR_PERCENTILES else None,
            "p95_ms": quantile([float(r["Latency_ms"]) for r in ok], .95) if len(ok) >= MIN_OK_FOR_PERCENTILES else None}


def analyse_run(run_dir, window=30):
    with open(os.path.join(run_dir, "provenance.json"), encoding="utf-8") as fh:
        prov = json.load(fh)
    settings = prov["settings"]
    tool, rate = settings.get("FLOOD_TOOL", "wrk"), float(settings.get("FLOOD_RATE") or 0)
    bots = int(settings.get("BOTNET_COUNT") or 0)
    start = float(read_csv(os.path.join(run_dir, "scenario_results.csv"))[0]["Attack_Start"])
    out = {"campaign": os.path.basename(os.path.dirname(os.path.dirname(run_dir))),
           "label": prov["mode"]["label"], "run": os.path.basename(run_dir), "tool": tool,
           "rate_per_bot": rate, "nominal_total": rate * bots if tool != "wrk" else None,
           "window_s": window, "status": prov.get("status")}
    legit = read_csv(os.path.join(run_dir, "availability_raw.csv"))

    def between(lo, hi):
        return [r for r in legit if lo <= float(r["T_Start"]) - start < hi]

    out["legit"] = _legit(between(0, window))
    out["legit_before"] = _legit(between(-1e9, 0))
    out["legit_first_5s"] = _legit(between(0, 5))
    out["legit_last_10s"] = _legit(between(window - 10, window))
    path = os.path.join(run_dir, "server_requests.csv")
    if os.path.isfile(path):
        status, per_sec = collections.Counter(), collections.Counter()
        for r in read_csv(path):
            if r["Client_Class"] == "bot" and r["T_Rel_s"] != "" and 0 <= int(r["T_Rel_s"]) < window:
                status[r["Status"]] += int(r["Requests"])
                per_sec[int(r["T_Rel_s"])] += int(r["Requests"])
        per_second = [per_sec.get(t, 0) for t in range(window)]
        out["bot"] = {"total": sum(per_second), "offered_per_s": sum(per_second) / window,
                      "offered_median_per_s": statistics.median(per_second[1:]) if window > 1 else None,
                      "served_per_s": status.get("200", 0) / window, "status": dict(sorted(status.items())),
                      "per_second": per_second}
    done = os.path.join(run_dir, "DONE")
    if os.path.isfile(done):
        with open(done, encoding="utf-8") as fh:
            info = json.load(fh)
        out["exit_code"], out["seconds"] = info.get("exit_code"), info.get("seconds")
    return out


def r50(rows):
    """R50 under amendment A (docs/EXPC_ATTACKER_SETTING_DESIGN.md, section 6): the nominal total rate where the legit
    success crosses 50 %, linear in log-rate between two adjacent open-loop rates, the lower with 50 % or more and the
    higher below it. A dict with the bracket and the value, or {"r50": None, "why": ...} when the ladder has no single
    crossing; one run per rate is assumed."""
    ladder = sorted((r["nominal_total"], r["legit"]["success"], r["rate_per_bot"]) for r in rows
                    if r["tool"] != "wrk" and r["legit"]["success"] is not None)
    if not ladder:
        return {"r50": None, "why": "no open-loop run with legit requests"}
    if len({rate for rate, _, _ in ladder}) != len(ladder):
        return {"r50": None, "why": "two runs at one rate"}
    above = [success >= 50 for _, success, _ in ladder]
    if all(above):
        return {"r50": None, "why": "the success is 50 % or more at every rate"}
    if not above[0]:
        return {"r50": None, "why": "the success is below 50 % at the lowest rate"}
    first_below = above.index(False)
    if any(above[first_below:]):
        return {"r50": None, "why": "not monotone: a rate above one that is below 50 % is back at 50 % or more"}
    (lo, s_lo, per_bot_lo), (hi, s_hi, _) = ladder[first_below - 1], ladder[first_below]
    value = math.exp(math.log(lo) + (s_lo - 50) / (s_lo - s_hi) * (math.log(hi) - math.log(lo)))
    bots = lo / per_bot_lo
    return {"r50": value, "per_bot": value / bots, "lo": lo, "hi": hi, "success_lo": s_lo, "success_hi": s_hi,
            "cells_per_bot": [round(value / bots * f) for f in CELL_FACTORS]}


def r50_text(result):
    if result["r50"] is None:
        return f"R50 (amendment A): not defined, {result['why']}.\n"
    cells = ", ".join(str(c) for c in result["cells_per_bot"])
    return (f"R50 (amendment A, nominal total rate, linear in log-rate between {result['lo']:g} requests/s at "
            f"{result['success_lo']:.1f} % and {result['hi']:g} at {result['success_hi']:.1f} %): "
            f"{result['r50']:.0f} requests/s, {result['per_bot']:.0f} per bot. "
            f"0.5, 1 and 2 x that, per bot: {cells}.\n")


def _f(value, spec="{:.0f}"):
    return "-" if value is None else spec.format(value)


def render_markdown(rows, window=30, r50_result=None):
    load_intro = (f"Load the server received from the bots, by arrival, in the first {window} s of the attack "
                  "(`Offered` counts every request line of a bot address, `Served` those with status 200; "
                  "the median leaves out the first second, in which the generators start):")
    seen_intro = (f"What the legit clients saw in the same {window} s, from their own records "
                  f"(percentiles only from {MIN_OK_FOR_PERCENTILES} or more successes):")
    load = [load_intro, "",
            "| Campaign | Run | Flood | Nominal /s | Offered /s | Offered /s, median | Served /s | Other statuses | Run time s |",
            "|---|---|---|---|---|---|---|---|---|"]
    seen = ["", seen_intro, "",
            "| Campaign | Run | Legit n | Success % | Timeouts % | Before the start, success % (n) | First 5 s, % | Last 10 s, % | p50 ok ms | p95 ok ms |",
            "|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        bot, legit = r.get("bot"), r["legit"]
        flood = "wrk, closed-loop" if r["tool"] == "wrk" else f"{r['tool']}, {r['rate_per_bot']:g}/s per bot"
        others = ", ".join(f"{k}: {v}" for k, v in (bot or {}).get("status", {}).items() if k != "200") or "-"
        load.append(f"| `{r['campaign'][:16]}` | `{r['label']}/{r['run']}` | {flood} | {_f(r['nominal_total'])} | "
                    f"{_f(bot and bot['offered_per_s'])} | {_f(bot and bot['offered_median_per_s'])} | "
                    f"{_f(bot and bot['served_per_s'])} | {others} | {_f(r.get('seconds'), '{:.0f}')} |")
        before = r["legit_before"]
        seen.append(f"| `{r['campaign'][:16]}` | `{r['label']}/{r['run']}` | {legit['n']} | {_f(legit['success'], '{:.1f}')} | "
                    f"{_f(legit['timeout'], '{:.1f}')} | {_f(before['success'], '{:.1f}')} ({before['n']}) | "
                    f"{_f(r['legit_first_5s']['success'], '{:.1f}')} | {_f(r['legit_last_10s']['success'], '{:.1f}')} | "
                    f"{_f(legit['p50_ms'])} | {_f(legit['p95_ms'])} |")
    text = "\n".join(load + seen) + "\n"
    return text if r50_result is None else text + "\n" + r50_text(r50_result)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("dirs", nargs="+")
    ap.add_argument("--window", type=int, default=30, help="seconds from the attack's start (default 30)")
    ap.add_argument("--r50", action="store_true", help="add R50 of amendment A from the open-loop runs")
    ap.add_argument("--md", help="write the tables here")
    ap.add_argument("--json", help="write all figures here")
    a = ap.parse_args(argv)
    runs = find_runs(a.dirs)
    if not runs:
        sys.exit("no runs (provenance.json) under the given directories")
    rows = sorted((analyse_run(r, a.window) for r in runs),
                  key=lambda r: (r["tool"] != "wrk", r["rate_per_bot"], r["campaign"], r["run"]))
    table = render_markdown(rows, a.window, r50(rows) if a.r50 else None)
    print(table, end="")
    if a.md:
        with open(a.md, "w", encoding="utf-8") as fh:
            fh.write(table)
    if a.json:
        with open(a.json, "w", encoding="utf-8") as fh:
            json.dump(rows, fh, indent=1)
            fh.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
