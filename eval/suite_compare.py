#!/usr/bin/env python3
"""Compare complete suite runs scenario by scenario (audit G-11, EXP-B).

Offline and read-only. Every argument is LABEL=PATH. PATH is a published campaign or a run
directory; every scenario_results.csv below it is one run. A PATH with one run is one column
(LABEL); a PATH with several runs contributes one column per run (LABEL/run1, LABEL/run2, ...).

    ./venv/bin/python eval/suite_compare.py \\
        R2=results/2026-10-13_regression-default-full-suite \\
        after=results/2026-10-20_regression-after-audit-defaults [--md table.md]

Three tables with one row per scenario, then one with one row per engine:
  * bans         bots banned out of the bots launched ("5/5"); a "!" marks a run in which a
                 legitimate client was banned or the legit HTTP check failed;
  * engines      the engine that banned the bots (counts when several engines took part);
  * time         exact time to mitigate in seconds, "median / max" over the bots, from the
                 ban events (first ban of a bot minus the attack start the harness records);
  * by engine    the same times pooled over every bot of every run listed: number of bots,
                 minimum, median and maximum per engine (the bound per rule).

The tables carry no inference: one run per column is a description, not a comparison.
"""
import argparse
import collections
import csv
import json
import os
import statistics
import sys

FILE = "scenario_results.csv"
ABBREV = {"l4_syn": "L4 SYN", "l4_volumetric": "L4 volumetric", "l4_slowconn": "L4 SlowConn",
          "l4_lowsyn": "L4 low-SYN", "l7_rate": "L7 rate", "l7_rudy": "L7 R.U.D.Y.", "gru": "GRU"}


def find_runs(label, path):
    """[(column label, directory)] for every scenario_results.csv at or below `path`."""
    found = []
    for d, _dirs, files in os.walk(path):
        if FILE in files:
            found.append(d)
    found.sort()
    if len(found) == 1:
        return [(label, found[0])]
    return [(f"{label}/{os.path.basename(d)}", d) for d in found]


def _json(text, default):
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return default


def load_run(directory):
    """{scenario: summary} of one scenario_results.csv, in file order."""
    out = collections.OrderedDict()
    with open(os.path.join(directory, FILE), encoding="utf-8", newline="") as fh:
        for r in csv.DictReader(fh):
            by_bot = _json(r.get("Engine_By_Bot"), {})
            engines = collections.Counter(by_bot.values())
            per_bot = [(by_bot.get(ip, "?"), float(t))
                       for ip, t in _json(r.get("TTM_Exact_By_Bot"), {}).items()]
            out[r["Data_Scenario"]] = {
                "per_bot": per_bot,
                "bots": int(r["Bots"]), "banned": int(r["Banned_Events"]),
                "median": float(r["TTM_Exact_Median_s"]) if r.get("TTM_Exact_Median_s") else None,
                "max": float(r["TTM_Exact_Max_s"]) if r.get("TTM_Exact_Max_s") else None,
                "engines": engines,
                "fp": len(_json(r.get("FP_IPs"), [])),
                "http_ok": r.get("Legit_HTTP_OK") == r.get("Legit_HTTP_Total"),
                "result": r.get("Result", "")}
    return out


def cell_bans(s):
    if s is None:
        return "—"
    flag = "" if (s["fp"] == 0 and s["http_ok"]) else " !"
    return f"{s['banned']}/{s['bots']}{flag}"


def cell_engines(s):
    if s is None or not s["engines"]:
        return "—"
    parts = [(ABBREV.get(e, e), n) for e, n in sorted(s["engines"].items())]
    if len(parts) == 1:
        return parts[0][0]
    return ", ".join(f"{name} {n}" for name, n in parts)


def cell_time(s):
    if s is None or s["median"] is None:
        return "—"
    return f"{s['median']:.2f} / {s['max']:.2f}"


def bounds_table(columns, runs):
    """Per engine: how many bots and the min / median / max exact time to mitigate over every
    bot of every run listed."""
    by_engine = collections.defaultdict(list)
    for _, d in columns:
        for s in runs[d].values():
            for engine, t in s["per_bot"]:
                by_engine[engine].append(t)
    lines = ["| Engine | Bots | Min | Median | Max |", "|---|---|---|---|---|"]
    for engine in sorted(by_engine):
        ts = sorted(by_engine[engine])
        lines.append(f"| {ABBREV.get(engine, engine)} | {len(ts)} | {ts[0]:.2f} "
                     f"| {statistics.median(ts):.2f} | {ts[-1]:.2f} |")
    return lines


def all_banned(run, scenarios):
    """Number of `scenarios` of this run in which every bot was banned."""
    return sum(1 for sc in scenarios if sc in run and run[sc]["banned"] == run[sc]["bots"])


def table(columns, runs, scenarios, cell):
    lines = ["| Scenario | " + " | ".join(c for c, _ in columns) + " |",
             "|---|" + "---|" * len(columns)]
    for sc in scenarios:
        lines.append(f"| {sc} | " + " | ".join(cell(runs[d].get(sc)) for _, d in columns) + " |")
    return lines


def compare(specs):
    """Markdown for LABEL=PATH specs."""
    columns, runs = [], {}
    for spec in specs:
        label, _, path = spec.partition("=")
        if not path:
            raise SystemExit(f"expected LABEL=PATH, got {spec!r}")
        found = find_runs(label, path)
        if not found:
            raise SystemExit(f"no {FILE} below {path}")
        for col, d in found:
            columns.append((col, d))
            runs[d] = load_run(d)
    scenarios = []
    for _, d in columns:
        for sc in runs[d]:
            if sc not in scenarios:
                scenarios.append(sc)
    complete = ", ".join(f"{c} {all_banned(runs[d], scenarios)}/{len(scenarios)}"
                         for c, d in columns)
    out = ["**Bots banned** (a ! marks a legitimate client banned or a failed legit HTTP check)", ""]
    out += table(columns, runs, scenarios, cell_bans)
    out += ["", f"Scenarios with every bot banned: {complete}.", "",
            "**Engines that banned the bots**", ""]
    out += table(columns, runs, scenarios, cell_engines)
    out += ["", "**Exact time to mitigate, seconds (median / max over the bots)**", ""]
    out += table(columns, runs, scenarios, cell_time)
    out += ["", "**Exact time to mitigate by engine, over every bot of every run above (seconds)**",
            ""]
    out += bounds_table(columns, runs)
    return "\n".join(out) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("runs", nargs="+", metavar="LABEL=PATH")
    ap.add_argument("--md", help="write the tables to this file")
    args = ap.parse_args(argv)
    text = compare(args.runs)
    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(text)
    print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
