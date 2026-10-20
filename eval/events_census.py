#!/usr/bin/env python3
"""Census of the daemon's ban-event logs (audit G-16, G-11).

Offline and read-only. Over every ban_events.jsonl under the given roots it counts the
events by kind, the bans by engine, the bans of legitimate clients (10.0.1.x, the testbed
convention) and every ban by the XDP-fed GRU.

Logs are DEDUPLICATED BY CONTENT. A published campaign and the raw store it was copied
from hold byte-identical logs, so counting both double-counts runs: the audit's first
census saw 71 files, but they were 39 distinct logs. --keep-duplicates turns this off.

    ./venv/bin/python eval/events_census.py ROOT [ROOT ...] [--keep-duplicates]
        [--md FILE] [--json FILE]
"""
import argparse
import collections
import glob
import hashlib
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
import ban_events

LEGIT_PREFIX = "10.0.1."


def find_logs(roots):
    paths = []
    for root in roots:
        paths += glob.glob(os.path.join(root, "**", "ban_events.jsonl"), recursive=True)
    return sorted(set(paths))


def _digest(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def census(roots, dedupe=True):
    files = find_logs(roots)
    groups = collections.OrderedDict()
    for p in files:
        groups.setdefault(_digest(p) if dedupe else p, []).append(p)
    kinds, engines = collections.Counter(), collections.Counter()
    configs = collections.Counter()
    legit_bans, gru_bans = [], []
    empty = 0
    for paths in groups.values():
        rep = paths[0]
        events = ban_events.read_events(rep)
        empty += not events
        for e in events:
            kinds[e["kind"]] += 1
            if e["kind"] == "start":
                configs[(f"xdp_gru={e.get('xdp_gru')}", f"l7_shadow={e.get('l7_shadow')}",
                         f"profile={e.get('heuristic_profile')}")] += 1
            if e["kind"] != "ban":
                continue
            engines[e.get("engine")] += 1
            row = {"log": rep, "ip": e.get("ip"), "engine": e.get("engine"),
                   "value": e.get("value"), "hits": e.get("hits")}
            if str(e.get("ip", "")).startswith(LEGIT_PREFIX):
                legit_bans.append(row)
            if e.get("engine") == "gru":
                gru_bans.append(row)
    return {"files": len(files), "distinct_logs": len(groups), "logs_without_events": empty,
            "duplicates_removed": len(files) - len(groups) if dedupe else 0,
            "events_by_kind": dict(sorted(kinds.items())),
            "bans_by_engine": dict(sorted(engines.items(), key=lambda kv: (-kv[1], str(kv[0])))),
            "total_bans": sum(engines.values()),
            "start_configs": {" ".join(k): v for k, v in sorted(configs.items())},
            "legit_bans": legit_bans, "gru_bans": gru_bans,
            "gru_bans_of_legit_clients": sum(r["ip"].startswith(LEGIT_PREFIX) for r in gru_bans)}


def to_markdown(c):
    found = (f"* Files found: {c['files']}; distinct logs (by content): {c['distinct_logs']} "
             f"({c['duplicates_removed']} byte-identical copies removed); logs without events: "
             f"{c['logs_without_events']}.")
    events = "* Events: " + ", ".join(f"{k} {v}" for k, v in c["events_by_kind"].items())
    bans = f"* Bans: {c['total_bans']} (" + ", ".join(
        f"{k} {v}" for k, v in c["bans_by_engine"].items()) + ")"
    configs = "* Daemon configurations seen in `start` events: " + "; ".join(
        f"{k} x{v}" for k, v in c["start_configs"].items())
    gru = (f"* **GRU bans: {len(c['gru_bans'])}, of which {c['gru_bans_of_legit_clients']} "
           f"of legitimate clients.**")
    lines = ["**Ban-event census**", "", found, events, bans, configs, gru]
    lines += [f"  * `{r['log']}`: {r['ip']}, p = {r['value']}, hits = {r['hits']}"
              for r in c["gru_bans"]]
    lines += ["", f"Bans of legitimate clients ({len(c['legit_bans'])}):", ""]
    lines += [f"* `{r['log']}`: {r['ip']} by {r['engine']} (value {r['value']})"
              for r in c["legit_bans"]]
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("roots", nargs="+", help="directories searched recursively")
    ap.add_argument("--keep-duplicates", action="store_true",
                    help="count byte-identical logs once per file")
    ap.add_argument("--md", help="write the census as Markdown")
    ap.add_argument("--json", help="write the census as JSON")
    args = ap.parse_args(argv)
    c = census(args.roots, dedupe=not args.keep_duplicates)
    text = to_markdown(c)
    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(text)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(c, fh, indent=1)
            fh.write("\n")
    print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
