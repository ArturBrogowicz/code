#!/usr/bin/env python3
"""The origin's own start-up self-measurement, run alone (offline, no server, no network): the unloaded cost of every
route under the frozen record's knobs, exactly as origin.make_app measures it (origin.measure_unloaded, thread CPU
time, median of 5 round-robin batches), against the frozen costs. Prints one line. Writes nothing.
usage: python -I -B speed_probe.py WORKTREE [label]"""
import dataclasses
import datetime
import json
import os
import sys

wt = sys.argv[1]
sys.path.insert(0, os.path.join(wt, "bench"))
import origin as O  # noqa: E402

with open(os.path.join(wt, "bench", "calibration", "ddos-mitigation-2026-11-04.json"), encoding="utf-8") as fh:
    cal = json.load(fh)
fields = {f.name for f in dataclasses.fields(O.CostKnobs)}
knobs = {k: v for k, v in cal["knobs"].items() if k in fields}
org = O.Origin(O.CostKnobs(**knobs), 1, "probe")
got = O.measure_unloaded(org)
org.close()
frozen = cal["route_costs_ms"]
off = {k: (got[k] - frozen[k]) / frozen[k] * 100 for k in frozen}
print(datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%SZ"), (sys.argv[2] if len(sys.argv) > 2 else ""),
      "cpus", sorted(os.sched_getaffinity(0)), " ".join(f"{k} {off[k]:+.0f}%" for k in sorted(off)),
      "refused" if O.self_check(got, frozen) else "accepted")
