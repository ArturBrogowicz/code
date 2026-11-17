#!/usr/bin/env python3
"""HS1's probe (docs/HS1_PREREG.md, section 3): the origin's own unloaded cost estimate of every route, alone and offline.

It builds `bench/origin.py`'s `Origin` with the knobs of the frozen record of 2026-11-04 and times the routes with
`time_routes` (the estimator of the origin's start-up check and of the calibrator: batches of at least 1 ms, the routes in
turn, the median of `REPEATS` batches, the calling thread's CPU time). It prints one JSON line: the costs in ms, each route's
offset from the record's costs and the routes the origin's own 25 % check would refuse. No server, no network; writes nothing.

usage: python -I -B bench/vm/hs1_probe.py SAMPLE [REPEATS]      (pin it with taskset; the line names the CPU it ran on)
"""
import dataclasses
import datetime
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RECORD = os.path.join("bench", "calibration", "ddos-mitigation-2026-11-04.json")
REPEATS = 21                             # as the re-calibration design's H1 bracket and R1's speed hold (section 5.1)


def utc_now():
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def probe(O, cal, sample, repeats=REPEATS, clock=time.thread_time, now=utc_now, cpus=None):
    """One probe: `O` is the origin module, `cal` the frozen record (its knobs and route costs)."""
    fields = {f.name for f in dataclasses.fields(O.CostKnobs)}
    knobs = {k: v for k, v in cal["knobs"].items() if k in fields}
    start = now()
    org = O.Origin(O.CostKnobs(**knobs), 1, "hs1")
    try:
        got = O.time_routes(org, repeats, clock)
    finally:
        org.close()
    costs = got["costs_ms"]
    frozen = cal["route_costs_ms"]
    return {"utc": start, "utc_end": now(), "sample": sample,
            "cpus": sorted(os.sched_getaffinity(0)) if cpus is None else list(cpus),
            "repeats": repeats, "clock": got["clock"], "estimator_version": getattr(O, "ESTIMATOR_VERSION", None),
            "costs_ms": costs, "batch": got["batch"],
            "offset_pct": {k: (costs[k] - frozen[k]) / frozen[k] * 100 for k in frozen if k in costs},
            "refused": sorted(bad["class"] for bad in O.self_check(costs, frozen))}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not 1 <= len(argv) <= 2:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    sample = int(argv[0])
    repeats = int(argv[1]) if len(argv) > 1 else REPEATS
    sys.path.insert(0, os.path.join(ROOT, "bench"))
    import origin as O  # the origin of the tree this file belongs to
    with open(os.path.join(ROOT, RECORD), encoding="utf-8") as fh:
        cal = json.load(fh)
    print(json.dumps(probe(O, cal, sample, repeats), sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
