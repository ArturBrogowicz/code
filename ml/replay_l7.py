#!/usr/bin/env python3
"""Replay an L7 engine recording, or a JSON-lines access log, offline (Phase P2).

Offline and read-only: no nginx, no sockets, no traffic, no XDP.

* A recording (the daemon's L7_RECORD file) carries the daemon's poll ticks, with
  the flood state and the banned IPs at each tick. Replaying it through a fresh
  engine reproduces the live shadow decisions exactly. --compare-live checks that
  against the run's ban_events.jsonl: the replay-determinism criterion of the P2
  gate.
* A plain access log (an l7json file sink) has no ticks. Polls are then
  synthesised every --poll seconds of request time, without flood suppression.

Outputs the engine's events (JSONL) and a summary by IP class (testbed convention:
10.0.1.x benign, 10.0.2.x attack). --features-csv writes one window summary per
scored window, for the P2 feature review and as input to the P4 tabular baseline.

    ./venv/bin/python ml/replay_l7.py RECORDING [--model PKG] [--out events.jsonl]
        [--compare-live ban_events.jsonl] [--features-csv windows.csv]
"""
import argparse
import csv
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
import l7_engine as E
import l7_features as F
import l7_ingest

SUMMARY_EVERY = 5.0      # s; matches the daemon's report interval


def ip_class(ip):
    if ip.startswith("10.0.1."):
        return "benign"
    if ip.startswith("10.0.2."):
        return "attack"
    return "other"


def replay(items, engine, poll_every=1.0, summary_every=SUMMARY_EVERY):
    """Run stream items (l7_engine.read_stream) through `engine`; return its
    events: would-bans, plus an `l7_gru_poll` summary every `summary_every`
    seconds and a final one. Recorded poll ticks drive the polls exactly;
    without ticks, polls are synthesised every `poll_every` s of request time."""
    items = list(items)
    has_ticks = any(it[0] == "poll" for it in items)
    events = []
    state = {"next_summary": None, "last_now": None}

    def tick(now, suppressing=False, banned=()):
        events.extend(engine.poll(now, suppressing, banned))
        state["last_now"] = now
        if state["next_summary"] is None:
            state["next_summary"] = now + summary_every
        elif now >= state["next_summary"]:
            events.append({"kind": "l7_gru_poll", "t_poll": now, **engine.take_summary()})
            state["next_summary"] = now + summary_every

    next_poll = None
    for it in items:
        if it[0] == "poll":
            if has_ticks:
                tick(it[1], it[2], it[3])
            continue
        rec = l7_ingest.normalise(it[1])
        if rec is None:
            continue
        if not has_ticks:
            t = rec["msec"]
            if next_poll is None:
                next_poll = t + poll_every
            while t >= next_poll:
                tick(next_poll)
                next_poll += poll_every
        engine.on_record(rec)
    if not has_ticks and next_poll is not None:
        tick(next_poll)
    if state["last_now"] is not None:
        events.append({"kind": "l7_gru_poll", "t_poll": state["last_now"], "final": True,
                       **engine.take_summary()})
    return events


def _sums(events, kind="l7_gru_poll"):
    keys = ("polls", "suppressed_polls", "windows", "too_short", "gated_age", "over", "would_bans")
    return {k: sum(e.get(k, 0) or 0 for e in events if e.get("kind") == kind) for k in keys}


def compare_live(live_events, replay_events, tol=1e-5):
    """Compare a live run's shadow events with a replay of its recording."""
    lw = [e for e in live_events if e.get("kind") == "l7_would_ban"]
    rw = [e for e in replay_events if e.get("kind") == "l7_would_ban"]

    def ident(e):
        return (e["ip"], e["ua_h"], e["hits"], e["n_events"])

    seq_match = len(lw) == len(rw) and all(
        ident(a) == ident(b) and abs(a["p"] - b["p"]) <= tol for a, b in zip(lw, rw, strict=True))
    ls, rs = _sums(live_events), _sums(replay_events)
    counts_match = all(ls[k] == rs[k] for k in ("polls", "suppressed_polls", "windows",
                                                 "too_short", "gated_age", "over"))
    return {"would_bans_live": len(lw), "would_bans_replay": len(rw),
            "would_ban_sequence_match": seq_match, "live": ls, "replay": rs,
            "counts_match": counts_match, "match": seq_match and counts_match}


def summarise(events):
    by_class = {}
    for e in events:
        if e.get("kind") == "l7_would_ban":
            c = ip_class(e["ip"])
            by_class.setdefault(c, set()).add(e["ip"])
    max_p = {}
    for e in events:
        for t in e.get("top", []) if e.get("kind") == "l7_gru_poll" else []:
            max_p[t["ip"]] = max(max_p.get(t["ip"], 0.0), t["p"])
    return {"totals": _sums(events),
            "would_ban_ips_by_class": {k: sorted(v) for k, v in by_class.items()},
            "max_p_by_ip": dict(sorted(max_p.items()))}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("input", help="L7_RECORD recording, or an l7json access log")
    ap.add_argument("--model", help="model package dir (default: features-only)")
    ap.add_argument("--out", help="write the replay's events here (JSONL)")
    ap.add_argument("--compare-live", help="the live run's ban_events.jsonl")
    ap.add_argument("--features-csv", help="write one window summary per scored window")
    ap.add_argument("--poll", type=float, default=1.0, help="synthetic poll interval (s)")
    ap.add_argument("--min-events", type=int, default=E.DEFAULT_MIN_EVENTS)
    args = ap.parse_args()

    import torch
    torch.set_num_threads(1)              # as the daemon, for bit-identical scores

    writer = fh_csv = None
    names = None

    def hook(now, key, recs, p):
        nonlocal writer, names
        vec, nm = F.window_summary(recs, engine.cols)
        if writer is None:
            names = nm
            writer = csv.writer(fh_csv)
            writer.writerow(["t_poll", "ip", "ua_h", "class", "p", *names])
        writer.writerow([f"{now:.3f}", key[0], key[1], ip_class(key[0]),
                         "" if p is None else f"{p:.6f}", *(f"{v:.6g}" for v in vec)])

    engine = E.build_engine(args.model, min_events=args.min_events,
                            window_hook=hook if args.features_csv else None)
    if args.features_csv:
        fh_csv = open(args.features_csv, "w", newline="", encoding="utf-8")  # noqa: SIM115
    try:
        with open(args.input, encoding="utf-8", errors="replace") as fh:
            events = replay(E.read_stream(fh), engine, poll_every=args.poll)
    finally:
        if fh_csv:
            fh_csv.close()

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.writelines(json.dumps(e, separators=(",", ":"), default=str) + "\n"
                          for e in events)
    report = {"input": args.input, "model": args.model, **summarise(events)}
    if args.compare_live:
        with open(args.compare_live, encoding="utf-8") as fh:
            live = [json.loads(line) for line in fh if '"l7_' in line]
        report["compare_live"] = compare_live(live, events)
    print(json.dumps(report, indent=1, default=str))
    if args.compare_live and not report["compare_live"]["match"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
