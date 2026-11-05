#!/usr/bin/env python3
"""The P4 smoke run's fixtures (docs/P4_SLOW_DESIGN.md §9 "a parser fixture", §7.1; T-023 report §6), offline.

Two things only the VM can show, prepared here so that the smoke run's recordings become tests the moment they are
committed (tests/test_p4_smoke_fixtures.py; tests/fixtures/p4_smoke/):

  * the token layout of `ss -tinpH` (F-S3). ss_tinpH.txt is one real output of slow_pc.SS_ARGV in server_ns, and
    labels.json names four of its sockets by "ip:port": "keepalive" (a benign connection that has been answered),
    "backlog" (a connection still in the listen backlog, no nginx owner), "tls" (a :443 connection) and "slowloris"
    (an attack connection, unanswered, that has dribbled). fixture_problems() checks the parser reads each as the
    rule needs it, and reports which tcp_info tokens ss left out (whether ss omits a zero counter is [CLAIMED]);
  * the per-connection close (§7.1): the daemon kills a connection with `ss -K` and a filter
    `( dst <ip> and dport = :<port> and sport = :<sport> )`. kill_filter_keys() reads such a filter, filter_matches()
    finds the sockets of a snapshot it names, and kill_problems() checks a recorded before / after pair
    (ss_before_kill.txt, ss_after_kill.txt, kill_filter.txt): exactly one socket gone, and it is the one named.

Two more readings the smoke hands to the user before the ladder (review T-047 P-10, P-14), from what a run leaves:
worker_kills() counts gunicorn's WORKER TIMEOUT lines (do the benign uploads alone hold R's five workers in a control?), and
connection_summary() gives, per family and benign label, the connections a shadow run's record saw: their lifetimes, who ended
them and how many had been answered (bytes_acked above 64 B): do the server's own timeouts cut them before the rule's floor?

`fixture_from_record` cuts the parser fixture out of a shadow run's SLOW_PC_RECORD (eval/p4_runner.py), using the run's
roles: the first poll that holds every kind of socket.

    ./venv/bin/python eval/p4_smoke.py fixture RUN_DIR OUT_DIR      # writes ss_tinpH.txt and labels.json
    ./venv/bin/python eval/p4_smoke.py check FIXTURE_DIR             # the checks of the tests, printed
    ./venv/bin/python eval/p4_smoke.py workers RUN_DIR               # worker kills and nginx's upstream errors
    ./venv/bin/python eval/p4_smoke.py connections RUN_DIR           # per family: lifetimes, who ended them, bytes_acked
"""
import argparse
import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
import slow_pc

LABELS = ("keepalive", "backlog", "tls", "slowloris")
_TERM = re.compile(r"\(\s*dst\s+(\S+)\s+and\s+dport\s+=\s+:(\d+)\s+and\s+sport\s+=\s+:(\d+)\s*\)")


def kill_filter_keys(expr):
    """[(ip, port, sport)] of a filter the daemon passes to `ss -K` (control_plane.slow_pc_close): terms
    `( dst A and dport = :P and sport = :S )` joined by " or ". Anything else is refused."""
    terms = [t.strip() for t in expr.split(" or ")]
    keys = []
    for t in terms:
        m = _TERM.fullmatch(t)
        if not m:
            raise ValueError(f"not a per-connection filter term: {t!r}")
        keys.append((m.group(1), int(m.group(2)), int(m.group(3))))
    return keys


def filter_matches(expr, text):
    """The keys (ip, port, local, sport) of the sockets of an `ss -tinpH` output that the filter names: dst is the
    peer's address, dport its port, sport the server's port, as ss reads them."""
    want = set(kill_filter_keys(expr))
    _socks, present, _skipped, _bad = slow_pc.parse_ss(text)
    return sorted(k for k in present if (k[0], k[1], k[3]) in want)


def _find(socks, label):
    ip, _, port = label.rpartition(":")
    return next((s for s in socks if s.ip == ip and s.port == int(port)), None)


def fixture_problems(text, labels):
    """What is wrong with a parser fixture, as (problems, notes): problems fail the test; notes say which tcp_info
    tokens ss did not print for the labelled sockets (a missing token counts as 0, F-S3)."""
    socks, _present, skipped, bad = slow_pc.parse_ss(text)
    problems, notes = [], []
    if skipped:
        problems.append(f"{skipped} socket lines the parser could not read, the first: {bad!r}")
    if set(labels) != set(LABELS):
        problems.append(f"labels must be exactly {LABELS}, got {sorted(labels)}")
        return problems, notes
    got = {k: _find(socks, v) for k, v in labels.items()}
    for k, s in got.items():
        if s is None:
            problems.append(f"{k} {labels[k]} is not a socket of the fixture")
    if problems:
        return problems, notes
    ka, bl, tls, lo = (got[k] for k in LABELS)
    if not (ka.owned and ka.info["bytes_acked"] > slow_pc.ANSWERED_MAX_BYTES_80):
        problems.append(f"keepalive: owned and answered (bytes_acked > 64) expected, got {ka.owned} {ka.info}")
    if bl.owned:
        problems.append("backlog: a socket in the listen backlog has no nginx owner (F-S5), the fixture's has one")
    if tls.sport != 443:
        problems.append(f"tls: server port 443 expected, got {tls.sport}")
    if not (lo.owned and lo.info["bytes_acked"] <= slow_pc.ANSWERED_MAX_BYTES_80 and lo.info["data_segs_in"] >= 1
            and lo.info["bytes_received"] > 0):
        problems.append(f"slowloris: owned, unanswered, data received in segments expected, got {lo.owned} {lo.info}")
    for k, s in got.items():
        line = next(ln for ln in text.splitlines() if f"{s.ip}:{s.port}" in ln)
        block = text[text.index(line):].split("\n", 2)[:2]
        missing = [f for f in slow_pc.INFO_FIELDS if f"{f}:" not in " ".join(block)]
        if missing:
            notes.append(f"{k}: ss printed no {', '.join(missing)}")
    return problems, notes


def kill_problems(before, after, expr):
    """The recorded `ss -K` check: the filter names exactly one socket of `before`, and exactly that one is gone in
    `after` (every other socket still there)."""
    named = filter_matches(expr, before)
    _s, b, _k, _x = slow_pc.parse_ss(before)
    _s, a, _k, _x = slow_pc.parse_ss(after)
    problems = []
    if len(named) != 1:
        problems.append(f"the filter names {len(named)} sockets of the snapshot before the kill, not one: {named}")
    gone = sorted(b - a)
    if gone != named:
        problems.append(f"gone after the kill: {gone}; named by the filter: {named}")
    return problems


def fixture_from_record(record_path, roles):
    """(text, labels) of the first poll of a shadow run's record that holds a keep-alive benign socket, a backlog
    socket, a :443 socket and an attack socket that has dribbled; None when no poll does."""
    for p in slow_pc.read_record(record_path):
        if not p.get("ss"):
            continue
        socks, _present, _skipped, _bad = slow_pc.parse_ss(p["ss"])
        pick = {
            "keepalive": [s for s in socks if roles.get(s.ip, "attack") != "attack" and s.owned
                          and s.info["bytes_acked"] > slow_pc.ANSWERED_MAX_BYTES_80],
            "backlog": [s for s in socks if not s.owned],
            "tls": [s for s in socks if s.sport == 443],
            "slowloris": [s for s in socks if roles.get(s.ip) == "attack" and s.owned and s.info["data_segs_in"] >= 1
                          and s.info["bytes_acked"] <= slow_pc.ANSWERED_MAX_BYTES_80],
        }
        if all(pick.values()):
            return p["ss"], {k: f"{v[0].ip}:{v[0].port}" for k, v in pick.items()}
    return None


WORKER_KILL = "WORKER TIMEOUT"       # gunicorn's arbiter, for a sync worker silent for its 30 s
ERROR_CAUSES = ("client timed out", "upstream prematurely closed", "upstream timed out", "Connection reset by peer")


def _read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def worker_kills(run_dir):
    """{"worker_kills", "error_log"}: gunicorn's worker kills in a run, and nginx's error log lines by cause."""
    log = _read(os.path.join(run_dir, "error.log"))
    return {"worker_kills": _read(os.path.join(run_dir, "gunicorn.log")).count(WORKER_KILL),
            "error_log": {cause: log.count(cause) for cause in ERROR_CAUSES}}


def _quantile(values, q):
    values = sorted(values)
    return values[min(len(values) - 1, int(q * len(values)))] if values else None


def connection_summary(run_dir):
    """Per label (an attack family, or a benign p4_role), from a run's SLOW_PC_RECORD: how many connections the snapshots saw,
    their lifetimes (first to last sighting) and who ended them: "rule" (an enforced close), "held to the end" (still there at
    the last snapshot), "answered" (gone with bytes_acked above 64 B: a 502, a 408), "unanswered" (gone with no answer: a client
    or a silent close). A lifetime is at the polls' resolution, and nginx's error log says more (worker_kills)."""
    with open(os.path.join(run_dir, "manifest.json"), encoding="utf-8") as fh:
        man = json.load(fh)
    labels = {e["address"]: e["kind_or_family"] if e["role"] == "attack" else e["p4_role"] for e in man["entities"]}
    conns = {}
    polls = [p for p in slow_pc.read_record(os.path.join(run_dir, "slow_pc.jsonl.gz")) if p.get("ss") is not None]
    for p in polls:
        for s in slow_pc.parse_ss(p["ss"])[0]:
            c = conns.setdefault((s.ip, s.port, s.sport), {"first": p["t"], "acked": 0})
            c["last"], c["acked"] = p["t"], max(c["acked"], s.info["bytes_acked"])
    closed = set()
    for line in _read(os.path.join(run_dir, "ban_events.jsonl")).splitlines():
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if ev.get("kind") == "slow_pc_close" and ev.get("enforced"):
            closed.add((ev["ip"], ev["port"], ev["sport"]))
    end = polls[-1]["t"] if polls else 0.0
    out = {}
    for key, c in conns.items():
        row = out.setdefault(labels.get(key[0], "unlabelled"), {"connections": 0, "lifetimes_s": [], "answered_above_64_B": 0,
                                                                "ended_by": dict.fromkeys(("rule", "held to the end", "answered",
                                                                                           "unanswered"), 0)})
        answered = c["acked"] > slow_pc.ANSWERED_MAX_BYTES_80
        row["connections"] += 1
        row["lifetimes_s"].append(c["last"] - c["first"])
        row["answered_above_64_B"] += answered
        who = "rule" if key in closed else "held to the end" if c["last"] >= end - 1.5 else "answered" if answered else "unanswered"
        row["ended_by"][who] += 1
    for row in out.values():
        lives = row.pop("lifetimes_s")
        row["lifetime_s"] = {"median": _quantile(lives, 0.5), "p90": _quantile(lives, 0.9), "max": max(lives)}
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fixture")
    f.add_argument("run_dir")
    f.add_argument("out_dir")
    c = sub.add_parser("check")
    c.add_argument("fixture_dir")
    for name, helper in (("workers", "worker kills and nginx's errors"), ("connections", "per family: lifetimes, who ended them")):
        sub.add_parser(name, help=helper).add_argument("run_dir")
    args = ap.parse_args(argv)
    if args.cmd in ("workers", "connections"):
        print(json.dumps(worker_kills(args.run_dir) if args.cmd == "workers" else connection_summary(args.run_dir),
                         indent=1, sort_keys=True))
        return 0
    if args.cmd == "fixture":
        with open(os.path.join(args.run_dir, "manifest.json"), encoding="utf-8") as fh:
            roles = json.load(fh)["roles"]
        got = fixture_from_record(os.path.join(args.run_dir, "slow_pc.jsonl.gz"), roles)
        if got is None:
            print("no poll holds every kind of socket", file=sys.stderr)
            return 1
        os.makedirs(args.out_dir, exist_ok=True)
        with open(os.path.join(args.out_dir, "ss_tinpH.txt"), "w", encoding="utf-8") as fh:
            fh.write(got[0])
        with open(os.path.join(args.out_dir, "labels.json"), "w", encoding="utf-8") as fh:
            json.dump(got[1], fh, indent=1, sort_keys=True)
        return 0
    d = args.fixture_dir
    with open(os.path.join(d, "ss_tinpH.txt"), encoding="utf-8") as fh:
        text = fh.read()
    with open(os.path.join(d, "labels.json"), encoding="utf-8") as fh:
        labels = json.load(fh)
    problems, notes = fixture_problems(text, labels)
    if os.path.isfile(os.path.join(d, "kill_filter.txt")):
        with open(os.path.join(d, "kill_filter.txt"), encoding="utf-8") as fh:
            expr = fh.read().strip()
        with open(os.path.join(d, "ss_before_kill.txt"), encoding="utf-8") as fh:
            before = fh.read()
        with open(os.path.join(d, "ss_after_kill.txt"), encoding="utf-8") as fh:
            after = fh.read()
        problems += kill_problems(before, after, expr)
    for line in problems + notes:
        print(line)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
