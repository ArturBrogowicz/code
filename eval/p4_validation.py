#!/usr/bin/env python3
"""P4 validation scoring (docs/P4_SLOW_DESIGN.md §6.4 and §13 row 3; review item P4-03), committed before
any validation run.

The validation runs record every poll's input of the per-connection rule (SLOW_PC_RECORD; the rule in
shadow). This tool replays those records through slow_pc.Detector at every point of the frozen grid, one
pass per run with one detector per point, counts what each point would have done into one slow_pc.Outcome
per point (the definitions are frozen with Outcome), sums the counts over the runs and lets
slow_pc.select_thresholds() choose T, F and K. Pure and offline: it reads files and writes a JSON record.

The runs come from the run index, not from the command line (review T-047 P-09): per validation seed the last attempt with
every run valid, whose run directories hold the manifests; a seed without such an attempt, and a manifest whose run.json says the
run was invalid, are refused; the attempts each seed superseded are listed in the record. eval/p4_runner.py refuses a re-run
of a seed whose runs were all valid.

One manifest per run (JSON), written by the runner:

    {"seed": 4001, "arm": "U_loris", "record": "slow_pc.jsonl.gz",
     "roles": {"10.0.2.1": "attack", "10.0.4.1": "cgnat", "10.0.5.1": "slow_uploader", ...},
     "daemon": {"HEURISTIC_PROFILE": "tolerant", "SLOW_PC": "1", "SLOW_PC_ENFORCE": "0"}}

`record` is relative to the manifest. The runs must be exactly slow_pc.VALIDATION_SEEDS x
slow_pc.VALIDATION_RUNS. Every address with a readable socket in a run's snapshots needs a role:
"attack" for the attackers, "slow_uploader" for the slow uploaders (benign as well), and any other
non-empty string for the other benign clients (browser devices, CGNAT pools, uploaders, ...).

Re-registration record (D-035, 2026-10-31T12:44Z, the user's "Approve all four", before any data; review T-039
V-04). A validation run runs M_pc's daemon mode without enforcement: the tolerant profile, the rule in shadow and
recording (HEURISTIC_PROFILE=tolerant, SLOW_PC=1, SLOW_PC_ENFORCE=0, SLOW_PC_RECORD). Its manifest records that mode
under "daemon" (eval/p4_runner.py writes it), and the scorer refuses a manifest with another mode, a poll the rule
enforced, and a poll whose `banned` set holds an address that is not an attacker's: another engine's ban of a benign
address would drop its sockets unjudged at every grid point and make the benign constraints hold by construction.

Re-registration record (T-052, 2026-11-03T15:01Z, the orchestrator's brief, before any data; reviews T-047 and T-050; labelled,
not a decision of the user), committed before the code it judges: a run with no readable socket of a benign role is refused: the constraints on that role would
hold by construction. The record also holds the settings of the validation's blocks, which eval/p4_runner.py compares with the
campaign's.

The share of attacking addresses banned within SECONDARY_DEADLINE_S of their first connection, the T_mit
of the design note before its re-registration, is reported next to each point; it is not used.

    ./venv/bin/python eval/p4_validation.py ROOT [--json OUT]       # ROOT holds index.jsonl and the runs
"""
import argparse
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
import ban_events
import slow_pc

ATTACK, SLOW_UPLOADER = "attack", "slow_uploader"
VALIDATION_DAEMON = {"HEURISTIC_PROFILE": "tolerant", "SLOW_PC": "1", "SLOW_PC_ENFORCE": "0"}   # D-035 (V-04)
SECONDARY_DEADLINE_S = 30.0


def load_run(manifest_path):
    """A run's manifest with its record read: {"seed", "arm", "roles", "polls", "manifest", "record"}."""
    with open(manifest_path, encoding="utf-8") as fh:
        m = json.load(fh)
    if not isinstance(m, dict) or {"seed", "arm", "record", "roles"} - set(m):
        raise ValueError(f"{manifest_path}: a manifest needs seed, arm, record and roles")
    roles = m["roles"]
    if not isinstance(roles, dict) or not all(isinstance(r, str) and r for r in roles.values()):
        raise ValueError(f"{manifest_path}: roles must map each address to a non-empty string")
    if m.get("daemon") != VALIDATION_DAEMON:
        raise ValueError(f"{manifest_path}: a validation run runs the daemon as {VALIDATION_DAEMON} (D-035), "
                         f"the manifest says {m.get('daemon')!r}")
    where = os.path.dirname(os.path.abspath(manifest_path))
    try:
        with open(os.path.join(where, "run.json"), encoding="utf-8") as fh:
            checks = json.load(fh)["checks"]
    except (OSError, ValueError, KeyError) as exc:
        raise ValueError(f"{manifest_path}: no run.json with the run's checks beside it: {exc}") from None
    if not checks.get("ok"):
        raise ValueError(f"{manifest_path}: an invalid run is not scored: {checks.get('reasons')}")
    record = os.path.join(where, m["record"])
    return {"seed": m["seed"], "arm": m["arm"], "roles": dict(roles),
            "polls": slow_pc.read_record(record), "manifest": manifest_path, "record": record}


def runs_from_index(root):
    """(manifests, attempts) of the validation: per seed, the last attempt of ROOT/index.jsonl with every run of
    slow_pc.VALIDATION_RUNS valid; `attempts` says, per seed, which was judged and which it superseded."""
    sys.path.insert(0, os.path.join(REPO, "eval"))
    import p4_runner
    rows = [x for x in p4_runner.read_index(root) if x["phase"] == "validation"]
    manifests, attempts = [], []
    for seed in slow_pc.VALIDATION_SEEDS:
        mine = [x for x in rows if x["block"] == seed]
        numbers = sorted({x["attempt"] for x in mine})
        good = [a for a in numbers if {x["arm"] for x in mine if x["attempt"] == a and x["valid"]} >= set(slow_pc.VALIDATION_RUNS)]
        if not good:
            raise ValueError(f"seed {seed}: no attempt in {root} has every validation run valid")
        attempts.append({"seed": seed, "judged": good[-1], "superseded": [a for a in numbers if a != good[-1]]})
        manifests += [os.path.join(root, x["dir"], "slow_pc_manifest.json") for x in mine
                      if x["attempt"] == good[-1] and x["arm"] in slow_pc.VALIDATION_RUNS]
    return manifests, attempts


def settings_of(manifests):
    """The settings of the validation's blocks (eval/p4_runner.py block_settings, in block.json beside each attempt's runs): one
    setting, which the campaign's must match (review T-047 P-08)."""
    seen = []
    for path in manifests:
        try:
            with open(os.path.join(os.path.dirname(os.path.dirname(path)), "block.json"), encoding="utf-8") as fh:
                settings = json.load(fh)["settings"]
        except (OSError, ValueError, KeyError) as exc:
            raise ValueError(f"{path}: no block.json with the block's settings beside its attempt: {exc}") from None
        if settings not in seen:
            seen.append(settings)
    if len(seen) != 1:
        raise ValueError(f"the validation's blocks hold {len(seen)} different settings")
    return seen[0]


def check_runs(runs):
    """The validation set must be exactly the frozen seeds x runs: no run missing, none extra."""
    have = sorted((r["seed"], r["arm"]) for r in runs)
    want = sorted((s, a) for s in slow_pc.VALIDATION_SEEDS for a in slow_pc.VALIDATION_RUNS)
    if have != want:
        raise ValueError(f"the validation runs must be exactly {want}, got {have}")


def score_run(polls, roles, grid=slow_pc.GRID, ttl_s=slow_pc.BAN_TTL_S):
    """One run's counts at every grid point: {point: dict of the Outcome fields plus
    "secondary_banned"}. Each recorded poll is read once and fed to one Detector per point; a
    failed read is a skipped poll for all of them, as in the daemon."""
    dets = {pt: slow_pc.Detector(*pt, ttl_s) for pt in grid}
    first_seen, benign_keys, slow_keys = {}, set(), set()
    closed = {pt: set() for pt in grid}
    banned_at = {pt: {} for pt in grid}
    for p in polls:
        t, items = p["t"], [tuple(i) for i in p.get("l7", ())]
        if p.get("enforce"):
            raise ValueError(f"the rule enforced at t={t}: a validation run records it in shadow (D-035)")
        foreign = sorted(ip for ip in p.get("banned", ()) if roles.get(ip) != ATTACK)
        if foreign:
            raise ValueError(f"the daemon had banned addresses that are not attackers' at t={t}: {foreign[:5]} "
                             "(D-035: such a record is refused, its benign sockets would go unjudged)")
        if p.get("ss") is None:
            for d in dets.values():
                d.skip(t, items)
            continue
        parsed = slow_pc.parse_ss(p["ss"])
        unlabelled = sorted({key[0] for key in parsed[1]} - set(roles))
        if unlabelled:
            raise ValueError(f"addresses without a role at t={t}: {unlabelled[:5]}")
        for key in parsed[1]:
            ip = key[0]
            first_seen.setdefault(ip, t)
            if roles[ip] != ATTACK:
                benign_keys.add(key)
                if roles[ip] == SLOW_UPLOADER:
                    slow_keys.add(key)
        banned = p.get("banned", ())
        for pt, d in dets.items():
            r = d.poll_parsed(t, parsed, items, banned)
            closed[pt].update((c.ip, c.port, c.local, c.sport) for c in r.closes)
            for b in r.bans:
                banned_at[pt].setdefault(b.ip, t)
    attackers = [ip for ip in first_seen if roles[ip] == ATTACK]
    out = {}
    for pt in grid:
        bans = banned_at[pt]

        def in_time(ip, limit, bans=bans):
            return ip in bans and bans[ip] - first_seen[ip] <= limit
        out[pt] = {"attack_addresses": len(attackers),
                   "attack_banned_in_time": sum(in_time(ip, slow_pc.DEADLINE_S) for ip in attackers),
                   "benign_addresses_banned": sum(1 for ip in bans if roles[ip] != ATTACK),
                   "benign_connections": len(benign_keys),
                   "benign_connections_closed": len(closed[pt] & benign_keys),
                   "slow_uploader_closed": len(closed[pt] & slow_keys),
                   "secondary_banned": sum(in_time(ip, SECONDARY_DEADLINE_S) for ip in attackers)}
    return out


def score(runs, grid=slow_pc.GRID):
    """Sum the runs' counts per point: ({point: slow_pc.Outcome}, {point: banned within
    SECONDARY_DEADLINE_S})."""
    totals = {pt: dict.fromkeys((*slow_pc.Outcome._fields, "secondary_banned"), 0) for pt in grid}
    for run in runs:
        for pt, counts in score_run(run["polls"], run["roles"], grid).items():
            for k, v in counts.items():
                totals[pt][k] += v
    outcomes = {pt: slow_pc.Outcome(*(c[k] for k in slow_pc.Outcome._fields)) for pt, c in totals.items()}
    return outcomes, {pt: c["secondary_banned"] for pt, c in totals.items()}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("root", help="the runner's root: index.jsonl and the runs")
    ap.add_argument("--json", help="write the per-point outcomes and the selection here")
    args = ap.parse_args(argv)
    try:
        manifests, attempts = runs_from_index(args.root)
        runs = [load_run(m) for m in manifests]
        check_runs(runs)
        settings = settings_of(manifests)
    except ValueError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 2
    outcomes, secondary = score(runs)
    sel = slow_pc.select_thresholds(outcomes)
    if sel.point is None:
        print("no grid point meets the constraints: the rule fails its budget (§6.4)")
    else:
        t, f, k = sel.point
        o = outcomes[sel.point]
        print(f"chosen T={t} s, F={f} B/s, K={k}: {o.attack_banned_in_time}/{o.attack_addresses} attacking "
              f"addresses banned within {slow_pc.DEADLINE_S:g} s ({secondary[sel.point]} within "
              f"{SECONDARY_DEADLINE_S:g} s); {sel.feasible} of {len(slow_pc.GRID)} points meet the constraints")
    if args.json:
        record = {
            "selection": {"point": sel.point, "share": None if sel.share is None else str(sel.share),
                          "feasible": sel.feasible},
            "deadline_s": slow_pc.DEADLINE_S, "secondary_deadline_s": SECONDARY_DEADLINE_S, "attempts": attempts,
            "settings": settings,
            "outcomes": [{"T": t, "F": f, "K": k, **o._asdict(),
                          "secondary_banned": secondary[(t, f, k)]}
                         for (t, f, k), o in sorted(outcomes.items())],
            "runs": [{"seed": r["seed"], "arm": r["arm"], "polls": len(r["polls"]),
                      "manifest_sha256": ban_events.file_sha256(r["manifest"]),
                      "record_sha256": ban_events.file_sha256(r["record"])} for r in runs],
            "slow_pc_sha256": ban_events.file_sha256(os.path.join(REPO, "slow_pc.py"))}
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(record, fh, indent=1)
    return 0 if sel.point is not None else 2


if __name__ == "__main__":
    sys.exit(main())
