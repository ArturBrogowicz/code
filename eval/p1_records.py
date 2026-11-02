#!/usr/bin/env python3
"""A P1 run's records (docs/L7V2_DESIGN.md 5, 11): what eval/p1_runner.py's directories say, per run, for the analysis
(eval/p1_analysis.py). Pure analysis over what a run wrote; it starts nothing and sends nothing.

  * run_record(): the harm figures through eval/l7v2_harm.py (assess_run, unchanged), and the secondary outcomes: attacker
    requests served, server CPU, the legit CPU's load, the bans and denies, and the benign users wrongly acted on;
  * acted_on(): the primary outcome "benign users wrongly acted on, at level 1 or level 2, per run, attributed from the
    manifest", in the budget's units. An XDP ban, of any engine (D-037: the arm's L7V2_ENGINE counts, though it sits
    outside ban_events.ENGINES), costs everyone behind the address: the entity's units. A deny costs per the run's arm: a
    view-level key one user (D-031), an (IP, UA) key every benign user behind it (D-043, E-4). An entity's cost is at most
    its units;
  * recording(): a U run's engine input for the replay. The file sink is lossless where the daemon's socket is not (design
    15), and a U run has no daemon, so its "recording" is the sink, with poll ticks at whole seconds of the log clock, the
    engine's cadence (ml/l7v2_model_prereg.json selection.policy_engine_poll_s). An M run also keeps the daemon's own
    L7_RECORD stream;
  * summarize_root(): the records of every attempt of ROOT/index.jsonl, valid or not (design 13 row 6).

    ./venv/bin/python eval/p1_records.py ROOT runs.jsonl --calibration REC
"""
import argparse
import json
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
for _p in (REPO, os.path.join(REPO, "ml"), HERE, os.path.join(REPO, "bench")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import l7v2_harm as LH
import l7v2_replay as RP
import l7v2_rules as RULES
import p1_runner as RUN
import p4_runner as P4

import l7_dataset as D
import l7_ingest

ACTION_KINDS = ("ban", "l7_deny")


def read_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def benign_units(manifest):
    """{entity: its benign users} of a run's manifest (l7_dataset.user_units)."""
    out = {}
    for _u, ent, role in D.user_units(manifest):
        if role != "attack":
            out[ent] = out.get(ent, 0) + 1
    return out


def acted_on(manifest, events, budget):
    """Who the run's actions reached, attributed from the manifest (see the module doc): {"benign_users", "benign_users_total",
    "benign_by_kind", "benign_entities", "attack_entities", "unattributed", "bans_by_engine", "denies"}. An action on an
    address that the manifest does not label is counted as unattributed, never dropped."""
    label, t0, units = D.labeler(manifest), D.time_origin(manifest), benign_units(manifest)
    kof = D.kind_or_family(manifest)
    behind = RULES.plan_users(manifest) if budget == "rule_key" else {}
    whole, keys, attack, unattributed = set(), {}, set(), 0
    for e in events:
        if e.get("kind") not in ACTION_KINDS or (e["kind"] == "ban" and e.get("enforced") is False):
            continue
        ip = e.get("ip")
        t_rel = None if t0 is None or e.get("t_wall") is None else e["t_wall"] - t0
        cls, _fam, _held, ent = label(ip, t_rel)
        if cls == D.ATTACK:
            attack.add(ent)
        elif cls != D.BENIGN:
            unattributed += 1
        elif e["kind"] == "ban":
            whole.add(ent)
        elif budget == "rule_key":
            keys.setdefault(ent, {})[(ip, e.get("ua_h"))] = behind.get((ip, e.get("ua_h"))) or 1
        else:
            keys.setdefault(ent, {})[(ip, e.get("ua_h"), e.get("sid_h"))] = 1
    cost = {ent: units.get(ent, 1) for ent in whole}
    for ent, k in keys.items():
        if ent not in whole:
            cost[ent] = min(sum(k.values()), units.get(ent, 1))
    by_kind = {}
    for ent, n in cost.items():
        by_kind[str(kof.get(ent))] = by_kind.get(str(kof.get(ent)), 0) + n
    bans = RUN.run_bans(events)
    return {"benign_users": sum(cost.values()), "benign_users_total": sum(units.values()),
            "benign_by_kind": dict(sorted(by_kind.items())), "benign_entities": sorted(cost), "attack_entities": sorted(attack),
            "unattributed": unattributed, "bans_by_engine": {k: len(v) for k, v in sorted(bans.items())},
            "denies": sum(1 for e in events if e.get("kind") == "l7_deny")}


def attacker_served(access_log, manifest, window_rel):
    """The attack entities' requests answered 2xx that started in the window (secondary outcome), by nginx's log."""
    label, t0 = D.labeler(manifest), D.time_origin(manifest)
    n = 0
    with D.open_log(access_log) as fh:
        for line in fh:
            obj = l7_ingest.parse_l7_line(line)
            if obj is None or not obj.get("ip"):
                continue
            t_rel = l7_ingest._num(obj.get("msec")) - l7_ingest._num(obj.get("rt")) - t0
            if window_rel[0] <= t_rel < window_rel[1] and label(obj["ip"], t_rel)[0] == D.ATTACK \
                    and 200 <= int(l7_ingest._num(obj.get("status"))) < 300:
                n += 1
    return n


def cpu_load(run_dir, window_rel):
    """The busy share of the server CPUs and of the legit CPU over the window, from the run's 1-s samples; None without them."""
    path = os.path.join(run_dir, "cpu.jsonl")
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as fh:
        rows = [json.loads(x) for x in fh]
    rows = [r for r in rows if window_rel[0] <= r["t"] <= window_rel[1]]
    if len(rows) < 2:
        return None

    def share(cpus):
        busy = total = 0
        for c in cpus:
            if c in rows[0]["cpu"] and c in rows[-1]["cpu"]:
                busy += rows[-1]["cpu"][c][0] - rows[0]["cpu"][c][0]
                total += rows[-1]["cpu"][c][1] - rows[0]["cpu"][c][1]
        return round(busy / total, 4) if total else None

    return {"server": share(_cpus(RUN.PINS["server"])), "legit": share(_cpus(RUN.PINS["legit"]))}


def _cpus(text):
    out = []
    for part in text.split(","):
        lo, _dash, hi = part.partition("-")
        out += [str(c) for c in range(int(lo), int(hi or lo) + 1)]
    return out


def time_to_mitigate(q_per_s, attack_start, bins=5, recovered=99.0):
    """Design 11: from the attack's start to the first 5 consecutive 1-s bins with Q >= 99 %; None if there are none."""
    q = q_per_s or []
    for t in range(math.ceil(attack_start), len(q) - bins + 1):
        if all(x is not None and x >= recovered for x in q[t:t + bins]):
            return float(t - attack_start)
    return None


def access_log(run_dir):
    return next((p for p in (os.path.join(run_dir, D.ACCESS_LOG_GZ), os.path.join(run_dir, D.ACCESS_LOG)) if os.path.isfile(p)),
                None)


def recording(run_dir):
    """A run's engine input for the replay: the file sink's records, with poll ticks at whole seconds of the log clock."""
    path = access_log(run_dir)
    if path is None:
        raise FileNotFoundError(f"{run_dir}: no file sink")
    return RP.with_poll_ticks(RP.read_items(path))


def run_record(run_dir, cal, block=None, attempt=1):
    """One run's record for eval/p1_analysis.py. A run that never started is an invalid record without figures."""
    man, meta = read_json(os.path.join(run_dir, D.MANIFEST_FILE)), read_json(os.path.join(run_dir, "run.json"))
    base = {"format": "p1-run-record/1", "block": man["seed"] if block is None else block, "attempt": attempt, "run": man["run"],
            "arm": man["arm"], "class": man["class"], "levels": man["levels"], "valid": meta["checks"]["ok"],
            "reasons": meta["checks"]["reasons"]}
    if D.time_origin(man) is None:
        return {**base, "Q": None, "p95_s": None, "acted_on": None}
    t = man["timeline"]
    window = (float(t["baseline_s"]), float(t["baseline_s"] + t["attack_s"]))
    a = LH.assess_run(run_dir, cal, t)
    m = a["metrics"]
    events = P4._events(os.path.join(run_dir, "ban_events.jsonl"))
    log = access_log(run_dir)
    return {**base, "Q": m["Q"], "p95_s": m["p95_s"], "requests": m["requests"], "failures": m["failures"],
            "by_class": m["by_class"], "by_profile": m["by_profile"], "time_resolved": {k: m.get(k) for k in TIME_KEYS},
            "time_to_mitigate_s": time_to_mitigate(m.get("q_per_s"), window[0]),
            "server_q": a["server"] and a["server"]["Q"], "unrecorded": m.get("unrecorded"),
            "attacker_served": attacker_served(log, man, window) if log else None, "cpu": cpu_load(run_dir, window),
            "acted_on": acted_on(man, events, meta.get("budget"))}


TIME_KEYS = ("degraded_s", "degraded_in_attack_s", "first_degraded_s", "recovery_s", "q_per_s")


def index_lines(root):
    with open(os.path.join(root, "index.jsonl"), encoding="utf-8") as fh:
        return [json.loads(x) for x in fh if x.strip()]


def summarize_root(root, cal, out_path, phase="campaign"):
    """The records of every attempt of a phase, valid or not (design 13 row 6): one JSON line per run."""
    with open(out_path, "w", encoding="utf-8") as fh:
        for x in index_lines(root):
            if x["phase"] == phase:
                fh.write(json.dumps(run_record(os.path.join(root, x["dir"]), cal, x["block"], x["attempt"]), sort_keys=True) + "\n")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("root")
    ap.add_argument("out")
    ap.add_argument("--calibration", default=P4.PLACEHOLDER)
    ap.add_argument("--phase", default="campaign", choices=RUN.PHASES)
    args = ap.parse_args(argv)
    import l7_backend
    cal, _status, _tag = l7_backend.load_record(args.calibration)
    summarize_root(args.root, cal, args.out, args.phase)
    return 0


if __name__ == "__main__":
    sys.exit(main())
