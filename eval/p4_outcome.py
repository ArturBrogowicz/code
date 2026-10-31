#!/usr/bin/env python3
"""The pre-registered outcome of P4 (docs/P4_SLOW_DESIGN.md §10, with T_mit re-registered to 90 s), as pure
analysis over run records, written and tested on synthetic fixtures before any evaluation data exist.

Units: a BLOCK is one evaluation seed (3101-3110) with eight runs, C, Cp (the placebo C'), U_loris, U_post,
M_def_loris, M_pc_loris, M_def_post and M_pc_post; a run is 30 s of baseline, 210 s of attack and 30 s of
recovery. Per family (loris, post):

  * HARMFUL iff the harm gate passes U against C (eval/harm_gate.criterion: a mean dQ = Q(C) - Q(U) of at least
    10 pp, or a mean dL = log2(p95(U) / p95(C)) of at least 1, the 95 % t-interval excluding 0 and at least 80 %
    of the blocks with the sign of the mean), over at least 10 valid blocks, the placebo (C' against C) does
    not pass the same rule, and at least 9 of 10 blocks are individually at dQ >= 10 pp or dL >= 1.
  * MITIGATED (M_pc) iff (a) in at least 9 of 10 blocks Q(M_pc) in 1-s bins is back at >= 0.99 x Q(C) for 5
    consecutive bins within T_mit of the attack's start, (b) Q(M_pc) over [attack start + T_mit, attack end] is
    >= 0.99 x Q(C) as a mean over the blocks and in at least 9 of 10 of them, and (c) no benign address (CGNAT
    pools and browser devices included) is banned in any M_pc run. Benign connections closed are reported.
  * the status: "not harmful", "harmful but not mitigated", "mitigated with collateral" (a and b, not c), or
    "mitigated". M7 is "supported with scope" for the families that are harmful and mitigated (profile R, these
    families at this scale, this testbed), else "not supported".
  * reported next to it: Q(M_pc) - Q(M_def) per block with eval/run_level_stats.decide, and the bans per arm by
    role.

Two readings are this code's, not the note's, and are pinned by tests: (a) counts the 5 bins from the first bin
below 0.99 x Q(C) after the attack starts (a run that never dips has recovered at once), and they must end
within T_mit; (b)'s window starts at attack start + T_mit, which was the note's "+ 30 s" when T_mit was 30 s,
and ends with the attack (LEVEL_WINDOW_S). Reading (a) was accepted by the user on 2026-10-31 ("P4 recovery
+ HG4"); (b)'s window is the one the re-registration below names.

Re-registration record. The P4 attack length 120 → 210 s, re-registered 2026-10-31 by the user, before any
data, so that the window of (b), from attack start + T_mit (90 s) to the attack's end, is 120 s long; a run
is now 270 s.

A run record (one dict per run; summarize() builds it from eval/harm_gate.run_metrics and the ban events):
    {"block": 3101, "arm": "M_pc_loris", "valid": true, "Q": 97.5, "p95_s": 0.21,
     "q_per_s": [...one value or None per second of the run...], "q_level": 98.9, "level_window": [120, 240],
     "banned": {"10.0.3.1": "attack", ...}, "benign_closed": 0}
A record is refused unless it has one bin per second of the pre-registered run (RUN_S = 270) and its q_level was
taken over LEVEL_WINDOW_S (review T-039 V-05): a run on another timeline, or a level over another window, is not
judged silently.

    ./venv/bin/python eval/p4_outcome.py RUNS.jsonl [--json OUT]
"""
import argparse
import json
import math
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "eval"))
import harm_gate as HG
import run_level_stats as RLS

import slow_pc

# ── pinned against docs/P4_SLOW_DESIGN.md §10 (tests/test_p4_outcome.py) ──
BLOCK_SEEDS = tuple(range(3101, 3111))
CONTROL, PLACEBO = "C", "Cp"
FAMILIES = ("loris", "post")
ARMS = (CONTROL, PLACEBO, "U_loris", "U_post", "M_def_loris", "M_pc_loris", "M_def_post", "M_pc_post")
TIMELINE = {"baseline_s": 30, "attack_s": 210, "recovery_s": 30}   # attack 120 -> 210 s, 2026-10-31
GATE = {"floor_pp": 10.0, "floor_log2_p95": 1.0, "ci_level": 0.95, "same_sign_share": 0.8}
MIN_VALID_BLOCKS = 10
BLOCK_SHARE = (9, 10)            # "in >= 9 of 10 blocks", for harm, (a) and (b)
T_MIT_S = slow_pc.DEADLINE_S     # 90 s since the re-registration of 2026-10-30
RECOVERY_RATIO, RECOVERY_BINS = 0.99, 5
LEVEL_RATIO = 0.99
LEVEL_FROM_S = T_MIT_S           # (b): [attack start + T_mit, attack end]
LEVEL_WINDOW_S = (TIMELINE["baseline_s"] + LEVEL_FROM_S,           # the same span in run time: the
                  TIMELINE["baseline_s"] + TIMELINE["attack_s"])   # `window` of run_metrics for q_level
RUN_S = sum(TIMELINE.values())   # a record has one q_per_s bin per second of the run
ATTACK = "attack"
SCOPE = "profile R, {families} at this scale, this testbed"
FAMILY_NAMES = {"loris": "Slowloris", "post": "slow POST"}


def check_record_timeline(q_per_s, level_window):
    """Refuse bins that are not one per second of the pre-registered run, or a level not taken over
    LEVEL_WINDOW_S."""
    if len(q_per_s) != RUN_S:
        raise ValueError(f"{len(q_per_s)} one-second bins, not {RUN_S} (the run of {TIMELINE})")
    if level_window is None or [float(x) for x in level_window] != [float(x) for x in LEVEL_WINDOW_S]:
        raise ValueError(f"q_level taken over {level_window!r}, not LEVEL_WINDOW_S {list(LEVEL_WINDOW_S)}")


def summarize(block, arm, valid, metrics, level_metrics, ban_events, roles, slow_pc_closes=(), *, level_window):
    """One run record from the run's harm-gate metrics (eval/harm_gate.run_metrics: over the attack
    window, and with window=LEVEL_WINDOW_S for `level_metrics`; `level_window` is the window the caller
    took it over, and must be LEVEL_WINDOW_S), its ban events and the role of every client address.
    Every banned address must have a role."""
    check_record_timeline(metrics["q_per_s"], level_window)
    banned = {}
    for ev in ban_events:
        if ev.get("kind") != "ban":
            continue
        ip = ev.get("ip")
        if ip not in roles:
            raise ValueError(f"banned address without a role: {ip!r}")
        banned[ip] = roles[ip]
    benign_closed = len({(c["ip"], c["port"], c["sport"]) for c in slow_pc_closes
                         if roles.get(c["ip"], ATTACK) != ATTACK})
    return {"block": block, "arm": arm, "valid": bool(valid), "Q": metrics["Q"], "p95_s": metrics["p95_s"],
            "q_per_s": list(metrics["q_per_s"]), "q_level": level_metrics["Q"],
            "level_window": [float(x) for x in level_window], "banned": banned, "benign_closed": benign_closed}


def recovery_s(q_per_s, threshold, start=TIMELINE["baseline_s"]):
    """Seconds from the attack's start to the end of the first 5 consecutive bins at >= threshold
    that follow the first bin below it; 0 if no bin of the attack window is below it; None if the
    bins never recover."""
    end = start + TIMELINE["attack_s"]
    dips = [i for i in range(start, min(end, len(q_per_s)))
            if q_per_s[i] is not None and q_per_s[i] < threshold]
    if not dips:
        return 0
    for i in range(dips[0] + 1, len(q_per_s) - RECOVERY_BINS + 1):
        if all(x is not None and x >= threshold for x in q_per_s[i:i + RECOVERY_BINS]):
            return i + RECOVERY_BINS - start
    return None


def enough(count, n):
    """At least 9 of 10: a share of the n blocks, rounded up."""
    num, den = BLOCK_SHARE
    return n > 0 and count * den >= num * n


def _blocks(runs):
    by = {}
    for r in runs:
        if r["arm"] not in ARMS:
            raise ValueError(f"unknown arm {r['arm']!r}")
        if r["block"] not in BLOCK_SEEDS:
            raise ValueError(f"block {r['block']!r} is not an evaluation seed")
        try:
            check_record_timeline(r["q_per_s"], r.get("level_window"))
        except ValueError as exc:
            raise ValueError(f"block {r['block']} {r['arm']}: {exc}") from None
        if r["arm"] in by.setdefault(r["block"], {}):
            raise ValueError(f"two runs of {r['arm']} in block {r['block']}")
        by[r["block"]][r["arm"]] = r
    return by


def _ok(block, *arms):
    return all(a in block and block[a]["valid"] for a in arms)


def _log2(num, den):
    return math.log2(num / den) if num and den else None


def harm(blocks, family):
    """The harm criterion of one family: the gate on U against C, the placebo, the stricter count."""
    u = f"U_{family}"
    valid = [b for b in blocks.values() if _ok(b, CONTROL, PLACEBO, u)]
    dq = [b[CONTROL]["Q"] - b[u]["Q"] for b in valid]
    dl = [_log2(b[u]["p95_s"], b[CONTROL]["p95_s"]) for b in valid]
    dqp = [b[CONTROL]["Q"] - b[PLACEBO]["Q"] for b in valid]
    dlp = [_log2(b[PLACEBO]["p95_s"], b[CONTROL]["p95_s"]) for b in valid]

    def rule(values, floor):
        if any(v is None for v in values):
            return {"n": len(values), "evaluable": False, "passed": False}
        return HG.criterion(values, floor, GATE)
    gate_q, gate_l = rule(dq, GATE["floor_pp"]), rule(dl, GATE["floor_log2_p95"])
    plac_q, plac_l = rule(dqp, GATE["floor_pp"]), rule(dlp, GATE["floor_log2_p95"])
    each = sum(1 for q, lg in zip(dq, dl, strict=True)
               if q >= GATE["floor_pp"] or (lg is not None and lg >= GATE["floor_log2_p95"]))
    passed = gate_q["passed"] or gate_l["passed"]
    placebo = plac_q["passed"] or plac_l["passed"]
    enough_blocks = len(valid) >= MIN_VALID_BLOCKS
    return {"valid_blocks": len(valid), "gate_Q": gate_q, "gate_p95": gate_l, "placebo_passes": placebo,
            "blocks_individually": each, "harmful": bool(enough_blocks and passed and not placebo
                                                          and enough(each, len(valid)))}


def mitigation(blocks, family):
    """(a) recovery, (b) level and (c) collateral of M_pc for one family, and the M_def comparison."""
    m = f"M_pc_{family}"
    valid = [b for b in blocks.values() if _ok(b, CONTROL, m)]
    rec = [recovery_s(b[m]["q_per_s"], RECOVERY_RATIO * b[CONTROL]["Q"]) for b in valid]
    in_time = sum(1 for r in rec if r is not None and r <= T_MIT_S)
    level_ok = sum(1 for b in valid if b[m]["q_level"] >= LEVEL_RATIO * b[CONTROL]["Q"])
    mean_ok = bool(valid) and (sum(b[m]["q_level"] for b in valid)
                               >= LEVEL_RATIO * sum(b[CONTROL]["Q"] for b in valid))
    collateral = sorted({(b[m]["block"], ip, role) for b in blocks.values() if m in b
                         for ip, role in b[m]["banned"].items() if role != ATTACK})
    a = len(valid) >= MIN_VALID_BLOCKS and enough(in_time, len(valid))
    b_ = len(valid) >= MIN_VALID_BLOCKS and mean_ok and enough(level_ok, len(valid))
    pairs = [b for b in blocks.values() if _ok(b, m, f"M_def_{family}")]
    d = [b[m]["Q"] - b[f"M_def_{family}"]["Q"] for b in pairs]
    return {"valid_blocks": len(valid), "recovery_s": rec, "recovered_in_time": in_time, "a": a,
            "level_blocks": level_ok, "level_mean_ok": mean_ok, "b": b_,
            "benign_banned": [list(x) for x in collateral], "c": not collateral,
            "benign_closed": sum(b[m].get("benign_closed", 0) for b in blocks.values() if m in b),
            "vs_m_def": {"n": len(d), "decision": RLS.decide(d)}}


def bans_by_arm(runs):
    """{arm: {role: banned addresses}}: the collateral of every arm, M_def's included."""
    out = {}
    for r in runs:
        for role in r["banned"].values():
            out.setdefault(r["arm"], {}).setdefault(role, 0)
            out[r["arm"]][role] += 1
    return out


def outcome(runs):
    """The verdict of §10 over a list of run records."""
    blocks = _blocks(runs)
    fam = {}
    for f in FAMILIES:
        h, m = harm(blocks, f), mitigation(blocks, f)
        if not h["harmful"]:
            status = "not harmful"
        elif m["a"] and m["b"]:
            status = "mitigated" if m["c"] else "mitigated with collateral"
        else:
            status = "harmful but not mitigated"
        fam[f] = {"status": status, "harm": h, "mitigation": m}
    qualified = [f for f in FAMILIES if fam[f]["status"] == "mitigated"]
    if qualified:
        m7 = "supported with scope: " + SCOPE.format(
            families=" and ".join(FAMILY_NAMES[f] for f in qualified))
    else:
        m7 = "not supported"
    return {"M7": m7, "families": fam, "bans_by_arm": bans_by_arm(runs), "t_mit_s": T_MIT_S}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("runs", help="JSON Lines, one run record per line")
    ap.add_argument("--json", help="write the full verdict here")
    args = ap.parse_args(argv)
    with open(args.runs, encoding="utf-8") as fh:
        runs = [json.loads(line) for line in fh if line.strip()]
    res = outcome(runs)
    print(f"M7: {res['M7']}")
    for f, r in res["families"].items():
        print(f"  {FAMILY_NAMES[f]}: {r['status']}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(res, fh, indent=1, default=str)
    return 0


if __name__ == "__main__":
    sys.exit(main())
