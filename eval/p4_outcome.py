#!/usr/bin/env python3
"""The pre-registered outcome of P4 (docs/P4_SLOW_DESIGN.md §10, with T_mit re-registered to 90 s), as pure
analysis over run records, written and tested on synthetic fixtures before any evaluation data exist.

Units: a BLOCK is one evaluation seed (3101-3110) with nine runs, C, Cp (the placebo C'), C_M (the attack-free
protected control, D-041), U_loris, U_post, M_def_loris, M_pc_loris, M_def_post and M_pc_post; a run is 30 s of baseline, 210 s of attack and 30 s of
recovery. Per family (loris, post):

  * HARMFUL iff the harm gate passes U against C (eval/harm_gate.criterion: a mean dQ = Q(C) - Q(U) of at least
    10 pp, or a mean dL = log2(p95(U) / p95(C)) of at least 1, the 95 % t-interval excluding 0 and at least 80 %
    of the blocks with the sign of the mean), over at least 10 valid blocks, the placebo (C' against C) does
    not pass the same rule, and at least 9 of 10 blocks are individually at dQ >= 10 pp or dL >= 1.
  * MITIGATED (M_pc) iff (a) in at least 9 of 10 blocks Q(M_pc) in 1-s bins is back at >= 0.99 x Q(C) for 5
    consecutive bins within T_mit of the attack's start, (b) Q(M_pc) over [attack start + T_mit, attack end] is
    >= 0.99 x C_M's level over that same window (D-046) as a mean over the blocks and in at least 9 of 10 of them, and
    (c) no benign address (CGNAT
    pools and browser devices included) is banned in any M_pc run, and no CGNAT or browser identity in any attempt of
    C_M (D-046: C_M_COLLATERAL_ROLES, for both families). Benign connections closed are reported. A block
    counts for the mitigation only with C, C_M and M_pc valid; C_M's validity is what C's is, the run's own checks,
    with no floor on its Q, since a low Q(C_M) is the cost it exists to show.
  * the status: "not harmful", "harmful but not mitigated", "mitigated with collateral" (a and b, not c), or
    "mitigated"; "invalid (k of 10 valid)" when fewer than 10 blocks are valid for the harm or, for a harmful
    family, for the mitigation (D-035, below); both families are judged on the same attempts (D-050), so they are
    invalid together. A control that is not healthy (control_health(): Q(C) >= 99 %, each route
    class of at least 20 judged requests >= 95 %) makes its attempt of C invalid, and without a valid C a block counts for
    nothing (D-046, D-050). M7 is "supported with scope" for the families that are harmful and
    mitigated (profile R, these families at this scale, this testbed); "invalid (k of 10 valid)" when fewer than 10
    blocks are judged; else "not supported". D-041's reading, that M7 names a family invalid next to one that qualifies,
    cannot arise since D-050.
  * a block is judged on one attempt, the last with every arm of NEEDED_ARMS valid (and C healthy), all arms from it
    (D-050). M_def is not needed: no criterion reads it. The attempts it supersedes, and which attempt was judged, are in
    the output. A later attempt after a complete one, attempt numbers other than 1, 2, ..., and more than MAX_RERUNS
    re-runs in the campaign are refused.
  * reported next to it: Q(M_pc) - Q(M_def) per block with eval/run_level_stats.decide, the bans per arm by role,
    and, as a finding of its own that judges nothing, the deployed limits' own cost (D-041, limits_cost()): Q(C_M)
    against Q(C) per block, what nginx refused in C_M by role with the CGNAT pools named, and the per-connection
    rule's own bans and closes in C_M.

Two readings are this code's, not the note's, and are pinned by tests: (a) counts the 5 bins from the first
harmed second after the attack starts (a run that is never harmed has recovered at once; the harmed second as
re-registered by D-035 below), and they must end within T_mit; (b)'s window starts at attack start + T_mit, which was the note's "+ 30 s" when T_mit was 30 s,
and ends with the attack (LEVEL_WINDOW_S). Reading (a) was accepted by the user on 2026-10-31 ("P4 recovery
+ HG4"); (b)'s window is the one the re-registration below names.

Re-registration record. The P4 attack length 120 → 210 s, re-registered 2026-10-31 by the user, before any
data, so that the window of (b), from attack start + T_mit (90 s) to the attack's end, is 120 s long; a run
is now 270 s.

Re-registration record (D-035, V-01; 2026-10-31T12:44Z, the user's "Approve all four", before any data; review
T-039 V-01). The harmed second of (a) is the first of RECOVERY_BINS = 5 consecutive 1-s bins below 0.99 x Q(C)
inside the attack window (one bin below the bar is sampling noise when a second holds 20-50 judged requests);
the recovery is the end of the first 5 consecutive bins at or above 0.99 x Q(C) after it, in seconds from the
attack's start; a run with no such harm has recovered at once (0). recovery() reports the recovery together with
the onset it was counted from, and mitigation() reports both per block. The noisy fixtures of
tests/test_p4_outcome.py (binomial bins, seeded) pin it: with the harm starting 30 s into the attack, a true
recovery at +95 s fails (a) and one at +60 s passes, at 20 and 50 judged requests a second and Q(C) 99.5 and 99.9.

Re-registration record (D-035, V-02; 2026-10-31T12:44Z, before any data; review T-039 V-02). Fewer than 10 valid
blocks decide nothing: the family is "invalid (k of 10 valid)", never "not harmful" or "harmful but not
mitigated", and so is M7 unless another family qualifies (then M7 names the invalid family next to its claim), as
the harm gate this code cites says INVALID (eval/harm_gate.py).

Re-registration record (D-035, V-03; 2026-10-31T12:44Z, before any data; review T-039 V-03). The outcome takes
every attempt of the run index: each record names its attempt, and a block may hold several attempts of an arm.
The harm and (a) and (b) are judged on the last valid attempt of each (block, arm); (c), the benign connections
closed and the bans per arm are counted over ALL attempts, invalid ones included, so a re-run cannot hide a ban.

Re-registration record (D-041; 2026-10-31T16:06Z, the user's "Approve as recommended", before any data; T-023c F3,
review T-039 V-13), committed before the code it judges. Each block gains an attack-free protected control C_M:
profile R with the deployed limits (nginx_profile_r_limits.conf) and M_pc's daemon configuration, no attack, seeded
with the block, its validity rules C's. Criterion (b) compares M_pc's level window with 0.99 x Q(C_M) instead of
Q(C); (a) and the harm stay on Q(C). The limits' own cost (Q(C_M) against Q(C), 503s by role, the CGNAT pools named) is
reported as a separate finding and judges nothing. Also accepted: when one family qualifies and the other is invalid,
M7 states its claim and names the invalid family.

Re-registration record (D-046; 2026-11-01T15:52Z, the user's "Keep, with changes", before any data, told first that the
premise of D-041 was overstated), committed before the code it judges. C_M stays, and: (1) criterion (b) compares M_pc's
level window with 0.99 x C_M's q_level over the same window, not with C_M's Q over the attack window; (2)
eval/harm_gate.control_health (Q(C) >= 99 %, each route class >= 95 %) is enforced for a block to count, as §10 cites the
harm gate: an unhealthy control makes the block invalid, "invalid (k of 10 valid)", never a negative verdict; it judges C
alone, and C_M keeps no floor; (3) a CGNAT or browser identity banned in C_M, in any attempt, counts against (c), for
both families.

Re-registration record (D-050; 2026-11-02T08:48Z, the user's "Approve as recommended", before any data; review T-047 P-03,
P-04, P-11), committed before the code it judges. A block is judged on one attempt, the last with every arm a criterion
needs valid, all arms from it, replacing D-035's "last valid attempt of each (block, arm)"; (c) and the benign closes count
over all attempts, and superseded attempts are listed in the output. A later attempt of a block whose earlier attempt had
every needed arm valid and a healthy C is refused, and so are more than 2 re-runs in the campaign. In P4's control
health the class floor (>= 95 %) applies only to a class with at least 20 judged requests; smaller classes are reported,
not judged; eval/harm_gate.control_health itself is unchanged.

Re-registration record (T-052b, 2026-11-04T12:16Z, the orchestrator's brief, before any data; the rule of eval/harm_gate.py and
eval/l7v2_harm.py), committed before the code it judges: no verdict on records whose block ran under a calibration record that is not frozen, except
with --dry-run, which labels everything it prints.

Re-registration record (T-052, 2026-11-03T15:01Z, the orchestrator's brief, before any data; reviews T-047 and T-050; labelled,
not a decision of the user), committed before the code it judges: (c) cannot be met over an attempt of M_pc or C_M whose ban record is unreadable. The output
lists every invalid run with its reasons and, per family, why each block is left out of the comparison with M_def; these judge nothing.

Re-registration record (D-069, 2026-11-06T16:30Z, the user's minimum cut of the VM plan, before any data; T-071, T-074),
committed before the code it judges: P4 runs Slowloris only. A block's settings name its `families` (eval/p4_runner.py
block_settings), and the arms, the needed arms, the validation's runs and the verdict follow them: a campaign of ("loris",)
needs C, Cp, C_M, U_loris and M_pc_loris, refuses a record of a slow-POST arm, and M7 judges Slowloris alone. Slow POST's
code stays, fenced: it is judged only in a campaign whose settings name both families. A record whose settings name no
families is from before the cut, and is read with both.

A run of C states its health in its record: "control_reasons" is control_health's list, empty when it is healthy. A
record of C without it is refused, and C's "valid" stays what the run's own checks said, the outcome adding the health.

A run record (one dict per run; summarize() builds it from eval/harm_gate.run_metrics and the ban events):
    {"block": 3101, "arm": "M_pc_loris", "attempt": 1, "valid": true, "Q": 97.5, "p95_s": 0.21,
     "q_per_s": [...one value or None per second of the run...], "q_level": 98.9, "level_window": [120, 240],
     "banned": {"10.0.3.1": "attack", ...}, "benign_closed": 0,
     "refused": {"by_role": {"cgnat": {"requests": 900, "refused": 12}, ...},
                 "cgnat": {"CGNAT-12": {"address": "10.0.17.3", "requests": 300, "refused": 1}, ...}}}
`refused` is optional and judges nothing (eval/p4_runner.py refusals(): nginx's 429 and 503 from the run's access log).
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

import l7_backend
import slow_pc

# ── pinned against docs/P4_SLOW_DESIGN.md §10 (tests/test_p4_outcome.py) ──
BLOCK_SEEDS = tuple(range(3101, 3111))
CONTROL, PLACEBO, PROTECTED = "C", "Cp", "C_M"   # C_M: attack-free, R + the deployed limits + M_pc's daemon (D-041)
FAMILIES = ("loris", "post")
NEEDED_ARMS = (CONTROL, PLACEBO, PROTECTED, "U_loris", "U_post", "M_pc_loris", "M_pc_post")   # the arms a criterion reads
MAX_RERUNS = 2                   # D-050: at most 2 re-run blocks, counted as harm_gate counts them: each extra attempt is one
ARMS = (CONTROL, PLACEBO, PROTECTED, "U_loris", "U_post", "M_def_loris", "M_pc_loris", "M_def_post", "M_pc_post")
TIMELINE = {"baseline_s": 30, "attack_s": 210, "recovery_s": 30}   # attack 120 -> 210 s, 2026-10-31
GATE = {"floor_pp": 10.0, "floor_log2_p95": 1.0, "ci_level": 0.95, "same_sign_share": 0.8}
MIN_VALID_BLOCKS = 10
BLOCK_SHARE = (9, 10)            # "in >= 9 of 10 blocks", for harm, (a) and (b)
T_MIT_S = slow_pc.DEADLINE_S     # 90 s since the re-registration of 2026-10-30
RECOVERY_RATIO, RECOVERY_BINS = 0.99, 5
LEVEL_RATIO = 0.99
CONTROL_Q_MIN = 99.0             # D-046, with HG.CONTROL_CLASS_Q_MIN = 95 %; pinned here, whatever a record's gate says
CONTROL_CLASS_MIN_N = 20         # D-050: the class floor judges a class with at least this many judged requests
LEVEL_FROM_S = T_MIT_S           # (b): [attack start + T_mit, attack end]
LEVEL_WINDOW_S = (TIMELINE["baseline_s"] + LEVEL_FROM_S,           # the same span in run time: the
                  TIMELINE["baseline_s"] + TIMELINE["attack_s"])   # `window` of run_metrics for q_level
RUN_S = sum(TIMELINE.values())   # a record has one q_per_s bin per second of the run
ATTACK = "attack"
# D-046 (3), "a CGNAT or browser identity": the p4_role labels of ml/p4_traffic.py whose clients are browser devices (a
# TPC-W device, a search user, the users of a CGNAT pool). A ban of another benign identity in C_M stays reported.
C_M_COLLATERAL_ROLES = ("cgnat", "tpcw_browsing", "search_user")
SCOPE = "profile R, {families} at this scale, this testbed"
FAMILY_NAMES = {"loris": "Slowloris", "post": "slow POST"}
CUT_FAMILIES = ("loris",)        # D-069: the families P4 runs; FAMILIES stays the design's, whose code stays tested


def check_families(families):
    """The families a block runs, as a tuple in FAMILIES' order (D-069): a non-empty selection of FAMILIES, without repeats."""
    if isinstance(families, str) or not families:
        raise ValueError(f"families must be a non-empty selection of {FAMILIES}, got {families!r}")
    families = tuple(families)
    if len(set(families)) != len(families) or set(families) - set(FAMILIES):
        raise ValueError(f"families must be a selection of {FAMILIES}, got {families!r}")
    return tuple(f for f in FAMILIES if f in families)


def arm_family(arm):
    """The family an arm attacks with (U_loris: "loris"), or None for an arm without attack."""
    return next((f for f in FAMILIES if arm.endswith("_" + f)), None)


def _of(arms, families):
    families = check_families(families)
    return tuple(a for a in arms if arm_family(a) in (None, *families))


def arms_of(families=FAMILIES):
    """ARMS, without the arms of a family the block does not run (D-069)."""
    return _of(ARMS, families)


def needed_arms(families=FAMILIES):
    """NEEDED_ARMS, without the arms of a family the block does not run (D-069)."""
    return _of(NEEDED_ARMS, families)


def validation_runs(families=FAMILIES):
    """slow_pc.VALIDATION_RUNS, without the runs of a family the block does not run (D-069)."""
    return _of(slow_pc.VALIDATION_RUNS, families)


def settings_families(settings):
    """The families a block's settings name; a block from before D-069 names none, and ran both."""
    return check_families((settings or {}).get("families") or FAMILIES)


def check_record_timeline(q_per_s, level_window):
    """Refuse bins that are not one per second of the pre-registered run, or a level not taken over
    LEVEL_WINDOW_S."""
    if len(q_per_s) != RUN_S:
        raise ValueError(f"{len(q_per_s)} one-second bins, not {RUN_S} (the run of {TIMELINE})")
    if level_window is None or [float(x) for x in level_window] != [float(x) for x in LEVEL_WINDOW_S]:
        raise ValueError(f"q_level taken over {level_window!r}, not LEVEL_WINDOW_S {list(LEVEL_WINDOW_S)}")


def control_health(metrics, cal):
    """P4's control health (D-046, D-050): (reasons, small classes). eval/harm_gate.control_health, unchanged, on Q(C) at
    CONTROL_Q_MIN and on the route classes with at least CONTROL_CLASS_MIN_N judged requests; a smaller class, where one slow
    export would decide the block (review T-047 P-11: C5 holds 1-5 requests in 8 of 10 seeds), is reported, not judged. The
    pilot's halving rule reads this too (ml/p4_traffic.py halve)."""
    classes = metrics["by_class"]
    judged = {k: c for k, c in classes.items() if c["n"] >= CONTROL_CLASS_MIN_N}
    small = {k: {f: c[f] for f in ("n", "ok", "Q")} for k, c in classes.items() if c["n"] < CONTROL_CLASS_MIN_N}
    reasons = HG.control_health({**metrics, "by_class": judged},
                                {**cal, "gate": {**cal["gate"], "control_q_min": CONTROL_Q_MIN}})
    return reasons, small


def summarize(block, arm, valid, metrics, level_metrics, ban_events, roles, slow_pc_closes=(), *, level_window,
              attempt, refused=None, cal=None, settings=None, ban_problem=None, reasons=(), view_slip_s=None):
    """One run record from the run's harm-gate metrics (eval/harm_gate.run_metrics: over the attack
    window, and with window=LEVEL_WINDOW_S for `level_metrics`; `level_window` is the window the caller
    took it over, and must be LEVEL_WINDOW_S), its ban events and the role of every client address.
    Every banned address, and every address with a closed connection, must have a role. A run of C also states
    its health (D-046): `cal` is the calibration record whose SLOs its classes were judged by. `settings` are its block's
    (eval/p4_runner.py block_settings): the outcome refuses a mix. `ban_problem` says why the bans given may not be all of them; `reasons` why the run is invalid; `view_slip_s` is the largest
    lateness of a client against its own schedule (eval/p4_runner.py stall_reading)."""
    check_record_timeline(metrics["q_per_s"], level_window)
    banned = {}
    for ev in ban_events:
        if ev.get("kind") != "ban":
            continue
        ip = ev.get("ip")
        if ip not in roles:
            raise ValueError(f"banned address without a role: {ip!r}")
        banned[ip] = roles[ip]
    unlabelled = sorted({c["ip"] for c in slow_pc_closes} - set(roles))
    if unlabelled:                                  # fail closed, as for a ban (review T-039 V-06)
        raise ValueError(f"closed connections of addresses without a role: {unlabelled[:5]}")
    benign_closed = len({(c["ip"], c["port"], c["sport"]) for c in slow_pc_closes if roles[c["ip"]] != ATTACK})
    control_reasons, control_small = None, None
    if arm == CONTROL:
        if cal is None:
            raise ValueError("a record of C needs the calibration its health is judged under (D-046)")
        control_reasons, control_small = control_health(metrics, cal)
    return {"block": block, "arm": arm, "attempt": attempt, "valid": bool(valid), "Q": metrics["Q"],
            "p95_s": metrics["p95_s"],
            "q_per_s": list(metrics["q_per_s"]), "q_level": level_metrics["Q"],
            "level_window": [float(x) for x in level_window], "banned": banned, "benign_closed": benign_closed,
            "refused": refused, "control_reasons": control_reasons, "control_small_classes": control_small,
            "settings": settings, "ban_problem": ban_problem, "reasons": list(reasons), "view_slip_s": view_slip_s}


def recovery(q_per_s, threshold, start=TIMELINE["baseline_s"]):
    """Reading (a) as re-registered by D-035: {"onset_s", "recovery_s"}, both in seconds from the attack's start.
    The harmed second (onset) is the first of RECOVERY_BINS consecutive bins below `threshold`, all inside the
    attack window; the recovery is the end of the first RECOVERY_BINS consecutive bins at or above it after the
    onset. No harmed second: {"onset_s": None, "recovery_s": 0}; harmed and never back: recovery_s None. An empty
    second (None) is neither harmed nor recovered."""
    end, n = start + TIMELINE["attack_s"], RECOVERY_BINS
    onset = next((i for i in range(start, min(end, len(q_per_s)) - n + 1)
                  if all(x is not None and x < threshold for x in q_per_s[i:i + n])), None)
    if onset is None:
        return {"onset_s": None, "recovery_s": 0}
    for i in range(onset + 1, len(q_per_s) - n + 1):
        if all(x is not None and x >= threshold for x in q_per_s[i:i + n]):
            return {"onset_s": onset - start, "recovery_s": i + n - start}
    return {"onset_s": onset - start, "recovery_s": None}


def recovery_s(q_per_s, threshold, start=TIMELINE["baseline_s"]):
    """The recovery of recovery() alone."""
    return recovery(q_per_s, threshold, start)["recovery_s"]


def enough(count, n):
    """At least 9 of 10: a share of the n blocks, rounded up."""
    num, den = BLOCK_SHARE
    return n > 0 and count * den >= num * n


def _blocks(runs):
    by = {}
    kinds = {json.dumps(r.get("settings"), sort_keys=True) for r in runs}
    if "null" in kinds:
        raise ValueError("a record names its block's settings (scale, halvings, T, F, K, calibration, code)")
    if len(kinds) > 1:
        raise ValueError(f"the records hold {len(kinds)} different settings of scale, halvings, T, F, K, calibration or "
                         "code: a campaign holds one (review T-047 P-08)")
    families = settings_families(runs[0]["settings"]) if runs else FAMILIES
    arms, needed = arms_of(families), needed_arms(families)
    for r in runs:
        if r["arm"] not in ARMS:
            raise ValueError(f"unknown arm {r['arm']!r}")
        if r["arm"] not in arms:
            raise ValueError(f"block {r['block']}: a record of {r['arm']}, in a campaign of the families {list(families)} (D-069)")
        if r["block"] not in BLOCK_SEEDS:
            raise ValueError(f"block {r['block']!r} is not an evaluation seed")
        try:
            check_record_timeline(r["q_per_s"], r.get("level_window"))
        except ValueError as exc:
            raise ValueError(f"block {r['block']} {r['arm']}: {exc}") from None
        att = r.get("attempt")
        if not isinstance(att, int) or isinstance(att, bool) or att < 1:
            raise ValueError(f"block {r['block']} {r['arm']}: a record names its attempt of the run index, got {att!r}")
        if any(x["attempt"] == att for x in by.setdefault(r["block"], {}).setdefault(r["arm"], [])):
            raise ValueError(f"two records of {r['arm']} attempt {att} in block {r['block']}")
        if r["arm"] == CONTROL:                     # D-046: an unhealthy control is not a valid control
            if not isinstance(r.get("control_reasons"), list):
                raise ValueError(f"block {r['block']} attempt {att}: a record of C states its health (control_reasons)")
            r = {**r, "run_valid": r["valid"], "valid": r["valid"] and not r["control_reasons"]}
        by[r["block"]][r["arm"]].append(r)
    judged, picks, superseded, reruns = {}, {}, [], 0
    for block, arms in by.items():
        attempts = sorted({r["attempt"] for rs in arms.values() for r in rs})
        if attempts != list(range(1, len(attempts) + 1)):
            raise ValueError(f"block {block}: attempts {attempts}, not 1, 2, ... (D-050)")
        at = {a: {r["arm"]: r for rs in arms.values() for r in rs if r["attempt"] == a} for a in attempts}
        lacking = {a: [arm for arm in needed if not (arm in at[a] and at[a][arm]["valid"])] for a in attempts}
        complete = [a for a in attempts if not lacking[a]]
        if any(a != attempts[-1] for a in complete):
            raise ValueError(f"block {block}: attempt {complete[0] + 1} follows attempt {complete[0]}, whose every needed "
                             "arm was valid and whose C was healthy (D-050)")
        reruns += len(attempts) - 1
        picks[block] = complete[-1] if complete else None
        judged[block] = at[picks[block]] if complete else {}
        superseded += [{"block": block, "attempt": a, "invalid_or_missing": lacking[a]} for a in attempts if a != picks[block]]
    if reruns > MAX_RERUNS:
        raise ValueError(f"{reruns} re-runs in the campaign, at most {MAX_RERUNS} (D-050)")
    return judged, by, picks, sorted(superseded, key=lambda x: (x["block"], x["attempt"]))


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


def left_out_of_m_def(blocks, family):
    """Why each block is not in the comparison with M_def (review T-050 T050-16): the comparison judges nothing, and without this
    "too few blocks" would not say whether M_def failed or the comparison was never run."""
    name = f"M_def_{family}"
    out = []
    for block in sorted(blocks):
        b = blocks[block]
        if not b:
            out.append({"block": block, "why": ["no attempt of the block has every needed arm valid and a healthy C"]})
        elif name not in b:
            out.append({"block": block, "why": [f"the judged attempt has no run of {name}"]})
        elif not b[name]["valid"]:
            out.append({"block": block, "why": b[name].get("reasons") or ["invalid, no reason recorded"]})
    return out


def mitigation(blocks, family, every=None):
    """(a) recovery, (b) level and (c) collateral of M_pc for one family, and the M_def comparison. `blocks` holds the
    attempt judged per (block, arm); `every` all the attempts, over which (c) and the benign closes are counted."""
    every = every or {b: {arm: [r] for arm, r in arms.items()} for b, arms in blocks.items()}
    m = f"M_pc_{family}"
    valid = [b for b in blocks.values() if _ok(b, CONTROL, PROTECTED, m)]
    found = [recovery(b[m]["q_per_s"], RECOVERY_RATIO * b[CONTROL]["Q"]) for b in valid]
    rec = [x["recovery_s"] for x in found]
    in_time = sum(1 for r in rec if r is not None and r <= T_MIT_S)
    level_ok = sum(1 for b in valid if b[m]["q_level"] >= LEVEL_RATIO * b[PROTECTED]["q_level"])
    mean_ok = bool(valid) and (sum(b[m]["q_level"] for b in valid)
                               >= LEVEL_RATIO * sum(b[PROTECTED]["q_level"] for b in valid))
    attempts = [r for arms in every.values() for r in arms.get(m, ())]
    collateral = sorted({(r["block"], ip, role) for r in attempts for ip, role in r["banned"].items() if role != ATTACK})
    in_c_m = sorted({(r["block"], ip, role) for arms in every.values() for r in arms.get(PROTECTED, ())
                     for ip, role in r["banned"].items() if role in C_M_COLLATERAL_ROLES})
    unknown = sorted({(r["block"], r["attempt"], r["arm"], r["ban_problem"]) for r in
                      [*attempts, *(r for arms in every.values() for r in arms.get(PROTECTED, ()))] if r.get("ban_problem")})
    a = len(valid) >= MIN_VALID_BLOCKS and enough(in_time, len(valid))
    b_ = len(valid) >= MIN_VALID_BLOCKS and mean_ok and enough(level_ok, len(valid))
    pairs = [b for b in blocks.values() if _ok(b, CONTROL, m, f"M_def_{family}")]
    d = [b[m]["Q"] - b[f"M_def_{family}"]["Q"] for b in pairs]
    return {"valid_blocks": len(valid), "recovery_s": rec, "recovery_onset_s": [x["onset_s"] for x in found],
            "recovered_in_time": in_time, "a": a,
            "level_blocks": level_ok, "level_mean_ok": mean_ok, "b": b_,
            "benign_banned": [list(x) for x in collateral], "benign_banned_c_m": [list(x) for x in in_c_m],
            "ban_records_unreadable": [list(x) for x in unknown],
            "c": not collateral and not in_c_m and not unknown,
            "benign_closed": sum(r.get("benign_closed", 0) for r in attempts), "attempts": len(attempts),
            "vs_m_def": {"n": len(d), "decision": RLS.decide(d), "left_out": left_out_of_m_def(blocks, family)}}


def bans_by_arm(runs):
    """{arm: {role: banned addresses}}: the collateral of every arm, M_def's included."""
    out = {}
    for r in runs:
        for role in r["banned"].values():
            out.setdefault(r["arm"], {}).setdefault(role, 0)
            out[r["arm"]][role] += 1
    return out


def _add_counts(into, name, counts):
    row = into.setdefault(name, {"requests": 0, "refused": 0})
    row["requests"] += counts["requests"]
    row["refused"] += counts["refused"]


def _refused_total(record):
    refused = record.get("refused")
    return None if refused is None else sum(c["refused"] for c in refused["by_role"].values())


def limits_cost(blocks):
    """The deployed limits' own cost to benign users, a finding of its own that judges nothing (D-041). Per block with a
    valid C and C_M: Q(C), Q(C_M) and C_M's level, what nginx refused in each, and the per-connection rule's own effect
    in C_M (benign addresses banned, benign connections closed), which would lower (b)'s bar. Over them: the mean of
    Q(C) - Q(C_M) with eval/run_level_stats.decide, and C_M's refusals by role and per CGNAT pool by name."""
    rows, by_role, pools = [], {}, {}
    for block in sorted(blocks):
        b = blocks[block]
        if not _ok(b, CONTROL, PROTECTED):
            continue
        c, cm = b[CONTROL], b[PROTECTED]
        rows.append({"block": block, "Q_C": c["Q"], "Q_C_M": cm["Q"], "q_level_C_M": cm["q_level"],
                     "dQ_pp": c["Q"] - cm["Q"], "refused_C": _refused_total(c), "refused_C_M": _refused_total(cm),
                     "benign_banned_C_M": sorted(ip for ip, role in cm["banned"].items() if role != ATTACK),
                     "benign_closed_C_M": cm.get("benign_closed", 0)})
        refused = cm.get("refused") or {}
        for role, counts in refused.get("by_role", {}).items():
            _add_counts(by_role, role, counts)
        for name, counts in refused.get("cgnat", {}).items():
            _add_counts(pools, name, counts)
    d = [r["dQ_pp"] for r in rows]
    return {"blocks": rows, "mean_dQ_pp": sum(d) / len(d) if d else None,
            "decision": RLS.decide(d), "refused_by_role": by_role, "refused_cgnat": pools}


def unhealthy_controls(every):
    """Every attempt of C that ran soundly and was not healthy, with its reasons: what made those blocks invalid (D-046)."""
    return [{"block": r["block"], "attempt": r["attempt"], "reasons": r["control_reasons"]}
            for block in sorted(every) for r in every[block].get(CONTROL, ())
            if r["run_valid"] and r["control_reasons"]]


def small_control_classes(every):
    """Per attempt of C, the route classes too small for the class floor, reported and not judged (D-050)."""
    return [{"block": r["block"], "attempt": r["attempt"], "classes": r["control_small_classes"]}
            for block in sorted(every) for r in every[block].get(CONTROL, ()) if r.get("control_small_classes")]


def invalid_runs(every):
    """Every run that was not sound, in any attempt, with its reasons: what made an arm or a block count for nothing (T050-16). An
    unhealthy control ran soundly: it is in unhealthy_controls()."""
    return [{"block": r["block"], "attempt": r["attempt"], "arm": r["arm"], "reasons": r.get("reasons") or []}
            for block in sorted(every) for arm in ARMS for r in every[block].get(arm, ()) if not r.get("run_valid", r["valid"])]


def largest_view_slip(runs):
    """The run whose client was latest against its own schedule, beside Q: it judges nothing (T-052); past STALL_BOUND_S the runner
    has made the run invalid."""
    late = [r for r in runs if r.get("view_slip_s") is not None]
    if not late:
        return None
    r = max(late, key=lambda x: x["view_slip_s"])
    return {"view_slip_s": r["view_slip_s"], "block": r["block"], "attempt": r["attempt"], "arm": r["arm"], "Q": r["Q"]}


def invalid(k):
    """The status of a family, or of M7, with fewer than MIN_VALID_BLOCKS valid blocks (D-035, V-02)."""
    return f"invalid ({k} of {len(BLOCK_SEEDS)} valid)"


def outcome(runs, dry_run=False):
    """The verdict of §10 over a list of run records, whose block ran under a frozen calibration record unless `dry_run`, which
    labels the result (T-052b, as eval/harm_gate.analyse)."""
    blocks, every, picks, superseded = _blocks(runs)
    settings = runs[0]["settings"] if runs else {}
    if runs and not dry_run:
        l7_backend.require_frozen({"status": settings.get("calibration_status")})
    families = settings_families(settings)
    fam = {}
    for f in families:
        h, m = harm(blocks, f), mitigation(blocks, f, every)
        k = None
        if h["valid_blocks"] < MIN_VALID_BLOCKS:
            k, status = h["valid_blocks"], invalid(h["valid_blocks"])
        elif not h["harmful"]:
            status = "not harmful"
        elif m["valid_blocks"] < MIN_VALID_BLOCKS:
            k, status = m["valid_blocks"], invalid(m["valid_blocks"])
        elif m["a"] and m["b"]:
            status = "mitigated" if m["c"] else "mitigated with collateral"
        else:
            status = "harmful but not mitigated"
        fam[f] = {"status": status, "harm": h, "mitigation": m, "valid_blocks_if_invalid": k}
    qualified = [f for f in families if fam[f]["status"] == "mitigated"]
    lacking = [f for f in families if fam[f]["valid_blocks_if_invalid"] is not None]
    if qualified:
        m7 = "supported with scope: " + SCOPE.format(
            families=" and ".join(FAMILY_NAMES[f] for f in qualified))
    elif lacking:
        m7 = invalid(min(fam[f]["valid_blocks_if_invalid"] for f in lacking))
    else:
        m7 = "not supported"
    return {"M7": m7, "families_run": list(families), "dry_run": settings.get("calibration_status") != "frozen",
            "calibration": {k: settings.get(f"calibration_{k}") for k in ("status", "sha256")}, "families": fam, "bans_by_arm": bans_by_arm(runs), "t_mit_s": T_MIT_S,
            "limits_cost": limits_cost(blocks), "unhealthy_controls": unhealthy_controls(every),
            "small_control_classes": small_control_classes(every),
            "judged_attempts": picks, "superseded_attempts": superseded, "invalid_runs": invalid_runs(every),
            "largest_view_slip": largest_view_slip(runs)}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("runs", help="JSON Lines, one run record per line")
    ap.add_argument("--json", help="write the full verdict here")
    ap.add_argument("--dry-run", action="store_true", help="allow records under a calibration that is not frozen; labelled")
    args = ap.parse_args(argv)
    with open(args.runs, encoding="utf-8") as fh:
        runs = [json.loads(line) for line in fh if line.strip()]
    try:
        res = outcome(runs, dry_run=args.dry_run)
    except l7_backend.RecordError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 2
    if res["dry_run"]:
        print(f"DRY RUN: the calibration record is {res['calibration']['status']}: figures, not a result")
    print(f"M7: {res['M7']}" + (" (dry run)" if res["dry_run"] else ""))
    for f, r in res["families"].items():
        print(f"  {FAMILY_NAMES[f]}: {r['status']}")
    for f, r in res["families"].items():
        for block, attempt, arm, why in r["mitigation"]["ban_records_unreadable"]:
            print(f"  {FAMILY_NAMES[f]}: (c) cannot be met: the ban record of {arm}, block {block} attempt {attempt}: {why}")
    for f, r in res["families"].items():
        versus = r["mitigation"]["vs_m_def"]
        print(f"  {FAMILY_NAMES[f]}: M_pc against M_def over {versus['n']} blocks: {versus['decision']}")
        for x in versus["left_out"]:
            print(f"    left out, block {x['block']}: {'; '.join(x['why'])}")
    for x in res["invalid_runs"]:
        print(f"  invalid: block {x['block']} attempt {x['attempt']} {x['arm']}: {'; '.join(x['reasons'])}")
    if res["largest_view_slip"]:
        x = res["largest_view_slip"]
        print(f"  largest view slip {x['view_slip_s']:.2f} s: block {x['block']} attempt {x['attempt']} {x['arm']}, Q {x['Q']}")
    for s in res["superseded_attempts"]:
        print(f"  superseded: block {s['block']} attempt {s['attempt']}, invalid or missing {', '.join(s['invalid_or_missing'])}")
    for u in res["unhealthy_controls"]:
        print(f"  unhealthy control, block {u['block']} attempt {u['attempt']}: {'; '.join(u['reasons'])}")
    cost = res["limits_cost"]
    if cost["blocks"]:
        print(f"  the deployed limits' own cost (judges nothing): Q(C) - Q(C_M) {cost['mean_dQ_pp']:.2f} pp over "
              f"{len(cost['blocks'])} blocks, {cost['decision']}; refused in C_M {cost['refused_by_role']}, "
              f"CGNAT pools {cost['refused_cgnat']}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(res, fh, indent=1, default=str)
    return 0


if __name__ == "__main__":
    sys.exit(main())
