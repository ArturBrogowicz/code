"""The pre-registered outcome of P4 (eval/p4_outcome.py; docs/P4_SLOW_DESIGN.md §10, T_mit re-registered to
90 s), on synthetic run records for every outcome the note names, before any evaluation data exist."""
import contextlib
import io
import json
import os
import random
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "eval"))
import p4_outcome as O

BOTH = "supported with scope: profile R, Slowloris and slow POST at this scale, this testbed"


def bins(base, dip=None, until=None, total=270, start=35):
    """1-s bins of a run: `base`, except `dip` from second `start` to `until` (run time)."""
    q = [base] * total
    if dip is not None:
        for i in range(start, total if until is None else until):
            q[i] = dip
    return q


def rec(block, arm, q, p95=0.10, q_per_s=None, q_level=None, banned=None, valid=True, closed=0, attempt=1,
        refused=None, control_reasons=None):
    return {"block": block, "arm": arm, "attempt": attempt, "valid": valid, "Q": q, "p95_s": p95,
            "q_per_s": q_per_s if q_per_s is not None else bins(q),
            "q_level": q if q_level is None else q_level, "level_window": list(O.LEVEL_WINDOW_S),
            "banned": banned or {}, "benign_closed": closed, "refused": refused,
            "control_reasons": ([] if arm == "C" else None) if control_reasons is None else control_reasons}


def rerun(runs, block, first=None):
    """`block` made again: its records become attempt 2, and attempt 1 is a copy with the changes `first` holds per arm."""
    out = []
    for r in runs:
        if r["block"] != block:
            out.append(r)
            continue
        out.append(dict(r, attempt=2))
        out.append({**r, **(first or {}).get(r["arm"], {}), "attempt": 1})
    return out


def campaign(over=None):
    """Ten blocks in which both families harm (U at 60-69 % against C at 99.5 %, p95 x 4), M_def does not
    help and bans the CGNAT pool, and M_pc dips at 35 s, is back at 60 s (35 s after the attack's start)
    and holds 99.4 % over the level window. `over` maps (arm, block index) or arm to a dict of changes."""
    over = over or {}
    runs = []
    for i, block in enumerate(O.BLOCK_SEEDS):
        c = 99.5 + 0.1 * (i % 3)
        base = {
            "C": {"q": c, "p95": 0.100 + 0.001 * i},
            "C_M": {"q": c, "p95": 0.100 + 0.001 * i},
            "Cp": {"q": c + (0.2 if i % 2 else -0.2),
                   "p95": 0.100 + 0.001 * i + (0.001 if i % 2 else -0.001)},
        }
        for f in O.FAMILIES:
            base[f"U_{f}"] = {"q": 60.0 + i, "p95": 0.40, "q_per_s": bins(c, 60.0 + i)}
            base[f"M_def_{f}"] = {"q": 70.0 + i, "p95": 0.30, "q_per_s": bins(c, 70.0 + i),
                                  "banned": {"10.0.4.1": "cgnat"}}
            base[f"M_pc_{f}"] = {"q": 99.0 + 0.05 * i, "p95": 0.11, "q_per_s": bins(c, 50.0, until=60),
                                 "q_level": 99.4,
                                 "banned": {f"10.0.{3 if f == 'loris' else 6}.1": "attack"}}
        for arm, kw in base.items():
            kw = {**kw, **over.get(arm, {}), **over.get((arm, i), {})}
            runs.append(rec(block, arm, **kw))
    return runs


class PinnedConstantsTest(unittest.TestCase):
    def test_the_constants_of_section_10(self):
        self.assertEqual(O.BLOCK_SEEDS, tuple(range(3101, 3111)))
        self.assertEqual(O.ARMS, ("C", "Cp", "C_M", "U_loris", "U_post", "M_def_loris", "M_pc_loris",
                                  "M_def_post", "M_pc_post"))           # C_M re-registered by D-041
        self.assertEqual(O.PROTECTED, "C_M")
        self.assertEqual((O.CONTROL_Q_MIN, O.HG.CONTROL_CLASS_Q_MIN), (99.0, 95.0))    # D-046
        self.assertEqual(O.CONTROL_CLASS_MIN_N, 20)                                   # D-050
        self.assertEqual(O.TIMELINE, {"baseline_s": 30, "attack_s": 210, "recovery_s": 30})
        self.assertEqual(O.GATE, {"floor_pp": 10.0, "floor_log2_p95": 1.0, "ci_level": 0.95,
                                  "same_sign_share": 0.8})
        self.assertEqual((O.MIN_VALID_BLOCKS, O.BLOCK_SHARE), (10, (9, 10)))
        self.assertEqual((O.T_MIT_S, O.LEVEL_FROM_S), (90.0, 90.0))      # re-registered 2026-10-30
        self.assertEqual((O.RECOVERY_RATIO, O.RECOVERY_BINS, O.LEVEL_RATIO), (0.99, 5, 0.99))

    def test_the_attack_was_re_registered_to_210_s_before_any_data(self):
        # The user's decision of 2026-10-31 ("Lengthen to 210 s"): (b)'s window, from attack start +
        # T_mit to the attack's end, is 120 s long again; the record is in the module and in
        # docs/EVALUATION.md.
        record = ("The P4 attack length 120 → 210 s, re-registered 2026-10-31 by the user, before "
                  "any data")
        self.assertEqual(O.LEVEL_WINDOW_S, (120.0, 240.0))
        self.assertEqual(O.LEVEL_WINDOW_S[1] - O.LEVEL_WINDOW_S[0], 120.0)
        self.assertEqual(sum(O.TIMELINE.values()), 270)
        with open(os.path.join(REPO, "docs", "EVALUATION.md"), encoding="utf-8") as fh:
            doc = " ".join(fh.read().split())
        for text in (" ".join(O.__doc__.split()), doc):
            self.assertIn(record, text)


class RecoveryTest(unittest.TestCase):
    def test_the_recovery_time_after_the_harmed_second(self):
        # D-035 (V-01) re-registered the harmed second: the first of 5 consecutive bins below the bar. The flat
        # fixtures of the first reading keep their values (their dips last longer than 5 s).
        self.assertEqual(O.recovery_s(bins(99.5), 98.5), 0)                       # never harmed
        self.assertEqual(O.recovery_s(bins(99.5, 50.0, until=60), 98.5), 35)       # 60 + 5 - 30
        self.assertEqual(O.recovery_s(bins(99.5, 50.0, until=115), 98.5), 90)     # just in time
        self.assertEqual(O.recovery_s(bins(99.5, 50.0, until=116), 98.5), 91)
        self.assertIsNone(O.recovery_s(bins(99.5, 50.0), 98.5))                   # never back
        q = bins(99.5, 50.0, until=60)
        q[62] = None                                                              # an empty second
        self.assertEqual(O.recovery_s(q, 98.5), 38)
        self.assertEqual(O.recovery(bins(99.5, 50.0, until=60), 98.5), {"onset_s": 5, "recovery_s": 35})

    def test_a_dip_shorter_than_5_bins_is_not_the_harmed_second(self):
        q = bins(99.5, 50.0, start=35, until=39)                                  # 4 bins low, then healthy
        self.assertEqual(O.recovery(q, 98.5), {"onset_s": None, "recovery_s": 0})
        q = bins(99.5, 50.0, start=60, until=130)                                 # the real harm comes later
        q[33] = q[41] = 97.0                                                      # two noisy seconds before it
        self.assertEqual(O.recovery(q, 98.5), {"onset_s": 30, "recovery_s": 105})
        q = bins(99.5, 50.0, start=236, until=270)                                # its 5 bins leave the window
        self.assertEqual(O.recovery(q, 98.5), {"onset_s": None, "recovery_s": 0})
        q = bins(99.5, 50.0, start=235, until=270)
        self.assertEqual(O.recovery(q, 98.5), {"onset_s": 205, "recovery_s": None})

    def test_the_recovery_reading_was_accepted_by_the_user(self):
        # 2026-10-31: the user accepted reading (a), counted from the first second below
        # 0.99 x Q(C); the seconds before the harm builds up are not a recovery.
        record = "Reading (a) was accepted by the user on 2026-10-31"
        self.assertIn(record, " ".join(O.__doc__.split()))
        with open(os.path.join(REPO, "docs", "EVALUATION.md"), encoding="utf-8") as fh:
            self.assertIn("(a) starts counting at the first second below the threshold, a reading the "
                          "user accepted on 2026-10-31", " ".join(fh.read().split()))
        q = bins(99.5, 50.0, start=60, until=100)        # harm builds up for 30 s, then 40 s low
        self.assertEqual(O.recovery_s(q, 98.5), 75)       # 100 + 5 - 30, not the first 5 seconds
        self.assertIn("Re-registration record (D-035, V-01", O.__doc__)

    def test_the_share_of_blocks(self):
        self.assertEqual([O.enough(k, 10) for k in (8, 9, 10)], [False, True, True])
        self.assertEqual([O.enough(k, 12) for k in (10, 11)], [False, True])
        self.assertFalse(O.enough(0, 0))


def noisy(rng, n, qc, onset, true_rec, harm):
    """1-s bins with binomial noise (review T-039 work/sim_recovery.py): n judged requests a second, each a success
    with probability Q(C) before the harm and after the true recovery, `harm` during it; the harm runs from `onset`
    to `true_rec` seconds after the attack's start."""
    out = []
    for i in range(O.RUN_S):
        p = harm if onset <= i - O.TIMELINE["baseline_s"] < true_rec else qc / 100.0
        out.append(100.0 * rng.binomialvariate(n, p) / n)
    return out


class NoisyRecoveryTest(unittest.TestCase):
    """D-035 (V-01): with the harm starting 30 s into the attack, a true recovery at +95 s must fail (a) and one at
    +60 s must pass, at 20 and 50 judged requests a second and Q(C) 99.5 and 99.9; seeded."""

    CASES = tuple((n, qc, harm) for n in (20, 50) for qc in (99.5, 99.9) for harm in (0.60, 0.90))

    def pass_rate(self, rng, n, qc, true_rec, harm, blocks=200):
        hits = 0
        for _ in range(blocks):
            r = O.recovery_s(noisy(rng, n, qc, 30, true_rec, harm), O.RECOVERY_RATIO * qc)
            hits += r is not None and r <= O.T_MIT_S
        return hits / blocks

    def test_the_per_block_pass_rates(self):
        rng = random.Random(20261031)
        for n, qc, harm in self.CASES:
            late, early = self.pass_rate(rng, n, qc, 95, harm), self.pass_rate(rng, n, qc, 60, harm)
            self.assertLessEqual(late, 0.05, (n, qc, harm, "recovery at +95 s"))
            self.assertGreaterEqual(early, 0.90, (n, qc, harm, "recovery at +60 s"))

    def test_criterion_a_over_ten_noisy_blocks(self):
        # (a) over 10 blocks, in 40 seeded campaigns per case: never passed with the true recovery at +95 s, passed
        # in at least 36 of 40 with it at +60 s. The per-block rate at 50 judged requests a second and Q(C) 99.5 is
        # about 0.97 (one failed request in 50 puts a bin under the bar), so about 3.5 % of honest campaigns fail
        # (a) there (artifacts/v01_pass_rates.txt of T-023c); a single seeded campaign would pin luck, not the rule.
        rng = random.Random(31)
        for n, qc, harm in self.CASES:
            for true_rec, low, high in ((95, 0, 0), (60, 36, 40)):
                passed, onsets = 0, []
                for _ in range(40):
                    over = {}
                    for i in range(10):
                        over[("C", i)] = {"q": qc}
                        over[("M_pc_loris", i)] = {"q_per_s": noisy(rng, n, qc, 30, true_rec, harm)}
                    m = O.outcome(campaign(over))["families"]["loris"]["mitigation"]
                    passed += m["a"]
                    onsets += m["recovery_onset_s"]
                self.assertTrue(low <= passed <= high, (n, qc, harm, true_rec, passed))
                # counted from the harm: its first second, or up to 4 s before it when noisy healthy bins join its run
                inside = sum(1 for o in onsets if o is not None and 26 <= o < true_rec) / len(onsets)
                self.assertGreaterEqual(inside, 0.95, (n, qc, harm, true_rec))

class OutcomeTest(unittest.TestCase):
    def test_both_families_harmful_and_mitigated(self):
        res = O.outcome(campaign())
        self.assertEqual(res["M7"], BOTH)
        for f in O.FAMILIES:
            fam = res["families"][f]
            self.assertEqual(fam["status"], "mitigated")
            self.assertEqual((fam["harm"]["valid_blocks"], fam["harm"]["blocks_individually"]), (10, 10))
            self.assertFalse(fam["harm"]["placebo_passes"])
            self.assertEqual(fam["mitigation"]["recovery_s"], [35] * 10)
            self.assertEqual(fam["mitigation"]["vs_m_def"]["decision"], "supported (+)")
        self.assertEqual(res["bans_by_arm"]["M_def_loris"], {"cgnat": 10})
        self.assertEqual(res["bans_by_arm"]["M_pc_post"], {"attack": 10})

    def test_one_family_mitigated_too_late_names_the_other(self):
        late = {"q_per_s": bins(99.5, 50.0, until=125), "q_level": 98.0}
        res = O.outcome(campaign({"M_pc_post": late}))
        self.assertEqual(res["M7"], "supported with scope: profile R, Slowloris at this scale, this testbed")
        m = res["families"]["post"]["mitigation"]
        self.assertEqual((res["families"]["post"]["status"], m["a"], m["b"], m["recovered_in_time"]),
                         ("harmful but not mitigated", False, False, 0))

    def test_a_cgnat_ban_in_one_m_pc_run_is_collateral(self):
        res = O.outcome(campaign({("M_pc_loris", 3): {"banned": {"10.0.4.1": "cgnat"}}}))
        loris = res["families"]["loris"]
        self.assertEqual(loris["status"], "mitigated with collateral")
        self.assertEqual(loris["mitigation"]["benign_banned"], [[3104, "10.0.4.1", "cgnat"]])
        self.assertEqual(res["M7"], "supported with scope: profile R, slow POST at this scale, this testbed")

    def test_no_harm_no_claim(self):
        over = {f"U_{f}": {"q": 98.5, "p95": 0.10, "q_per_s": bins(99.5)} for f in O.FAMILIES}
        res = O.outcome(campaign(over))
        self.assertEqual(res["M7"], "not supported")
        self.assertEqual({r["status"] for r in res["families"].values()}, {"not harmful"})

    def test_the_stricter_count_needs_9_of_10_blocks(self):
        # Mean dQ about 25 pp, interval above 0, every sign positive: the gate passes, but only 8
        # of 10 blocks reach 10 pp on their own.
        over = {("U_loris", i): {"q": 95.0, "p95": 0.10} for i in (8, 9)}
        res = O.outcome(campaign(over))
        harm = res["families"]["loris"]["harm"]
        self.assertTrue(harm["gate_Q"]["passed"])
        self.assertEqual((harm["blocks_individually"], harm["harmful"]), (8, False))
        self.assertEqual(res["families"]["loris"]["status"], "not harmful")

    def test_a_placebo_that_passes_voids_the_harm(self):
        over = {("Cp", i): {"q": 60.0 + i, "p95": 0.40} for i in range(10)}
        res = O.outcome(campaign(over))
        self.assertTrue(res["families"]["loris"]["harm"]["placebo_passes"])
        self.assertEqual(res["M7"], "not supported")

    def test_fewer_than_10_valid_blocks_decide_nothing(self):
        # Updated by D-035 (V-02): this test pinned "not harmful" for 9 valid blocks, a negative verdict made of missing
        # data. Updated by D-050: a block is judged on one attempt with every needed arm valid, so an invalid arm of one
        # family takes the block from both, and M7 is invalid instead of naming the family next to the other's claim.
        res = O.outcome(campaign({("U_post", 0): {"valid": False}}))
        for family in res["families"].values():
            self.assertEqual(family["harm"]["valid_blocks"], 9)
            self.assertEqual(family["status"], "invalid (9 of 10 valid)")
        self.assertEqual(res["M7"], "invalid (9 of 10 valid)")

    def test_missing_data_is_never_a_negative_verdict(self):
        res = O.outcome(campaign({("U_post", 0): {"valid": False}, ("Cp", 4): {"valid": False}}))
        self.assertEqual({r["status"] for r in res["families"].values()}, {"invalid (8 of 10 valid)"})
        self.assertEqual(res["M7"], "invalid (8 of 10 valid)")
        res = O.outcome(campaign({("M_pc_loris", 2): {"valid": False}}))
        self.assertEqual(res["families"]["loris"]["status"], "invalid (9 of 10 valid)")    # not "not mitigated"
        runs = [r for r in campaign() if r["block"] != 3110]                               # a block never run
        res = O.outcome(runs)
        self.assertEqual(res["M7"], "invalid (9 of 10 valid)")
        over = {f"U_{f}": {"q": 98.5, "p95": 0.10, "q_per_s": bins(99.5)} for f in O.FAMILIES}
        over[("U_post", 0)] = {"valid": False}
        res = O.outcome(campaign(over))
        self.assertEqual(res["M7"], "invalid (9 of 10 valid)")                             # never "not harmful"
        self.assertEqual(O.invalid(7), "invalid (7 of 10 valid)")
        self.assertIn("Re-registration record (D-035, V-02", O.__doc__)

    def test_the_level_window_alone_can_fail_mitigation(self):
        res = O.outcome(campaign({"M_pc_loris": {"q_level": 98.0}}))
        m = res["families"]["loris"]["mitigation"]
        self.assertEqual((m["a"], m["b"], res["families"]["loris"]["status"]),
                         (True, False, "harmful but not mitigated"))


class AttemptsTest(unittest.TestCase):
    """D-050 (review T-047 P-03, P-04): a block is judged on one attempt, the last with every needed arm valid, all arms from
    it; (c) and the benign closes count over all attempts; a re-run needs a reason and the budget holds 2."""

    def test_a_ban_in_an_invalid_attempt_is_not_hidden_by_the_re_run(self):
        runs = rerun(campaign(), 3104, {"M_pc_loris": {"valid": False, "benign_closed": 3,
                                                       "banned": {"10.0.4.1": "cgnat", "10.0.3.1": "attack"}}})
        res = O.outcome(runs)
        loris = res["families"]["loris"]
        self.assertEqual(loris["status"], "mitigated with collateral")
        self.assertEqual(loris["mitigation"]["benign_banned"], [[3104, "10.0.4.1", "cgnat"]])
        self.assertEqual((loris["mitigation"]["benign_closed"], loris["mitigation"]["attempts"]), (3, 11))
        self.assertTrue(loris["mitigation"]["a"] and loris["mitigation"]["b"])
        self.assertEqual(res["bans_by_arm"]["M_pc_loris"], {"attack": 11, "cgnat": 1})

    def test_the_judged_attempt_gives_every_arm_and_the_rest_are_listed(self):
        # Attempt 1 lacks U_post; attempt 2 is complete, with another C and another M_pc. Nothing of attempt 1 is read.
        late = {"q_per_s": bins(99.5, 50.0, until=125), "q_level": 98.0}
        runs = campaign({("U_post", 0): {"valid": False}, ("M_pc_loris", 0): late})
        bad_first = rerun(runs, 3101, {"M_pc_loris": {"q_per_s": bins(99.5), "q_level": 99.6}})
        for r in bad_first:
            if r["block"] == 3101 and r["attempt"] == 2:
                r["valid"] = True
        res = O.outcome(bad_first)
        self.assertEqual(res["judged_attempts"][3101], 2)
        self.assertEqual(res["superseded_attempts"], [{"block": 3101, "attempt": 1, "invalid_or_missing": ["U_post"]}])
        self.assertEqual(max(res["families"]["loris"]["mitigation"]["recovery_s"]), 100)            # attempt 2's M_pc
        self.assertEqual(res["judged_attempts"][3102], 1)

    def test_arms_are_never_mixed_across_attempts(self):
        # Review T-047's F3: attempt 1 lacks U_post, and attempt 2's C is not healthy. Each attempt holds a good half; no
        # attempt holds every needed arm, so the block is not judged and nothing is paired across attempts.
        runs = campaign({("U_post", 0): {"valid": False}})
        mixed = rerun(runs, 3101)
        for r in mixed:
            if r["block"] == 3101 and r["attempt"] == 2:
                r["valid"] = True
                if r["arm"] == "C":
                    r["control_reasons"] = ["Q(C) is 98.00 %, below 99 %"]
        res = O.outcome(mixed)
        self.assertIsNone(res["judged_attempts"][3101])
        self.assertEqual({r["harm"]["valid_blocks"] for r in res["families"].values()}, {9})
        self.assertEqual(res["M7"], "invalid (9 of 10 valid)")
        self.assertEqual([s["attempt"] for s in res["superseded_attempts"]], [1, 2])

    def test_a_re_run_of_a_complete_attempt_is_refused(self):
        # Review T-047's F2: a verdict must not be re-run into existence.
        with self.assertRaisesRegex(ValueError, "whose every needed arm was valid"):
            O.outcome(rerun(campaign(), 3101))

    def test_an_invalid_m_def_is_no_reason_for_a_re_run(self):
        self.assertNotIn("M_def_loris", O.NEEDED_ARMS)
        self.assertNotIn("M_def_post", O.NEEDED_ARMS)
        res = O.outcome(campaign({("M_def_loris", 2): {"valid": False}}))
        self.assertEqual(res["M7"], BOTH)                                                 # it judges nothing
        self.assertEqual(res["families"]["loris"]["mitigation"]["vs_m_def"]["n"], 9)
        with self.assertRaisesRegex(ValueError, "whose every needed arm was valid"):
            O.outcome(rerun(campaign(), 3103, {"M_def_loris": {"valid": False}}))

    def test_at_most_two_re_runs(self):
        first = {"U_post": {"valid": False}}
        two = rerun(rerun(campaign(), 3101, first), 3102, first)
        self.assertEqual(O.outcome(two)["M7"], BOTH)
        with self.assertRaisesRegex(ValueError, "3 re-runs in the campaign, at most 2"):
            O.outcome(rerun(two, 3103, first))
        self.assertEqual(O.MAX_RERUNS, 2)

    def test_attempt_numbers_are_1_2_and_so_on(self):
        runs = [dict(r, attempt=2) if r["block"] == 3101 else r for r in campaign()]
        with self.assertRaisesRegex(ValueError, "not 1, 2"):
            O.outcome(runs)

    def test_every_record_names_its_attempt(self):
        runs = campaign()
        runs[5] = {k: v for k, v in runs[5].items() if k != "attempt"}
        with self.assertRaisesRegex(ValueError, "names its attempt"):
            O.outcome(runs)
        runs = campaign()
        runs.append(dict(runs[3]))
        with self.assertRaisesRegex(ValueError, "two records"):
            O.outcome(runs)
        self.assertIn("Re-registration record (D-035, V-03", O.__doc__)

    def test_the_command_line_lists_what_is_superseded(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "runs.jsonl")
            with open(path, "w", encoding="utf-8") as fh:
                fh.writelines(json.dumps(r) + "\n" for r in rerun(campaign(), 3101, {"U_post": {"valid": False}}))
            printed = io.StringIO()
            with contextlib.redirect_stdout(printed):
                self.assertEqual(O.main([path]), 0)
        self.assertIn("superseded: block 3101 attempt 1, invalid or missing U_post", printed.getvalue())


class ProtectedControlTest(unittest.TestCase):
    """D-041 and D-046: (b) is judged against C_M's level over the same window; (a) and the harm are what they were; C_M's
    validity rules are C's."""

    def test_b_reads_c_ms_level_over_the_same_window_not_its_q(self):
        # D-046: the limits' cost sits in C_M's attack window (Q 96), not in its level window (99.6). A run at 97.5 %
        # over the level window is 2 pp under what C_M does there, and fails, although it clears 0.99 x 96.
        cold = O.outcome(campaign({"C_M": {"q": 96.0, "q_level": 99.6},
                                   "M_pc_loris": {"q_level": 97.5}}))["families"]["loris"]["mitigation"]
        self.assertEqual((cold["b"], cold["level_blocks"], cold["level_mean_ok"]), (False, 0, False))
        # The other way: a C_M whose level is low sets a low bar, whatever its Q over the attack window.
        low = O.outcome(campaign({"C_M": {"q": 99.9, "q_level": 97.0},
                                  "M_pc_loris": {"q_level": 96.5}}))["families"]["loris"]["mitigation"]
        self.assertEqual((low["b"], low["level_blocks"], low["level_mean_ok"]), (True, 10, True))
        at_bar = O.outcome(campaign({"C_M": {"q": 50.0, "q_level": 100.0},
                                     "M_pc_post": {"q_level": 99.0}}))["families"]["post"]["mitigation"]
        self.assertEqual((at_bar["b"], at_bar["level_blocks"]), (True, 10))           # at 0.99 x its level exactly

    def test_the_protected_control_is_the_bar_of_b(self):
        # The limits cost 2 pp and M_pc holds what they leave: under 0.99 x Q(C), at 0.99 x Q(C_M).
        low = O.outcome(campaign({"C_M": {"q": 97.5}, "M_pc_loris": {"q_level": 97.0}}))["families"]["loris"]
        self.assertEqual((low["mitigation"]["b"], low["mitigation"]["level_blocks"], low["status"]),
                         (True, 10, "mitigated"))
        # A protected control above M_pc fails (b), although M_pc is within 0.99 x Q(C) (98.5 to 98.7).
        high = O.outcome(campaign({"C_M": {"q": 99.9}, "M_pc_loris": {"q_level": 98.8}}))["families"]["loris"]
        self.assertEqual((high["mitigation"]["b"], high["mitigation"]["level_blocks"], high["status"]),
                         (False, 0, "harmful but not mitigated"))
        at_bar = O.outcome(campaign({"C_M": {"q": 100.0}, "M_pc_post": {"q_level": 99.0}}))["families"]["post"]
        self.assertTrue(at_bar["mitigation"]["b"])                                   # at 0.99 x Q(C_M) exactly

    def test_a_and_the_harm_stay_on_the_unprotected_control(self):
        # M_pc back at the limits' level only: 97 % never reaches 0.99 x Q(C), so (a) fails although (b) holds. D-041
        # moved (b) alone; this pins it, and the report asks whether (a) should follow.
        flat = {"C_M": {"q": 97.5}, "M_pc_loris": {"q_per_s": bins(99.5, 97.0, start=35, until=270), "q_level": 97.0}}
        loris = O.outcome(campaign(flat))["families"]["loris"]
        self.assertEqual((loris["mitigation"]["a"], loris["mitigation"]["b"], loris["status"]),
                         (False, True, "harmful but not mitigated"))
        self.assertEqual(O.outcome(campaign({"C_M": {"q": 50.0}}))["families"]["loris"]["harm"],
                         O.outcome(campaign())["families"]["loris"]["harm"])

    def test_c_ms_validity_counts_for_the_block(self):
        # Since D-050 C_M is a needed arm: its block is judged on an attempt with C_M valid, or not at all.
        res = O.outcome(campaign({("C_M", 2): {"valid": False}}))
        self.assertEqual({r["status"] for r in res["families"].values()}, {"invalid (9 of 10 valid)"})
        self.assertEqual({r["harm"]["valid_blocks"] for r in res["families"].values()}, {9})
        self.assertEqual(res["M7"], "invalid (9 of 10 valid)")
        missing = [r for r in campaign() if not (r["arm"] == "C_M" and r["block"] == 3105)]
        self.assertEqual(O.outcome(missing)["families"]["post"]["mitigation"]["valid_blocks"], 9)
        again = rerun(campaign(), 3103, {"C_M": {"valid": False, "Q": 10.0}})         # the attempt with every arm is judged
        self.assertEqual(O.outcome(again)["M7"], BOTH)

    def test_c_m_has_no_floor_on_its_q(self):
        res = O.outcome(campaign({"C_M": {"q": 80.0}, "M_pc_loris": {"q_level": 79.5}}))
        self.assertEqual(res["families"]["loris"]["mitigation"]["valid_blocks"], 10)
        self.assertTrue(res["families"]["loris"]["mitigation"]["b"])

    def test_a_cgnat_or_browser_ban_in_c_m_counts_against_c(self):
        # D-046 (3) replaces D-041's "reported, not counted", which this test pinned: for both families, in C_M's arm alone.
        for ip, role in (("10.0.4.1", "cgnat"), ("10.0.1.7", "tpcw_browsing"), ("10.0.1.8", "search_user")):
            res = O.outcome(campaign({("C_M", 1): {"banned": {ip: role}}}))
            for f in O.FAMILIES:
                m = res["families"][f]["mitigation"]
                self.assertEqual((m["c"], m["benign_banned"], m["benign_banned_c_m"], res["families"][f]["status"]),
                                 (False, [], [[3102, ip, role]], "mitigated with collateral"), role)
            self.assertEqual(res["M7"], "not supported")
            self.assertEqual(res["bans_by_arm"]["C_M"], {role: 1})

    def test_a_ban_in_any_attempt_of_c_m_counts(self):
        runs = rerun(campaign(), 3104, {"C_M": {"valid": False, "banned": {"10.0.4.1": "cgnat"}}})
        m = O.outcome(runs)["families"]["loris"]["mitigation"]
        self.assertEqual((m["c"], m["benign_banned_c_m"], m["valid_blocks"]), (False, [[3104, "10.0.4.1", "cgnat"]], 10))

    def test_another_benign_identity_banned_in_c_m_stays_reported(self):
        for role in ("api_bulk", "crawler_polite", "uploader", "slow_uploader"):
            res = O.outcome(campaign({("C_M", 1): {"banned": {"10.0.4.9": role}}}))
            m = res["families"]["loris"]["mitigation"]
            self.assertEqual((m["c"], m["benign_banned_c_m"], res["M7"]), (True, [], BOTH), role)
            self.assertEqual(res["bans_by_arm"]["C_M"], {role: 1})
            self.assertEqual(res["limits_cost"]["blocks"][1]["benign_banned_C_M"], ["10.0.4.9"])

    def test_the_roles_are_the_labels_of_the_population(self):
        sys.path.insert(0, os.path.join(REPO, "ml"))
        import p4_traffic as PT
        labels = set(PT.roles(PT.build_plan(3101, "eval")["entities"]).values())
        self.assertEqual(O.C_M_COLLATERAL_ROLES, ("cgnat", "tpcw_browsing", "search_user"))
        self.assertEqual(labels - set(O.C_M_COLLATERAL_ROLES), {"api_bulk", "crawler_polite", "uploader", "slow_uploader"})
        self.assertLessEqual(set(O.C_M_COLLATERAL_ROLES), labels)


def refused_counts(cgnat12, cgnat24, others=0):
    return {"by_role": {"cgnat": {"requests": 2000, "refused": cgnat12 + cgnat24},
                        "tpcw_browsing": {"requests": 4000, "refused": others}},
            "cgnat": {"CGNAT-12": {"address": "10.0.17.3", "requests": 700, "refused": cgnat12},
                      "CGNAT-24": {"address": "10.0.18.9", "requests": 1300, "refused": cgnat24}}}


class LimitsCostTest(unittest.TestCase):
    """D-041: the deployed limits' own cost, a separate finding that judges nothing."""

    def over(self):
        out = {}
        for i in range(10):
            out[("C_M", i)] = {"q": 97.0 + 0.1 * i, "refused": refused_counts(5, 100 + i)}
            out[("C", i)] = {"refused": refused_counts(0, 0)}
        return out

    def test_q_c_m_against_q_c_and_the_refusals_by_role_with_the_pools_named(self):
        cost = O.outcome(campaign(self.over()))["limits_cost"]
        self.assertEqual(len(cost["blocks"]), 10)
        first = cost["blocks"][0]
        self.assertEqual((first["block"], first["Q_C"], first["Q_C_M"], first["refused_C"], first["refused_C_M"]),
                         (3101, 99.5, 97.0, 0, 105))
        self.assertAlmostEqual(first["dQ_pp"], 2.5)
        self.assertEqual(cost["decision"], "supported (+)")
        self.assertGreater(cost["mean_dQ_pp"], 2.0)
        self.assertEqual(cost["refused_by_role"]["cgnat"], {"requests": 20000, "refused": 50 + 1045})
        self.assertEqual(cost["refused_by_role"]["tpcw_browsing"]["refused"], 0)
        self.assertEqual(cost["refused_cgnat"], {"CGNAT-12": {"requests": 7000, "refused": 50},
                                                 "CGNAT-24": {"requests": 13000, "refused": 1045}})

    def test_the_rules_own_effect_in_c_m_is_shown(self):
        over = self.over()
        over[("C_M", 4)].update(banned={"10.0.4.1": "cgnat", "10.0.3.1": "attack"}, closed=7)
        row = O.outcome(campaign(over))["limits_cost"]["blocks"][4]
        self.assertEqual((row["benign_banned_C_M"], row["benign_closed_C_M"]), (["10.0.4.1"], 7))

    def test_it_judges_nothing_and_needs_valid_controls(self):
        plain, costed = O.outcome(campaign()), O.outcome(campaign({k: {"refused": v.get("refused")}
                                                                   for k, v in self.over().items()}))
        self.assertEqual((plain["M7"], plain["families"]["loris"]["status"]),
                         (costed["M7"], costed["families"]["loris"]["status"]))
        none = O.outcome(campaign())["limits_cost"]
        self.assertEqual((none["blocks"][0]["refused_C_M"], none["refused_by_role"]), (None, {}))
        over = self.over()
        over[("C_M", 0)]["valid"] = False
        over[("C", 1)]["valid"] = False
        cost = O.outcome(campaign(over))["limits_cost"]
        self.assertEqual([r["block"] for r in cost["blocks"]], list(O.BLOCK_SEEDS[2:]))
        self.assertIsNone(O.outcome([r for r in campaign() if r["arm"] != "C_M"])["limits_cost"]["mean_dQ_pp"])

    def test_the_command_line_prints_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = os.path.join(tmp, "runs.jsonl")
            with open(runs, "w", encoding="utf-8") as fh:
                fh.writelines(json.dumps(r) + "\n" for r in campaign(self.over()))
            printed = io.StringIO()
            with contextlib.redirect_stdout(printed):
                self.assertEqual(O.main([runs]), 0)
        self.assertIn("the deployed limits' own cost (judges nothing)", printed.getvalue())
        self.assertIn("CGNAT-24", printed.getvalue())


HEALTH_CAL = {"gate": {"control_q_min": 99.0}, "slo_ms": {"C0": 100, "C1": 300, "C5": 3000}}


class ControlHealthTest(unittest.TestCase):
    """D-046: eval/harm_gate.control_health is enforced for a block to count; an unhealthy control makes it invalid."""

    @staticmethod
    def metrics(q, c1=100.0):
        return {"Q": q, "p95_s": 0.1, "q_per_s": [q] * 270, "by_class": {"C1": {"n": 100, "ok": int(c1), "Q": c1}}}

    def summarize(self, arm, metrics, cal=HEALTH_CAL):
        return O.summarize(3101, arm, True, metrics, {"Q": metrics["Q"]}, [], {}, level_window=O.LEVEL_WINDOW_S,
                           attempt=1, cal=cal)

    def test_summarize_states_the_health_of_c_alone(self):
        self.assertEqual(self.summarize("C", self.metrics(99.0))["control_reasons"], [])
        self.assertIn("below 99 %", self.summarize("C", self.metrics(98.9))["control_reasons"][0])
        self.assertIn("class C1", self.summarize("C", self.metrics(99.5, c1=94.0))["control_reasons"][0])
        loose = {**HEALTH_CAL, "gate": {"control_q_min": 90.0}}
        self.assertTrue(self.summarize("C", self.metrics(95.0), loose)["control_reasons"], "the floor is pinned")
        for arm in ("Cp", "C_M", "M_pc_loris"):
            self.assertIsNone(self.summarize(arm, self.metrics(80.0))["control_reasons"])
        with self.assertRaisesRegex(ValueError, "D-046"):
            self.summarize("C", self.metrics(99.5), cal=None)

    def test_the_class_floor_needs_20_judged_requests(self):
        # D-050 (review T-047 P-11): one slow export must not decide a block.
        def with_class(n, ok):
            return {"Q": 99.5, "p95_s": 0.1, "q_per_s": [99.5] * 270,
                    "by_class": {"C1": {"n": 100, "ok": 100, "Q": 100.0}, "C5": {"n": n, "ok": ok, "Q": 100.0 * ok / n}}}
        small = self.summarize("C", with_class(19, 0))
        self.assertEqual(small["control_reasons"], [])
        self.assertEqual(small["control_small_classes"], {"C5": {"n": 19, "ok": 0, "Q": 0.0}})
        self.assertIn("class C5", self.summarize("C", with_class(20, 18))["control_reasons"][0])
        self.assertEqual(self.summarize("C", with_class(20, 19))["control_reasons"], [])
        self.assertEqual(self.summarize("C", with_class(20, 19))["control_small_classes"], {})
        low_q = {**with_class(5, 5), "Q": 98.9}                                    # Q(C) stays on every request
        self.assertIn("below 99 %", self.summarize("C", low_q)["control_reasons"][0])

    def test_harm_gates_function_is_unchanged_for_the_harm_benchmark(self):
        m = {"Q": 99.5, "by_class": {"C5": {"n": 2, "ok": 0, "Q": 0.0}}}
        self.assertIn("class C5", O.HG.control_health(m, {**HEALTH_CAL, "slo_ms": {"C5": 3000}})[0])

    def test_small_classes_are_reported_in_the_output(self):
        small = {"C5": {"n": 2, "ok": 2, "Q": 100.0}}
        runs = campaign()
        k = next(i for i, r in enumerate(runs) if r["arm"] == "C" and r["block"] == 3104)
        runs[k] = dict(runs[k], control_small_classes=small)
        self.assertEqual(O.outcome(runs)["small_control_classes"], [{"block": 3104, "attempt": 1, "classes": small}])

    def test_an_unhealthy_control_makes_the_block_invalid_never_a_negative_verdict(self):
        why = ["Q(C) is 98.00 %, below 99 %"]
        res = O.outcome(campaign({("C", 2): {"control_reasons": why}}))
        for fam in res["families"].values():
            self.assertEqual(fam["status"], "invalid (9 of 10 valid)")
            self.assertEqual((fam["harm"]["valid_blocks"], fam["mitigation"]["valid_blocks"]), (9, 9))
            self.assertEqual(fam["mitigation"]["vs_m_def"]["n"], 9)
        self.assertEqual(res["M7"], "invalid (9 of 10 valid)")
        self.assertEqual(res["unhealthy_controls"], [{"block": 3103, "attempt": 1, "reasons": why}])
        self.assertEqual(len(res["limits_cost"]["blocks"]), 9)

    def test_it_holds_when_the_harm_would_say_otherwise(self):
        over = {f"U_{f}": {"q": 98.5, "p95": 0.10, "q_per_s": bins(99.5)} for f in O.FAMILIES}
        over[("C", 0)] = {"control_reasons": ["x"]}
        res = O.outcome(campaign(over))
        self.assertEqual({r["status"] for r in res["families"].values()}, {"invalid (9 of 10 valid)"})   # not "not harmful"

    def test_a_re_run_with_a_healthy_control_counts_and_the_first_stays_reported(self):
        res = O.outcome(rerun(campaign(), 3103, {"C": {"control_reasons": ["x"]}}))
        self.assertEqual(res["M7"], BOTH)
        self.assertEqual(res["unhealthy_controls"], [{"block": 3103, "attempt": 1, "reasons": ["x"]}])

    def test_a_run_that_was_not_sound_is_not_called_unhealthy(self):
        res = O.outcome(campaign({("C", 2): {"valid": False, "control_reasons": ["Q(C) is n/a"]}}))
        self.assertEqual(res["unhealthy_controls"], [])
        self.assertEqual(res["M7"], "invalid (9 of 10 valid)")

    def test_a_record_of_c_must_state_its_health(self):
        runs = campaign()
        k = next(i for i, r in enumerate(runs) if r["arm"] == "C")
        runs[k] = {a: v for a, v in runs[k].items() if a != "control_reasons"}
        with self.assertRaisesRegex(ValueError, "states its health"):
            O.outcome(runs)

    def test_the_command_line_names_the_unhealthy_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "runs.jsonl")
            with open(path, "w", encoding="utf-8") as fh:
                fh.writelines(json.dumps(r) + "\n" for r in campaign({("C", 2): {"control_reasons": ["low Q"]}}))
            printed = io.StringIO()
            with contextlib.redirect_stdout(printed):
                self.assertEqual(O.main([path]), 0)
        self.assertIn("unhealthy control, block 3103 attempt 1: low Q", printed.getvalue())


class InputTest(unittest.TestCase):
    def test_bad_records_are_refused(self):
        runs = campaign()
        for bad in (runs + [dict(runs[0])], runs + [rec(3111, "C", 99.0)], runs + [rec(3101, "M_tol", 99.0)]):
            with self.assertRaises(ValueError):
                O.outcome(bad)

    def test_summarize_from_the_harm_gate_metrics_and_the_events(self):
        q = [99.0, None, 98.0] * 90
        metrics = {"Q": 97.0, "p95_s": 0.2, "q_per_s": q}
        events = [{"kind": "start"}, {"kind": "ban", "ip": "10.0.3.1"}, {"kind": "ban", "ip": "10.0.4.1"}]
        closes = [{"ip": "10.0.4.1", "port": 1, "sport": 443}, {"ip": "10.0.4.1", "port": 1, "sport": 443},
                  {"ip": "10.0.3.1", "port": 2, "sport": 80}]
        roles = {"10.0.3.1": "attack", "10.0.4.1": "cgnat"}
        win = O.LEVEL_WINDOW_S
        r = O.summarize(3101, "M_pc_loris", True, metrics, {"Q": 98.0}, events, roles, closes, level_window=win,
                        attempt=1)
        self.assertEqual(r, {"block": 3101, "arm": "M_pc_loris", "attempt": 1, "valid": True, "Q": 97.0, "p95_s": 0.2,
                             "q_per_s": q, "q_level": 98.0, "level_window": [120.0, 240.0],
                             "banned": {"10.0.3.1": "attack", "10.0.4.1": "cgnat"}, "benign_closed": 1,
                             "refused": None, "control_reasons": None, "control_small_classes": None})
        with self.assertRaises(ValueError):
            O.summarize(3101, "C", True, metrics, {"Q": 98.0}, [{"kind": "ban", "ip": "10.9.9.9"}], roles,
                        level_window=win, attempt=1)

    def test_a_close_of_an_unlabelled_address_is_refused(self):
        metrics = {"Q": 97.0, "p95_s": 0.2, "q_per_s": [99.0] * 270}
        closes = [{"ip": "10.0.4.1", "port": 1, "sport": 443}, {"ip": "10.0.9.9", "port": 2, "sport": 80}]
        with self.assertRaisesRegex(ValueError, "10.0.9.9"):
            O.summarize(3101, "M_pc_loris", True, metrics, {"Q": 98.0}, [], {"10.0.4.1": "cgnat"}, closes,
                        level_window=O.LEVEL_WINDOW_S, attempt=1)

    def test_a_run_on_another_timeline_or_window_is_refused(self):
        metrics = {"Q": 97.0, "p95_s": 0.2, "q_per_s": [99.0] * 180}          # the 30 + 120 + 30 s schedule
        with self.assertRaises(ValueError):
            O.summarize(3101, "C", True, metrics, {"Q": 98.0}, [], {}, level_window=O.LEVEL_WINDOW_S, attempt=1)
        metrics["q_per_s"] = [99.0] * 270
        for window in ((30, 240), (60, 150), None):
            with self.assertRaises(ValueError):
                O.summarize(3101, "C", True, metrics, {"Q": 98.0}, [], {}, level_window=window, attempt=1)
        self.assertEqual(O.RUN_S, 270)
        short = campaign({("M_pc_loris", 4): {"q_per_s": bins(99.5, total=180)}})
        with self.assertRaisesRegex(ValueError, "180 one-second bins"):
            O.outcome(short)
        runs = campaign()
        runs[7] = dict(runs[7], level_window=[60.0, 240.0])
        with self.assertRaisesRegex(ValueError, "LEVEL_WINDOW_S"):
            O.outcome(runs)
        runs[7].pop("level_window")
        with self.assertRaises(ValueError):
            O.outcome(runs)

    def test_the_command_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs, out = os.path.join(tmp, "runs.jsonl"), os.path.join(tmp, "verdict.json")
            with open(runs, "w", encoding="utf-8") as fh:
                fh.writelines(json.dumps(r) + "\n" for r in campaign())
            printed = io.StringIO()
            with contextlib.redirect_stdout(printed):
                self.assertEqual(O.main([runs, "--json", out]), 0)
            with open(out, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["M7"], BOTH)
        self.assertIn(f"M7: {BOTH}", printed.getvalue())


if __name__ == "__main__":
    unittest.main()
