"""The pre-registered outcome of P4 (eval/p4_outcome.py; docs/P4_SLOW_DESIGN.md §10, T_mit re-registered to
90 s), on synthetic run records for every outcome the note names, before any evaluation data exist."""
import contextlib
import io
import json
import os
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


def rec(block, arm, q, p95=0.10, q_per_s=None, q_level=None, banned=None, valid=True, closed=0):
    return {"block": block, "arm": arm, "valid": valid, "Q": q, "p95_s": p95,
            "q_per_s": q_per_s if q_per_s is not None else bins(q),
            "q_level": q if q_level is None else q_level, "level_window": list(O.LEVEL_WINDOW_S),
            "banned": banned or {}, "benign_closed": closed}


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
        self.assertEqual(O.ARMS, ("C", "Cp", "U_loris", "U_post", "M_def_loris", "M_pc_loris",
                                  "M_def_post", "M_pc_post"))
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
    def test_the_recovery_time_after_the_first_dip(self):
        self.assertEqual(O.recovery_s(bins(99.5), 98.5), 0)                       # never dipped
        self.assertEqual(O.recovery_s(bins(99.5, 50.0, until=60), 98.5), 35)       # 60 + 5 - 30
        self.assertEqual(O.recovery_s(bins(99.5, 50.0, until=115), 98.5), 90)     # just in time
        self.assertEqual(O.recovery_s(bins(99.5, 50.0, until=116), 98.5), 91)
        self.assertIsNone(O.recovery_s(bins(99.5, 50.0), 98.5))                   # never back
        q = bins(99.5, 50.0, until=60)
        q[62] = None                                                              # an empty second
        self.assertEqual(O.recovery_s(q, 98.5), 38)

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

    def test_the_share_of_blocks(self):
        self.assertEqual([O.enough(k, 10) for k in (8, 9, 10)], [False, True, True])
        self.assertEqual([O.enough(k, 12) for k in (10, 11)], [False, True])
        self.assertFalse(O.enough(0, 0))


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
        res = O.outcome(campaign({("U_post", 0): {"valid": False}}))
        self.assertEqual(res["families"]["post"]["harm"]["valid_blocks"], 9)
        self.assertEqual(res["families"]["post"]["status"], "not harmful")
        self.assertEqual(res["M7"], "supported with scope: profile R, Slowloris at this scale, this testbed")

    def test_the_level_window_alone_can_fail_mitigation(self):
        res = O.outcome(campaign({"M_pc_loris": {"q_level": 98.0}}))
        m = res["families"]["loris"]["mitigation"]
        self.assertEqual((m["a"], m["b"], res["families"]["loris"]["status"]),
                         (True, False, "harmful but not mitigated"))


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
        r = O.summarize(3101, "M_pc_loris", True, metrics, {"Q": 98.0}, events, roles, closes, level_window=win)
        self.assertEqual(r, {"block": 3101, "arm": "M_pc_loris", "valid": True, "Q": 97.0, "p95_s": 0.2,
                             "q_per_s": q, "q_level": 98.0, "level_window": [120.0, 240.0],
                             "banned": {"10.0.3.1": "attack", "10.0.4.1": "cgnat"}, "benign_closed": 1})
        with self.assertRaises(ValueError):
            O.summarize(3101, "C", True, metrics, {"Q": 98.0}, [{"kind": "ban", "ip": "10.9.9.9"}], roles,
                        level_window=win)

    def test_a_run_on_another_timeline_or_window_is_refused(self):
        metrics = {"Q": 97.0, "p95_s": 0.2, "q_per_s": [99.0] * 180}          # the 30 + 120 + 30 s schedule
        with self.assertRaises(ValueError):
            O.summarize(3101, "C", True, metrics, {"Q": 98.0}, [], {}, level_window=O.LEVEL_WINDOW_S)
        metrics["q_per_s"] = [99.0] * 270
        for window in ((30, 240), (60, 150), None):
            with self.assertRaises(ValueError):
                O.summarize(3101, "C", True, metrics, {"Q": 98.0}, [], {}, level_window=window)
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
