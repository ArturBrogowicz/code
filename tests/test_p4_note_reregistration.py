"""The P4 design note carries its dated re-registrations (review T-039 V-07, T-029 P4-04): a reader of
docs/P4_SLOW_DESIGN.md meets T_mit 90 s, the 210 s attack and the recovery reading next to the superseded text, and
the values are the pinned code's."""
import os
import re
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "eval"))
import p4_outcome as O

import slow_pc

NOTE = os.path.join(REPO, "docs", "P4_SLOW_DESIGN.md")


def note():
    with open(NOTE, encoding="utf-8") as fh:
        return fh.read()


class ReRegistrationTest(unittest.TestCase):
    def test_the_dated_block_names_the_three_decisions_with_the_codes_values(self):
        text = note()
        block = text[text.index("**Re-registrations, dated, all before any P4 data**"):text.index("Two further forms")]
        for decision, date in (("D-025", "2026-10-30T14:33Z"), ("D-030", "2026-10-31T09:23Z"),
                               ("D-031", "2026-10-31T09:23Z")):
            self.assertRegex(block, rf"\| {decision} \| {re.escape(date)} \|")
        self.assertEqual(slow_pc.DEADLINE_S, 90.0)
        self.assertIn("T_mit 30 s → **90 s**", block)
        self.assertEqual(O.TIMELINE, {"baseline_s": 30, "attack_s": 210, "recovery_s": 30})
        self.assertIn("**210 s** (was 120 s)", block)
        self.assertEqual(O.LEVEL_WINDOW_S, (120, 240))
        self.assertIn("[120 s, 240 s] of the run (`LEVEL_WINDOW_S`)", block)

    def test_t052_is_dated_everywhere_before_the_code_it_judges(self):
        text = note()
        block = text[text.index("**Re-registrations, dated, all before any P4 data**"):text.index("Two further forms")]
        self.assertIn("| D-057 | 2026-11-03T14:09Z |", block)
        self.assertIn("| D-060 | 2026-11-04T11:32Z |", block)
        for n in range(1, 6):
            self.assertIn(f"| T-052 ({n}) | 2026-11-03T15:01Z |", block)
        for needle in ("`--selection`", "no readable socket of a benign role", "ban file is gone", "more than 10 s after its intended start",
                       "why each block is left out of the comparison with M_def"):
            self.assertIn(needle, block)
        with open(os.path.join(REPO, "docs", "EVALUATION.md"), encoding="utf-8") as fh:
            self.assertIn("**Re-registration record (T-052).** 2026-11-03T15:01Z", fh.read())
        for path in ("eval/p4_runner.py", "eval/p4_outcome.py", "eval/p4_validation.py"):
            with open(os.path.join(REPO, path), encoding="utf-8") as fh:
                self.assertIn("Re-registration record (T-052, 2026-11-03T15:01Z", fh.read(), path)

    def test_t052b_is_dated_everywhere_before_the_code_it_judges(self):
        text = note()
        block = text[text.index("**Re-registrations, dated, all before any P4 data**"):text.index("Two further forms")]
        self.assertIn("| T-052b | 2026-11-04T12:16Z |", block)
        for needle in ("`--phase campaign` before anything runs", "`l7_backend.require_frozen`", "No threshold, SLO or arm changes"):
            self.assertIn(needle, block)
        with open(os.path.join(REPO, "docs", "EVALUATION.md"), encoding="utf-8") as fh:
            self.assertIn("**Re-registration record (T-052b).** 2026-11-04T12:16Z", fh.read())
        for path in ("eval/p4_runner.py", "eval/p4_outcome.py"):
            with open(os.path.join(REPO, path), encoding="utf-8") as fh:
                self.assertIn("Re-registration record (T-052b, 2026-11-04T12:16Z", fh.read(), path)

    def test_d063_is_dated_everywhere_before_the_code_it_judges(self):
        text = note()
        block = text[text.index("**Re-registrations, dated, all before any P4 data**"):text.index("Two further forms")]
        for row in ("| D-063 (1) | 2026-11-04T13:04Z |", "| D-063 (2) | 2026-11-04T13:04Z |"):
            self.assertIn(row, block)
        for needle in ("a dead backend read as harm", "once per server start", "The 25 %, the estimator and the clock stay"):
            self.assertIn(needle, block)
        with open(os.path.join(REPO, "docs", "EVALUATION.md"), encoding="utf-8") as fh:
            self.assertIn("**Re-registration record (D-063).** 2026-11-04T13:04Z", fh.read())
        for path in ("eval/p4_runner.py", "gunicorn_profile_r.py"):
            with open(os.path.join(REPO, path), encoding="utf-8") as fh:
                self.assertIn("Re-registration record (D-063, 2026-11-04T13:04Z", fh.read(), path)

    def test_every_superseded_statement_carries_its_marker(self):
        text = note()
        for old in ("T_mit = 30 s, as in the plan", "banned within 30 s of their first connection",
                    "120 s of attack and 30 s of recovery.", "within T_mit = 30 s of the attack start",
                    "over [attack start + 30 s, attack end]", "180 s of traffic"):
            at = text.index(old)
            self.assertIn("[re-registered:", text[at:at + 400], old)
        self.assertEqual(text[text.index("Two further forms"):].count("[re-registered:"), 20)

    def test_t071_is_dated_before_the_code_it_judges(self):
        # T-074: the extension of T-071 as approved (D-069, D-073 to D-075), re-registered before any ladder data and before its code.
        text = note()
        block = text[text.index("**Re-registrations, dated, all before any P4 data**"):text.index("Two further forms")]
        for row in ("| D-069 | 2026-11-06T16:30Z |", "| D-073 (1) | 2026-11-07T08:33Z |", "| D-073 (2) | 2026-11-07T08:33Z |",
                    "| D-073 (3) | 2026-11-07T08:33Z |", "| D-073 (4) | 2026-11-07T08:33Z |", "| D-073 (5) | 2026-11-07T08:33Z |",
                    "| D-074 | 2026-11-07T08:33Z |", "| D-075 | 2026-11-07T08:33Z |"):
            self.assertIn(row, block)
        self.assertLess(block.index("| D-068 |"), block.index("| D-069 |"))
        for needle in ("**Slowloris only**", "`--families loris,post`", "**(100, 175, 250, 300, 400, 500)**",
                       "each higher level runs only once every lower level has 2 sound repeats and none of them is a knee",
                       "**0.5 × min(planned, 1,800)**", "**C and C' of a health phase on pilot seed 9101, before the ladder**",
                       "D-058's guard", "`p4-health/1`", "never fires the rule", "**benign clients run on CPU 7**",
                       "**attack generators and the runner on CPUs 3-6**", "`--loris 500` (560 addresses)", "\"not reachable\"",
                       "**No knee at the extended top is a reported result (rule A, R-021):**", "not applicable: no harmful attack",
                       "`eval/p4_outcome.py --knees`", "**grouped**", "a thread per source", "without `--group`"):
            self.assertIn(needle, block)
        after = text[text.index("Two further forms"):]
        for old, marker in (("If either of two pilot controls is unhealthy", "D-073 (3)]"),
                            ("{100, 175, 250, 300} from the per-seed pool", "(100, 175, 250, 300, 400, 500)"),
                            ("~1,800 (L7-03 needed ~1,900", "Slow Read's figure"),
                            ("it must stay under R's 60 s header timeout", "read in P4-S s2, D-073 (5)]"),
                            ("so they never reach the access log", "s2 counts them, D-073 (5)]"),
                            ("2 families × 3 levels (the 4th only if no knee is found)", "D-069, D-073 (1), (3)]"),
                            ("**The cut**, Slowloris only", "the cut is the plan, with C_M, D-069]"),
                            ("The ladder's top level is 300", "the loris generators are grouped, D-073 (1), (5), D-075]"),
                            ("VM timer stalls inflate client-side latency", "run on CPU 7 itself, D-073 (4)]")):
            at = after.index(old)
            self.assertIn(marker, after[at:at + 700], old)
        self.assertIn("**Status (2026-11-07):", text)

    def test_d046_is_dated_everywhere_before_the_code_it_judges(self):
        text = note()
        block = text[text.index("**Re-registrations, dated, all before any P4 data**"):text.index("Two further forms")]
        for row in ("| D-046 (1) | 2026-11-01T15:52Z |", "| D-046 (2) | 2026-11-01T15:52Z |",
                    "| D-046 (3) | 2026-11-01T15:52Z |"):
            self.assertIn(row, block)
        for needle in ("0.99 × C_M's level over the same window", "`harm_gate.control_health`", "invalid (k of 10 valid)",
                       "A CGNAT or browser identity banned in C_M"):
            self.assertIn(needle, block)
        for marker in ("against 0.99 × C_M's level over the same window, D-046]", "a healthy control", "banned in C_M counts too"):
            self.assertIn(marker, text[text.index("Two further forms"):])
        with open(os.path.join(REPO, "docs", "EVALUATION.md"), encoding="utf-8") as fh:
            self.assertIn("**Re-registration record (D-046).** 2026-11-01T15:52Z", fh.read())
        self.assertIn("Re-registration record (D-046; 2026-11-01T15:52Z", O.__doc__)

    def test_d041_is_dated_everywhere_before_the_code_it_judges(self):
        text = note()
        block = text[text.index("**Re-registrations, dated, all before any P4 data**"):text.index("Two further forms")]
        for row in ("| D-041 (1) | 2026-10-31T16:06Z |", "| D-041 (2) | 2026-10-31T16:06Z |"):
            self.assertIn(row, block)
        for needle in ("0.99 × Q(C_M) instead of Q(C)", "(a) and the harm stay on Q(C)", "503s by role",
                       "the CGNAT pools named"):
            self.assertIn(needle, block)
        for needle in ("liveness bound applies to the validation runs too", "names the invalid family",
                       "each block's runs in a seeded order", "class C6 doing C2's work until a measured C6 cost exists"):
            self.assertIn(needle, block)
        with open(os.path.join(REPO, "docs", "EVALUATION.md"), encoding="utf-8") as fh:
            self.assertIn("**Re-registration record (D-041).** 2026-10-31T16:06Z", fh.read())
        self.assertIn("Re-registration record (D-041; 2026-10-31T16:06Z", O.__doc__)
        for path in ("eval/p4_runner.py", "l7_backend.py"):
            with open(os.path.join(REPO, path), encoding="utf-8") as fh:
                self.assertIn("D-041", fh.read(), path)

    def test_d050_is_dated_everywhere_before_the_code_it_judges(self):
        text = note()
        block = text[text.index("**Re-registrations, dated, all before any P4 data**"):text.index("Two further forms")]
        for row in ("| D-050 (1) | 2026-11-02T08:48Z |", "| D-050 (2) | 2026-11-02T08:48Z |",
                    "| D-050 (3) | 2026-11-02T08:48Z |"):
            self.assertIn(row, block)
        for needle in ("refuses `--attempt N`", "at most 2 re-run blocks", "judged on one attempt",
                       "superseded attempts are listed", "stub_status is recorded, never a validity rule",
                       "at least 20 judged requests"):
            self.assertIn(needle, block)
        self.assertIn("a block is judged on one attempt, D-050]", text[text.index("Two further forms"):])
        with open(os.path.join(REPO, "docs", "EVALUATION.md"), encoding="utf-8") as fh:
            self.assertIn("**Re-registration record (D-050).** 2026-11-02T08:48Z", fh.read())
        self.assertIn("Re-registration record (D-050; 2026-11-02T08:48Z", O.__doc__)
        with open(os.path.join(REPO, "eval", "p4_runner.py"), encoding="utf-8") as fh:
            self.assertIn("Re-registration record (D-050, 2026-11-02T08:48Z", fh.read())

    def test_the_budget_counts_what_it_left_out(self):
        # Review T-047 P-17: the packet, the ladder's 4th level and each halving's repeat.
        run_h = 5.5 / 60
        packet, ladder, validation, campaign, reruns = 0.8, 24 * run_h, 6 * run_h, 90 * run_h, 18 * run_h
        total = packet + ladder + validation + campaign + reruns
        self.assertEqual((f"{total:.1f}", f"{total - reruns:.1f}"), ("13.5", "11.8"))
        self.assertEqual((f"{8 * run_h:.2f}", f"{2 * run_h:.2f}", f"{32 * run_h:.1f}"), ("0.73", "0.18", "2.9"))
        self.assertEqual(f"{total + 8 * run_h + 32 * run_h:.1f}", "17.1")
        with open(os.path.join(REPO, "docs", "EVALUATION.md"), encoding="utf-8") as fh:
            evaluation = fh.read()
        for text in (note(), evaluation):
            flat = " ".join(text.split())
            self.assertIn("**~13.5 h**, ~11.8 h without re-runs", flat)
            self.assertIn("The worst case with one halving is ~17.1 h", flat)
        self.assertTrue(note().startswith("# P4:"))
        self.assertIn("**Status (2026-11-02): approved, and built offline", note())

    def test_the_vm_budget_of_d041_is_section_11s_arithmetic(self):
        minutes = 5.5                                  # 270 s of traffic plus about 60 s of set-up, §11's method
        smoke, ladder, validation = 3, 24, 6
        campaign, reruns = 10 * 9, 2 * 9               # 9 runs a block with C_M; re-runs of at most 2 blocks
        without = (smoke + ladder + validation + campaign) * minutes / 60
        total = without + reruns * minutes / 60
        self.assertEqual((f"{campaign * minutes / 60:.2f}", f"{reruns * minutes / 60:.2f}"), ("8.25", "1.65"))
        self.assertEqual((f"{total:.1f}", f"{without:.1f}"), ("12.9", "11.3"))
        block = note()
        self.assertIn("campaign 90 runs, 8.25 h; re-runs at most 18, 1.65 h; in all ~12.9 h, ~11.3 h without re-runs",
                      block)


if __name__ == "__main__":
    unittest.main()
