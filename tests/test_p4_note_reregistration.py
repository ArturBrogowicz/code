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

    def test_every_superseded_statement_carries_its_marker(self):
        text = note()
        for old in ("T_mit = 30 s, as in the plan", "banned within 30 s of their first connection",
                    "120 s of attack and 30 s of recovery.", "within T_mit = 30 s of the attack start",
                    "over [attack start + 30 s, attack end]", "180 s of traffic"):
            at = text.index(old)
            self.assertIn("[re-registered:", text[at:at + 400], old)
        self.assertEqual(text[text.index("Two further forms"):].count("[re-registered:"), 9)

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
