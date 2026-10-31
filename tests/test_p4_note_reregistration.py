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
        self.assertEqual(text[text.index("Two further forms"):].count("[re-registered:"), 6)


if __name__ == "__main__":
    unittest.main()
