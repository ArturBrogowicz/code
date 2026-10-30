"""The frozen threshold-selection rule of the per-connection slow rule (docs/P4_SLOW_DESIGN.md
§6.4, §13 row 3). It was committed before any P4 data existed; these tests pin it, so changing
it after the validation runs is a visible decision, not a silent edit."""
import hashlib
import itertools
import os
import sys
import unittest
from fractions import Fraction

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
import slow_pc as P

# sha256 of the frozen block of slow_pc.py, from its first marker line to its end marker.
FROZEN_SHA256 = "f61293355524100a8adba6748beb8b3948fa744d5a2aeb8c2e3dbcd684dbdebb"   # renewed for P4-01


def frozen_block():
    with open(os.path.join(REPO, "slow_pc.py"), encoding="utf-8") as fh:
        text = fh.read()
    start = text.index("# ── Frozen 2026-10-30, before any data")
    end = text.index("# ── End of the frozen block")
    return text[start:end]


def outcome(banned=5, benign_banned=0, closed=0, slow=0, attackers=10, conns=1000):
    return P.Outcome(attack_addresses=attackers, attack_banned_in_time=banned,
                     benign_addresses_banned=benign_banned, benign_connections=conns,
                     benign_connections_closed=closed, slow_uploader_closed=slow)


def grid(default=None, **points):
    """Every grid point at `default` (an Outcome), with the overrides {"T_F_K": Outcome}."""
    base = default or outcome(banned=0)
    table = dict.fromkeys(P.GRID, base)
    for name, o in points.items():
        t, f, k = (int(x) for x in name.lstrip("p").split("_"))
        table[(t, f, k)] = o
    return table


class FrozenConstantsTest(unittest.TestCase):
    def test_the_grid_and_the_fixed_constants(self):
        self.assertEqual((P.T_GRID_S, P.F_GRID_BPS, P.K_GRID),
                         ((5, 10, 15, 20), (16, 64, 256, 1024), (2, 3, 4, 6)))
        self.assertEqual(P.GRID, tuple(itertools.product(P.T_GRID_S, P.F_GRID_BPS, P.K_GRID)))
        self.assertEqual(len(P.GRID), 64)
        self.assertEqual(
            (P.ANSWERED_MAX_BYTES_80, P.DRIBBLE_MIN_SEGS, P.PERSISTENCE_POLLS, P.BAN_WINDOW_S,
             P.SHARED_UA_KEYS, P.UA_WINDOW_S, P.BAN_TTL_S, P.MAX_CLOSES_PER_POLL,
             P.MAX_BANS_PER_MIN, P.DEADLINE_S, P.BENIGN_CLOSE_BUDGET, P.VALIDATION_SEEDS,
             P.VALIDATION_RUNS),
            (64, 2, 3, 60.0, 3, 600.0, 300, 500, 20, 90.0, (1, 1000), (4001, 4002),
             ("C", "U_loris", "U_post")))

    def test_t_mit_was_re_registered_to_90_s_before_any_data(self):
        # P4-01, the user's decision of 2026-10-30: the record is in the pinned block and in
        # docs/EVALUATION.md; nothing else of the grid or the rule changed (the test above).
        record = ("2026-10-30: T_mit 30 → 90 s, decided by the user BEFORE any data, because the "
                  "frozen detector's dribble leg needs 2 data segments after the first poll.")
        self.assertEqual(P.DEADLINE_S, 90.0)
        self.assertIn(record, " ".join(frozen_block().replace("#", " ").split()))
        with open(os.path.join(REPO, "docs", "EVALUATION.md"), encoding="utf-8") as fh:
            self.assertIn(record, " ".join(fh.read().split()))

    def test_the_frozen_block_is_unchanged(self):
        self.assertEqual(hashlib.sha256(frozen_block().encode("utf-8")).hexdigest(),
                         FROZEN_SHA256)


class ConstraintsTest(unittest.TestCase):
    def test_every_constraint_must_hold(self):
        self.assertTrue(P.feasible(outcome()))
        self.assertFalse(P.feasible(outcome(benign_banned=1)))     # a CGNAT pool, say
        self.assertFalse(P.feasible(outcome(closed=1, slow=1)))     # one slow uploader closed

    def test_the_benign_close_budget_is_one_in_a_thousand_inclusive(self):
        self.assertTrue(P.feasible(outcome(closed=1, conns=1000)))
        self.assertTrue(P.feasible(outcome(closed=2, conns=2000)))
        self.assertFalse(P.feasible(outcome(closed=2, conns=1999)))
        self.assertFalse(P.feasible(outcome(closed=1, conns=999)))


class SelectionTest(unittest.TestCase):
    def test_the_largest_share_banned_in_time_wins(self):
        sel = P.select_thresholds(grid(p5_1024_2=outcome(banned=9), p10_64_3=outcome(banned=8)))
        self.assertEqual(sel, P.Selection((5, 1024, 2), Fraction(9, 10), 64))

    def test_a_point_that_breaks_a_constraint_cannot_win(self):
        table = grid(p5_1024_2=outcome(banned=10, benign_banned=1),
                     p5_256_2=outcome(banned=10, closed=2, conns=1000),
                     p5_64_2=outcome(banned=10, closed=1, slow=1),
                     p20_16_6=outcome(banned=3))
        sel = P.select_thresholds(table)
        self.assertEqual((sel.point, sel.share, sel.feasible), ((20, 16, 6), Fraction(3, 10), 61))

    def test_ties_go_to_the_larger_t_then_the_smaller_f_then_the_larger_k(self):
        same = outcome(banned=7)
        self.assertEqual(P.select_thresholds(grid(p5_16_6=same, p10_1024_2=same)).point,
                         (10, 1024, 2))
        self.assertEqual(P.select_thresholds(grid(p10_64_6=same, p10_16_2=same)).point,
                         (10, 16, 2))
        self.assertEqual(P.select_thresholds(grid(p10_16_2=same, p10_16_4=same)).point,
                         (10, 16, 4))

    def test_with_nothing_banned_anywhere_the_most_conservative_point_is_chosen(self):
        sel = P.select_thresholds(grid())
        self.assertEqual((sel.point, sel.share), ((20, 16, 6), Fraction(0)))

    def test_no_feasible_point_fails_the_budget(self):
        sel = P.select_thresholds(grid(outcome(banned=10, benign_banned=2)))
        self.assertEqual(sel, P.Selection(None, None, 0))

    def test_the_input_must_be_exactly_the_grid(self):
        table = grid()
        del table[(5, 16, 2)]
        with self.assertRaises(ValueError):
            P.select_thresholds(table)
        with self.assertRaises(ValueError):                         # a widened grid
            P.select_thresholds({**grid(), (30, 16, 2): outcome()})

    def test_the_totals_must_agree_across_points_and_parts_fit_their_whole(self):
        for bad in (grid(p5_16_2=outcome(attackers=11)), grid(p5_16_2=outcome(conns=999)),
                    grid(p5_16_2=outcome(banned=11)), grid(p5_16_2=outcome(closed=1, slow=2)),
                    grid(p5_16_2=outcome(closed=1001)), grid(outcome(banned=0, attackers=0)),
                    grid(p5_16_2=outcome()._replace(benign_connections_closed=-1)),
                    grid(p5_16_2=outcome()._replace(attack_banned_in_time=1.0))):
            with self.assertRaises(ValueError):
                P.select_thresholds(bad)


if __name__ == "__main__":
    unittest.main()
