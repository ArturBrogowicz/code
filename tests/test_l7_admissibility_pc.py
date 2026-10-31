"""The admissibility replica of the P4 per-connection rule (ml/l7_admissibility.py, slow_pc.py;
docs/P4_SLOW_DESIGN.md §9): the same simulated plans that the benign gate judges, per connection.
Offline and pure."""
import math
import os
import random
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "ml"))
import l7_admissibility as adm
import l7_benign
import l7_traffic

CGNAT = [s for s in l7_traffic.OVERLAP_KINDS if s.kind == "cgnat_browsers"]


class PerConnectionAdmissibilityTest(unittest.TestCase):
    def test_the_cgnat_pools_fail_slowconn_at_8_and_pass_the_per_connection_rule(self):
        # The expected result of §9: at the DEFAULT count the old per-address rule trips on both
        # pools, as it banned them live in P5c.1; the per-connection rule closes none of their
        # connections at any grid point, so it needs no tolerant 180.
        self.assertEqual([s.params["users"] for s in CGNAT], [12, 24])
        for spec in CGNAT:
            with self.subTest(users=spec.params["users"]):
                old = adm.check_spec(spec.kind, spec.params, l7_traffic.GATE_DURATION_S,
                                     l7_traffic.GATE_SEEDS)
                self.assertIn("slowconn", old["trips"])
                self.assertGreaterEqual(old["worst"]["established_max"],
                                        l7_traffic.THRESHOLDS["slowconn_ban_conns"])
                new = adm.check_spec_pc(spec.kind, spec.params, l7_traffic.GATE_DURATION_S,
                                        l7_traffic.GATE_SEEDS)
                self.assertEqual((new["admissible"], new["closes"], new["banned"], new["point"]),
                                 (True, 0, False, (5, 1024, 2)))
                self.assertGreater(new["connections_min"], 50)

    def test_no_benign_kind_of_the_overlap_mix_is_closed(self):
        for spec in l7_traffic.OVERLAP_KINDS:
            with self.subTest(kind=spec.kind, params=spec.params):
                new = adm.check_spec_pc(spec.kind, spec.params, 300.0, range(3))
                self.assertTrue(new["admissible"], new)

    def test_the_scan_closes_unanswered_dribbling_connections_and_bans_at_k(self):
        # Synthetic, not a generator: a request starts every 2 s on the connection and none is
        # ever answered. At (5, 1024, 2) it is suspect from t = 7 (age 6 > 5) and closed at 9.
        loris = (0.5, 120.0, [(0.5 + 2 * i, math.inf) for i in range(60)])
        self.assertEqual(adm.pc_scan([loris], 120.0), (1, False))
        self.assertEqual(adm.pc_scan([loris, loris], 120.0), (2, True))
        answered = (0.5, 120.0, [(0.5 + 2 * i, 0.502 + 2 * i) for i in range(60)])
        self.assertEqual(adm.pc_scan([answered] * 6, 120.0), (0, False))
        waiting = (0.5, 120.0, [(0.5, math.inf)])                # nothing after the first poll
        self.assertEqual(adm.pc_scan([waiting] * 6, 120.0), (0, False))
        self.assertEqual(adm.pc_scan([loris] * 2, 120.0, (20, 16, 6)), (0, False))   # 125 B/s > F

    def test_the_connections_are_client_wires_connections_with_their_requests(self):
        for spec in (l7_traffic.OVERLAP_KINDS[0], CGNAT[0], l7_traffic.OVERLAP_KINDS[6]):
            with self.subTest(kind=spec.kind):
                plan = l7_benign.plan_client(spec.kind, spec.params, 600.0, random.Random(3))
                starts, _ends, _status, spans = adm.client_wire(plan, 600.0)
                conns = adm.client_connections(plan, 600.0)
                self.assertEqual(sorted((o, c) for o, c, _r in conns), sorted(spans))
                self.assertEqual(sorted(s for _o, _c, r in conns for s, _e in r), starts)


if __name__ == "__main__":
    unittest.main()
