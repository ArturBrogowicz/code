"""The P3 pre-registration (docs/P3_DATASET_DESIGN.md §5, §6.1, §8 item 3) is pinned value by value:
a change to the committed file must change this test too, in the same reviewed commit."""
import hashlib
import json
import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "ml"))
import p3_prereg as P


class PinnedSeedsTest(unittest.TestCase):
    def setUp(self):
        self.pre = P.load()

    def test_seed_lists_are_the_approved_ones(self):
        s = self.pre["seeds"]
        self.assertEqual(s["p3_train"], [1001, 1002, 1003, 1004])
        self.assertEqual(s["p3_val"], [2001, 2002, 2003, 2004])
        self.assertIn("D-052", self.pre["version_2"])
        self.assertEqual(s["p3_eval"], list(range(3201, 3211)))
        self.assertEqual(s["p1_live_eval"], list(range(3001, 3011)))
        self.assertEqual(s["p4_val"], [4001, 4002])
        self.assertEqual(s["p4_eval"], list(range(3101, 3111)))
        self.assertEqual(s["p1_pilot"], list(range(9001, 9009)))
        self.assertEqual(s["p4_pilot"], list(range(9101, 9107)))
        self.assertEqual(s["p3_smoke"], [9201, 9202])
        self.assertEqual(len(s), 9)

    def test_no_seed_serves_two_lists(self):
        every = [x for v in self.pre["seeds"].values() for x in v]
        self.assertEqual(len(every), len(set(every)))
        self.assertNotIn(1, every)                     # the P3/P5 seed that leaked (VR:V10)

    def test_overlapping_lists_are_refused(self):
        bad = json.loads(json.dumps(self.pre))
        bad["seeds"]["p3_val"].append(1001)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "p.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(bad, fh)
            with self.assertRaises(P.PreregError):
                P.load(path)

    def test_roles(self):
        self.assertEqual(P.seed_role(1003, self.pre), "train")
        self.assertEqual(P.seed_role(2002, self.pre), "val")
        self.assertEqual(P.seed_role(2004, self.pre), "val")
        self.assertEqual(P.seed_role(3210, self.pre), "eval")
        self.assertEqual(P.seed_role(9201, self.pre), "pilot")
        self.assertIsNone(P.seed_role(3001, self.pre))           # P1's, not P3's
        self.assertIsNone(P.seed_role(1, self.pre))
        P.check_seed(1001, "train", self.pre)
        with self.assertRaises(P.PreregError):
            P.check_seed(1001, "eval", self.pre)
        self.assertEqual(P.seeds_for("val", self.pre), [2001, 2002, 2003, 2004])

    def test_server_configs_alternate_and_every_split_holds_both(self):
        self.assertEqual(P.server_config(1001, self.pre)[0], "A")
        self.assertEqual(P.server_config(1002, self.pre)[0], "B")
        a, b = self.pre["server_configs"]["A"], self.pre["server_configs"]["B"]
        self.assertEqual((a["gunicorn_workers"], a["gunicorn_threads"]), (2, 8))
        self.assertEqual((b["gunicorn_workers"], b["gunicorn_threads"]), (4, 4))
        for role in ("train", "val", "eval"):
            self.assertEqual({P.server_config(s, self.pre)[0] for s in P.seeds_for(role, self.pre)},
                             {"A", "B"}, role)


class PinnedVolumeAndCurveTest(unittest.TestCase):
    def test_volume_targets(self):
        v = P.load()["volume"]
        self.assertEqual((v["capture_s"], v["eval_capture_s"]), (900, 1140))
        self.assertEqual(v["lead_in_s"] + 3 * v["phase_s"] + v["tail_s"], v["capture_s"])
        # The C3b@M3 slot is one 240 s slot after the core phases, and (D-036, 2026-10-31) the 120 s benign tail
        # follows it as in every capture: 60 + 3 x 240 + 240 + 120 = 1,140 s (it was 1,020 s, the slot as the tail).
        self.assertEqual(v["lead_in_s"] + 3 * v["phase_s"] + v["eval_tail_s"] + v["tail_s"], v["eval_capture_s"])
        self.assertTrue(v["eval_tail_label"].startswith("re-registered 2026-10-31, before any capture"))
        self.assertIn("confirmed by the user at 14:46:37Z ('Confirm 1140 s', D-036)", v["eval_tail_label"])
        self.assertIn("forward reference", v["eval_tail_label"])
        self.assertEqual(v["core_phases"], ["C2", "C3a", "C3b@M2"])
        self.assertEqual(v["eval_only_phase"], "C3b@M3")
        self.assertEqual(v["phase_intensity_multipliers"], [0.5, 1, 2])
        self.assertEqual((v["benign_users_min"], v["attack_entities_per_core_family_min"]), (120, 50))
        self.assertIn("re-registered 2026-10-31 by the user, before any capture", v["benign_users_min_note"])
        self.assertEqual((v["cgnat_pools"], v["cgnat_users"], v["c3b_m1_entities"]), (2, 36, 10))
        pool = P.load()["pool"]
        self.assertEqual((pool["range"], pool["address_limit"]), ("10.0.16.0/20", 300))
        ext = P.load()["eval_extension"]
        self.assertEqual((ext["next_seed"], ext["max_eval_captures"]), (3211, 20))

    def test_learning_curve_constants(self):
        lc = P.load()["learning_curve"]
        self.assertEqual(lc["fractions"], [0.1, 0.25, 0.5, 1.0])
        self.assertEqual((lc["draws"], lc["inits"], lc["full_inits"]), (5, 3, 15))
        self.assertEqual(lc["draws"] * lc["inits"], lc["full_inits"])     # 15 fits at every fraction
        self.assertEqual(lc["models"], ["gru", "hgb", "lr", "gru_shuffled"])
        self.assertEqual((lc["epochs"], lc["hidden"], lc["layers"]), (25, 64, 2))
        self.assertEqual(lc["benign_budget"], 0.01)
        self.assertEqual(lc["theta_grid"][0], 0.5)
        self.assertEqual(lc["theta_grid"][-1], 0.999)
        self.assertEqual(lc["theta_grid"], sorted(lc["theta_grid"]))
        self.assertEqual(lc["k_grid"], [1, 2, 3, 5, 8])
        self.assertEqual((lc["bootstrap_b"], lc["ci"]), (2000, 0.95))
        self.assertEqual((lc["flatten_pp"], lc["still_learning_pp"], lc["ranking_pp"],
                          lc["sequence_pp"]), (5.0, 5.0, 10.0, 10.0))

    def test_the_ip_ua_age_only_baseline_d040(self):
        # T042-F01, registered 2026-10-31 under D-040 before any capture: the request level's (IP, UA)-key age-only
        # baseline and the 'age-assisted' label
        b = P.load()["learning_curve"]["age_only_ip_ua"]
        self.assertTrue(b["label"].startswith("registered 2026-10-31 under D-040"))
        self.assertEqual(b["auc_band"], 0.15)
        self.assertIn("(IP, UA)", b["key"])
        self.assertIn("'age-assisted'", b["reading"])
        self.assertIn("within 0.5 +- auc_band is 'near chance'", b["reading"])


class SizingRecordTest(unittest.TestCase):
    """ml/p3_sizing_prereg.json: the user's D-076, before any P3 capture."""
    PATH = os.path.join(REPO, "ml", "p3_sizing_prereg.json")
    SHA256 = "86c4c6e76eb0a890406fec12e4767bd2616097a5c10b6f886ea414790395e470"

    def test_the_file_is_the_frozen_version(self):
        with open(self.PATH, "rb") as fh:
            self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), self.SHA256)
        with open(self.PATH, encoding="utf-8") as fh:
            rec = json.load(fh)
        self.assertEqual((rec["format"], rec["date"], rec["pace_cap"]), ("p3-sizing/1", "2026-11-07", 2.0))
        self.assertIn("D-076", rec["decision"])
        self.assertEqual(sorted(rec["carrier"]), ["C2", "C3a", "C3b"])
        self.assertIn("count only", rec["carrier"]["C3b"])


if __name__ == "__main__":
    unittest.main()
