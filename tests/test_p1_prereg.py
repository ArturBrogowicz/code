"""The P1 record of D-049 (ml/p1_prereg.json): every value that judges is pinned, so a change shows up as a failing test and must
become a new file. Offline and pure."""
import hashlib
import json
import os
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PATH = os.path.join(REPO, "ml", "p1_prereg.json")
PATH_5 = os.path.join(REPO, "ml", "p1_prereg_5.json")
PREREG_5_SHA256 = "162374d1291ab59e52a70e72bf3eadfda31eb809365fb9094b50acd3c95fbb9c"
PATH_4 = os.path.join(REPO, "ml", "p1_prereg_4.json")
PREREG_4_SHA256 = "e3a39613818313d69c32062a35d52499e36f46bf98bcac7517bdd059c84c3862"
PATH_3 = os.path.join(REPO, "ml", "p1_prereg_3.json")
PREREG_3_SHA256 = "d29c2689c440f2e74c63aa9282435fb2fc899883d7e27d8ba05325d7fe1385b6"
PATH_2 = os.path.join(REPO, "ml", "p1_prereg_2.json")
PREREG_2_SHA256 = "0dd33f224f6a8d24b24913c23b5be21dc41aab0e9ca282ff4cfbc5628cf9ef99"
PREREG_SHA256 = "2c256fedc2352c8004ccb619748244ac5ee0c4cd5f677a5668a0cee3004b01ac"


def load():
    with open(PATH, encoding="utf-8") as fh:
        return json.load(fh)


class FrozenFileTest(unittest.TestCase):
    def test_the_file_is_the_frozen_version(self):
        with open(PATH, "rb") as fh:
            self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), PREREG_SHA256)
        rec = load()
        self.assertEqual((rec["format"], rec["date"]), ("p1-prereg/1", "2026-11-02"))
        self.assertIn("D-049", rec["decision"])

    def test_the_halving_rule(self):
        rule = load()["halving"]
        self.assertEqual((rule["seed"], rule["controls"]), (9001, ["C", "Cp"]))
        self.assertEqual((rule["health"]["q_min"], rule["health"]["class_q_min"]), (99.0, 95.0))
        self.assertEqual((rule["floor"]["max_halvings"], rule["max_reruns"]), (2, 2))

    def test_the_floor_is_the_mix_it_says(self):
        """The record's counts are the frozen mix's: count >> halvings, at least 1, on every spec of count > 1."""
        import sys
        sys.path.insert(0, os.path.join(REPO, "ml"))
        import l7_pools as LP
        specs = LP.POPULATIONS["l7v2"]["benign"]
        floor = load()["halving"]["floor"]
        h = floor["max_halvings"]
        kept = {s["kind"]: max(1, s["count"] >> h) for s in specs if s["count"] > 1}
        self.assertEqual(kept, floor["counts_at_the_floor"])
        by_h = [sum(max(1, s["count"] >> k) for s in specs) for k in range(4)]
        self.assertEqual(by_h, floor["addresses_by_halvings"])

    def test_the_age_rule_and_the_readings(self):
        rec = load()
        self.assertIn("not applied", rec["age_check"]["p1"])
        self.assertIn("enforced", rec["age_check"]["p3"])
        self.assertEqual(sorted(rec["readings"]["assumptions"]), ["file_sink_silence_s", "side_bots"])
        for text in rec["readings"]["assumptions"].values():
            self.assertTrue(text.startswith("[ASSUMPTION]"))


class SecondRecordTest(unittest.TestCase):
    """ml/p1_prereg_2.json: D-052, D-053 and D-054, which add to the record above."""

    @staticmethod
    def load():
        with open(PATH_2, encoding="utf-8") as fh:
            return json.load(fh)

    def test_the_file_is_the_frozen_version(self):
        with open(PATH_2, "rb") as fh:
            self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), PREREG_2_SHA256)
        rec = self.load()
        self.assertEqual((rec["format"], rec["date"]), ("p1-prereg-2/1", "2026-11-02"))
        for decision in ("D-052", "D-053", "D-054"):
            self.assertIn(decision, rec["decisions"])

    def test_the_timeline_and_the_windows(self):
        rec = self.load()
        t = rec["timeline"]
        self.assertEqual((t["baseline_s"], t["attack_s"], t["recovery_s"]), (30, 210, 30))
        self.assertIn("flash_gap_s now fits", t["arrivals"])
        self.assertIn("+ 90 s", rec["harm_windows"]["primary"])
        self.assertIn("as registered", rec["harm_windows"]["admission"])

    def test_the_cost_left_and_its_gate(self):
        left = self.load()["reported_per_class"]["attack_cost_left"]
        self.assertEqual((left["key_age_gate_s"], left["reload_s"]), (20.0, 10.0))
        self.assertEqual(left["judges"], "nothing")

    def test_the_validation_seeds_and_the_point_check(self):
        rec = self.load()
        self.assertEqual(rec["validation"]["p3_val"], [2001, 2002, 2003, 2004])
        check = rec["point_check"]
        self.assertEqual(check["seeds"], list(range(9001, 9009)))
        self.assertEqual(check["stops"], ["R*", "hgb", "view_gru"])
        self.assertIn("dated decision", check["over_budget"])
        self.assertIn("nothing is re-tuned silently", check["no_retune"])

    def test_the_run_validity(self):
        rec = self.load()
        self.assertIn("evicted > 0", rec["run_validity"]["invalid_when"])
        self.assertIn("thread:l7_shadow", rec["run_validity"]["invalid_when"])
        self.assertIn("by engine", rec["bans_by_engine"]["rule"])


class ThirdRecordTest(unittest.TestCase):
    """ml/p1_prereg_3.json: T-051's fix round on T-050, which adds to the records above and judges no arm."""

    @staticmethod
    def load():
        with open(PATH_3, encoding="utf-8") as fh:
            return json.load(fh)

    def test_the_file_is_the_frozen_version(self):
        with open(PATH_3, "rb") as fh:
            self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), PREREG_3_SHA256)
        rec = self.load()
        self.assertEqual((rec["format"], rec["date"]), ("p1-prereg-3/1", "2026-11-03"))
        self.assertIn("T050-05, -06, -09's rule, -10 and -14 are the user's", rec["decisions"])

    def test_the_generator_s_bound_is_inside_the_run_s_grace(self):
        g = self.load()["generator"]
        self.assertEqual((g["drain_s"], g["hard_exit_s"]), (5.0, 7.0))
        self.assertLess(g["hard_exit_s"], 10.0, "eval/p4_runner.py STOP_GRACE_S")

    def test_the_validity_numbers_are_labelled_assumptions(self):
        v = self.load()["run_validity"]
        self.assertEqual((v["enforcing"]["parsed_min_share"], v["enforcing"]["reload_within_s"], v["attack"]["attack_seen_min_share"]), (0.5, 30.0, 0.9))
        for text in (v["enforcing"]["parsed_min_share_status"], v["enforcing"]["reload_within_s_status"], v["attack"]["attack_seen_min_share_status"]):
            self.assertTrue(text.startswith("[ASSUMPTION]"))
        self.assertIn("validity.timer_p99_ms", v["timer_gate"])
        self.assertIn("benign addresses only, from the attack's start to the run's end", v["file_sink"])

    def test_the_ladder_and_the_late_window(self):
        rec = self.load()
        self.assertIn("last attempt's with both runs sound", rec["ladder"]["rule"])
        self.assertEqual(rec["reported"]["late_window"]["from_attack_start_s"], 180.0)


class FourthRecordTest(unittest.TestCase):
    """ml/p1_prereg_4.json: the user's D-058."""

    @staticmethod
    def load():
        with open(PATH_4, encoding="utf-8") as fh:
            return json.load(fh)

    def test_the_file_is_the_frozen_version(self):
        with open(PATH_4, "rb") as fh:
            self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), PREREG_4_SHA256)
        rec = self.load()
        self.assertEqual((rec["format"], rec["date"]), ("p1-prereg-4/1", "2026-11-03"))
        self.assertIn("D-058", rec["decision"])

    def test_its_numbers(self):
        rec = self.load()
        self.assertEqual((rec["reruns"]["max_per_block"], rec["reruns"]["max_per_campaign"]), (1, 2))
        self.assertEqual(rec["halving"]["server_q_min"], 99.0)
        self.assertEqual(rec["control_health"]["class_floor_from_n"], 20)
        self.assertIn("invalid (k of 10)", rec["judged_blocks"]["rule"])
        self.assertIn("superseded and excluded ones too", rec["over_all_attempts"]["rule"])
        self.assertIn("control_health stays unchanged", rec["control_health"]["rule"])


if __name__ == "__main__":
    unittest.main()


class Prereg5Test(unittest.TestCase):
    """ml/p1_prereg_5.json: the user's D-073, D-074 and D-075, before any ladder run."""

    @staticmethod
    def load():
        with open(PATH_5, encoding="utf-8") as fh:
            return json.load(fh)

    def test_the_file_is_the_frozen_version(self):
        with open(PATH_5, "rb") as fh:
            self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), PREREG_5_SHA256)
        rec = self.load()
        self.assertEqual((rec["format"], rec["date"]), ("p1-prereg-5/1", "2026-11-07"))
        for d in ("D-073", "D-074", "D-075"):
            self.assertIn(d, rec["decision"])

    def test_its_numbers(self):
        rec = self.load()
        self.assertEqual(rec["ladder"]["levels"], {"C2": [1, 2, 4, 8, 16], "C3a": [2, 4, 6, 8], "C3b": [50, 100, 150, 200, 300]})
        self.assertEqual(rec["ladder"]["repeats"], 2)
        self.assertEqual((rec["ladder"]["seed_map"]["first"], rec["ladder"]["seed_map"]["seeds"]), (9001, 8))
        self.assertEqual(rec["c3a"]["sources_bounds"], [50, 320])
        self.assertEqual((rec["address_limit"]["ceiling"], rec["address_limit"]["read"]["margin_mb"]), (468, 1024))
        self.assertEqual((rec["premise"]["windows_s"], rec["premise"]["quantile"]), ([1, 10, 30, 60, 300], 0.99))
        self.assertIn("never read as no harm", rec["ladder"]["statuses"]["not_reachable"])
        self.assertIn("C2 alone", rec["no_knee"]["campaign"])
