"""Offline tests for bench/calibration.py: the schema, the hash, the status rules and the two pure rules
(the knee, the drift check) of the harm benchmark's calibration record (docs/HG1B_MINIMAL_DESIGN.md 5.2).

Nothing is measured here; the record is a file and the rules are functions.
"""
import contextlib
import copy
import dataclasses
import io
import json
import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "bench"))
import calibration as C
import origin as O


def placeholder():
    with open(C.PLACEHOLDER, encoding="utf-8") as fh:
        return json.load(fh)


class RecordTest(unittest.TestCase):
    def test_the_committed_placeholder_is_valid_hashed_and_not_a_result(self):
        cal = C.load(C.PLACEHOLDER)
        self.assertEqual(cal["status"], "placeholder")
        self.assertEqual(cal["sha256"], C.digest(cal))
        with self.assertRaisesRegex(C.RecordError, "illustrations, not measurements"):
            C.require_frozen(cal)

    def test_the_placeholder_agrees_with_the_origin(self):
        cal = C.load(C.PLACEHOLDER)
        self.assertEqual(cal["knobs"], dataclasses.asdict(O.CostKnobs()))
        self.assertEqual(set(cal["route_costs_ms"]), set(O.CLASSES))
        self.assertEqual(C.knobs_of(cal), O.CostKnobs())
        app = O.app_from_env({"ORIGIN_CALIBRATION": C.PLACEHOLDER, "ORIGIN_KNOBS": '{"rows_total": 300}'})
        self.addCleanup(app.close)
        self.assertEqual(app.tag, "placeholder")

    def test_the_design_constants_are_in_the_record(self):
        cal = C.load(C.PLACEHOLDER)
        self.assertEqual(cal["gate"], {"floor_pp": 10.0, "floor_log2_p95": 1.0, "min_blocks": 10,
                                       "same_sign_share": 0.8, "ci_level": 0.95, "control_q_min": 99.0,
                                       "max_reruns": 2})
        self.assertEqual(cal["slo_ms"], {"C0": 100, "C1": 300, "C2": 300, "C3": 1000, "C4": 1000,
                                         "C5": 3000, "C6": 1000})
        self.assertEqual(cal["validity"]["profile"], "relative")
        self.assertEqual((cal["validity"]["slip_gross_s"], cal["validity"]["slip_delta_s"]), (0.25, 0.05))

    def test_every_departure_from_the_schema_is_named(self):
        broken = {
            "schema": 2, "status": "draft", "created_utc": "", "host": [], "route_costs_ms": {"C0": 1},
            "knobs": {"nonsense": 1}, "capacity": {"c_slo_rps": 100, "c_sat_rps": 90},
            "mix": {"C0": 0.5, "C1": 0.4}, "slo_ms": {"C0": 100}, "gate": {"floor_pp": 10},
            "validity": {"profile": "lax"}, "knees": []}
        problems = C.problems_of({**placeholder(), **broken})
        for fragment in ("schema", "status", "created_utc", "host", "route_costs_ms", "knobs", "capacity",
                         "mix", "slo_ms", "gate", "validity", "knees"):
            with self.subTest(field=fragment):
                self.assertTrue(any(line.startswith(fragment) for line in problems), (fragment, problems))
        self.assertEqual(C.problems_of([]), ["the record is not an object"])

    def test_values_are_checked_not_only_keys(self):
        base = placeholder()
        for path, value in (("route_costs_ms.C3", 0), ("route_costs_ms.C3", float("nan")),
                            ("capacity.c_slo_rps", -1), ("slo_ms.C0", "100"), ("gate.min_blocks", 2),
                            ("gate.ci_level", 1.0), ("gate.same_sign_share", 0), ("gate.max_reruns", -1),
                            ("validity.cpu_share", 0), ("mix.C0", 0.9)):
            cal = copy.deepcopy(base)
            section, key = path.split(".")
            cal[section][key] = value
            with self.subTest(path=path, value=value):
                self.assertTrue(C.problems_of(cal), path)

    def test_the_knobs_must_be_the_origins(self):
        cal = placeholder()
        cal["knobs"]["bogus"] = 3
        self.assertTrue(any(line.startswith("knobs") for line in C.problems_of(cal)))


class HashTest(unittest.TestCase):
    def test_the_hash_ignores_key_order_and_whitespace_and_itself(self):
        cal = placeholder()
        reordered = dict(reversed(list(cal.items())))
        self.assertEqual(C.digest(cal), C.digest(reordered))
        self.assertEqual(C.digest(cal), C.digest({**cal, "sha256": "0" * 64}))
        self.assertEqual(C.canonical(cal), json.dumps(json.loads(C.canonical(cal)), sort_keys=True,
                                                      separators=(",", ":")).encode())

    def test_any_change_to_any_field_changes_the_hash(self):
        cal = placeholder()
        base = C.digest(cal)
        for path, value in (("created_utc", "2026-10-24T00:00:00Z"), ("route_costs_ms.C3", 31.0),
                            ("capacity.c_slo_rps", 181.0), ("gate.floor_pp", 11.0), ("mix.C0", 0.34),
                            ("slo_ms.C0", 101), ("validity.profile", "strict"), ("knobs.api_burn", 4001)):
            changed = copy.deepcopy(cal)
            section, _, key = path.partition(".")
            if key:
                changed[section][key] = value
            else:
                changed[section] = value
            with self.subTest(path=path):
                self.assertNotEqual(C.digest(changed), base)
        self.assertNotEqual(C.digest({**cal, "knees": {"costly_search": 2.0}}), base)

    def test_status_and_hash_rules(self):
        cal = placeholder()
        with self.assertRaisesRegex(C.RecordError, "is not the hash"):
            C.validate({**cal, "sha256": "0" * 64})
        C.validate({k: v for k, v in cal.items() if k != "sha256"})            # a placeholder may omit it
        frozen = C.freeze(cal, "2026-10-24T08:00:00Z")
        self.assertEqual((frozen["status"], frozen["created_utc"]), ("frozen", "2026-10-24T08:00:00Z"))
        self.assertEqual(frozen["sha256"], C.digest(frozen))
        self.assertIs(C.require_frozen(frozen), frozen)
        with self.assertRaisesRegex(C.RecordError, "carries its hash"):
            C.validate({k: v for k, v in frozen.items() if k != "sha256"})
        with self.assertRaisesRegex(C.RecordError, "is not the hash"):
            C.validate({**frozen, "route_costs_ms": {**frozen["route_costs_ms"], "C3": 99.0}})

    def test_dump_and_load_round_trip_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as tmp:
            frozen = C.freeze(placeholder())
            first, second = os.path.join(tmp, "a.json"), os.path.join(tmp, "b.json")
            C.dump(frozen, first)
            C.dump(C.load(first), second)
            with open(first, "rb") as a, open(second, "rb") as b:
                self.assertEqual(a.read(), b.read())
            with self.assertRaises(C.RecordError):
                C.dump({**frozen, "status": "draft"}, os.path.join(tmp, "c.json"))


class DerivedTest(unittest.TestCase):
    def test_rho_the_mean_cost_and_the_spare_capacity(self):
        cal = C.load(C.PLACEHOLDER)
        self.assertEqual(C.rho_rps(cal), 90.0)
        self.assertAlmostEqual(C.mean_cost_ms(cal), 0.33 * 0.05 + 0.22 * 3 + 0.33 * 2 + 0.11 * 30 + 0.01 * 150)
        self.assertAlmostEqual(C.spare_capacity(cal), 90 * C.mean_cost_ms(cal) / 1000)
        self.assertAlmostEqual(C.spare_capacity(cal), 0.5523, places=4)


class KneeTest(unittest.TestCase):
    LEVELS = (0.125, 0.25, 0.5, 1, 2, 4, 8)

    def ladder(self, harms):
        return list(zip(self.LEVELS, harms, strict=True))

    def test_the_knee_of_a_monotone_ladder_is_its_lowest_passing_level(self):
        out = C.knee(self.ladder([[0, 1], [2, 3], [4, 6], [9, 11], [18, 20], [30, 35], [40, 41]]), floor=10)
        self.assertEqual((out["level"], out["passing"], out["monotone"]), (2.0, [2.0, 4.0, 8.0], True))
        self.assertNotIn("why", out)

    def test_a_level_must_pass_in_every_repeat(self):
        out = C.knee(self.ladder([[0, 1], [2, 3], [4, 6], [9, 30], [18, 20], [30, 35], [40, 41]]), floor=10)
        self.assertEqual(out["level"], 2.0)                    # level 1 passes once, fails once

    def test_a_noisy_ladder_gives_its_lowest_pass_and_says_it_is_not_monotone(self):
        out = C.knee(self.ladder([[12, 11], [3, 4], [20, 21], [30, 30], [5, 6], [30, 31], [40, 41]]), floor=10)
        self.assertEqual(out["level"], 0.125)
        self.assertFalse(out["monotone"])

    def test_a_ladder_that_never_passes_is_a_finding(self):
        out = C.knee(self.ladder([[0, 1], [2, 3], [4, 6], [5, 5], [6, 7], [8, 9], [9, 9]]), floor=10)
        self.assertIsNone(out["level"])
        self.assertEqual(out["why"], "cannot harm this server within the generator limit")

    def test_one_repeat_is_not_enough_and_the_input_may_be_unsorted(self):
        out = C.knee([(4, [50]), (2, [40, 41]), (1, [1, 2])], floor=10)
        self.assertEqual(out["level"], 2.0)
        self.assertIsNone(C.knee([(1, [50])], floor=10)["level"])

    def test_the_floor_is_inclusive(self):
        self.assertEqual(C.knee([(1, [10, 10])], floor=10)["level"], 1.0)
        self.assertIsNone(C.knee([(1, [10, 9.99])], floor=10)["level"])


class DriftTest(unittest.TestCase):
    def test_the_boundaries_are_2_pp_and_25_percent(self):
        self.assertEqual(C.drift_ok(99.0, 100.0, 97.0, 125.0), (True, []))
        self.assertEqual(C.drift_ok(99.0, 100.0, 101.0, 75.0), (True, []))
        ok, reasons = C.drift_ok(99.0, 100.0, 96.9, 100.0)
        self.assertFalse(ok)
        self.assertIn("Q 96.9", reasons[0])
        ok, reasons = C.drift_ok(99.0, 100.0, 99.0, 125.1)
        self.assertFalse(ok)
        self.assertIn("p95", reasons[0])
        self.assertFalse(C.drift_ok(99.0, 0.0, 99.0, 1.0)[0])     # a zero frozen p95 cannot be compared with


class CommandLineTest(unittest.TestCase):
    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = C.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_check_show_and_rehash(self):
        code, out, _ = self.run_main("check", C.PLACEHOLDER)
        self.assertEqual((code, "valid, placeholder" in out), (0, True))
        code, out, _ = self.run_main("show", C.PLACEHOLDER)
        self.assertEqual(code, 0)
        self.assertAlmostEqual(json.loads(out)["rho_rps"], 90.0)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "p.json")
            cal = placeholder()
            cal["capacity"]["c_slo_rps"] = 200.0
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(cal, fh)
            code, _, err = self.run_main("check", path)
            self.assertEqual(code, 1)
            self.assertIn("is not the hash", err)
            self.assertEqual(self.run_main("rehash", path)[0], 0)
            self.assertEqual(self.run_main("check", path)[0], 0)
            frozen = os.path.join(tmp, "f.json")
            C.dump(C.freeze(placeholder()), frozen)
            code, _, err = self.run_main("rehash", frozen)
            self.assertEqual(code, 2)
            self.assertIn("never rewritten", err)


if __name__ == "__main__":
    unittest.main()
