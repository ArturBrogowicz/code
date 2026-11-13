"""Offline tests for bench/calibration.py: the schema, the hash, the status rules and the two pure rules
(the knee, the drift check) of the harm benchmark's calibration record (docs/HG1B_MINIMAL_DESIGN.md 5.2).

Nothing is measured here; the record is a file and the rules are functions.
"""
import contextlib
import copy
import dataclasses
import io
import json
import math
import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "bench"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import calibration as C
import calibration_fixtures as F
import origin as O
import population as P


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
        self.assertEqual((cal["validity"]["slip_pooled_s"], cal["validity"]["slip_delta_s"]), (0.10, 0.05))
        self.assertEqual(cal["judged_profiles"], ["perfect", "broadband"])
        self.assertIsNone(cal["drift_reference"])

    def test_the_link_profiles_are_the_populations_and_the_suites(self):
        self.assertEqual(list(C.LINK_PROFILES), [name for name, _ in P.NETEM_MIX])
        with open(os.path.join(REPO, "test_distributed_suite.py"), encoding="utf-8") as fh:
            source = fh.read()
        for name in C.LINK_PROFILES:
            self.assertIn(f'"{name}"', source)

    def test_every_departure_from_the_schema_is_named(self):
        broken = {
            "schema": 3, "status": "draft", "created_utc": "", "host": [], "route_costs_ms": {"C0": 1},
            "knobs": {"nonsense": 1}, "capacity": {"c_slo_rps": 100, "c_sat_rps": 90},
            "mix": {"C0": 0.5, "C1": 0.4}, "slo_ms": {"C0": 100}, "gate": {"floor_pp": 10},
            "validity": {"profile": "lax"}, "knees": [], "judged_profiles": [],
            "drift_reference": {"rho_rps": 1}}
        problems = C.problems_of({**placeholder(), **broken})
        for fragment in ("schema", "status", "created_utc", "host", "route_costs_ms", "knobs", "capacity",
                         "mix", "slo_ms", "gate", "validity", "knees", "judged_profiles", "drift_reference"):
            with self.subTest(field=fragment):
                self.assertTrue(any(line.startswith(fragment) for line in problems), (fragment, problems))
        self.assertEqual(C.problems_of([]), ["the record is not an object"])

    def test_values_are_checked_not_only_keys(self):
        base = placeholder()
        for path, value in (("route_costs_ms.C3", 0), ("route_costs_ms.C3", float("nan")),
                            ("capacity.c_slo_rps", -1), ("slo_ms.C0", "100"), ("gate.min_blocks", 2),
                            ("gate.ci_level", 1.0), ("gate.same_sign_share", 0), ("gate.max_reruns", -1),
                            ("validity.cpu_share", 0), ("validity.slip_pooled_s", 0), ("validity.slip_pooled_s", float("nan")),
                            ("mix.C0", 0.9)):
            cal = copy.deepcopy(base)
            section, key = path.split(".")
            cal[section][key] = value
            with self.subTest(path=path, value=value):
                self.assertTrue(C.problems_of(cal), path)

    def test_the_validity_block_has_the_pooled_slip_ceiling_and_not_the_per_stream_one(self):
        cal = placeholder()
        self.assertEqual(C.problems_of(cal), [])
        old = copy.deepcopy(cal)
        old["validity"]["slip_gross_s"] = old["validity"].pop("slip_pooled_s")
        problems = C.problems_of(old)
        self.assertEqual(len(problems), 1, problems)
        self.assertTrue(problems[0].startswith("validity: exactly profile, slip_pooled_s, slip_delta_s,"), problems)

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
                            ("slo_ms.C0", 101), ("validity.profile", "strict"), ("knobs.api_burn", 4001),
                            ("judged_profiles", ["perfect"])):
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
        frozen = F.frozen(cal, "2026-10-24T08:00:00Z")
        self.assertEqual((frozen["status"], frozen["created_utc"]), ("frozen", "2026-10-24T08:00:00Z"))
        self.assertEqual(frozen["sha256"], C.digest(frozen))
        self.assertIs(C.require_frozen(frozen), frozen)
        with self.assertRaisesRegex(C.RecordError, "carries its hash"):
            C.validate({k: v for k, v in frozen.items() if k != "sha256"})
        with self.assertRaisesRegex(C.RecordError, "is not the hash"):
            C.validate({**frozen, "route_costs_ms": {**frozen["route_costs_ms"], "C3": 99.0}})

    def test_dump_and_load_round_trip_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as tmp:
            frozen = F.frozen()
            first, second = os.path.join(tmp, "a.json"), os.path.join(tmp, "b.json")
            C.dump(frozen, first)
            C.dump(C.load(first), second)
            with open(first, "rb") as a, open(second, "rb") as b:
                self.assertEqual(a.read(), b.read())
            with self.assertRaises(C.RecordError):
                C.dump({**frozen, "status": "draft"}, os.path.join(tmp, "c.json"))


class JudgedProfilesTest(unittest.TestCase):
    def test_a_non_empty_list_of_distinct_link_profiles(self):
        for good in (["perfect"], ["perfect", "broadband"], list(C.LINK_PROFILES), ["mobile_bad"]):
            with self.subTest(good=good):
                self.assertEqual(C.problems_of({**placeholder(), "judged_profiles": good}), [])
        for bad in ([], ["perfect", "perfect"], ["gprs"], "perfect", ["perfect", 1], None, {"perfect": 1}):
            with self.subTest(bad=bad):
                problems = C.problems_of({**placeholder(), "judged_profiles": bad})
                self.assertTrue(any(line.startswith("judged_profiles") for line in problems), problems)

    def test_a_record_without_the_key_is_refused(self):
        cal = placeholder()
        del cal["judged_profiles"]
        self.assertTrue(any(line.startswith("judged_profiles") for line in C.problems_of(cal)))


class DriftReferenceTest(unittest.TestCase):
    GOOD = F.SAMPLE_DRIFT

    def test_a_placeholder_may_leave_it_out_and_a_frozen_record_may_not(self):
        self.assertEqual(C.problems_of(placeholder()), [])
        with self.assertRaisesRegex(C.RecordError, "drift_reference: a frozen record carries"):
            C.freeze(placeholder(), "2026-10-24T08:00:00Z", host=F.SAMPLE_HOST)
        self.assertEqual(C.problems_of({**placeholder(), "drift_reference": self.GOOD}), [])

    def test_every_departure_is_named(self):
        cases = (({"rho_rps": 90.0}, "drift_reference: rho_rps, q_pct, p95_s and attack"),
                 ({**self.GOOD, "rho_rps": 0}, "drift_reference.rho_rps"),
                 ({**self.GOOD, "q_pct": 0}, "drift_reference.q_pct"),
                 ({**self.GOOD, "q_pct": 100.5}, "drift_reference.q_pct"),
                 ({**self.GOOD, "p95_s": -1}, "drift_reference.p95_s"),
                 ({**self.GOOD, "p95_s": "0.05"}, "drift_reference.p95_s"),
                 ({**self.GOOD, "attack": []}, "drift_reference.attack: an object"),
                 ({**self.GOOD, "attack": {"f": {"level": 2}}}, "drift_reference.attack.f: level, q_pct and p95_s"),
                 ({**self.GOOD, "attack": {"f": {"level": 0, "q_pct": 50, "p95_s": 0.1}}},
                  "drift_reference.attack.f.level"),
                 ({**self.GOOD, "attack": {"f": {"level": 2, "q_pct": 101, "p95_s": 0.1}}},
                  "drift_reference.attack.f.q_pct"))
        for ref, fragment in cases:
            with self.subTest(fragment=fragment):
                problems = C.problems_of({**placeholder(), "drift_reference": ref})
                self.assertTrue(any(fragment in line for line in problems), problems)

    def test_a_hundred_percent_is_a_valid_reference_and_zero_is_not(self):
        ref = {**self.GOOD, "q_pct": 100.0}
        self.assertEqual(C.problems_of({**placeholder(), "drift_reference": ref}), [])
        self.assertTrue(C.problems_of({**placeholder(), "drift_reference": {**self.GOOD, "q_pct": 0.0}}))

    def test_no_attack_reference_is_a_valid_reference(self):
        self.assertEqual(C.problems_of({**placeholder(), "drift_reference": {**self.GOOD, "attack": {}}}), [])


class ReferenceV2Test(unittest.TestCase):
    """The reference of schema 2 (docs/RECALIBRATION_2026-11_DESIGN.md 4 and 7, K1): five rounds on the drift check's own seeds, every
    run's Q and log2 p95, their means and SDs, and the tolerances computed at the freeze."""
    RECORD = os.path.join(REPO, "bench", "calibration", "ddos-mitigation-2026-11-04.json")

    def test_the_record_of_2026_11_04_still_loads_with_its_hash_as_schema_1(self):
        cal = C.load(self.RECORD)
        self.assertEqual((cal["schema"], cal["status"]), (1, "frozen"))
        self.assertEqual(cal["sha256"], "cff6e515acf6f1969435e8843ea79c0c5338be13170a3dc052049928bf1aa0bf")
        self.assertEqual(C.digest(cal), cal["sha256"])
        self.assertEqual((C.SCHEMA, C.SCHEMAS), (2, (1, 2)))
        self.assertEqual(set(cal["drift_reference"]), {"rho_rps", "q_pct", "p95_s", "attack"}, "the single-run shape")

    def test_a_schema_2_record_round_trips(self):
        cal = F.frozen_v2()
        self.assertEqual((cal["schema"], C.problems_of(cal)), (2, []))
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "v2.json")
            C.dump(cal, path)
            self.assertEqual(C.load(path), cal)
        ref = cal["drift_reference"]
        self.assertEqual((ref["n"], ref["seeds"]), (5, {"legit": 41, "attack": {"costly_search_flood": 44}}))
        self.assertEqual(ref["rule"], {"n": 5, "m": 3, "c": 3.0, "k": 3.0 * math.sqrt(1 / 5 + 1 / 3), "floor_pp": 10.0,
                                       "floor_log2_p95": 1.0, "legit_q_pp": 2.0, "legit_p95": 0.25, "wide_sd_q_pp": 5.0})

    def test_a_schema_2_record_without_any_of_the_new_fields_is_refused(self):
        good = F.drift_reference_v2()
        for key in C.REFERENCE_V2_KEYS:
            with self.subTest(missing=key):
                ref = {k: v for k, v in good.items() if k != key}
                self.assertTrue(any(line.startswith("drift_reference") for line in C.problems_of({**placeholder(), "schema": 2,
                                                                                                 "drift_reference": ref})))
        for key in C.ATTACK_V2_KEYS:
            with self.subTest(missing_attack=key):
                ref = copy.deepcopy(good)
                del ref["attack"]["costly_search_flood"][key]
                self.assertTrue(C.problems_of({**placeholder(), "schema": 2, "drift_reference": ref}))
        for key in C.SUMMARY_KEYS:
            with self.subTest(missing_legit=key):
                ref = copy.deepcopy(good)
                del ref["legit"][key]
                self.assertTrue(C.problems_of({**placeholder(), "schema": 2, "drift_reference": ref}))
        with self.assertRaisesRegex(C.RecordError, "drift_reference: a frozen record carries"):
            C.freeze({**placeholder(), "schema": 2}, host=F.SAMPLE_HOST)
        old_shape = C.problems_of({**placeholder(), "schema": 2, "drift_reference": F.SAMPLE_DRIFT})
        self.assertTrue(any("(schema 2)" in line for line in old_shape), "a single-run reference is not schema 2's")

    def test_n_below_5_or_seeds_other_than_the_drifts_are_refused(self):
        four = [r for r in F.SAMPLE_ROUNDS_LEGIT[:4]]
        with self.assertRaisesRegex(ValueError, "5 rounds, no more and no fewer"):
            C.drift_reference_of(90.0, four, F.SAMPLE_ROUNDS_ATTACK, placeholder()["gate"])
        ref = F.drift_reference_v2()
        for change, said in ((lambda r: r.update(n=4), "drift_reference.n: 5 rounds"),
                             (lambda r: r["seeds"].update(legit=31), "drift_reference.seeds: the drift check's own"),
                             (lambda r: r["seeds"]["attack"].update(costly_search_flood=36), "drift_reference.seeds"),
                             (lambda r: r["attack"]["costly_search_flood"]["q_pct"].pop(), "q_pct: 5 values")):
            with self.subTest(said=said):
                bad = copy.deepcopy(ref)
                change(bad)
                problems = C.problems_of({**placeholder(), "schema": 2, "drift_reference": bad})
                self.assertTrue(any(said in line for line in problems), problems)

    def test_means_sds_and_both_clamps_to_1e_12(self):
        k = C.drift_rule(placeholder()["gate"])["k"]
        self.assertAlmostEqual(k, 2.1908902300206643, delta=1e-12)
        ref = F.drift_reference_v2()
        a = ref["attack"]["costly_search_flood"]
        self.assertAlmostEqual(a["mean_q_pct"], 64.0, delta=1e-12)
        self.assertAlmostEqual(a["sd_q_pp"], math.sqrt(10.0), delta=1e-12)
        self.assertAlmostEqual(a["tol_q_pp"], math.sqrt(48.0), delta=1e-12, msg="k s = 3 sqrt(8/15) sqrt(10) = sqrt(48)")
        self.assertAlmostEqual(a["mean_log2_p95"], math.log2(0.2) + 0.2, delta=1e-12)
        self.assertAlmostEqual(a["sd_log2_p95"], math.sqrt(0.025), delta=1e-12)
        self.assertEqual(a["tol_log2"], 0.5, "k t = 0.346 is below half the floor: the lower clamp")
        self.assertFalse(a["wide_spread"])
        for sd, floor, want in ((1.0, 10.0, 5.0), (10.0, 10.0, 10.0), (0.0, 10.0, 5.0), (0.1, 1.0, 0.5), (1.0, 1.0, 1.0)):
            with self.subTest(sd=sd, floor=floor):
                self.assertEqual(C.drift_tolerance(sd, floor, k), want)
        legit = ref["legit"]
        self.assertAlmostEqual(legit["mean_q_pct"], 99.86, delta=1e-12)
        self.assertAlmostEqual(legit["sd_q_pp"], math.sqrt(sum((q - 99.86) ** 2 for q in (100.0, 99.5, 100.0, 99.8, 100.0)) / 4), delta=1e-12)

    def test_a_family_whose_sd_of_q_is_above_5_pp_is_frozen_and_labelled(self):
        """D6: frozen with the spread on record and labelled, the tolerance at its cap."""
        wide = {"costly_search_flood": {"level": 4.0, "runs": [{"Q": q, "p95_s": 0.3} for q in (50.0, 60.0, 70.0, 55.0, 65.0)]}}
        cal = F.frozen_v2(drift_reference=F.drift_reference_v2(attacks=wide))
        a = cal["drift_reference"]["attack"]["costly_search_flood"]
        self.assertTrue(a["wide_spread"])
        self.assertEqual((a["tol_q_pp"], a["tol_log2"]), (10.0, 0.5))
        bad = copy.deepcopy(cal["drift_reference"])
        bad["attack"]["costly_search_flood"]["wide_spread"] = False
        self.assertTrue(any("wide_spread" in line for line in C.problems_of({**placeholder(), "schema": 2, "drift_reference": bad})))

    def test_tolerances_and_means_that_are_not_their_runs_are_refused(self):
        for key, value in (("tol_q_pp", 7.0), ("mean_q_pct", 63.0), ("sd_log2_p95", 0.2)):
            with self.subTest(key=key):
                ref = F.drift_reference_v2()
                ref["attack"]["costly_search_flood"][key] = value
                self.assertTrue(any(key in line for line in C.problems_of({**placeholder(), "schema": 2, "drift_reference": ref})))
        ref = F.drift_reference_v2()
        ref["rule"]["c"] = 2.0
        self.assertTrue(any("drift_reference.rule" in line for line in C.problems_of({**placeholder(), "schema": 2, "drift_reference": ref})))


class HostTest(unittest.TestCase):
    def freeze_with(self, host):
        return F.frozen(placeholder(), host=host)

    def test_the_sample_host_is_complete(self):
        self.assertEqual(C.problems_of(F.frozen()), [])

    def test_a_placeholder_keeps_a_free_form_host(self):
        self.assertEqual(C.problems_of({**placeholder(), "host": {"note": "anything"}}), [])

    def test_a_frozen_host_is_checked_key_by_key(self):
        cases = (("uname", "", "host.uname"), ("uname", 3, "host.uname"), ("cpus", "8", "host.cpus"),
                 ("cpus", True, "host.cpus"), ("mem_mib", -1, "host.mem_mib"), ("origin_seed", 1.5, "host.origin_seed"),
                 ("origin_sha256", "abc", "host.origin_sha256"), ("loadgen_sha256", "Z" * 64, "host.loadgen_sha256"),
                 ("pins", {"server": "0-1"}, "host.pins: missing"), ("pins", [], "host.pins: an object"),
                 ("gunicorn", {"version": "26"}, "host.gunicorn: missing"),
                 ("nginx", {"version": "1.28.3", "conf_sha256": "x"}, "host.nginx.conf_sha256"))
        for key, value, fragment in cases:
            with self.subTest(key=key, value=value):
                host = copy.deepcopy(F.SAMPLE_HOST)
                host[key] = value
                with self.assertRaisesRegex(C.RecordError, fragment):
                    self.freeze_with(host)

    def test_a_missing_key_is_named(self):
        host = copy.deepcopy(F.SAMPLE_HOST)
        del host["nginx"]
        with self.assertRaisesRegex(C.RecordError, "host: missing nginx"):
            self.freeze_with(host)

    def test_freeze_replaces_the_host_and_the_reference_it_is_given(self):
        cal = F.frozen()
        other = copy.deepcopy(F.SAMPLE_HOST)
        other["cpus"] = 4
        again = C.freeze(cal, host=other, drift_reference={**F.SAMPLE_DRIFT, "rho_rps": 120.0})
        self.assertEqual((again["host"]["cpus"], again["drift_reference"]["rho_rps"]), (4, 120.0))
        self.assertEqual(cal["host"]["cpus"], 8)                     # the argument is not changed
        self.assertNotEqual(again["sha256"], cal["sha256"])


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


DRIFT_GATE = {"floor_pp": 10.0, "floor_log2_p95": 1.0}


class DriftAttackTest(unittest.TestCase):
    """D-062, docs/HG1C_DESIGN.md departure 33: an attack run's tolerance is the record's gate floors."""

    def test_q_off_by_10_passes_and_10_1_fails_in_both_directions(self):
        for q in (80.0, 60.0):
            self.assertEqual(C.drift_attack_ok(DRIFT_GATE, 70.0, 0.2, q, 0.2), (True, []), q)
        for q in (80.1, 59.9):
            ok, reasons = C.drift_attack_ok(DRIFT_GATE, 70.0, 0.2, q, 0.2)
            self.assertFalse(ok, q)
            self.assertEqual(len(reasons), 1)
            self.assertIn("floor_pp, 10 pp", reasons[0], "the reason names the tolerance")

    def test_a_p95_ratio_of_2_and_a_half_passes_and_2_01_fails_in_both_directions(self):
        for p95 in (0.4, 0.1):
            self.assertEqual(C.drift_attack_ok(DRIFT_GATE, 70.0, 0.2, 70.0, p95), (True, []), p95)
        for p95 in (0.2 * 2.01, 0.2 / 2.01):
            ok, reasons = C.drift_attack_ok(DRIFT_GATE, 70.0, 0.2, 70.0, p95)
            self.assertFalse(ok, p95)
            self.assertEqual(len(reasons), 1)
            self.assertIn("floor_log2_p95, a factor of 2", reasons[0], "the reason names the tolerance")

    def test_the_tolerance_follows_the_records_gate_block(self):
        tight, wide = {"floor_pp": 5.0, "floor_log2_p95": 0.5}, {"floor_pp": 20.0, "floor_log2_p95": 2.0}
        self.assertTrue(C.drift_attack_ok(tight, 70.0, 0.2, 75.0, 0.2 * 2 ** 0.5)[0])
        self.assertFalse(C.drift_attack_ok(tight, 70.0, 0.2, 75.1, 0.2)[0])
        self.assertFalse(C.drift_attack_ok(tight, 70.0, 0.2, 70.0, 0.2 * 1.5)[0])
        self.assertTrue(C.drift_attack_ok(wide, 70.0, 0.2, 90.0, 0.8)[0])
        self.assertFalse(C.drift_attack_ok(wide, 70.0, 0.2, 90.1, 0.2)[0])
        self.assertFalse(C.drift_attack_ok(wide, 70.0, 0.2, 70.0, 0.81)[0])

    def test_what_cannot_be_compared_fails_and_says_so(self):
        for frozen_p95, q, p95 in ((0.0, 70.0, 1.0), (0.2, 70.0, 0.0), (0.2, 70.0, None), (0.2, None, 0.2)):
            ok, reasons = C.drift_attack_ok(DRIFT_GATE, 70.0, frozen_p95, q, p95)
            self.assertFalse(ok, (frozen_p95, q, p95))
            self.assertTrue(reasons)

    def test_the_legit_probes_rule_is_not_the_attack_runs(self):
        self.assertFalse(C.drift_ok(70.0, 0.2, 75.0, 0.2)[0])
        self.assertTrue(C.drift_attack_ok(DRIFT_GATE, 70.0, 0.2, 75.0, 0.2)[0])


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
            C.dump(F.frozen(), frozen)
            code, _, err = self.run_main("rehash", frozen)
            self.assertEqual(code, 2)
            self.assertIn("never rewritten", err)


if __name__ == "__main__":
    unittest.main()
