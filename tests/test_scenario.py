"""Offline tests for bench/scenario.py: the record's schema, its pairing with a control, the numbers of the plan,
the rule that no deployed threshold moves an intensity, and three golden plans (docs/HG1B_MINIMAL_DESIGN.md 5.4).

Nothing here opens a socket or starts a process; one test makes that a failure.
"""
import contextlib
import copy
import io
import json
import math
import os
import re
import sys
import tempfile
import unittest
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "bench"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import calibration as C
import calibration_fixtures as F
import origin as O
import population as P
import scenario as S

SPECS = os.path.join(REPO, "bench", "scenarios")
GOLDEN = os.path.join(REPO, "tests", "golden")
NAMES = ("benign_control", "costly_search_sub_threshold", "cheap_static_flood")
CAL = C.load(C.PLACEHOLDER)
RHO, SPARE = C.rho_rps(CAL), C.spare_capacity(CAL)


def path_of(name):
    return os.path.join(SPECS, name + ".json")


def record(name):
    with open(path_of(name), encoding="utf-8") as fh:
        return json.load(fh)


def with_change_in(raw, key, value):
    """A copy of `raw` with the dotted `key` set."""
    raw = copy.deepcopy(raw)
    node = raw
    *head, last = key.split(".")
    for part in head:
        node = node[part]
    node[last] = value
    return raw


def with_change(name, key, value):
    return with_change_in(record(name), key, value)


def scenario(name, **changes):
    raw = record(name)
    for key, value in changes.items():
        raw = with_change_in(raw, key.replace("__", "."), value)
    return S.from_record(raw)


def plan_of(name, cal=CAL, seed=None, **changes):
    return S.plan(scenario(name, **changes), cal, seed)


def run_main(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = S.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class SpecsTest(unittest.TestCase):
    def test_the_shipped_specs_load_and_are_named_after_their_files(self):
        for name in NAMES:
            with self.subTest(name=name):
                scn = S.load(path_of(name))
                self.assertEqual(scn.id, name)
                self.assertEqual(S.problems_of(record(name)), [])

    def test_every_attack_is_paired_with_the_control_and_the_pair_is_fit(self):
        control = S.load(path_of("benign_control"))
        self.assertTrue(control.is_control)
        for name in NAMES[1:]:
            scn = S.load(path_of(name))
            self.assertEqual(scn.controls, {"control": "benign_control", "placebo": "repeat"})
            self.assertEqual(S.pair_problems(scn, control), [])

    def test_the_routes_and_the_arrival_follow_the_family(self):
        for name in NAMES[1:]:
            raw = record(name)
            fam = P.ATTACK_FAMILIES[raw["family"]]
            self.assertEqual(raw["routes"], {fam.route_class: 1.0})
            self.assertEqual(raw["arrival"], {"process": fam.process, "loop": "open"})

    def test_the_ladder_is_the_designs_and_contains_the_level(self):
        for name in NAMES[1:]:
            it = record(name)["intensity"]
            self.assertEqual(it["ladder"], [0.125, 0.25, 0.5, 1, 2, 4, 8])
            self.assertIn(it["level"], it["ladder"])

    def test_the_gate_asks_for_ten_blocks_and_both_metrics(self):
        for name in NAMES[1:]:
            self.assertEqual(record(name)["gate"], {"blocks": 10, "metrics": ["Q", "p95"]})
            self.assertEqual(record(name)["seed_namespace"], "calib")


class SchemaTest(unittest.TestCase):
    def test_a_record_that_is_not_an_object(self):
        self.assertEqual(S.problems_of([]), ["the record is not an object"])
        with self.assertRaisesRegex(S.ScenarioError, "not an object"):
            S.from_record("x")

    def test_unknown_and_missing_keys_are_named(self):
        raw = record("costly_search_sub_threshold")
        raw["colour"] = 1
        del raw["timeline"]
        problems = S.problems_of(raw)
        self.assertTrue(any(line.startswith("unknown keys: colour") for line in problems), problems)
        self.assertTrue(any(line.startswith("missing keys: timeline") for line in problems), problems)

    def test_the_optional_keys_may_be_absent(self):
        raw = record("costly_search_sub_threshold")
        del raw["description"]
        self.assertEqual(S.problems_of(raw), [])
        scn = S.from_record(raw)
        self.assertEqual((scn.description, scn.first_seed), ("", 1))

    def test_every_departure_is_named(self):
        cases = (
            ("schema", 2, "schema"), ("id", "Bad Id", "id"), ("family", "dos", "family"), ("class", "H", "class"),
            ("grounding", "  ", "grounding"), ("resource", "gpu", "resource"), ("description", 3, "description"),
            ("routes", {"C1": 1.0}, "routes"), ("routes", {"C3": 0.5}, "routes"),
            ("intensity", {"unit": "pps"}, "intensity: unit, ladder and level"),
            ("intensity.unit", "pps", "intensity.unit"), ("intensity.ladder", [2, 1], "intensity.ladder"),
            ("intensity.ladder", [], "intensity.ladder"), ("intensity.ladder", [1, 1, 2], "intensity.ladder"),
            ("intensity.ladder", [0, 1], "intensity.ladder"), ("intensity.level", 0, "intensity.level"),
            ("intensity.level", "high", "intensity.level"), ("intensity.level", True, "intensity.level"),
            ("sources", 0, "sources"), ("sources", 255, "sources"), ("sources", 2.5, "sources"),
            ("arrival.loop", "closed", "arrival.loop"), ("arrival.process", "pulse", "arrival.process"),
            ("arrival", None, "arrival: process and loop"),
            ("gate.blocks", 2, "gate.blocks"), ("gate.blocks", "10", "gate.blocks"),
            ("gate.metrics", ["Q", "p99"], "gate.metrics"), ("gate.metrics", [], "gate.metrics"),
            ("gate.metrics", ["Q", "Q"], "gate.metrics"),
            ("controls.placebo", "none", "controls.placebo"), ("controls.control", "Bad Id", "controls.control"),
            ("controls", None, "controls: control and placebo"),
            ("benign.identities", 7, "benign.identities"), ("benign.identities", 509, "benign.identities"),
            ("benign.per_profile", 0, "benign.per_profile"), ("benign.per_profile", 7, "benign.per_profile"),
            ("netem", "uniform", "netem"), ("timeline.attack_s", 4, "timeline"), ("timeline.baseline_s", "30", "timeline"),
            ("seed_namespace", "prod", "seed_namespace"), ("first_seed", 95, "first_seed"),
            ("first_seed", 0, "first_seed"), ("first_seed", 1.5, "first_seed"),
        )
        for key, value, fragment in cases:
            with self.subTest(key=key, value=value):
                raw = with_change_in(record("costly_search_sub_threshold"), key, value)
                problems = S.problems_of(raw)
                self.assertTrue(any(fragment in line for line in problems), (key, value, problems))
                with self.assertRaises(S.ScenarioError):
                    S.from_record(raw)

    def test_a_spec_is_checked_whole_not_at_its_first_fault(self):
        raw = record("costly_search_sub_threshold")
        raw.update({"schema": 9, "sources": 0, "netem": "x"})
        self.assertGreaterEqual(len(S.problems_of(raw)), 3)

    def test_the_blocks_must_fit_the_namespace(self):
        raw = with_change_in(record("costly_search_sub_threshold"), "first_seed", 90)
        self.assertEqual(S.problems_of(raw), [])                     # 90 .. 99 is calib's last ten
        raw = with_change_in(raw, "gate.blocks", 11)
        self.assertTrue(any("first_seed" in line for line in S.problems_of(raw)))
        raw = with_change_in(with_change_in(record("costly_search_sub_threshold"), "seed_namespace", "test"),
                             "first_seed", 300)
        self.assertEqual(S.problems_of(raw), [])

    def test_an_attack_free_scenario_must_hold_no_attack(self):
        for key, value in (("routes", {"C3": 1.0}), ("intensity", {"unit": "cost_rate_S", "ladder": [1], "level": 1}),
                           ("sources", 3), ("arrival", {"process": "poisson", "loop": "open"}),
                           ("gate", {"blocks": 10, "metrics": ["Q"]}),
                           ("controls", {"control": "benign_control", "placebo": "repeat"})):
            with self.subTest(key=key):
                raw = with_change_in(record("benign_control"), key, value)
                self.assertTrue(any(line.startswith(f"{key}:") for line in S.problems_of(raw)), S.problems_of(raw))

    def test_a_bool_is_not_an_integer_or_a_number(self):
        for key, value in (("sources", True), ("gate.blocks", True), ("benign.identities", True),
                           ("intensity.level", True), ("schema", True)):
            with self.subTest(key=key):
                raw = with_change_in(record("costly_search_sub_threshold"), key, value)
                self.assertTrue(S.problems_of(raw), key)

    def test_load_names_the_file_and_rejects_text_that_is_not_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "x.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("{nope")
            with self.assertRaisesRegex(S.ScenarioError, r"x\.json: not JSON"):
                S.load(path)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"schema": 3}, fh)
            with self.assertRaisesRegex(S.ScenarioError, r"x\.json: "):
                S.load(path)


class PairTest(unittest.TestCase):
    def test_every_departure_between_a_scenario_and_its_control_is_named(self):
        control = S.load(path_of("benign_control"))
        for key, value, fragment in (("benign.identities", 150, "benign_identities"),
                                     ("benign.per_profile", 2, "per_profile"),
                                     ("timeline.attack_s", 60, "timeline"), ("seed_namespace", "train", "seed_namespace"),
                                     ("first_seed", 2, "first_seed")):
            with self.subTest(key=key):
                raw = with_change_in(record("costly_search_sub_threshold"), key, value)
                if key == "seed_namespace":
                    raw["first_seed"] = 100
                problems = S.pair_problems(S.from_record(raw), control)
                self.assertTrue(any(fragment in line for line in problems), problems)

    def test_the_control_must_be_attack_free_and_the_one_named(self):
        scn = S.load(path_of("costly_search_sub_threshold"))
        other = S.load(path_of("cheap_static_flood"))
        problems = S.pair_problems(scn, other)
        self.assertTrue(any("is not attack-free" in line for line in problems), problems)
        self.assertTrue(any("is paired with benign_control" in line for line in problems), problems)


class LevelTest(unittest.TestCase):
    def test_a_number_is_the_level(self):
        self.assertEqual(S.resolve_level(scenario("costly_search_sub_threshold"), CAL), 2.0)
        self.assertEqual(S.resolve_level(scenario("cheap_static_flood"), CAL), 4.0)

    def test_the_knee_is_read_from_the_calibration(self):
        scn = scenario("costly_search_sub_threshold", intensity__level="knee")
        cal = copy.deepcopy(CAL)
        cal["knees"] = {"costly_search_flood": 0.5}
        self.assertEqual(S.resolve_level(scn, cal), 0.5)
        self.assertEqual(S.plan(scn, cal)["attack"]["level"], 0.5)

    def test_a_knee_that_is_missing_or_none_is_an_error_with_the_reason(self):
        scn = scenario("costly_search_sub_threshold", intensity__level="knee")
        for knees in ({}, {"costly_search_flood": None}, {"cheap_static_flood": 1.0}):
            cal = copy.deepcopy(CAL)
            cal["knees"] = knees
            with self.subTest(knees=knees), self.assertRaisesRegex(S.ScenarioError, "needs a knee"):
                S.resolve_level(scn, cal)


class PlanNumbersTest(unittest.TestCase):
    def test_the_attack_is_a_cost_rate(self):
        p = plan_of("costly_search_sub_threshold")
        a = p["attack"]
        cost = CAL["route_costs_ms"]["C3"]
        self.assertAlmostEqual(a["total_rate"], 2.0 * SPARE / (cost / 1000), places=5)
        self.assertAlmostEqual(a["per_source_rate"], a["total_rate"] / 100)
        self.assertAlmostEqual(a["cost_cpu_s"], 2.0 * SPARE, places=6)
        self.assertAlmostEqual(a["cost_in_s"], 2.0, places=6)
        self.assertEqual((a["family"], a["route"], a["sources"], a["level"]), ("costly_search_flood", "C3", 100, 2.0))
        self.assertEqual(a["knee"], "not measured")

    def test_the_model_utilisation_adds_up_to_the_designs_picture(self):
        p = plan_of("costly_search_sub_threshold")
        capacity = CAL["capacity"]["c_slo_rps"] * C.mean_cost_ms(CAL) / 1000
        self.assertAlmostEqual(p["calibration"]["capacity_cpu_s"], capacity)
        self.assertAlmostEqual(p["attack"]["utilisation"], 1.0, places=3)           # level 2 x S = half the capacity x 2
        self.assertAlmostEqual(p["benign"]["drawn_utilisation"], 0.5, delta=0.01)

    def test_sub_threshold_means_below_every_rule(self):
        a = plan_of("costly_search_sub_threshold")["attack"]
        total = a["total_rate"]
        by_name = {t["name"]: t for t in a["thresholds"]}
        self.assertEqual({n: (t["above"], t["below"]) for n, t in by_name.items()},
                         {"limit_req": (False, True), "l7_rule": (False, True)})
        self.assertEqual(by_name["limit_req"]["sources_to_fall_below"], math.floor(total / 30) + 1)
        self.assertEqual(by_name["l7_rule"]["sources_to_fall_below"], math.floor(total / 50) + 1)
        self.assertEqual(a["rules"], {"limit_req_sheds": False, "reject_share": 0.0, "l7_rule_bans": False,
                                      "error_ratio_branch": False})

    def test_a_plain_flood_is_above_every_rule_and_says_how_many_sources_it_would_take(self):
        a = plan_of("cheap_static_flood")["attack"]
        by_name = {t["name"]: t for t in a["thresholds"]}
        self.assertEqual({n: (t["above"], t["below"]) for n, t in by_name.items()},
                         {"limit_req": (True, False), "l7_rule": (True, False)})
        # the smallest n that brings a source strictly below the limit
        for name, limit in (("limit_req", 30), ("l7_rule", 50)):
            n = by_name[name]["sources_to_fall_below"]
            self.assertLess(a["total_rate"] / n, limit)
            self.assertGreaterEqual(a["total_rate"] / (n - 1), limit)
        self.assertAlmostEqual(a["rules"]["reject_share"], 1 - 30 / a["per_source_rate"])
        self.assertTrue(a["rules"]["limit_req_sheds"] and a["rules"]["l7_rule_bans"])
        self.assertFalse(a["rules"]["error_ratio_branch"])                           # 80 % is not above 80 %

    def test_the_error_ratio_branch_needs_more_than_80_percent_rejected(self):
        a = plan_of("cheap_static_flood", intensity__level=8)["attack"]
        self.assertGreater(a["rules"]["reject_share"], 0.8)
        self.assertTrue(a["rules"]["error_ratio_branch"])

    def test_the_class_table_follows_the_population(self):
        b = plan_of("benign_control")["benign"]
        self.assertEqual([x["name"] for x in b["classes"]], [c.name for c in P.BENIGN_CLASSES])
        self.assertAlmostEqual(sum(x["rate"] for x in b["classes"]), RHO)
        self.assertAlmostEqual(sum(x["rate_share"] for x in b["classes"]), 1.0)
        self.assertEqual(sum(x["identities"] for x in b["classes"]), 200)
        self.assertAlmostEqual(sum(x["utilisation"] for x in b["classes"]), 0.5, delta=0.02)
        for x, c in zip(b["classes"], P.BENIGN_CLASSES, strict=True):
            cost = x["rate"] * sum(w * CAL["route_costs_ms"][r] for r, w in c.routes) / 1000
            self.assertAlmostEqual(x["cost_cpu_s"], cost)
        self.assertAlmostEqual(sum(m["drawn"] for m in b["mix"]), 1.0)
        self.assertAlmostEqual(sum(m["calibration"] for m in b["mix"]), 1.0)
        self.assertLess(b["mix_gap_pp"], S.MIX_TOLERANCE_PP)

    def test_the_entity_seeds_are_the_populations(self):
        p = plan_of("costly_search_sub_threshold", seed=7)
        self.assertEqual(p["scenario"]["seed"], 7)
        by_role = {e["role"]: e for e in p["entities"]}
        self.assertEqual(sum(e["n"] for e in p["entities"]), 300)
        for role, e in by_role.items():
            self.assertEqual(e["first"], P.entity_seed("calib", 7, role, 0))
            self.assertEqual(e["last"], P.entity_seed("calib", 7, role, e["n"] - 1))
        self.assertIn("attack:costly_search_flood", by_role)
        self.assertNotEqual(by_role["benign:page_browser"]["first"],
                            plan_of("costly_search_sub_threshold", seed=8)["entities"][0]["first"])

    def test_the_streams_are_the_populations_and_the_namespaces_hold_every_alias(self):
        p = plan_of("costly_search_sub_threshold")
        self.assertEqual(len(p["streams"]), p["generator"]["processes"])
        self.assertEqual(sum(n["aliases"] for n in p["namespaces"]), 300)
        self.assertEqual({s["kind"] for s in p["streams"]}, {"legit", "attack"})
        self.assertEqual(plan_of("benign_control")["streams"],
                         [s for s in p["streams"] if s["kind"] == "legit"])           # the same legit draw

    def test_the_generator_figures(self):
        p = plan_of("costly_search_sub_threshold")
        g = p["generator"]
        for k in g["kinds"].values():
            self.assertAlmostEqual(k["cores"], k["rate"] * 0.1 / 1000)
            self.assertAlmostEqual(k["share"], k["cores"] / k["cpus"])
        self.assertEqual((g["kinds"]["legit"]["cpus"], g["kinds"]["attack"]["cpus"]), (1, 4))
        for k in g["kinds"].values():
            self.assertAlmostEqual(k["inflight"], k["max_stream_rate"] * 10.0)         # the request timeout
        self.assertEqual((g["kinds"]["legit"]["cap"], g["kinds"]["attack"]["cap"]), (2000, 5000))
        self.assertEqual(g["memory_mb"], g["processes"] * 30)
        self.assertEqual((g["ceiling_rps"], g["cpu_share_limit"]), (5000, 0.7))
        biggest = max((s for s in p["streams"] if s["kind"] == "legit"), key=lambda s: s["addresses"])
        self.assertEqual(g["kinds"]["legit"]["nofile"], biggest["addresses"] * P.POOL["legit"] + 2000 + 64)

    def test_the_links_the_legit_requests_ride_and_the_share_that_votes(self):
        b = plan_of("costly_search_sub_threshold")["benign"]
        self.assertEqual(list(b["link_shares"]), list(C.LINK_PROFILES))
        self.assertAlmostEqual(sum(b["link_shares"].values()), 1.0)
        self.assertEqual(b["judged_profiles"], ["perfect", "broadband"])
        self.assertAlmostEqual(b["judged_share"], b["link_shares"]["perfect"] + b["link_shares"]["broadband"])
        self.assertAlmostEqual(b["judged_share"], 0.763, places=3)          # HG1c design note, Appendix A
        pop = P.draw("calib", 1, RHO, 200)
        by_rate = {p: sum(s.rate for s in pop.of_kind("legit") if s.netem == p) for p in C.LINK_PROFILES}
        for profile, share in b["link_shares"].items():
            self.assertAlmostEqual(share, by_rate[profile] / sum(by_rate.values()))

    def test_a_control_has_no_attack_sections(self):
        p = plan_of("benign_control")
        self.assertIsNone(p["attack"])
        self.assertEqual(list(p["generator"]["kinds"]), ["legit"])
        self.assertEqual(p["expected_gate"]["class"], "n/a")
        self.assertIsNone(p["scenario"]["blocks"])
        self.assertEqual(p["scenario"]["kind"], "control")

    def test_the_plan_is_json(self):
        for name in NAMES:
            p = plan_of(name)
            self.assertEqual(json.loads(json.dumps(p)), p)


class ExpectedGateTest(unittest.TestCase):
    def test_the_cost_rate_model_reads_the_level_only(self):
        classes = {4: "likely PASS", 2: "likely PASS", 1: "cannot say", 0.75: "cannot say", 0.5: "likely FAIL",
                   0.125: "likely FAIL"}
        for level, want in classes.items():
            with self.subTest(level=level):
                self.assertEqual(S.expected_gate(level)["class"], want)
                self.assertEqual(plan_of("costly_search_sub_threshold", intensity__level=level)["expected_gate"]["class"],
                                 want)
        self.assertEqual(S.expected_gate(None)["class"], "n/a")

    def test_the_two_shipped_attacks(self):
        self.assertEqual(plan_of("costly_search_sub_threshold")["expected_gate"]["class"], "likely PASS")
        self.assertEqual(plan_of("cheap_static_flood")["expected_gate"]["class"], "likely PASS")


class ThresholdsNeverChooseTest(unittest.TestCase):
    def test_changing_every_deployed_threshold_moves_no_intensity_and_no_stream(self):
        for name in NAMES:
            base = plan_of(name)
            for factor in (0.01, 100.0):
                scaled = tuple(S.Threshold(t.name, t.limit * factor, t.where, t.effect) for t in S.RATE_THRESHOLDS)
                with (mock.patch.object(S, "RATE_THRESHOLDS", scaled), mock.patch.object(S, "LIMIT_CONN", 7),
                      mock.patch.object(S, "SLOWCONN_CONNS", 99), mock.patch.object(S, "ERROR_RATIO", 0.1)):
                    moved = plan_of(name)
                with self.subTest(name=name, factor=factor):
                    self.assertEqual(moved["streams"], base["streams"])
                    self.assertEqual(moved["entities"], base["entities"])
                    self.assertEqual(moved["generator"], base["generator"])
                    self.assertEqual(moved["benign"], base["benign"])
                    self.assertEqual(moved["expected_gate"], base["expected_gate"])
                    if base["attack"]:
                        for key in ("level", "total_rate", "per_source_rate", "cost_cpu_s", "cost_in_s", "sources"):
                            self.assertEqual(moved["attack"][key], base["attack"][key], key)
                        self.assertNotEqual(moved["attack"]["thresholds"], base["attack"]["thresholds"])

    def test_the_intensity_has_no_threshold_among_its_inputs(self):
        # the rate of the attack is rebuilt here from the level, the spare capacity and the route cost alone
        for name in NAMES[1:]:
            p, scn = plan_of(name), scenario(name)
            route = P.ATTACK_FAMILIES[scn.family].route_class
            want = scn.intensity["level"] * SPARE / (CAL["route_costs_ms"][route] / 1000)
            self.assertAlmostEqual(p["attack"]["total_rate"], want, places=5)

    def test_the_printed_thresholds_are_the_deployed_ones(self):
        with open(os.path.join(REPO, "nginx.conf"), encoding="utf-8") as fh:
            nginx = fh.read()
        with open(os.path.join(REPO, "control_plane.py"), encoding="utf-8") as fh:
            daemon = fh.read()

        def number(text, pattern):
            return float(re.search(pattern, text, re.MULTILINE).group(1))

        self.assertEqual(number(nginx, r"limit_req_zone \$binary_remote_addr zone=mylimit:\S+ rate=(\d+)r/s"),
                         S.LIMIT_REQ_RATE)
        self.assertEqual(number(nginx, r"limit_req zone=mylimit burst=(\d+) nodelay"), S.LIMIT_REQ_BURST)
        self.assertEqual(number(nginx, r"limit_conn connlimit (\d+);"), S.LIMIT_CONN)
        self.assertEqual(number(daemon, r"^HEURISTIC_MAX_RPS = (\d+)"), S.L7_MAX_RPS)
        self.assertEqual(number(daemon, r"^HEURISTIC_WINDOW = ([\d.]+)"), S.L7_WINDOW_S)
        self.assertEqual(number(daemon, r"^HEURISTIC_ERROR_RATIO = ([\d.]+)"), S.ERROR_RATIO)
        self.assertEqual(number(daemon, r"error_ratio > HEURISTIC_ERROR_RATIO and rps > (\d+)"), S.ERROR_RATIO_MIN_RPS)
        self.assertEqual(number(daemon, r"^SLOWCONN_CONN_THRESHOLD = (\d+)"), S.SLOWCONN_CONNS)
        self.assertEqual({t.name: t.limit for t in S.RATE_THRESHOLDS},
                         {"limit_req": S.LIMIT_REQ_RATE, "l7_rule": S.L7_MAX_RPS})


class WarningsTest(unittest.TestCase):
    def words(self, p):
        return " | ".join(p["warnings"])

    def test_a_placeholder_calibration_is_warned_about_and_a_frozen_one_is_not(self):
        p = plan_of("costly_search_sub_threshold")
        self.assertEqual(p["calibration"]["status"], "placeholder")
        self.assertIn("placeholder", self.words(p))
        frozen = F.frozen(CAL, "2026-10-24T08:00:00Z")
        q = plan_of("costly_search_sub_threshold", cal=frozen)
        self.assertEqual((q["calibration"]["status"], q["calibration"]["sha8"]), ("frozen", frozen["sha256"][:8]))
        self.assertNotIn("placeholder", self.words(q))
        self.assertNotEqual(p["calibration"]["sha8"], q["calibration"]["sha8"])
        self.assertIn("frozen sha256:" + frozen["sha256"][:8], S.render(q))

    def test_a_level_off_the_ladder_is_flagged(self):
        self.assertIn("not on the ladder", self.words(plan_of("costly_search_sub_threshold", intensity__level=3)))
        self.assertNotIn("not on the ladder", self.words(plan_of("costly_search_sub_threshold")))

    def test_a_generator_that_cannot_carry_the_plan_is_flagged(self):
        p = plan_of("cheap_static_flood", intensity__level=1000, intensity__ladder=[1000])
        self.assertIn("the run would be invalid", self.words(p))
        self.assertGreater(p["generator"]["kinds"]["attack"]["split"], 0)
        self.assertLessEqual(p["generator"]["kinds"]["attack"]["max_stream_rate"], 5000)
        ok = plan_of("cheap_static_flood")
        self.assertNotIn("the run would be invalid", self.words(ok))

    def test_a_stream_that_could_fill_the_engines_cap_is_flagged(self):
        # a stalled server holds rate x timeout requests in flight; at the cap the engine drops, and a run would be
        # valid or not according to the attack's effect
        for name in NAMES:
            self.assertNotIn("in flight", self.words(plan_of(name)), name)
        p = plan_of("cheap_static_flood", intensity__level=8)
        self.assertIn("requests in flight, at or above the engine's cap of 5000", self.words(p))
        self.assertGreaterEqual(p["generator"]["kinds"]["attack"]["inflight"], 5000)

    def test_fewer_blocks_than_the_gate_needs_is_flagged(self):
        p = plan_of("costly_search_sub_threshold", gate__blocks=6)
        self.assertIn("INVALID by construction", self.words(p))
        self.assertNotIn("INVALID by construction", self.words(plan_of("costly_search_sub_threshold")))

    def test_a_level_below_the_recorded_knee_and_a_family_that_cannot_harm_are_flagged(self):
        cal = copy.deepcopy(CAL)
        cal["knees"] = {"costly_search_flood": 4.0}
        p = S.plan(scenario("costly_search_sub_threshold"), cal)
        self.assertIn("below the recorded knee 4", self.words(p))
        self.assertEqual(p["attack"]["knee"], 4.0)
        cal["knees"] = {"costly_search_flood": None}
        q = S.plan(scenario("costly_search_sub_threshold"), cal)
        self.assertIn("cannot harm this server", self.words(q))
        self.assertIn("none within the generator limit", S.render(q))

    def test_a_minority_of_judged_clients_is_flagged(self):
        cal = copy.deepcopy(CAL)
        cal["judged_profiles"] = ["mobile_bad"]                    # about 6 % of the legit requests at seed 1
        p = S.plan(scenario("costly_search_sub_threshold"), cal)
        self.assertLess(p["benign"]["judged_share"], 0.5)
        self.assertIn("of the legit requests are on the judged links (mobile_bad)", self.words(p))
        self.assertNotIn("judged links", self.words(plan_of("costly_search_sub_threshold")))

    def test_the_warning_uses_the_right_article(self):
        words = self.words(plan_of("cheap_static_flood", intensity__level=8))
        self.assertIn("an attack stream could have", words)
        self.assertNotIn("a attack", words)
        slow = copy.deepcopy(CAL)
        slow["validity"]["cpu_share"] = 1e-6                         # a legit stream that cannot be carried
        self.assertIn("the legit generator needs", self.words(S.plan(scenario("benign_control"), slow)))

    def test_an_assumed_grounding_is_flagged(self):
        self.assertIn("grounding is 'assumed'", self.words(plan_of("cheap_static_flood")))
        self.assertNotIn("grounding is 'assumed'", self.words(plan_of("costly_search_sub_threshold")))

    def test_a_scenario_that_cannot_be_drawn_is_a_scenario_error(self):
        with self.assertRaisesRegex(S.ScenarioError, "outside the namespace"):
            plan_of("costly_search_sub_threshold", seed=100)
        with self.assertRaisesRegex(S.ScenarioError, "outside the namespace"):
            plan_of("costly_search_sub_threshold", seed=0)


class OfflineTest(unittest.TestCase):
    def test_a_plan_opens_no_socket_and_starts_no_process(self):
        def refuse(*_args, **_kwargs):
            raise AssertionError("the plan touched the outside")

        with (mock.patch("socket.socket", refuse), mock.patch("subprocess.Popen", refuse),
              mock.patch("os.system", refuse), mock.patch("time.sleep", refuse)):
            for name in NAMES:
                S.render(plan_of(name))

    def test_the_plan_is_deterministic_and_holds_no_path_or_clock(self):
        for name in NAMES:
            a, b = S.render(plan_of(name)), S.render(plan_of(name))
            self.assertEqual(a, b)
            self.assertNotIn(REPO, a)
            self.assertIsNone(re.search(r"\d{4}-\d{2}-\d{2}T", a))


class GoldenTest(unittest.TestCase):
    def test_the_plans_are_the_committed_ones(self):
        for name in NAMES:
            with self.subTest(name=name):
                with open(os.path.join(GOLDEN, name + ".plan.txt"), encoding="utf-8") as fh:
                    want = fh.read()
                self.assertEqual(S.render(plan_of(name)), want,
                                 f"regenerate: python3 bench/scenario.py --plan bench/scenarios/{name}.json "
                                 f"> tests/golden/{name}.plan.txt, and read the diff")


class CommandLineTest(unittest.TestCase):
    def test_check_lists_the_specs_and_their_controls(self):
        code, out, err = run_main("--check", *[path_of(n) for n in NAMES])
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(out.count(": valid"), 3)
        self.assertEqual(out.count("paired with benign_control"), 2)

    def test_plan_is_the_default_and_prints_each_scenario(self):
        code, out, _ = run_main(path_of("benign_control"), path_of("cheap_static_flood"))
        self.assertEqual(code, 0)
        self.assertEqual(sum(1 for line in out.splitlines() if line.startswith("== ")), 2)
        self.assertEqual(run_main("--plan", path_of("benign_control"), path_of("cheap_static_flood")), (0, out, ""))

    def test_json_is_one_plan_per_spec(self):
        code, out, _ = run_main("--plan", "--json", path_of("benign_control"), path_of("cheap_static_flood"))
        self.assertEqual(code, 0)
        plans = json.loads(out)
        self.assertEqual([p["scenario"]["id"] for p in plans], ["benign_control", "cheap_static_flood"])

    def test_the_seed_option_changes_the_draw_and_a_bad_seed_is_an_error(self):
        _, one, _ = run_main("--plan", "--json", path_of("benign_control"))
        _, two, _ = run_main("--plan", "--json", "--seed", "2", path_of("benign_control"))
        self.assertNotEqual(json.loads(one)[0]["entities"], json.loads(two)[0]["entities"])
        code, _, err = run_main("--plan", "--seed", "300", path_of("benign_control"))
        self.assertEqual(code, 1)
        self.assertIn("outside the namespace", err)

    def test_a_broken_spec_a_missing_control_and_a_bad_calibration_are_exit_1_with_a_message(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = os.path.join(tmp, "bad.json")
            with open(bad, "w", encoding="utf-8") as fh:
                json.dump(with_change("costly_search_sub_threshold", "sources", 0), fh)
            code, _, err = run_main("--check", bad)
            self.assertEqual(code, 1)
            self.assertIn("bad.json", err)
            self.assertIn("sources", err)
            alone = os.path.join(tmp, "alone.json")
            with open(alone, "w", encoding="utf-8") as fh:
                json.dump(record("costly_search_sub_threshold"), fh)
            code, _, err = run_main("--plan", alone)
            self.assertEqual(code, 1)
            self.assertIn("benign_control is not at", err)
            cal = os.path.join(tmp, "cal.json")
            with open(cal, "w", encoding="utf-8") as fh:
                fh.write("{}")
            self.assertEqual(run_main("--plan", "--calibration", cal, path_of("benign_control"))[0], 1)
            self.assertEqual(run_main("--plan", "--calibration", os.path.join(tmp, "none.json"),
                                      path_of("benign_control"))[0], 1)

    def test_a_pair_that_does_not_match_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name, change in (("benign_control", ("timeline.attack_s", 60)),
                                 ("costly_search_sub_threshold", ("sources", 100))):
                with open(os.path.join(tmp, name + ".json"), "w", encoding="utf-8") as fh:
                    json.dump(with_change(name, *change), fh)
            code, _, err = run_main("--check", os.path.join(tmp, "costly_search_sub_threshold.json"))
            self.assertEqual(code, 1)
            self.assertIn("timeline", err)

    def test_a_frozen_calibration_removes_the_banner(self):
        with tempfile.TemporaryDirectory() as tmp:
            frozen = os.path.join(tmp, "frozen.json")
            C.dump(F.frozen(CAL, "2026-10-24T08:00:00Z"), frozen)
            code, out, _ = run_main("--plan", "--calibration", frozen, path_of("cheap_static_flood"))
            self.assertEqual(code, 0)
            self.assertIn("frozen sha256:", out)
            self.assertNotIn("PLACEHOLDER", out)

    def test_every_origin_class_a_scenario_names_is_served(self):
        for name in NAMES[1:]:
            for route in record(name)["routes"]:
                self.assertIn(route, O.CLASSES)


if __name__ == "__main__":
    unittest.main()
