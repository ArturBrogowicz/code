"""The P1 runner (eval/p1_runner.py; docs/L7V2_DESIGN.md 4.3, 5.3, 5.4, 9, 10, 14), offline: plans as data, and blocks executed
on the fake host of tests/p1_fake_host.py. Nothing touches the machine."""
import contextlib
import copy
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
for _p in (HERE, REPO, os.path.join(REPO, "eval"), os.path.join(REPO, "ml"), os.path.join(REPO, "bench")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import executor as X
import l7v2_verdict_prereg as VP
import p1_fake_host as F
import p1_runner as R
import population as POP

import ban_events
import l7_conf
import l7_dataset

RUN_NAMES = ["C", "Cp", "M_default_rules_C3b", "M_gru_C2", "M_gru_C3a", "M_gru_C3b", "M_hgb_C3b", "M_rstar_C2", "M_rstar_C3a",
             "M_rstar_C3b", "U_C2", "U_C3a", "U_C3b"]


def thin(frozen, root, seed=3001, **kw):
    return R.plan_block("campaign", seed, root, frozen=frozen, benign_specs=F.thin_benign(), max_sources=3, **kw)


def read_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def index(root):
    with open(os.path.join(root, "index.jsonl"), encoding="utf-8") as fh:
        return [json.loads(x) for x in fh]


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.frozen = F.frozen_inputs(os.path.join(cls.tmp.name, "frozen"))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.root = tempfile.mkdtemp(dir=self.tmp.name)


class PlanTest(Base):
    def setUp(self):
        super().setUp()
        self.block = thin(self.frozen, self.root)
        self.runs = {r["name"]: r for r in self.block["runs"]}

    def test_the_live_set_in_a_seeded_order(self):
        self.assertEqual(sorted(self.block["order"]), RUN_NAMES)
        self.assertEqual(len(RUN_NAMES), VP.load()["live_set"]["runs_per_block"])
        again = thin(self.frozen, self.root)
        self.assertEqual(again["order"], self.block["order"])
        self.assertNotEqual(thin(self.frozen, self.root, seed=3002)["order"], self.block["order"])
        self.assertEqual(thin(self.frozen, self.root, attempt=2)["order"], self.block["order"], "a re-run keeps its order")

    def test_the_minimum_cut(self):
        cut = thin(self.frozen, self.root, cut=True)
        self.assertEqual(sorted(cut["order"]), ["C", "Cp", "M_gru_C2", "M_gru_C3b", "M_hgb_C3b", "M_rstar_C2", "M_rstar_C3b",
                                                "U_C2", "U_C3b"])
        self.assertEqual(len(cut["order"]), VP.load()["live_set"]["minimum_cut"]["runs_per_block"])

    def test_a_run_holds_the_benign_entities_and_its_class_only(self):
        n_benign = sum(1 for e in self.runs["C"]["entities"] if e["role"] == "benign")
        self.assertEqual({e["role"] for e in self.runs["C"]["entities"]}, {"benign"})
        for name, fams in (("U_C2", {"C2"}), ("M_gru_C3a", {"C3a"}), ("U_C3b", {"C3b@M2", "C3b@M1", "C3b@M3", "C3b@M2exp"})):
            ents = self.runs[name]["entities"]
            self.assertEqual({e["kind_or_family"] for e in ents if e["role"] == "attack"}, fams)
            self.assertEqual(sum(1 for e in ents if e["role"] == "benign"), n_benign)
        self.assertEqual([e["address"] for e in self.runs["U_C2"]["entities"]],
                         [e["address"] for e in self.runs["M_gru_C2"]["entities"]], "every run of a block uses them unchanged")

    def test_the_arm_table_is_the_only_source_of_each_arms_daemon(self):
        base = {**dict(X.DAEMON_ENV), "MITIGATION_BACKEND": "xdp"}
        run = self.runs["M_gru_C3b"]
        env = run["daemon"]["env"]
        out = run["out"]
        self.assertEqual(env, {**base, "HEURISTIC_PROFILE": "tolerant", "L7_SHADOW": "1", "L7_ENFORCE": "1", "L7_ARM": "view_gru",
                               "L7_KILL_FILE": R.KILL_FILE, "L7_SOCKET_PATH": R.SOCKET_PATH, "L7_ALLOWLIST": "",
                               "BAN_EVENTS": os.path.join(out, "ban_events.jsonl"),
                               "L7_ENFORCE_DIR": os.path.join(out, "l7v2_deny"), "L7_NGINX_CONF": os.path.join(out, "nginx.conf"),
                               "L7_SELECTION": self.frozen["selection"], "L7_SELECTION_SHA256": self.frozen["selection_sha256"],
                               "L7_RECORD": os.path.join(out, "l7_record.jsonl")})
        self.assertEqual(self.runs["M_hgb_C3b"]["daemon"]["env"]["L7_ARM"], "hgb")
        star = self.runs["M_rstar_C2"]["daemon"]["env"]
        self.assertEqual((star["L7_ARM"], star["L7_SELECTION"], star["L7_SELECTION_SHA256"]),
                         ("R*", self.frozen["rules"], self.frozen["rules_sha256"]))
        dflt = self.runs["M_default_rules_C3b"]["daemon"]["env"]
        self.assertEqual({k: dflt[k] for k in ("HEURISTIC_PROFILE", "L7_SHADOW", "L7_ENFORCE", "L7_MODEL")},
                         {"HEURISTIC_PROFILE": "default", "L7_SHADOW": "0", "L7_ENFORCE": "0", "L7_MODEL": ""})
        self.assertNotIn("L7_SELECTION", dflt)
        for name in ("C", "Cp", "U_C2", "U_C3a", "U_C3b"):
            self.assertIsNone(self.runs[name]["daemon"], name)

    def test_changing_the_table_changes_the_plan_in_one_place(self):
        table = copy.deepcopy(R.ARM_TABLE)
        table["R*"]["daemon"]["L7_NEW"] = "x"
        with mock.patch.object(R, "ARM_TABLE", table):
            block = thin(self.frozen, self.root)
        star = {r["name"]: r for r in block["runs"]}["M_rstar_C3b"]
        self.assertEqual(star["daemon"]["env"]["L7_NEW"], "x")

    def test_pins_are_the_harm_benchmarks(self):
        self.assertEqual(R.PINS, POP.PIN_PLAN_DAEMON)
        run = self.runs["M_gru_C3b"]
        self.assertEqual(run["nginx"]["start"][:3], ["taskset", "-c", R.PINS["server"]])
        self.assertEqual(run["gunicorn"]["argv"][:3], ["taskset", "-c", R.PINS["server"]])
        self.assertEqual(run["daemon"]["argv"][:3], ["taskset", "-c", R.PINS["daemon"]])
        for x in run["launches"]:
            self.assertEqual(x["argv"][:3], ["taskset", "-c", R.PINS["legit" if x["role"] == "benign" else "attack"]])

    def test_gunicorn_is_the_costed_backend_on_loopback_as_design_4_3(self):
        argv = self.runs["U_C2"]["gunicorn"]["argv"]
        text = " ".join(argv)
        self.assertIn(f"L7_BACKEND=costed L7_CALIBRATION={self.frozen['calibration']}", text)
        self.assertIn("--workers 2 --threads 8 -b 127.0.0.1:8080 l7_webapp:app", text)

    def test_generators_carry_their_entitys_plan(self):
        run = self.runs["U_C3b"]
        by = {e["entity_id"]: e for e in run["entities"]}
        for x in run["launches"]:
            e = by[x["entity_id"]]
            a = x["argv"]
            self.assertEqual(a[a.index("--source") + 1], e["address"])
            self.assertEqual(a[a.index("--seed") + 1], str(e["client_seed"]))
            self.assertEqual(json.loads(a[a.index("--params") + 1]), e["params"])
            self.assertEqual(float(a[a.index("--duration") + 1]), round(e["schedule"]["stop_s"] - e["schedule"]["start_s"], 1))
            self.assertEqual(a[a.index("--family") + 1] if e["role"] == "attack" else a[a.index("--kind") + 1], e["kind_or_family"])
        starts = [x["start_s"] for x in run["launches"]]
        self.assertEqual(starts, sorted(starts))

    def test_frozen_items_are_checked_by_sha256_before_a_campaign(self):
        for why, change in (("the selection's sha256", {"selection_sha256": "0" * 64}),
                            ("the rules' sha256", {"rules_sha256": "0" * 64}),
                            ("no selection", {"selection": None}),
                            ("no knees", {"knees": None})):
            with self.subTest(why), self.assertRaises(R.PlanError):
                thin({**self.frozen, **change}, self.root)
        self.assertEqual(self.block["frozen"]["selection"]["sha256"], self.frozen["selection_sha256"])
        self.assertEqual(self.block["frozen"]["rules"]["sha256"], self.frozen["rules_sha256"])
        self.assertEqual(self.block["frozen"]["calibration"]["status"], "frozen")

    def test_a_campaign_refuses_a_placeholder_record_and_unclaimed_selections(self):
        d = tempfile.mkdtemp(dir=self.tmp.name)
        placeholder = F.frozen_inputs(os.path.join(d, "a"), record_status="placeholder")
        with self.assertRaises(R.PlanError):
            thin(placeholder, self.root)
        unclaimed = F.frozen_inputs(os.path.join(d, "b"), valid=False)
        with self.assertRaisesRegex(R.PlanError, "valid for claims"):
            thin(unclaimed, self.root)

    def test_the_rule_selection_must_come_from_the_record_in_use(self):
        other = F.frozen_inputs(os.path.join(tempfile.mkdtemp(dir=self.tmp.name), "a"))
        with open(other["rules"], encoding="utf-8") as fh:
            sel = json.load(fh)
        sel["calibration"]["sha256"] = "f" * 64
        with open(other["rules"], "w", encoding="utf-8") as fh:
            json.dump(sel, fh)
        other["rules_sha256"] = R.sha256_file(other["rules"])
        with self.assertRaisesRegex(R.PlanError, "another calibration record"):
            thin(other, self.root)

    def test_smoke_and_ladder_take_named_runs_on_pilot_seeds(self):
        block = R.plan_block("ladder", 9001, self.root, frozen=self.frozen, levels={"C2": 2.0}, runs=["C", "U_C2"],
                             label="C2_L2_r1", benign_specs=F.thin_benign(), max_sources=3)
        self.assertEqual(sorted(block["order"]), ["C", "U_C2"])
        self.assertIn("b9001_a1_C2_L2_r1", block["dir"])
        with self.assertRaises(R.PlanError):
            R.plan_block("ladder", 3001, self.root, frozen=self.frozen, levels={"C2": 2.0}, runs=["C", "U_C2"])

    def test_the_plan_mode_starts_nothing(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = R.main(["--phase", "ladder", "--seed", "9001", "--class", "C3b", "--level", "50", "--plan",
                           "--calibration", self.frozen["calibration"], "--health", self.frozen["health"], "--root", self.root])
        self.assertEqual(code, 0)
        self.assertIn("run U_C3b", out.getvalue())
        self.assertFalse(os.path.exists(os.path.join(self.root, "ladder")))

    def test_vm_time_as_built(self):
        self.assertAlmostEqual(R.vm_minutes(13), 13 * 5.25)
        self.assertAlmostEqual(10 * R.vm_minutes(13) / 60.0, 11.375)
        self.assertAlmostEqual(10 * R.vm_minutes(9) / 60.0, 7.875)


class ConfTest(Base):
    def render(self, arm):
        return R.render_conf({**R.ARM_TABLE[arm]}, "/var/tmp/p1/run", "/var/tmp/p1/run/l7v2_deny")

    def test_u_runs_log_every_field_to_their_own_sink_with_no_limits(self):
        text = self.render("U")
        self.assertIn("access_log /var/tmp/p1/run/access.log l7json;", text)
        self.assertIn('"sid_set":"$upstream_cookie_sid"', text)
        self.assertNotIn("limit_req zone", text)
        self.assertNotIn("$l7_deny", text)
        self.assertIn("access_log /var/tmp/p1/run/ddos_ml_access.log json_ml_format;", text)
        self.assertNotIn("/var/log/nginx/ddos_ml_access.log", text, "no daemon, no feed")

    def test_an_enforcing_arm_has_the_deny_map_the_socket_tolerant_limits_and_the_feed(self):
        text = self.render("view_gru")
        self.assertIn("include /var/tmp/p1/run/l7v2_deny/deny.map;", text)
        self.assertIn("if ($l7_deny) {", text)
        self.assertIn(f"access_log syslog:server=unix:{R.SOCKET_PATH},nohostname,tag=l7 l7json;", text)
        self.assertIn("access_log /var/tmp/p1/run/access.log l7json;", text)
        self.assertIn("rate=82r/s", text)
        self.assertIn("burst=133 nodelay", text)
        self.assertIn("access_log /var/log/nginx/ddos_ml_access.log json_ml_format;", text)

    def test_the_status_quo_has_the_deployed_limits_and_no_socket_sink(self):
        text = self.render("default_rules")
        self.assertIn("rate=30r/s", text)
        self.assertIn("burst=100 nodelay", text)
        self.assertNotIn("syslog:server", text)
        self.assertIn("access_log /var/tmp/p1/run/access.log l7json;", text)

    def test_every_m_arm_has_one_conf_shape(self):
        # T-025e's F8: one conf for every M arm, or R* alone pays the second map's lookup
        for arm in ("default_rules", "hgb", "view_gru", "R*"):
            with self.subTest(arm):
                self.assertEqual(R.ARM_TABLE[arm]["conf_kw"], {"key_map": True})
                self.assertEqual(R.ARM_TABLE[arm]["deny_kw"], {"key_level": True})
                self.assertIn("include /var/tmp/p1/run/l7v2_deny/deny.map;", self.render(arm))

    def test_an_m_arm_asks_for_the_key_map_once_t025e_is_merged(self):
        seen = {}

        def protected(text, run_dir, key_map=False):
            seen["key_map"] = key_map
            return text

        def prepare(run_dir, key_level=False):
            seen["key_level"] = key_level

        with mock.patch.object(l7_conf, "protected", protected), mock.patch.object(R.l7_denymap, "prepare_run_dir", prepare):
            self.assertIsNone(R.m_arms_pending())
            self.render("view_gru")
            spec = {"conf": "protected", **R.ARM_TABLE["view_gru"]}
            R.l7_denymap.prepare_run_dir("/d", **spec["deny_kw"])
        self.assertEqual(seen, {"key_map": True, "key_level": True})

    def test_the_tracked_confs_are_only_read(self):
        before = {n: R.sha256_file(os.path.join(REPO, n)) for n in ("nginx.conf", "nginx_unprotected.conf")}
        for arm in ("U", "default_rules", "view_gru", "R*"):
            self.render(arm)
        self.assertEqual(before, {n: R.sha256_file(os.path.join(REPO, n)) for n in before})


class ExecuteTest(Base):
    def block(self, runs=("C", "U_C2", "M_gru_C2", "M_default_rules_C3b"), levels=None, **kw):
        return R.plan_block("smoke", 9001, self.root, frozen=self.frozen, levels=levels or {"C2": 1.0, "C3b": 50}, runs=list(runs),
                            benign_specs=F.thin_benign(), max_sources=3, **kw)

    def test_a_block_writes_the_harm_contract_and_a_valid_index(self):
        host = F.P1FakeHost()
        block = self.block()
        results = R.run_block(host, block)
        self.assertTrue(all(res["ok"] for _n, res in results), results)
        meta = read_json(os.path.join(block["dir"], "block.json"))
        for key in ("block", "attempt", "seed", "calibration_sha256", "timeline", "order", "frozen"):
            self.assertIn(key, meta)
        self.assertEqual(meta["timeline"], {"baseline_s": 30, "attack_s": 210, "recovery_s": 30})
        lines = index(self.root)
        self.assertEqual([x["run"] for x in lines], block["order"])
        for run in block["runs"]:
            d = run["out"]
            self.assertTrue(os.path.isfile(os.path.join(d, "access.log.gz")), d)
            self.assertFalse(os.path.exists(os.path.join(d, "access.log")))
            rj = read_json(os.path.join(d, "run.json"))
            self.assertEqual((rj["role"], rj["class"], rj["checks"]["ok"]), (run["role"], run["class"], True))
            self.assertEqual(rj["provenance"]["pins"], R.PINS)
            self.assertEqual(rj["provenance"]["frozen"]["calibration"]["status"], "frozen")
            self.assertIn("eval/p1_runner.py", rj["provenance"]["files_sha256"])
            m = read_json(os.path.join(d, l7_dataset.MANIFEST_FILE))
            self.assertEqual(m["format"], l7_dataset.DATASET_FORMAT_V3)
            self.assertIsNotNone(l7_dataset.time_origin(m))
            self.assertEqual(set(m["ip_map"]), {e["address"] for e in m["entities"]})

    def test_the_deny_directory_and_the_conf_are_the_runs_own(self):
        host = F.P1FakeHost()
        block = self.block(runs=("M_gru_C2",))
        R.run_block(host, block)
        run = block["runs"][0]
        deny = run["nginx"]["deny_dir"]
        self.assertTrue(os.path.isfile(os.path.join(deny, "deny.map")))
        self.assertEqual(os.stat(deny).st_mode & 0o777, 0o700)
        with open(run["nginx"]["conf_path"], encoding="utf-8") as fh:
            self.assertIn(f"include {deny}/deny.map;", fh.read())
        self.assertEqual(host.kinds()["daemon"], 1)

    def test_u_and_controls_have_no_daemon(self):
        host = F.P1FakeHost()
        R.run_block(host, self.block(runs=("C", "Cp", "U_C2")))
        self.assertEqual(host.kinds().get("daemon", 0), 0)

    def test_an_attempt_is_never_overwritten(self):
        host = F.P1FakeHost()
        R.run_block(host, self.block(runs=("C",)))
        with self.assertRaises(R.PlanError):
            R.run_block(host, self.block(runs=("C",)))
        R.run_block(host, self.block(runs=("C",), attempt=2))
        self.assertEqual([x["attempt"] for x in index(self.root)], [1, 2])

    def invalid(self, host, runs=("M_gru_C2",), **kw):
        block = self.block(runs=runs, **kw)
        ((_n, res),) = R.run_block(host, block)
        self.assertFalse(res["ok"])
        self.assertEqual(index(self.root)[-1]["reasons"], res["reasons"])
        return " | ".join(res["reasons"])

    def test_refusals_before_the_traffic(self):
        self.assertIn("not root", self.invalid(F.P1FakeHost(root=False)))
        self.root = tempfile.mkdtemp(dir=self.tmp.name)
        self.assertIn("leftover", self.invalid(F.P1FakeHost(netns=["p1n0_perfect"])))
        self.root = tempfile.mkdtemp(dir=self.tmp.name)
        self.assertIn("kill file", self.invalid(F.P1FakeHost(kill_file=True)))

    def test_checks_of_a_run_that_ran(self):
        cases = (("stack", {"stack_ready": False}, "did not answer"),
                 ("nginx", {"nginx_fails": True}, "nginx did not start"),
                 ("dies", {"daemon_dies_at": 100.0}, "the daemon exited"),
                 ("late kill", {"kill_appears_at": 60.0}, "the kill file appeared"),
                 ("not armed", {"armed": False}, "not armed"),
                 ("lying start", {"start_overrides": {"heuristic_profile": "default"}}, "start event"),
                 ("another arm", {"arm_overrides": {"arm": "hgb"}}, "l7_enforce_arm event says arm"),
                 ("another selection", {"arm_overrides": {"selection_sha256": "0" * 64}}, "l7_enforce_arm event says selection_sha256"),
                 ("silence", {"quiet_from": 60.0}, "silence"))
        for why, kw, want in cases:
            with self.subTest(why):
                self.root = tempfile.mkdtemp(dir=self.tmp.name)
                self.assertIn(want, self.invalid(F.P1FakeHost(**kw)))

    def test_a_generator_that_fails_invalidates_the_run(self):
        probe = self.block(runs=("U_C2",))
        ip = next(e["address"] for e in probe["runs"][0]["entities"] if e["role"] == "attack")
        self.root = tempfile.mkdtemp(dir=self.tmp.name)
        self.assertIn("exited with code", self.invalid(F.P1FakeHost(gen_fails=[ip]), runs=("U_C2",)))

    def test_an_m_arm_is_refused_on_a_real_host_until_t025e_is_merged(self):
        pending = R.m_arms_pending()
        block = self.block(runs=("M_rstar_C2", "U_C2"))
        self.assertEqual({r["name"]: r["pending"] for r in block["runs"]}, {"M_rstar_C2": pending, "U_C2": None})
        if pending:
            host = F.P1FakeHost()
            host.simulated = False
            res = dict(R.run_block(host, block))
            self.assertFalse(res["M_rstar_C2"]["ok"])
            self.assertIn("T-025e", res["M_rstar_C2"]["reasons"][0])
            self.assertTrue(res["U_C2"]["ok"], res["U_C2"]["reasons"])
            self.assertEqual(host.kinds().get("daemon", 0), 0, "nothing of the M arm was started")

    def test_r_stars_rule_is_checked_against_the_rule_selection(self):
        block = self.block(runs=("M_rstar_C2",))
        ((_n, res),) = R.run_block(F.P1FakeHost(rule_arm="multiscale_rate"), block)
        self.assertFalse(res["ok"])
        self.assertIn("rule_arm='multiscale_rate'", res["reasons"][0])
        self.root = tempfile.mkdtemp(dir=self.tmp.name)
        ((_n, ok),) = R.run_block(F.P1FakeHost(), self.block(runs=("M_rstar_C2",)))
        self.assertTrue(ok["ok"], ok["reasons"])

    def test_the_ban_parser_counts_the_arms_engine(self):
        self.assertIn(ban_events.L7V2_ENGINE, R.BAN_ENGINES)
        self.assertLessEqual(set(ban_events.ENGINES), set(R.BAN_ENGINES))
        events = [{"kind": "ban", "engine": ban_events.L7V2_ENGINE, "ip": "10.0.16.1"}, {"kind": "ban", "engine": "l7_rate", "ip": "a"},
                  {"kind": "l7_deny", "ip": "b"}, {"kind": "ban", "engine": "new_engine", "ip": "c"}]
        got = R.run_bans(events)
        self.assertEqual({k: len(v) for k, v in got.items()}, {"l7v2": 1, "l7_rate": 1, "new_engine": 1})

    def test_the_command_line_runs_a_block_on_the_fake(self):
        orig = R.PT.build_block

        def thinned(*a, **kw):
            return orig(*a, **{**kw, "benign_specs": F.thin_benign(), "max_sources": 2})
        with mock.patch.object(R.PT, "build_block", side_effect=thinned):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = R.main(["--phase", "ladder", "--seed", "9001", "--class", "C2", "--level", "1", "--health", self.frozen["health"],
                               "--calibration", self.frozen["calibration"], "--root", self.root], host=F.P1FakeHost())
        self.assertEqual(code, 0, out.getvalue())
        self.assertEqual({x["run"] for x in index(self.root)}, {"C", "U_C2"})
        self.assertEqual(index(self.root)[0]["label"], "C2_L1_r1")


class ShadowValidityTest(Base):
    """D-054, T048-14: the conditions the parity claim names, per M run; what makes a run invalid, and what is only recorded."""

    def run_with(self, acts):
        block = R.plan_block("smoke", 9001, self.root, frozen=self.frozen, levels={"C2": 1.0}, runs=["M_rstar_C2"], label=f"s{len(os.listdir(self.root))}",
                             benign_specs=F.thin_benign(), max_sources=3, attempt=1)
        res = dict(R.run_block(F.P1FakeHost(acts=lambda _r, _b: acts), block))["M_rstar_C2"]
        return res, read_json(os.path.join(block["dir"], "M_rstar_C2", "run.json"))

    def test_a_clean_run_records_zeros(self):
        res, meta = self.run_with([(60.0, {"kind": "l7_shadow", "evicted": 0, "late": 0, "active_keys": 3})])
        self.assertTrue(res["ok"], res["reasons"])
        self.assertEqual(meta["shadow"], {"reports": 1, "evicted": 0, "late": 0, "daemon_errors": [], "shadow_restarts_in_attack": 0})
        self.assertEqual(meta["bans_by_engine"], {})

    def test_an_eviction_makes_it_invalid_and_late_is_only_recorded(self):
        res, meta = self.run_with([(60.0, {"kind": "l7_shadow", "evicted": 0, "late": 7}), (70.0, {"kind": "l7_shadow", "evicted": 3, "late": 2})])
        self.assertFalse(res["ok"])
        self.assertTrue(any("evicted 3 addresses" in r for r in res["reasons"]), res["reasons"])
        self.assertEqual((meta["shadow"]["evicted"], meta["shadow"]["late"]), (3, 7))
        res, meta = self.run_with([(60.0, {"kind": "l7_shadow", "evicted": 0, "late": 7})])
        self.assertTrue(res["ok"], res["reasons"])
        self.assertEqual(meta["shadow"]["late"], 7)

    def test_a_view_store_s_late_count_is_read_too(self):
        _res, meta = self.run_with([(60.0, {"kind": "l7_shadow", "late_dropped": 4})])
        self.assertEqual((meta["shadow"]["late"], meta["shadow"]["evicted"]), (4, 0))

    def test_a_shadow_restart_in_the_attack_window_makes_it_invalid(self):
        err = {"kind": "daemon_error", "where": "thread:l7_shadow", "error": "ZeroDivisionError", "action": "restarted in 5 s"}
        res, meta = self.run_with([(100.0, err)])
        self.assertFalse(res["ok"])
        self.assertTrue(any("shadow thread stopped or restarted 1 times" in r for r in res["reasons"]), res["reasons"])
        self.assertEqual(meta["shadow"]["daemon_errors"][0]["where"], "thread:l7_shadow")

    def test_a_restart_before_the_attack_and_another_thread_s_error_are_only_recorded(self):
        res, meta = self.run_with([(0.5, {"kind": "daemon_error", "where": "thread:l7_shadow", "error": "x", "action": "y"}),
                                   (100.0, {"kind": "daemon_error", "where": "telemetry", "error": "x", "action": "y"})])
        self.assertTrue(res["ok"], res["reasons"])
        self.assertEqual(len(meta["shadow"]["daemon_errors"]), 2)
        self.assertEqual(meta["shadow"]["shadow_restarts_in_attack"], 0)

    def test_bans_are_reported_by_engine_per_run(self):
        _res, meta = self.run_with([(60.0, {"kind": "ban", "engine": "l7v2", "ip": "10.0.0.1"}), (61.0, {"kind": "ban", "engine": "l7_rate", "ip": "10.0.0.2"}),
                                    (62.0, {"kind": "ban", "engine": "l7_rate", "ip": "10.0.0.3"})])
        self.assertEqual(meta["bans_by_engine"], {"l7_rate": 2, "l7v2": 1})

    def test_a_run_without_a_daemon_has_no_shadow_report(self):
        block = R.plan_block("smoke", 9001, self.root, frozen=self.frozen, runs=["C"], label="c", benign_specs=F.thin_benign())
        R.run_block(F.P1FakeHost(), block)
        meta = read_json(os.path.join(block["dir"], "C", "run.json"))
        self.assertEqual((meta["shadow"], meta["bans_by_engine"]), (None, {}))


class PointsTest(Base):
    """D-052: a campaign takes the pilot's check of the frozen points, bound to what it runs, and an arm over the budget stops it."""

    def points(self, **fields):
        path = os.path.join(tempfile.mkdtemp(dir=self.tmp.name), "points.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({**read_json(self.frozen["points"]), **fields}, fh)
        return {**self.frozen, "points": path}

    def test_a_campaign_refuses_without_it(self):
        with self.assertRaisesRegex(R.PlanError, "pilot's check of the frozen operating points"):
            thin({**self.frozen, "points": None}, self.root)
        with self.assertRaisesRegex(R.PlanError, "the point check"):
            thin({**self.frozen, "points": os.path.join(self.root, "none.json")}, self.root)
        with self.assertRaisesRegex(R.PlanError, "not a p1-points/1 file"):
            thin(self.points(format="p1-points/0"), self.root)

    def test_a_check_on_other_frozen_items_is_refused(self):
        for field, value in (("record_sha256", "f" * 64), ("selection_sha256", "f" * 64), ("rules_sha256", "f" * 64), ("benign_halvings", 1)):
            with self.subTest(field=field), self.assertRaisesRegex(R.PlanError, field):
                thin(self.points(**{field: value}), self.root)

    def test_an_arm_over_the_budget_stops_it_until_a_dated_decision(self):
        over = self.points(status="over_budget", over_budget=["R*"])
        with self.assertRaisesRegex(R.PlanError, r"\['R\*'\] over the budget .* until a dated decision"):
            thin(over, self.root)
        with self.assertRaisesRegex(R.PlanError, "must name a dated decision"):
            thin({**over, "points_decision": "the user said so"}, self.root)
        frozen = {**over, "points_decision": "D-099, 2026-11-05: R* stays at its frozen point"}
        block = thin(frozen, self.root)
        got = block["frozen"]["points"]
        self.assertEqual((got["status"], got["over_budget"], got["decision"]), ("over_budget", ["R*"], frozen["points_decision"]))
        self.assertEqual(got["sha256"], R.sha256_file(frozen["points"]))

    def test_an_incomplete_check_is_refused_whatever_is_named(self):
        frozen = {**self.points(status="incomplete", missing_seeds=[9008]), "points_decision": "D-099, 2026-11-05"}
        with self.assertRaisesRegex(R.PlanError, r"incomplete.*\[9008\]"):
            thin(frozen, self.root)

    def test_a_pilot_block_needs_none(self):
        block = R.plan_block("ladder", 9001, self.root, frozen={**self.frozen, "points": None}, levels={"C2": 2.0}, runs=["C", "U_C2"], label="x",
                             benign_specs=F.thin_benign(), max_sources=3)
        self.assertNotIn("points", block["frozen"])


class SmokeReadsTest(Base):
    """What a smoke reads (D-049, E-2, E-4): a level above the verified address limit, in a smoke only; the load against rho."""

    def test_a_smoke_reads_above_the_limit_and_nothing_else_does(self):
        kw = {"frozen": self.frozen, "levels": {"C3b": 300}, "runs": ["U_C3b"], "label": "aliases"}
        with self.assertRaisesRegex(R.PlanError, "verified limit of 300"):
            R.plan_block("smoke", 9001, self.root, **kw)
        block = R.plan_block("smoke", 9001, self.root, address_limit=468, **kw)
        run = block["runs"][0]
        self.assertEqual(len({e["address"] for e in run["entities"]}), 138 - len(block["dropped"]) + 30 + 300)
        self.assertEqual(sum(len(n["addresses"]) for n in run["namespaces"]), len(run["entities"]))
        self.assertEqual(block["address_limit"], 468)
        with self.assertRaisesRegex(R.PlanError, "only a smoke"):
            R.plan_block("ladder", 9001, self.root, frozen=self.frozen, levels={"C3b": 300}, runs=["U_C3b"], address_limit=468)
        with self.assertRaisesRegex(R.PlanError, "only a smoke"):
            R.plan_block("health", 9001, self.root, frozen=self.frozen, address_limit=468)
        with self.assertRaisesRegex(R.PlanError, "only a smoke"):
            thin(self.frozen, self.root, address_limit=468)

    def test_the_plan_shows_the_load_against_rho_and_the_block_keeps_it(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = R.main(["--phase", "health", "--seed", "9001", "--plan", "--calibration", self.frozen["calibration"],
                           "--root", self.root])
        self.assertEqual(code, 0)
        self.assertRegex(out.getvalue(), r"benign nominal [\d.]+ req/s, [\d.]+ CPU-s/s .* rho 90 req/s, 0.552 CPU-s/s; C_slo 180 req/s, "
                                         r"1.105 CPU-s/s; S 0.552")
        block = R.plan_block("health", 9001, self.root, frozen=self.frozen, benign_specs=F.thin_benign())
        R.run_block(F.P1FakeHost(), block)
        meta = read_json(os.path.join(block["dir"], "block.json"))
        self.assertEqual(meta["benign_load"]["rho_req_s"], 90.0)
        self.assertEqual(meta["address_limit"], 300)


class AgeCheckTest(Base):
    """arrivals.age_check on P1's runs (D-049): recorded per run, not applied."""

    def test_every_run_records_its_class_s_report_and_a_control_none(self):
        block = thin(self.frozen, self.root)
        by_name = {r["name"]: r for r in block["runs"]}
        self.assertEqual(by_name["C"]["age_check"], {"applied": False, "rule": "ml/p1_prereg.json age_check", "report": None})
        self.assertIsNone(by_name["Cp"]["age_check"]["report"])
        for cls in ("C2", "C3a", "C3b"):
            for name in (f"U_{cls}", f"M_gru_{cls}", f"M_rstar_{cls}"):
                self.assertEqual(by_name[name]["age_check"]["report"], block["age_check"][cls], name)
                self.assertFalse(by_name[name]["age_check"]["applied"])

    def test_a_failing_check_invalidates_nothing_and_every_phase_records_it(self):
        block = R.plan_block("ladder", 9001, self.root, frozen=self.frozen, levels={"C2": 2.0}, runs=["C", "U_C2"], label="x",
                             benign_specs=F.thin_benign(), max_sources=3)
        report = {"pass": False, "ks": 0.9}
        with mock.patch.object(R.PT, "age_report", return_value={"C2": report}):
            block = R.plan_block("ladder", 9001, self.root, frozen=self.frozen, levels={"C2": 2.0}, runs=["C", "U_C2"], label="y",
                                 benign_specs=F.thin_benign(), max_sources=3)
        results = dict(R.run_block(F.P1FakeHost(), block))
        self.assertTrue(results["U_C2"]["ok"], results["U_C2"]["reasons"])
        meta = read_json(os.path.join(block["dir"], "U_C2", "run.json"))
        self.assertEqual(meta["age_check"]["report"], report)
        self.assertTrue(meta["checks"]["ok"])
        self.assertEqual(read_json(os.path.join(block["dir"], "block.json"))["age_check"], {"C2": report})


class HalvingTest(Base):
    """The halving rule of ml/p1_prereg.json in the runner (D-049): a health step's two controls, a factor frozen before the ladder."""

    def health_file(self, **fields):
        """A health file on the fixture's record, in a directory of its own."""
        d = tempfile.mkdtemp(dir=self.tmp.name)
        path = os.path.join(d, "health.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({**read_json(self.frozen["health"]), **fields}, fh)
        return {**self.frozen, "health": path}

    def ladder(self, frozen, **kw):
        return R.plan_block("ladder", 9001, self.root, frozen=frozen, levels={"C2": 2.0}, runs=["C", "U_C2"], label="C2_L2_r1",
                            benign_specs=F.thin_benign(), max_sources=3, **kw)

    def test_a_health_step_is_the_rule_s_two_controls_on_its_seed(self):
        block = R.plan_block("health", 9001, self.root, frozen=self.frozen, halvings=1, benign_specs=F.thin_benign())
        self.assertEqual(sorted(block["order"]), ["C", "Cp"])
        self.assertEqual((block["halvings"], block["levels"], block["label"]), (1, {}, "h1"))
        self.assertTrue(all(not [x for x in r["launches"] if x["role"] == "attack"] for r in block["runs"]))
        for bad in ({"seed": 9002}, {"seed": 3001}):
            with self.subTest(bad=bad), self.assertRaisesRegex(R.PlanError, "pilot seed 9001"):
                R.plan_block("health", bad["seed"], self.root, frozen=self.frozen, benign_specs=F.thin_benign())
        with self.assertRaisesRegex(R.PlanError, "without attack"):
            R.plan_block("health", 9001, self.root, frozen=self.frozen, levels={"C2": 1.0}, benign_specs=F.thin_benign())
        with self.assertRaisesRegex(R.PlanError, "rule's floor"):
            R.plan_block("health", 9001, self.root, frozen=self.frozen, halvings=3, benign_specs=F.thin_benign())

    def test_a_ladder_and_a_campaign_refuse_without_a_frozen_factor(self):
        none = {**self.frozen, "health": None}
        with self.assertRaisesRegex(R.PlanError, "frozen factor"):
            self.ladder(none)
        with self.assertRaisesRegex(R.PlanError, "frozen factor"):
            thin(none, self.root)
        with self.assertRaisesRegex(R.PlanError, "health file"):
            self.ladder({**self.frozen, "health": os.path.join(self.root, "none.json")})

    def test_a_refusal_says_why(self):
        refused = self.health_file(decision="refused", benign_halvings=None, why="not at the floor of 2 halvings")
        with self.assertRaisesRegex(R.PlanError, "not at the floor of 2 halvings"):
            self.ladder(refused)
        with self.assertRaisesRegex(R.PlanError, "not at the floor of 2 halvings"):
            thin(refused, self.root)
        pending = self.health_file(decision="run", benign_halvings=None, why="the next step runs at 1 halvings")
        with self.assertRaisesRegex(R.PlanError, "the next step"):
            self.ladder(pending)

    def test_a_factor_read_on_another_record_or_past_the_floor_is_refused(self):
        with self.assertRaisesRegex(R.PlanError, "calibration record"):
            self.ladder(self.health_file(record_sha256="f" * 64))
        with self.assertRaisesRegex(R.PlanError, "rule's floor"):
            self.ladder(self.health_file(benign_halvings=3))
        with self.assertRaisesRegex(R.PlanError, "not a p1-health/1 file"):
            self.ladder(self.health_file(format="p1-health/0"))

    def test_the_factor_applies_to_a_ladder_and_cannot_be_overridden(self):
        full = self.ladder(self.frozen)
        block = self.ladder(self.health_file(benign_halvings=1))
        self.assertEqual((full["halvings"], block["halvings"]), (0, 1))
        self.assertLess(*(len([e for e in b["runs"][0]["entities"] if e["role"] != "attack"]) for b in (block, full)))
        with self.assertRaisesRegex(R.PlanError, "not at --halvings"):
            self.ladder(self.frozen, halvings=1)

    def test_a_campaign_s_knees_must_name_the_factor(self):
        d = tempfile.mkdtemp(dir=self.tmp.name)
        knees = read_json(self.frozen["knees"])
        for name, value in (("a", None), ("b", 1)):
            path = os.path.join(d, name + ".json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({**knees, "benign_halvings": value}, fh)
            with self.subTest(value=value), self.assertRaisesRegex(R.PlanError, "halvings, the frozen factor is 0"):
                thin({**self.frozen, "knees": path}, self.root)
        frozen = self.health_file(benign_halvings=1)
        with self.assertRaisesRegex(R.PlanError, "the frozen factor is 1"):
            thin(frozen, self.root)

    def test_the_factor_is_recorded_with_the_block_and_every_run(self):
        frozen = self.health_file(benign_halvings=1)
        block = self.ladder(frozen)
        R.run_block(F.P1FakeHost(), block)
        self.assertEqual(read_json(os.path.join(block["dir"], "block.json"))["halvings"], 1)
        self.assertEqual(block["frozen"]["health"]["sha256"], R.sha256_file(frozen["health"]))
        for run in block["runs"]:
            self.assertEqual(read_json(os.path.join(run["out"], "run.json"))["halvings"], 1)
            self.assertEqual(read_json(os.path.join(run["out"], l7_dataset.MANIFEST_FILE))["halvings"], 1)

    def test_a_smoke_plans_within_the_floor_and_the_command_line_names_it(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = R.main(["--phase", "health", "--seed", "9001", "--halvings", "2", "--plan",
                           "--calibration", self.frozen["calibration"], "--root", self.root])
        self.assertEqual(code, 0)
        self.assertIn("benign halvings 2", out.getvalue())
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(R.main(["--phase", "smoke", "--seed", "9001", "--halvings", "3", "--runs", "C", "--plan",
                                     "--calibration", self.frozen["calibration"], "--root", self.root]), 2)


if __name__ == "__main__":
    unittest.main()
