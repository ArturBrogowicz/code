"""The P1 runner (eval/p1_runner.py; docs/L7V2_DESIGN.md 4.3, 5.3, 5.4, 9, 10, 14), offline: plans as data, and blocks executed
on the fake host of tests/p1_fake_host.py. Nothing touches the machine."""
import contextlib
import copy
import inspect
import io
import json
import os
import socket
import subprocess
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
import l7v2_harm as LH
import l7v2_verdict_prereg as VP
import p1_fake_host as F
import p1_runner as R
import population as POP

import ban_events
import l7_backend
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
    return R.read_index(root)


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


FEEDS_ITS_SOCKET = {"C": False, "U_C3b": False, "M_default_rules_C3b": False, "M_hgb_C3b": True, "M_gru_C3b": True, "M_rstar_C3b": True}


class AttackGeneratorTest(Base):
    """T050-02: P1's attack generators, on the fake and on the real ml/l7_gen.py with P1's own argv, on a loopback sink."""

    def block(self):
        return R.plan_block("smoke", 9001, self.root, frozen=self.frozen, levels={"C2": 1.0}, runs=["U_C2"], label="stats",
                            benign_specs=F.thin_benign({"exporter": 1}), max_sources=2)

    def test_a_u_run_is_valid_and_its_generators_left_their_stats(self):
        block = self.block()
        res = dict(R.run_block(F.P1FakeHost(), block))["U_C2"]
        self.assertTrue(res["ok"], res["reasons"])
        self.assertEqual(len(os.listdir(os.path.join(block["dir"], "U_C2", "attack_stats"))), 2)

    def test_the_real_generator_with_p1_s_argv_exits_0_and_writes_its_stats(self):
        block = self.block()
        R.run_block(F.P1FakeHost(), block)
        run = block["runs"][0]
        x = next(x for x in run["launches"] if x["role"] == "attack")
        stats = x["argv"][x["argv"].index("--stats") + 1]
        os.remove(stats)
        argv = list(x["argv"][x["argv"].index(R.P4.GEN) + 1:])
        with socket.create_server(("127.0.0.1", 0)) as srv:
            argv[argv.index("--host") + 1] = "127.0.0.1"
            argv[argv.index("--port") + 1] = str(srv.getsockname()[1])
            argv[argv.index("--source") + 1] = "127.0.0.1"
            argv[argv.index("--duration") + 1] = "0.5"
            driver = ("import sys, ipaddress; sys.path.insert(0, 'ml'); import l7_gen; "
                      "l7_gen.TESTBED_NET = ipaddress.ip_network('127.0.0.0/8'); sys.exit(l7_gen.main(sys.argv[1:]))")
            got = subprocess.run([sys.executable, "-c", driver, *argv], cwd=REPO, capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(got.returncode, 0, got.stderr[-500:])
        self.assertTrue(os.path.isfile(stats))


class WrittenConfTest(Base):
    """T050-01: what execute_run writes, and nginx reads, not what the table's row renders. An enforcing arm's conf feeds its socket."""

    def written(self):
        block = R.plan_block("smoke", 9001, self.root, frozen=self.frozen, levels={"C3b": 3}, runs=list(FEEDS_ITS_SOCKET), label="conf",
                             benign_specs=F.thin_benign(), max_sources=2)
        R.run_block(F.P1FakeHost(), block)
        out = {}
        for name in FEEDS_ITS_SOCKET:
            with open(os.path.join(block["dir"], name, "nginx.conf"), encoding="utf-8") as fh:
                out[name] = fh.read()
        return out

    def test_only_an_enforcing_arm_feeds_the_socket_and_every_daemon_feeds_the_heuristic(self):
        for name, text in self.written().items():
            with self.subTest(name):
                sink = f"syslog:server=unix:{R.SOCKET_PATH}"
                self.assertEqual(sink in text, FEEDS_ITS_SOCKET[name], "the socket sink")
                self.assertEqual("/var/log/nginx/ddos_ml_access.log" in text, name.startswith("M_"), "the daemon's feed")

    def test_the_written_conf_is_what_the_table_s_row_renders(self):
        block = R.plan_block("smoke", 9001, self.root, frozen=self.frozen, levels={"C3b": 3}, runs=["M_gru_C3b"], label="same",
                             benign_specs=F.thin_benign(), max_sources=2)
        R.run_block(F.P1FakeHost(), block)
        run = block["runs"][0]
        with open(run["nginx"]["conf_path"], encoding="utf-8") as fh:
            self.assertEqual(fh.read(), R.render_conf(R.ARM_TABLE["view_gru"], run["out"], run["nginx"]["deny_dir"]))


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


class BackendExitTest(Base):
    """D-063: a gunicorn that exits by itself. On the fake's real path through execute_run; its requests get 502s from its death on."""

    BOOT = "[ERROR] Worker (pid:7) exited with code 3.\n[ERROR] Reason: Worker failed to boot.\n"

    def block(self, *runs, **kw):
        self.made = getattr(self, "made", 0) + 1
        return R.plan_block("smoke", 9001, self.root, frozen=self.frozen, levels={"C2": 1.0}, runs=list(runs), label=f"g{self.made}",
                            benign_specs=F.thin_benign(), max_sources=3, **kw)

    def run_one(self, name, **host):
        block = self.block(name)
        res = dict(R.run_block(F.P1FakeHost(**host), block))[name]
        return res, read_json(os.path.join(block["dir"], name, "run.json"))

    def test_gunicorn_dying_in_mid_run_makes_the_run_invalid(self):
        for name in ("U_C2", "C", "M_gru_C2"):
            res, meta = self.run_one(name, gunicorn_dies=(100.0, 1, ""))
            with self.subTest(name):
                self.assertFalse(res["ok"])
                self.assertEqual([r for r in res["reasons"] if "gunicorn" in r], ["gunicorn exited at 100 s (code 1)"])
                self.assertEqual(meta["checks"]["reasons"], res["reasons"])

    def test_the_reason_names_what_the_log_shows_in_p4_s_words(self):
        refusal = "origin.CalibrationError: C0: 0.005 ms against 0.05 ms frozen\n" + self.BOOT
        for text, want in ((self.BOOT, "gunicorn exited at 150 s (code 3): a worker failed to boot (gunicorn.log)"),
                           (refusal, "gunicorn exited at 150 s (code 3): the origin refused its calibration record (gunicorn.log)")):
            res, _meta = self.run_one("C", gunicorn_dies=(150.0, 3, text))
            self.assertIn(want, res["reasons"])

    def test_a_dead_backend_does_not_read_as_harm(self):
        """The failure itself: Q falls in U, by every reading, client and server, and the class would be harmed. The block must say why not."""
        block = self.block("C", "Cp", "U_C2")
        R.run_block(F.P1FakeHost(gunicorn_dies=(60.0, 1, ""), gunicorn_dies_in={"U_C2"}), block)
        got = LH.assess_block(block["dir"], l7_backend.load_record(self.frozen["calibration"])[0])
        self.assertLess(got["runs"]["U_C2"]["metrics"]["Q"], 50.0, "the 502s are in Q")
        self.assertGreater(got["classes"]["C2"]["dQ"], 10.0)
        self.assertFalse(got["classes"]["C2"]["valid"])
        self.assertIn("U_C2: gunicorn exited at 60 s (code 1)", got["classes"]["C2"]["reasons"])
        self.assertFalse(got["valid_all"])

    def test_gunicorn_dying_after_the_loop_s_last_look_is_seen_once(self):
        res, _meta = self.run_one("C", gunicorn_dies=(270.2, 1, ""))
        self.assertEqual(len([r for r in res["reasons"] if r.startswith("gunicorn exited at 27")]), 1, res["reasons"])

    def test_the_runner_stopping_gunicorn_is_no_reason(self):
        res, _meta = self.run_one("C")
        self.assertEqual(res["reasons"], [])

    def test_a_refused_master_never_serves(self):
        """Named at once, with no traffic, no daemon and no 30-s wait; nginx is stopped and the testbed torn down."""
        block = self.block("M_gru_C2")
        host = F.P1FakeHost(gunicorn_refuses="[INFO] Starting gunicorn 26.2.0\nCalibrationError: C0: 0.005 ms against 0.05 ms frozen\n")
        res = dict(R.run_block(host, block))["M_gru_C2"]
        self.assertEqual(res["reasons"], ["gunicorn exited before the traffic (code 1): the origin refused its calibration record (gunicorn.log)"])
        self.assertEqual({p.kind for p in host.procs}, {"server"})
        self.assertLess(host.t, 5.0)
        self.assertTrue(host.ran("ip", "netns", "del", "server_ns"))
        self.assertFalse(os.path.exists(os.path.join(block["dir"], "M_gru_C2", "cpu.jsonl")))

    def test_nginx_gone_at_the_run_s_end_makes_the_run_invalid(self):
        res, meta = self.run_one("U_C2", nginx_gone=True)
        self.assertEqual(res["reasons"], ["nginx was not running at the run's end: its quit exited 1"])
        self.assertEqual(meta["checks"]["reasons"], res["reasons"])

    def test_the_nginx_reason_is_p4_s_one_function(self):
        self.assertEqual(R.P4.nginx_gone(1), "nginx was not running at the run's end: its quit exited 1")
        self.assertIn("P4.nginx_gone", inspect.getsource(R))
        self.assertIn("nginx_gone(quit_code)", inspect.getsource(R.P4.finish))

    def test_a_run_that_never_began_has_no_end_to_speak_of(self):
        res, _meta = self.run_one("C", nginx_gone=True, stack_ready=False)
        self.assertEqual(len(res["reasons"]), 1, res["reasons"])
        self.assertIn("did not answer", res["reasons"][0])

    def test_the_helper_is_p4_s_and_not_a_copy(self):
        source = inspect.getsource(R)
        self.assertIn("P4.gunicorn_gone", source)
        self.assertNotIn("GUNICORN_REFUSALS", source)
        self.assertFalse(hasattr(R, "gunicorn_gone"))


class TimerGateTest(Base):
    """T050-11: the harm benchmark's gate before a run, at the record's limit, with its probes in run.json."""

    def run_with(self, p99):
        block = R.plan_block("smoke", 9001, self.root, frozen=self.frozen, runs=["C"], label=f"t{len(os.listdir(self.root))}", benign_specs=F.thin_benign())
        host = F.P1FakeHost(timer_p99=p99)
        res = dict(R.run_block(host, block))["C"]
        return res, read_json(os.path.join(block["dir"], "C", "run.json")), host

    def test_the_limit_is_the_record_s(self):
        block = R.plan_block("smoke", 9001, self.root, frozen=self.frozen, runs=["C"], label="l", benign_specs=F.thin_benign())
        self.assertEqual(block["runs"][0]["timer_limit_ms"], 10.0)

    def test_a_quiet_timer_passes_and_its_probe_is_recorded(self):
        res, meta, _h = self.run_with(2.0)
        self.assertTrue(res["ok"], res["reasons"])
        self.assertEqual((meta["timer"]["timer_limit_ms"], meta["timer"]["timer_refused_probes"], meta["timer"]["timer_probes"][0]["p99_ms"]), (10.0, 0, 2.0))

    def test_a_refused_probe_waits_and_passes_with_its_wait_recorded(self):
        res, meta, _h = self.run_with([50.0, 12.0, 3.0])
        self.assertTrue(res["ok"], res["reasons"])
        self.assertEqual((len(meta["timer"]["timer_probes"]), meta["timer"]["timer_refused_probes"]), (3, 2))
        self.assertGreaterEqual(meta["timer"]["timer_waited_s"], 60.0)

    def test_a_timer_that_never_passes_starts_nothing(self):
        res, meta, host = self.run_with(50.0)
        self.assertFalse(res["ok"])
        self.assertTrue(any("the timer gate refused the run" in r and "nothing was started" in r for r in res["reasons"]), res["reasons"])
        self.assertGreater(meta["timer"]["timer_refused_probes"], 10)
        self.assertEqual([c for c in host.commands if c[2] == "popen"], [], "no process was started")

    def test_an_unreadable_probe_is_a_refused_one(self):
        res, meta, _h = self.run_with([None, 2.0])
        self.assertTrue(res["ok"], res["reasons"])
        self.assertEqual(meta["timer"]["timer_refused_probes"], 1)


class RunnerReportTest(Base):
    def test_the_runner_s_lateness_is_reported(self):
        block = R.plan_block("smoke", 9001, self.root, frozen=self.frozen, runs=["C"], label="r", benign_specs=F.thin_benign())
        R.run_block(F.P1FakeHost(), block)
        got = read_json(os.path.join(block["dir"], "C", "run.json"))["runner"]
        self.assertGreaterEqual(got["largest_launch_lag_s"], 0.0)
        self.assertLess(got["largest_launch_lag_s"], 2.0)
        self.assertLessEqual(got["largest_loop_gap_s"], 1.5)

    def test_a_loop_that_stalled_shows(self):
        got = R.runner_report({"cpu": [{"t": 0.0}, {"t": 1.0}, {"t": 32.0}, {"t": 33.0}], "lags": [0.0, 31.0]})
        self.assertEqual(got, {"largest_launch_lag_s": 31.0, "largest_loop_gap_s": 31.0})


class OneSettingTest(Base):
    """T050-12, -17: a campaign at one setting; the order; the index before and after a run; the executor's CPU."""

    def knees(self, **fields):
        path = os.path.join(tempfile.mkdtemp(dir=self.tmp.name), "knees.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({**read_json(self.frozen["knees"]), **fields}, fh)
        return {**self.frozen, "knees": path}

    def test_a_block_at_other_knees_is_refused(self):
        R.run_block(F.P1FakeHost(), thin(self.frozen, self.root, cut=True))
        with self.assertRaisesRegex(R.PlanError, "knees_sha256.*differ from b3001_a1"):
            R.run_block(F.P1FakeHost(), thin(self.knees(C3b=40), self.root, seed=3002, cut=True))
        self.assertFalse(os.path.exists(os.path.join(self.root, "campaign", "b3002_a1")), "nothing was started")
        R.run_block(F.P1FakeHost(), thin(self.frozen, self.root, seed=3002, cut=True))

    def test_a_block_on_other_code_is_refused(self):
        R.run_block(F.P1FakeHost(), thin(self.frozen, self.root, cut=True))
        block = thin(self.frozen, self.root, seed=3002, cut=True)
        real = R.sha256_file
        with mock.patch.object(R, "sha256_file", lambda p: "f" * 64 if p.endswith("l7_rule_engine.py") else real(p)), \
                self.assertRaisesRegex(R.PlanError, "code_sha256"):
            R.run_block(F.P1FakeHost(), block)

    def test_a_pilot_block_is_not_bound(self):
        for label, frozen in (("a", self.frozen), ("b", self.knees(C3b=40))):
            block = R.plan_block("smoke", 9001, self.root, frozen=frozen, runs=["C"], label=label, benign_specs=F.thin_benign())
            R.run_block(F.P1FakeHost(), block)

    def test_the_settings_are_in_block_json_and_provenance_holds_the_record_s_files(self):
        block = thin(self.frozen, self.root, cut=True)
        R.run_block(F.P1FakeHost(), block)
        got = read_json(os.path.join(block["dir"], "block.json"))["settings"]
        self.assertEqual(got["selection_sha256"], self.frozen["selection_sha256"])
        self.assertEqual(got["record_digest"], block["frozen"]["calibration"]["digest"])
        self.assertTrue(set(R.PT.prereg_3()["one_setting"]["provenance_adds"]) <= set(R.PROVENANCE_FILES))
        for name in R.PROVENANCE_FILES:
            self.assertTrue(os.path.isfile(os.path.join(REPO, name)), name)

    def test_a_campaign_s_order_does_not_read_a_label(self):
        self.assertEqual(R.block_order("campaign", 3001, RUN_NAMES, "x"), R.block_order("campaign", 3001, RUN_NAMES))
        self.assertNotEqual(R.block_order("smoke", 9001, RUN_NAMES, "x"), R.block_order("smoke", 9001, RUN_NAMES, "y"))

    def test_a_runner_s_death_leaves_an_invalid_line(self):
        block = R.plan_block("smoke", 9001, self.root, frozen=self.frozen, levels={"C2": 1.0}, runs=["C", "U_C2"], label="dead",
                             benign_specs=F.thin_benign(), max_sources=2)
        real = R.execute_run

        def dies(host, run, sums):
            if run["name"] == block["order"][1]:
                raise KeyboardInterrupt
            return real(host, run, sums)

        with mock.patch.object(R, "execute_run", dies), self.assertRaises(KeyboardInterrupt):
            R.run_block(F.P1FakeHost(), block)
        rows = index(self.root)
        self.assertEqual([x["run"] for x in rows], block["order"])
        self.assertTrue(rows[0]["valid"])
        self.assertFalse(rows[1]["valid"])
        self.assertIn("the runner died", rows[1]["reasons"][0])
        with open(os.path.join(self.root, "index.jsonl"), "a", encoding="utf-8") as fh:
            fh.write('{"cut in the mid')
        self.assertEqual(len(index(self.root)), 2)

    def test_the_runner_keeps_to_the_executor_s_cpu(self):
        host = F.P1FakeHost()
        orig = R.PT.build_block

        def thinned(*a, **kw):
            return orig(*a, **{**kw, "benign_specs": F.thin_benign()})
        with mock.patch.object(R.PT, "build_block", side_effect=thinned), contextlib.redirect_stdout(io.StringIO()):
            R.main(["--phase", "smoke", "--seed", "9001", "--runs", "C", "--calibration", self.frozen["calibration"], "--root", self.root], host=host)
        self.assertEqual(host.pinned, "6")


class ArmCouldActTest(Base):
    """T050-07: no M run with an empty feed, failing reloads or a failing step passes as valid."""

    def run_with(self, acts=(), **host):
        block = R.plan_block("smoke", 9001, self.root, frozen=self.frozen, levels={"C2": 1.0}, runs=["M_gru_C2"], label=f"a{len(os.listdir(self.root))}",
                             benign_specs=F.thin_benign(), max_sources=3)
        res = dict(R.run_block(F.P1FakeHost(acts=lambda _r, _b: list(acts), **host), block))["M_gru_C2"]
        return res, read_json(os.path.join(block["dir"], "M_gru_C2", "run.json"))

    def test_a_healthy_feed_passes_and_its_loss_is_reported(self):
        res, meta = self.run_with()
        self.assertTrue(res["ok"], res["reasons"])
        self.assertEqual(meta["shadow"]["parsed"], meta["sink"]["lines"])
        self.assertEqual(meta["shadow"]["socket_loss"], 0.0)
        res, meta = self.run_with(parsed_share=0.8)
        self.assertTrue(res["ok"], res["reasons"])
        self.assertAlmostEqual(meta["shadow"]["socket_loss"], 0.2, delta=0.01)

    def test_a_conf_without_the_socket_sink_invalidates_the_run(self):
        """T050-01's failure itself: armed, sha256s right, no error anywhere, and nothing received."""
        real = R.render_conf
        with mock.patch.object(R, "render_conf", lambda spec, out, deny: real({**spec, "daemon": {"L7_SHADOW": "0"}}, out, deny)):
            res, meta = self.run_with()
        self.assertFalse(res["ok"])
        self.assertTrue(any("the arm's feed is empty" in r for r in res["reasons"]), res["reasons"])
        self.assertEqual(meta["shadow"]["parsed"], 0)

    def test_a_feed_that_loses_most_of_the_sink_invalidates_the_run(self):
        res, _meta = self.run_with(parsed_share=0.4)
        self.assertFalse(res["ok"])
        self.assertTrue(any("of the file sink's" in r and "at least 0.5" in r for r in res["reasons"]), res["reasons"])

    def test_denies_whose_reload_fails_invalidate_the_run(self):
        deny = {"kind": "l7_deny", "level": 1, "ip": "10.0.0.9"}
        res, _m = self.run_with([(60.0, deny), (65.0, {"kind": "l7_reload", "ok": False}), (75.0, {"kind": "l7_reload", "ok": False})])
        self.assertFalse(res["ok"])
        self.assertTrue(any("no reload took effect within 30 s" in r for r in res["reasons"]), res["reasons"])
        self.assertTrue(any("the last reload of the run failed" in r for r in res["reasons"]), res["reasons"])

    def test_a_retried_reload_is_recorded_and_passes(self):
        deny = {"kind": "l7_deny", "level": 1, "ip": "10.0.0.9"}
        res, meta = self.run_with([(60.0, deny), (65.0, {"kind": "l7_reload", "ok": False}), (75.0, {"kind": "l7_reload", "ok": True})])
        self.assertTrue(res["ok"], res["reasons"])
        self.assertEqual((meta["shadow"]["denies"], meta["shadow"]["reloads"], meta["shadow"]["reloads_failed"]), (1, 2, 1))

    def test_a_late_reload_invalidates_it(self):
        deny = {"kind": "l7_deny", "level": 1, "ip": "10.0.0.9"}
        res, _m = self.run_with([(60.0, deny), (95.0, {"kind": "l7_reload", "ok": True})])
        self.assertTrue(any("no reload took effect within 30 s" in r for r in res["reasons"]), res["reasons"])

    def test_the_arm_s_step_error_in_the_attack_window_invalidates_it(self):
        err = {"kind": "daemon_error", "where": "l7_enforce", "error": "x", "action": "step skipped"}
        res, meta = self.run_with([(100.0, err)])
        self.assertFalse(res["ok"])
        self.assertTrue(any("the arm's step failed 1 times" in r for r in res["reasons"]), res["reasons"])
        self.assertEqual(meta["shadow"]["arm_step_errors_in_attack"], 1)

    def test_the_default_rules_arm_has_no_feed_to_read(self):
        block = R.plan_block("smoke", 9001, self.root, frozen=self.frozen, levels={"C3b": 3}, runs=["M_default_rules_C3b"], label="def",
                             benign_specs=F.thin_benign(), max_sources=2)
        res = dict(R.run_block(F.P1FakeHost(), block))["M_default_rules_C3b"]
        self.assertTrue(res["ok"], res["reasons"])


class AttackRanTest(Base):
    """T050-08: a U whose bots send nothing is not 'no harm', an M whose bots send nothing is not 'mitigated'."""

    def run_with(self, silent_count, sources=10):
        block = R.plan_block("smoke", 9001, self.root, frozen=self.frozen, levels={"C2": 1.0}, runs=["U_C2"], label=f"b{silent_count}",
                             benign_specs=F.thin_benign(), max_sources=sources)
        addresses = [e["address"] for e in block["runs"][0]["entities"] if e["role"] == "attack"]
        res = dict(R.run_block(F.P1FakeHost(silent=addresses[:silent_count]), block))["U_C2"]
        return res, read_json(os.path.join(block["dir"], "U_C2", "run.json")), len(addresses)

    def test_an_attack_that_reached_the_server_passes(self):
        res, meta, n = self.run_with(0)
        self.assertTrue(res["ok"], res["reasons"])
        self.assertEqual((meta["sink"]["attack_planned"], meta["sink"]["attack_seen"]), (n, n))

    def test_one_source_of_ten_is_within_the_share(self):
        res, meta, n = self.run_with(1)
        self.assertEqual(meta["sink"]["attack_seen"], n - 1)
        self.assertTrue(res["ok"], res["reasons"])

    def test_an_attack_that_did_not_is_invalid(self):
        res, _m, n = self.run_with(10)
        self.assertFalse(res["ok"])
        self.assertTrue(any(f"from 0 of its {n} addresses" in r for r in res["reasons"]), res["reasons"])


class BenignSilenceTest(Base):
    """T050-11: an attack's lines must not hide a silent benign side."""

    def test_a_silence_of_the_benign_addresses_under_an_attack_s_lines(self):
        sink = os.path.join(self.root, "access.log")
        plan = {"timeline": {"baseline_s": 30, "attack_s": 210, "recovery_s": 30},
                "entities": [{"address": "10.0.1.1", "role": "benign"}, {"address": "10.0.2.1", "role": "attack"}]}
        def line(ip, t):
            return json.dumps({"msec": 1000.0 + t, "rt": 0.01, "ip": ip, "uri": "/", "status": 200, "ua": "u", "method": "GET"}) + "\n"
        with open(sink, "w", encoding="utf-8") as fh:
            fh.writelines(line("10.0.2.1", t) for t in range(35, 240))
            fh.writelines(line("10.0.1.1", t) for t in range(5, 270, 4) if not 100 <= t < 130)
        got = R.sink_reading(sink, plan, 1000.0)
        self.assertGreater(got["benign_gap_s"], 25.0)
        self.assertEqual(got["attack_seen"], 1)
        self.assertTrue(any("on the benign addresses" in r for r in R.sink_problems(got)))

    def test_before_the_attack_a_natural_silence_judges_nothing(self):
        sink = os.path.join(self.root, "access2.log")
        plan = {"timeline": {"baseline_s": 30, "attack_s": 210, "recovery_s": 30}, "entities": [{"address": "10.0.1.1", "role": "benign"}]}
        with open(sink, "w", encoding="utf-8") as fh:
            fh.writelines(json.dumps({"msec": 1000.0 + t, "rt": 0.01, "ip": "10.0.1.1", "uri": "/", "status": 200, "ua": "u", "method": "GET"}) + "\n"
                          for t in range(28, 270, 4))
        got = R.sink_reading(sink, plan, 1000.0)
        self.assertLessEqual(got["benign_gap_s"], 4.0)
        self.assertEqual(R.sink_problems(got), [])


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
        self.assertEqual({k: meta["shadow"][k] for k in ("reports", "evicted", "late", "daemon_errors", "shadow_restarts_in_attack")},
                         {"reports": 2, "evicted": 0, "late": 0, "daemon_errors": [], "shadow_restarts_in_attack": 0})
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
