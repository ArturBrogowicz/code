"""Offline tests for the plan half of bench/executor.py (docs/HG1C_DESIGN.md 6): the namespaces, the aliases, the stack,
the streams and the teardown as data, the rendered Nginx configuration, and the ties to the suite's testbed.

Nothing here opens a socket or starts a process; the suite is imported with its handlers patched out, as in
tests/test_suite_harness.py, to compare constants and read source.
"""
import contextlib
import hashlib
import inspect
import io
import json
import os
import re
import sys
import tempfile
import unittest
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "bench"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import calibration as C
import executor as EX
import loadgen as LG
import loadtools as LT
import origin as O
import population as P
import scenario as SC

with mock.patch("atexit.register"), mock.patch("signal.signal"):
    import test_distributed_suite as S

SPECS = os.path.join(REPO, "bench", "scenarios")
GOLDEN = os.path.join(REPO, "tests", "golden")
CAL = C.load(C.PLACEHOLDER)
OUT = "/var/tmp/ddos_campaigns/example/b01_a1"


def spec_path(name):
    return os.path.join(SPECS, name + ".json")


def sha_of(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def scenario(name="costly_search_sub_threshold", **benign):
    with open(spec_path(name), encoding="utf-8") as fh:
        raw = json.load(fh)
    raw["benign"] = {**raw["benign"], **benign}
    return SC.from_record(raw)


def plan(kind="U", name="costly_search_sub_threshold", seed=1, out=None, **benign):
    return EX.plan_run(scenario(name, **benign), CAL, kind, seed, out or f"{OUT}/{kind}", C.PLACEHOLDER,
                       sha_of(spec_path(name)))


def prims(steps, name):
    return [s for s in steps if isinstance(s, EX.Prim) and s.name == name]


class PlanTest(unittest.TestCase):
    def test_a_run_has_its_namespaces_its_streams_and_its_hash(self):
        p = plan()
        self.assertEqual((p.scenario, p.kind, p.seed, p.level), ("costly_search_sub_threshold", "U", 1, 2.0))
        self.assertEqual(len(p.streams), 33)
        self.assertEqual(sorted(s.kind for s in p.streams).count("attack"), 4)
        self.assertEqual([n.name for n in p.namespaces],
                         ["hg_0_perfect", "hg_1_broadband", "hg_2_mobile_3g", "hg_3_mobile_bad"])
        self.assertEqual(sum(len(n.addresses) for n in p.namespaces), 300)
        self.assertEqual({s.ns for s in p.streams}, {n.name for n in p.namespaces})
        self.assertEqual(len(p.plan_sha256), 64)
        self.assertEqual(p.calibration_status, "placeholder")
        self.assertEqual(p.calibration_sha256, CAL["sha256"])

    def test_the_three_runs_of_a_block_have_the_same_legit_streams(self):
        c, cp, u = plan("C"), plan("Cp"), plan("U")
        self.assertEqual(c.plan_sha256, cp.plan_sha256)
        self.assertEqual(c.plan_sha256, u.plan_sha256)
        self.assertEqual([s.kind for s in c.streams], ["legit"] * 29)
        self.assertEqual(len(u.streams), 33)

        def legit(p):
            return [(s.id, s.ns, s.rate, s.seed, s.nofile, tuple(a.replace(p.out, "") for a in s.argv))
                    for s in p.streams if s.kind == "legit"]
        self.assertEqual(legit(c), legit(u))
        self.assertEqual(legit(cp), legit(u))

    def test_another_seed_is_another_plan_hash(self):
        self.assertNotEqual(plan(seed=1).plan_sha256, plan(seed=2).plan_sha256)
        self.assertEqual(plan(seed=2).plan_sha256, plan(seed=2).plan_sha256)

    def test_bad_input_is_a_plan_error(self):
        for kind, name, seed, fragment in (("X", "costly_search_sub_threshold", 1, "kind"),
                                           ("U", "benign_control", 1, "attack-free"),
                                           ("C", "costly_search_sub_threshold", 100, "outside the namespace")):
            with self.subTest(kind=kind, name=name, seed=seed), self.assertRaisesRegex(EX.PlanError, fragment):
                plan(kind, name, seed)
        self.assertEqual(plan("C", "benign_control").kind, "C")

    def test_the_addresses_are_the_populations_and_each_is_added_once(self):
        p = plan()
        pop = SC.population_of(scenario(), CAL, 1)[0]
        want = pop.alias_plan()
        seen = []
        for ns in p.namespaces:
            [made] = [s for s in p.topology if isinstance(s, EX.Prim) and s.name == "client_ns" and s.args[0] == ns.name]
            batch = [s for s in p.topology if isinstance(s, EX.Cmd) and s.ns == ns.name]
            added = [m.group(1) for line in (batch[0].stdin.splitlines() if batch else [])
                     if (m := re.fullmatch(rf"addr add (\S+){re.escape(EX.SUBNET_MASK)} dev {EX.CLIENT_IF}", line))]
            self.assertEqual(list(ns.addresses), want[ns.index])
            self.assertEqual([made.args[1], *added], list(ns.addresses))
            seen += [made.args[1], *added]
        self.assertEqual(len(seen), 300)
        self.assertEqual(len(set(seen)), 300)
        self.assertEqual(set(seen), {i.address for i in pop.identities})

    def test_the_topology_is_in_order_and_complete(self):
        p = plan()
        names = [(s.name if isinstance(s, EX.Prim) else "cmd") for s in p.topology]
        self.assertEqual(names[:2], ["bridge", "server_ns"])
        for ns in p.namespaces:
            at = {s.name: i for i, s in enumerate(p.topology) if isinstance(s, EX.Prim) and s.args[:1] == (ns.name,)}
            self.assertLess(at["client_ns"], at["netem"])
        self.assertEqual(len(prims(p.topology, "client_ns")), 4)
        self.assertEqual([s.args for s in prims(p.topology, "netem")], [(n.name, n.profile) for n in p.namespaces])

    def test_a_profile_without_an_identity_gets_no_namespace(self):
        p = plan(identities=8, per_profile=6)
        self.assertLess(len(p.namespaces), 24)
        self.assertTrue(all(ns.addresses for ns in p.namespaces))
        self.assertEqual(len(prims(p.topology, "client_ns")), len(p.namespaces))
        self.assertEqual(len(prims(p.topology, "netem")), len(p.namespaces))

    def test_the_veth_names_are_unique_and_short_whatever_the_number_of_namespaces(self):
        for per_profile in range(1, 7):
            names = [EX.ns_name(spec) for spec in P.namespaces(per_profile)]
            outer = [EX.outer_veth(n) for n in names]
            self.assertEqual(len(set(names)), len(names))
            self.assertEqual(len(set(outer)), len(outer), outer)
            self.assertTrue(all(len(v) <= 15 for v in outer), outer)

    def test_the_host_end_of_a_veth_is_named_as_the_suite_names_it(self):
        rule = re.search(r'veth_outer = f"(vo_)\{ns_name\[:(\d+)\]\}"', inspect.getsource(S.create_client_ns))
        prefix, cut = rule.group(1), int(rule.group(2))
        for name in ("hg_0_perfect", "hg_3_mobile_bad", "hg_21_mobile_3g", "x"):
            self.assertEqual(EX.outer_veth(name), prefix + name[:cut])

    def test_the_namespaces_are_not_ones_the_suites_cleanup_or_the_campaign_runners_leftover_check_knows(self):
        for spec in P.namespaces(6):
            name = EX.ns_name(spec)
            self.assertTrue(name.startswith(EX.NS_PREFIX))
            self.assertFalse(name.startswith(("server_ns", "legit_", "bot_")), name)
            self.assertIsNone(re.match(r"(server_ns|legit_|bot_)", name))

    def test_the_streams_carry_the_pins_and_the_limits_the_scenario_plan_prints(self):
        p = plan()
        printed = SC.plan(scenario(), CAL)["generator"]["kinds"]
        for kind in ("legit", "attack"):
            streams = [s for s in p.streams if s.kind == kind]
            self.assertEqual(max(s.nofile for s in streams), printed[kind]["nofile"])
            for s in streams:
                head = ["prlimit", f"--nofile={s.nofile}", "--", "taskset", "-c", P.PIN_PLAN[kind]]
                self.assertEqual(list(s.argv[:6]), head, s.id)
        self.assertEqual(P.PIN_PLAN["legit"], "6")

    def test_every_stream_command_is_one_the_engine_accepts_and_names_its_own_files(self):
        for s in plan().streams:
            with self.subTest(stream=s.id):
                tail = list(s.argv[s.argv.index(os.path.join(REPO, "bench", "loadgen.py")) + 1:])
                self.assertEqual(tail[tail.index("--summary") + 1], s.summary)
                self.assertEqual(tail[tail.index("--records") + 1], s.records)
                self.assertEqual(os.path.dirname(s.summary), s.workdir)
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    self.assertEqual(LG.main([*tail, "--plan"]), 0)
                self.assertIn("requests over", out.getvalue())

    def test_the_stream_commands_are_the_wrappers(self):
        p = plan()
        s = next(x for x in p.streams if x.kind == "attack")
        spec = P.to_load_spec(next(x for x in SC.population_of(scenario(), CAL, 1)[0].streams if x.id == s.id), EX.HTTP_URL)
        wrapped = LT.build_plan("loadgen", spec, s.workdir).steps[0].argv
        self.assertEqual(s.argv[3:], tuple(wrapped))

    def test_the_stack_is_the_proposed_one_in_order(self):
        p = plan()
        kinds = [type(x).__name__ for x in p.stack]
        self.assertEqual(kinds, ["Mkdir", "Write", "Cmd", "Cmd", "Cmd", "Cmd", "Cmd", "Cmd"])
        gun = next(x for x in p.stack if isinstance(x, EX.Cmd) and "gunicorn" in x.argv)
        nginx = next(x for x in p.stack if isinstance(x, EX.Cmd) and "nginx" in x.argv)
        self.assertLess(p.stack.index(gun), p.stack.index(nginx))
        self.assertEqual((gun.ns, gun.keep, nginx.ns, nginx.keep), (EX.SERVER_NS, True, EX.SERVER_NS, False))
        self.assertEqual(dict(gun.env), {"ORIGIN_CALIBRATION": os.path.abspath(C.PLACEHOLDER), "ORIGIN_SEED": "1"})
        self.assertEqual(gun.argv[:3], ("taskset", "-c", "0-1"))
        self.assertEqual(gun.argv[gun.argv.index("--bind") + 1], "127.0.0.1:8080")
        self.assertEqual((gun.argv[gun.argv.index("--workers") + 1], gun.argv[gun.argv.index("--threads") + 1]), ("2", "8"))
        self.assertEqual((gun.argv[-1], gun.argv[gun.argv.index("--chdir") + 1]), ("origin:app", os.path.join(REPO, "bench")))
        self.assertEqual(nginx.argv, ("taskset", "-c", "0-1", "nginx", "-c", f"{p.out}/nginx.conf"))
        [write] = [x for x in p.stack if isinstance(x, EX.Write)]
        self.assertEqual((write.path, write.sha256), (f"{p.out}/nginx.conf", p.nginx_conf_sha256))
        self.assertEqual(hashlib.sha256(p.nginx_conf.encode()).hexdigest(), p.nginx_conf_sha256)
        touched = next(x for x in p.stack if isinstance(x, EX.Cmd) and x.argv[0] == "touch")
        self.assertEqual(set(touched.argv[1:]), {f"{p.out}/nginx_access.log", f"{p.out}/nginx_error.log"})
        self.assertIn(f"access_log {p.out}/nginx_access.log json_ml_format;", p.nginx_conf)

    def test_the_certificate_is_made_only_if_it_is_missing(self):
        cert = next(x for x in plan().stack if isinstance(x, EX.Cmd) and x.argv[0] == "openssl")
        self.assertEqual(cert.when, f"absent:{EX.CERT}")
        self.assertIn(EX.CERT, cert.argv)

    def test_the_readiness_probe_asks_for_routes_the_origin_serves(self):
        p = plan()
        patterns = dict(O.ROUTES)
        self.assertEqual([k for k, _ in p.checks], list(O.CLASSES))
        for klass, path in p.checks:
            self.assertTrue(patterns[klass].fullmatch(path.split("?")[0]), (klass, path))
        self.assertIsNone(patterns["C0"].fullmatch("/"))                   # the origin answers 404 at "/"
        self.assertTrue(patterns["C0"].fullmatch(EX.READY_PATH))

    def test_nothing_in_the_plan_kills_or_searches_by_pattern(self):
        p = plan()
        for step in (*p.topology, *p.stack, *p.teardown):
            if isinstance(step, EX.Cmd):
                self.assertNotIn(step.argv[0], ("pkill", "killall", "pgrep"), step)
                self.assertNotIn("-f", step.argv, step)

    def test_the_teardown_finds_processes_by_namespace_and_removes_what_was_built(self):
        p = plan()
        names = [n.name for n in p.namespaces] + [EX.SERVER_NS]
        cmds = [x.argv for x in p.teardown]
        self.assertEqual([c for c in cmds if c[:3] == ("ip", "netns", "pids")], [("ip", "netns", "pids", n) for n in names])
        self.assertEqual([c for c in cmds if c[:3] == ("ip", "netns", "del")], [("ip", "netns", "del", n) for n in names])
        self.assertEqual(cmds[-1], ("ip", "link", "del", EX.BRIDGE))
        links = {c[3] for c in cmds if c[:3] == ("ip", "link", "del")}
        self.assertEqual(links, {EX.outer_veth(n.name) for n in p.namespaces} | {EX.SERVER_VETH_HOST_END, EX.BRIDGE})
        self.assertLess(max(i for i, c in enumerate(cmds) if c[:3] == ("ip", "netns", "pids")),
                        min(i for i, c in enumerate(cmds) if c[:3] == ("ip", "netns", "del")))

    def test_the_attack_is_launched_so_that_it_starts_at_the_end_of_the_baseline(self):
        p = plan()
        s = p.settings
        self.assertAlmostEqual(EX.launch_attack_after(p), 30.0 + s["startup_delay_legit_s"] - s["startup_delay_attack_s"])
        self.assertAlmostEqual(EX.launch_attack_after(p), 31.5)
        self.assertEqual({x.start_s for x in p.streams if x.kind == "attack"}, {30.0})
        self.assertEqual({(x.start_s, x.duration_s) for x in p.streams if x.kind == "legit"}, {(0.0, 105.0)})

    def test_settings_are_recorded_and_can_be_overridden(self):
        p = plan()
        self.assertEqual(p.settings, EX.SETTINGS)
        q = EX.plan_run(scenario(), CAL, "U", 1, f"{OUT}/U", C.PLACEHOLDER, settings={"startup_delay_legit_s": 2.5})
        self.assertEqual(q.settings["startup_delay_legit_s"], 2.5)
        self.assertAlmostEqual(EX.launch_attack_after(q), 32.2)

    def test_the_plan_is_pure_and_is_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                a, b = plan(), plan()
                self.assertEqual(a, b)
                data = EX.as_json(a)
                self.assertEqual(os.listdir(tmp), [])
            finally:
                os.chdir(cwd)
        self.assertEqual(json.loads(json.dumps(data)), data)
        self.assertEqual({x["do"] for x in data["topology"]}, {"prim", "cmd"})
        self.assertEqual({x["do"] for x in data["stack"]}, {"mkdir", "write", "cmd"})
        self.assertEqual(len(data["streams"]), 33)
        self.assertEqual(data["plan_sha256"], a.plan_sha256)

    def test_a_run_directory_is_called_after_its_kind_because_the_gate_reads_the_role_from_the_name(self):
        for kind, name in (("U", "C"), ("C", "run1"), ("Cp", "Cp_old")):
            with self.subTest(kind=kind, name=name), self.assertRaisesRegex(EX.PlanError, "is called"):
                EX.plan_run(scenario(), CAL, kind, 1, f"{OUT}/{name}", C.PLACEHOLDER)
        self.assertEqual(EX.plan_run(scenario(), CAL, "Cp", 1, f"{OUT}/Cp/", C.PLACEHOLDER).kind, "Cp")

    def test_a_smoke_test_overrides_the_load_and_says_so(self):
        p = EX.plan_run(scenario(), CAL, "C", 1, f"{OUT}/C", C.PLACEHOLDER, rho=20.0)
        self.assertEqual(p.overrides, {"rho_rps": 20.0})
        self.assertAlmostEqual(sum(s.rate for s in p.streams), 20.0, delta=0.5)
        self.assertEqual(plan().overrides, {})
        self.assertIn("OVERRIDES", EX.describe(p))
        self.assertNotIn("OVERRIDES", EX.describe(plan()))
        self.assertNotEqual(p.plan_sha256, plan("C").plan_sha256)

    def test_a_smoke_test_can_shorten_the_timeline_and_says_so(self):
        p = EX.plan_run(scenario(), CAL, "U", 1, f"{OUT}/U", C.PLACEHOLDER, timeline=(10.0, 12.0, 8.0))
        self.assertEqual(p.overrides, {"timeline_s": [10.0, 12.0, 8.0]})
        self.assertEqual(p.timeline, {"baseline_s": 10.0, "attack_s": 12.0, "recovery_s": 8.0, "total_s": 30.0})
        self.assertEqual({s.duration_s for s in p.streams if s.kind == "legit"}, {30.0})
        self.assertEqual({(s.start_s, s.duration_s) for s in p.streams if s.kind == "attack"}, {(10.0, 12.0)})
        self.assertEqual(EX.launch_attack_after(p), 10.0 + 1.8 - 0.3)
        self.assertIn("timeline_s", EX.describe(p))
        both = EX.plan_run(scenario(), CAL, "U", 1, f"{OUT}/U", C.PLACEHOLDER, rho=20.0, timeline=(10.0, 12.0, 8.0))
        self.assertEqual(both.overrides, {"rho_rps": 20.0, "timeline_s": [10.0, 12.0, 8.0]})

    def test_a_timeline_that_is_not_three_positive_numbers_is_refused(self):
        for bad in ((10.0, 10.0), (10.0, 0.0, 10.0), (10.0, -1.0, 10.0)):
            with self.subTest(timeline=bad), self.assertRaises(EX.PlanError):
                EX.plan_run(scenario(), CAL, "C", 1, f"{OUT}/C", C.PLACEHOLDER, timeline=bad)

    def test_a_load_that_is_not_a_positive_number_is_refused(self):
        for bad in (0, -5.0, float("nan"), float("inf"), "20", True):
            with self.subTest(rho=bad), self.assertRaises(EX.PlanError):
                EX.plan_run(scenario(), CAL, "C", 1, f"{OUT}/C", C.PLACEHOLDER, rho=bad)

    def test_a_relative_run_directory_becomes_absolute(self):
        p = EX.plan_run(scenario(), CAL, "C", 1, "runs/C", C.PLACEHOLDER)
        self.assertTrue(os.path.isabs(p.out))
        self.assertTrue(all(s.workdir.startswith(p.out) for s in p.streams))


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


class NginxConfTest(unittest.TestCase):
    ORIGINAL = read(EX.NGINX_CONF)

    def test_only_the_two_log_lines_change(self):
        out = EX.render_nginx_conf(self.ORIGINAL, "/run/x/access.log", "/run/x/error.log")
        old, new = self.ORIGINAL.splitlines(), out.splitlines()
        self.assertEqual(len(old), len(new))
        changed = [(a, b) for a, b in zip(old, new, strict=True) if a != b]
        self.assertEqual(len(changed), 2)
        self.assertEqual([b.strip() for _, b in changed],
                         ["access_log /run/x/access.log json_ml_format;", "error_log /run/x/error.log info;"])
        self.assertEqual([a.strip() for a, _ in changed],
                         ["access_log /var/log/nginx/ddos_ml_access.log json_ml_format;",
                          "error_log /var/log/nginx/error.log info;"])

    def test_the_rendering_keeps_the_indentation_and_the_original_file_alone(self):
        out = EX.render_nginx_conf(self.ORIGINAL, "/a", "/b")
        self.assertIn("\n    access_log /a json_ml_format;\n", out)
        self.assertEqual(self.ORIGINAL, read(EX.NGINX_CONF))
        self.assertEqual(out, EX.render_nginx_conf(self.ORIGINAL, "/a", "/b"))

    def test_the_stack_is_the_unprotected_one(self):
        out = EX.render_nginx_conf(self.ORIGINAL, "/a", "/b")
        self.assertIsNone(re.search(r"^[ \t]*(limit_req_zone|limit_req[ \t]|limit_conn_zone|limit_conn[ \t])", out, re.MULTILINE))
        self.assertIn("proxy_pass http://127.0.0.1:8080;", out)

    def test_a_configuration_that_does_not_have_exactly_these_lines_is_refused(self):
        lines = self.ORIGINAL.splitlines(keepends=True)
        access = next(i for i, x in enumerate(lines) if x.strip().startswith("access_log /var/log/nginx"))
        error = next(i for i, x in enumerate(lines) if x.strip().startswith("error_log /var/log/nginx"))
        without_access = "".join(x for i, x in enumerate(lines) if i != access)
        twice = "".join(lines[:access + 1] + [lines[access]] + lines[access + 1:])
        other = "".join(x.replace("/var/log/nginx/error.log", "/var/log/nginx/other.log") if i == error else x
                        for i, x in enumerate(lines))
        for text, fragment in ((without_access, "access_log"), (twice, "access_log"), (other, "error_log"), ("", "access_log")):
            with self.subTest(fragment=fragment), self.assertRaisesRegex(EX.PlanError, fragment):
                EX.render_nginx_conf(text, "/a", "/b")


class SuiteContractTest(unittest.TestCase):
    """The executor plans the suite's testbed without importing it; these say that it still is the suite's."""

    def test_the_constants_are_the_suites(self):
        self.assertEqual((EX.SERVER_NS, EX.SERVER_IP, EX.BRIDGE, EX.SUBNET_MASK, EX.HTTP_URL),
                         (S.SERVER_NS, S.SERVER_IP, S.BRIDGE_NAME, S.SUBNET_MASK, S.HTTP_URL))
        self.assertEqual(EX.NGINX_CONF, S.NGINX_UNPROTECTED_CONF)

    def test_every_symbol_the_executor_will_call_exists_with_the_signature_it_expects(self):
        for name in ("run", "create_host_bridge", "create_server_ns", "create_client_ns", "apply_tc"):
            self.assertTrue(callable(getattr(S, name)), name)
        self.assertEqual(list(inspect.signature(S.create_client_ns).parameters), ["ns_name", "ip_addr"])
        self.assertEqual(list(inspect.signature(S.apply_tc).parameters), ["ns_name", "profile"])
        self.assertEqual(list(inspect.signature(S.create_host_bridge).parameters), [])
        self.assertEqual(list(inspect.signature(S.create_server_ns).parameters), [])
        self.assertEqual(list(inspect.signature(S.run).parameters)[:3], ["cmd", "ns", "bg"])

    def test_the_names_the_executor_relies_on_are_in_the_suites_source(self):
        client, server = inspect.getsource(S.create_client_ns), inspect.getsource(S.create_server_ns)
        self.assertIn(f'veth_inner = "{EX.CLIENT_IF}"', client)
        self.assertIn('veth_outer = f"vo_{ns_name[:12]}"', client)
        self.assertIn(f'"{EX.SERVER_VETH_HOST_END}"', server)
        self.assertIn("{ip_addr}{SUBNET_MASK} dev {veth_inner}", client)

    def test_the_link_profiles_are_the_suites(self):
        source = inspect.getsource(S.apply_tc)
        self.assertEqual(sorted(set(re.findall(r'profile == "(\w+)"', source)) | {"perfect"}), sorted(C.LINK_PROFILES))
        for name in C.LINK_PROFILES:
            self.assertIn(f'"{name}"', inspect.getsource(S.build_topology))

    def test_the_suites_kill_patterns_do_not_match_the_executors_own_command_line(self):
        cleanup = inspect.getsource(S.cleanup_all)
        patterns = re.findall(r'"-f", "([^"]+)"', cleanup)
        self.assertTrue(patterns)
        ours = "python3 bench/executor.py plan bench/scenarios/costly_search_sub_threshold.json --kind U --seed 1"
        ours_run = "sudo ./venv/bin/python bench/executor.py run bench/scenarios/costly_search_sub_threshold.json"
        for pattern in patterns:
            for line in (ours, ours_run):
                self.assertIsNone(re.search(pattern, line), (pattern, line))


class DescribeTest(unittest.TestCase):
    def golden(self, name):
        with open(os.path.join(GOLDEN, name), encoding="utf-8") as fh:
            return fh.read()

    def test_the_plans_are_the_committed_ones(self):
        for kind, spec, golden in (("U", "costly_search_sub_threshold", "executor_costly_search_sub_threshold_U.plan.txt"),
                                   ("C", "benign_control", "executor_benign_control_C.plan.txt")):
            with self.subTest(golden=golden):
                text = EX.describe(plan(kind, spec))
                self.assertEqual(text, self.golden(golden),
                                 f"regenerate: python3 bench/executor.py plan bench/scenarios/{spec}.json --kind {kind} "
                                 f"--seed 1 --out {OUT}/{kind} > tests/golden/{golden}, and read the diff")

    def test_the_text_holds_no_path_of_this_checkout_and_no_interpreter(self):
        text = EX.describe(plan())
        self.assertNotIn(REPO, text)
        self.assertNotIn(sys.executable, text)
        self.assertIn("<python>", text)
        self.assertIn("<repo>/bench/loadgen.py", text)

    def test_it_says_what_it_does_not_do_in_the_header(self):
        text = EX.describe(plan())
        self.assertIn("PLACEHOLDER", text)
        self.assertIn("never by pattern", text)
        self.assertIn("never", EX.describe(plan("C")).split("teardown")[1])
        self.assertIn("no attack in this run", EX.describe(plan("C")))

    def test_a_control_run_has_no_attack_line(self):
        text = EX.describe(plan("C"))
        self.assertNotIn("attack streams are launched", text)
        self.assertIn("29 engine processes (29 legit, 0 attack)", text)


class CommandLineTest(unittest.TestCase):
    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = EX.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_plan_prints_the_plan(self):
        code, out, err = self.run_main("plan", spec_path("costly_search_sub_threshold"), "--kind", "U", "--seed", "1",
                                       "--out", f"{OUT}/U")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(out, EX.describe(plan("U")))

    def test_the_default_seed_is_the_scenarios_first_and_the_default_calibration_the_placeholder(self):
        a = self.run_main("plan", spec_path("benign_control"), "--kind", "C", "--out", f"{OUT}/C")
        b = self.run_main("plan", spec_path("benign_control"), "--kind", "C", "--seed", "1", "--calibration",
                          C.PLACEHOLDER, "--out", f"{OUT}/C")
        self.assertEqual(a, b)

    def test_json_is_the_plan_json_of_a_run(self):
        code, out, _ = self.run_main("plan", spec_path("costly_search_sub_threshold"), "--kind", "Cp", "--seed", "3",
                                     "--out", f"{OUT}/Cp", "--json")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual((data["kind"], data["seed"], data["scenario"]), ("Cp", 3, "costly_search_sub_threshold"))
        self.assertEqual(data["plan_sha256"], plan("Cp", seed=3).plan_sha256)

    def test_errors_are_one_line_and_exit_1(self):
        for argv in (["plan", spec_path("benign_control"), "--kind", "U"],
                     ["plan", spec_path("costly_search_sub_threshold"), "--kind", "C", "--seed", "100"],
                     ["plan", "no/such/spec.json", "--kind", "C"],
                     ["plan", spec_path("benign_control"), "--kind", "C", "--calibration", "no/such/cal.json"]):
            with self.subTest(argv=argv):
                code, out, err = self.run_main(*argv)
                self.assertEqual((code, out), (1, ""))
                self.assertEqual(len(err.strip().splitlines()), 1, err)

    def test_a_kind_is_required_and_must_be_known(self):
        for argv in (["plan", spec_path("benign_control")], ["plan", spec_path("benign_control"), "--kind", "M"]):
            with self.subTest(argv=argv), self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                EX.main(argv)

    def test_a_frozen_calibration_removes_the_banner(self):
        import calibration_fixtures as F
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "frozen.json")
            C.dump(F.frozen(), path)
            code, out, _ = self.run_main("plan", spec_path("benign_control"), "--kind", "C", "--calibration", path)
        self.assertEqual(code, 0)
        self.assertNotIn("PLACEHOLDER", out)
        self.assertIn("frozen", out.splitlines()[1])


if __name__ == "__main__":
    unittest.main()
