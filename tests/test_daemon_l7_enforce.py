"""The L7 v2 enforcing arm inside the daemon (L7_ENFORCE=1; l7_enforce.py, l7_denymap.py; docs/L7V2_DESIGN.md 9), on
the fakes of tests/daemon_harness.py: the real l7_shadow_monitor reads scripted datagrams through the real L7 v2 view
engine (a stub scorer), and the arm's steps run in between, as its thread would; nginx, `ss` and XDP are the harness's
fakes. Nothing is imported from control_plane.py and nothing is attached, started or reloaded for real.
"""
import ast
import os
import sys
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, REPO)
import daemon_harness as H
import test_daemon_l7_shadow_v2 as V2

import l7_denymap
import l7_enforce
import l7_engine
import l7_ingest

CONF = "/var/tmp/ddos_campaigns/example/run/nginx.conf"     # the run's rendered conf: only named in the reload argv
RELOAD = ["nginx", "-c", CONF, "-s", "reload"]
BOT, BOT_UA, POOL, SID, SID2, SID3 = V2.BOT, V2.BOT_UA, V2.POOL, V2.SID, V2.SID2, V2.SID3
RefStub, bot, browser, rec, run_shadow = V2.RefStub, V2.bot, V2.browser, V2.rec, V2.run_shadow
ENFORCE = {"L7_SHADOW": "1", "L7_ENFORCE": "1", "L7_NGINX_CONF": CONF, "L7_ARM": "view_gru",
           "L7_SELECTION": "/var/tmp/ddos_campaigns/example/sel/selection.json", "L7_SELECTION_SHA256": "0" * 64}


class L7Case(unittest.TestCase):
    def daemon(self, **env):
        d = H.Daemon(env)
        self.addCleanup(d.close)
        self.detector = RefStub()                                      # what l7_arms.load gives the arm
        self.loads = []
        arms = types.SimpleNamespace(load=lambda *a: self.loads.append(a) or self.detector)
        d.ns.update(l7_denymap=l7_denymap, l7_enforce=l7_enforce, l7_arms=arms)
        d.ns["L7_ENFORCE_DIR"] = os.path.join(d._tmp.name, "l7v2")
        d.clock.now = 999.0
        return d

    def shadow(self, d, records, until, scorer=None):
        """The real l7_shadow_monitor over `records`, the arm stepping every second when enforcing."""
        tick = (lambda _t: d.call("l7_enforce_poll")) if d.L7_ENFORCE else None
        return run_shadow(d, records, until, scorer=scorer, tick=tick)

    def map_lines(self, d):
        with open(os.path.join(d.L7_ENFORCE_DIR, l7_denymap.DENY_FILE), encoding="ascii") as fh:
            return fh.read().splitlines()


class OffByDefaultTest(L7Case):
    def test_without_l7_enforce_the_shadow_runs_as_before(self):
        d = self.daemon(L7_SHADOW="1")
        self.assertFalse(d.L7_ENFORCE)
        self.shadow(d, bot() + browser(), until=1100.0)
        [wb] = d.events("l7_would_ban")
        self.assertEqual((wb["ip"], wb["sid_h"]), (BOT, l7_ingest.stable_hash32(SID)))
        kinds = {e["kind"] for e in d.events()}
        self.assertEqual(kinds, {"l7_would_ban", "l7_shadow", "l7_gru_poll"})
        self.assertIsNone(d.l7_arm)
        self.assertEqual((d.proc.calls, d.bans(), d.blacklist.ips()), ([], [], set()))
        self.assertFalse(os.path.exists(d.L7_ENFORCE_DIR))

    def test_every_use_of_the_arm_in_the_shadow_thread_is_behind_l7_enforce(self):
        with open(H.SOURCE, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        [monitor] = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "l7_shadow_monitor"]
        guarded = set()
        for node in ast.walk(monitor):
            if isinstance(node, ast.If) and isinstance(node.test, ast.Name) and node.test.id == "L7_ENFORCE":
                guarded |= {id(n) for s in node.body for n in ast.walk(s)}
        uses = [n for n in ast.walk(monitor) if isinstance(n, ast.Name) and n.id in ("l7_arm", "l7_detector")]
        self.assertEqual(len(uses), 4)                                  # the detector; attach, observe, submit
        self.assertTrue(all(id(n) in guarded for n in uses))
        # no ban path from the shadow thread, whatever the switch (test_control_plane_contract checks direct calls)
        called = {n.func.id for n in ast.walk(monitor) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        self.assertFalse(called & {"ban_ip", "block_ip_in_xdp", "kill_zombie_connections", "l7_nginx_reload"})

    def test_an_enforcing_daemon_without_the_engine_or_the_conf_does_not_start(self):
        for env in [{k: v for k, v in ENFORCE.items() if k != gone} for gone in ENFORCE if gone != "L7_ENFORCE"] + [
                {**ENFORCE, "L7_MODEL": "/var/tmp/pkg"}]:
            with self.subTest(env=env), self.assertRaises(SystemExit):
                H.Daemon(env)
        self.assertFalse(self.daemon(L7_NGINX_CONF=CONF).L7_ENFORCE)    # unused while off


class ThreadTest(L7Case):
    def started(self, d):
        from test_daemon_robustness import MainRun
        main = MainRun(d)

        def tailer(_path):
            d.stop_event.set()
            return
            yield                                                       # a generator, like the real one
        main.run(tailer)
        d.stop_event.clear()
        return main.threads

    def test_the_arm_runs_in_its_own_supervised_thread_built_before_the_shadow_starts(self):
        d = self.daemon(**ENFORCE)
        threads = self.started(d)
        self.assertEqual(sorted(t.args[0] for t in threads),
                         ["inference", "l7_enforce", "l7_shadow", "rudy", "telemetry"])
        self.assertEqual([t for t in threads if t.target is not d.supervise], [])
        names = [t.args[0] for t in threads]
        self.assertLess(names.index("l7_enforce"), names.index("l7_shadow"))
        self.assertIsInstance(d.l7_arm, l7_enforce.Arm)
        self.assertEqual(self.loads, [(ENFORCE["L7_SELECTION"], "0" * 64, "view_gru")])
        self.assertIs(d.l7_detector, self.detector)
        self.assertEqual(self.map_lines(d), [])                         # the run directory and an empty map
        [start] = d.events("start")
        self.assertTrue(start["l7_enforce"])
        self.assertNotIn("l7_enforce", [t.args[0] for t in self.started(self.daemon(L7_SHADOW="1"))])

    def test_a_failing_step_is_reported_and_the_next_one_runs(self):
        d = self.daemon(**ENFORCE)
        d.call("l7_enforce_init")
        calls = []

        def step(now):
            calls.append(now)
            if len(calls) == 1:
                raise RuntimeError("boom")
        d.l7_arm.step = step
        d.run_loop("l7_enforce_monitor", 3)
        self.assertEqual(calls, [1000.0, 1001.0, 1002.0])
        [err] = d.events("daemon_error")
        self.assertEqual((err["where"], err["error"], err["action"]), ("l7_enforce", "RuntimeError: boom",
                                                                         "step skipped"))

    def test_a_run_directory_others_may_write_stops_the_daemon(self):
        d = self.daemon(**ENFORCE)
        os.makedirs(d.L7_ENFORCE_DIR, mode=0o777)
        os.chmod(d.L7_ENFORCE_DIR, 0o777)
        with self.assertRaises(SystemExit):
            d.call("l7_enforce_init")


class ReloadTest(L7Case):
    def test_the_reload_signals_the_runs_nginx_and_reads_its_exit_status(self):
        d = self.daemon(**ENFORCE)
        self.assertEqual(d.call("l7_nginx_reload"), (True, ""))
        d.proc.failures[("nginx",)] = 1
        ok, detail = d.call("l7_nginx_reload")
        self.assertEqual((ok, detail), (False, "nginx exited 1: simulated failure"))
        d.proc.failures[("nginx",)] = FileNotFoundError(2, "No such file or directory", "nginx")
        self.assertFalse(d.call("l7_nginx_reload")[0])
        self.assertEqual(d.proc.calls, [RELOAD] * 3)


class EndToEndTest(L7Case):
    def test_a_bot_is_denied_at_nginx_then_xdp_banned_when_it_keeps_sending(self):
        d = self.daemon(**ENFORCE)
        d.call("l7_enforce_init")
        self.shadow(d, bot() + browser(), until=1100.0)
        [wb] = d.events("l7_would_ban")
        [deny] = d.events("l7_deny")
        self.assertEqual((deny["ip"], deny["ua_h"], deny["sid_h"], deny["arm"], deny["level"]),
                         (BOT, wb["ua_h"], wb["sid_h"], "view_gru", 1))
        log = d.events()                                                # in the order written (t_wall is real time)
        self.assertLess(log.index(wb), log.index(deny))                 # no action without a would-ban before it
        self.assertGreaterEqual(deny["key_age_s"], l7_enforce.KEY_AGE_S)
        self.assertEqual(d.proc.matching("nginx")[0], RELOAD)
        [ban] = d.bans()
        self.assertEqual({k: ban[k] for k in ("ip", "engine", "level", "arm", "threshold", "consecutive", "p",
                                              "ttl_s", "ua_keys", "sid_keys")},
                         {"ip": BOT, "engine": "l7v2", "level": 2, "arm": "view_gru", "threshold": 0.5,
                          "consecutive": 2, "p": 0.99, "ttl_s": 300, "ua_keys": 1, "sid_keys": 1})
        self.assertGreaterEqual(ban["after_s"], l7_enforce.LEVEL2_AFTER_S)
        [entry] = list(d.l7_arm.denies)
        self.assertGreaterEqual(d.ban_timestamps[BOT] - entry.t_loaded, l7_enforce.LEVEL2_AFTER_S)
        self.assertEqual((d.blacklist.ips(), d.banned_ips), ({BOT}, {BOT}))
        self.assertIn(["ss", "-K", "dst", BOT], d.proc.calls)
        self.assertIn(f"[BAN] {BOT} banned for 300s. Reason: L7 v2 arm view_gru", d.console())
        self.assertEqual(self.map_lines(d), [f'"{BOT}|{BOT_UA}|{SID}" 1;'])
        acts = [i for i, e in enumerate(log) if e["kind"] in ("l7_deny", "l7_enforce_miss", "l7_reload", "ban")]
        self.assertTrue(acts and min(acts) > log.index(wb))

    def test_a_cgnat_address_gets_the_deny_and_never_the_xdp_ban(self):
        d = self.daemon(**ENFORCE)
        d.call("l7_enforce_init")
        records = bot(ip=POOL) + browser(ip=POOL, sid=SID2) + browser(ip=POOL, sid=SID3, t0=1001.0)
        self.shadow(d, records, until=1100.0)
        self.assertEqual([e["ip"] for e in d.events("l7_deny")], [POOL])
        self.assertEqual((d.bans(), d.blacklist.ips()), ([], set()))
        [guard] = [s for s in d.events("l7_enforce_skip") if s["reason"] == "cgnat_guard"]
        self.assertEqual((guard["ip"], guard["sid_keys"]), (POOL, 3))

    def test_a_key_past_the_engines_per_poll_cap_is_acted_on_as_the_engine_decides(self):
        # T038-06 (review of the model side): L7ViewEngine scores at most MAX_NEW_WINDOWS new windows of a key per
        # poll, so a key that completes more (pageless API keys, here 10 requests in one second) has its k
        # consecutive windows span non-adjacent ones. The arm does not look at the streak: it acts on the would-ban
        # the engine emits, as for any key. Pinned here as the current behaviour, not endorsed.
        d = self.daemon(**ENFORCE)
        d.call("l7_enforce_init")
        burst = [rec(BOT, f"/api/item/{n}", 1000.0 + 0.09 * n) for n in range(10)]
        later = [rec(BOT, f"/api/item/{n}", 1030.0 + 0.5 * n) for n in range(4)]
        scorer = self.detector
        engine = self.shadow(d, burst + later, until=1040.0)
        self.assertEqual(scorer.calls[0], l7_engine.MAX_NEW_WINDOWS)    # 6 windows completed, the last 4 scored
        [wb] = d.events("l7_would_ban")
        self.assertLess(wb["t_poll"], 1002.0)                           # the poll that took the whole burst
        self.assertEqual(engine.totals["would_bans"], 1)
        skipped = sum(p.get("skipped", 0) for p in d.events("l7_gru_poll"))
        self.assertEqual(skipped, 10 - 1 - 4 + 1 - l7_engine.MAX_NEW_WINDOWS)
        [deny] = d.events("l7_deny")
        self.assertEqual((deny["ip"], deny["p"]), (BOT, wb["p"]))


if __name__ == "__main__":
    unittest.main()
