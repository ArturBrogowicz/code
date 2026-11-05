"""R*'s level 2 and its events (l7_enforce at the rule level, l7_arms' validity checks; docs/L7V2_DESIGN.md 9.2, 9.3, 19;
D-044 OC-2): an XDP ban only for a single-key address, as for every arm, and events that carry the arm, the rule's
statistic and threshold, k, the level and the users seen behind the key. Offline, on the fakes of tests/daemon_harness.py.
"""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "ml"))
import daemon_harness as H
import test_daemon_l7_shadow_v2 as V2
import test_l7_enforce as T
import test_l7_rstar as RS

import ban_events
import l7_arms as L
import l7_denymap as D
import l7_enforce as A
import l7_engine
import l7_ingest as I

BOT, UA, SID = T.BOT, T.UA, T.SID
STAT = {"key:cost_60": 412.5}
LIMIT = {"key:cost_60": 300.0}


def decision(ip=BOT, ua=UA, t=1010.0):
    return {**RS.rule_would_ban(ip, ua, t), "statistic": STAT, "stat_threshold": LIMIT}


class EventsTest(RS.Section9Case):
    def test_the_deny_carries_the_arm_the_rule_its_statistic_k_the_level_and_the_users_seen(self):
        for sid in ("a" * 32, "b" * 32, "b" * 32, ""):
            self.see(sid=sid, start=990.0)
        self.arm.submit(decision())
        self.step(1010.0)
        [deny] = self.f.read("l7_deny")
        self.assertEqual({k: deny[k] for k in ("arm", "rule_arm", "statistic", "stat_threshold", "threshold", "consecutive",
                                               "p", "level", "users_seen", "sid_h")},
                         {"arm": "R*", "rule_arm": "cost_budget", "statistic": STAT, "stat_threshold": LIMIT,
                          "threshold": 0.5, "consecutive": 3, "p": 1.0, "level": 1, "users_seen": 3, "sid_h": None})

    def test_every_decision_event_carries_them_and_users_seen_is_read_when_the_event_is_written(self):
        self.see(ua='Bad "UA"', sid="a" * 32, start=990.0)
        self.see(start=1005.0, ip="10.0.17.6")
        self.arm.submit(decision(ua='Bad "UA"'))                         # a miss
        self.arm.submit(decision(ip="10.0.17.6"))                        # waits: 5 s old
        self.step(1010.0)
        [miss] = self.f.read("l7_enforce_miss")
        [wait] = self.f.read("l7_enforce_skip")
        self.assertEqual([(e["rule_arm"], e["statistic"], e["users_seen"]) for e in (wait,)], [("cost_budget", STAT, 1)])
        self.assertEqual((miss["statistic"], miss["stat_threshold"], miss["users_seen"], miss["level"]), (STAT, LIMIT, 1, 1))
        self.see(ip="10.0.17.6", sid="c" * 32, start=1011.0)
        self.step(1030.0)
        self.assertEqual(self.f.read("l7_deny")[0]["users_seen"], 2)

    def test_users_seen_is_bounded_per_key_and_over_keys(self):
        for n in range(A.MAX_USERS_PER_KEY + 10):
            self.see(sid=f"{n:032x}", start=990.0)
        self.assertEqual(len(self.arm.users[(BOT, I.stable_hash32(UA))]), A.MAX_USERS_PER_KEY)
        self.arm.raw.max_keys = 3
        for n in range(6):
            self.see(ip=f"10.0.22.{n}", start=990.0)
        self.assertEqual(len(self.arm.users), 3)

    def test_a_view_arms_events_are_as_they_were(self):
        self.arm.denies = D.DenyMap(self.run_dir)
        self.arm.attach(T.view_engine())
        self.see(start=900.0)
        self.arm.submit(T.would_ban())
        self.step(1000.0)
        [deny] = self.f.read("l7_deny")
        self.assertEqual(set(deny) - {"t_wall", "t_mono_ns"},
                         {"kind", "ip", "ua_h", "sid_h", "arm", "threshold", "consecutive", "p", "t_poll", "level", "shared",
                          "key_age_s", "active", "ttl_s"})
        self.assertEqual(self.arm.users, {})
        self.assertNotIn("rule_arm", self.f.read("l7_enforce_arm")[-1])

    def test_no_event_carries_a_raw_user_agent_or_session_id(self):
        self.see(sid=SID, start=990.0)
        self.arm.submit(decision())
        self.step(1010.0)
        self.see(sid=SID, start=1041.0)
        self.step(1042.0)
        self.step(1400.0)
        with open(self.f.events_path, encoding="utf-8") as fh:
            text = fh.read()
        self.assertGreater(len(text.splitlines()), 3)
        for raw in (UA, SID):
            self.assertNotIn(raw, text)


class Level2Test(RS.Section9Case):
    def denied(self, **kw):
        self.see(start=990.0, **kw)
        self.arm.submit(decision())
        self.step(1010.0)                                                # denied, reloaded: in effect from 1010

    def test_an_xdp_ban_only_after_30_s_of_sending_past_the_deny_for_a_single_key_address(self):
        self.denied(sid="a" * 32)
        self.see(sid="b" * 32, start=1039.9)                             # any session of the key is the key sending
        self.step(1040.0)
        self.assertEqual(self.f.bans, [])
        self.see(sid="a" * 32, start=1040.0)
        self.step(1041.0)
        [ban] = self.f.bans
        self.assertEqual({k: ban[k] for k in ("ip", "engine", "level", "arm", "rule_arm", "statistic", "stat_threshold", "p",
                                              "threshold", "consecutive", "ua_keys", "sid_keys", "after_s", "denied",
                                              "users_seen", "ua_h", "sid_h")},
                         {"ip": BOT, "engine": "l7v2", "level": 2, "arm": "R*", "rule_arm": "cost_budget", "statistic": STAT,
                          "stat_threshold": LIMIT, "p": 1.0, "threshold": 0.5, "consecutive": 3, "ua_keys": 1,
                          "sid_keys": 2, "after_s": 30.0, "denied": True, "users_seen": 2,
                          "ua_h": I.stable_hash32(UA), "sid_h": None})
        self.assertEqual(ban_events.engine_from_reason(ban["reason"]), ban_events.L7V2_ENGINE)
        self.assertIn("in 3 rows", ban["reason"])
        self.assertEqual(self.f.closed, [BOT])

    def test_the_cgnat_guard_holds_the_deny_stays_and_no_ban_follows(self):
        for extra in ({"ua": ["Other/1", "Other/2"]}, {"sid": ["c" * 32, "d" * 32, "e" * 32]}):
            with self.subTest(extra=extra):
                self.setUp()
                for v in next(iter(extra.values())):
                    self.see(start=1000.0, **{next(iter(extra)): v})
                self.denied()
                for t in (1050.0, 1100.0, 1200.0):
                    self.see(start=t)
                    self.step(t + 1)
                self.assertEqual(self.f.bans, [])
                [guard] = [s for s in self.f.read("l7_enforce_skip") if s["reason"] == "cgnat_guard"]
                self.assertEqual((guard["level"], max(guard["ua_keys"], guard["sid_keys"])), (2, 3))
                self.assertEqual(len(self.arm.denies), 1)

    def test_a_key_of_an_address_that_turned_single_is_banned_when_it_is(self):
        for ua in ("Other/1", "Other/2"):
            self.see(ua=ua, start=400.0)                                 # both older than 10 min at 1051
        self.denied()
        self.see(start=1041.0)
        self.step(1051.0)
        self.assertEqual([(b["ip"], b["ua_keys"]) for b in self.f.bans], [(BOT, 1)])

    def test_an_unenforceable_key_reaches_level_2_only_if_its_address_is_single_key(self):
        ua = 'Bad "UA"'
        self.see(ua=ua, start=990.0)
        self.arm.submit(decision(ua=ua))
        self.step(1010.0)
        self.see(ua=ua, start=1040.0)
        self.step(1041.0)
        self.assertEqual([(b["ip"], b["denied"], b["after_s"]) for b in self.f.bans], [(BOT, False, 30.0)])

    def test_at_most_20_level_2_bans_a_minute_and_the_kill_switch_lifts_them(self):
        lifted = []
        self.arm.lift = lambda bans: lifted.extend(bans) or [ip for ip, _t in bans]
        ips = [f"10.0.20.{n}" for n in range(1, 26)]
        for ip in ips:
            self.see(ip=ip, start=990.0)
            self.arm.submit(decision(ip=ip))
        self.step(1010.0)
        for ip in ips:
            self.see(ip=ip, start=1040.0)
        self.step(1041.0)
        self.assertEqual(len(self.f.bans), A.MAX_LEVEL2_PER_MIN)
        [c] = self.f.read("l7_enforce_capped")
        self.assertEqual((c["what"], c["n"], c["arm"]), ("ban", 5, "R*"))
        self.arm.killed = lambda: True
        self.step(1042.0)
        self.assertEqual(sorted(ip for ip, _t in lifted), sorted(b["ip"] for b in self.f.bans))


class ValidityTest(RS.SelectionCase):
    def refused(self, needle, **over):
        path, sha = RS.write_selection(os.path.join(self.tmp.name, needle.split()[0] + str(len(over))), **over)
        with self.assertRaises(L.DetectorError) as cm:
            L.load(path, sha, L.RSTAR)
        self.assertIn(needle, str(cm.exception))

    def test_the_calibration_record_must_be_frozen_and_the_packages(self):
        for status in ("placeholder", "measured", None):
            with self.subTest(status=status):
                self.refused("frozen", calibration={"sha256": "c" * 64, "status": status})
        self.refused("calibration record or rule spec", calibration={"sha256": "d" * 64, "status": "frozen"})

    def test_the_rule_spec_must_be_this_trees(self):
        self.refused("another rule spec", spec_sha256="0" * 64)

    def test_the_arm_event_says_what_runs(self):
        det = self.detector()
        case = T.ArmCase("run")
        case.setUp()
        self.addCleanup(case.doCleanups)
        case.arm.denies = D.DenyMap(case.run_dir, key_level=True)
        case.arm.attach(l7_engine.build_engine(scorer=det))
        ev = case.f.read("l7_enforce_arm")[-1]
        self.assertEqual({k: ev[k] for k in ("armed", "arm", "arm_kind", "rule_arm", "level", "threshold", "consecutive",
                                             "valid_for_claims", "stat_threshold", "calibration_sha256")},
                         {"armed": True, "arm": "R*", "arm_kind": "rule", "rule_arm": "cost_budget", "level": "rule",
                          "threshold": 0.5, "consecutive": 3, "valid_for_claims": True,
                          "stat_threshold": {"key:cost_60": 300.0}, "calibration_sha256": "c" * 64})


class WouldBanTest(RS.SelectionCase):
    def test_the_engines_decision_names_the_statistic_that_passed(self):
        det = self.detector(point=(["key:cost_10"], [100.0], 2))
        eng = l7_engine.build_engine(scorer=det)
        events = []
        for t in (1000.0, 1001.0):
            eng.on_record(I.normalise(RS.obj(BOT, "/export", t)))
            events += eng.poll(t + 0.5)
        [ev] = events
        self.assertEqual((ev["statistic"], ev["stat_threshold"]), ({"key:cost_10": 320.0}, {"key:cost_10": 100.0}))
        self.assertGreater(ev["statistic"]["key:cost_10"], ev["stat_threshold"]["key:cost_10"])
        json.dumps(ev)                                                   # it goes to the event log as it is


class DaemonEndToEndTest(RS.SelectionCase):
    def test_a_costly_bot_is_denied_at_nginx_then_xdp_banned_through_the_real_ban_path(self):
        path, sha = RS.write_selection(os.path.join(self.tmp.name, "sel"), "cost_budget", (["key:cost_60"], [100.0], 2))
        d = H.Daemon({"L7_SHADOW": "1", "L7_ENFORCE": "1", "L7_NGINX_CONF": "/x/nginx.conf", "L7_ARM": L.RSTAR,
                      "L7_SELECTION": path, "L7_SELECTION_SHA256": sha})
        self.addCleanup(d.close)
        d.ns.update(l7_denymap=D, l7_enforce=A, l7_arms=L, l7_engine=l7_engine)
        d.ns["L7_ENFORCE_DIR"] = os.path.join(d._tmp.name, "l7v2")
        d.ns["L7_SOCKET_GROUP"] = os.getgid()
        d.clock.now = 999.0
        d.call("l7_enforce_init")
        ua = "Bot/2.0 (compatible; deep-linker)"
        records = [RS.obj(BOT, "/export", 1000.0 + 2 * n, ua=ua, sid=f"{n % 2 + 1:032x}") for n in range(50)]
        records += V2.browser(until=1100.0)                              # below the rule: never decided
        reader = V2.FakeReader(d, records, 1110.0, tick=lambda _t: d.call("l7_enforce_poll"))
        ingest = type("Ingest", (), {k: staticmethod(getattr(I, k)) if callable(getattr(I, k)) else getattr(I, k)
                                     for k in dir(I) if not k.startswith("__")})
        ingest.SyslogDatagramReader = staticmethod(lambda _path, **_kw: reader)
        d.ns["l7_ingest"] = ingest
        d.call("l7_shadow_monitor", "/run/ddos_l7.sock")
        [wb] = d.events("l7_would_ban")
        [deny] = d.events("l7_deny")
        [ban] = d.bans()
        log = d.events()
        self.assertLess(log.index(wb), log.index(deny))
        self.assertLess(log.index(deny), log.index(ban))
        self.assertEqual((wb["ip"], deny["rule_arm"], deny["users_seen"] >= 2), (BOT, "cost_budget", True))
        self.assertEqual((ban["engine"], ban["level"], ban["arm"], ban["rule_arm"], ban["ttl_s"]),
                         ("l7v2", 2, "R*", "cost_budget", 300))
        self.assertEqual((d.blacklist.ips(), d.banned_ips), ({BOT}, {BOT}))
        self.assertIn(["ss", "-K", "dst", BOT], d.proc.calls)
        self.assertIn(f"[BAN] {BOT} banned for 300s. Reason: L7 v2 arm R*", d.console())


if __name__ == "__main__":
    unittest.main()
