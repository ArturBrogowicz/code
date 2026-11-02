"""D-047: a deny that ends while its key keeps sending is renewed, for every arm alike (l7_enforce.Arm._renew; docs/L7V2_DESIGN.md,
As-built): a decision fires when a run reaches k and a denied key's 429s keep its run, so nothing else would decide it again. A
key that stopped sending lets its deny expire. The renewal needs no new would-ban and logs itself; the reload pacing, the caps
and the kill switch hold. Offline, on the fakes of tests/daemon_harness.py and tests/test_l7_enforce.py.
"""
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

import l7_arms as L
import l7_denymap as D
import l7_enforce as A
import l7_engine
import l7_ingest as I

BOT, UA, SID = T.BOT, T.UA, T.SID


class Alike:
    """The same cases for a view arm and for R*: `would_ban` and `line` are the arm's own."""

    def lines(self):
        with open(self.arm.denies.path, encoding="ascii") as fh:
            return fh.read().splitlines()

    def denied(self, **kw):
        """A key denied at 1010 (reload at 1010, so the TTL ends after 1310)."""
        self.see(start=990.0)
        self.arm.submit(self.would_ban(**kw))
        self.step(1010.0)
        self.assertEqual(self.lines(), [self.line])

    def send(self, t):
        """The key sends at t, on an address shared with two other UAs, so that the CGNAT guard keeps level 2 out."""
        self.see(start=t)
        for ua in ("Other/1", "Other/2"):
            self.see(ua=ua, start=t)

    def test_a_long_attack_on_a_shared_address_is_not_served_again(self):
        self.denied()
        for t, sent in ((1200.0, 1190.0), (1311.0, 1300.0), (1500.0, 1490.0), (1612.0, 1600.0), (1800.0, 1790.0),
                        (1913.0, 1900.0)):
            self.send(sent)
            self.step(t)
            self.assertEqual(self.lines(), [self.line], t)
        renewals = self.f.read("l7_deny_renew")
        self.assertEqual([(r["level"], r["why"], r["renewal"], r["denied"], r["arm"], r["ip"], r["ttl_s"]) for r in renewals],
                         [(1, "sending", n, True, self.arm_name, BOT, 300) for n in (1, 2, 3)])
        self.assertEqual(renewals[0]["last_request_s"], 11.0)
        self.assertEqual(self.f.read("l7_deny_end"), [])
        self.assertEqual(len(self.f.read("l7_deny")), 1)                 # one deny, no new decision
        self.assertEqual(self.arm.counts["would_bans"], 1)
        self.assertEqual(self.f.reloads, [1010.0])                       # no line changed, so no reload was due
        self.assertEqual((self.arm.counts["renewed"], self.f.bans), (3, []))

    def test_a_key_that_stopped_sending_lets_its_deny_expire(self):
        for name, last, expires in (("never after the deny", None, True), ("before the window", 1190.9, True),
                                    ("at the window's edge", 1191.0, False)):
            with self.subTest(name):
                self.setUp()
                self.denied()
                if last:
                    self.send(last)
                self.step(1311.0)
                self.assertEqual(self.lines() == [], expires)
                self.assertEqual([e["reason"] for e in self.f.read("l7_deny_end")], ["ttl"] if expires else [])
                self.assertEqual(len(self.f.read("l7_deny_renew")), 0 if expires else 1)

    def test_a_renewed_key_that_then_stops_expires_a_ttl_later(self):
        self.denied()
        self.send(1300.0)
        self.step(1311.0)                                                # renewed: its TTL now ends after 1611
        self.step(1611.0)
        self.assertEqual(self.lines(), [self.line])
        self.step(1611.5)
        self.assertEqual([e["reason"] for e in self.f.read("l7_deny_end")], ["ttl"])
        self.assertEqual(self.lines(), [])

    def test_the_kill_switch_ends_it_and_nothing_renews_it_afterwards(self):
        self.denied()
        self.arm.killed = lambda: True
        self.send(1305.0)
        self.step(1311.0)
        self.assertEqual((self.lines(), self.f.read("l7_deny_renew")), ([], []))
        self.arm.killed = lambda: False
        self.send(1320.0)
        for t in (1321.0, 1640.0, 1950.0):
            self.step(t)
        self.assertEqual((self.lines(), self.f.read("l7_deny_renew"), len(self.f.read("l7_deny"))), ([], [], 1))

    def test_the_cap_holds_a_renewal_adds_no_line_and_a_new_decision_is_still_capped(self):
        self.arm.denies.cap = 1
        self.denied()
        self.send(1305.0)
        self.see(ip="10.0.17.6", start=1000.0)
        self.arm.submit(self.would_ban(ip="10.0.17.6", t=1311.0))
        self.step(1311.0)
        self.assertEqual((self.lines(), len(self.arm.denies)), ([self.line], 1))
        self.assertEqual(len(self.f.read("l7_deny_renew")), 1)
        [capped] = self.f.read("l7_enforce_capped")
        self.assertEqual((capped["what"], capped["ip"]), ("deny", "10.0.17.6"))

    def test_the_reload_pacing_holds_beside_a_renewal(self):
        self.denied()
        self.see(ip="10.0.17.6", start=1000.0)
        self.arm.submit(self.would_ban(ip="10.0.17.6", t=1307.0))
        self.step(1307.0)                                                # a new line: reloaded at 1307
        self.send(1305.0)
        self.see(ip="10.0.17.7", start=1000.0)
        self.arm.submit(self.would_ban(ip="10.0.17.7", t=1311.0))
        self.step(1311.0)                                                # a renewal and a new line, 4 s after a reload
        self.assertEqual(len(self.f.read("l7_deny_renew")), 1)
        self.assertEqual(self.f.reloads, [1010.0, 1307.0])
        self.step(1317.0)
        self.assertEqual(self.f.reloads, [1010.0, 1307.0, 1317.0])

    def test_keys_that_share_a_line_keep_it_while_either_sends(self):
        self.see(start=990.0)
        self.see(ua=UA.upper(), start=990.0)
        self.arm.submit(self.would_ban())
        self.arm.submit(self.would_ban(ua=UA.upper()))
        self.step(1010.0)
        self.assertEqual([d["shared"] for d in self.f.read("l7_deny")], [False, True])
        self.send(1305.0)                                                # only one of the two keys still sends
        self.step(1311.0)
        self.assertEqual((self.lines(), self.f.read("l7_deny_end")), ([self.line], []))
        self.step(1612.0)                                                # now neither does
        self.assertEqual(self.lines(), [])
        self.assertEqual(len(self.f.read("l7_deny_end")), 2)

    def banned_at_1042(self):
        """The key denied at 1010 and, single-key and still sending at 1041, XDP-banned at 1042; the ban hides it."""
        self.denied()
        self.see(start=1041.0)
        self.step(1042.0)
        self.assertEqual([b["level"] for b in self.f.bans], [2])

    def test_an_xdp_banned_address_hides_its_key_so_its_deny_is_renewed(self):
        self.banned_at_1042()
        self.step(1311.0)
        self.assertEqual(self.lines(), [self.line])
        self.assertEqual([r["why"] for r in self.f.read("l7_deny_renew")], ["xdp_banned"])

    def test_when_the_ban_has_ended_level_2_applies_again_with_its_guards(self):
        self.banned_at_1042()
        self.step(1311.0)
        self.f.banned_ips.clear()                                        # the daemon's TTL sweep lifted it
        self.step(1343.0)                                                # the deny still answers: 30 s of sending first
        self.assertEqual(self.lines(), [self.line])
        self.see(start=1372.9)
        self.step(1373.0)
        self.assertEqual(len(self.f.bans), 1)
        self.see(start=1373.0)
        self.step(1374.0)
        self.assertEqual(len(self.f.bans), 2)
        self.assertNotIn("renewal", self.f.bans[0])
        self.assertEqual((self.f.bans[1]["renewal"], self.f.bans[1]["level"], self.f.bans[1]["arm"], self.f.bans[1]["after_s"]),
                         (1, 2, self.arm_name, 30.0))
        self.step(1612.0)                                                # under the second ban: renewed
        self.f.banned_ips.clear()
        self.step(1680.0)
        self.send(1711.0)                                                # now a shared address: the CGNAT guard holds
        self.step(1712.0)
        self.assertEqual(len(self.f.bans), 2)
        self.assertIn("cgnat_guard", [s["reason"] for s in self.f.read("l7_enforce_skip")])

    def test_the_level_2_rate_cap_holds_for_a_renewed_ban(self):
        self.banned_at_1042()
        self.step(1311.0)
        self.f.banned_ips.clear()
        self.step(1343.0)
        self.arm.level2_times = [1373.0] * A.MAX_LEVEL2_PER_MIN
        self.see(start=1374.0)
        self.step(1375.0)
        self.assertEqual(len(self.f.bans), 1)
        self.assertEqual([c["what"] for c in self.f.read("l7_enforce_capped")], ["ban"])

    def test_a_miss_is_tracked_through_its_ban_and_banned_again_when_it_keeps_sending(self):
        ua = 'Bad "UA"'
        self.see(ua=ua, start=990.0)
        self.arm.submit(self.would_ban(ua=ua))
        self.step(1010.0)
        self.assertEqual(self.lines(), [])
        self.see(ua=ua, start=1040.0)
        self.step(1041.0)
        self.assertEqual(len(self.f.bans), 1)
        self.step(1311.0)                                                # the ban still holds: tracked on
        self.assertEqual([(r["why"], r["denied"]) for r in self.f.read("l7_deny_renew")], [("xdp_banned", False)])
        self.f.banned_ips.clear()
        self.step(1342.0)
        self.see(ua=ua, start=1372.0)
        self.step(1373.0)
        self.assertEqual([b.get("renewal") for b in self.f.bans], [None, 1])


class ViewArmTest(Alike, T.ArmCase):
    arm_name = "view_gru"
    line = f'"{BOT}|{UA}|{SID}" 1;'

    def would_ban(self, **kw):
        return T.would_ban(**kw)

    def test_a_sid_less_line_on_an_address_that_turned_shared_is_withdrawn_all_the_same(self):
        self.see(sid="", start=990.0)
        self.arm.submit(T.would_ban(sid=""))
        self.step(1010.0)
        self.assertEqual(self.lines(), [f'"{BOT}|{UA}|" 1;'])
        for sid in ("c" * 32, "d" * 32, "e" * 32):
            self.see(ua="Other/1", sid=sid, start=1300.0)
        self.see(sid="", start=1305.0)
        self.step(1311.0)
        self.assertEqual(self.lines(), [])
        self.assertEqual([e["reason"] for e in self.f.read("l7_deny_end")], ["cgnat_guard"])


class RStarArmTest(Alike, RS.Section9Case):
    arm_name = "R*"
    line = f'"{BOT}|{UA}" 1;'

    def would_ban(self, ip=BOT, ua=UA, t=1010.0):
        return RS.rule_would_ban(ip, ua, t)

    def test_any_session_of_the_key_counts_as_it_sending(self):
        self.denied()
        self.see(sid="d" * 32, start=1305.0)
        self.step(1311.0)
        self.assertEqual(self.lines(), [self.line])
        [r] = self.f.read("l7_deny_renew")
        self.assertEqual((r["arm"], r["rule_arm"], r["users_seen"], r["sid_h"]), ("R*", "cost_budget", 2, None))


class RealEngineTest(RS.SelectionCase):
    def test_r_star_keeps_one_decision_and_one_deny_through_a_long_attack(self):
        det = self.detector(point=(["key:cost_60"], [100.0], 2))
        eng = l7_engine.build_engine(scorer=det)
        case = RS.Section9Case("run")
        case.setUp()
        self.addCleanup(case.doCleanups)
        case.arm.attach(eng)
        t = 1000.0
        for n in range(1000):
            o = RS.obj(BOT, "/export", t + n, ua=UA)
            case.arm.observe(o, I.normalise(o))
            eng.on_record(I.normalise(o))
            for ev in eng.poll(t + n + 0.5):
                ev.pop("kind")
                case.arm.submit(ev)
            case.step(t + n + 0.6)
        self.assertEqual(eng.totals["would_bans"], 1)                    # the run never broke
        self.assertEqual(len(case.f.read("l7_deny")), 1)
        self.assertEqual(case.f.read("l7_deny_end"), [])
        self.assertEqual(len(case.f.read("l7_deny_renew")), 3)           # after 300, 600 and 900 s

    def test_the_daemon_keeps_the_deny_and_bans_again_after_its_ttl_sweep(self):
        path, sha = RS.write_selection(os.path.join(self.tmp.name, "sel"), "cost_budget", (["key:cost_60"], [100.0], 2))
        d = H.Daemon({"L7_SHADOW": "1", "L7_ENFORCE": "1", "L7_NGINX_CONF": "/x/nginx.conf", "L7_ARM": L.RSTAR,
                      "L7_SELECTION": path, "L7_SELECTION_SHA256": sha})
        self.addCleanup(d.close)
        d.ns.update(l7_denymap=D, l7_enforce=A, l7_arms=L, l7_engine=l7_engine)
        d.ns["L7_ENFORCE_DIR"] = os.path.join(d._tmp.name, "l7v2")
        d.ns["L7_SOCKET_GROUP"] = os.getgid()
        d.clock.now = 999.0
        d.call("l7_enforce_init")

        def tick(_t):
            d.call("unblock_expired_bans")                               # the telemetry thread's TTL sweep
            d.call("l7_enforce_poll")
        ua = "Bot/2.0 (compatible; deep-linker)"
        # the XDP ban drops its packets: the log shows the bot only while its address is not banned
        records = [RS.obj(BOT, "/export", 1000.0 + 2 * n, ua=ua, sid=RS.SIDS[0]) for n in range(28)]
        records += [RS.obj(BOT, "/export", 1360.0 + 2 * n, ua=ua, sid=RS.SIDS[0]) for n in range(30)]
        reader = V2.FakeReader(d, records, 1420.0, tick=tick)
        ingest = type("Ingest", (), {k: staticmethod(getattr(I, k)) if callable(getattr(I, k)) else getattr(I, k)
                                     for k in dir(I) if not k.startswith("__")})
        ingest.SyslogDatagramReader = staticmethod(lambda _path, **_kw: reader)
        d.ns["l7_ingest"] = ingest
        d.call("l7_shadow_monitor", "/run/ddos_l7.sock")
        self.assertEqual(len(d.events("l7_would_ban")), 1)
        self.assertEqual(len(d.events("l7_deny")), 1)
        self.assertEqual(d.events("l7_deny_end"), [])
        self.assertEqual([r["why"] for r in d.events("l7_deny_renew")], ["xdp_banned"])
        self.assertEqual([(b["engine"], b["level"], b.get("renewal")) for b in d.bans()],
                         [("l7v2", 2, None), ("l7v2", 2, 1)])
        self.assertEqual([u["ip"] for u in d.events("unban")], [BOT])
        with open(os.path.join(d.L7_ENFORCE_DIR, D.KEY_DENY_FILE), encoding="ascii") as fh:
            self.assertEqual(fh.read(), f'"{BOT}|{ua}" 1;\n')
        self.assertEqual((d.blacklist.ips(), d.banned_ips), ({BOT}, {BOT}))


if __name__ == "__main__":
    unittest.main()
