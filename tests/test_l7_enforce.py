"""The L7 v2 enforcing arm's decision policy (l7_enforce.Arm; docs/L7V2_DESIGN.md 9.1-9.2), on fakes: the reload,
the XDP ban and the connection kill are recorded callables, the clock is the `now` each step is given, the deny map is
a real file in a temporary directory. Offline: no nginx, no XDP."""
import json
import os
import sys
import tempfile
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)
import ban_events
import l7_denymap as D
import l7_enforce as A
import l7_ingest as I

BOT = "10.0.17.5"
POOL = "10.0.18.9"
SID = "b" * 32
UA = "Bot/2.0 (compatible, deep-linker)"
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) {x}"    # a brace: unenforceable at level 1 (9.4, D-038)


def obj(ip=BOT, ua=UA, sid=SID, start=1000.0, rt=0.01, uri="/page/1"):
    return {"msec": start + rt, "rt": rt, "ip": ip, "method": "GET", "uri": uri, "status": 200, "ua": ua,
            "ref": "", "sid": sid, "sid_set": ""}


def would_ban(ip=BOT, ua=UA, sid=SID, t=1010.0, p=0.99):
    return {"level": "view", "ip": ip, "ua_h": I.stable_hash32(ua), "sid_h": I.stable_hash32(sid) if sid else I.NO_SID,
            "p": p, "hits": 2, "n_views": 5, "ip_banned": False, "threshold": 0.9, "consecutive": 2, "t_poll": t}


def view_engine(arm_name="view_gru"):
    scorer = types.SimpleNamespace(cfg={"meta": {"arm": arm_name}}, sha256="ab" * 32)
    return types.SimpleNamespace(scorer=scorer, level="view", threshold=0.9, consecutive=2)


class Fakes:
    def __init__(self, tmp):
        self.reloads, self.reload_ok, self.bans, self.closed, self.banned_ips = [], True, [], [], set()
        self.now = 0.0
        self.events_path = os.path.join(tmp, "events.jsonl")
        self.events = ban_events.EventLog(self.events_path)

    def reload(self):
        self.reloads.append(self.now)
        if self.reload_ok:
            return True, ""
        return False, f'nginx exited 1: nginx: [emerg] conflicting parameter "{BOT}|{UA}|{SID}" in deny.map:2'

    def ban(self, ip, reason, engine, **detail):
        self.bans.append({"ip": ip, "reason": reason, "engine": engine, **detail})
        self.banned_ips.add(ip)
        return self.now

    def close(self, ip):
        self.closed.append(ip)

    def banned(self, ip):
        return ip in self.banned_ips

    def read(self, *kinds):
        return ban_events.read_events(self.events_path, kinds or None)


class ArmCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.f = Fakes(tmp.name)
        self.addCleanup(self.f.events.close)
        self.run_dir = os.path.join(tmp.name, "run")
        D.prepare_run_dir(self.run_dir)
        self.arm = A.Arm(D.DenyMap(self.run_dir), reload=self.f.reload, ban=self.f.ban, close=self.f.close,
                         banned=self.f.banned, events=self.f.events, allow=A.allowlist("10.0.40.0/24"))
        self.arm.attach(view_engine())

    def see(self, **kw):
        o = obj(**kw)
        self.arm.observe(o, I.normalise(o))

    def step(self, now):
        self.f.now = now
        self.arm.step(now)

    def map_lines(self):
        with open(os.path.join(self.run_dir, D.DENY_FILE), encoding="ascii") as fh:
            return fh.read().splitlines()


class Level1Test(ArmCase):
    def test_a_key_is_denied_once_it_is_20_s_old_and_the_map_is_reloaded_in_batches(self):
        self.see(start=1000.0)
        self.see(ip="10.0.17.6", start=1000.0)
        self.arm.submit(would_ban(t=1010.0))
        self.step(1010.0)                                              # 10 s old: the decision waits
        [wait] = self.f.read("l7_enforce_skip")
        self.assertEqual((wait["reason"], wait["key_age_s"], wait["until"]), ("key_age", 10.0, 1020.0))
        self.assertEqual((self.f.reloads, self.map_lines()), ([], []))
        self.step(1019.9)
        self.assertEqual(self.f.read("l7_deny"), [])
        self.step(1020.0)
        [deny] = self.f.read("l7_deny")
        self.assertEqual({k: deny[k] for k in ("ip", "level", "arm", "threshold", "consecutive", "p", "key_age_s",
                                               "shared", "active", "ttl_s")},
                         {"ip": BOT, "level": 1, "arm": "view_gru", "threshold": 0.9, "consecutive": 2, "p": 0.99,
                          "key_age_s": 20.0, "shared": False, "active": 1, "ttl_s": 300})
        self.assertEqual(self.f.reloads, [1020.0])
        self.assertEqual(self.map_lines(), [f'"{BOT}|{UA}|{SID}" 1;'])
        self.arm.submit(would_ban(ip="10.0.17.6", t=1025.0))
        self.step(1025.0)                                              # denied, but the last reload was 5 s ago
        self.assertEqual((self.f.reloads, len(self.map_lines())), ([1020.0], 1))
        self.step(1030.0)
        self.assertEqual((self.f.reloads, len(self.map_lines())), ([1020.0, 1030.0], 2))
        self.assertEqual([(r["ok"], r["entries"], r["changes"]) for r in self.f.read("l7_reload")],
                         [(True, 1, 1), (True, 2, 1)])

    def test_no_action_on_the_allowlist_a_key_already_denied_or_an_ip_already_banned(self):
        for ip in ("10.0.0.1", "127.0.0.1", "10.0.40.7", "10.0.17.9"):
            self.see(ip=ip, start=900.0)
        self.f.banned_ips.add("10.0.17.9")
        for ip in ("10.0.0.1", "127.0.0.1", "10.0.40.7", "10.0.17.9", "10.0.17.9"):
            self.arm.submit(would_ban(ip=ip))
        self.see(start=900.0)
        self.arm.submit(would_ban())
        self.arm.submit(would_ban())
        self.step(1000.0)
        self.assertEqual([s["reason"] for s in self.f.read("l7_enforce_skip")],
                         ["allowlist"] * 3 + ["ip_banned"] * 2 + ["already_denied"])
        self.assertEqual(len(self.map_lines()), 1)

    def test_an_unenforceable_key_is_a_miss_and_never_reaches_the_map(self):
        self.see(ua=BROWSER_UA, start=900.0)
        self.arm.submit(would_ban(ua=BROWSER_UA))
        self.step(1000.0)
        [miss] = self.f.read("l7_enforce_miss")
        self.assertEqual((miss["rule"], miss["level"], miss["ip"]), ("ua_forbidden_char", 1, BOT))
        self.assertEqual((self.map_lines(), self.f.reloads, self.f.read("l7_deny")), ([], [], []))
        self.assertEqual(self.arm.counts["missed"], 1)

    def test_a_failed_reload_is_reported_without_the_raw_key_and_retried_10_s_later(self):
        self.see(start=900.0)
        self.f.reload_ok = False
        self.arm.submit(would_ban())
        self.step(1000.0)
        self.step(1005.0)
        self.f.reload_ok = True
        self.step(1010.0)
        reloads = self.f.read("l7_reload")
        self.assertEqual([(r["ok"], r["entries"]) for r in reloads], [(False, 1), (True, 1)])
        self.assertNotIn(UA, reloads[0]["detail"])
        self.assertIn("conflicting parameter", reloads[0]["detail"])
        self.assertEqual(self.f.reloads, [1000.0, 1010.0])
        self.assertEqual([e.t_loaded for e in self.arm.denies], [1010.0])

    def test_a_deny_ends_after_its_ttl_and_the_map_is_rewritten(self):
        self.see(start=900.0)
        self.arm.submit(would_ban())
        self.step(1000.0)
        self.step(1300.0)
        self.assertEqual(self.f.read("l7_deny_end"), [])
        self.step(1300.5)
        [end] = self.f.read("l7_deny_end")
        self.assertEqual((end["reason"], end["denied"], end["effective"], end["age_s"]), ("ttl", True, True, 300.5))
        self.assertEqual((self.map_lines(), self.f.reloads), ([], [1000.0, 1300.5]))
        self.arm.submit(would_ban(t=1301.0))                            # the key may be denied again
        self.step(1301.0)
        self.assertEqual(len(self.f.read("l7_deny")), 2)

    def test_keys_that_differ_only_in_case_share_one_entry(self):
        self.see(start=900.0)
        self.see(ua=UA.upper(), start=900.0)
        self.arm.submit(would_ban())
        self.arm.submit(would_ban(ua=UA.upper()))
        self.step(1000.0)
        self.assertEqual([d["shared"] for d in self.f.read("l7_deny")], [False, True])
        self.assertEqual(len(self.map_lines()), 1)

    def test_nothing_is_done_without_a_view_model_or_under_gru_only(self):
        for engine, refuse, why in (
                (types.SimpleNamespace(scorer=None, level="view", threshold=0.95, consecutive=3), None,
                 "no model: the engine runs features-only"),
                (types.SimpleNamespace(scorer=types.SimpleNamespace(cfg={}, sha256="x"), threshold=0.9,
                                       consecutive=2), None,
                 "a request-level engine keys by (IP, UA); the deny map needs (IP, UA, sid) keys"),
                (view_engine(), "GRU_ONLY=1", "GRU_ONLY=1")):
            with self.subTest(why=why):
                self.arm.attach(engine, refuse=refuse)
                self.see(start=900.0)
                self.arm.submit(would_ban())
                self.step(1000.0)
                self.assertEqual(self.f.read("l7_enforce_skip")[-1]["why"], why)
                self.assertEqual(self.f.read("l7_enforce_arm")[-1]["armed"], False)
        self.assertEqual((self.map_lines(), self.f.bans), ([], []))

    def test_observe_counts_its_errors_and_never_raises(self):
        self.arm.observe({"ua": "x"}, {"ip": BOT})                       # no msec, no hashes
        self.arm.step(1000.0)
        [poll] = self.f.read("l7_enforce_poll")
        self.assertEqual(poll["observe_errors"], 1)
        self.assertTrue(poll["first_error"].startswith("KeyError"))


class Level2Test(ArmCase):
    def deny_bot(self, ua=UA):
        self.see(ua=ua, start=990.0)
        self.arm.submit(would_ban(ua=ua))
        self.step(1010.0)                                              # denied, reloaded: in effect from 1010

    def test_an_xdp_ban_only_after_30_s_of_sending_past_the_deny_for_a_single_key_ip(self):
        self.deny_bot()
        self.see(start=1039.9)                                         # 429s keep coming
        self.step(1040.0)
        self.assertEqual(self.f.bans, [])
        self.see(start=1040.0)
        self.step(1041.0)
        [ban] = self.f.bans
        self.assertEqual({k: ban[k] for k in ("ip", "engine", "level", "value", "p", "threshold", "consecutive",
                                              "arm", "ua_keys", "sid_keys", "after_s", "denied")},
                         {"ip": BOT, "engine": "l7v2", "level": 2, "value": 0.99, "p": 0.99, "threshold": 0.9,
                          "consecutive": 2, "arm": "view_gru", "ua_keys": 1, "sid_keys": 1, "after_s": 30.0,
                          "denied": True})
        self.assertEqual(ban_events.engine_from_reason(ban["reason"]), ban_events.L7V2_ENGINE)
        self.assertEqual(ban_events.ENGINE_LABELS[ban_events.L7V2_ENGINE], "L7 v2")
        self.assertEqual(self.f.closed, [BOT])
        self.see(start=1060.0)
        self.step(1061.0)
        self.assertEqual(len(self.f.bans), 1)                          # once

    def test_a_deny_that_never_took_effect_never_escalates(self):
        self.f.reload_ok = False
        self.deny_bot()
        self.see(start=1100.0)
        self.step(1101.0)
        self.assertEqual(self.f.bans, [])

    def test_the_cgnat_guard_an_ip_with_three_uas_or_three_sids_is_never_xdp_banned(self):
        for extra in ({"ua": ["Other/1", "Other/2"]}, {"sid": ["c" * 32, "d" * 32]}):
            with self.subTest(extra=extra):
                self.setUp()
                for v in next(iter(extra.values())):
                    self.see(start=1000.0, **{next(iter(extra)): v})
                self.deny_bot()
                for t in (1050.0, 1100.0, 1200.0):
                    self.see(start=t)
                    self.step(t + 1)
                self.assertEqual(self.f.bans, [])
                [guard] = [s for s in self.f.read("l7_enforce_skip") if s["reason"] == "cgnat_guard"]
                self.assertEqual((guard["level"], max(guard["ua_keys"], guard["sid_keys"])), (2, 3))

    def test_the_guard_counts_the_last_10_min_only(self):
        self.see(ua="Other/1", start=400.0)
        self.see(ua="Other/2", start=409.0)                            # both older than 10 min at 1010
        self.deny_bot()
        self.see(start=1041.0)
        self.step(1042.0)
        self.assertEqual([(b["ip"], b["ua_keys"]) for b in self.f.bans], [(BOT, 1)])

    def test_an_unenforceable_key_reaches_level_2_only_if_its_ip_is_single_key(self):
        self.deny_bot(ua=BROWSER_UA)                                   # a miss at 1010: no map line, no reload
        self.see(ua=BROWSER_UA, start=1039.0)
        self.step(1039.5)
        self.assertEqual(self.f.bans, [])
        self.see(ua=BROWSER_UA, start=1040.0)
        self.step(1041.0)
        self.assertEqual([(b["ip"], b["denied"], b["after_s"]) for b in self.f.bans], [(BOT, False, 30.0)])
        self.assertEqual(self.f.reloads, [])
        self.setUp()
        for n in range(3):
            self.see(ip=POOL, ua=BROWSER_UA, sid=f"{n:032x}", start=1000.0)
        self.see(ip=POOL, ua=BROWSER_UA, sid=SID, start=1000.0)
        self.arm.submit(would_ban(ip=POOL, ua=BROWSER_UA))
        self.step(1020.0)
        self.see(ip=POOL, ua=BROWSER_UA, start=1060.0)
        self.step(1061.0)
        self.assertEqual(self.f.bans, [])
        self.assertEqual(self.arm.counts["guarded"], 1)

    def test_an_unseen_ip_counts_as_shared(self):
        ips = A.IpKeys(max_ips=2)
        ips.note("10.0.0.5", 1, -1, 0.0)
        self.assertEqual(ips.counts("10.0.0.5", 1.0), (1, 0))
        ips.note("10.0.0.6", 1, -1, 0.0)
        ips.note("10.0.0.7", 1, -1, 0.0)
        self.assertIsNone(ips.counts("10.0.0.5", 1.0))                 # evicted: unknown, so never single-key


class IpKeysTest(unittest.TestCase):
    def test_keeping_the_three_most_recent_values_counts_exactly_below_three(self):
        import random
        rng = random.Random(7)
        for _ in range(300):
            ips = A.IpKeys(window=600.0)
            seen = {}
            for _n in range(rng.randrange(1, 12)):
                ua, t = rng.randrange(6), rng.uniform(0, 1200)
                ips.note("10.0.0.5", ua, -1, t)
                seen[ua] = max(seen.get(ua, t), t)
            now = rng.uniform(600, 1800)
            true = sum(1 for t in seen.values() if t >= now - 600)
            got = ips.counts("10.0.0.5", now)[0]
            self.assertEqual(got < 3, true < 3)
            self.assertEqual(got, min(true, 3))

    def test_requests_without_a_session_add_no_sid(self):
        ips = A.IpKeys()
        ips.note("10.0.0.5", 1, I.NO_SID, 0.0)
        ips.note("10.0.0.5", 2, I.NO_SID, 0.0)
        self.assertEqual(ips.counts("10.0.0.5", 0.0), (2, 0))


class NothingRawTest(ArmCase):
    def test_no_event_carries_a_raw_user_agent_or_session_id(self):
        self.see(start=900.0)
        self.see(ua=BROWSER_UA, ip="10.0.17.7", start=900.0)
        self.arm.submit(would_ban())
        self.arm.submit(would_ban(ua=BROWSER_UA, ip="10.0.17.7"))
        self.f.reload_ok = False
        self.step(1000.0)
        self.f.reload_ok = True
        self.see(start=1100.0)
        for t in (1010.0, 1101.0, 1400.0):
            self.step(t)
        with open(self.f.events_path, encoding="utf-8") as fh:
            text = fh.read()
        self.assertGreater(len(text.splitlines()), 6)
        for raw in (UA, BROWSER_UA, SID, json.dumps(UA)[1:-1]):
            self.assertNotIn(raw, text)


class CanonicalAddressTest(ArmCase):
    """T-042 E01: inet_aton, which the XDP ban path uses, reads these as 10.0.18.9; nginx never logs them."""

    SPELLINGS = ("10.0.4617", "012.0.18.9", "0xa.0.18.9", "10.0.18.9 ")

    def test_no_decision_on_an_address_that_is_not_canonical_dotted_quad(self):
        for n, ip in enumerate(self.SPELLINGS):
            for t in (900.0, 1000.0, 1050.0, 1100.0):
                self.see(ip=ip, start=t + n)
            self.arm.submit(would_ban(ip=ip))
        for t in (1000.0, 1060.0, 1120.0):
            self.step(t)
        skips = [(s["reason"], s["ip"]) for s in self.f.read("l7_enforce_skip")]
        self.assertEqual(skips, [("ip_format", ip) for ip in self.SPELLINGS])
        self.assertEqual((self.map_lines(), self.f.bans, self.f.read("l7_enforce_miss")), ([], [], []))
        self.assertEqual([ip for ip in self.SPELLINGS if self.arm.ips.counts(ip, 1120.0) is not None], [])

    def test_a_forged_spelling_cannot_ban_a_shared_and_allowlisted_address(self):
        # the review's probe: 10.0.18.9 is a CGNAT address (3 UAs) and allowlisted; records under '10.0.4617' keep
        # coming for minutes
        self.arm.allow = A.allowlist("10.0.18.9")
        for ua in ("A/1", "B/1", "C/1"):
            self.see(ip="10.0.18.9", ua=ua, start=990.0)
        for t in range(990, 1200, 5):
            self.see(ip="10.0.4617", start=float(t))
        self.arm.submit(would_ban(ip="10.0.4617"))
        for t in range(1010, 1200, 10):
            self.step(float(t))
        self.assertEqual((self.f.bans, self.map_lines()), ([], []))
        self.assertEqual(self.arm.ips.counts("10.0.18.9", 1100.0), (3, 1))

    def test_the_allowlist_fails_closed(self):
        nets = A.allowlist()
        for ip in self.SPELLINGS + ("", "::1", None, 7):
            self.assertTrue(A.allowed(ip, nets), ip)
        self.assertFalse(A.allowed("10.0.18.9", nets))
        self.assertTrue(A.allowed("10.0.0.1", nets))


if __name__ == "__main__":
    unittest.main()
