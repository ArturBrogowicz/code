"""R*'s live path (l7_rule_engine.py, l7_arms.RuleDetector, l7_enforce at the rule level; docs/L7V2_DESIGN.md 9.5, 10, 19):
every record into the replay's RuleStats, rows at each poll, then section 9 unchanged. ml/l7v2_replay.RulePath is the
reference: on generated streams, and on a recording the daemon's own shadow thread wrote, the live path decides the same
keys at the same polls. Offline: fakes only (tests/daemon_harness.py), no nginx and no XDP.
"""
import hashlib
import json
import os
import random
import sys
import tempfile
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "ml"))
import daemon_harness as H
import l7v2_replay as RP
import l7v2_rules as R
import test_daemon_l7_shadow_v2 as V2
import test_l7_enforce as T

import l7_arms as L
import l7_denymap
import l7_enforce
import l7_engine
import l7_ingest as I
import l7_rule_engine as E

COSTS = {"C0": 0.5, "C1": 8.0, "C2": 4.0, "C3": 40.0, "C5": 160.0}
CAL = {"sha256": "c" * 64, "status": "frozen"}
BOT, BROWSER, POOL = "10.0.17.5", "10.0.16.5", "10.0.18.9"
BOT_UA = "Bot/2.0 (compatible; deep-linker)"
SIDS = [f"{n:032x}" for n in range(1, 8)]
POINTS = {"cost_budget": (["key:cost_60"], [300.0], 3),
          "sustained_rate": (["key:rate_10"], [1.5], 2),
          "token_bucket": (["key:bucket_1"], [12.0], 1),
          "multiscale_rate": (["key:rate_1", "key:rate_10", "key:rate_60", "key:rate_300"], [6.0, 2.0, 1.5, 1.2], 2)}


def package(arm, columns, thresholds, k, calibration=CAL):
    op = {"params": {"arm": arm}, "columns": columns, "thresholds": thresholds, "threshold": 0.5, "consecutive": k}
    return R.make_package(arm, op, COSTS, calibration), op


def write_selection(d, arm="cost_budget", point=None, **over):
    """A frozen rule selection in `d`, as ml/l7v2_rules.select writes one: (path, sha256)."""
    cfg, op = package(arm, *(point or POINTS[arm]))
    os.makedirs(os.path.join(d, "rules"), exist_ok=True)
    rel = f"rules/{arm}.json"
    R.save_package(os.path.join(d, rel), cfg)
    with open(os.path.join(d, rel), "rb") as fh:
        art = hashlib.sha256(fh.read()).hexdigest()
    sel = {"format": R.SELECTION_FORMAT, "source": "test", "valid_for_claims": True, "spec_sha256": R.spec_sha256(),
           "calibration": CAL, "r_star": arm,
           "arms": {arm: {"artifact": rel, "artifact_sha256": art, "operating_point": {**op, "recall": 0.5}},
                    "population": {"operating_point": None}, "default_rules": {"fixed": {"recall": 0.1}}}}
    sel.update(over)
    path = os.path.join(d, "rules_selection.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(sel, fh)
    with open(path, "rb") as fh:
        return path, hashlib.sha256(fh.read()).hexdigest()


def obj(ip, uri, start, ua=BOT_UA, sid="", rt=0.02, status=200):
    return {"msec": round(start + rt, 3), "ip": ip, "method": "GET", "uri": uri, "status": status, "rt": rt, "ua": ua,
            "ref": "", "sid": sid, "sid_set": ""}


def stream(seed, duration=240, flood=(100, 118)):
    """A stream of recorded items [("record", obj), ("poll", t, suppressing, banned)]: costly bots, browsers, a pool with
    many sessions under one UA, a key that pauses, records that arrive out of completion order, ticks at an arbitrary
    phase, a flood in the middle, and records no canonical address or field type would produce."""
    rng = random.Random(seed)
    t0, recs = 1000.0, []
    for i in range(5):                                                 # costly bots, some of them keep to a low rate
        gap = rng.choice((1.0, 2.5, 6.0))
        for n in range(int(duration / gap)):
            s = t0 + n * gap + rng.random()
            recs.append((s, obj(f"10.0.17.{i + 1}", rng.choice(("/search?q=alpha", "/export", "/page/9")), s, rt=rng.choice((0.02, 0.4)))))
    for i in range(6):                                                 # browsers: bursts of assets, long dwells
        s = t0 + rng.random() * 30
        sid = rng.choice(SIDS)
        while s < t0 + duration:
            recs.append((s, obj(f"10.0.16.{i + 1}", f"/page/{rng.randrange(40)}", s, ua="Mozilla/5.0 (X11; Linux)", sid=sid)))
            for a in range(rng.randrange(4, 30)):
                recs.append((s + 0.01 * a, obj(f"10.0.16.{i + 1}", f"/static/site6/a{a}.png", s + 0.01 * a,
                                               ua="Mozilla/5.0 (X11; Linux)", sid=sid)))
            s += rng.expovariate(1 / 7.0)
    for n in range(int(duration)):                                     # a shared address: one UA, many sessions
        s = t0 + n + rng.random()
        recs.append((s, obj(POOL, "/search?q=beta" if n % 3 == 0 else "/page/3", s, ua="Pool/1", sid=rng.choice(SIDS))))
    for n in range(int(duration / 4)):
        s = t0 + 4 * n
        recs.append((s, obj("10.0.4617", "/export", s, ua="Forged/1")))
        recs.append((s + 0.1, {**obj(BOT, "/export", s), "ua": 7}))
    recs.sort(key=lambda r: r[0] + rng.random() * 0.05)                # arrival order is not completion order
    items, nxt, phase = [], t0 + 1.0 + rng.random(), rng.random() * 0.2
    for arrival, o in recs:
        while nxt <= arrival:
            items.append(("poll", nxt, flood[0] <= nxt - t0 < flood[1], ()))
            nxt += 1.0 + rng.random() * phase
        items.append(("record", o))
    items.append(("poll", nxt, False, ()))
    return items


def live_decisions(items, det):
    """{key: t_poll of its first would-ban} and the engine's totals, driven as the shadow thread drives it."""
    eng = l7_engine.build_engine(scorer=det)
    first = {}
    for it in items:
        if it[0] == "poll":
            for ev in eng.poll(it[1], it[2], it[3]):
                first.setdefault((ev["ip"], ev["ua_h"]), ev["t_poll"])
        else:
            rec = I.normalise(it[1])
            if rec is not None:
                eng.on_record(rec)
    return first, eng


class SelectionCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def detector(self, arm="cost_budget", point=None, sub="sel"):
        d = os.path.join(self.tmp.name, sub, arm)
        path, sha = write_selection(d, arm, point)
        return L.load(path, sha, L.RSTAR)


class ParityTest(SelectionCase):
    """The reference: ml/l7v2_replay.RulePath. Its code is not touched; the live path must agree with it."""

    def test_the_live_path_decides_the_replays_keys_at_the_same_polls(self):
        decided_somewhere = set()
        for arm in POINTS:
            det = self.detector(arm)
            for seed in (1, 2, 3):
                with self.subTest(arm=arm, seed=seed):
                    items = stream(seed)
                    want, counts = RP.RulePath(det.rule).run(items)
                    got, eng = live_decisions(items, det)
                    self.assertEqual(got, want)
                    self.assertEqual(eng.totals["windows"], counts["rows"])
                    self.assertEqual((eng.totals["polls"], eng.rule_stats.late), (counts["polls"], counts["late"]))
                    self.assertEqual(eng.evicted, 0)
                    decided_somewhere |= {arm} if want else set()
        self.assertEqual(decided_somewhere, set(POINTS))               # the comparison is not vacuous at any rule

    def test_a_flood_clears_the_runs_and_decides_nothing_in_both(self):
        det = self.detector()
        quiet = stream(5, flood=(0, 0))
        flood = stream(5, flood=(0, 240))                              # suppressing from the first poll to the last
        self.assertTrue(RP.RulePath(det.rule).run(quiet)[0])
        self.assertEqual(live_decisions(flood[:-1], det)[0], {})
        self.assertEqual(RP.RulePath(det.rule).run(flood[:-1])[0], {})

    def test_k_consecutive_rows_a_row_below_the_threshold_resets_the_run(self):
        det = self.detector(point=(["key:cost_10"], [100.0], 3))
        eng = l7_engine.build_engine(scorer=det)
        fired = []

        def second(t, uri):                                            # one request, then the poll of that second
            eng.on_record(I.normalise(obj(BOT, uri, t)))
            fired.extend((e["t_poll"], e["hits"], e["threshold"], e["consecutive"], e["level"])
                         for e in eng.poll(t + 0.5))
        for t, uri in ((1000.0, "/export"), (1001.0, "/export"), (1002.0, "/page/1"), (1020.0, "/page/1"),
                       (1021.0, "/export"), (1022.0, "/page/1"), (1023.0, "/page/1"), (1024.0, "/page/1")):
            second(t, uri)
        # over 100 ms in 10 s at 1000, 1001, 1002 (160 + 160 + 8): the third row in a run decides
        self.assertEqual(fired, [(1002.5, 3, 0.5, 3, "rule"), (1023.5, 3, 0.5, 3, "rule")])
        self.assertEqual(eng.hits[(BOT, I.stable_hash32(BOT_UA))], 4)

    def test_the_daemons_own_shadow_thread_and_its_recording_agree_with_the_replay(self):
        path, sha = write_selection(os.path.join(self.tmp.name, "daemon"), "cost_budget")
        record = os.path.join(self.tmp.name, "l7_record.jsonl")
        d = H.Daemon({"L7_SHADOW": "1", "L7_ENFORCE": "1", "L7_NGINX_CONF": "/x/nginx.conf", "L7_ARM": L.RSTAR,
                      "L7_SELECTION": path, "L7_SELECTION_SHA256": sha, "L7_RECORD": record})
        self.addCleanup(d.close)
        d.ns.update(l7_denymap=l7_denymap, l7_enforce=l7_enforce, l7_arms=L, l7_engine=l7_engine)
        d.ns["L7_ENFORCE_DIR"] = os.path.join(d._tmp.name, "l7v2")
        d.ns["L7_SOCKET_GROUP"] = os.getgid()
        d.clock.now = 999.0
        d.call("l7_enforce_init")
        records = [o for it in stream(7) if it[0] == "record" for o in [it[1]] if isinstance(o.get("ua"), str)]
        records += V2.browser(until=1200.0)
        reader = V2.FakeReader(d, records, 1260.0, tick=lambda _t: d.call("l7_enforce_poll"))
        ingest = types.SimpleNamespace(**{k: getattr(I, k) for k in dir(I) if not k.startswith("__")})
        ingest.SyslogDatagramReader = lambda _path, **_kw: reader
        d.ns["l7_ingest"] = ingest
        d.call("l7_shadow_monitor", "/run/ddos_l7.sock")
        want, counts = RP.RulePath(d.l7_detector.rule).run(RP.read_items(record))
        logged = {}
        for ev in d.events("l7_would_ban"):
            logged.setdefault((ev["ip"], ev["ua_h"]), round(ev["t_poll"], 6))
        self.assertTrue(want)
        self.assertEqual(logged, want)
        self.assertEqual({e["level"] for e in d.events("l7_would_ban")}, {"rule"})
        self.assertGreater(counts["polls"], 200)
        [armed] = d.events("l7_enforce_arm")
        self.assertEqual((armed["armed"], armed["arm"], armed["arm_kind"], armed["level"], armed["rule"],
                          armed["consecutive"]), (True, "R*", "rule", "rule", "cost_budget", 3))
        self.assertEqual(d.events("daemon_error"), [])
        reports = d.events("l7_shadow")
        self.assertEqual({"active_keys", "distinct_ips", "late", "evicted"} - set(reports[-1]), set())


class BoundsTest(SelectionCase):
    def test_a_client_rotating_user_agents_cannot_grow_the_path_without_bound(self):
        det = self.detector()
        eng = E.L7RuleEngine(det, max_keys=50, max_ips=20)
        for n in range(500):
            eng.on_record(I.normalise(obj(f"10.1.{n % 200}.1", "/page/1", 1000.0 + n * 0.01, ua=f"Rot/{n}")))
            if n % 50 == 0:
                eng.poll(1000.0 + n * 0.01)
        eng.poll(1006.0)
        self.assertLessEqual(len(eng.rule_stats._key), 50)
        self.assertLessEqual(len(eng.rule_stats._ip), 20)
        self.assertEqual(eng.stats()["active_keys"], 50)
        self.assertGreater(eng.stats()["evicted"], 0)
        self.assertEqual(E.MAX_KEYS, 65536)

    def test_the_module_cannot_reach_the_ban_path(self):
        import ast
        with open(os.path.join(REPO, "l7_rule_engine.py"), encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | \
            {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        self.assertEqual(used & {"ban_ip", "block_ip_in_xdp", "blacklist_map", "kill_zombie_connections", "iptables"},
                         set())


class SelectionTest(SelectionCase):
    def refused(self, path, sha, arm, needle):
        with self.assertRaises(L.DetectorError) as cm:
            L.load(path, sha, arm)
        self.assertIn(needle, str(cm.exception))

    def test_r_star_loads_with_its_own_point(self):
        det = self.detector()
        self.assertEqual((det.level, det.kind, det.arm, det.rule_name, det.threshold, det.consecutive),
                         ("rule", "rule", "R*", "cost_budget", 0.5, 3))
        self.assertIsInstance(l7_engine.build_engine(scorer=det), E.L7RuleEngine)

    def test_only_r_star_and_only_from_an_intact_selection(self):
        d = os.path.join(self.tmp.name, "a")
        path, sha = write_selection(d)
        self.refused(path, sha, "cost_budget", "R* only")
        self.refused(path, sha, "population", "R* only")
        self.refused(path, "0" * 64, L.RSTAR, "not the recorded")
        for name, over, needle in (("none", {"r_star": None}, "no R*"),
                                   ("smoke", {"valid_for_claims": False}, "valid_for_claims"),
                                   ("format", {"format": "l7v2-rule-selection/2"}, "is not a")):
            with self.subTest(name):
                p, s = write_selection(os.path.join(self.tmp.name, name), **over)
                self.refused(p, s, L.RSTAR, needle)

    def test_an_altered_package_or_one_that_is_not_the_selections_point(self):
        d = os.path.join(self.tmp.name, "b")
        path, sha = write_selection(d)
        with open(path, encoding="utf-8") as fh:
            sel = json.load(fh)
        art = os.path.join(d, sel["arms"]["cost_budget"]["artifact"])
        with open(art, "r+", encoding="utf-8") as fh:
            cfg = json.load(fh)
        cfg["thresholds"] = [1.0]
        with open(art, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh)
        self.refused(path, sha, L.RSTAR, "altered")
        d = os.path.join(self.tmp.name, "c")
        path, _sha = write_selection(d)
        with open(path, encoding="utf-8") as fh:
            sel = json.load(fh)
        sel["arms"]["cost_budget"]["operating_point"]["consecutive"] = 5
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(sel, fh)
        with open(path, "rb") as fh:
            self.refused(path, hashlib.sha256(fh.read()).hexdigest(), L.RSTAR, "not the selection's")

    def test_a_refused_selection_stops_the_daemon(self):
        path, sha = write_selection(os.path.join(self.tmp.name, "smoke"), valid_for_claims=False)
        d = H.Daemon({"L7_SHADOW": "1", "L7_ENFORCE": "1", "L7_NGINX_CONF": "/x/nginx.conf", "L7_ARM": L.RSTAR,
                      "L7_SELECTION": path, "L7_SELECTION_SHA256": sha})
        self.addCleanup(d.close)
        d.ns.update(l7_denymap=l7_denymap, l7_enforce=l7_enforce, l7_arms=L)
        d.ns["L7_ENFORCE_DIR"] = os.path.join(d._tmp.name, "l7v2")
        d.ns["L7_SOCKET_GROUP"] = os.getgid()
        with self.assertRaises(SystemExit):
            d.call("l7_enforce_init")
        self.assertIn("valid_for_claims", d.events("daemon_error")[0]["error"])


class RuleEngineFake:
    """What Arm.attach reads of R*'s engine."""

    level = "rule"
    threshold, consecutive = 0.5, 3
    scorer = types.SimpleNamespace(arm="R*", kind="rule", rule_name="cost_budget", sha256="ab" * 32, selection_sha256="cd" * 32,
                                   valid_for_claims=True, cfg={"meta": {"arm": "R*"}})


def rule_would_ban(ip=BOT, ua=T.UA, t=1010.0):
    return {"level": "rule", "ip": ip, "ua_h": I.stable_hash32(ua), "p": 1.0, "hits": 3, "t_row": t - 0.5,
            "ip_banned": False, "threshold": 0.5, "consecutive": 3, "t_poll": t}


class Section9Case(T.ArmCase):
    """The arm on R*'s (IP, UA) keys."""

    def setUp(self):
        super().setUp()
        self.arm.attach(RuleEngineFake())


class Section9Test(Section9Case):
    def test_the_20_s_key_age_gate_counts_from_the_first_request_of_any_session(self):
        self.see(ip=BOT, sid="a" * 32, start=1000.0)
        self.see(ip=BOT, sid="b" * 32, start=1015.0)                     # a later session of the same (IP, UA) key
        self.arm.submit(rule_would_ban())
        self.step(1010.0)
        [wait] = self.f.read("l7_enforce_skip")
        self.assertEqual((wait["reason"], wait["key_age_s"], wait["until"], wait["sid_h"]), ("key_age", 10.0, 1020.0, None))
        self.step(1019.9)
        self.assertEqual(self.arm.tracked, {})
        self.step(1020.0)
        self.assertEqual(list(self.arm.tracked), [(BOT, I.stable_hash32(T.UA))])

    def test_no_action_on_the_allowlist_a_non_canonical_address_or_a_banned_one(self):
        for ip in ("10.0.0.1", "127.0.0.1", "10.0.40.7", "10.0.4617", "012.0.18.9", "0xa.0.18.9", "10.0.18.9 ", "10.0.17.9"):
            self.see(ip=ip, start=900.0)
            self.arm.submit(rule_would_ban(ip=ip))
        self.f.banned_ips.add("10.0.17.9")
        self.step(1000.0)
        self.assertEqual([s["reason"] for s in self.f.read("l7_enforce_skip")],
                         ["allowlist"] * 3 + ["ip_format"] * 4 + ["ip_banned"])
        self.assertEqual((self.arm.tracked, self.map_lines()), ({}, []))
        self.assertIsNone(self.arm.ips.counts("10.0.4617", 1000.0))

    def test_a_key_already_acted_on_is_not_acted_on_twice_and_the_kill_switch_stops_decisions(self):
        self.see(start=900.0)
        self.arm.submit(rule_would_ban())
        self.arm.submit(rule_would_ban())
        self.step(1000.0)
        self.assertEqual(self.f.read("l7_enforce_skip")[-1]["reason"], "already_denied")
        self.arm.killed = lambda: True
        self.see(ip="10.0.17.6", start=900.0)
        self.arm.submit(rule_would_ban(ip="10.0.17.6"))
        self.step(1001.0)
        self.assertEqual(self.f.read("l7_enforce_skip")[-1]["reason"], "killed")

    def test_a_view_arm_keeps_its_three_part_keys(self):
        self.arm.attach(T.view_engine())
        self.see(start=900.0)
        self.arm.submit(T.would_ban())
        self.step(1000.0)
        self.assertEqual(self.map_lines(), [f'"{T.BOT}|{T.UA}|{T.SID}" 1;'])
        self.assertEqual(self.f.read("l7_deny")[0]["sid_h"], I.stable_hash32(T.SID))


if __name__ == "__main__":
    unittest.main()
