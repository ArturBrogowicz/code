"""R*'s level-1 deny (l7_denymap.DenyMap(key_level=True), l7_conf.protected(key_map=True), l7_enforce at the rule level;
docs/L7V2_DESIGN.md 9.2, 9.4, 19): a second map on "$remote_addr|$http_user_agent" that covers every session of an (IP, UA)
key, with the same write rules, reload pacing, TTL and caps; the kill switch and stop() empty it too. Offline: nginx is
a port of its tokenizer and of its map's lookup, the reload is a recorded callable, and no conf is tested by nginx.
"""
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "bench"))
sys.path.insert(0, os.path.join(REPO, "ml"))
import daemon_harness as H
import test_daemon_l7_shadow_v2 as V2
import test_l7_conf as CT
import test_l7_denymap as DT
import test_l7_enforce as T
import test_l7_rstar as RS

import l7_arms as L
import l7_conf as C
import l7_denymap as D
import l7_enforce
import l7_engine
import l7_ingest as I

RUN = "/var/tmp/ddos_campaigns/p1/b01_M_rstar/l7v2"
BOT, UA, SID = T.BOT, T.UA, T.SID


def lookup(text, source):
    """nginx's answer for this source value on a map file's text: its parsed keys lower-cased (ngx_hash_add_key), the
    source lower-cased (ngx_http_map_find), an exact match; "0" (the default) otherwise."""
    keys = {k.lower(): v for k, v in DT.nginx_directives(text)}
    return keys.get(source.lower(), "0")


class WriterCase(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = os.path.join(self.tmp.name, "run")
        D.prepare_run_dir(self.dir, key_level=True)
        self.dm = D.DenyMap(self.dir, key_level=True)

    def read(self, name=D.KEY_DENY_FILE):
        with open(os.path.join(self.dir, name), encoding="ascii") as fh:
            return fh.read()


class KeyMapWriterTest(WriterCase):
    def test_the_same_write_rules_and_one_key_line_per_entry(self):
        written = []
        for n, ua in enumerate(list(DT.HOSTILE) + list(DT.TRICKY_BUT_WRITABLE) + list(DT.SEMICOLONS_WRITABLE)
                               + list(DT.SEMICOLONS_REFUSED)):
            ip = f"10.0.{2 + n // 200}.{n % 200 + 1}"
            status, detail = self.dm.add(ip, ua, "ignored", 1000.0)     # a sid has no place in this map
            rule = DT.HOSTILE.get(ua) or DT.SEMICOLONS_REFUSED.get(ua) if isinstance(ua, (str, int)) else None
            if rule:
                self.assertEqual((status, detail), ("refused", rule), ua)
            else:
                self.assertEqual(status, "added", ua)
                written.append(f"{ip}|{ua}")
        self.dm.write()
        text = self.read()
        self.assertEqual(self.read(D.DENY_FILE), "")                    # the session-level map is not touched
        lines = text.splitlines(keepends=True)
        self.assertEqual(len(lines), len(written))
        for ln in lines:
            self.assertTrue(ln.endswith(" 1;\n"))
            self.assertRegex(ln[:-1], f"^{D.KEY_LINE_RE.pattern}$")
        parsed = DT.nginx_directives(text)
        self.assertEqual(sorted(parsed), sorted([k, "1"] for k in written))
        self.assertTrue(all(k[0].isdigit() for k, _v in parsed))        # never a ~ regex, never a special word

    def test_non_canonical_addresses_are_refused_and_keys_differing_in_case_share_a_line(self):
        for ip in ("10.0.4617", "012.0.18.9", "0xa.0.18.9", "10.0.18.9 ", "::1"):
            self.assertEqual(self.dm.add(ip, "a", "", 1.0), ("refused", "ip_format"))
        status, first = self.dm.add(BOT, "Bot/1.0", "", 1.0)
        self.assertEqual((status, self.dm.add(BOT, "bot/1.0", "", 2.0)), ("added", ("present", first)))
        self.assertEqual(first.key, f"{BOT}|Bot/1.0")

    def test_the_cap_the_ttl_and_the_atomic_write_are_the_same(self):
        for n in range(D.MAX_DENIES):
            self.assertEqual(self.dm.add(f"10.1.{n // 250}.{n % 250 + 1}", "ua", "", 1000.0)[0], "added")
        self.assertEqual(self.dm.add("10.9.9.9", "ua", "", 1000.0), ("capped", None))
        self.dm.write()
        self.assertEqual(len(DT.nginx_directives(self.read())), D.MAX_DENIES)
        self.assertEqual(self.dm.expire(1300.0), [])
        self.assertEqual(len(self.dm.expire(1300.5)), D.MAX_DENIES)
        self.dm.write()
        self.assertEqual(self.read(), "")
        self.assertEqual(sorted(os.listdir(self.dir)), sorted(D.MAP_FILES))     # no temporary file left

    def test_the_run_directory_has_the_second_map_only_when_asked(self):
        other = os.path.join(self.tmp.name, "view")
        D.prepare_run_dir(other)
        self.assertEqual(os.listdir(other), [D.DENY_FILE])
        self.assertEqual(sorted(os.listdir(self.dir)), sorted(D.MAP_FILES))


class CoverageTest(WriterCase):
    """What the two maps deny, read the way nginx reads them."""

    def test_a_line_covers_every_session_of_its_key_and_nothing_else(self):
        self.dm.add(BOT, "Mozilla/5.0 (X11; Linux x86_64)", "", 1.0)
        self.dm.write()
        text = self.read()
        ua = "Mozilla/5.0 (X11; Linux x86_64)"
        source = f"{BOT}|{ua}"                                          # "$remote_addr|$http_user_agent": no sid in it
        self.assertEqual(lookup(text, source), "1")
        self.assertEqual(lookup(text, source.upper()), "1")             # strings are matched ignoring the case
        for other in (f"{BOT}|{ua}x", f"10.0.17.6|{ua}", f"{BOT}|", f"{BOT}|{ua}|{SID}"):
            self.assertEqual(lookup(text, other), "0", other)

    def test_a_session_level_line_covers_one_session_where_a_key_level_line_covers_them_all(self):
        three = D.DenyMap(self.dir)
        three.add(BOT, UA, SID, 1.0)
        three.write()
        self.dm.add(BOT, UA, "", 1.0)
        self.dm.write()
        sessions = [SID, "c" * 32, ""]                                  # "" is a request without the cookie
        self.assertEqual([lookup(self.read(D.DENY_FILE), f"{BOT}|{UA}|{s}") for s in sessions], ["1", "0", "0"])
        # the key map's source has no sid, so every session of the key gives the same source value
        self.assertEqual({lookup(self.read(), f"{BOT}|{UA}") for _s in sessions}, {"1"})


class ArmCase(RS.Section9Case):
    def key_lines(self):
        with open(os.path.join(self.run_dir, D.KEY_DENY_FILE), encoding="ascii") as fh:
            return fh.read().splitlines()


class Level1Test(ArmCase):
    def test_a_decision_writes_a_key_line_once_the_key_is_20_s_old_in_batched_paced_reloads(self):
        self.see(start=1000.0)
        self.see(ip="10.0.17.6", start=1000.0)
        self.arm.submit(RS.rule_would_ban(t=1010.0))
        self.step(1010.0)
        self.assertEqual((self.key_lines(), self.f.reloads), ([], []))
        self.step(1020.0)
        self.assertEqual(self.key_lines(), [f'"{BOT}|{UA}" 1;'])
        self.assertEqual(self.f.reloads, [1020.0])
        self.arm.submit(RS.rule_would_ban(ip="10.0.17.6", t=1025.0))
        self.step(1025.0)                                                # the last reload was 5 s ago: batched
        self.assertEqual((len(self.key_lines()), self.f.reloads), (1, [1020.0]))
        self.step(1030.0)
        self.assertEqual((len(self.key_lines()), self.f.reloads), (2, [1020.0, 1030.0]))
        [deny, _second] = self.f.read("l7_deny")
        self.assertEqual((deny["level"], deny["ttl_s"], deny["sid_h"], deny["shared"]), (1, 300, None, False))
        self.assertEqual(self.map_lines(), [])                           # deny.map stays empty

    def test_every_session_of_the_key_counts_as_the_key_sending(self):
        self.see(sid="a" * 32, start=990.0)
        self.arm.submit(RS.rule_would_ban())
        self.step(1010.0)
        self.see(sid="b" * 32, start=1040.0)                             # another session of the same (IP, UA) key
        self.assertEqual(self.arm.tracked[(BOT, I.stable_hash32(UA))]["last"], 1040.0)

    def test_a_shared_address_gets_the_line_d043_charges_the_users_behind_it(self):
        for n in range(3):                                               # three UAs and three sessions on one address
            self.see(ua=f"Other/{n}", sid=f"{n:032x}", start=990.0)
        self.see(sid="", start=990.0)
        self.arm.submit(RS.rule_would_ban())
        self.step(1010.0)
        self.assertEqual(self.key_lines(), [f'"{BOT}|{UA}" 1;'])
        self.assertEqual(self.f.read("l7_enforce_miss"), [])
        self.step(1020.0)                                                # and no withdrawal as for a sid-less session line
        self.assertEqual((self.key_lines(), self.f.read("l7_deny_end")), ([f'"{BOT}|{UA}" 1;'], []))

    def test_an_unenforceable_user_agent_is_a_miss(self):
        ua = 'Bot "quoted"'
        self.see(ua=ua, start=990.0)
        self.arm.submit(RS.rule_would_ban(ua=ua))
        self.step(1010.0)
        self.assertEqual([m["rule"] for m in self.f.read("l7_enforce_miss")], ["ua_forbidden_char"])
        self.assertEqual(self.key_lines(), [])

    def test_the_ttl_the_cap_and_a_failed_reload_are_the_same(self):
        self.see(start=900.0)
        self.f.reload_ok = False
        self.arm.submit(RS.rule_would_ban())
        self.step(1000.0)
        self.f.reload_ok = True
        self.step(1005.0)
        self.step(1010.0)
        self.assertEqual([(r["ok"], r["entries"]) for r in self.f.read("l7_reload")], [(False, 1), (True, 1)])
        self.step(1300.5)
        self.assertEqual([e["reason"] for e in self.f.read("l7_deny_end")], ["ttl"])
        self.assertEqual(self.key_lines(), [])
        self.arm.denies = D.DenyMap(self.run_dir, cap=1, key_level=True)
        for n in range(2):
            self.see(ip=f"10.0.21.{n}", start=900.0)
            self.arm.submit(RS.rule_would_ban(ip=f"10.0.21.{n}", t=1400.0))
        self.step(1400.0)
        [c] = self.f.read("l7_enforce_capped")
        self.assertEqual((c["what"], c["cap"], c["ip"], c["level"]), ("deny", 1, "10.0.21.1", 1))

    def test_an_engine_and_a_map_of_different_levels_do_not_arm(self):
        self.arm.attach(T.view_engine())                                 # a key-level map under a view engine
        self.assertEqual(self.arm.armed, False)
        self.arm.denies = D.DenyMap(self.run_dir)
        self.arm.attach(RS.RuleEngineFake())                             # a session-level map under R*
        self.assertEqual(self.arm.armed, False)
        self.assertEqual([e["armed"] for e in self.f.read("l7_enforce_arm")][-2:], [False, False])


class SafeguardsTest(ArmCase):
    def denied(self):
        self.see(start=990.0)
        self.arm.submit(RS.rule_would_ban())
        self.step(1010.0)
        self.assertEqual(len(self.key_lines()), 1)

    def test_the_kill_switch_empties_the_key_map_paced(self):
        self.denied()
        self.arm.killed = lambda: True
        self.step(1011.0)
        self.assertEqual(self.f.reloads, [1010.0])                       # the spacing holds
        self.step(1020.0)
        self.assertEqual((self.key_lines(), self.f.reloads), ([], [1010.0, 1020.0]))
        self.assertEqual([e["reason"] for e in self.f.read("l7_deny_end")], ["kill"])

    def test_stop_empties_the_key_map_at_once(self):
        self.denied()
        self.f.now = 1012.0
        self.arm.stop(1012.0)
        self.assertEqual((self.key_lines(), self.f.reloads), ([], [1010.0, 1012.0]))

    def test_start_empties_either_map_an_earlier_daemon_left(self):
        for name, lines in ((D.DENY_FILE, f'"{BOT}|a|" 1;\n'), (D.KEY_DENY_FILE, f'"{BOT}|a" 1;\n"{BOT}|b" 1;\n')):
            with open(os.path.join(self.run_dir, name), "w", encoding="ascii") as fh:
                fh.write(lines)
        self.f.now = 500.0
        self.arm.start(500.0)
        self.assertEqual((self.map_lines(), self.key_lines(), self.f.reloads), ([], [], [500.0]))
        self.assertEqual(self.f.read("l7_reload")[0]["changes"], 3)

    def test_a_view_arms_daemon_empties_a_stale_key_map_too(self):
        self.arm.denies = D.DenyMap(self.run_dir)
        with open(os.path.join(self.run_dir, D.KEY_DENY_FILE), "w", encoding="ascii") as fh:
            fh.write(f'"{BOT}|a" 1;\n')
        self.f.now = 500.0
        self.arm.start(500.0)
        self.assertEqual((self.key_lines(), self.f.reloads), ([], [500.0]))


class ConfTest(unittest.TestCase):
    def setUp(self):
        self.orig = C.read(C.PROTECTED_CONF)
        self.text = C.protected(self.orig, RUN, key_map=True)

    def test_the_copy_has_both_maps_in_http_and_both_429s_in_server(self):
        http, server = self.text.index("http {"), self.text.index("    server {")
        m = re.search(r'^    map "\$remote_addr\|\$http_user_agent" \$l7_deny_key \{\n'
                      r"        default 0;\n        include ([^;]+);\n    \}\n", self.text, re.MULTILINE)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), f"{RUN}/{D.KEY_DENY_FILE}")
        self.assertTrue(http < m.start() < server)
        self.assertLess(self.text.index("map_hash_bucket_size"), self.text.index('map "$remote_addr'))   # before both maps
        self.assertEqual(self.text.count("map_hash_bucket_size"), 1)
        deny = self.text.index("if ($l7_deny) {")
        key = self.text.index("if ($l7_deny_key) {")
        self.assertTrue(self.text.index("server_name") < deny < key < self.text.index("location /"))
        self.assertEqual(self.text.count("return 429;"), 2)
        self.assertEqual(self.text.count("{"), self.orig.count("{") + 4)
        self.assertEqual(self.text.count("}"), self.orig.count("}") + 4)
        self.assertTrue(CT.is_subsequence(self.orig.splitlines(), self.text.splitlines()))
        self.assertEqual(C.KEY_DENY_FILE, D.KEY_DENY_FILE)

    def test_without_it_the_copy_is_as_it_was_and_the_tracked_confs_are_untouched(self):
        plain = C.protected(self.orig, RUN)
        self.assertEqual(plain, C.protected(self.orig, RUN, key_map=False))
        self.assertNotIn("$l7_deny_key", plain)
        self.assertNotIn("deny_key.map", plain)
        self.assertEqual({n: CT.sha(os.path.join(REPO, n)) for n in CT.PINNED}, CT.PINNED)
        with self.assertRaises(C.ConfError):
            C.protected(self.text, RUN, key_map=True)                    # rendered once only

    def test_the_sink_and_the_log_paths_still_render(self):
        import capture_l7
        import executor
        out = executor.render_nginx_conf(capture_l7.render_l7_sink(C.run_confs(RUN, key_map=True)["protected"],
                                                                   "/run/ddos_l7.sock"),
                                         "/var/tmp/run/access.log", "/var/tmp/run/error.log", feed=True)
        self.assertEqual(out.count("$l7_deny_key"), 2)
        self.assertIn("access_log syslog:server=unix:/run/ddos_l7.sock,nohostname,tag=l7 l7json;", out)


class DaemonTest(RS.SelectionCase):
    def daemon(self):
        path, sha = RS.write_selection(os.path.join(self.tmp.name, "sel"), "cost_budget", (["key:cost_60"], [100.0], 2))
        d = H.Daemon({"L7_SHADOW": "1", "L7_ENFORCE": "1", "L7_NGINX_CONF": "/x/nginx.conf", "L7_ARM": L.RSTAR,
                      "L7_SELECTION": path, "L7_SELECTION_SHA256": sha})
        self.addCleanup(d.close)
        d.ns.update(l7_denymap=D, l7_enforce=l7_enforce, l7_arms=L, l7_engine=l7_engine)
        d.ns["L7_ENFORCE_DIR"] = os.path.join(d._tmp.name, "l7v2")
        d.ns["L7_SOCKET_GROUP"] = os.getgid()
        d.clock.now = 999.0
        return d

    def shadow(self, d, records, until):
        import types
        reader = V2.FakeReader(d, records, until, tick=lambda _t: d.call("l7_enforce_poll"))
        ingest = types.SimpleNamespace(**{k: getattr(I, k) for k in dir(I) if not k.startswith("__")})
        ingest.SyslogDatagramReader = lambda _path, **_kw: reader
        d.ns["l7_ingest"] = ingest
        d.call("l7_shadow_monitor", "/run/ddos_l7.sock")

    def test_the_daemon_denies_every_session_of_a_key_through_the_key_map(self):
        d = self.daemon()
        d.call("l7_enforce_init")
        self.assertEqual(sorted(os.listdir(d.L7_ENFORCE_DIR)), sorted(D.MAP_FILES))
        ua = "Bot/2.0 (compatible; deep-linker)"
        records = [RS.obj(BOT, "/export", 1000.0 + 2 * n, ua=ua, sid=f"{n % 3:032x}") for n in range(30)]
        self.shadow(d, records, 1070.0)
        self.assertEqual(d.proc.matching("nginx")[0], ["nginx", "-c", "/x/nginx.conf", "-s", "reload"])
        with open(os.path.join(d.L7_ENFORCE_DIR, D.KEY_DENY_FILE), encoding="ascii") as fh:
            self.assertEqual(fh.read(), f'"{BOT}|{ua}" 1;\n')
        with open(os.path.join(d.L7_ENFORCE_DIR, D.DENY_FILE), encoding="ascii") as fh:
            self.assertEqual(fh.read(), "")
        [deny] = d.events("l7_deny")
        self.assertEqual((deny["arm"], deny["level"], deny["ip"]), ("R*", 1, BOT))
        d.call("l7_enforce_stop")
        with open(os.path.join(d.L7_ENFORCE_DIR, D.KEY_DENY_FILE), encoding="ascii") as fh:
            self.assertEqual(fh.read(), "")


if __name__ == "__main__":
    unittest.main()
