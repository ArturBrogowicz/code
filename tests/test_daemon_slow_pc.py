"""The P4 per-connection slow rule inside the daemon (SLOW_PC=1; slow_pc.py; docs/P4_SLOW_DESIGN.md
§6-§7), on the fakes of tests/daemon_harness.py: nothing is imported from control_plane.py, no
`ss` and no nginx run. The fake `ss -tinpH` output is a function of the fake clock; the daemon's
first poll is at t = 1001.
"""
import ast
import contextlib
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, REPO)
import daemon_harness as H

import slow_pc as P

IP = "10.0.3.1"
CGNAT = "10.0.4.1"
NGINX = 'users:(("nginx",pid=4242,fd=17))'
FAST = {"SLOW_PC": "1", "SLOW_PC_T": "5", "SLOW_PC_F": "256"}   # short runs; K stays 6


def sock(ip, port, sport=80, owned=True, acked=1, received=100, segs=1):
    """One socket as `ss -tinpH state established` prints it."""
    owner = NGINX if owned else ""
    return (f"0      0      10.0.0.1:{sport}   {ip}:{port} {owner}".rstrip()
            + f"\n\t cubic bytes_acked:{acked} bytes_received:{received} data_segs_in:{segs}"
            " lastrcv:500 rcv_space:14480\n")


def loris(ip, port, t, sport=80, opened=1000.5, gap=2.0):
    """A Slowloris connection at time t: a partial request, then a 30-byte header line every
    `gap` s, never an answer."""
    segs = 1 + int((t - opened) // gap)
    return sock(ip, port, sport, received=100 + 30 * (segs - 1), segs=segs)


def loris_world(ip=IP, conns=6, first_port=41000):
    return lambda t: "".join(loris(ip, first_port + i, t) for i in range(conns))


def access(d, records, dt=0.01):
    """The real body of the daemon's access-log loop over these records (dicts), the clock
    moving dt before each."""
    def paced():
        for rec in records:
            d.clock.now += dt
            yield json.dumps(rec) + "\n"
    with contextlib.redirect_stdout(d.out):
        d._main_loop(paced())


class SlowPcCase(unittest.TestCase):
    def daemon(self, **env):
        d = H.Daemon(env)
        self.addCleanup(d.close)
        return d

    @staticmethod
    def run_world(d, polls, world, setup=None):
        """`polls` polls of the real telemetry loop; before each, `ss -tinpH` is set to
        world(t), and then setup(k) runs."""
        def on(k):
            d.proc.ss_info = world(d.clock.now)
            if setup:
                setup(k)
        d.poll(polls, on)

    @staticmethod
    def brief(ev, *keys):
        return tuple(ev[k] for k in keys)


class SwitchTest(SlowPcCase):
    def test_off_by_default_the_daemon_runs_as_before(self):
        d = self.daemon()
        self.assertFalse(d.SLOW_PC)
        self.run_world(d, 12, loris_world())
        self.assertEqual(d.proc.matching("ss", "-tinpH"), [])
        self.assertEqual(d.events("slow_pc_close", "slow_pc_would_ban", "slow_pc_capped",
                                  "slow_pc_poll"), [])
        self.assertIsNone(d.slow_pc_engine)
        d.l7_requests([(0.01, IP, 200)] * 3)
        self.assertTrue(d.slow_pc_inbox.empty())

    def test_thresholds_off_the_frozen_grid_stop_the_daemon_at_start(self):
        for env in ({"SLOW_PC_T": "7"}, {"SLOW_PC_F": "100"}, {"SLOW_PC_K": "5"}):
            with self.subTest(env=env), self.assertRaises(SystemExit):
                self.daemon(SLOW_PC="1", **env)
        self.assertEqual(self.daemon(SLOW_PC_T="7").SLOW_PC_T, 7)     # unused while off
        d = self.daemon(SLOW_PC="1")
        self.assertEqual((d.SLOW_PC_T, d.SLOW_PC_F, d.SLOW_PC_K), (20, 16, 6))

    def test_the_start_event_records_the_rule_and_its_thresholds(self):
        with open(H.SOURCE, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        [start] = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                   and isinstance(n.func, ast.Attribute) and n.func.attr == "emit"
                   and n.args and getattr(n.args[0], "value", None) == "start"]
        kw = {k.arg: k.value for k in start.keywords}
        self.assertIn("slow_pc", kw)
        self.assertIn("slow_pc_sha256", kw)
        keys = {k.value for k in kw["thresholds"].keys}
        self.assertLessEqual({"slow_pc_t_s", "slow_pc_f_bps", "slow_pc_k"}, keys)

    def test_the_rule_runs_after_the_per_address_rules_and_before_the_gru_feed(self):
        with open(H.SOURCE, encoding="utf-8") as fh:
            src = fh.read()
        body = src[src.index("def l3_l4_telemetry_monitor"):]
        self.assertLess(body.index("for key, per_cpu_values in telemetry_map.items()"),
                        body.index("slow_pc_poll()"))
        self.assertLess(body.index("slow_pc_poll()"), body.index("flow_map.items()"))


class ShadowTest(SlowPcCase):
    def test_it_logs_what_it_would_close_and_ban_and_enforces_nothing(self):
        d = self.daemon(**FAST)
        self.run_world(d, 12, loris_world())
        # First seen at t = 1001; old from 1007; the third suspect poll in a row is 1009.
        closes = d.events("slow_pc_close")
        self.assertEqual(sorted(c["port"] for c in closes), list(range(41000, 41006)))
        self.assertEqual({self.brief(c, "ip", "sport", "enforced", "age_s", "streak", "ua_keys")
                          for c in closes}, {(IP, 80, False, 8.0, 3, 0)})
        self.assertEqual([self.brief(w, "ip", "value", "threshold", "ua_keys")
                          for w in d.events("slow_pc_would_ban")], [(IP, 6, 6, 0)])
        self.assertEqual((d.bans(), d.blacklist.ips(), d.banned_ips), ([], set(), set()))
        self.assertEqual(d.proc.matching("ss", "-K"), [])
        self.assertEqual(d.proc.matching("ss", "-tinpH"), [P.SS_ARGV] * 12)

    def test_a_failed_read_skips_the_poll_and_keeps_the_streaks(self):
        for failure in (OSError(12, "Cannot allocate memory"), 1):
            with self.subTest(failure=failure):
                d = self.daemon(**FAST)

                def setup(k, d=d, failure=failure):
                    if k == 8:
                        d.proc.failures[("ss", "-tinpH")] = failure
                    elif k == 9:
                        del d.proc.failures[("ss", "-tinpH")]
                self.run_world(d, 12, loris_world(), setup)
                # Suspect at t = 1007, 1009 and 1010: the failed poll 1008 neither counts nor
                # resets, so the close comes one poll later.
                self.assertEqual({c["age_s"] for c in d.events("slow_pc_close")}, {9.0})
                [err] = d.events("daemon_error")
                self.assertEqual((err["where"], err["action"]),
                                 ("slow_pc", "poll skipped, streaks kept"))

    def test_an_error_in_the_rule_cannot_stop_the_other_rules(self):
        class Broken:
            def poll(self, *_args):
                raise RuntimeError("boom")

        d = self.daemon(SLOW_PC="1")
        d.ns["slow_pc_engine"] = Broken()
        d.poll(1, lambda k: d.telemetry.add(IP, pkts=300, syn=300))
        self.assertEqual([(b["ip"], b["engine"]) for b in d.bans()], [(IP, "l4_syn")])
        [err] = d.events("daemon_error")
        self.assertEqual((err["where"], err["error"], err["action"]),
                         ("slow_pc", "RuntimeError: boom", "poll skipped"))

    def test_the_poll_report_every_five_seconds(self):
        d = self.daemon(**FAST)
        bad = sock("2001:db8::7", 41999).replace("2001:db8::7", "[2001:db8::7]")

        def setup(k):
            if k == 3:
                d.proc.failures[("ss", "-tinpH")] = 1
            elif k == 4:
                del d.proc.failures[("ss", "-tinpH")]
        self.run_world(d, 11, lambda t: loris_world()(t) + bad, setup)
        reports = d.events("slow_pc_poll")
        self.assertEqual(len(reports), 3)                   # t = 1001, 1006, 1011
        first, second, third = reports
        self.assertEqual(self.brief(first, "mode", "polls", "ss_failed", "sockets", "owned",
                                    "tracked", "skipped_lines", "inbox_dropped"),
                         ("shadow", 1, 0, 6, 6, 6, 1, 0))
        self.assertTrue(first["bad_sample"].startswith("0      0      10.0.0.1:80   [2001:db8::7]"))
        self.assertEqual(self.brief(second, "polls", "ss_failed", "suspect", "closes"), (4, 1, 0, 0))
        self.assertEqual(self.brief(third, "polls", "suspect", "closes", "bans"), (5, 18, 6, 1))


class AccessLogTest(SlowPcCase):
    UA_LINES = tuple({"client_ip": IP, "status": 200, "user_agent": ua} for ua in ("a", "b", "c"))

    def test_the_rate_rule_bans_exactly_as_before(self):
        flood = [{"client_ip": IP, "status": 200, "user_agent": f"ua{i % 3}"} for i in range(51)]
        for env in ({}, {"SLOW_PC": "1"}):
            with self.subTest(env=env):
                d = self.daemon(**env)
                access(d, flood)
                self.assertEqual([self.brief(b, "ip", "engine", "value") for b in d.bans()],
                                 [(IP, "l7_rate", 51.0)])
                self.assertEqual(d.slow_pc_inbox.qsize(), 51 if env else 0)

    def test_an_address_with_three_ua_keys_is_never_banned(self):
        for lines, would_ban in ((self.UA_LINES[:2], [(IP, 6, 2)]), (self.UA_LINES, [])):
            with self.subTest(ua_keys=len(lines)):
                d = self.daemon(**FAST)
                access(d, lines, dt=0.1)
                self.run_world(d, 12, loris_world())
                self.assertEqual(len(d.events("slow_pc_close")), 6)
                self.assertEqual([self.brief(w, "ip", "value", "ua_keys")
                                  for w in d.events("slow_pc_would_ban")], would_ban)

    def test_on_443_the_logged_client_port_answers_a_connection(self):
        # A CGNAT pool on :443 whose connections keep carrying requests: the TLS handshake
        # answers all of them, so only the access log (the client port, which profile R's format
        # logs) tells the served ones apart.
        def world(t):
            return "".join(sock(CGNAT, 43000 + i, 443, acked=4100, received=900 + 40 * int(t - 1000),
                                segs=3 + int(t - 1000)) for i in range(24))
        lines = [{"client_ip": CGNAT, "port": 43000 + i, "status": 200, "user_agent": f"u{i % 12}"}
                 for i in range(24)]
        other = [{"client_ip": "10.0.9.9", "port": 50000, "status": 200}]
        for logged, closes in ((True, 0), (False, 24)):
            with self.subTest(logged=logged):
                d = self.daemon(**FAST)
                access(d, lines if logged else other)
                self.run_world(d, 12, world)
                self.assertEqual(len(d.events("slow_pc_close")), closes)

    def test_without_the_client_port_in_the_log_443_is_not_judged(self):
        # The deployed json_ml_format has no port: with it, every :443 connection would look
        # unanswered, so the rule leaves :443 alone until a record with a port arrives.
        d = self.daemon(**FAST)
        access(d, [{"client_ip": "10.0.9.9", "status": 200, "user_agent": "a"}])
        self.run_world(d, 12, lambda t: "".join(
            sock(CGNAT, 43000 + i, 443, acked=4100, received=900 + 40 * int(t - 1000),
                 segs=3 + int(t - 1000)) for i in range(24)))
        self.assertEqual(d.events("slow_pc_close"), [])

    def test_a_full_inbox_drops_and_counts_and_bad_records_are_ignored(self):
        d = self.daemon(**FAST)
        d.ns["slow_pc_inbox"] = H.queue.Queue(maxsize=2)
        access(d, [{"client_ip": IP, "status": 200}] * 5 + [{"client_ip": "x"}, {"status": 200}])
        self.assertEqual((d.slow_pc_inbox.qsize(), d.slow_pc_counts["inbox_dropped"]), (2, 3))
        self.run_world(d, 1, lambda t: "")
        [report] = d.events("slow_pc_poll")
        self.assertEqual((report["inbox_dropped"], report["note_errors"]), (3, 0))


class RecordTest(SlowPcCase):
    def test_the_record_replays_to_the_same_decisions(self):
        d = self.daemon(**FAST, SLOW_PC_K="2")
        path = os.path.join(d._tmp.name, "slow_pc.jsonl.gz")
        d.ns["SLOW_PC_RECORD"] = path
        access(d, [{"client_ip": "10.0.3.2", "port": 41000, "status": 200, "user_agent": "a"}])

        def world(t):
            return loris_world()(t) + loris_world("10.0.3.2", 2)(t)

        def setup(k):
            if k == 5:
                d.proc.failures[("ss", "-tinpH")] = 1
            elif k == 6:
                del d.proc.failures[("ss", "-tinpH")]
        self.run_world(d, 12, world, setup)
        d.slow_pc_record_fh.close()                            # the end of the run
        polls = P.read_record(path)
        self.assertEqual([round(p["t"] - 1001.01, 6) for p in polls], [float(i) for i in range(12)])
        self.assertEqual(([p["ss"] is None for p in polls].index(True), polls[0]["enforce"]),
                         (4, False))
        self.assertEqual(polls[0]["l7"], [["10.0.3.2", 41000, P.l7_ingest.stable_hash32("a"),
                                           polls[0]["l7"][0][3]]])
        replayed = [c._asdict() for _t, r in P.replay(polls, 5, 256, 2) for c in r.closes]
        logged = [{k: e[k] for k in replayed[0]} for e in d.events("slow_pc_close")]
        self.assertEqual((len(replayed), replayed), (8, logged))
        with open(path, "rb") as fh:
            data = fh.read()
        with open(path, "wb") as fh:
            fh.write(data[:-30])                               # a run cut mid-write
        self.assertEqual(len(P.read_record(path)), 11)

    def test_a_failed_write_stops_the_recording_not_the_rule(self):
        d = self.daemon(**FAST, SLOW_PC_RECORD="/nonexistent-T023/slow_pc.jsonl.gz")
        self.run_world(d, 12, loris_world())
        self.assertEqual(len(d.events("slow_pc_close")), 6)
        [err] = d.events("daemon_error")
        self.assertEqual((err["where"], err["action"]), ("slow_pc_record", "recording stopped"))
        self.assertIs(d.slow_pc_record_fh, False)


ENFORCE = {**FAST, "SLOW_PC_ENFORCE": "1"}


class EnforceTest(SlowPcCase):
    """§7: ss -K on each connection, an XDP ban of the address on the aggregate, the caps, the
    kill switch."""

    def test_each_connection_is_closed_by_its_own_filter_then_the_address_is_banned(self):
        d = self.daemon(**ENFORCE)
        self.run_world(d, 10, loris_world())
        expr = " or ".join(f"( dst {IP} and dport = :{41000 + i} and sport = :80 )"
                           for i in range(6))
        self.assertEqual(d.proc.matching("ss", "-K"),
                         [["ss", "-K", "-t", "state", "established", expr],
                          ["ss", "-K", "dst", IP]])                # then kill_zombie_connections
        [ban] = d.bans()
        self.assertEqual(self.brief(ban, "ip", "engine", "value", "threshold", "ua_keys", "ttl_s"),
                         (IP, "l4_slowconn_pc", 6, 6, 0, 300))
        self.assertEqual(ban["reason"], "Per-connection slow rule (6 connections closed in 60 s)")
        self.assertEqual(H.ban_events.engine_from_reason(ban["reason"]), "l4_slowconn_pc")
        self.assertEqual(H.ban_events.ENGINE_LABELS["l4_slowconn_pc"], "L4 SlowConn-PC")
        self.assertEqual((d.blacklist.ips(), d.banned_ips), ({IP}, {IP}))
        self.assertEqual({c["enforced"] for c in d.events("slow_pc_close")}, {True})
        self.assertEqual(d.events("slow_pc_would_ban"), [])
        self.assertIn(f"[BAN] {IP} banned for 300s. Reason: Per-connection slow rule", d.console())
        d = self.daemon(SLOW_PC_ENFORCE="1")                    # without SLOW_PC=1: off
        self.run_world(d, 12, loris_world())
        self.assertEqual((d.proc.matching("ss", "-tinpH"), d.proc.matching("ss", "-K")), ([], []))

    def test_at_most_32_connections_per_call_and_never_an_unfiltered_kill(self):
        d = self.daemon(**ENFORCE)
        self.run_world(d, 9, loris_world(conns=40))
        kills = d.proc.matching("ss", "-K")
        self.assertEqual([k[5].count("( dst ") for k in kills[:2]], [32, 8])
        self.assertEqual(kills[2:], [["ss", "-K", "dst", IP]])
        d.proc.calls.clear()
        self.assertEqual(d.call("slow_pc_close", []), 0)
        self.assertEqual(d.proc.calls, [])

    def test_a_failed_close_call_is_reported_and_a_surviving_socket_counted(self):
        for gone in (True, False):
            with self.subTest(gone=gone):
                d = self.daemon(**ENFORCE)
                if not gone:
                    d.proc.failures[("ss", "-K", "-t")] = 1         # the close call fails

                def world(t, d=d, gone=gone):
                    return "" if gone and d.proc.matching("ss", "-K") else loris_world()(t)
                self.run_world(d, 11, world)
                failed = sum(r["close_failed"] for r in d.events("slow_pc_poll"))
                errors = [e["error"] for e in d.events("daemon_error")]
                self.assertEqual((failed, errors),
                                 (0, []) if gone else (6, ["1 ss -K call(s) failed"]))

    def test_the_kill_file_and_gru_only_send_it_back_to_shadow(self):
        def world(t):
            two = loris_world("10.0.3.2")(t) if t >= 1010 else ""
            return loris_world()(t) + two
        for case in ("kill file", "GRU_ONLY"):
            with self.subTest(case):
                d = self.daemon(**ENFORCE, **({"GRU_ONLY": "1"} if case == "GRU_ONLY" else {}))
                kill = os.path.join(d._tmp.name, "kill")
                d.ns["SLOW_PC_KILL_FILE"] = kill
                if case == "kill file":
                    with open(kill, "w", encoding="utf-8"):
                        pass

                def setup(k, kill=kill):
                    if k == 10 and os.path.exists(kill):
                        os.remove(kill)                         # the switch is read every poll
                self.run_world(d, 19, world, setup)
                closes = {(c["ip"], c["enforced"]) for c in d.events("slow_pc_close")}
                would = [w["ip"] for w in d.events("slow_pc_would_ban")]
                bans = [b["ip"] for b in d.bans()]
                if case == "kill file":
                    self.assertEqual(closes, {(IP, False), ("10.0.3.2", True)})
                    self.assertEqual((would, bans), ([IP], ["10.0.3.2"]))
                else:
                    self.assertEqual(closes, {(IP, False), ("10.0.3.2", False)})
                    self.assertEqual((would, bans), ([IP, "10.0.3.2"], []))
                modes = [r["mode"] for r in d.events("slow_pc_poll")]
                self.assertEqual(modes[0], "shadow")

    def test_m_def_bans_the_cgnat_pool_and_misses_slowloris_m_pc_the_reverse(self):
        # A co-resident CGNAT pool (72 idle keep-alive connections, all answered: P5c.1's pools)
        # and a Slowloris address at 6 connections, the benign device's footprint (§5, §8).
        # M_def, the default profile without the rule: SlowConn bans the pool (>= 8 connections,
        # < 250 B per poll, 3 polls) and never sees 6 < 8. M_pc (D-S7), the tolerant profile
        # (SlowConn at 180) with the rule enforcing: the Slowloris address only.
        def world(t):
            pool = "".join(sock(CGNAT, 42000 + i, acked=5200, received=420) for i in range(72))
            return pool + loris_world()(t)
        for arm, env, bans in (("M_def", {}, [(CGNAT, "l4_slowconn")]),
                               ("M_pc", {**ENFORCE, "HEURISTIC_PROFILE": "tolerant"},
                                [(IP, "l4_slowconn_pc")])):
            with self.subTest(arm=arm):
                d = self.daemon(**env)

                def setup(_k, d=d):
                    d.telemetry.add(CGNAT, pkts=4, nbytes=200)
                    d.telemetry.add(IP, pkts=2, nbytes=60)
                    d.set_established({CGNAT: 72, IP: 6})
                self.run_world(d, 30, world, setup)
                self.assertEqual([self.brief(b, "ip", "engine") for b in d.bans()], bans)
                self.assertEqual({c["ip"] for c in d.events("slow_pc_close")},
                                 {IP} if arm == "M_pc" else set())

    def test_the_caps_are_logged(self):
        # 90 addresses x 6 Slowloris connections, all due at t = 1009: 500 closes and 40 held
        # back; 83 addresses complete, 20 banned and 63 held back; at 1010 the last 40 close and
        # 7 more addresses complete, all held back (20 bans in the last minute).
        def world(t):
            return "".join(loris(f"10.2.0.{a + 1}", 53000 + i, t) for a in range(90)
                           for i in range(6))
        d = self.daemon(**ENFORCE)
        self.run_world(d, 10, world)
        capped = [self.brief(c, "what", "n", "cap") for c in d.events("slow_pc_capped")]
        self.assertEqual(capped, [("close", 40, 500), ("ban", 63, 20), ("ban", 70, 20)])
        self.assertEqual(len(d.bans()), 20)
        self.assertEqual(len(d.events("slow_pc_close")), 540)
        self.assertEqual(len(d.events("slow_pc_capped")[1]["ips"]), 50)



class DocumentationTest(unittest.TestCase):
    def test_evaluation_md_documents_the_rule_profile_r_the_events_and_the_tests(self):
        with open(os.path.join(REPO, "docs", "EVALUATION.md"), encoding="utf-8") as fh:
            doc = fh.read()
        start = doc.index("## P4: the per-connection slow rule and profile R")
        section = doc[start:doc.index("\n## ", start + 1)]
        for name in ("`SLOW_PC`", "`SLOW_PC_ENFORCE`", "`SLOW_PC_KILL_FILE`", "`SLOW_PC_T`",
                     "`SLOW_PC_RECORD`", "`l4_slowconn_pc`", "`l7_rudy`", "`nginx_profile_r.conf`",
                     "`nginx_profile_r_limits.conf`", "`gunicorn_profile_r.py`",
                     "`slow_pc.select_thresholds()`", "`tests/test_slow_pc_rule.py`",
                     "`tests/test_slow_pc.py`", "`tests/test_daemon_slow_pc.py`",
                     "`tests/test_profile_r.py`", "`tests/test_l7_admissibility_pc.py`",
                     "[NOT RUN]"):
            self.assertIn(name, section, name)
        events = doc[doc.index("## Ban events"):doc.index("## Metrics")]
        for kind in ("slow_pc_close", "slow_pc_would_ban", "slow_pc_capped", "slow_pc_poll",
                     "l4_slowconn_pc", "slow_pc_enforce"):
            self.assertIn(f"`{kind}`", events, kind)


if __name__ == "__main__":
    unittest.main()
