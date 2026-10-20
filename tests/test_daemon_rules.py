"""Behavioural characterization tests for the daemon's live rules (audit G-29, REPORT 7.4).

The real code of control_plane.py runs against fakes (tests/daemon_harness.py): no root, no BPF,
no sockets, no sleeping. The tests pin what the rules do today, thresholds and weaknesses
included, so that moving them out of the 1000-line script (a detect_rules.py module) cannot
change them unnoticed. A test named `..._weakness` documents behaviour that is wrong or weak on
purpose-built input; it is pinned, not endorsed. Changing the rules is a decision, and then the
test changes with it.
"""
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "ml"))
import daemon_harness as H

IP = "10.0.2.1"
OTHER = "10.0.2.2"


def iv(**counters):
    """One interval's worth of XDP counters for FakeTelemetry.add: pkts, syn, nbytes."""
    return counters


RUDY_TIMEOUT = ('2026/10/13 08:49:01 [info] 1234#1234: *5 client timed out (110: Connection '
                'timed out) while reading client request body, client: {ip}, server: _, '
                'request: "POST /?r=1 HTTP/1.1", host: "10.0.0.1"\n')
RUDY_HEADER_TIMEOUT = ('2026/10/13 08:49:01 [info] 1#1: *5 client timed out (110: Connection '
                       'timed out) while reading client request headers, client: 10.0.2.1, '
                       'server: _\n')
RUDY_TOO_LARGE = ('2026/10/13 08:49:01 [error] 1#1: *5 client intended to send too large body: '
                  '1000000 bytes, client: 10.0.2.1, server: _, request: "POST / HTTP/1.1"\n')
RUDY_IPV6 = ('2026/10/13 08:49:01 [info] 1#1: *5 client timed out (110: Connection timed out) '
             'while reading client request body, client: 2001:db8::1, server: _\n')


class DaemonCase(unittest.TestCase):
    def daemon(self, **env):
        d = H.Daemon(env)
        self.addCleanup(d.close)
        return d

    @staticmethod
    def run_polls(d, intervals, ip=IP, conns=0):
        """One interval per element of `intervals` (the kwargs of FakeTelemetry.add: pkts, syn,
        nbytes). `conns` is the number of established connections `ss` shows for `ip`, one
        value or one per interval."""
        def setup(k):
            d.telemetry.add(ip, **intervals[k - 1])
            c = conns[k - 1] if isinstance(conns, (list, tuple)) else conns
            d.set_established({ip: c} if c else {})
        d.poll(len(intervals), setup)

    @staticmethod
    def brief(ban):
        return {k: ban.get(k) for k in ("ip", "engine", "value", "threshold")}


class HarnessTest(DaemonCase):
    def test_nothing_is_attached_loaded_or_started(self):
        d = self.daemon()
        for name in ("bpf", "bpf_function", "scaler", "gru_model", "device", "BPF", "torch"):
            self.assertNotIn(name, d.ns, name)
        skipped = " ".join(d.skipped)
        for text in ("BPF(src_file", "attach_xdp", "joblib.load", "torch.load", "try:"):
            self.assertIn(text, skipped, text)
        self.assertIs(d.ns["EVENTS"], d.events_log)
        self.assertIs(d.ns["blacklist_map"], d.blacklist)

    def test_the_daemons_environment_is_the_one_the_test_gives(self):
        with mock.patch.dict(os.environ, {"XDP_GRU": "1", "GRU_ONLY": "1",
                                          "HEURISTIC_PROFILE": "tolerant"}):
            d = self.daemon()
        self.assertEqual((d.XDP_GRU, d.GRU_ONLY, d.HEURISTIC_PROFILE),
                         (False, False, "default"))


class ThresholdsTest(DaemonCase):
    def test_default_thresholds(self):
        d = self.daemon()
        self.assertEqual(
            {k: getattr(d, k) for k in (
                "SYN_FLOOD_THRESHOLD", "UDP_FLOOD_THRESHOLD", "SLOWCONN_CONN_THRESHOLD",
                "SLOWCONN_IDLE_BYTES", "SLOWCONN_CONSECUTIVE", "LOWSYN_SYN_MIN",
                "LOWSYN_ESTABLISH_GRACE", "LOWSYN_CONSECUTIVE", "BAN_TTL_SECONDS",
                "GLOBAL_SYN_THRESHOLD", "GLOBAL_PPS_THRESHOLD", "VOLUMETRIC_COOLDOWN",
                "HEURISTIC_WINDOW", "HEURISTIC_MAX_RPS", "HEURISTIC_ERROR_RATIO",
                "HEURISTIC_MIN_REQUESTS", "RUDY_TIMEOUT_THRESHOLD", "RUDY_WINDOW",
                "CLIENT_IDLE_TIMEOUT", "L4_POLL_INTERVAL")},
            {"SYN_FLOOD_THRESHOLD": 200, "UDP_FLOOD_THRESHOLD": 5000,
             "SLOWCONN_CONN_THRESHOLD": 8, "SLOWCONN_IDLE_BYTES": 250,
             "SLOWCONN_CONSECUTIVE": 3, "LOWSYN_SYN_MIN": 3, "LOWSYN_ESTABLISH_GRACE": 15.0,
             "LOWSYN_CONSECUTIVE": 4, "BAN_TTL_SECONDS": 300, "GLOBAL_SYN_THRESHOLD": 5000,
             "GLOBAL_PPS_THRESHOLD": 50000, "VOLUMETRIC_COOLDOWN": 15.0,
             "HEURISTIC_WINDOW": 10.0, "HEURISTIC_MAX_RPS": 50, "HEURISTIC_ERROR_RATIO": 0.8,
             "HEURISTIC_MIN_REQUESTS": 5, "RUDY_TIMEOUT_THRESHOLD": 3, "RUDY_WINDOW": 60.0,
             "CLIENT_IDLE_TIMEOUT": 60.0, "L4_POLL_INTERVAL": 1.0})

    def test_the_xdp_gru_is_off_unless_asked_for(self):
        self.assertFalse(self.daemon().XDP_GRU)
        self.assertTrue(self.daemon(XDP_GRU="1").XDP_GRU)
        self.assertTrue(self.daemon(GRU_ONLY="1").XDP_GRU)            # implied by GRU_ONLY
        self.assertFalse(self.daemon(GRU_ONLY="1", XDP_GRU="0").XDP_GRU)

    def test_the_tolerant_profile_relaxes_exactly_two_thresholds(self):
        d = self.daemon(HEURISTIC_PROFILE="tolerant")
        self.assertEqual((d.HEURISTIC_MAX_RPS, d.SLOWCONN_CONN_THRESHOLD), (108, 180))
        self.assertEqual((d.SYN_FLOOD_THRESHOLD, d.UDP_FLOOD_THRESHOLD, d.HEURISTIC_ERROR_RATIO,
                          d.SLOWCONN_IDLE_BYTES, d.LOWSYN_SYN_MIN), (200, 5000, 0.8, 250, 3))

    def test_an_unknown_profile_stops_the_daemon(self):
        with self.assertRaises(SystemExit):
            self.daemon(HEURISTIC_PROFILE="lenient")


class SynFloodTest(DaemonCase):
    def test_the_per_ip_threshold_is_strict(self):
        d = self.daemon()
        self.run_polls(d, [iv(pkts=200, syn=200)])
        self.assertEqual(d.bans(), [])
        d = self.daemon()
        self.run_polls(d, [iv(pkts=201, syn=201)])
        self.assertEqual([self.brief(b) for b in d.bans()],
                         [{"ip": IP, "engine": "l4_syn", "value": 201, "threshold": 200}])

    def test_the_ban_blocks_the_ip_and_arms_the_volumetric_cooldown(self):
        d = self.daemon()
        self.run_polls(d, [iv(pkts=300, syn=300)])
        self.assertEqual(d.blacklist.ips(), {IP})
        self.assertIn(IP, d.banned_ips)
        self.assertEqual(d.volumetric_active_until, d.clock.now + 15.0)
        self.assertEqual([e["kind"] for e in d.events("suppress_on", "suppress_off")],
                         ["suppress_on"])

    def test_the_rate_is_a_delta_of_the_cumulative_counters(self):
        d = self.daemon()
        self.run_polls(d, [iv(pkts=150, syn=150)] * 3)       # cumulative 450, delta 150
        self.assertEqual(d.bans(), [])

    def test_the_first_sighting_counts_the_whole_cumulative_value(self):
        d = self.daemon()
        d.telemetry.add(IP, pkts=500, syn=500)                  # seen before the daemon polled
        d.poll(1)
        self.assertEqual([b["engine"] for b in d.bans()], ["l4_syn"])

    def test_a_counter_that_went_down_is_a_new_key(self):
        d = self.daemon()

        def setup(k):
            if k == 1:
                d.telemetry.add(IP, pkts=400, syn=100)
            else:                                               # key evicted and re-created
                d.telemetry.counters.clear()
                d.telemetry.add(IP, pkts=250, syn=250)          # 250, not 250 - 100
        d.poll(2, setup)
        self.assertEqual([self.brief(b) for b in d.bans()],
                         [{"ip": IP, "engine": "l4_syn", "value": 250, "threshold": 200}])

    def test_a_banned_ip_is_not_evaluated_again(self):
        d = self.daemon()
        self.run_polls(d, [iv(pkts=300, syn=300)] * 3)
        self.assertEqual(len(d.bans()), 1)

    def test_gru_only_mode_disables_the_rule(self):
        d = self.daemon(GRU_ONLY="1")
        self.run_polls(d, [iv(pkts=900, syn=900)])
        self.assertEqual(d.bans(), [])


class VolumetricTest(DaemonCase):
    def test_the_threshold_is_strict_and_counts_non_syn_packets(self):
        for pkts, syn, banned in ((5000, 0, False), (5001, 0, True),
                                  (5150, 150, False),      # 5000 non-SYN packets
                                  (5151, 150, True)):      # 5001 non-SYN packets
            with self.subTest(pkts=pkts, syn=syn):
                d = self.daemon()
                self.run_polls(d, [iv(pkts=pkts, syn=syn)])
                self.assertEqual([b["engine"] for b in d.bans()],
                                 ["l4_volumetric"] if banned else [])

    def test_the_event_carries_the_measured_value(self):
        d = self.daemon()
        self.run_polls(d, [iv(pkts=7000, syn=100)])
        self.assertEqual([self.brief(b) for b in d.bans()],
                         [{"ip": IP, "engine": "l4_volumetric", "value": 6900,
                           "threshold": 5000}])

    def test_the_syn_rule_wins_when_both_apply(self):
        d = self.daemon()
        self.run_polls(d, [iv(pkts=9000, syn=300)])
        self.assertEqual([b["engine"] for b in d.bans()], ["l4_syn"])

    def test_the_ban_arms_the_cooldown(self):
        d = self.daemon()
        self.run_polls(d, [iv(pkts=6000)])
        self.assertEqual(d.volumetric_active_until, d.clock.now + 15.0)

    def test_gru_only_mode_disables_the_rule(self):
        d = self.daemon(GRU_ONLY="1")
        self.run_polls(d, [iv(pkts=60000)])
        self.assertEqual(d.bans(), [])


class SlowConnTest(DaemonCase):
    def idle(self, n, nbytes=100, **kw):
        return [iv(pkts=10, nbytes=nbytes, **kw)] * n

    def test_three_consecutive_idle_intervals_with_eight_connections_ban(self):
        d = self.daemon()
        self.run_polls(d, self.idle(2), conns=8)
        self.assertEqual(d.bans(), [])
        d = self.daemon()
        self.run_polls(d, self.idle(3), conns=8)
        self.assertEqual(len(d.bans()), 1)
        ban = d.bans()[0]
        self.assertEqual((ban["engine"], ban["value"], ban["threshold"], ban["bytes"]),
                         ("l4_slowconn", 8, 8, 100))
        self.assertEqual(d.proc.matching("ss", "-K"), [["ss", "-K", "dst", IP]])

    def test_seven_connections_are_never_enough(self):
        d = self.daemon()
        self.run_polls(d, self.idle(12), conns=7)
        self.assertEqual(d.bans(), [])

    def test_the_byte_limit_is_strict(self):
        for nbytes, banned in ((249, True), (250, False)):
            with self.subTest(nbytes=nbytes):
                d = self.daemon()
                self.run_polls(d, self.idle(3, nbytes=nbytes), conns=8)
                self.assertEqual(len(d.bans()), 1 if banned else 0)

    def test_one_busy_interval_resets_the_count(self):
        d = self.daemon()
        seq = self.idle(2) + self.idle(1, nbytes=300) + self.idle(2)
        self.run_polls(d, seq, conns=8)
        self.assertEqual(d.bans(), [])
        d = self.daemon()
        self.run_polls(d, seq + self.idle(1), conns=8)          # third idle one since the reset
        self.assertEqual(len(d.bans()), 1)

    def test_an_interval_without_new_packets_still_counts(self):
        d = self.daemon()
        self.run_polls(d, [iv(pkts=1)] + [iv()] * 2, conns=8)
        self.assertEqual(len(d.bans()), 1)

    def test_a_steady_trickle_resets_the_count_weakness(self):
        # Audit G-19: the 3-interval streak restarts on any interval with 250 bytes or more. A
        # bot that holds 8+ connections and sends one 300-byte request in every third interval
        # is never banned, however long it keeps this up.
        d = self.daemon()
        cycle = self.idle(2) + self.idle(1, nbytes=300)
        self.run_polls(d, cycle * 8, conns=40)
        self.assertEqual(d.bans(), [])

    def test_the_tolerant_threshold_does_not_see_the_suites_slow_attacks(self):
        # 8 (Slowloris) and 10 (R.U.D.Y.) sockets per bot, against 180 (REPORT 9.6, EXP-B).
        d = self.daemon(HEURISTIC_PROFILE="tolerant")
        self.run_polls(d, self.idle(12), conns=10)
        self.assertEqual(d.bans(), [])

    def test_gru_only_mode_disables_the_rule(self):
        d = self.daemon(GRU_ONLY="1")
        self.run_polls(d, self.idle(5), conns=8)
        self.assertEqual(d.bans(), [])


class LowSynTest(DaemonCase):
    syns = staticmethod(lambda n, syn=3: [iv(pkts=syn, syn=syn)] * n)

    def test_four_consecutive_intervals_of_syns_without_a_handshake_ban(self):
        d = self.daemon()
        self.run_polls(d, self.syns(3))
        self.assertEqual(d.bans(), [])
        d = self.daemon()
        self.run_polls(d, self.syns(4))
        self.assertEqual([self.brief(b) for b in d.bans()],
                         [{"ip": IP, "engine": "l4_lowsyn", "value": 3, "threshold": 3}])

    def test_two_syns_per_interval_are_below_the_minimum(self):
        d = self.daemon()
        self.run_polls(d, self.syns(20, syn=2))
        self.assertEqual(d.bans(), [])

    def test_an_interval_below_the_minimum_resets_the_streak(self):
        seq = self.syns(2) + self.syns(1, syn=2) + self.syns(3)
        d = self.daemon()
        self.run_polls(d, seq)
        self.assertEqual(d.bans(), [])
        d = self.daemon()
        self.run_polls(d, seq + self.syns(1))
        self.assertEqual(len(d.bans()), 1)

    def test_a_recent_handshake_exempts_the_ip_for_fifteen_seconds(self):
        # Interval 1 shows an established connection at t=1001. The grace runs to t=1016
        # inclusive; the first interval outside it is the 17th, and the streak needs 4.
        conns = [1] + [0] * 19
        d = self.daemon()
        self.run_polls(d, self.syns(19), conns=conns[:19])
        self.assertEqual(d.bans(), [])
        d = self.daemon()
        self.run_polls(d, self.syns(20), conns=conns)
        self.assertEqual([b["engine"] for b in d.bans()], ["l4_lowsyn"])
        self.assertEqual(d.clock.now, 1020.0)

    def test_an_ip_with_an_established_connection_is_not_low_and_slow(self):
        d = self.daemon()
        self.run_polls(d, self.syns(30), conns=1)
        self.assertEqual(d.bans(), [])

    def test_gru_only_mode_disables_the_rule(self):
        d = self.daemon(GRU_ONLY="1")
        self.run_polls(d, self.syns(8))
        self.assertEqual(d.bans(), [])


class GlobalFloodTest(DaemonCase):
    def spread(self, d, n_ips, **per_ip):
        """Counters for n_ips distinct sources, each below every per-IP threshold."""
        for i in range(n_ips):
            d.telemetry.add(f"10.1.{i // 250}.{i % 250 + 1}", **per_ip)

    def test_syn_cookies_are_enabled_once_and_the_flag_resets_at_half(self):
        d = self.daemon()

        def setup(k):
            if k in (1, 2, 4):
                self.spread(d, 30, pkts=190, syn=190)          # 5700 SYN in total, 190 each
        d.poll(4, setup)
        self.assertEqual(d.bans(), [])
        # Interval 1 enables; 2 is still high (no second call); 3 is quiet and resets the
        # flag; 4 is high again and enables again.
        self.assertEqual(d.proc.matching("sysctl"),
                         [["sysctl", "-w", "net.ipv4.tcp_syncookies=1"]] * 2)

    def test_the_global_syn_threshold_is_strict(self):
        for extra, enabled in ((0, False), (1, True)):
            with self.subTest(total=5000 + extra):
                d = self.daemon()
                self.spread(d, 25, pkts=200, syn=200)                 # 5000, 200 each: no per-IP ban
                if extra:
                    d.telemetry.add("10.9.9.9", pkts=1, syn=1)
                d.poll(1)
                self.assertEqual(d.bans(), [])
                self.assertEqual(len(d.proc.matching("sysctl")), 1 if enabled else 0)
                self.assertEqual(d.syn_cookies_enabled, enabled)

    def test_the_syn_cookie_flag_resets_at_half_the_threshold(self):
        d = self.daemon()
        self.spread(d, 30, pkts=190, syn=190)
        d.poll(1)
        self.assertTrue(d.syn_cookies_enabled)
        for total, still in ((2501, True), (2500, False)):
            with self.subTest(total=total):
                self.spread(d, 13, pkts=192, syn=192)                 # 2496
                d.telemetry.add("10.9.9.9", pkts=total - 2496, syn=total - 2496)
                d.poll(1)
                self.assertEqual(d.syn_cookies_enabled, still)

    def test_the_global_packet_threshold_is_strict(self):
        for extra, suppressed in ((0, False), (1, True)):
            with self.subTest(total=50000 + extra):
                d = self.daemon()
                self.spread(d, 20, pkts=2500)                         # 50 000, 2500 each
                if extra:
                    d.telemetry.add("10.9.9.9", pkts=1)
                d.poll(1)
                self.assertEqual(d.bans(), [])
                self.assertEqual(len(d.events("suppress_on")), 1 if suppressed else 0)

    def test_the_volumetric_cooldown_is_announced_and_lifted_after_fifteen_seconds(self):
        # Interval 1 (t=1001) sees 80 000 packets and arms the cooldown until t=1016; the
        # event for the end of it comes in the interval that starts at t=1016, the 16th.
        for polls, kinds in ((15, ["suppress_on"]), (16, ["suppress_on", "suppress_off"])):
            with self.subTest(polls=polls):
                d = self.daemon()
                self.spread(d, 20, pkts=4000)
                d.poll(polls)
                self.assertEqual([e["kind"] for e in d.events("suppress_on", "suppress_off")],
                                 kinds)


class BanIpTest(DaemonCase):
    def test_xdp_backend(self):
        d = self.daemon()
        d.call("ban_ip", IP, reason="because", engine="l4_syn", value=7, threshold=5)
        self.assertEqual(d.blacklist.ips(), {IP})
        self.assertEqual(d.proc.calls, [])
        self.assertEqual(d.banned_ips, {IP})
        self.assertEqual(d.ban_timestamps, {IP: d.clock.now})
        [ban] = d.bans()
        self.assertEqual({k: ban[k] for k in ban if not k.startswith("t_")},
                         {"kind": "ban", "ip": IP, "engine": "l4_syn", "reason": "because",
                          "backend": "xdp", "enforced": True, "ttl_s": 300, "value": 7,
                          "threshold": 5})

    def test_the_console_line_the_suite_parses(self):
        d = self.daemon()
        d.call("ban_ip", IP, reason="Per-IP SYN flood (201 SYN/s)", engine="l4_syn")
        self.assertIn(f"[BAN] {IP} banned for 300s. Reason: Per-IP SYN flood (201 SYN/s)",
                      d.console())

    def test_iptables_backend_issues_one_drop_rule(self):
        d = self.daemon(MITIGATION_BACKEND="iptables")
        d.call("ban_ip", IP, reason="r", engine="l4_syn")
        self.assertEqual(d.proc.calls, [["ip", "netns", "exec", "server_ns", "iptables", "-A",
                                         "INPUT", "-s", IP, "-j", "DROP"]])
        self.assertEqual(d.proc.checks, [True])
        self.assertEqual(d.blacklist.ips(), set())
        self.assertEqual(d.bans()[0]["backend"], "iptables")

    def test_a_failed_iptables_call_is_recorded_as_a_ban_weakness(self):
        # The event says enforced=false, but the IP is in banned_ips: every engine skips it
        # from now on, so a source whose rule never went in is neither blocked nor re-detected
        # until the TTL runs out.
        d = self.daemon(MITIGATION_BACKEND="iptables")
        d.proc.failures[("ip", "netns")] = 1
        d.call("ban_ip", IP, reason="r", engine="l4_syn")
        [ban] = d.bans()
        self.assertFalse(ban["enforced"])
        self.assertIn(IP, d.banned_ips)
        self.run_polls(d, [iv(pkts=900, syn=900)])             # the same source keeps flooding
        self.assertEqual(len(d.bans()), 1)

    def test_banning_twice_adds_two_iptables_rules_and_removes_one_weakness(self):
        # F-18: ban_ip does not de-duplicate. banned_ips and ban_timestamps hold one entry per
        # IP, so the TTL sweep deletes one rule and the other keeps dropping the source.
        d = self.daemon(MITIGATION_BACKEND="iptables")
        d.call("ban_ip", IP, reason="r", engine="l4_syn")
        d.call("ban_ip", IP, reason="r", engine="l7_rate")
        d.clock.now += 301.0
        d.call("unblock_expired_bans")
        verbs = [c[5] for c in d.proc.calls if c[:5] == ["ip", "netns", "exec", "server_ns",
                                                         "iptables"]]
        self.assertEqual(verbs, ["-A", "-A", "-D"])


class TtlTest(DaemonCase):
    def test_a_ban_expires_after_more_than_the_ttl(self):
        d = self.daemon()
        d.call("ban_ip", IP, reason="r", engine="l4_syn")
        d.clock.now += 300.0
        d.call("unblock_expired_bans")
        self.assertIn(IP, d.banned_ips)                          # exactly 300 s: still banned
        d.clock.now += 0.001
        d.call("unblock_expired_bans")
        self.assertNotIn(IP, d.banned_ips)
        self.assertEqual(d.blacklist.ips(), set())
        self.assertEqual(d.ban_timestamps, {})
        [unban] = d.events("unban")
        self.assertEqual((unban["ip"], unban["backend"]), (IP, "xdp"))
        self.assertAlmostEqual(unban["age_s"], 300.001, places=3)

    def test_an_expired_ban_whose_rule_is_already_gone_is_still_removed(self):
        d = self.daemon()
        d.call("ban_ip", IP, reason="r", engine="l4_syn")
        d.blacklist.entries.clear()
        d.clock.now += 301.0
        d.call("unblock_expired_bans")
        self.assertEqual(d.banned_ips, set())
        self.assertEqual(len(d.events("unban")), 1)

    def test_iptables_backend_deletes_the_rule_without_checking_the_result(self):
        d = self.daemon(MITIGATION_BACKEND="iptables")
        d.call("ban_ip", IP, reason="r", engine="l4_syn")
        d.clock.now += 301.0
        d.call("unblock_expired_bans")
        self.assertEqual(d.proc.calls[-1], ["ip", "netns", "exec", "server_ns", "iptables",
                                            "-D", "INPUT", "-s", IP, "-j", "DROP"])
        self.assertEqual(d.proc.checks[-1], False)

    def test_an_unbanned_source_can_be_banned_again(self):
        d = self.daemon()
        self.run_polls(d, [iv(pkts=300, syn=300)])
        d.clock.now += 301.0
        d.call("unblock_expired_bans")
        self.run_polls(d, [iv(pkts=300, syn=300)])
        self.assertEqual(len(d.bans()), 2)

    def test_idle_clients_are_forgotten_after_a_minute(self):
        d = self.daemon()
        self.run_polls(d, [iv(pkts=10)])                       # seen at t=1001
        self.assertIn(IP, d.client_last_seen)
        d.clock.now += 60.0
        d.call("evict_idle_clients")
        self.assertIn(IP, d.client_last_seen)                    # exactly 60 s: kept
        d.clock.now += 0.5
        d.call("evict_idle_clients")
        self.assertNotIn(IP, d.client_last_seen)
        self.assertNotIn(IP, d.prev_telemetry)
        self.assertEqual(d.telemetry.counters, {})


class EstablishedConnectionsTest(DaemonCase):
    def parse(self, text):
        d = self.daemon()
        d.proc.ss_established = text
        return dict(d.call("get_established_conns_by_ip"))

    def test_counts_connections_to_the_public_ports_by_peer(self):
        text = ("ESTAB 0 0 10.0.0.1:80 10.0.2.1:50000\n"
                "ESTAB 0 0 10.0.0.1:80 10.0.2.1:50001\n"
                "ESTAB 0 0 10.0.0.1:443 10.0.2.1:50002\n"
                "ESTAB 0 0 10.0.0.1:80 10.0.2.2:50000\n")
        self.assertEqual(self.parse(text), {"10.0.2.1": 3, "10.0.2.2": 1})

    def test_other_local_ports_are_ignored(self):
        text = ("ESTAB 0 0 10.0.0.1:8080 10.0.2.1:50000\n"
                "ESTAB 0 0 10.0.0.1:5000 10.0.2.1:50001\n"
                "ESTAB 0 0 127.0.0.1:8000 127.0.0.1:60000\n")
        self.assertEqual(self.parse(text), {})

    def test_the_state_column_is_optional(self):
        self.assertEqual(self.parse("0 0 10.0.0.1:80 10.0.2.1:50000\n"), {"10.0.2.1": 1})

    def test_short_and_blank_lines_are_skipped(self):
        self.assertEqual(self.parse("\nESTAB\n\n0 0 10.0.0.1:80 10.0.2.1:50000\n"),
                         {"10.0.2.1": 1})

    def test_ipv6_peers_are_counted_by_their_bracketless_address(self):
        text = "ESTAB 0 0 [2001:db8::2]:80 [2001:db8::1]:51000\n"
        self.assertEqual(self.parse(text), {"2001:db8::1": 1})

    def test_a_missing_or_slow_ss_gives_no_connections(self):
        d = self.daemon()
        d.proc.failures[("ss",)] = FileNotFoundError("ss")
        self.assertEqual(dict(d.call("get_established_conns_by_ip")), {})
        d.proc.failures[("ss",)] = d.proc.TimeoutExpired(["ss"], 2)
        self.assertEqual(dict(d.call("get_established_conns_by_ip")), {})


class L7RateRuleTest(DaemonCase):
    """The rate and error-ratio rule of the main log loop: the daemon's own loop body, fed
    with lines. The clock moves by the first element of each request."""

    @staticmethod
    def steady(n, dt, status=200, ip=IP):
        return [(dt, ip, status)] * n

    def banned(self, d):
        return [self.brief(b) for b in d.bans()]

    def test_fifty_requests_in_half_a_second_pass_the_fifty_first_is_banned(self):
        d = self.daemon()
        d.l7_requests(self.steady(50, 0.01))
        self.assertEqual(d.bans(), [])
        d = self.daemon()
        d.l7_requests(self.steady(51, 0.01))
        self.assertEqual(self.banned(d),
                         [{"ip": IP, "engine": "l7_rate", "value": 51.0, "threshold": 50}])
        self.assertEqual(d.bans()[0]["error_ratio"], 0.0)

    def test_the_window_is_clamped_to_one_second(self):
        # Five requests in 40 ms are 5 rps, not 125 (the burst guard of the audit's section 3).
        d = self.daemon()
        d.l7_requests(self.steady(5, 0.01))
        self.assertEqual(d.bans(), [])

    def test_a_sustained_rate_is_judged_over_the_ten_second_window(self):
        d = self.daemon()
        d.l7_requests(self.steady(1200, 0.025))                 # 40 rps for 30 s
        self.assertEqual(d.bans(), [])
        d = self.daemon()
        d.l7_requests(self.steady(1200, 1 / 60))                # 60 rps
        self.assertEqual(len(d.bans()), 1)
        self.assertLess(d.ban_timestamps[IP] - 1000.0, 1.0)     # at the 51st request, 0.83 s in

    def test_fewer_than_five_requests_never_ban(self):
        # HEURISTIC_MIN_REQUESTS is redundant today: with the one-second clamp, n < 5 requests
        # are at most 4 rps, below both the 50 rps and the "more than 10 rps" conditions.
        d = self.daemon()
        d.l7_requests([(0.001, IP, 500)] * 4)
        self.assertEqual(d.bans(), [])

    def test_error_ratio_needs_more_than_ten_requests_per_second(self):
        d = self.daemon()
        d.l7_requests(self.steady(10, 0.04, status=404))         # 100 % errors, 10 rps
        self.assertEqual(d.bans(), [])
        d = self.daemon()
        d.l7_requests(self.steady(11, 0.04, status=404))         # 11 rps
        self.assertEqual(self.banned(d)[0]["engine"], "l7_rate")
        self.assertEqual(d.bans()[0]["error_ratio"], 1.0)

    def test_error_ratio_must_be_strictly_above_eighty_percent(self):
        reqs = [(0.01, IP, 200)] * 3 + [(0.01, IP, 404)] * 12   # 12 of 15 = 0.8
        d = self.daemon()
        d.l7_requests(reqs)
        self.assertEqual(d.bans(), [])
        d = self.daemon()
        d.l7_requests(reqs + [(0.01, IP, 404)])                  # 13 of 16 = 0.8125
        self.assertEqual(len(d.bans()), 1)

    def test_503_is_not_a_client_error_and_399_is_not_an_error(self):
        d = self.daemon()
        d.l7_requests(self.steady(40, 0.01, status=503))
        d.l7_requests(self.steady(40, 0.01, status=399, ip=OTHER))
        self.assertEqual(d.bans(), [])
        d = self.daemon()
        d.l7_requests(self.steady(11, 0.04, status=400))
        self.assertEqual(len(d.bans()), 1)

    def test_a_ban_stops_the_evaluation_and_drops_the_tracking(self):
        d = self.daemon()
        d.l7_requests(self.steady(120, 0.005))
        self.assertEqual(len(d.bans()), 1)
        self.assertNotIn(IP, d.request_tracker)
        self.assertEqual(d.proc.matching("ss", "-K"), [["ss", "-K", "dst", IP]])

    def test_each_ip_is_judged_on_its_own_requests(self):
        d = self.daemon()
        both = []
        for _ in range(30):
            both += [(0.005, IP, 200), (0.005, OTHER, 200)]
        d.l7_requests(both)                                       # 30 requests each in 0.3 s
        self.assertEqual(d.bans(), [])

    def test_malformed_lines_are_ignored_and_a_missing_status_means_200(self):
        d = self.daemon()
        d.l7_requests(["not json\n", "{\n", '{"client_ip": "10.0.2.1"}\n'] * 20)
        self.assertEqual(d.bans(), [])

    def test_gru_only_mode_disables_the_rule(self):
        d = self.daemon(GRU_ONLY="1")
        d.l7_requests(self.steady(200, 0.005))
        self.assertEqual(d.bans(), [])

    def test_the_tolerant_profile_allows_up_to_108_requests_per_second(self):
        d = self.daemon(HEURISTIC_PROFILE="tolerant")
        d.l7_requests(self.steady(100, 0.005))                    # 100 in half a second
        self.assertEqual(d.bans(), [])
        d.l7_requests(self.steady(20, 0.005))                     # the 109th and on
        self.assertEqual(len(d.bans()), 1)
        self.assertEqual(d.bans()[0]["threshold"], 108)


class RudyRuleTest(DaemonCase):
    def feed(self, d, advances, ip=IP):
        d.rudy_lines([(dt, RUDY_TIMEOUT.format(ip=ip)) for dt in advances])

    def test_three_body_timeouts_within_a_minute_ban(self):
        d = self.daemon()
        self.feed(d, [0, 1, 1])
        self.assertEqual([self.brief(b) for b in d.bans()],
                         [{"ip": IP, "engine": "l7_rudy", "value": 3, "threshold": 3}])
        self.assertEqual(d.proc.matching("ss", "-K"), [["ss", "-K", "dst", IP]])
        self.assertNotIn(IP, d.rudy_tracker)

    def test_two_are_not_enough(self):
        d = self.daemon()
        self.feed(d, [0, 1])
        self.assertEqual(d.bans(), [])

    def test_the_window_is_sixty_seconds_inclusive(self):
        d = self.daemon()
        self.feed(d, [0, 30, 30])                                 # 60 s from the first: kept
        self.assertEqual(len(d.bans()), 1)
        d = self.daemon()
        self.feed(d, [0, 30, 31])                                 # 61 s: the first drops out
        self.assertEqual(d.bans(), [])

    def test_timeouts_are_counted_per_ip(self):
        d = self.daemon()
        d.rudy_lines([(0, RUDY_TIMEOUT.format(ip=IP)), (1, RUDY_TIMEOUT.format(ip=OTHER)),
                      (1, RUDY_TIMEOUT.format(ip=IP))])
        self.assertEqual(d.bans(), [])

    def test_lines_of_a_banned_ip_are_ignored(self):
        d = self.daemon()
        self.feed(d, [0, 1, 1, 1, 1, 1, 1])
        self.assertEqual(len(d.bans()), 1)

    def test_only_body_read_timeouts_match(self):
        # Three copies of each line: only the first kind reaches the ban threshold. In
        # particular the 413 of an oversized body and the header timeouts of Slowloris do not
        # count, so Nginx's own limits hide a slow POST from this rule.
        lines = {
            "body timeout": (RUDY_TIMEOUT.format(ip=IP), True),
            "header timeout (Slowloris)": (RUDY_HEADER_TIMEOUT, False),
            "too large body (413)": (RUDY_TOO_LARGE, False),
            "ipv6 client": (RUDY_IPV6, False),
        }
        for name, (line, matches) in lines.items():
            with self.subTest(name):
                d = self.daemon()
                d.rudy_lines([(0, line)] * 3)
                self.assertEqual(len(d.bans()), 1 if matches else 0)

    def test_gru_only_mode_disables_the_rule(self):
        d = self.daemon(GRU_ONLY="1")
        self.feed(d, [0, 1, 1, 1])
        self.assertEqual(d.bans(), [])


if __name__ == "__main__":
    unittest.main()
