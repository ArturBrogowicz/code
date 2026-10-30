"""The per-connection slow rule of P4 (slow_pc.py; docs/P4_SLOW_DESIGN.md §6-§7, §9): the reader
of `ss -tinpH` and the detector, on fakes. Pure: no `ss`, no clock, no daemon.

The token layout of `ss -tinpH` is the one F-S3 names (the manual page of iproute2 6.19.0 and the
strings of /usr/bin/ss); a fixture recorded on the VM in the pilot confirms it [NOT RUN].
"""
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
import slow_pc as P

NGINX = 'users:(("nginx",pid=4242,fd=17))'


def sock_text(ip="10.0.2.7", port=40001, sport=80, owner=NGINX, local="10.0.0.1", state="",
              **info):
    """One socket as `ss -tinpH state established` prints it: the socket line (no State
    column unless `state`), then the tcp_info line indented by a tab. A field of `info`
    that is None is not printed, as ss omits a counter that is zero."""
    fields = {"bytes_sent": 0, "bytes_acked": 1, "bytes_received": 0, "segs_out": 2,
              "segs_in": 3, "data_segs_in": 0, "lastsnd": 900, "lastrcv": 900,
              "lastack": 900, "rcv_space": 14480}
    fields.update(info)
    tcp = " ".join(f"{k}:{v}" for k, v in fields.items() if v is not None)
    head = f"{state + ' ' if state else ''}0      0      {local}:{sport}   {ip}:{port} {owner}"
    return f"{head.rstrip()}\n\t cubic wscale:7,7 rto:204 rtt:0.05/0.025 mss:1448 {tcp} send 2.3Gbps app_limited\n"


class ParseTest(unittest.TestCase):
    def test_a_socket_and_its_tcp_info(self):
        socks, present, skipped, bad = P.parse_ss(sock_text(bytes_received=231, data_segs_in=4,
                                                            bytes_acked=1, notsent=0))
        [s] = socks
        self.assertEqual((s.ip, s.port, s.local, s.sport, s.owned),
                         ("10.0.2.7", 40001, "10.0.0.1", 80, True))
        self.assertEqual((s.info["bytes_received"], s.info["data_segs_in"],
                          s.info["bytes_acked"], s.info["rcv_space"], s.info["lastrcv"]),
                         (231, 4, 1, 14480, 900))
        self.assertEqual(present, {("10.0.2.7", 40001, "10.0.0.1", 80)})
        self.assertEqual((skipped, bad), (0, None))
        self.assertEqual(s.key, ("10.0.2.7", 40001, "10.0.0.1", 80))

    def test_a_token_ss_does_not_print_counts_as_zero(self):
        [s], *_ = P.parse_ss(sock_text(bytes_acked=None, bytes_received=None, data_segs_in=None,
                                       bytes_sent=None))
        self.assertEqual({k: s.info[k] for k in ("bytes_acked", "bytes_received",
                                                  "data_segs_in", "bytes_sent", "notsent")},
                         dict.fromkeys(("bytes_acked", "bytes_received", "data_segs_in",
                                        "bytes_sent", "notsent"), 0))

    def test_a_socket_no_process_holds_is_in_the_backlog(self):
        [s], *_ = P.parse_ss(sock_text(owner=""))
        self.assertFalse(s.owned)
        [s], *_ = P.parse_ss(sock_text(owner='users:(("python3",pid=7,fd=3))'))
        self.assertFalse(s.owned)
        [s], *_ = P.parse_ss(sock_text(owner='users:(("nginx",pid=8,fd=9),("nginx",pid=7,fd=9))'))
        self.assertTrue(s.owned)

    def test_layout_variants(self):
        with_state = sock_text(state="ESTAB")
        one_line = sock_text().replace("\n\t", " ")              # ss -O prints one line
        mapped = sock_text(ip="[::ffff:10.0.2.9]", local="[::ffff:10.0.0.1]")
        for text, ip in ((with_state, "10.0.2.7"), (one_line, "10.0.2.7"), (mapped, "10.0.2.9")):
            with self.subTest(text=text[:40]):
                [s], _present, skipped, _bad = P.parse_ss(text)
                self.assertEqual((s.ip, s.local, s.sport, s.owned, skipped),
                                 (ip, "10.0.0.1", 80, True, 0))
                self.assertEqual(s.info["rcv_space"], 14480)

    def test_many_sockets_keep_their_own_fields(self):
        text = "".join(sock_text(port=40000 + i, sport=(80, 443)[i % 2], bytes_received=i)
                       for i in range(50))
        socks, present, skipped, _bad = P.parse_ss(text)
        self.assertEqual(([s.port for s in socks], [s.info["bytes_received"] for s in socks]),
                         (list(range(40000, 40050)), list(range(50))))
        self.assertEqual((len(present), skipped), (50, 0))
        self.assertEqual({s.sport for s in socks}, {80, 443})

    def test_unreadable_sockets_are_skipped_counted_and_sampled(self):
        good = sock_text(port=40001)
        cases = {
            "IPv6 client": sock_text(ip="[2001:db8::1]", local="[2001:db8::2]"),
            "not an address": sock_text(ip="10.0.2.300"),
            "leading zero": sock_text(ip="10.0.2.07"),
            "port too large": sock_text(port=70000),
            "port of other digits": sock_text().replace(":40001", ":４0001"),
            "port of 6 digits": sock_text(port="000080"),
            "private listener": sock_text(sport=8080),
            "garbled users": sock_text(owner='users:(("nginx",pid=x))'),
            "one column": "garbage\n",
            "a repeated socket": good,
        }
        for name, text in cases.items():
            with self.subTest(name):
                socks, present, skipped, bad = P.parse_ss(good + text)
                self.assertEqual(([s.port for s in socks], skipped), ([40001], 1))
                self.assertEqual(bad, (good + text).splitlines()[2][:160])
                self.assertIn(("10.0.2.7", 40001, "10.0.0.1", 80), present)

    def test_a_malformed_token_leaves_the_socket_present_but_unjudged(self):
        for token in ("bytes_received:12x", "data_segs_in:-1", "bytes_acked:" + "9" * 21,
                      "bytes_acked:１２"):
            with self.subTest(token):
                text = sock_text(bytes_received=None, bytes_acked=None, data_segs_in=None)
                text = text.replace("send 2.3Gbps", token + " send 2.3Gbps")
                socks, present, skipped, bad = P.parse_ss(text)
                self.assertEqual((socks, skipped), ([], 1))
                self.assertEqual(present, {("10.0.2.7", 40001, "10.0.0.1", 80)})
                self.assertTrue(bad.startswith("0 "))

    def test_blank_lines_a_stray_info_line_and_long_garbage_do_not_raise(self):
        text = "\n\t bytes_acked:5\n\n" + "x" * 5000 + "\n" + sock_text() + "   \n"
        socks, present, skipped, bad = P.parse_ss(text)
        self.assertEqual((len(socks), len(present), skipped, bad), (1, 1, 2, "\t bytes_acked:5"))
        self.assertEqual(P.parse_ss("x" * 5000 + "\n")[2:], (1, "x" * 160))
        self.assertEqual(P.parse_ss(""), ([], set(), 0, None))

    def test_the_reader_command(self):
        self.assertEqual(P.SS_ARGV, ["ss", "-tinpH", "state", "established",
                                     "( sport = :80 or sport = :443 )"])


def loris(t, opened=0.5, gap=2.0, first=100, line=30):
    """tcp_info of a Slowloris connection at time t: a partial request when it opened, then
    one header line of `line` bytes every `gap` s, never an answer."""
    segs = 1 + int((t - opened) // gap)
    return {"bytes_acked": 1, "bytes_received": first + line * (segs - 1), "data_segs_in": segs}


class Sim:
    """Sockets whose counters are functions of the time, polled once a second from t=1."""

    def __init__(self, det):
        self.det, self.t, self.socks = det, 0.0, {}

    def add(self, ip, port, info, sport=80, owner=NGINX):
        """`info(t)` gives the tcp_info fields at time t."""
        self.socks[(ip, port, sport)] = (info, owner)

    def text(self):
        return "".join(sock_text(ip=ip, port=port, sport=sport, owner=owner, **info(self.t))
                       for (ip, port, sport), (info, owner) in self.socks.items())

    def step(self, items=(), banned=()):
        self.t += 1.0
        return self.det.poll(self.t, self.text(), items, banned)

    def run(self, n, **kw):
        return [self.step(**kw) for _ in range(n)]


def closes_at(results):
    """{poll number: closes in it}, for the polls that closed something."""
    return {i + 1: len(r.closes) for i, r in enumerate(results) if r.closes}


class DetectorLegsTest(unittest.TestCase):
    """The five legs (§6.2) and the persistence; each benign kind of §6.2 and §9 is spared by
    the leg named in its test."""

    def test_slowloris_is_closed_t_plus_three_polls_after_it_is_first_seen(self):
        for t_s in P.T_GRID_S:
            with self.subTest(T=t_s):
                sim = Sim(P.Detector(t_s, 256, 6))
                for i in range(6):
                    sim.add("10.0.3.1", 41000 + i, loris)
                # First seen at poll 1, so t - 1 s old at poll t: old (age > T) from poll T + 2,
                # and the third suspect poll in a row is poll T + 4.
                results = sim.run(t_s + 4)
                self.assertEqual(closes_at(results), {t_s + 4: 6})
                [r] = [r for r in results if r.closes]
                c = r.closes[0]
                self.assertEqual((c.ip, c.sport, c.age_s, c.streak, c.bytes_acked),
                                 ("10.0.3.1", 80, float(t_s + 3), 3, 1))
                self.assertEqual(r.bans, [P.Ban("10.0.3.1", 6, 0)])    # K = 6, no UA key

    def test_a_cgnat_pool_of_answered_idle_connections_is_never_suspect(self):
        # 72 keep-alive connections from one address, all answered (bytes_acked well over 64),
        # idle or still carrying requests: the old per-address rule bans this pool (P5c.1).
        sim = Sim(P.Detector(5, 1024, 2))
        for i in range(72):
            busy = i % 2
            sim.add("10.0.4.1", 42000 + i, lambda t, b=busy: {
                "bytes_acked": 5200, "bytes_received": 420 + 3 * int(t) * b,
                "data_segs_in": 1 + int(t) * b})
        results = sim.run(90)
        self.assertEqual(sum(len(r.closes) for r in results), 0)
        self.assertEqual(sim.det.stats["suspect"], 0)

    def test_a_cgnat_pool_on_443_is_answered_through_the_access_log(self):
        # F-S4: on :443 the TLS handshake answers every connection, so bytes cannot say
        # whether a request was served. The access log's (client, port) can.
        def busy(t):
            return {"bytes_acked": 4100, "bytes_received": 900 + 40 * int(t),
                    "data_segs_in": 3 + int(t)}
        for logged, expected in ((True, 0), (False, 24)):
            with self.subTest(logged=logged):
                sim = Sim(P.Detector(5, 1024, 6))
                for i in range(24):
                    sim.add("10.0.4.2", 43000 + i, busy, sport=443)
                other = [("10.0.9.9", 50000, 7, 0.9)]             # the log carries ports
                items = [("10.0.4.2", 43000 + i, 7, 0.9) for i in range(24)] if logged else other
                results = [sim.step(items=items)] + sim.run(30)
                self.assertEqual(sum(len(r.closes) for r in results), expected)

    def test_a_legitimate_slow_uploader_above_f_is_spared_by_the_rate_leg(self):
        # 16 kbit/s = 2,000 B/s: unanswered and dribbling for its whole upload, but above every
        # F of the grid.
        for f in P.F_GRID_BPS:
            with self.subTest(F=f):
                sim = Sim(P.Detector(5, f, 2))
                sim.add("10.0.5.1", 44000, lambda t: {"bytes_acked": 1,
                                                       "bytes_received": 600 + 2000 * int(t),
                                                       "data_segs_in": 2 + 2 * int(t)})
                self.assertEqual(closes_at(sim.run(60)), {})

    def test_slow_post_below_f_is_closed(self):
        # 230 bytes of headers, then 16 bytes of a declared 100 KB body every 3 s (§5). Its
        # mean rate falls below F = 16 B/s at poll 23 (342 B in 22 s); closed at poll 25.
        sim = Sim(P.Detector(10, 16, 2))
        sim.add("10.0.6.1", 45000, lambda t: loris(t, gap=3.0, first=230, line=16))
        results = sim.run(40)
        self.assertEqual(closes_at(results), {25: 1})
        c = results[24].closes[0]
        self.assertEqual((c.bytes_received, c.age_s), (358, 24.0))

    def test_a_request_waiting_on_a_slow_server_is_spared_by_the_dribble_leg(self):
        # F-S6: its whole request arrived before the first poll; it then waits for an answer
        # with zero response bytes and a falling byte rate, but nothing more arrives.
        for segs_before in (1, 2):
            with self.subTest(segments=segs_before):
                sim = Sim(P.Detector(5, 1024, 2))
                sim.add("10.0.7.1", 46000, lambda t, n=segs_before: {
                    "bytes_acked": 1, "bytes_received": 380, "data_segs_in": n})
                self.assertEqual(closes_at(sim.run(60)), {})
                self.assertEqual(sim.det.stats["suspect"], 0)

    def test_a_backlog_socket_is_never_a_candidate(self):
        # F-S5: when nginx's slots are full, a client completes the handshake into the listen
        # backlog; no nginx process holds the socket yet.
        sim = Sim(P.Detector(5, 1024, 2))
        sim.add("10.0.8.1", 47000, loris, owner="")
        self.assertEqual(closes_at(sim.run(40)), {})
        sim.socks[("10.0.8.1", 47000, 80)] = (loris, NGINX)       # accepted at poll 41
        self.assertEqual(closes_at(sim.run(3)), {3: 1})             # its age runs from poll 1

    def test_443_answered_only_by_the_handshake_is_suspect_when_the_other_legs_hold(self):
        sim = Sim(P.Detector(5, 1024, 2))
        sim.add("10.0.9.1", 48000, lambda t: {**loris(t), "bytes_acked": 3100}, sport=443)
        first = sim.step(items=[("10.0.9.9", 50000, 7, 0.9)])    # another client's request
        self.assertEqual(closes_at([first, *sim.run(9)]), {9: 1})

    def test_443_is_judged_only_once_the_access_log_has_shown_a_client_port(self):
        # A log format without the client port (the deployed json_ml_format) cannot answer any
        # :443 connection, so none is judged unanswered until a record with a port arrives.
        for items, closed in (((), {}), ((("10.0.9.9", None, 7, 0.9),), {}),
                              ((("10.0.9.9", 50000, 7, 0.9),), {9: 1})):
            with self.subTest(items=items):
                sim = Sim(P.Detector(5, 1024, 2))
                sim.add("10.0.9.3", 48002, lambda t: {**loris(t), "bytes_acked": 3100},
                        sport=443)
                first = sim.step(items=items)
                self.assertEqual(closes_at([first, *sim.run(9)]), closed)
                self.assertEqual(sim.det.ports_seen, bool(closed))

    def test_the_access_log_answers_a_443_connection_only_during_its_lifetime(self):
        # A request of the same client port logged up to 2 s before the first poll that saw
        # the connection answers it (the poll's resolution); one logged 10 s before belongs to
        # an earlier connection.
        for logged_at, closed in ((-1.5, {}), (-2.0, {}), (-10.0, {9: 1})):
            with self.subTest(logged_at=logged_at):
                sim = Sim(P.Detector(5, 1024, 2))
                sim.add("10.0.9.2", 48001, lambda t: {**loris(t), "bytes_acked": 3100}, sport=443)
                first = sim.step(items=[("10.0.9.2", 48001, 7, 1.0 + logged_at)])
                self.assertEqual(closes_at([first, *sim.run(9)]), closed)

    def test_the_boundaries_of_each_leg(self):
        # At poll t the socket is t - 1 s old (first seen at poll 1). Legs, at T = 5 and
        # F = 64: age > T, bytes_acked <= 64, bytes_received < F x age, >= 2 data segments
        # since the first poll. The streak after each of 9 polls:
        def streaks(acked=64, rate=63.9, segs=2):
            det = P.Detector(5, 64, 2)
            sim = Sim(det)
            sim.add("10.0.10.1", 49000, lambda t: {
                "bytes_acked": acked, "bytes_received": int(rate * (t - 1)),
                "data_segs_in": 1 + (segs if t > 1 else 0)})
            out = []
            for _ in range(9):
                sim.step()
                out.append(det.conns[("10.0.10.1", 49000, "10.0.0.1", 80)].streak)
            return out
        self.assertEqual(streaks(), [0, 0, 0, 0, 0, 0, 1, 2, 3])   # age 5 is not > T; closed at 9
        self.assertEqual(streaks(acked=65), [0] * 9)
        self.assertEqual(streaks(rate=64), [0] * 9)
        self.assertEqual(streaks(segs=1), [0] * 9)


class DetectorGuardsTest(unittest.TestCase):
    """§6.3: what a garbled poll or a failed `ss` does to the streaks; the banned addresses."""

    def test_a_garbled_line_or_a_failed_ss_neither_resets_nor_advances_a_streak(self):
        for gap in ("garbled", "failed"):
            with self.subTest(gap):
                det = P.Detector(5, 256, 2)
                sim = Sim(det)
                sim.add("10.0.11.1", 50000, loris)
                sim.run(7)                                   # suspect from poll 7: streak 1
                sim.step()                                   # poll 8: streak 2
                self.assertEqual(det.conns[("10.0.11.1", 50000, "10.0.0.1", 80)].streak, 2)
                sim.t += 1.0
                if gap == "garbled":
                    r = det.poll(sim.t, sim.text().replace("bytes_received:", "bytes_received:x"))
                    self.assertEqual((r.closes, det.stats["skipped_lines"]), ([], 1))
                else:
                    det.skip(sim.t)
                    self.assertEqual(det.stats["ss_failed"], 1)
                self.assertEqual(det.conns[("10.0.11.1", 50000, "10.0.0.1", 80)].streak, 2)
                self.assertEqual(closes_at([sim.step()]), {1: 1})   # poll 10: streak 3

    def test_a_vanished_socket_is_forgotten_and_a_new_one_starts_young(self):
        det = P.Detector(5, 256, 2)
        sim = Sim(det)
        sim.add("10.0.11.2", 50001, loris)
        sim.run(6)
        info = sim.socks.pop(("10.0.11.2", 50001, 80))
        sim.step()
        self.assertEqual(det.conns, {})
        sim.socks[("10.0.11.2", 50001, 80)] = info
        self.assertEqual(closes_at(sim.run(9)), {9: 1})           # first seen again at poll 8

    def test_sockets_of_banned_addresses_are_not_judged(self):
        sim = Sim(P.Detector(5, 256, 2))
        for i in range(3):
            sim.add("10.0.11.3", 50010 + i, loris)
        self.assertEqual(closes_at(sim.run(20, banned={"10.0.11.3"})), {})
        self.assertEqual(sim.det.conns, {})

    def test_hostile_peer_addresses_are_skipped_and_sampled(self):
        det = P.Detector(5, 256, 2)
        text = sock_text(ip="[2001:db8::66]") + sock_text(ip="10.0.2.1;rm") + sock_text()
        r = det.poll(1.0, text)
        self.assertEqual((r.closes, len(det.conns), det.stats["skipped_lines"]), ([], 1, 2))
        stats = det.take_stats()
        self.assertTrue(stats["bad_sample"].startswith("0      0      10.0.0.1:80   [2001:db8::66]"))
        self.assertEqual((stats["skipped_lines"], det.take_stats()["bad_sample"]), (2, None))

    def test_a_close_that_left_the_socket_is_counted_as_failed(self):
        det = P.Detector(5, 256, 2)
        sim = Sim(det)
        for i in range(2):
            sim.add("10.0.11.4", 50020 + i, loris)
        [r] = [r for r in sim.run(9) if r.closes]
        det.closed([(c.ip, c.port, c.local, c.sport) for c in r.closes])
        sim.socks.pop(("10.0.11.4", 50020, 80))                   # one went, one stayed
        sim.step()
        self.assertEqual(det.stats["close_failed"], 1)
        sim.step()
        self.assertEqual(det.stats["close_failed"], 1)            # counted once

    def test_off_grid_thresholds_are_refused(self):
        for point in ((7, 64, 2), (5, 100, 2), (5, 64, 5)):
            with self.subTest(point=point), self.assertRaises(ValueError):
                P.Detector(*point)


class AddressAggregateTest(unittest.TestCase):
    """§7.2: an address is banned only after K closes within 60 s and only with fewer than 3
    UA keys in the access log over 10 minutes; caps; the rule's own bans and their TTL."""

    @staticmethod
    def loris_address(sim, ip, n, opened=0.5):
        for i in range(n):
            sim.add(ip, 51000 + i, lambda t, o=opened: loris(t, opened=o))

    def test_k_closes_within_the_window_ban_fewer_do_not(self):
        for k in P.K_GRID:
            with self.subTest(K=k):
                sim = Sim(P.Detector(5, 256, k))
                self.loris_address(sim, "10.0.12.1", k - 1)
                self.assertEqual([r.bans for r in sim.run(30) if r.bans], [])
                sim = Sim(P.Detector(5, 256, k))
                self.loris_address(sim, "10.0.12.1", k)
                self.assertEqual([r.bans for r in sim.run(30) if r.bans],
                                 [[P.Ban("10.0.12.1", k, 0)]])

    def test_closes_60_s_apart_add_up_61_s_apart_do_not(self):
        # The first connection is closed at poll 9; a second one first seen at poll s is
        # closed at poll s + 8.
        for second_seen, bans in ((61, [[P.Ban("10.0.12.2", 2, 0)]]), (62, [])):
            with self.subTest(apart=second_seen + 8 - 9):
                sim = Sim(P.Detector(5, 256, 2))
                sim.add("10.0.12.2", 52000, loris)
                sim.run(second_seen - 1)
                sim.add("10.0.12.2", 52001, loris)
                results = sim.run(10)
                self.assertEqual(closes_at(results), {9: 1})
                self.assertEqual([r.bans for r in results if r.bans], bans)

    def test_an_address_with_three_ua_keys_is_never_banned_its_connections_still_close(self):
        for keys, banned in ((2, True), (3, False)):
            with self.subTest(ua_keys=keys):
                sim = Sim(P.Detector(5, 256, 2))
                self.loris_address(sim, "10.0.12.3", 6)
                items = [("10.0.12.3", None, ua, 0.5) for ua in range(keys)]
                results = [sim.step(items=items), *sim.run(10)]
                self.assertEqual(sum(len(r.closes) for r in results), 6)
                self.assertEqual(bool([r for r in results if r.bans]), banned)
                spared = [b for r in results for b in r.spared]
                self.assertEqual(spared, [] if banned else [P.Ban("10.0.12.3", 6, 3)])

    def test_ua_keys_older_than_ten_minutes_do_not_count(self):
        sim = Sim(P.Detector(5, 256, 2))
        sim.t = 600.0
        self.loris_address(sim, "10.0.12.4", 2, opened=600.5)
        items = [("10.0.12.4", None, ua, 0.5) for ua in range(3)]   # logged 600.5 s earlier
        results = [sim.step(items=items), *sim.run(10)]
        self.assertEqual([b for r in results for b in r.bans], [P.Ban("10.0.12.4", 2, 0)])

    def test_a_banned_address_is_skipped_until_its_ttl_ends(self):
        # Banned at poll 9 and skipped while t <= 309; its sockets are new again at poll 310.
        # (They live through the ban only here: the daemon kills them, ss -K dst <ip>.)
        det = P.Detector(5, 1024, 2, ttl_s=300)
        sim = Sim(det)
        self.loris_address(sim, "10.0.12.5", 2)
        results = sim.run(400)
        bans = [(i + 1, r.bans) for i, r in enumerate(results) if r.bans]
        self.assertEqual(bans, [(9, [P.Ban("10.0.12.5", 2, 0)]),
                                (318, [P.Ban("10.0.12.5", 2, 0)])])

    def test_the_close_cap_and_the_ban_cap(self):
        # 250 addresses x 6 Slowloris connections (§9 case 2), all suspect at once.
        det = P.Detector(5, 256, 6)
        sim = Sim(det)
        for a in range(250):
            for i in range(6):
                sim.add(f"10.1.{a // 200}.{a % 200 + 1}", 53000 + i, loris)
        results = sim.run(80)
        self.assertEqual(closes_at(results), {9: 500, 10: 500, 11: 500})
        self.assertEqual([r.capped_closes for r in results[8:12]], [1000, 500, 0, 0])
        bans = {i + 1: len(r.bans) for i, r in enumerate(results) if r.bans}
        self.assertEqual(bans, {9: 20, 69: 20})                    # 20 in any 60 s
        # Poll 9 closes the 6 sockets of 83 addresses (the oldest first, then by key): 20 are
        # banned, 63 wait; the waiting ones are judged again each poll until their closes leave
        # the 60-s window.
        self.assertEqual(len(results[8].capped_bans), 63)
        self.assertEqual(det.stats["bans"], 40)


class L7ItemTest(unittest.TestCase):
    def test_the_daemons_log_and_the_l7_log(self):
        ua = "Mozilla/5.0 (X11; Linux x86_64)"
        h = P.l7_ingest.stable_hash32(ua)
        self.assertEqual(P.l7_item({"client_ip": "10.0.2.1", "user_agent": ua, "status": 200}, 5.0),
                         ("10.0.2.1", None, h, 5.0))
        self.assertEqual(P.l7_item({"ip": "10.0.2.1", "port": 41000, "ua": ua}, 5.0),
                         ("10.0.2.1", 41000, h, 5.0))
        self.assertEqual(P.l7_item({"client_ip": "10.0.2.1", "port": "41000"}, 5.0)[:3],
                         ("10.0.2.1", 41000, P.l7_ingest.stable_hash32("")))

    def test_unusable_fields(self):
        for obj in ([], "x", {"status": 200}, {"client_ip": None}, {"client_ip": 7},
                    {"client_ip": "2001:db8::1"}, {"client_ip": "10.0.2.1 "}):
            with self.subTest(obj=obj):
                self.assertIsNone(P.l7_item(obj, 1.0))
        for port in (True, 0, 70000, "4x", "１２", -1, 1.5, None, "9" * 30):
            with self.subTest(port=port):
                self.assertIsNone(P.l7_item({"client_ip": "10.0.2.1", "port": port}, 1.0)[1])
        self.assertEqual(P.l7_item({"client_ip": "10.0.2.1", "user_agent": ["x"]}, 1.0)[2],
                         P.l7_ingest.stable_hash32(""))


if __name__ == "__main__":
    unittest.main()
