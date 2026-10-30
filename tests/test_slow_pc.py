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


if __name__ == "__main__":
    unittest.main()
