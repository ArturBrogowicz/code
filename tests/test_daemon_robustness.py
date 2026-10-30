"""Robustness tests for the daemon (T-013: H-01 to H-03 of the 2026-10-29 review).

The real code of control_plane.py runs against the fakes of tests/daemon_harness.py, as in
tests/test_daemon_rules.py: nothing is imported from control_plane.py (it attaches XDP at
import), and nothing is attached, started or slept for real. Each test fails on the daemon
before the fix it covers.
"""
import contextlib
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, REPO)
import daemon_harness as H

IP = "10.0.2.1"
OTHER = "10.0.2.2"


def access_line(ip=IP, uri=b"/", agent=b"curl/8.5.0", status=200):
    """One line of nginx's json_ml_format (nginx.conf), as bytes. escape=json escapes '"', '\\'
    and bytes below 0x20 only, so whatever a client sends at or above 0x80 is written as it is."""
    return (b'{"timestamp":"2026-10-30T09:00:00+00:00","client_ip":"%s","request_method":"GET",'
            b'"request_uri":"%s","status":%d,"request_time":0.001,"request_length":80,'
            b'"bytes_sent":200,"user_agent":"%s"}\n' % (ip.encode(), uri, status, agent))


def body_timeout_line(ip=IP, uri=b"/"):
    """A body-read timeout in nginx's error log; the request line is logged unescaped."""
    return (b"2026/10/30 09:00:00 [info] 1234#1234: *5 client timed out (110: Connection timed "
            b"out) while reading client request body, client: %s, server: _, request: "
            b'"POST %s HTTP/1.1", host: "10.0.0.1"\n' % (ip.encode(), uri))


# 0xFF and 0x80 can never start a UTF-8 sequence; 0xE2 0x82 is a three-byte sequence cut short.
UNDECODABLE = {"0xFF": b"\xff", "0x80": b"\x80", "truncated": b"\xe2\x82"}


class DaemonCase(unittest.TestCase):
    def daemon(self, **env):
        d = H.Daemon(env)
        self.addCleanup(d.close)
        return d

    @staticmethod
    def tail(d, tailer, writes):
        """Run the daemon's real `tailer` over a real file that starts empty. The tailer opens
        it at its end; each time it then sleeps at end of file, the next chunk of `writes` is
        appended, and the sleep after the last one stops it. The access-log tailer is a
        generator: its lines are returned."""
        path = os.path.join(d._tmp.name, "tailed.log")
        with open(path, "wb"):
            pass
        pending = list(writes)

        def on_sleep(_k):
            if pending:
                with open(path, "ab") as fh:
                    fh.write(pending.pop(0))
            else:
                d.stop_event.set()

        d.stop_event.clear()
        d.clock.on_sleep = on_sleep
        try:
            with contextlib.redirect_stdout(d.out):
                result = d.ns[tailer](path)
                return list(result) if tailer == "tail_nginx_logs" else None
        finally:
            d.clock.on_sleep = None
            d.stop_event.clear()

    @staticmethod
    def l7_lines(d, lines, dt=0.01):
        """The real body of the main log loop over `lines`, the clock moving `dt` before each."""
        def paced():
            for line in lines:
                d.clock.now += dt
                yield line
        with contextlib.redirect_stdout(d.out):
            d._main_loop(paced())


class UndecodableBytesTest(DaemonCase):
    """H-01: one byte that is not UTF-8 made readline() raise UnicodeDecodeError in either tailer,
    which ended the R.U.D.Y. thread, or the main loop and with it the daemon (XDP detached)."""

    def test_the_access_log_tailer_reads_them_as_replacement_characters(self):
        for name, raw in UNDECODABLE.items():
            with self.subTest(name):
                d = self.daemon()
                lines = self.tail(d, "tail_nginx_logs", [access_line(agent=b"x" + raw + b"y"),
                                                         access_line(uri=b"/" + raw)])
                self.assertEqual(len(lines), 2)
                self.assertIn('"user_agent":"x�y"}', lines[0])
                self.assertIn('"request_uri":"/�"', lines[1])

    def test_a_line_with_replacement_characters_still_counts_for_the_rate_rule(self):
        # 51 requests in 0.51 s from one source, each with a 0xFF in its User-Agent: the
        # 51st is over 50 rps and bans, exactly as for clean lines.
        d = self.daemon()
        lines = self.tail(d, "tail_nginx_logs", [access_line(agent=b"bot\xff")] * 51)
        self.assertEqual(len(lines), 51)
        self.l7_lines(d, lines)
        self.assertEqual([(b["ip"], b["engine"], b["value"]) for b in d.bans()],
                         [(IP, "l7_rate", 51.0)])

    def test_a_character_cut_by_a_partial_write_is_skipped_like_any_partial_line(self):
        # The tailer can read a line that nginx has not finished writing. If the cut falls
        # inside a multi-byte character, even valid UTF-8 used to raise ("unexpected end of
        # data"). Now both fragments are malformed JSON and are skipped; the next line counts.
        d = self.daemon()
        line = access_line(agent="€".encode())             # the euro sign, E2 82 AC
        cut = line.index(b"\xe2\x82") + 2
        lines = self.tail(d, "tail_nginx_logs", [line[:cut], line[cut:], access_line(ip=OTHER)])
        self.assertEqual(len(lines), 3)
        self.assertTrue(lines[0].endswith('"user_agent":"�'))
        self.assertEqual(lines[1], '�"}\n')
        self.l7_lines(d, lines)
        self.assertEqual(list(d.request_tracker), [OTHER])
        self.assertNotIn("Loop error", d.console())

    def test_the_error_log_tailer_reads_them_and_still_bans_rudy(self):
        for name, raw in UNDECODABLE.items():
            with self.subTest(name):
                d = self.daemon()
                self.tail(d, "tail_nginx_error_logs", [body_timeout_line(uri=b"/" + raw)] * 3)
                self.assertEqual([(b["ip"], b["engine"], b["value"]) for b in d.bans()],
                                 [(IP, "l7_rudy", 3)])


if __name__ == "__main__":
    unittest.main()
