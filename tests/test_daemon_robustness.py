"""Robustness tests for the daemon (T-013: H-01 to H-03 of the 2026-10-29 review).

The real code of control_plane.py runs against the fakes of tests/daemon_harness.py, as in
tests/test_daemon_rules.py: nothing is imported from control_plane.py (it attaches XDP at
import), and nothing is attached, started or slept for real. Each test fails on the daemon
before the fix it covers.
"""
import ast
import contextlib
import os
import sys
import threading
import types
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



def main_statement():
    """The daemon's module-level `try` statement: start-up, the main log loop and the
    `finally` that detaches XDP."""
    with open(H.SOURCE, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    for node in tree.body:
        if isinstance(node, ast.Try) and any(
                isinstance(n, ast.For) and isinstance(n.iter, ast.Call)
                and H._dotted(n.iter.func) == "tail_nginx_logs" for n in ast.walk(node)):
            return node
    raise AssertionError("control_plane.py: the main try statement was not found")


class FakeBPF:
    def __init__(self):
        self.removed = []

    def remove_xdp(self, dev, flags):
        self.removed.append((dev, flags))


class FakeSignal:
    SIGTERM = 15

    def __init__(self):
        self.handlers = {}

    def signal(self, signum, handler):
        self.handlers[signum] = handler


class MainRun:
    """The daemon's main statement in the harness's namespace. What it would attach or start
    is faked: `bpf` records remove_xdp, `threads` the threads it starts (none runs), `sig` the
    signal handlers it installs; `tailer`, when given, replaces tail_nginx_logs."""

    def __init__(self, d):
        self.d = d
        self.bpf = FakeBPF()
        self.sig = FakeSignal()
        self.threads = []
        threads = self.threads

        class Thread:
            def __init__(self, target=None, args=(), kwargs=None, daemon=None, name=None):
                self.target, self.args, self.name = target, tuple(args), name

            def start(self):
                threads.append(self)

            def is_alive(self):
                return True

        self.threading = types.SimpleNamespace(Thread=Thread, Lock=threading.Lock,
                                               Event=threading.Event)

    def run(self, tailer=None):
        ns = self.d.ns
        saved = {k: ns[k] for k in ("threading", "tail_nginx_logs")}
        ns.update(bpf=self.bpf, signal=self.sig, threading=self.threading)
        if tailer is not None:
            ns["tail_nginx_logs"] = tailer
        code = compile(ast.Module(body=[main_statement()], type_ignores=[]), H.SOURCE, "exec")
        try:
            with contextlib.redirect_stdout(self.d.out):
                exec(code, ns)  # noqa: S102 - the daemon's own statement, against fakes
        finally:
            ns.update(saved)


class MainLoopTest(DaemonCase):
    """H-01: an exception that escaped the log tailer left the main loop, reached the finally
    and detached XDP: every ban was lifted and detection stopped. Now the tailer is recreated;
    only Ctrl-C or SIGTERM (stop_event) ends the daemon."""

    def test_an_error_in_the_tailer_recreates_it_and_keeps_xdp_attached(self):
        d = self.daemon()
        main = MainRun(d)
        opened, attached_meanwhile = [], []

        def tailer(path):
            opened.append(path)
            if len(opened) == 1:
                raise OSError(5, "Input/output error")          # e.g. from readline()
            for _ in range(51):                                 # the recreated tailer: a flood
                d.clock.now += 0.01
                yield access_line(agent=b"bot").decode()
            attached_meanwhile.append(main.bpf.removed == [])
            d.stop_event.set()                                  # then an intentional stop

        main.run(tailer)
        self.assertEqual(opened, [d.NGINX_LOG_FILE] * 2)
        self.assertEqual(attached_meanwhile, [True])
        self.assertEqual([(b["ip"], b["engine"]) for b in d.bans()], [(IP, "l7_rate")])
        [err] = d.events("daemon_error")
        self.assertEqual((err["where"], err["error"]),
                         ("access_log", "OSError: [Errno 5] Input/output error"))
        self.assertEqual(d.clock.sleeps, 1)                     # the backoff
        self.assertEqual(main.bpf.removed, [("veth_server", 0)])   # the stop detaches, once

    def test_ctrl_c_still_detaches_xdp_once_after_an_error(self):
        d = self.daemon()
        main = MainRun(d)
        opened = []

        def tailer(_path):
            opened.append(1)
            if len(opened) == 1:
                raise ValueError("I/O operation on closed file.")
            raise KeyboardInterrupt
            yield                                               # a generator, like the real one

        main.run(tailer)                                        # KeyboardInterrupt is handled
        self.assertEqual(len(opened), 2)
        self.assertEqual(len(d.events("daemon_error")), 1)
        self.assertEqual(main.bpf.removed, [("veth_server", 0)])
        self.assertIn("Execution interrupted by user", d.console())

    def test_sigterm_is_an_intentional_stop_that_detaches_xdp_once(self):
        # The real tailer on an empty log: the first time it sleeps at end of file, SIGTERM
        # arrives. Before the fix the daemon installed no handler, so SIGTERM killed it on the
        # spot and XDP stayed attached with its bans and no TTL sweep (security review S17).
        d = self.daemon()
        main = MainRun(d)
        log = os.path.join(d._tmp.name, "access.log")
        with open(log, "wb"):
            pass
        d.ns["NGINX_LOG_FILE"] = log

        def on_sleep(_k):
            main.sig.handlers[main.sig.SIGTERM](main.sig.SIGTERM, None)
        d.clock.on_sleep = on_sleep
        main.run()
        self.assertTrue(d.stop_event.is_set())
        self.assertEqual(main.bpf.removed, [("veth_server", 0)])
        self.assertEqual(d.events("daemon_error"), [])
        self.assertEqual(d.clock.sleeps, 1)


if __name__ == "__main__":
    unittest.main()
