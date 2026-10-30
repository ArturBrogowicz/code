"""Robustness tests for the daemon (T-013: H-01 to H-03 of the 2026-10-29 review).

The real code of control_plane.py runs against the fakes of tests/daemon_harness.py, as in
tests/test_daemon_rules.py: nothing is imported from control_plane.py (it attaches XDP at
import), and nothing is attached, started or slept for real. Each test fails on the daemon
before the fix it covers.
"""
import ast
import contextlib
import os
import re
import sys
import threading
import types
import unittest
import warnings
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, REPO)
import daemon_harness as H

with mock.patch("atexit.register"), mock.patch("signal.signal"):
    import test_distributed_suite as S  # as tests/test_suite_harness.py does

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
    SIG_IGN = "SIG_IGN"                                         # not callable, like signal.SIG_IGN

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


class SigtermInsideSet(threading.Event):
    """stop_event whose set() runs the SIGTERM handler installed at that moment, as a signal that
    arrives while set() holds the Event's lock would (the window of D-02). A real Event would then
    deadlock if the handler called set() again; this one counts the re-entry instead."""

    def __init__(self, sig):
        super().__init__()
        self.sig, self.inside, self.reentries = sig, False, 0

    def set(self):
        if self.inside:
            self.reentries += 1
            return
        self.inside = True
        try:
            handler = self.sig.handlers.get(self.sig.SIGTERM)
            if callable(handler):
                handler(self.sig.SIGTERM, None)
            super().set()
        finally:
            self.inside = False


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

    def test_a_sigterm_inside_stop_event_set_cannot_deadlock_the_stop(self):
        # D-02 (review T-017): stop_event.set() holds the Event's non-reentrant lock. A SIGTERM
        # handled inside it (a second one during the handler's own set(), or one during the
        # finally's) called set() again and deadlocked, and remove_xdp never ran. The double
        # delivers a SIGTERM inside every set(); the handler and the finally now ignore SIGTERM
        # before they call it.
        for first in ("SIGTERM", "Ctrl-C"):
            with self.subTest(first):
                d = self.daemon()
                main = MainRun(d)
                d.ns["stop_event"] = event = SigtermInsideSet(main.sig)
                log = os.path.join(d._tmp.name, "access.log")
                with open(log, "wb"):
                    pass
                d.ns["NGINX_LOG_FILE"] = log

                def on_sleep(_k, first=first, sig=main.sig):
                    if first == "Ctrl-C":
                        raise KeyboardInterrupt
                    sig.handlers[sig.SIGTERM](sig.SIGTERM, None)
                d.clock.on_sleep = on_sleep
                main.run()
                self.assertEqual(event.reentries, 0)
                self.assertTrue(event.is_set())
                self.assertEqual(main.sig.handlers[main.sig.SIGTERM], main.sig.SIG_IGN)
                self.assertEqual(main.bpf.removed, [("veth_server", 0)])



class FullBlacklist(H.FakeBlacklist):
    """blacklist_map whose next `failures` updates fail the way bcc's do on a full BPF hash
    map: bcc 0.35 raises a bare Exception (bcc/table.py:379-382)."""

    def __init__(self, failures=0):
        super().__init__()
        self.failures = failures

    def __setitem__(self, key, leaf):
        if self.failures:
            self.failures -= 1
            raise Exception("Could not update table: Argument list too long")  # noqa: TRY002
        super().__setitem__(key, leaf)


def use_blacklist(d, blacklist):
    blacklist.entries.update(d.blacklist.entries)
    d.blacklist = blacklist
    d.ns["blacklist_map"] = blacklist


MAP_FULL = "Exception: Could not update table: Argument list too long"


class TelemetryGuardTest(DaemonCase):
    """H-02: the telemetry loop had no exception guard. One error (a failed BPF map update in
    ban_ip, say) ended the thread for good: no more L4 detection, TTL unbans or idle eviction,
    while the process ran on and no event said so."""

    def test_a_failing_poll_is_reported_and_the_rules_resume_after_a_fresh_snapshot(self):
        d = self.daemon()
        d.call("ban_ip", OTHER, reason="r", engine="l4_syn")    # t=1000: expires after t=1300
        blacklist = FullBlacklist()
        use_blacklist(d, blacklist)
        d.clock.now = 1299.0

        def setup(k):
            d.telemetry.add(IP, pkts=300, syn=300)               # a SYN flood in every poll
            if k == 1:
                blacklist.failures = 1                           # the first poll's ban fails
        d.poll(3, setup)
        [err] = d.events("daemon_error")
        self.assertEqual((err["where"], err["error"]), ("telemetry", MAP_FULL))
        self.assertEqual([e["ip"] for e in d.events("unban")], [OTHER])  # TTL sweep, t=1301
        # t=1301 re-takes the snapshots (D-01); t=1302 bans on a one-poll delta.
        self.assertEqual([(b["ip"], b["engine"], b.get("value")) for b in d.bans()],
                         [(OTHER, "l4_syn", None), (IP, "l4_syn", 300)])
        self.assertEqual(d.ban_timestamps, {IP: 1302.0})
        self.assertEqual(d.blacklist.ips(), {IP})

    def test_an_outage_is_not_read_as_one_interval(self):
        # D-01 (review T-017): 30 failed polls (`ss` failing with an OSError, which
        # get_established_conns_by_ip does not catch) left every snapshot where it was. The first
        # good poll then read 31 s of normal traffic as one interval and banned an 8-SYN/s client
        # (l4_syn 248) and a 200-packet/s one (l4_volumetric 6107). Now that poll only re-takes
        # the snapshots; on the next one, a flood that began during the outage is banned at its
        # one-poll rate.
        d = self.daemon()
        flood, outage = "10.0.2.9", 30

        def setup(k):
            d.telemetry.add(IP, pkts=8, syn=8)                   # 8 SYN/s
            d.telemetry.add(OTHER, pkts=200, syn=3)              # 200 packets/s
            if k >= 20:
                d.telemetry.add(flood, pkts=300, syn=300)        # starts during the outage
            if k == 2:
                d.proc.failures[("ss", "-tan")] = OSError(12, "Cannot allocate memory")
            if k == 2 + outage:
                del d.proc.failures[("ss", "-tan")]              # polls 2..31 failed
        d.poll(2 + outage + 1, setup)
        self.assertEqual(len(d.events("daemon_error")), outage)
        self.assertEqual([(b["ip"], b["engine"], b["value"]) for b in d.bans()],
                         [(flood, "l4_syn", 300)])
        self.assertEqual(d.ban_timestamps, {flood: 1033.0})     # the second good poll


class SupervisorTest(DaemonCase):
    """H-02: the worker threads ran their targets bare, so an exception ended a thread for good,
    with a traceback on stderr and no event. Now each target runs under supervise()."""

    def started_threads(self, d):
        """The threads the daemon's main statement starts (none runs), its main loop stopping
        at once."""
        main = MainRun(d)

        def tailer(_path):
            d.stop_event.set()
            return
            yield                                               # a generator, like the real one
        main.run(tailer)
        d.stop_event.clear()
        return main.threads

    @staticmethod
    def running(threads, func):
        [thread] = [t for t in threads if func in (t.target, *t.args)]
        return thread

    def test_the_rudy_thread_survives_a_failed_ban_and_bans_after_its_restart(self):
        d = self.daemon()
        d.ns["NGINX_ERROR_LOG"] = d.error_log
        thread = self.running(self.started_threads(d), d.tail_nginx_error_logs)
        use_blacklist(d, FullBlacklist(failures=1))
        # The first tailer reads three body timeouts and its ban fails. The restarted one
        # reads a fourth, still inside the 60-s window, and bans.
        line = body_timeout_line().decode()
        d._fake_logs += [H.FakeLogFile([(0, line)] * 3, d.clock), H.FakeLogFile([(0, line)], d.clock)]
        d.clock.on_sleep = lambda k: d.stop_event.set() if k >= 2 else None
        with contextlib.redirect_stdout(d.out):
            thread.target(*thread.args)                          # what the thread runs
        self.assertEqual([(b["ip"], b["engine"], b["value"]) for b in d.bans()],
                         [(IP, "l7_rudy", 4)])
        [err] = d.events("daemon_error")
        self.assertEqual((err["where"], err["error"]), ("thread:rudy", MAP_FULL))
        self.assertEqual(d.clock.sleeps, 2)                     # the backoff, then end of file

    def test_every_worker_thread_is_supervised(self):
        d = self.daemon(L7_SHADOW="1")
        threads = self.started_threads(d)
        self.assertEqual(sorted(t.args[0] for t in threads if t.target is d.supervise),
                         ["inference", "l7_shadow", "rudy", "telemetry"])
        self.assertEqual([t for t in threads if t.target is not d.supervise], [])

    def test_a_worker_that_ends_while_the_daemon_runs_is_reported_once(self):
        # The L7 shadow returns when it cannot bind its socket: it is not restarted, but the
        # event log now says so.
        d = self.daemon(L7_SHADOW="1", L7_SOCKET_PATH="/nonexistent-T013/ddos_l7.sock")
        thread = self.running(self.started_threads(d), d.l7_shadow_monitor)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ResourceWarning)    # l7_ingest's unbound socket
            with contextlib.redirect_stdout(d.out):
                thread.target(*thread.args)
        self.assertIn("L7 shadow: cannot bind", d.console())
        [err] = d.events("daemon_error")
        self.assertEqual((err["where"], err["error"], err["action"]),
                         ("thread:l7_shadow", "returned", "not restarted"))



class BackendBindTest(unittest.TestCase):
    """H-03 (security review S11): gunicorn listened on 0.0.0.0:8080 in server_ns, so a client
    could reach the backend directly, past nginx's limits, its access log (the L7 rule and the
    L7 shadow) and SlowConn, which counts connections to :80 and :443 only."""

    def test_the_suite_binds_gunicorn_to_nginx_upstream_only(self):
        with mock.patch.object(S, "run") as run, mock.patch.object(S, "_wait_http_ready"), \
                mock.patch.object(S.time, "sleep"):
            S._start_web_stack()
        [argv] = [c.args[0] for c in run.call_args_list if "gunicorn" in c.args[0]]
        bind = argv[argv.index("-b") + 1]
        self.assertEqual(bind, "127.0.0.1:8080")
        for conf in ("nginx.conf", "nginx_unprotected.conf"):     # the two the suite serves
            with open(os.path.join(REPO, conf), encoding="utf-8") as fh:
                self.assertEqual(re.findall(r"proxy_pass http://(\S+);", fh.read()), [bind], conf)


class DocumentationTest(unittest.TestCase):
    def test_the_robustness_section_names_the_defects_and_every_test_class_here(self):
        with open(os.path.join(REPO, "docs", "EVALUATION.md"), encoding="utf-8") as fh:
            doc = fh.read()
        start = doc.index("## Daemon robustness (2026-10-30)")
        section = doc[start:doc.index("\n## ", start)]
        for defect in ("H-01", "H-02", "H-03"):
            self.assertIn(defect, section)
        here = sys.modules[__name__]
        classes = [name for name, obj in vars(here).items() if isinstance(obj, type)
                   and issubclass(obj, unittest.TestCase) and obj.__module__ == here.__name__
                   and name.endswith("Test") and name != "DocumentationTest"]
        self.assertEqual(len(classes), 5)
        for name in classes:
            self.assertIn(f"`{name}`", section)


if __name__ == "__main__":
    unittest.main()
