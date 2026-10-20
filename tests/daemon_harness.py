"""Runs control_plane.py's own functions and loops against fakes (audit G-29). Not a test module.

control_plane.py attaches XDP, loads a model and blocks in a log-tailing loop as soon as it is
imported, so tests/test_control_plane_contract.py can only parse it. This harness executes the
real code instead, without importing the module:

* every top-level `def` is executed as it is;
* a top-level assignment is executed when its right-hand side is built from literals, names and
  a few harmless constructors (the thresholds, the per-IP state, the locks). Every other
  top-level statement (imports, BPF(...), joblib.load, torch.*, prints, the `with` that reads
  the model config, the main `try`) is skipped, so nothing is attached, loaded or started;
* the daemon's `time`, `subprocess` and `os` are fakes you control; the BPF tables are dict-like
  fakes; the ban-event log is the real ban_events.EventLog on a temporary file;
* `poll(n)` runs the real l3_l4_telemetry_monitor loop for n intervals, `l7_requests(...)` the
  real body of the main log loop (taken from the AST, with the file tail replaced by your lines)
  and `rudy_lines(...)` the real tail_nginx_error_logs.

What the tests pin is what the daemon does, including its known weaknesses. A refactor that
moves the rules elsewhere has to keep these tests green.
"""
import ast
import contextlib
import io
import json
import os
import queue
import socket
import struct
import subprocess
import tempfile
import threading
import types
from collections import defaultdict, deque

import ban_events
import l7_ingest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCE = os.path.join(REPO, "control_plane.py")

SAFE_CALLS = {"set", "dict", "list", "tuple", "int", "float", "str", "bool", "defaultdict",
              "deque", "os.environ.get", "threading.Lock", "threading.Event", "queue.Queue",
              "SystemExit"}
SAFE_ROOTS = {"os", "ban_events", "l7_ingest", "threading", "queue"}


def _dotted(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _safe_expr(node):
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            if _dotted(n.func) not in SAFE_CALLS:
                return False
        elif isinstance(n, ast.Attribute):
            name = _dotted(n)
            if name is None or name.split(".")[0] not in SAFE_ROOTS:
                return False
        elif isinstance(n, (ast.Await, ast.Yield, ast.YieldFrom, ast.NamedExpr)):
            return False
    return True


def _safe_stmt(node):
    if isinstance(node, ast.FunctionDef):
        return not node.decorator_list
    if isinstance(node, ast.Assign):
        return _safe_expr(node.value)
    if isinstance(node, ast.If):
        return _safe_expr(node.test) and all(_safe_stmt(s) for s in node.body + node.orelse)
    if isinstance(node, ast.Raise):
        return node.exc is None or _safe_expr(node.exc)
    return False


class FakeClock:
    """The daemon's `time`. sleep() advances the clock and then calls `on_sleep(n)`, where n
    counts the sleeps so far: that is how a test sets up the interval the loop is about to see
    and stops the loop."""

    def __init__(self, start=1000.0):
        self.now = float(start)
        self.sleeps = 0
        self.on_sleep = None

    def time(self):
        return self.now

    def monotonic_ns(self):
        return int(self.now * 1e9)

    def sleep(self, seconds):
        self.now += seconds
        self.sleeps += 1
        if self.on_sleep:
            self.on_sleep(self.sleeps)


class FakeSubprocess:
    """The daemon's `subprocess`: records every argv and answers `ss -tan state established`
    from `ss_established`. `failures` maps an argv prefix to an exception to raise or to a
    non-zero return code (which raises CalledProcessError when the call has check=True)."""

    CalledProcessError = subprocess.CalledProcessError
    SubprocessError = subprocess.SubprocessError
    TimeoutExpired = subprocess.TimeoutExpired

    def __init__(self):
        self.calls = []
        self.checks = []                # the check= flag of each call, parallel to calls
        self.ss_established = ""
        self.failures = {}

    def run(self, argv, check=False, capture_output=False, text=False, timeout=None):
        argv = list(argv)
        self.calls.append(argv)
        self.checks.append(check)
        for prefix, effect in self.failures.items():
            if argv[:len(prefix)] == list(prefix):
                if isinstance(effect, BaseException):
                    raise effect
                if check:
                    raise subprocess.CalledProcessError(effect, argv, output=b"",
                                                        stderr=b"simulated failure")
                return types.SimpleNamespace(returncode=effect, stdout="" if text else b"",
                                             stderr="" if text else b"simulated failure")
        out = self.ss_established if argv[:3] == ["ss", "-tan", "state"] else ""
        return types.SimpleNamespace(returncode=0, stdout=out if text else out.encode(),
                                     stderr="" if text else b"")

    def matching(self, *prefix):
        return [c for c in self.calls if c[:len(prefix)] == list(prefix)]


class FakeBlacklist:
    """blacklist_map: Key(ip_int) / Leaf(0), item assignment and deletion, like a BCC table."""

    def __init__(self):
        self.entries = {}

    @staticmethod
    def Key(value):
        return types.SimpleNamespace(value=value)

    @staticmethod
    def Leaf(value):
        return types.SimpleNamespace(value=value)

    def __setitem__(self, key, leaf):
        self.entries[key.value] = leaf.value

    def __delitem__(self, key):
        del self.entries[key.value]    # KeyError when absent, as in BCC

    def ips(self):
        return {socket.inet_ntoa(struct.pack("=I", v)) for v in self.entries}


class FakeTelemetry:
    """telemetry_map: cumulative per-IP counters (one CPU), read through .items()."""

    def __init__(self):
        self.counters = {}

    @staticmethod
    def Key(value):
        return types.SimpleNamespace(value=value)

    def add(self, ip, pkts=0, syn=0, nbytes=0):
        """Add to the cumulative counters of `ip`, as the XDP program would have."""
        key = struct.unpack("=I", socket.inet_aton(ip))[0]
        c = self.counters.setdefault(key, [0, 0, 0])
        c[0] += pkts
        c[1] += syn
        c[2] += nbytes

    def items(self):
        return [(self.Key(k), [types.SimpleNamespace(packet_count=c[0], syn_count=c[1],
                                                     byte_count=c[2])])
                for k, c in list(self.counters.items())]

    def __delitem__(self, key):
        del self.counters[key.value]


class EmptyFlowMap:
    def items(self):
        return []


class FakeLogFile:
    """An error log that is already open at its end. It yields the queued (seconds to
    advance, text) lines, then reports end-of-file, which makes the daemon sleep."""

    def __init__(self, lines, clock):
        self.lines = list(lines)
        self.clock = clock

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def seek(self, *args):
        return 0

    def readline(self):
        if not self.lines:
            return ""
        advance, text = self.lines.pop(0)
        self.clock.now += advance
        return text


class Daemon:
    """control_plane.py in a private namespace. `env` is the daemon's os.environ (an empty
    dict gives the defaults whatever the developer's shell exports)."""

    def __init__(self, env=None):
        self.env = dict(env or {})
        self.clock = FakeClock()
        self.proc = FakeSubprocess()
        self.blacklist = FakeBlacklist()
        self.telemetry = FakeTelemetry()
        self.out = io.StringIO()
        self._tmp = tempfile.TemporaryDirectory()
        self.events_path = os.path.join(self._tmp.name, "ban_events.jsonl")
        self.error_log = os.path.join(self._tmp.name, "error.log")
        with open(self.error_log, "w", encoding="utf-8"):
            pass
        self.events_log = ban_events.EventLog(self.events_path)
        try:
            self._load()
        except BaseException:           # e.g. the daemon's SystemExit on an unknown profile
            self.close()
            raise

    def _load(self):
        with open(os.path.join(REPO, "training_results", "feature_config_testbed.json"),
                  encoding="utf-8") as fh:
            gru_cfg = json.load(fh)
        fake_os = types.SimpleNamespace(environ=self.env, stat=os.stat, SEEK_END=os.SEEK_END,
                                        getpid=os.getpid, path=os.path)
        self.ns = {
            "__name__": "control_plane_under_test", "os": fake_os, "time": self.clock,
            "subprocess": self.proc, "socket": socket, "struct": struct, "json": json,
            "threading": threading, "queue": queue, "defaultdict": defaultdict,
            "deque": deque, "ban_events": ban_events, "l7_ingest": l7_ingest,
            "EVENTS": self.events_log, "blacklist_map": self.blacklist,
            "telemetry_map": self.telemetry, "flow_map": EmptyFlowMap(),
            "_gru_cfg": gru_cfg, "open": self._open,
        }
        self._fake_logs = []
        with open(SOURCE, encoding="utf-8") as fh:
            source = fh.read()
        tree = ast.parse(source)
        self.skipped = []
        for node in tree.body:
            if _safe_stmt(node):
                code = compile(ast.Module(body=[node], type_ignores=[]), SOURCE, "exec")
                exec(code, self.ns)  # noqa: S102
            else:
                self.skipped.append(ast.unparse(node).splitlines()[0])
        self._main_loop = self._extract_main_loop(tree)

    # --- plumbing -------------------------------------------------------------------------

    def _open(self, path, *args, **kwargs):
        """The daemon's open(): the error log is a FakeLogFile, anything else is real."""
        if self._fake_logs and path == self.error_log:
            return self._fake_logs.pop(0)
        return open(path, *args, **kwargs)

    def _extract_main_loop(self, tree):
        """The body of `for log_line in tail_nginx_logs(...)` in the main try block, as a
        function over a list of lines. The statements are the daemon's own."""
        for node in tree.body:
            if not isinstance(node, ast.Try):
                continue
            for sub in ast.walk(node):
                if (isinstance(sub, ast.For) and isinstance(sub.iter, ast.Call)
                        and _dotted(sub.iter.func) == "tail_nginx_logs"):
                    template = ast.parse("def l7_main_loop(_lines):\n"
                                         "    for log_line in _lines:\n        pass\n")
                    template.body[0].body[0].body = sub.body
                    ast.fix_missing_locations(template)
                    exec(compile(template, SOURCE, "exec"), self.ns)  # noqa: S102
                    return self.ns["l7_main_loop"]
        raise AssertionError("control_plane.py: main loop over tail_nginx_logs not found")

    def close(self):
        self.events_log.close()
        self._tmp.cleanup()

    def __getattr__(self, name):
        """Constants and state of the daemon: d.SYN_FLOOD_THRESHOLD, d.banned_ips, ..."""
        try:
            return self.__dict__["ns"][name]
        except KeyError:
            raise AttributeError(name) from None

    # --- driving the real code --------------------------------------------------------------

    def call(self, name, *args, **kwargs):
        """Call one of the daemon's functions, collecting its console output in self.out."""
        with contextlib.redirect_stdout(self.out):
            return self.ns[name](*args, **kwargs)

    def poll(self, n=1, setup=None):
        """Run n intervals of the real l3_l4_telemetry_monitor loop. `setup(k)` runs at the
        start of interval k (1-based, after the fake one-second sleep): put the counters and
        the socket table that interval should see there. Each call starts the loop afresh:
        its local state (the flood-suppression flags) does not carry over between calls, the
        module state (counters, bans, snapshots) does."""
        self.ns["stop_event"].clear()

        def on_sleep(k):
            if setup:
                setup(k)
            if k >= n:
                self.ns["stop_event"].set()

        self.clock.sleeps = 0
        self.clock.on_sleep = on_sleep
        try:
            self.call("l3_l4_telemetry_monitor")
        finally:
            self.clock.on_sleep = None
            self.ns["stop_event"].clear()

    def set_established(self, counts):
        """What `ss -tan state established` shows next: {peer ip: connections to :80}."""
        lines = []
        for ip, n in counts.items():
            lines += [f"ESTAB 0 0 10.0.0.1:80 {ip}:{40000 + i}" for i in range(n)]
        self.proc.ss_established = "\n".join(lines) + ("\n" if lines else "")

    def l7_requests(self, requests):
        """Feed the real main-loop body with access-log lines. Each request is
        (seconds since the previous one, client ip, status) or a raw string."""
        def lines():
            for r in requests:
                if isinstance(r, str):
                    yield r
                    continue
                dt, ip, status = r
                self.clock.now += dt
                yield json.dumps({"client_ip": ip, "status": status}) + "\n"
        with contextlib.redirect_stdout(self.out):
            self._main_loop(lines())

    def rudy_lines(self, lines):
        """Run the real tail_nginx_error_logs over (seconds to advance, text) lines."""
        self._fake_logs.append(FakeLogFile(lines, self.clock))
        self.ns["stop_event"].clear()
        self.clock.on_sleep = lambda _k: self.ns["stop_event"].set()   # end of file: stop
        try:
            self.call("tail_nginx_error_logs", self.error_log)
        finally:
            self.clock.on_sleep = None
            self.ns["stop_event"].clear()

    # --- reading the result -----------------------------------------------------------------

    def events(self, *kinds):
        return ban_events.read_events(self.events_path, kinds or None)

    def bans(self):
        return self.events("ban")

    def console(self):
        return self.out.getvalue()
