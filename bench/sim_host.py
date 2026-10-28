"""A simulated host: the testbed of the executor as a small model in memory, commands answered from it, processes that
live on a virtual clock, faults on request, and, if given a `SyntheticServer`, what a stack would do to the requests of a run
(docs/HG1C_DESIGN.md 6.1 and 7).

It stands in for the machine in the executor's tests and in `gate_campaign.py --simulate`, which runs a whole campaign on it and lets
eval/harm_gate.py give a verdict: the offline integration test of the benchmark, and a way to see the protocol work (blocks, orders,
the re-run rule, resume) without a namespace. Nothing here touches the machine. The files a real run leaves (the engines' summaries and
records, the Nginx log) are written to the directories the caller gives; everything else (namespaces, links, processes, /proc, /sys)
is the model's. The model answers only what the executor asks of it and says "no such command" to anything else, so a command the
executor starts to use is noticed here and not passed over. What it cannot show is in docs/HG1C_DESIGN.md 9: that the real commands do
what the model says, which is what S1-S4 are for.
"""
import collections
import contextlib
import datetime
import gzip
import heapq
import itertools
import json
import os
import re
import signal
import sys
import zlib

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import executor as X
import loadgen as LG
import origin as O
import population as P

BASE_EPOCH = 1_798_000_000.0              # the virtual clock's wall time at its zero
# what S1 and S1b measured on loopback and S4 with the real launch chain (docs/HG1C_DESIGN.md 14, 25), which the executor's settings cover
LEGIT_STARTUP_S = 2.8                     # a legit engine's loop begins this long after its launch when 29 are launched at once on one CPU
ATTACK_STARTUP_S = 0.14                   # an attack engine's, on CPUs of its own
EXIT_DELAY_PER_REQUEST_S = 8e-6           # an engine exits this much later for each request it sent
NGINX_FORK_S = 0.05                       # the launcher of the Nginx daemon returns this long after the daemon has forked
OK_FLAGS = {"slip": False, "sent_short": False, "cpu": False, "descriptors": False, "ports": False, "dropped": False}
RECORD_HEADER = "i,t_intended,t_sent,t_done,status,bytes,err,ident,reused\n"
CLASS_OF_PATH = {path: klass for klass, path in O.SAMPLE_URLS.items()}
CPUS = 8


def exec_args(argv):
    """The command line a process shows once the wrappers that exec into it (taskset, prlimit) are gone."""
    argv = list(argv)
    while argv and argv[0] in ("taskset", "prlimit"):
        argv = argv[3:] if argv[0] == "taskset" else argv[argv.index("--") + 1:]
    return argv


def allowed_cpus(argv):
    """The CPU list a `taskset -c` in the command gave the process, else every CPU."""
    return argv[argv.index("taskset") + 2] if "taskset" in argv else f"0-{CPUS - 1}"


class SimProc:
    """A process of the model. `returncode` is None while it lives; `exit_time` is the wall-clock time of its exit."""

    def __init__(self, host, argv, ns, comm, role):
        self.host, self.argv, self.ns, self.comm, self.role = host, tuple(argv), ns, comm, role
        self.pid = next(host.pids)
        self.cpus = allowed_cpus(self.argv)
        self.started = host.t
        self.returncode = None
        self.exit_time = None
        self.ignores_term = False            # survives TERM, dies on KILL
        self.immortal = False                # survives both: what a teardown cannot take down

    def poll(self):
        return self.returncode

    def terminate(self):
        self.host.deliver(self, signal.SIGTERM)

    def kill(self):
        self.host.deliver(self, signal.SIGKILL)

    def jiffies(self):
        share = {"origin": 0.5, "nginx": 0.2}.get(self.role, 0.0)
        return int((self.host.t - self.started) * 100 * share)


class SimHost(X.Host):
    """`faults` maps a name to how many times it fires (None: always); `fault_schedule` maps the number of a topology (the 1st, the
    2nd... one is built per run) to faults that are armed when it is built, which is how a campaign's later runs are made to fail.
    `dies`, `silent` and `nonzero` are predicates on a stream id: those streams die at their start, exit 0 leaving no output, exit 3
    leaving their output. An engine exits when its last request is answered, `exit_delay_s` later, as bench/loadgen.py does (S1b): a
    stream of a few tenths of a request per second is gone long before its duration is over, and one whose last requests time out
    outlives it. `wall_late_s(stream id, index, kind)` is how long an engine was descheduled between reading its schedule's zero and
    the clock its wall time counts from: the summary of that stream reports that much less wall time; what it does to the first
    requests is not modeled. `ping_drops(namespace, source, k)` says whether the k-th packet of a ping is lost. With
    `daemon_holds_pipes` (the default) the Nginx daemon keeps the pipes of a command that was run to completion with its output
    captured, so that call returns only at its timeout, as the one in S3 did three times (why a real Nginx does that is an inference:
    docs/HG1C_DESIGN.md 14); started like the suite starts it, with no pipe, the launcher returns a moment after the daemon forks.
    `run_cost_s(argv)` is how long a command takes on the virtual clock (none, by default), so that a time the executor logs for a
    step can be told from another's.
    The names the tests use:
    missing_address, duplicate_mac, no_netem, ping_fails, nginx_fails, nginx_foreground (Nginx that does not daemonise: its launcher
    never returns), origin_dies, not_ready, wrong_class, wrong_tag,
    stubborn_origin, stubborn_nginx, origin_session_fails, leftover_nginx_after_teardown, server_address_missing, stream_dies (one
    engine dies), engines_die (every engine of one run dies: none of them can start), stream_silent, stream_nonzero, stream_hangs,
    table_unreadable."""

    simulated = True

    def __init__(self, root=True, dirty=False, nofile=(524288, 524288), uptime_s=7200.0, load1=0.05, timer_p99_ms=1.0,
                 preexisting=(), startup_s=None, exit_delay_s=0.04, exit_delay_per_request_s=EXIT_DELAY_PER_REQUEST_S, faults=None,
                 log_lines=20, tag="placeholder", python_exists=True, steal_share=0.0, on_sleep=None, server=None,
                 fault_schedule=None, dies=None, origin_costs=None, origin_noise=(0.0,), wall_late_s=None, silent=None, nonzero=None,
                 ping_drops=None, daemon_holds_pipes=True, run_cost_s=None):
        self.t = 0.0
        self.daemon_holds_pipes, self.call_timeout = daemon_holds_pipes, X.RealHost.COMMAND_TIMEOUT_S
        self.run_cost_s = run_cost_s
        self.wall_late_s, self.silent, self.nonzero, self.ping_drops = wall_late_s, silent, nonzero, ping_drops
        self.pids = itertools.count(1000)
        self.events, self.seq = [], itertools.count()
        self.procs = {}
        self.namespaces, self.links = {}, set()
        self.commands, self.prims, self.sleeps = [], [], []
        self.root, self.dirty, self.nofile = root, dirty, nofile
        self.uptime_s, self.load1, self.timer_p99_ms = uptime_s, load1, timer_p99_ms
        self.exit_delay_s, self.exit_delay_per_request_s = exit_delay_s, exit_delay_per_request_s
        self.startup_s = startup_s or (lambda sid, index, kind: (LEGIT_STARTUP_S if kind == "legit" else ATTACK_STARTUP_S) + 0.002 * index)
        self.faults = dict(faults or {})
        self.fault_schedule, self.topologies, self.dies = dict(fault_schedule or {}), 0, dies
        self.registry = {}                    # run directory -> the streams started in it, for a server that has a load
        self.origin_costs, self.origin_noise, self.origin_calls = origin_costs, tuple(origin_noise), 0
        self.log_lines, self.tag, self.python_exists, self.steal_share = log_lines, tag, python_exists, steal_share
        self.on_sleep, self.server = on_sleep, server
        self.table_extra = []                 # (pid, ppid, args) of processes that are not the model's: an editor, a shell
        self.shield, self.unshielded = False, []
        self.pinned = None
        self.stream_index, self.batch_at = 0, None
        self.dying_runs = set()               # run directories whose engines all die
        self.launch_times = {}
        self.access_log = None
        self.origin_ready_at = None
        for name in preexisting:
            self.namespaces[name] = {"addresses": [], "mac": "", "profile": "perfect"}

    # --- the clocks ------------------------------------------------------------------------------

    def time(self):
        return BASE_EPOCH + self.t

    def monotonic(self):
        return self.t

    def schedule(self, at, fn):
        heapq.heappush(self.events, (at, next(self.seq), fn))

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        end = self.t + seconds
        while self.events and self.events[0][0] <= end:
            at, _, fn = heapq.heappop(self.events)
            self.t = max(self.t, at)
            fn()
        self.t = end
        if self.on_sleep and not self.shield:        # a shielded stretch cannot be interrupted
            self.on_sleep(self)

    # --- faults ----------------------------------------------------------------------------------

    def fault(self, name):
        if name not in self.faults:
            return False
        left = self.faults[name]
        if left is None:
            return True
        if left <= 0:
            return False
        self.faults[name] = left - 1
        return True

    # --- processes -------------------------------------------------------------------------------

    def alive(self, ns=None):
        return [p for p in self.procs.values() if p.returncode is None and (ns is None or p.ns == ns)]

    def deliver(self, proc, sig):
        if proc.returncode is not None or proc.immortal:
            return
        if sig == signal.SIGTERM and proc.ignores_term:
            return
        self.end(proc, -int(sig))

    def end(self, proc, code):
        if proc.returncode is None:
            proc.returncode = code
            proc.exit_time = self.time()

    def spawn(self, argv, ns, comm, role):
        proc = SimProc(self, argv, ns, comm, role)
        self.procs[proc.pid] = proc
        return proc

    def popen(self, argv, ns="", env=None, stdout=None, stderr=None):
        argv = list(argv)
        self.commands.append(("popen", ns, tuple(argv)))
        text = " ".join(argv)
        if "bench/loadgen.py" in text:
            return self._start_stream(argv, ns, stderr)
        if "nginx" in (os.path.basename(a) for a in argv):
            return self._start_nginx(argv, ns, stderr)
        if "gunicorn" in text:
            return self._start_origin(argv, ns, stderr)
        raise AssertionError(f"the simulation has no process for {text[:100]}")

    def _start_nginx(self, argv, ns, stderr):
        """Nginx started with no pipe for the daemon to hold: the launcher returns 0 `NGINX_FORK_S` after the daemon has forked, or
        1 at once with Nginx's message on its stderr if it cannot start; with the fault `nginx_foreground` it never returns."""
        launcher = self.spawn(argv, ns, "nginx", "launcher")
        args = argv[[os.path.basename(a) for a in argv].index("nginx") + 1:]
        code, message = self._daemon_start(args, ns, allowed_cpus(argv))
        if code != 0:
            if stderr is not None:
                stderr.write(message.encode() + b"\n")
            self.end(launcher, code)
        elif not self.fault("nginx_foreground"):
            self.schedule(self.t + NGINX_FORK_S, lambda: self.end(launcher, 0))
        return launcher

    def _start_origin(self, argv, ns, stderr):
        proc = self.spawn(argv, ns, "gunicorn", "origin")
        if stderr is not None:
            stderr.write(b"[INFO] Booting worker\n")
        proc.ignores_term = self.fault("stubborn_origin")
        if self.fault("origin_dies"):
            self.schedule(self.t + 0.5, lambda: self.end(proc, 1))
        self.origin_ready_at = self.t + 1.5
        return proc

    def _start_stream(self, argv, ns, stderr):
        opts = {a: argv[i + 1] for i, a in enumerate(argv)
                if a in ("--rate", "--duration", "--summary", "--records", "--process", "--seed", "--period", "--duty")}
        local = [argv[i + 1] for i, a in enumerate(argv) if a == "--local-addr"]
        sid = os.path.basename(os.path.dirname(opts["--summary"]))
        kind = "legit" if sid.startswith("L-") else "attack"
        proc = self.spawn(argv, ns, "python3", "stream")
        if self.t != self.batch_at:                    # the start-up contention is among the streams launched together
            self.batch_at, self.stream_index = self.t, 0
        index, self.stream_index = self.stream_index, self.stream_index + 1
        self.launch_times[sid] = self.t
        if self.fault("stream_hangs"):
            return proc
        loop_start = self.t + self.startup_s(sid, index, kind)
        duration, rate = float(opts["--duration"]), float(opts["--rate"])
        n = max(1, round(rate * duration))
        run_dir = _run_dir(opts)
        if run_dir not in self.dying_runs and self.fault("engines_die"):
            self.dying_runs.add(run_dir)
        if run_dir in self.dying_runs or self.fault("stream_dies") or (self.dies is not None and self.dies(sid)):
            if stderr is not None:
                stderr.write(b"Traceback: the simulated engine died\n")
            self.schedule(loop_start + 3.0, lambda: self.end(proc, 2))
            return proc
        self.registry.setdefault(run_dir, []).append(
            {"kind": kind, "begin": loop_start, "end": loop_start + X.ENGINE_T0_OFFSET_S + duration, "rate": rate,
             "route": parse_stream_id(sid)[1]})
        silent = self.fault("stream_silent") or (self.silent is not None and self.silent(sid))
        code = 3 if self.fault("stream_nonzero") or (self.nonzero is not None and self.nonzero(sid)) else 0
        late = self.wall_late_s(sid, index, kind) if self.wall_late_s else 0.0
        # the engine has sent its last request when the schedule's last event is due; how long it takes to answer it is in the records,
        # which are made then (every stream that can touch them has been started), and the engine exits after that
        self.schedule(loop_start + X.ENGINE_T0_OFFSET_S + self._last_due(opts, n),
                      lambda: self._finish_stream(proc, sid, opts, local, loop_start, n, silent, code, late))
        return proc

    def _last_due(self, opts, n):
        """When the last request of a stream is due, in seconds after its schedule's zero."""
        duration = float(opts["--duration"])
        if self.server is None:
            return (n - 0.5) * duration / n
        sched = LG.schedule(opts.get("--process", "constant"), float(opts["--rate"]), duration, int(opts.get("--seed", 1)),
                            period=float(opts.get("--period", 1.0)), duty=float(opts.get("--duty", 0.5)))
        return float(sched[-1]) if len(sched) else 0.0

    def _finish_stream(self, proc, sid, opts, local, loop_start, n, silent, code, late):
        """The engine has sent its last request: it writes its files when the last is answered and exits `exit_delay_s` later (and a
        little more for each request). The files are made now, as the end of the loop is known only from them."""
        if proc.returncode is not None:
            return
        took = self.t - loop_start                     # a stream that leaves nothing ends with its last send
        if not silent:
            took, n = self._write_stream(sid, opts, local, loop_start, n, late)
        self.schedule(loop_start + took + self.exit_delay_s + self.exit_delay_per_request_s * n, lambda: self.end(proc, code))

    def _write_stream(self, sid, opts, local, loop_start, n, late):
        """Writes the stream's files. Returns the wall time its loop took, which is until its last request was answered (a timeout
        included), and the number of requests; the summary says `late` less than that."""
        duration = float(opts["--duration"])
        os.makedirs(os.path.dirname(opts["--summary"]), exist_ok=True)
        if self.server is not None:
            n = self.server.write(sid, opts, X.ENGINE_T0_OFFSET_S, max(1, len(local)), self.registry.get(_run_dir(opts), ()), loop_start)
        else:
            with gzip.open(opts["--records"], "wt") as fh:
                fh.write(RECORD_HEADER)
                for i in range(n):
                    due = (i + 0.5) * duration / n
                    fh.write(f"{i},{due:.6f},{due + 0.001:.6f},{due + 0.011:.6f},200,100,,0,1\n")
            write_summary(opts["--summary"], n, n, 0.002, (n - 0.5) * duration / n + 0.011 + X.ENGINE_T0_OFFSET_S)
        with open(opts["--summary"], encoding="utf-8") as fh:
            summary = json.load(fh)
        took = summary["wall_s"]
        if late:
            summary["wall_s"] = took - late
            with open(opts["--summary"], "w", encoding="utf-8") as fh:
                json.dump(summary, fh)
        if self.access_log and local:
            self._log_requests(local[0], loop_start + X.ENGINE_T0_OFFSET_S, duration, min(n, self.log_lines))
        return took, n

    def _log_requests(self, ip, zero, duration, count):
        with open(self.access_log, "a", encoding="utf-8") as fh:
            for i in range(count):
                ended = int(BASE_EPOCH + zero + (i + 0.5) * duration / count)
                fh.write(json.dumps({"timestamp": _iso(ended), "client_ip": ip, "request_method": "GET",
                                     "request_uri": "/static/1", "status": 200, "request_time": 0.01,
                                     "request_length": 100, "bytes_sent": 200, "user_agent": "fake"}) + "\n")

    # --- the suite's primitives ------------------------------------------------------------------

    def prim(self, name, *args):
        self.prims.append((name, args))
        self.commands.append(("prim", "", (name, *map(str, args))))
        if name == "bridge":
            self.topologies += 1                     # one topology is built per run, and again for a retried setup
            self.faults.update(self.fault_schedule.get(self.topologies, {}))
            self.links.add(X.BRIDGE)
        elif name == "server_ns":
            self.namespaces[X.SERVER_NS] = {"addresses": [] if self.fault("server_address_missing") else [X.SERVER_IP],
                                            "mac": "02:00:0a:00:00:01", "profile": "perfect"}
            self.links.add(X.SERVER_VETH_HOST_END)
        elif name == "client_ns":
            ns, address = args
            self.links.add(X.outer_veth(ns))
            mac = "02:00:" + ":".join(f"{int(o):02x}" for o in address.split("."))
            if self.fault("duplicate_mac"):
                mac = "12:af:eb:2d:8a:f2"
            self.namespaces[ns] = {"addresses": [] if self.fault("missing_address") else [address], "mac": mac,
                                   "profile": "perfect"}
        elif name == "netem":
            ns, profile = args
            if not self.fault("no_netem"):
                self.namespaces[ns]["profile"] = profile
        else:
            raise AssertionError(f"the simulation does not know the primitive {name}")

    # --- commands --------------------------------------------------------------------------------

    def run(self, argv, ns="", stdin="", env=None, timeout=None):
        argv = [str(a) for a in argv]
        self.commands.append(("run", ns, tuple(argv)))
        self.call_timeout = timeout or X.RealHost.COMMAND_TIMEOUT_S
        if self.run_cost_s and (cost := self.run_cost_s(argv)):
            self.sleep(cost)
        if argv[:3] == ["ip", "netns", "del"] and not self.shield:
            self.unshielded.append(tuple(argv))
        handler = getattr(self, "_cmd_" + os.path.basename(argv[0]).replace("-", "_"), None)
        if handler is None:
            return X.Result(127, "", f"fake: no such command {argv[0]}")
        return handler(argv[1:], ns, stdin)

    def _cmd_ip(self, a, ns, stdin):
        if a[:2] == ["netns", "list"]:
            return X.Result(0, "".join(f"{n} (id: {i})\n" for i, n in enumerate(self.namespaces)), "")
        if a[:2] == ["netns", "pids"]:
            return X.Result(0, "".join(f"{p.pid}\n" for p in self.alive(a[2])), "")
        if a[:2] == ["netns", "del"]:
            if a[2] not in self.namespaces:
                return X.Result(1, "", "Cannot remove namespace file: No such file or directory")
            del self.namespaces[a[2]]
            self.links.discard(X.outer_veth(a[2]))
            return X.Result(0, "", "")
        if a[:2] == ["link", "del"]:
            if a[2] not in self.links:
                return X.Result(1, "", f'Cannot find device "{a[2]}"')
            self.links.discard(a[2])
            return X.Result(0, "", "")
        if a[:3] == ["-br", "link", "show"]:
            return X.Result(0, "".join(f"{n}{'@if9' if n.startswith('vo_') else ''} UP 02:00:00:00:00:01 <BROADCAST,UP>\n"
                                       for n in sorted(self.links)), "")
        if a[:2] == ["-batch", "-"]:
            return self._batch(ns, stdin)
        if a[:3] == ["-j", "addr", "show"]:
            info = self.namespaces.get(ns)
            if info is None:
                return X.Result(1, "", "Cannot open network namespace")
            return X.Result(0, json.dumps([{"ifname": a[4], "addr_info": [{"family": "inet", "local": x, "prefixlen": 16}
                                                                          for x in info["addresses"]]}]), "")
        if a[:3] == ["-j", "link", "show"]:
            info = self.namespaces.get(ns)
            if info is None:
                return X.Result(1, "", "Cannot open network namespace")
            return X.Result(0, json.dumps([{"ifname": a[3], "address": info["mac"]}]), "")
        return X.Result(1, "", f"fake: unknown ip command {a}")

    def _batch(self, ns, stdin):
        info = self.namespaces.get(ns)
        if info is None:
            return X.Result(1, "", "Cannot open network namespace")
        for line in stdin.splitlines():
            m = re.fullmatch(r"addr add (\S+)/16 dev veth_in", line.strip())
            if not m:
                return X.Result(1, "", f"fake: unknown batch line {line!r}")
            info["addresses"].append(m.group(1))
        return X.Result(0, "", "")

    def _cmd_tc(self, a, ns, stdin):
        info = self.namespaces.get(ns)
        if a[:2] != ["qdisc", "show"] or info is None:
            return X.Result(1, "", "fake: unknown tc command")
        netem = info["profile"] != "perfect"
        return X.Result(0, "qdisc netem 8001: root refcnt 2 limit 1000 delay 20ms\n" if netem else
                        "qdisc noqueue 0: root refcnt 2\n", "")

    def _cmd_ping(self, a, ns, stdin):
        """ping answers (exit 0) if at least one of its `-c` packets is answered. `ping_drops(ns, source, k)` says whether the k-th
        packet (from 0) sent from `source` (None: the namespace's own address) in `ns` is lost on its way."""
        count = int(a[a.index("-c") + 1]) if "-c" in a else 1
        source = a[a.index("-I") + 1] if "-I" in a else None
        if self.fault("ping_fails"):
            return X.Result(1, "", "100% packet loss")
        received = sum(not (self.ping_drops and self.ping_drops(ns, source, k)) for k in range(count))
        return X.Result(0, f"{received} received", "") if received else X.Result(1, "", "100% packet loss")

    def _cmd_ps(self, a, ns, stdin):
        if a != ["-eo", "pid=,ppid=,args="] or self.fault("table_unreadable"):
            return X.Result(1, "", "ps: cannot read the process table")
        rows = [(4000, 1, "sudo ./venv/bin/python bench/executor.py run spec --out /var/tmp/gunicorn/nginx/C"),
                (self.pid(), 4000, "/repo/venv/bin/python bench/executor.py run spec --out /var/tmp/gunicorn/nginx/C")]
        rows += [(p.pid, 1, " ".join(exec_args(p.argv))) for p in self.alive()]
        rows += self.table_extra
        return X.Result(0, "".join(f"{pid:>7} {ppid:>7} {args}\n" for pid, ppid, args in rows), "")

    def _cmd_kill(self, a, ns, stdin):
        sig = {"-TERM": signal.SIGTERM, "-KILL": signal.SIGKILL}[a[0]]
        for pid in a[1:]:
            if int(pid) in self.procs:
                self.deliver(self.procs[int(pid)], sig)
        return X.Result(0, "", "")

    def _cmd_git(self, a, ns, stdin):
        a = a[a.index("-C") + 2:] if "-C" in a else a
        if a[:2] == ["rev-parse", "HEAD"]:
            return X.Result(0, "0123456789abcdef0123456789abcdef01234567\n", "")
        if a[:2] == ["rev-parse", "--abbrev-ref"]:
            return X.Result(0, "feat/hg1c\n", "")
        if a[0] == "status":
            return X.Result(0, " M bench/executor.py\n" if self.dirty else "", "")
        return X.Result(1, "", "fake: unknown git command")

    def _cmd_taskset(self, a, ns, stdin):
        rest = a[2:]
        if "timer-probe" in rest:
            return X.Result(0, json.dumps({"interval_s": 0.01, "samples": 200, "p50_ms": 0.1, "p99_ms": self.timer_p99_ms,
                                           "max_ms": self.timer_p99_ms * 2}), "")
        if "origin-session" in rest:
            return self._origin_session()
        if rest and rest[0] == "nginx":
            return self._cmd_nginx(rest[1:], ns, stdin, cpus=a[1])
        return X.Result(127, "", f"fake: no such command under taskset: {rest[:1]}")

    def _origin_session(self):
        """One session of the calibrator's step 1: the cost of each route in ms, each session scaled by its own factor of
        `origin_noise` (cycled), so that sessions can disagree by a known amount."""
        costs = self.origin_costs or ({k: v * 1000.0 for k, v in self.server.cost.items()} if self.server else
                                      {klass: 1.0 for klass in O.CLASSES})
        factor = 1.0 + self.origin_noise[self.origin_calls % len(self.origin_noise)]
        self.origin_calls += 1
        if self.fault("origin_session_fails"):
            return X.Result(1, "", "Traceback: the simulated session failed")
        return X.Result(0, json.dumps({k: v * factor for k, v in costs.items()}), "")

    def _cmd_nginx(self, a, ns, stdin, cpus=None):
        """Nginx run to completion with its output captured: the daemon forks and the call, whose pipes it holds, returns at its timeout."""
        code, message = self._daemon_start(a, ns, cpus)
        if code != 0:
            return X.Result(code, "", message)
        if self.daemon_holds_pipes:
            self.sleep(self.call_timeout)
            return X.Result(-1, "", "timeout")
        return X.Result(0, "", "")

    def _daemon_start(self, a, ns, cpus=None):
        """What starting the Nginx daemon on the configuration `a` names does: (0, "") with its master and a worker in `ns`, or the
        exit code and message of a start that fails."""
        if self.fault("nginx_fails"):
            return 1, "nginx: [emerg] bind() to 0.0.0.0:80 failed"
        with open(a[a.index("-c") + 1], encoding="utf-8") as fh:
            m = re.search(r"access_log\s+(\S+)\s+json_ml_format;", fh.read())
        self.access_log = m.group(1) if m else None
        for role in ("master", "worker"):
            proc = self.spawn(["nginx:", f"{role} process"], ns, "nginx", "nginx")
            proc.cpus = cpus or proc.cpus
            proc.immortal = self.fault_peek("leftover_nginx_after_teardown")
            proc.ignores_term = self.fault_peek("stubborn_nginx")
        return 0, ""

    def _cmd_mkdir(self, a, ns, stdin):
        return X.Result(0, "", "")                 # /var/log/nginx: the model does not touch the machine

    def _cmd_openssl(self, a, ns, stdin):
        return X.Result(0, "", "")

    def _cmd_touch(self, a, ns, stdin):
        for path in a:
            open(path, "a", encoding="utf-8").close()
        return X.Result(0, "", "")

    def _cmd_chmod(self, a, ns, stdin):
        return X.Result(0, "", "")

    def _stack_ready(self):
        origin = [p for p in self.alive() if p.role == "origin"]
        nginx = [p for p in self.alive() if p.role == "nginx"]
        return bool(origin and nginx) and self.origin_ready_at is not None and self.t >= self.origin_ready_at \
            and not self.fault_peek("not_ready")

    def fault_peek(self, name):
        return name in self.faults and self.faults[name] != 0

    def _cmd_curl(self, a, ns, stdin):
        path = "/" + a[-1].split("//", 1)[1].split("/", 1)[1]
        if not self._stack_ready():
            return X.Result(7, "000" if "-w" in a else "", "connection refused")
        if "-w" in a:
            return X.Result(0, "200", "")
        klass = CLASS_OF_PATH.get(path, "")
        if klass == "C3" and self.fault("wrong_class"):
            klass = "C1"
        tag = "frozen:00000000" if self.fault("wrong_tag") else self.tag
        return X.Result(0, f"HTTP/1.1 200 OK\r\nX-Origin-Calibration: {tag}\r\nX-Route-Class: {klass}\r\nX-Work: 5\r\n\r\n", "")

    # --- the files of /proc and /sys -------------------------------------------------------------

    def read_text(self, path):
        if path == "/proc/uptime":
            return f"{self.uptime_s + self.t:.2f} 0.00\n"
        if path == "/proc/loadavg":
            return f"{self.load1:.2f} 0.10 0.05 1/100 1234\n"
        if path == "/proc/meminfo":
            return "MemTotal:        9652224 kB\nMemFree:         8000000 kB\n"
        if path == "/proc/stat":
            return self._stat()
        if path.startswith("/sys/"):
            raise FileNotFoundError(path)
        m = re.fullmatch(r"/proc/(\d+)/(\w+(?:/\w+)?)", path)
        if m:
            return self._proc_file(int(m.group(1)), m.group(2), path)
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    def _stat(self):
        total = int(self.t * 100)
        lines = []
        for name, busy in [("cpu", 0.1)] + [(f"cpu{i}", 0.1) for i in range(CPUS)]:
            n = total * (CPUS if name == "cpu" else 1)
            user, steal = int(n * busy), int(n * self.steal_share)
            lines.append(f"{name} {user} 0 0 {n - user - steal} 0 0 0 {steal} {user // 2} 0")      # guest time is in user's already
        return "\n".join(lines) + "\n"

    def _proc_file(self, pid, what, path):
        proc = self.procs.get(pid)
        if proc is None or proc.returncode is not None:
            raise FileNotFoundError(path)
        if what == "comm":
            return proc.comm + "\n"
        if what == "stat":
            user = proc.jiffies() * 3 // 5                      # utime and stime are summed by whoever reads the CPU of a process
            return f"{pid} ({proc.comm}) S 1 1 1 0 0 0 0 0 0 0 {user} {proc.jiffies() - user} 0 0 20 0 1 0 100 1000000 100\n"
        if what == "status":
            return f"Name:\tx\nVmRSS:\t   25000 kB\nCpus_allowed_list:\t{proc.cpus}\n"
        if what == "limits":
            return ("Limit                     Soft Limit           Hard Limit           Units     \n"
                    "Max cpu time              unlimited            unlimited            seconds   \n"
                    f"Max open files            {self.nofile[0]:<20} {self.nofile[1]:<20} files     \n")
        if what == "net/netstat":
            n = int(self.t) // 10
            return f"TcpExt: SyncookiesSent ListenOverflows ListenDrops\nTcpExt: 0 {n} {n}\n"
        if what == "net/sockstat":
            return "sockets: used 20\nTCP: inuse 17 orphan 0 tw 5 alloc 20 mem 3\n"
        raise FileNotFoundError(path)

    def exists(self, path):
        m = re.fullmatch(r"/proc/(\d+)", path)
        if m:
            proc = self.procs.get(int(m.group(1)))
            return proc is not None and proc.returncode is None
        if path == os.path.join(REPO, "venv", "bin", "python"):
            return self.python_exists
        if path == X.CERT:
            return True
        return os.path.exists(path)

    # --- the rest of the machine -----------------------------------------------------------------

    def is_root(self):
        return self.root

    def nofile_limit(self):
        return self.nofile

    def clk_tck(self):
        return 100

    def facts(self):
        return {"uname": "Linux fake 7.0.0 x86_64", "cpus": CPUS, "mem_mib": 9426, "python": "3.14.4",
                "nginx": "nginx version: nginx/1.28.3", "gunicorn": "gunicorn (version 26.2.0)"}

    def pin(self, cpus):
        self.pinned = cpus

    def pid(self):
        return 4242

    @contextlib.contextmanager
    def shielded(self):
        self.shield = True
        try:
            yield
        finally:
            self.shield = False

    # --- what the tests look at ------------------------------------------------------------------

    def testbed(self):
        """Everything of the model that a teardown should have emptied."""
        return {"namespaces": sorted(self.namespaces), "links": sorted(self.links),
                "processes": sorted((p.comm, p.role) for p in self.alive())}

    def ran(self, *prefix):
        """The commands (kind, ns, argv) whose argv starts with `prefix`."""
        return [c for c in self.commands if c[2][:len(prefix)] == prefix]

    def kinds(self):
        return collections.Counter(c[0] for c in self.commands)


def _iso(epoch):
    return datetime.datetime.fromtimestamp(epoch, datetime.UTC).isoformat()


def _run_dir(opts):
    """The directory of the run a stream belongs to: <run>/streams/<id>/loadgen.summary.json."""
    return os.path.dirname(os.path.dirname(os.path.dirname(opts["--summary"])))


def write_summary(path, intended, completed, slip_p99, wall, errors=None):
    """The engine's summary, with the keys the harm gate reads."""
    summary = {"schema": 1, "tool": "loadgen", "intended": intended, "sent": intended, "dropped": 0, "completed": completed,
               "errors": errors or {}, "slip_s": {"p99": slip_p99}, "cpu": {"share": 0.02, "process_s": 0.1, "spin_s": 0.0},
               "wall_s": wall, "flags": dict(OK_FLAGS), "valid": True}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh)


# --- what the simulated stack does to the requests ------------------------------------------------

# the suite's links on the request path (mean delay, jitter, loss; seconds): docs/HG1C_DESIGN.md 4.1 and Appendix A
LINKS = {"perfect": (0.0, 0.0, 0.0), "broadband": (0.020, 0.002, 0.0), "mobile_3g": (0.150, 0.040, 0.02),
         "mobile_bad": (0.300, 0.080, 0.06)}
RETRANSMIT_S = 0.3                          # a lost packet costs a retransmission
TIMEOUT_S = 10.0                            # the engine's request timeout
ATTACK_RECORDS = 200                        # the harm gate reads the summary of an attack stream, not its records
# effects by run name, as the tests of the harm gate have them: the attack run U fails 30 % of the legit requests in its window
# (a gate that passes), none (one that fails), 4 % (below the floor), or slows them three times (a latency-only harm)
EFFECT_PRESETS = {"pass": {"U": {"fail_p": 0.3}}, "fail": {}, "small": {"U": {"fail_p": 0.04}}, "latency": {"U": {"slow": 3.0}}}


def origin_tag(cal):
    """The X-Origin-Calibration the origin answers with under `cal` (bench/origin.py, app_from_env)."""
    return f"frozen:{cal['sha256'][:8]}" if cal.get("status") == "frozen" else "placeholder"


def parse_stream_id(sid):
    """(kind, route class, link profile) of a stream from its id: `L-<process>-<class>-<profile>-<n>` for a legit stream and
    `A-<family>-<profile>-<n>` for an attack stream (bench/population.py), with `S<k>-` before it in a step of a staged load."""
    parts = sid.split("-")
    if re.fullmatch(r"S\d+", parts[0]):                 # a step of a staged load
        parts = parts[1:]
    if parts[0] == "L":
        return "legit", parts[2], parts[3]
    return "attack", P.ATTACK_FAMILIES[parts[1]].route_class, parts[2]


class SyntheticServer:
    """The effect of a simulated stack on a run's requests: each legit request costs its route's time from the calibration plus
    its link's delay, and then one of two things happens to it.

    With `effects`, a run named in it (C, Cp, U) has the legit requests inside the attack's window fail with probability
    `fail_p` (a timeout) and the others take `slow` times as long: a harm of a known size, for the tests of the gate and of
    the campaign. `effects` maps a run name to {"fail_p", "slow", "slip"}.

    With `capacity_cpu` (CPU-seconds a second the server can do), the harm comes from the load: at each request's time the streams
    of the run that are running offer rate x route cost, and where that exceeds the capacity the share that does not fit fails
    and the rest take as many times longer as the load is over the capacity (u = load / capacity; a request fails with
    probability 1 - 1/u when u > 1). The capacity and the ladders of the calibrator find a known capacity and a known knee in it.

    The random draws depend on the run's directory and its parent's name (b03_a1/U), so two attack-free runs of a block differ the way a
    control and its placebo do, and the repeats of a level differ from one another; the same run made again is the same. Not a model
    of any server."""

    def __init__(self, cal, timeline, effects=None, seed=1, capacity_cpu=None):
        self.cost = {klass: ms / 1000.0 for klass, ms in cal["route_costs_ms"].items()}
        baseline, attack = float(timeline[0]), float(timeline[1])
        self.window = (baseline, baseline + attack)
        self.effects = effects or {}
        self.seed = seed
        self.capacity_cpu = capacity_cpu

    def utilisation(self, times, begin, others):
        """Load over capacity at `times` (seconds into the stream) of a stream that began at `begin`, from the streams in
        `others` (dicts with kind, begin, end, rate, route; times of the host's clock): the run's axis starts where the first
        legit stream began."""
        zero = min((o["begin"] for o in others if o["kind"] == "legit"), default=begin)
        at = (begin - zero) + times
        load = np.zeros(len(times))
        for o in others:
            load += np.where((at >= o["begin"] - zero) & (at < o["end"] - zero), o["rate"] * self.cost[o["route"]], 0.0)
        return load / self.capacity_cpu

    def write(self, sid, opts, wall, identities, others=(), begin=0.0):
        """The records and the summary of one stream at the paths in `opts`; returns the number of requests it intended. The wall
        time in the summary is `wall` or, if more, until the last request was answered (a timeout included) plus the engine's offset."""
        run_dir = _run_dir(opts)
        run = os.path.basename(run_dir)
        label = f"{os.path.basename(os.path.dirname(run_dir))}/{run}"          # b03_a1/U, 07_L2_r1/U: what makes a run this run
        kind, route, profile = parse_stream_id(sid)
        sched = np.array(LG.schedule(opts.get("--process", "constant"), float(opts["--rate"]), float(opts["--duration"]),
                                     int(opts.get("--seed", 1)), period=float(opts.get("--period", 1.0)),
                                     duty=float(opts.get("--duty", 0.5))))
        n = len(sched)
        rng = np.random.default_rng([self.seed, zlib.crc32(label.encode()), zlib.crc32(sid.encode()), int(opts.get("--seed", 1))])
        effect = self.effects.get(run, {}) if kind == "legit" else {}
        slip = effect.get("slip", 0.002) * (0.5 + rng.random(n))
        sent = sched + slip
        service = self.cost[route] * rng.lognormal(0.0, 0.2, n)
        mean, jitter, loss = LINKS[profile]
        link = np.maximum(0.0, rng.normal(mean, jitter, n)) + np.where(rng.random(n) < loss, RETRANSMIT_S, 0.0)
        if self.capacity_cpu and kind == "legit":
            u = self.utilisation(sched, begin, others)
            over = np.maximum(u, 1.0)
            bad = rng.random(n) < 1.0 - 1.0 / over
            service = service * over + link
        else:
            hit = (sched >= self.window[0]) & (sched < self.window[1]) & (kind == "legit")
            bad = hit & (rng.random(n) < effect.get("fail_p", 0.0))
            service = np.where(hit & ~bad, service * effect.get("slow", 1.0), service) + link
        done = sent + service
        done[bad] = sent[bad] + TIMEOUT_S
        rows = n if kind == "legit" else min(n, ATTACK_RECORDS)
        with gzip.open(opts["--records"], "wt") as fh:
            fh.write(RECORD_HEADER)
            for i in range(rows):
                failed = bool(bad[i])
                fh.write(f"{i},{sched[i]:.6f},{sent[i]:.6f},{done[i]:.6f},{0 if failed else 200},100,"
                         f"{'timeout' if failed else ''},{i % identities},1\n")
        if n:                                          # the loop ends when its last request has, a timeout included
            wall = max(wall, float(done.max()) + X.ENGINE_T0_OFFSET_S)
        write_summary(opts["--summary"], n, int(n - bad.sum()), float(np.quantile(slip, 0.99)) if n else None, wall,
                      {"timeout": int(bad.sum())} if bad.any() else None)
        return n
