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
ENGINE_DRAIN_S = 0.15                     # the engine's wait for requests in flight after its last send
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
    `dies` is a predicate on a stream id: those streams die at their start. The names the tests use:
    missing_address, duplicate_mac, no_netem, ping_fails, nginx_fails, origin_dies, not_ready, wrong_class, wrong_tag,
    stubborn_origin, stubborn_nginx, leftover_nginx_after_teardown, server_address_missing, stream_dies, stream_silent,
    stream_nonzero, stream_hangs, table_unreadable."""

    def __init__(self, root=True, dirty=False, nofile=(524288, 524288), uptime_s=7200.0, load1=0.05, timer_p99_ms=1.0,
                 preexisting=(), startup_s=None, exit_delay_s=0.04, exit_delay_per_request_s=0.0, faults=None,
                 log_lines=20, tag="placeholder", python_exists=True, steal_share=0.0, on_sleep=None, server=None,
                 fault_schedule=None, dies=None):
        self.t = 0.0
        self.pids = itertools.count(1000)
        self.events, self.seq = [], itertools.count()
        self.procs = {}
        self.namespaces, self.links = {}, set()
        self.commands, self.prims, self.sleeps = [], [], []
        self.root, self.dirty, self.nofile = root, dirty, nofile
        self.uptime_s, self.load1, self.timer_p99_ms = uptime_s, load1, timer_p99_ms
        self.exit_delay_s, self.exit_delay_per_request_s = exit_delay_s, exit_delay_per_request_s
        self.startup_s = startup_s or (lambda sid, index, kind: (1.8 if kind == "legit" else 0.3) + 0.002 * index)
        self.faults = dict(faults or {})
        self.fault_schedule, self.topologies, self.dies = dict(fault_schedule or {}), 0, dies
        self.log_lines, self.tag, self.python_exists, self.steal_share = log_lines, tag, python_exists, steal_share
        self.on_sleep, self.server = on_sleep, server
        self.table_extra = []                 # (pid, ppid, args) of processes that are not the model's: an editor, a shell
        self.shield, self.unshielded = False, []
        self.pinned = None
        self.stream_index = 0
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
        if "gunicorn" in text:
            return self._start_origin(argv, ns, stderr)
        raise AssertionError(f"the simulation has no process for {text[:100]}")

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
        index, self.stream_index = self.stream_index, self.stream_index + 1
        self.launch_times[sid] = self.t
        if self.fault("stream_hangs"):
            return proc
        loop_start = self.t + self.startup_s(sid, index, kind)
        duration, rate = float(opts["--duration"]), float(opts["--rate"])
        n = max(1, round(rate * duration))
        wall = X.ENGINE_T0_OFFSET_S + duration + ENGINE_DRAIN_S
        if self.fault("stream_dies") or (self.dies is not None and self.dies(sid)):
            if stderr is not None:
                stderr.write(b"Traceback: the simulated engine died\n")
            self.schedule(loop_start + 3.0, lambda: self.end(proc, 2))
            return proc
        exit_at = loop_start + wall + self.exit_delay_s + self.exit_delay_per_request_s * n
        silent, code = self.fault("stream_silent"), 3 if self.fault("stream_nonzero") else 0
        self.schedule(exit_at, lambda: self._finish_stream(proc, sid, opts, local, loop_start, wall, n, silent, code))
        return proc

    def _finish_stream(self, proc, sid, opts, local, loop_start, wall, n, silent, code):
        if proc.returncode is not None:
            return
        if not silent:
            self._write_stream(sid, opts, local, loop_start, wall, n)
        self.end(proc, code)

    def _write_stream(self, sid, opts, local, loop_start, wall, n):
        duration = float(opts["--duration"])
        os.makedirs(os.path.dirname(opts["--summary"]), exist_ok=True)
        if self.server is not None:
            n = self.server.write(sid, opts, wall, max(1, len(local)))
        else:
            with gzip.open(opts["--records"], "wt") as fh:
                fh.write(RECORD_HEADER)
                for i in range(n):
                    due = (i + 0.5) * duration / n
                    fh.write(f"{i},{due:.6f},{due + 0.001:.6f},{due + 0.011:.6f},200,100,,0,1\n")
            write_summary(opts["--summary"], n, n, 0.002, wall)
        if self.access_log and local:
            self._log_requests(local[0], loop_start + X.ENGINE_T0_OFFSET_S, duration, min(n, self.log_lines))

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
        return X.Result(1, "", "100% packet loss") if self.fault("ping_fails") else X.Result(0, "1 received", "")

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
        if rest and rest[0] == "nginx":
            return self._cmd_nginx(rest[1:], ns, stdin, cpus=a[1])
        return X.Result(127, "", f"fake: no such command under taskset: {rest[:1]}")

    def _cmd_nginx(self, a, ns, stdin, cpus=None):
        if self.fault("nginx_fails"):
            return X.Result(1, "", "nginx: [emerg] bind() to 0.0.0.0:80 failed")
        with open(a[a.index("-c") + 1], encoding="utf-8") as fh:
            m = re.search(r"access_log\s+(\S+)\s+json_ml_format;", fh.read())
        self.access_log = m.group(1) if m else None
        for role in ("master", "worker"):
            proc = self.spawn(["nginx:", f"{role} process"], ns, "nginx", "nginx")
            proc.cpus = cpus or proc.cpus
            proc.immortal = self.fault_peek("leftover_nginx_after_teardown")
            proc.ignores_term = self.fault_peek("stubborn_nginx")
        return X.Result(0, "", "")

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
    its link's delay, and in a run named in `effects` the legit requests inside the attack's window fail with probability `fail_p`
    (a timeout) and the others take `slow` times as long. `effects` maps a run name (C, Cp, U) to {"fail_p", "slow", "slip"}; the
    random draws depend on the run, so two attack-free runs differ the way a control and its placebo do. Not a model of any
    server: it makes a harm of a known size so that the protocol around it can be seen to find it, or not to."""

    def __init__(self, cal, timeline, effects=None, seed=1):
        self.cost = {klass: ms / 1000.0 for klass, ms in cal["route_costs_ms"].items()}
        baseline, attack = float(timeline[0]), float(timeline[1])
        self.window = (baseline, baseline + attack)
        self.effects = effects or {}
        self.seed = seed

    def write(self, sid, opts, wall, identities):
        """The records and the summary of one stream at the paths in `opts`; returns the number of requests it intended."""
        run = os.path.basename(_run_dir(opts))
        kind, route, profile = parse_stream_id(sid)
        sched = np.array(LG.schedule(opts.get("--process", "constant"), float(opts["--rate"]), float(opts["--duration"]),
                                     int(opts.get("--seed", 1)), period=float(opts.get("--period", 1.0)),
                                     duty=float(opts.get("--duty", 0.5))))
        n = len(sched)
        rng = np.random.default_rng([self.seed, zlib.crc32(run.encode()), zlib.crc32(sid.encode()), int(opts.get("--seed", 1))])
        effect = self.effects.get(run, {}) if kind == "legit" else {}
        slip = effect.get("slip", 0.002) * (0.5 + rng.random(n))
        sent = sched + slip
        service = self.cost[route] * rng.lognormal(0.0, 0.2, n)
        mean, jitter, loss = LINKS[profile]
        link = np.maximum(0.0, rng.normal(mean, jitter, n)) + np.where(rng.random(n) < loss, RETRANSMIT_S, 0.0)
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
        write_summary(opts["--summary"], n, int(n - bad.sum()), float(np.quantile(slip, 0.99)) if n else None, wall,
                      {"timeout": int(bad.sum())} if bad.any() else None)
        return n
