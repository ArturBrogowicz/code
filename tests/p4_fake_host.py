"""A fake host for eval/p4_runner.py, in the style of bench/sim_host.py's SimHost: commands are recorded and answered
from a small model, processes live on a virtual clock, and the files a real run leaves are written where the runner
asks for them. Nothing here touches the machine: no namespace, no socket, no process.

The model, as far as the runner's outputs need it:
  * nginx starts as the real one does (review T-057 T057-01): `popen` with no pipe gives a launcher that returns at once, or exits 1 with its message on
    its stderr (`nginx_fails`), or never returns (`nginx_hangs`); `run`, which captures its output, comes back only at its 120-s timeout, with -1;
  * the stack answers its readiness probe and stub_status (except over `stub_fails`, seconds of the run: slots exhausted);
  * a generator (ml/l7_gen.py) exits 0 at the end of its duration, or `gen_late[its address]` seconds later (or `gen_code`
    for the entities named in `gen_fails`). A benign plan-kind generator writes its client-side rows (ml/l7_gen.py --records) at its exit, from
    its own plan (ml/l7_benign.plan_client with its seed): each request answered 200 in 30 ms, except while the
    attack harms (`harm(arm, t)`, by default while any attack connection is held), when it fails with err "conn";
  * the world's sockets on :80/:443 as `ss -tinpH` prints them: one answered keep-alive connection per benign
    generator, a slow uploader's connection unanswered at 2,000 B/s, and the connections of the first
    `modelled_attackers` attack sources, unanswered and dribbling (a line every 20 s); a connection the rule closes is
    re-opened 10 s later with a new port, and a banned address holds none;
  * an attack generator writes its --stats at its exit (`attack_fails`: nothing opens, for a local reason;
    `attack_opened_share`: the share that opens, the rest refused; None: no stats); a group (--group, D-075) is its sources'
    generators in one process: each source opens its connections and writes its own stats, `gen_fails` and `gen_late` name a
    source's address, and the group exits with the code and at the time of its latest source;
  * nginx's access log (l7json, written where the runner moves it): one line per answered request of a plan-kind
    generator and one per other benign generator; behind nginx_profile_r_limits.conf a share `limit_refuses` of a CGNAT
    pool's requests is refused with a 503, which its client also records;
  * the daemon (control_plane.py): `daemon_startup_s` after its start it prints its ready line and XDP's, writes its
    start event to BAN_EVENTS; with SLOW_PC=1, every `poll_every_s` it records the snapshot (slow_pc.record_member
    into SLOW_PC_RECORD), emits slow_pc_poll, and runs slow_pc.Detector at its SLOW_PC_T/F/K: in shadow its decisions
    are logged, enforcing they close connections and ban addresses (events slow_pc_close and ban). It dies at
    `daemon_dies_at` (seconds after its start) if given; SIGINT ends it with 0.
"""
import collections
import contextlib
import csv
import gzip
import heapq
import itertools
import json
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
for _p in (REPO, os.path.join(REPO, "ml"), os.path.join(REPO, "bench")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import executor as X
import l7_benign
import l7_gen

import l7_webapp
import slow_pc

BASE_EPOCH = 1_800_000_000.0
NGINX = 'users:(("nginx",pid=4242,fd=17))'
STUB = "Active connections: {a} \nserver accepts handled requests\n {n} {n} {r} \nReading: 0 Writing: 2 Waiting: {w} \n"


def _opt(argv, name, default=None):
    return argv[argv.index(name) + 1] if name in argv else default


class Proc:
    def __init__(self, host, kind, argv, env, stdout):
        self.host, self.kind, self.argv, self.env, self.stdout = host, kind, list(argv), dict(env or {}), stdout
        self.pid = next(host.pids)
        self.returncode = None
        self.exit_time = None

    def poll(self):
        return self.returncode

    def terminate(self):
        self.host.end(self, -15)

    def interrupt(self):
        self.host.end(self, 0 if self.kind == "daemon" else -2)

    def kill(self):
        self.host.end(self, -9)


class FakeHost(X.Host):
    simulated = True

    def __init__(self, *, root=True, netns=(), kill_file=False, kill_appears_at=None, stack_ready=True,
                 nginx_fails=False, daemon_dies_at=None, daemon_startup_s=3.0, gen_fails=(), gen_code=3,
                 poll_every_s=1.0, modelled_attackers=None, harm=None, fail_prim=None, limit_refuses=0.0,
                 gen_late=None, stub_fails=None, ss_fails=None, attack_fails=False, attack_opened_share=1.0, no_socket_of=(),
                 garbled_bans=False, ban_file_lost=False, gen_stall=None, runner_stall=None, gunicorn_refuses=None,
                 gunicorn_dies=None, nginx_gone=False, nginx_hangs=False, ip_batch_fails=False, netem_fails=False, timer_p99=2.0,
                 interrupt_at=None, logs_rotate_at=None, interrupt_again=False, logs_rotate_at_clock=None):
        self.t = 0.0
        self.root, self.netns, self.stack_ready, self.nginx_fails = root, list(netns), stack_ready, nginx_fails
        self.kill_file, self.kill_appears_at = kill_file, kill_appears_at
        self.daemon_dies_at, self.daemon_startup_s = daemon_dies_at, daemon_startup_s
        self.gen_fails, self.gen_code, self.poll_every_s = set(gen_fails), gen_code, poll_every_s
        self.modelled_attackers, self.harm, self.fail_prim = modelled_attackers, harm, fail_prim
        self.limit_refuses, self.gen_late, self.stub_fails = limit_refuses, dict(gen_late or {}), stub_fails
        self.attack_fails, self.attack_opened_share = attack_fails, attack_opened_share   # share None: no stats at all
        self.ss_fails = ss_fails                # True: `ss` fails on every poll; (lo, hi): over those seconds of the run
        self.no_socket_of = set(no_socket_of)   # benign kinds whose generators hold no socket the rule can see
        self.garbled_bans, self.ban_file_lost = garbled_bans, ban_file_lost     # the daemon's BAN_EVENTS, as a run leaves it
        self.gen_stall = dict(gen_stall or {})  # address -> (seconds after the generator's start, seconds it stalls): its views slip
        self.runner_stall = runner_stall        # (seconds of the run, seconds): one of the runner's own sleeps overruns by that
        self.gunicorn_refuses = gunicorn_refuses  # text: gunicorn's master writes it to its log and exits 1 at once, before it serves
        self.gunicorn_dies = gunicorn_dies      # (seconds of the run, its exit code, what its log says then)
        self.nginx_gone, self.gunicorn = nginx_gone, None   # nginx_gone: its -s quit fails, as for a master that has died
        self.nginx_hangs = nginx_hangs          # its launcher never returns
        self.interrupt_at = interrupt_at        # seconds of the run: Ctrl-C reaches the runner in its sleep
        self.logs_rotate_at = logs_rotate_at    # seconds of the run: nginx's logs get a new inode
        self.logs_rotate_at_clock = logs_rotate_at_clock    # the same at a moment of the host's clock, before the traffic or after it
        self.interrupt_again = interrupt_again  # a Ctrl-C arrives at the teardown's first `ip netns del` (a second one, after interrupt_at's)
        self.shield_depth, self.ignored_interrupts = 0, 0
        self.timer_p99 = list(timer_p99) if isinstance(timer_p99, (list, tuple)) else [timer_p99]   # the timer probe's answers, the last repeated; None: unreadable
        self.ip_batch_fails, self.netem_fails = ip_batch_fails, netem_fails     # the runner's own commands of the topology exit non-zero
        self.pids, self.seq = itertools.count(100), itertools.count()
        self.events, self.commands, self.prims, self.procs = [], [], [], []
        self.reset_world()

    def reset_world(self):
        self.world = getattr(self, "world", 0) + 1
        self.socks = {}            # key -> {"ip", "port", "sport", "kind", "opened"}
        self.access, self.limits = [], False
        self.banned, self.closed_at = {}, {}
        self.attack_trace = []     # (t, held attack connections)
        self.ports = itertools.count(20000)
        self.detector = None
        self.run_t0 = None

    # --- clock ---------------------------------------------------------------------------------
    def time(self):
        return BASE_EPOCH + self.t

    def monotonic(self):
        return self.t

    def at(self, t, fn):
        heapq.heappush(self.events, (t, next(self.seq), fn))

    def sleep(self, seconds):
        if self.interrupt_at is not None and self.run_t0 is not None and self.t - self.run_t0 >= self.interrupt_at:
            self.interrupt_at = None
            raise KeyboardInterrupt("signal 15")
        if self.runner_stall and self.run_t0 is not None and self.t - self.run_t0 >= self.runner_stall[0]:
            seconds += self.runner_stall[1]
            self.runner_stall = None
        end = self.t + seconds
        while self.events and self.events[0][0] <= end:
            t, _s, fn = heapq.heappop(self.events)
            self.t = max(self.t, t)
            fn()
        self.t = end

    # --- the host's face -------------------------------------------------------------------------
    def pin(self, cpus):
        self.commands.append(("", ("pin", cpus), ""))

    @contextlib.contextmanager
    def shielded(self):
        """As RealHost's: Ctrl-C, TERM and HUP are ignored inside."""
        self.shield_depth += 1
        try:
            yield
        finally:
            self.shield_depth -= 1

    def stat(self, path):
        rotated = (self.logs_rotate_at is not None and self.run_t0 is not None and self.t - self.run_t0 >= self.logs_rotate_at) or \
            (self.logs_rotate_at_clock is not None and self.t >= self.logs_rotate_at_clock)
        return (2 if rotated else 1), 100

    def is_root(self):
        return self.root

    def exists(self, path):
        if path == "/run/l7v2/kill":
            return self.kill_file or (self.kill_appears_at is not None and self.run_t0 is not None
                                      and self.t - self.run_t0 >= self.kill_appears_at)
        return os.path.exists(path)

    def read_text(self, path):
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    def prim(self, name, *args):
        self.prims.append((name, *args))
        if self.fail_prim == name:
            raise OSError(f"{name} failed")

    def run(self, argv, ns="", stdin="", env=None, timeout=None):
        argv = list(argv)
        self.commands.append((ns, tuple(argv), stdin))
        if "timer-probe" in argv:
            p99 = self.timer_p99.pop(0) if len(self.timer_p99) > 1 else self.timer_p99[0]
            return X.Result(0, "" if p99 is None else json.dumps({"p50_ms": 1.0, "p99_ms": p99, "max_ms": p99 + 1.0}), "")
        if argv[:2] == ["ip", "-batch"] and self.ip_batch_fails:
            return X.Result(2, "", "RTNETLINK answers: File exists\n")
        if argv[:2] == ["tc", "qdisc"] and self.netem_fails:
            return X.Result(2, "", "Error: Specified qdisc not found.\n")
        if argv[:3] == ["ip", "netns", "del"] and self.interrupt_again:
            self.interrupt_again = False
            if not self.shield_depth:
                self.commands.append((ns, tuple(argv), stdin))
                raise KeyboardInterrupt("signal 2, again")
            self.ignored_interrupts += 1
        if argv[:3] == ["ip", "netns", "list"]:
            return X.Result(0, "".join(f"{n}\n" for n in self.netns), "")
        if argv[0] == "curl" and argv[-1].endswith("/nginx_status"):
            if self.stub_fails and self.run_t0 is not None and self.stub_fails[0] <= self.t - self.run_t0 < self.stub_fails[1]:
                self.t += 1.0                      # curl's --max-time: the listener's slots are gone
                return X.Result(28, "", "timed out")
            held = sum(1 for _ in self.socks)
            return X.Result(0, STUB.format(a=held, n=10 + int(self.t), r=30 + 3 * int(self.t), w=held), "")
        if argv[0] == "curl":
            dead = self.gunicorn is not None and self.gunicorn.returncode is not None
            return X.Result(0, "200" if self.stack_ready and not dead else "502", "")
        if "nginx" in argv and "-s" in argv and self.nginx_gone:
            return X.Result(1, "", "nginx: [error] kill() failed (3: No such process)")
        if argv[:3] == ["mv", "-f", "/var/log/nginx/l7_capture.log"] and self.access:
            with open(argv[3], "w", encoding="utf-8") as fh:
                fh.writelines(json.dumps(x) + "\n" for x in self.access)
            self.access = []
            return X.Result(0, "", "")
        if "nginx" in argv and "-s" not in argv:            # captured, its daemon keeps the pipe: only the timeout ends the call
            self.sleep(timeout or X.RealHost.COMMAND_TIMEOUT_S)
            return X.Result(-1, "", "timeout")
        return X.Result(0, "", "")

    def popen(self, argv, ns="", env=None, stdout=None, stderr=None, cwd=None):
        argv = list(argv)
        self.commands.append((ns, tuple(argv), "popen"))
        text = " ".join(argv)
        if "control_plane.py" in text:
            p = Proc(self, "daemon", argv, env, stdout)
            self.procs.append(p)
            self._start_daemon(p)
            return p
        if "l7_gen.py" in text:
            p = Proc(self, "gen", argv, env, stdout)
            p.stderr_name = getattr(stderr, "name", None)
            self.procs.append(p)
            self._start_gen(p)
            return p
        p = Proc(self, "server", argv, env, stdout)
        self.procs.append(p)
        if "nginx" in argv and "-s" not in argv:            # a run's stack starts: a new world, and the launcher returns once it has forked
            self.reset_world()
            self.limits = any("limits" in a for a in argv)
            if self.nginx_fails:
                stderr.write(b"nginx: [emerg] unknown directive in the conf\n")
                self.end(p, 1)
            elif not self.nginx_hangs:
                self.end(p, 0)
        if "gunicorn" in text:
            self.gunicorn = p
            if self.gunicorn_refuses:
                self._gunicorn_stops(p, 1, self.gunicorn_refuses)
        return p

    def _gunicorn_stops(self, p, code, text):
        p.stdout.write(text)
        p.stdout.flush()
        self.end(p, code)

    def end(self, proc, code):
        if proc.returncode is None:
            proc.returncode, proc.exit_time = code, self.time()
            if proc.kind == "gen":
                self._gen_exit(proc)
            if proc.kind == "daemon" and self.ban_file_lost:
                os.remove(proc.env["BAN_EVENTS"])

    # --- generators ------------------------------------------------------------------------------
    def _start_gen(self, p):
        if self.run_t0 is None:
            self.run_t0 = self.t
            self._tick(self.world)
            if self.gunicorn_dies:
                at, code, text = self.gunicorn_dies
                self.at(self.t + at, lambda g=self.gunicorn, c=code, s=text: self._gunicorn_stops(g, c, s))
        a = p.argv
        if "--group" in a:
            return self._start_group(p)
        p.role, p.ip, p.port = _opt(a, "--role"), _opt(a, "--source"), int(_opt(a, "--port"))
        p.name = _opt(a, "--kind") or _opt(a, "--family")
        p.params, p.seed, p.dur = json.loads(_opt(a, "--params")), int(_opt(a, "--seed")), float(_opt(a, "--duration"))
        p.records, p.start, p.world = _opt(a, "--records"), self.t, self.world
        p.stats = _opt(a, "--stats")
        if p.role == "attack" and not self.attack_fails:
            n = len({q.ip for q in self.procs if q.kind == "gen" and getattr(q, "role", "") == "attack"
                     and q.world == self.world})
            if self.modelled_attackers is None or n <= self.modelled_attackers:
                for _ in range(p.params.get("conns", 1)):
                    self._open(p.ip, p.port, p.name)
        elif p.role != "attack" and p.name not in self.no_socket_of:
            self._open(p.ip, p.port, p.name)
        code = self.gen_code if p.ip in self.gen_fails else 0
        self.at(self.t + p.dur + 0.5 + self.gen_late.get(p.ip, 0.0), lambda: self.end(p, code))

    def _attack_ips(self):
        """The addresses of this world's attack sources started so far, grouped ones included."""
        return {ip for q in self.procs if q.kind == "gen" and getattr(q, "role", "") == "attack" and q.world == self.world
                for ip in getattr(q, "ips", (q.ip,)) if ip is not None}

    def _start_group(self, p):
        a = p.argv
        p.role, p.name, p.dur = "attack", _opt(a, "--family"), float(_opt(a, "--duration"))
        p.members, p.ip, p.ips, p.records, p.stats, p.start, p.world = json.loads(_opt(a, "--group"))["sources"], None, [], None, None, \
            self.t, self.world
        for m in p.members:
            p.ips.append(m["source"])
            if not self.attack_fails and (self.modelled_attackers is None or len(self._attack_ips()) <= self.modelled_attackers):
                for _ in range(m["params"].get("conns", 1)):
                    self._open(m["source"], int(m["port"]), p.name)
        code = self.gen_code if set(p.ips) & self.gen_fails else 0
        late = max((self.gen_late.get(ip, 0.0) for ip in p.ips), default=0.0)
        self.at(self.t + p.dur + 0.5 + late, lambda: self.end(p, code))

    def _open(self, ip, sport, kind):
        port = next(self.ports)
        self.socks[(ip, port, "10.0.0.1", sport)] = {"ip": ip, "port": port, "sport": sport, "kind": kind,
                                                     "opened": self.t}

    def _write_stats(self, p, params=None, path=None):
        conns = (params or p.params).get("conns", 1)
        opened = 0 if self.attack_fails else round(self.attack_opened_share * conns)
        with open(path or p.stats, "w", encoding="utf-8") as fh:
            json.dump({"opened": opened, "reopened": 0, "failed_opens": conns - opened, "sent_bytes": 14 * opened,
                       "local_errors": conns if self.attack_fails else 0}, fh)

    def _gen_exit(self, p):
        ips = getattr(p, "ips", [p.ip])
        if set(ips) & self.gen_fails and p.stderr_name:
            with open(p.stderr_name, "a", encoding="utf-8") as fh:
                fh.write("Traceback (most recent call last):\nOSError: [Errno 99] Cannot assign requested address\n")
        if p.stats and self.attack_opened_share is not None:
            self._write_stats(p)
        for m in getattr(p, "members", ()):
            if self.attack_opened_share is not None and m["source"] not in self.gen_fails:
                self._write_stats(p, m["params"], m["stats"])
        for key in [k for k, s in self.socks.items() if s["ip"] in ips]:
            del self.socks[key]
        if p.records:
            self._write_records(p)
        elif p.role == "benign":
            self._log(p, BASE_EPOCH + p.start + 60.0, "/upload", 200)

    def _log(self, p, sent, path, status):
        self.access.append({"msec": sent + 0.03, "rt": 0.03, "ip": p.ip, "port": 40000, "method": "GET", "uri": path,
                            "status": status, "lreq": "REJECTED" if status == 503 else "", "lconn": ""})

    def _tick(self, world):
        if world != self.world:
            return
        self.attack_trace.append((self.t, self._held_attack()))
        self.at(self.t + 1.0, lambda: self._tick(world))

    def harmed(self, t):
        if self.harm is not None:
            return self.harm(t)
        held = [n for tt, n in self.attack_trace if tt <= t]
        return bool(held) and held[-1] > 0

    def _write_records(self, p):
        plan = l7_benign.plan_client(p.name, p.params, p.dur, random.Random(p.seed))
        origin = BASE_EPOCH + p.start
        os.makedirs(os.path.dirname(p.records), exist_ok=True)
        with open(p.records, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(l7_gen.RECORD_COLUMNS)
            for u, user in enumerate(plan["users"]):
                items = []
                if "views" in user:
                    items = [(v["t"], vi, wi, path) for vi, v in enumerate(user["views"])
                             for wi, wave in enumerate(v["waves"]) for path in wave]
                else:
                    t = 0.0
                    for vi, (path, gap, *_r) in enumerate(user["requests"]):
                        items.append((t, vi, 0, path))
                        t += gap
                every = round(1 / self.limit_refuses) if self.limits and self.limit_refuses \
                    and p.name == "cgnat_browsers" else 0
                for k, (t_nom, vi, wi, path) in enumerate(items):
                    stall_at, stall_s = self.gen_stall.get(p.ip, (p.dur, 0.0))
                    t_nom += stall_s if t_nom >= stall_at else 0.0
                    if t_nom >= p.dur:
                        continue
                    sent = origin + t_nom
                    bad = self.harmed(p.start + t_nom)
                    status = "nan" if bad else (503 if every and k % every == 0 else 200)
                    if not bad:
                        self._log(p, sent, path, status)
                    w.writerow([f"{sent:.6f}", f"{sent:.6f}", f"{sent + (0.1 if bad else 0.03):.6f}",
                                status, "conn" if bad else "",
                                l7_webapp.route_class("GET", path) or "", u, vi, wi, f"{sent:.6f}", f"{origin:.6f}"])

    # --- the world as ss prints it ---------------------------------------------------------------
    def ss_text(self):
        lines = []
        for s in self.socks.values():
            age = self.t - s["opened"]
            if s["kind"] in ("slowloris", "slowpost"):
                n = int(age // 20)
                acked, recv, segs = 0, 80 + 14 * n, 1 + n
            elif s["kind"] == "slow_uploader":
                acked, recv, segs = 0, 300 + int(2000 * age), 1 + int(4 * age)
            else:
                acked, recv, segs = 5200, 600 + int(40 * age), 2 + int(age)
            lines.append(f"0      0      10.0.0.1:{s['sport']}   {s['ip']}:{s['port']} {NGINX}\n"
                         f"\t cubic bytes_acked:{acked} bytes_received:{recv} data_segs_in:{segs}\n")
        return "".join(lines)

    # --- the daemon ------------------------------------------------------------------------------
    def _emit(self, p, kind, **fields):
        with open(p.env["BAN_EVENTS"], "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"t_wall": self.time(), "kind": kind, **fields}) + "\n")

    def _start_daemon(self, p):
        p.started = self.t

        def ready():
            if p.returncode is not None:
                return
            p.stdout.write("[+] Successfully attached XDP program to interface veth_server.\n"
                           "[*] Listening for Nginx logs (heuristic engine): /var/log/nginx/ddos_ml_access.log\n")
            p.stdout.flush()
            self._emit(p, "start", heuristic_profile=p.env.get("HEURISTIC_PROFILE"), slow_pc=p.env.get("SLOW_PC"))
            if self.garbled_bans:
                with open(p.env["BAN_EVENTS"], "a", encoding="utf-8") as fh:
                    fh.write('{"kind": "ban", "ip": "10.0\n42\n')
            if p.env.get("SLOW_PC") == "1":
                self.detector = slow_pc.Detector(int(p.env.get("SLOW_PC_T", "20")), int(p.env.get("SLOW_PC_F", "16")),
                                                 int(p.env.get("SLOW_PC_K", "6")))
                self.at(self.t + self.poll_every_s, lambda: self._poll(p))
        self.at(self.t + self.daemon_startup_s, ready)
        if self.daemon_dies_at is not None:
            self.at(self.t + self.daemon_dies_at, lambda: self.end(p, 1))

    def _held_attack(self):
        return sum(1 for s in self.socks.values() if s["kind"] in ("slowloris", "slowpost"))

    def _poll(self, p):
        if p.returncode is not None:
            return
        now, text = self.time(), self.ss_text()
        fails = self.ss_fails
        if fails is True or (fails and self.run_t0 is not None and fails[0] <= self.t - self.run_t0 < fails[1]):
            text = None
        enforce = p.env.get("SLOW_PC_ENFORCE") == "1" and not self.exists("/run/l7v2/kill")
        banned = sorted(ip for ip, until in self.banned.items() if until > now)
        with open(p.env["SLOW_PC_RECORD"], "ab") as fh:
            fh.write(slow_pc.record_member(now, text, [], banned, enforce))
        if text is None:
            self.detector.skip(now, [])
            self._emit(p, "slow_pc_poll", mode="enforce" if enforce else "shadow", polls=0, ss_failed=1, sockets=0)
            self.at(self.t + self.poll_every_s, lambda: self._poll(p))
            return
        res = self.detector.poll(now, text, [], banned)
        for c in res.closes:
            self._emit(p, "slow_pc_close", enforced=enforce, **c._asdict())
        if enforce:
            for c in res.closes:
                s = self.socks.pop((c.ip, c.port, c.local, c.sport), None)
                if s is not None:
                    self.at(self.t + 10.0, lambda s=s: self._reopen(s))
            self.detector.closed([(c.ip, c.port, c.local, c.sport) for c in res.closes])
            for b in res.bans:
                self.banned[b.ip] = now + slow_pc.BAN_TTL_S
                self._emit(p, "ban", ip=b.ip, engine="l4_slowconn_pc", value=b.closes)
                for key in [k for k, s in self.socks.items() if s["ip"] == b.ip]:
                    del self.socks[key]
        self._emit(p, "slow_pc_poll", mode="enforce" if enforce else "shadow", polls=1, ss_failed=0, sockets=len(self.socks))
        self.at(self.t + self.poll_every_s, lambda: self._poll(p))

    def _reopen(self, s):
        live = any(q.kind == "gen" and s["ip"] in getattr(q, "ips", (q.ip,)) and q.returncode is None for q in self.procs)
        if live and self.banned.get(s["ip"], 0) <= self.time():
            self._open(s["ip"], s["sport"], s["kind"])

    # --- what the tests read -----------------------------------------------------------------------
    def ran(self, *prefix):
        return [c for c in self.commands if c[1][:len(prefix)] == prefix]

    def kinds(self):
        return collections.Counter(p.kind for p in self.procs)


def read_record(path):
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh]
