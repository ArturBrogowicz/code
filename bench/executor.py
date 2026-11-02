#!/usr/bin/env python3
"""The executor of the harm benchmark: one run of a plan in the namespaces, ending in the run contract
(docs/HG1C_DESIGN.md 6, docs/HG1B_MINIMAL_DESIGN.md 5.5).

A run is the control C, the placebo Cp (a second attack-free run) or the attack U of one block: the same population,
drawn by bench/population.py from the scenario's seed, in four client namespaces (one per link profile) that carry
the identities as address aliases, in front of an unprotected stack (Nginx, then the cost-calibrated origin under
gunicorn). The legit streams run for the whole timeline, the attack streams only in U, from the baseline's end.

This file has two halves. The first is a PLAN: pure functions that say, as data, every primitive, command and engine
process of a run, with no clock, no file and no process. `python3 bench/executor.py plan ...` prints it without root
and without importing the suite. The second half (below the plan) runs it through a `Host`.

    python3 bench/executor.py plan SPEC --calibration FILE --kind U --seed 1 [--out DIR] [--json]
    sudo ./venv/bin/python bench/executor.py run SPEC --calibration FILE --kind C --seed 1 --out DIR/C   # one run, root
    sudo ./venv/bin/python bench/executor.py smoke-topology SPEC --out DIR/C      # S2: the topology only, then taken down
    ./venv/bin/python bench/executor.py clock-probe SPEC --duration 30 [--attack] # S1: the engine's start-up, no root

The suite (test_distributed_suite.py) is used the way ml/capture_l7.py uses it: only its testbed primitives, imported
lazily after the checks (docs/HG1C_DESIGN.md 5). Everything the benchmark adds is here: the aliases, the stack, the
streams, the timeline, the telemetry, the cleanup and the leftovers. Nothing here kills a process by pattern.
"""
import argparse
import atexit
import collections
import contextlib
import csv
import dataclasses
import datetime
import gzip
import hashlib
import ipaddress
import json
import math
import os
import platform
import re
import resource
import shutil
import signal
import statistics
import subprocess
import sys
import threading
import time
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import calibration as C
import loadtools as LT
import origin as O
import population as P
import scenario as SC

# the suite's testbed (test_distributed_suite.py); tests/test_executor.py checks that these are still its values
SERVER_NS, SERVER_IP, BRIDGE = "server_ns", "10.0.0.1", "ddos_br0"
SUBNET_MASK = "/16"
HTTP_URL = f"http://{SERVER_IP}/"
CLIENT_IF = "veth_in"                     # the client end of every client namespace's veth pair
SERVER_VETH_HOST_END = "veth_srv_br"
NS_PREFIX = "hg_"                         # this runner's namespaces; the suite's cleanup does not know them
KINDS = ("C", "Cp", "U")
MITIGATED = "M_"                          # a protected run is M_<mode> (eval/harm_gate.py reads its role from the name)
# the protected arms (HG4, docs/HG1C_DESIGN.md 15): U's attack against a protected stack. Each mode's Nginx configuration, and the
# backend its daemon (control_plane.py) bans with, or None for no daemon
MODES = {"limits": {"conf": "nginx.conf", "daemon": None}, "xdp": {"conf": "nginx.conf", "daemon": "xdp"}}
MODE_TEXT = {"limits": "nginx.conf's limits (limit_req and limit_conn per address), no daemon",
             "xdp": "nginx.conf's limits, and control_plane.py banning into XDP (MITIGATION_BACKEND=xdp, XDP_GRU=0)"}
RESERVED_MODES = ("l7shadow", "l7")       # the L7 GRU's arms (G12): named now, refused until L7 v2 is built
MITIGATED_KINDS = tuple(MITIGATED + m for m in MODES)
NGINX_CONF = os.path.join(REPO, "nginx_unprotected.conf")
CERT, KEY = "/etc/ssl/certs/nginx-selfsigned.crt", "/etc/ssl/private/nginx-selfsigned.key"
GUNICORN = {"workers": 2, "threads": 8, "bind": "127.0.0.1:8080", "app": "origin:app"}
ORIGIN_SEED = 1
KINDS_OF_RUN = {"C": "control", "Cp": "placebo", "U": "attack", **{k: "mitigated" for k in MITIGATED_KINDS}}
DAEMON = os.path.join(REPO, "control_plane.py")
# the daemon reads the host's default Nginx logs (control_plane.py NGINX_LOG_FILE and NGINX_ERROR_LOG), and every run has its own: with
# a daemon, Nginx writes both, the run's first and this feed beside it (several access_log and error_log lines may stand at one level)
FEED_ACCESS_LOG, FEED_ERROR_LOG = "/var/log/nginx/ddos_ml_access.log", "/var/log/nginx/error.log"
FEED_BEFORE = "feed_before"               # where a run with a daemon keeps what the host's Nginx logs held before it (T-028 F-06)
# every other variable the daemon reads, set, so that nothing of the operator's environment reaches it (GRU_ONLY=1 there would turn
# its rules off); MITIGATION_BACKEND and BAN_EVENTS are the mode's and the run's. L7_SOCKET_PATH is read only with L7_SHADOW=1,
# and SLOW_PC_ENFORCE, _KILL_FILE, _RECORD, _T, _F, _K (P4's per-connection rule) are used only with SLOW_PC=1
DAEMON_ENV = (("XDP_GRU", "0"), ("GRU_ONLY", "0"), ("L7_SHADOW", "0"), ("HEURISTIC_PROFILE", "default"), ("L7_MODEL", ""),
              ("L7_RECORD", ""), ("SLOW_PC", "0"))
DAEMON_READY_LINE = "Listening for Nginx logs"      # what the daemon prints last before its loop; the suite waits for it too
# what a protected run's daemon must say it runs with in its start event, besides the mode's backend (G11): the rules as deployed,
# the XDP-fed GRU off (78cfc9c), no L7 shadow engine
MODE_DAEMON = {"xdp_gru": False, "gru_only": False, "l7_shadow": False, "heuristic_profile": "default"}
DAEMON_READY_TIMEOUT_S = 60.0             # the suite's wait for the daemon's first start (test_distributed_suite.start_server_services)
DAEMON_STOP_GRACE_S = 10.0                # SIGINT runs the daemon's finally, which detaches XDP; KILL after this
XDP_DEVICE = "veth_server"                # where the daemon attaches its program: the server's end of its veth pair
DAEMON_MAPS = ("blacklist_map", "telemetry_map", "flow_map")      # the maps of xdp_ddos_filter.c: a teardown looks for them
READY_PATH = O.SAMPLE_URLS["C0"]          # the origin has no route at "/": it answers 404 there
# recorded in every plan. The attack's start-up delay and the exit delay per request are what S1 and S1b measured on loopback, without
# namespaces (docs/HG1C_DESIGN.md 14). The legit start-up delay is S4's, with the real launch chain: the attack began 0.32 s early on 2.5 s,
# so the legit loops began about 2.8 s after their launch (taking the attack's 0.15 s as known), and the setting is 2.9 s
# (docs/HG1C_DESIGN.md 25). A legit stream's own launch does not depend on it (`launch_due`); the attack's launch, the stack-cost
# telemetry offset and the deadline do. The legit streams of a
# group are sound when the most of them that began within `t0_spread_limit_s` of one another, the pack, is a majority of the group and
# at most `straggler_share` of the group began outside it, provided the engines of those stragglers ended their loops with their last
# request (to within `straggler_tail_s`): then the estimate of where they began is as good as the others' and the harm gate places
# their records by it. No two streams of a group may begin further apart than `t0_range_limit_s`: a stream placed right still has
# its attack-window requests from another part of its schedule than a stream that began with the others (docs/HG1C_DESIGN.md 22).
# The pack of a group after the first begins within `group_start_limit_s` of where the plan puts it, the attack within
# `attack_start_limit_s` of the end of the baseline. A staged load that is read over the middle of each step is judged at its own
# limits (bench/calibrate.py `staged_limits`, docs/HG1C_DESIGN.md 24).
SETTINGS = {"startup_delay_legit_s": 2.9, "startup_delay_attack_s": 0.15, "readiness_timeout_s": 30.0,
            "warmup_requests": 2, "t0_spread_limit_s": 0.5, "t0_range_limit_s": 2.5, "attack_start_limit_s": 0.5,
            "group_start_limit_s": 0.5, "term_grace_s": 2.0,
            "min_nofile": 16384, "exit_delay_per_request_s": 8e-6, "straggler_share": 0.5, "straggler_tail_s": 0.1}


class PlanError(ValueError):
    """The run cannot be planned."""


@dataclasses.dataclass(frozen=True)
class Prim:
    """A primitive of the suite's testbed, called through the host."""
    name: str                        # bridge | server_ns | client_ns | netem
    args: tuple = ()
    purpose: str = ""


@dataclasses.dataclass(frozen=True)
class Cmd:
    """A command, in a network namespace ("" is the host)."""
    argv: tuple
    ns: str = ""
    stdin: str = ""
    env: tuple = ()                  # (("NAME", "value"), ...)
    when: str = ""                   # "" or "absent:<path>" (only if that path does not exist) or "present:<path>" (only if it does)
    keep: bool = False               # keep the process (gunicorn); every other command runs to completion
    detach: bool = False             # a daemon (Nginx): started with no pipe for it to hold, waited for until it has forked
    purpose: str = ""


@dataclasses.dataclass(frozen=True)
class Mkdir:
    """Directories of the run."""
    paths: tuple
    purpose: str = ""


@dataclasses.dataclass(frozen=True)
class Write:
    """A file of the run, whose text the plan holds (named by its hash)."""
    path: str
    sha256: str
    purpose: str = ""


@dataclasses.dataclass(frozen=True)
class Daemon:
    """The mitigation daemon of a protected run: started in `ns` from the checkout (`cwd`) once the stack is ready, held by its
    handle, ready when it says it listens, has written its start event to `events` and (with XDP) has attached its program; stopped
    with SIGINT, which runs its finally."""
    argv: tuple
    ns: str
    env: tuple
    cwd: str
    backend: str
    events: str                      # the run's ban_events.jsonl
    log: str                         # its stdout and stderr: daemon.log
    purpose: str = ""


@dataclasses.dataclass(frozen=True)
class Namespace:
    name: str
    index: int
    profile: str
    addresses: tuple


@dataclasses.dataclass(frozen=True)
class StreamLaunch:
    id: str
    kind: str
    route_class: str
    netem: str
    ns: str
    start_s: float
    duration_s: float
    rate: float
    seed: int
    nofile: int
    workdir: str
    summary: str
    records: str
    argv: tuple
    addresses: tuple = ()            # the identities it carries: the gate tells a blocked legit identity and an attack one by them


@dataclasses.dataclass(frozen=True)
class RunPlan:
    scenario: str
    kind: str
    seed: int
    out: str
    scenario_sha256: str
    calibration_sha256: str
    calibration_status: str
    calibration_path: str
    timeline: dict
    level: object
    namespaces: tuple
    topology: tuple
    stack: tuple
    checks: tuple                    # (route class, path): what the readiness probe asks for and expects back
    streams: tuple
    teardown: tuple
    nginx_conf: str
    nginx_conf_sha256: str
    plan_sha256: str
    settings: dict
    overrides: dict                  # what a smoke test changed (rho, timeline, timer limit); empty in a real run
    timer_limit_ms: float            # the run is refused if the timer on the legit CPU has p99 of this or more: the calibration's
                                     # validity.timer_p99_ms, unless a smoke test set it (overrides["timer_limit_ms"])
    mode: object = None              # None for C, Cp and U; `limits` or `xdp` for a protected run
    pins: object = None              # the pin plan of the run (population.PIN_PLAN, or PIN_PLAN_DAEMON in a campaign with a daemon)
    nginx_source: str = "nginx_unprotected.conf"      # the configuration of the repository that was rendered
    daemon: object = None            # a Daemon, for a mode that has one


# --- names -------------------------------------------------------------------------------------

def ns_name(spec):
    """`hg_<index>_<profile>` for a population.NsSpec. The index keeps mobile_3g and mobile_bad apart once the host-side
    veth name (`vo_` plus the first 12 characters, the suite's rule) is cut."""
    return f"{NS_PREFIX}{spec.index}_{spec.netem}"


def outer_veth(name):
    """The host end of a client namespace's veth pair, as create_client_ns names it."""
    return f"vo_{name[:12]}"


def _sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def sha256_file(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


# --- the Nginx configuration -------------------------------------------------------------------

ACCESS_LOG = re.compile(r"^([ \t]*)access_log[ \t]+/var/log/nginx/ddos_ml_access\.log[ \t]+json_ml_format;[ \t]*$", re.MULTILINE)
ERROR_LOG = re.compile(r"^([ \t]*)error_log[ \t]+/var/log/nginx/error\.log[ \t]+info;[ \t]*$", re.MULTILINE)


def render_nginx_conf(text, access_log, error_log, feed=False):
    """`nginx_unprotected.conf` (or a protected run's `nginx.conf`) with only its two log paths changed: the stack of every earlier
    campaign, and a log that belongs to this run. With `feed` (a mode with a daemon) each line is kept as well, after the run's: the
    daemon reads the host's default logs, so Nginx writes both. A file that does not have exactly these two lines is refused, not
    guessed at."""
    for pattern, what in ((ACCESS_LOG, "access_log"), (ERROR_LOG, "error_log")):
        if len(pattern.findall(text)) != 1:
            raise PlanError(f"nginx configuration: expected exactly one {what} line of the host's default path")

    def keep(m):
        return f"\n{m.group(0).strip(chr(10))}" if feed else ""
    text = ACCESS_LOG.sub(lambda m: f"{m.group(1)}access_log {access_log} json_ml_format;{keep(m)}", text)
    return ERROR_LOG.sub(lambda m: f"{m.group(1)}error_log {error_log} info;{keep(m)}", text)


# --- steps -------------------------------------------------------------------------------------

def topology_steps(namespaces):
    steps = [Prim("bridge", purpose="the central bridge in the host namespace"),
             Prim("server_ns", purpose=f"{SERVER_NS} at {SERVER_IP}, XDP-ready veth, checksum offload off")]
    for ns in namespaces:
        steps.append(Prim("client_ns", (ns.name, ns.addresses[0]),
                          f"{ns.name}: a veth pair, a unique MAC from {ns.addresses[0]}, that address"))
        rest = ns.addresses[1:]
        if rest:
            steps.append(Cmd(("ip", "-batch", "-"), ns.name,
                             stdin="".join(f"addr add {a}{SUBNET_MASK} dev {CLIENT_IF}\n" for a in rest),
                             purpose=f"{len(rest)} more addresses of {ns.name}"))
        steps.append(Prim("netem", (ns.name, ns.profile), f"{ns.profile} link on {ns.name}"))
    return tuple(steps)


def stack_steps(out, calibration_path, python, pins, conf_sha256, bench=None, conf_name="nginx_unprotected.conf", feed=False):
    """The server stack in `server_ns`: the origin under gunicorn, then Nginx on the rendered configuration (`conf_name` of the
    repository; with `feed`, the daemon's feed beside the run's logs: what the host's logs held is moved into the run first, so that
    Nginx starts them afresh and nothing of them is erased, T-028 F-06)."""
    bench = bench or HERE
    pin = ("taskset", "-c", pins["server"])
    env = (("ORIGIN_CALIBRATION", calibration_path), ("ORIGIN_SEED", str(ORIGIN_SEED)))
    feed_steps = (Mkdir((f"{out}/{FEED_BEFORE}",), "the host's Nginx logs as they were before this run"),
                  *(Cmd(("mv", "-f", path, f"{out}/{FEED_BEFORE}/{os.path.basename(path)}"), when=f"present:{path}",
                        purpose="the daemon's feed: moved into the run, not erased; Nginx creates it afresh for this run")
                    for path in (FEED_ACCESS_LOG, FEED_ERROR_LOG))) if feed else ()
    return (
        Mkdir((out, f"{out}/streams"), "the run directory"),
        Write(f"{out}/nginx.conf", conf_sha256, f"{conf_name} with its two log paths changed"
              + (", and the daemon's feed beside them" if feed else "")),
        Cmd(("mkdir", "-p", "/var/log/nginx"), purpose="Nginx opens its compiled-in log path at start-up"),
        *feed_steps,
        Cmd(("openssl", "req", "-x509", "-nodes", "-days", "365", "-newkey", "rsa:2048", "-keyout", KEY, "-out", CERT,
             "-subj", "/C=PL/ST=Masovian/L=Warsaw/O=PoC/CN=twojadomena.pl"), when=f"absent:{CERT}",
            purpose="the configuration listens on 443 with the suite's self-signed certificate"),
        Cmd(("touch", f"{out}/nginx_access.log", f"{out}/nginx_error.log"), purpose="the run's own logs"),
        Cmd(("chmod", "0666", f"{out}/nginx_access.log", f"{out}/nginx_error.log"),
            purpose="the Nginx workers run as nobody"),
        Cmd((*pin, python, "-m", "gunicorn", "--chdir", bench, "--workers", str(GUNICORN["workers"]),
             "--threads", str(GUNICORN["threads"]), "--bind", GUNICORN["bind"], GUNICORN["app"]), SERVER_NS,
            env=env, keep=True,
            purpose="the cost-calibrated origin, on loopback so that nothing reaches it except through Nginx"),
        Cmd((*pin, "nginx", "-c", f"{out}/nginx.conf"), SERVER_NS, detach=True,
            purpose="Nginx daemonises: started like the origin, with no pipe for it to hold, and found again by namespace"),
    )


def daemon_plan(out, python, pins, backend):
    """control_plane.py of a protected run: in `server_ns` on the daemon's CPU, from the checkout (its model, its scaler and its XDP
    source are relative paths), banning with `backend`, its events in the run's ban file, every other variable it reads set."""
    events = f"{out}/ban_events.jsonl"
    return Daemon(("taskset", "-c", pins["daemon"], python, "-u", DAEMON), SERVER_NS,
                  (("MITIGATION_BACKEND", backend), ("BAN_EVENTS", events), *DAEMON_ENV), REPO, backend, events, f"{out}/daemon.log",
                  "the mitigation daemon, held by its handle; its ban state is this run's alone (a new process in a new namespace)")


def check_paths():
    """What the readiness probe asks the stack for: each served route class and a path of it."""
    return tuple(sorted(O.SAMPLE_URLS.items()))


def teardown_steps(namespaces):
    """The templates of the teardown: the namespaces' contents are found with `ip netns pids`, never by pattern."""
    names = [ns.name for ns in namespaces] + [SERVER_NS]
    steps = [Cmd(("ip", "netns", "pids", n), purpose="every pid in it: TERM, then KILL after the grace") for n in names]
    steps += [Cmd(("ip", "netns", "del", n), purpose="the namespace and, with it, its veth ends") for n in names]
    steps += [Cmd(("ip", "link", "del", link), purpose="the host ends, if the namespace's deletion left them")
              for link in [outer_veth(ns.name) for ns in namespaces] + [SERVER_VETH_HOST_END, BRIDGE]]
    return tuple(steps)


# --- the plan ----------------------------------------------------------------------------------

def _positive(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x) and x > 0


def _legit_hash(streams):
    rows = [{"id": s.id, "route": s.route_class, "netem": s.netem, "process": s.process, "rate": s.rate,
             "period": s.period, "duty": s.duty, "seed": s.seed, "ns": s.ns_index, "addresses": list(s.addresses),
             "paths": list(s.paths), "start": s.start_s, "duration": s.duration_s}
            for s in sorted(streams, key=lambda s: s.id)]
    return _sha(json.dumps(rows, sort_keys=True, separators=(",", ":")))


def mode_of(kind):
    """The mode of a run's kind: None for C, Cp and U, `limits` or `xdp` for M_limits and M_xdp. The L7 GRU's modes are named and
    refused until they are built; anything else is not a kind."""
    if kind in KINDS:
        return None
    mode = kind[len(MITIGATED):] if kind.startswith(MITIGATED) else None
    if mode in MODES:
        return mode
    if mode in RESERVED_MODES:
        raise PlanError(f"{kind}: not built yet. The L7 GRU's arms ({', '.join(MITIGATED + m for m in RESERVED_MODES)}) wait for "
                        f"L7 v2; the protected arms built are {', '.join(MITIGATED_KINDS)}")
    raise PlanError(f"kind: one of {', '.join(KINDS + MITIGATED_KINDS)}, got {kind!r}")


def pins_for(kinds):
    """The pin plan of a run, or of a campaign, made of `kinds`: PIN_PLAN_DAEMON as soon as one of them has a daemon (the executor
    then has a CPU of its own), PIN_PLAN otherwise."""
    daemon = any(MODES[mode]["daemon"] for mode in map(mode_of, kinds) if mode is not None)
    return dict(P.PIN_PLAN_DAEMON if daemon else P.PIN_PLAN)


def plan_run(scn, cal, kind, seed, out, calibration_path, scenario_sha256="", manifest=None, root=None, settings=None,
             python=None, rho=None, timeline=None, timer_limit_ms=None, pins=None):
    """Everything a run will do, as data. `scn` is a bench/scenario.Scenario, `cal` a calibration record read from
    `calibration_path`, `kind` one of C, Cp, U and the protected M_<mode>, `out` the run's directory, which must be called after
    its kind (the gate reads the role from the name). A protected run is U's attack against its mode's stack. `rho` replaces the
    nominal load, `timeline` (baseline, attack, recovery seconds) the scenario's, and `timer_limit_ms` the calibration's limit for
    the timer of the legit CPU, for a smoke test; all three are recorded as overrides, and the harm gate gives no verdict on runs
    that carry any. `pins` is the pin plan (pins_for: of the campaign; of the kind alone by default)."""
    mode = mode_of(kind)
    if os.path.basename(os.path.normpath(out)) != kind:
        raise PlanError(f"the run directory of a {kind} run is called {kind}, not {os.path.basename(os.path.normpath(out))!r}")
    attack = kind == "U" or mode is not None
    if attack and scn.is_control:
        raise PlanError(f"{scn.id} is attack-free: it has no attack run")
    overrides = {}
    if rho is not None:
        if not _positive(rho):
            raise PlanError(f"rho: a positive number of requests per second, got {rho!r}")
        overrides["rho_rps"] = rho
    if timeline is not None:
        if len(timeline) != 3 or not all(_positive(v) for v in timeline):
            raise PlanError(f"timeline: baseline, attack and recovery seconds, all positive, got {timeline!r}")
        scn = dataclasses.replace(scn, timeline=P.Timeline(*timeline))
        overrides["timeline_s"] = list(timeline)
    if timer_limit_ms is not None:
        if not _positive(timer_limit_ms):
            raise PlanError(f"timer_limit_ms: a positive number of milliseconds, got {timer_limit_ms!r}")
        overrides["timer_limit_ms"] = timer_limit_ms
    try:
        pop, level = SC.population_of(scn, cal, seed, attack=attack, rho=rho)
    except SC.ScenarioError as exc:
        raise PlanError(str(exc)) from exc
    return plan_population(pop, scn.id, kind, seed, out, cal, calibration_path, scn.timeline, level, scenario_sha256, manifest,
                           root, settings, python, overrides, mode=mode, pins=pins or pins_for([kind]))


def plan_population(pop, scenario, kind, seed, out, cal, calibration_path, timeline, level=None, scenario_sha256="",
                    manifest=None, root=None, settings=None, python=None, overrides=None, mode=None, pins=None):
    """The plan of a run of a population that is drawn already: plan_run's for a scenario's, and bench/calibrate.py's for the
    staged load of the capacity probe and the legit probes. `timeline` is the population's population.Timeline; a stream is
    launched so that its loop starts at its `start_s` on the run's axis (launch_due). `mode` is a protected run's (MODES)."""
    out = os.path.abspath(out) if not os.path.isabs(out) else out
    python = python or os.path.join(REPO, "venv", "bin", "python")
    pins = dict(pins or P.PIN_PLAN)
    aliases = pop.alias_plan()
    namespaces = tuple(Namespace(ns_name(spec), spec.index, spec.netem, tuple(aliases[spec.index]))
                       for spec in pop.namespaces if spec.index in aliases)
    by_index = {ns.index: ns for ns in namespaces}
    source = NGINX_CONF if mode is None else os.path.join(REPO, MODES[mode]["conf"])
    backend = None if mode is None else MODES[mode]["daemon"]
    with open(source, encoding="utf-8") as fh:
        conf = render_nginx_conf(fh.read(), f"{out}/nginx_access.log", f"{out}/nginx_error.log", feed=backend is not None)
    conf_sha256 = _sha(conf)
    streams = []
    for s in pop.streams:
        spec = P.to_load_spec(s, HTTP_URL, pins)
        workdir = f"{out}/streams/{s.id}"
        launch = LT.build_plan("loadgen", spec, workdir, manifest, root)
        nofile = P.nofile_for(s, spec)
        streams.append(StreamLaunch(
            s.id, s.kind, s.route_class, s.netem, by_index[s.ns_index].name, s.start_s, s.duration_s, s.rate, s.seed,
            nofile, workdir, f"{workdir}/loadgen.summary.json", f"{workdir}/loadgen.records.csv.gz",
            ("prlimit", f"--nofile={nofile}", "--", *launch.steps[0].argv), tuple(s.addresses)))
    return RunPlan(
        scenario=scenario, kind=kind, seed=seed, out=out, scenario_sha256=scenario_sha256,
        calibration_sha256=cal.get("sha256") or C.digest(cal), calibration_status=cal["status"],
        calibration_path=os.path.abspath(calibration_path),
        timeline=dataclasses.asdict(timeline) | {"total_s": timeline.total_s}, level=level,
        namespaces=namespaces, topology=topology_steps(namespaces),
        stack=stack_steps(out, os.path.abspath(calibration_path), python, pins, conf_sha256, conf_name=os.path.basename(source),
                          feed=backend is not None),
        checks=check_paths(),
        streams=tuple(streams), teardown=teardown_steps(namespaces), nginx_conf=conf, nginx_conf_sha256=conf_sha256,
        plan_sha256=_legit_hash(pop.of_kind("legit")), settings={**SETTINGS, **(settings or {})},
        overrides=overrides or {}, timer_limit_ms=(overrides or {}).get("timer_limit_ms", cal["validity"]["timer_p99_ms"]),
        mode=mode, pins=pins, nginx_source=os.path.basename(source),
        daemon=daemon_plan(out, python, pins, backend) if backend else None)


# --- the plan as data and as text --------------------------------------------------------------

def as_json(plan):
    """The plan as JSON-able data (`plan.json` of a run). Steps get a `do` that names their kind."""
    def step(x):
        d = dataclasses.asdict(x)
        d["do"] = {Prim: "prim", Cmd: "cmd", Write: "write", Mkdir: "mkdir"}[type(x)]
        return d
    d = dataclasses.asdict(plan)
    for key in ("topology", "stack", "teardown"):
        d[key] = [step(x) for x in getattr(plan, key)]
    d["streams"] = [dataclasses.asdict(s) for s in plan.streams]
    d["namespaces"] = [dataclasses.asdict(n) for n in plan.namespaces]
    d["checks"] = [list(c) for c in plan.checks]
    return json.loads(json.dumps(d))


def _shown(text, python):
    """A command for the page: the interpreter and this checkout abbreviated, so that a plan reads the same anywhere.
    The venv's interpreter and the one running the executor are both `<python>`."""
    return (str(text).replace(os.path.join(REPO, "venv", "bin", "python"), "<python>").replace(python, "<python>")
            .replace(REPO, "<repo>"))


def _step_line(i, x, python):
    if isinstance(x, Prim):
        return f"{i:>3}. prim  {x.name} {' '.join(map(str, x.args))}".rstrip() + f"    # {x.purpose}"
    if isinstance(x, Mkdir):
        return f"{i:>3}. mkdir {' '.join(_shown(p, python) for p in x.paths)}    # {x.purpose}"
    if isinstance(x, Write):
        return f"{i:>3}. write {_shown(x.path, python)}  (sha256 {x.sha256[:12]})    # {x.purpose}"
    where = f"[{x.ns}] " if x.ns else ""
    when = f"[if {x.when}] " if x.when else ""
    env = " ".join(f"{k}={_shown(v, python)}" for k, v in x.env)
    keep = "keep " if x.keep else "detach " if x.detach else ""
    body = " ".join(_shown(a, python) for a in x.argv)
    stdin = f"  < {len(x.stdin.splitlines())} lines" if x.stdin else ""
    return f"{i:>3}. {keep}cmd   {where}{when}{env + ' ' if env else ''}{body}{stdin}    # {x.purpose}"


def launch_due(plan, stream):
    """Seconds after the launch of the first streams at which `stream` is launched, so that its loop starts at its `start_s`
    on the run's axis: its start, plus the legit start-up delay (the axis begins when the legit streams' loops do), less its
    own. The legit streams of a run start at 0 and are launched at once; the attack streams start at the end of the baseline
    and are launched earlier by the difference of the start-up delays; the steps of a staged load follow in the same way."""
    s = plan.settings
    own = s["startup_delay_attack_s"] if stream.kind == "attack" else s["startup_delay_legit_s"]
    return stream.start_s + s["startup_delay_legit_s"] - own


def launch_attack_after(plan):
    """Seconds after the launch of the legit streams at which the attack streams are launched, so that their loops start
    at the end of the baseline: the baseline plus the legit start-up delay less the attack's."""
    s = plan.settings
    return plan.timeline["baseline_s"] + s["startup_delay_legit_s"] - s["startup_delay_attack_s"]


def timeline_line(plan, legit, attack):
    """The `timeline` line of the plan's text: the legit streams together, or the steps of a staged load; the attack, if any."""
    t, delay = plan.timeline, plan.settings["startup_delay_legit_s"]
    starts = sorted({x.start_s for x in legit})
    if len(starts) > 1:
        line = (f"timeline      the legit load comes in {len(starts)} steps of {len(legit) // len(starts)} streams, the first "
                f"launched at L, the others so that their loops start at T = {', '.join(f'{x:g}' for x in starts[1:])} s; "
                f"T = 0 is {delay:g} s after L, and the run lasts {t['total_s']:g} s")
    else:
        line = (f"timeline      the {len(legit)} legit streams are launched at L; their loops start about {delay:g} s later, "
                f"which is T = 0, and run {t['total_s']:g} s")
    if attack:
        line += (f"; the {len(attack)} attack streams are launched at L + {launch_attack_after(plan):g} s to start at "
                 f"T = {t['baseline_s']:g} s and run {t['attack_s']:g} s")
    return line


def describe(plan, python=None):
    """The plan as text for `--plan`."""
    python = python or sys.executable
    attack = [s for s in plan.streams if s.kind == "attack"]
    legit = [s for s in plan.streams if s.kind == "legit"]
    banner = ("PLACEHOLDER: illustrative numbers, not measurements; nothing below is a result"
              if plan.calibration_status != "frozen" else "frozen")
    out = [f"== run {plan.kind} ({KINDS_OF_RUN[plan.kind]}) of {plan.scenario}, seed {plan.seed} ==",
           f"calibration   sha256:{plan.calibration_sha256[:8]} {banner}",
           f"scenario      sha256:{plan.scenario_sha256[:8] or '-'}"
           + (f", attack level {plan.level:g} x S" if plan.level is not None else ", no attack in this run"),
           f"run directory {plan.out}",
           timeline_line(plan, legit, attack),
           f"plan hash     {plan.plan_sha256[:12]} (the legit streams: equal in C, Cp and U of a block)",
           *([f"OVERRIDES     {plan.overrides}: a smoke test, not a result"] if plan.overrides else []),
           f"timer gate    refused if the timer on CPU {plan.pins['legit']} has p99 of {plan.timer_limit_ms:g} ms or more "
           + ("(set by --timer-limit-ms)" if "timer_limit_ms" in plan.overrides else "(the calibration's validity.timer_p99_ms)")
           + f"; a refused probe is made again every {TIMER_REPROBE_S:g} s, up to --wait-gate minutes from the first (0: one probe)",
           *([(f"timer record  the timer on the executor's CPU {plan.pins['executor']} is probed too, after the gate: recorded "
               "(environment.json, timer_executor), not judged")] if "executor" in plan.pins else []),
           f"nginx.conf    sha256:{plan.nginx_conf_sha256[:12]} ({plan.nginx_source} with its two log paths changed"
           + (", and the daemon's feed beside them)" if plan.daemon else ")"),
           *([f"mode          {plan.mode}: {MODE_TEXT[plan.mode]}"] if plan.mode else []),
           *(["pins          " + ", ".join(f"{k} {v}" for k, v in plan.pins.items())
              + f": the executor on CPU {P.executor_cpus(plan.pins)}, apart from the daemon's"] if plan.pins != P.PIN_PLAN else []),
           "settings      " + ", ".join(f"{k} {v}" for k, v in plan.settings.items()), ""]
    n_aliases = sum(len(n.addresses) for n in plan.namespaces)
    out.append(f"topology: {len(plan.namespaces)} client namespaces carrying {n_aliases} addresses")
    for n in plan.namespaces:
        out.append(f"      {n.name:<18} {n.profile:<11} {len(n.addresses):>4} addresses, first {n.addresses[0]}, "
                   f"veth {outer_veth(n.name)}")
    out += [_step_line(i, x, python) for i, x in enumerate(plan.topology, 1)]
    out += ["", "stack in " + SERVER_NS + f", then the readiness probe ({plan.settings['readiness_timeout_s']:g} s at most):"]
    out += [_step_line(i, x, python) for i, x in enumerate(plan.stack, 1)]
    out.append(f"  ready: HTTP 200 from {HTTP_URL[:-1]}{READY_PATH}, and each route answers with its own X-Route-Class: "
               + ", ".join(f"{k} {p}" for k, p in plan.checks))
    out.append(f"  warm-up: {plan.settings['warmup_requests']} requests per route from {SERVER_NS}")
    if plan.daemon:
        d = plan.daemon
        out += ["", (f"daemon in {SERVER_NS}, started after the warm-up and held by its handle ({DAEMON_READY_TIMEOUT_S:g} s at most to "
                     f"be ready), in {_shown(d.cwd, python)}, its output in {_shown(d.log, python)}:"),
                "    " + " ".join(f"{k}={_shown(v, python)}" for k, v in d.env) + " " + " ".join(_shown(a, python) for a in d.argv),
                f"  ready: it says '{DAEMON_READY_LINE}', its start event is in {os.path.basename(d.events)}"
                + (f", and an XDP program is attached to {XDP_DEVICE}" if d.backend == "xdp" else ""),
                (f"  stopped after the timeline with SIGINT (its finally detaches XDP), KILL after {DAEMON_STOP_GRACE_S:g} s, then "
                 f"`ip link set dev {XDP_DEVICE} xdp off`; the teardown also looks for XDP programs and the daemon's maps left loaded")]
    out += ["", f"streams: {len(plan.streams)} engine processes ({len(legit)} legit, {len(attack)} attack)"]
    rows = [("id", "ns", "vCPU", "rate", "start", "duration", "nofile")]
    for s in plan.streams:
        cpus = s.argv[s.argv.index("taskset") + 2] if "taskset" in s.argv else "-"
        rows.append((s.id, s.ns, cpus, f"{s.rate:.2f}", f"{s.start_s:g}", f"{s.duration_s:g}", str(s.nofile)))
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    for r in rows:
        out.append("    " + "  ".join(c.ljust(w) if i < 3 else c.rjust(w) for i, (c, w) in enumerate(zip(r, widths, strict=True))))
    first = plan.streams[0]
    out += ["  the command of the first, inside its namespace:",
            f"    ip netns exec {first.ns} " + " ".join(_shown(a, python) for a in first.argv)]
    out += ["", "teardown (also on any failure), with the namespaces found by `ip netns pids`, never by pattern:"]
    out += [_step_line(i, x, python) for i, x in enumerate(plan.teardown, 1)]
    return "\n".join(out) + "\n"


# --- the run: the plan through a Host ------------------------------------------------------------

Result = collections.namedtuple("Result", "code out err")
RunResult = collections.namedtuple("RunResult", "ok reasons out setup_retries seconds")
ENGINE_T0_OFFSET_S = 0.05            # bench/loadgen.py: the schedule's zero is 50 ms after its loop starts
EARLY_SLACK_S = 2.0                  # a stream that exits with an error, or leaving no output, this much before its end has died
DRAIN_S = 12.0                       # the engine waits for requests in flight for its timeout (10 s) plus 2 s
MAX_SETUP_RETRIES = 2
DAEMON_FORK_WAIT_S = 10.0            # Nginx's launcher has returned by then: it forks once the configuration is read
TICK_S = 1.0
REATTACH_EVERY = 10                  # ticks between two looks at which processes the server namespace holds
# what the suite reads from the environment when it is imported; tests/test_executor_run.py checks that this is
# eval/run_campaign.EVAL_VARS
SUITE_ENV_VARS = ("MITIGATION_MODE", "MITIGATION_BACKEND", "NGINX_PROTECTED", "OPERATING_POINT", "GUNICORN_WORKERS",
                  "GUNICORN_THREADS", "WRK_CONNS", "WRK_THREADS", "BOTNET_COUNT", "SERVER_CPUS", "ATTACK_CPUS",
                  "ATTACK_DURATION", "PROFILE_SEED", "FLOOD_TOOL", "FLOOD_RATE", "RESULTS_DIR", "RESULTS_ROOT",
                  "ONLY_SCENARIOS", "GRU_ONLY", "BAN_EVENTS")
LEFTOVER_NS = re.compile(r"(server_ns|legit_|bot_|hg_)")
LEFTOVER_LINKS = re.compile(r"(vo_|veth_srv_br$|ddos_br0$)")
# what a testbed leaves running, by what the process runs: the first word of its command line or, for an interpreter, the
# script or module it was given. Looked for in the process table; no pattern is ever matched over whole command lines
LEFTOVER_PROGRAMS = ("nginx", "wrk", "k6", "hping3", "gunicorn", "loadgen.py", "control_plane.py")
INTERPRETER_VALUES = ("-W", "-X", "--check-hash-based-pycs")          # Python options followed by a value
EXIT_OK, EXIT_USAGE, EXIT_FAILED, EXIT_UNSOUND = 0, 1, 2, 3


class RunFailed(RuntimeError):
    """The run could not be carried out, as opposed to being carried out and found unsound."""


class PreflightRefused(RunFailed):
    """A precondition of the run does not hold; nothing was built."""


class EnvironmentRefused(RunFailed):
    """The machine is not in the state the gate asks for (timers, load, uptime); nothing was built. `record` is what the timer gate
    saw before it refused, for the run's environment.json; None for a refusal of uptime or load."""

    record = None


class SetupFailed(RunFailed):
    """The topology or the stack could not be brought up."""


class LeftoverError(RunFailed):
    """Something of the run is still there after the teardown."""


class TableUnreadable(RunFailed):
    """The machine would not say what is on it (namespaces, links, processes). A check that cannot look does not call the
    machine clean."""


def cpu_list(text):
    """{0, 1} for "0-1" and {3, 4, 5, 7} for "3-5,7"."""
    cpus = set()
    for part in text.split(","):
        lo, _, hi = part.partition("-")
        cpus.update(range(int(lo), int(hi or lo) + 1))
    return cpus


class Host:
    """What the executor needs of the machine: commands, processes, the suite's primitives, the clocks and a few
    files of /proc and /sys. RealHost does them; tests/fake_host.py scripts them on a clock of its own."""

    simulated = False                # True for a host that measures nothing (bench/sim_host.py): its campaigns get a verdict
                                     # although they carry a smoke test's overrides, because they say nothing about any server

    def run(self, argv, ns="", stdin="", env=None, timeout=None):
        """Run a command to completion, in a network namespace if `ns`: a Result (code, stdout, stderr). A command that
        fails comes back with its code; only a host that cannot run it at all raises."""
        raise NotImplementedError

    def popen(self, argv, ns="", env=None, stdout=None, stderr=None, cwd=None):
        """Start a process and keep it, in the directory `cwd` if one is given: an object with pid, poll(), terminate(), interrupt()
        (SIGINT, as Ctrl-C would), kill() and exit_time (the wall-clock time at which it was seen to exit, stamped by a watcher of its
        own)."""
        raise NotImplementedError

    def prim(self, name, *args):
        """One of the suite's testbed primitives: bridge, server_ns, client_ns, netem."""
        raise NotImplementedError

    def time(self):
        raise NotImplementedError

    def monotonic(self):
        raise NotImplementedError

    def sleep(self, seconds):
        raise NotImplementedError

    def read_text(self, path):
        """The text of a file; OSError when it is not there."""
        raise NotImplementedError

    def exists(self, path):
        raise NotImplementedError

    def stat(self, path):
        """(inode, size in bytes) of a file; None when it is not there."""
        raise NotImplementedError

    def is_root(self):
        raise NotImplementedError

    def nofile_limit(self):
        """(soft, hard) open-file limit of this process, which its children inherit."""
        raise NotImplementedError

    def clk_tck(self):
        raise NotImplementedError

    def facts(self):
        """uname, CPUs, memory, and the versions of Python, Nginx and gunicorn."""
        raise NotImplementedError

    def pin(self, cpus):
        """Pin the executor itself to `cpus`."""
        raise NotImplementedError

    def pid(self):
        """The executor's own process id."""
        raise NotImplementedError

    @contextlib.contextmanager
    def shielded(self):
        """A stretch in which the executor cannot be interrupted: the teardown, which a second Ctrl-C must not cut short."""
        yield


class RealProc:
    """A process started by RealHost. A thread reaps it and stamps the moment, so that the exit time does not wait for the
    executor's loop."""

    def __init__(self, popen):
        self._p = popen
        self.pid = popen.pid
        self.returncode = None
        self.exit_time = None
        threading.Thread(target=self._watch, daemon=True).start()

    def _watch(self):
        rc = self._p.wait()
        self.exit_time = time.time()
        self.returncode = rc

    def poll(self):
        return self.returncode

    def terminate(self):
        with contextlib.suppress(ProcessLookupError):
            self._p.terminate()

    def interrupt(self):
        with contextlib.suppress(ProcessLookupError):
            self._p.send_signal(signal.SIGINT)

    def kill(self):
        with contextlib.suppress(ProcessLookupError):
            self._p.kill()


class RealHost(Host):
    COMMAND_TIMEOUT_S = 120

    def __init__(self, suite=None):
        self._suite = suite

    def suite(self):
        """The suite, imported now and not before: after the checks, with its evaluation variables out of the environment
        (it reads them as it is imported), and with the two things it does at import taken back: its `atexit` cleanup
        (a system-wide `pkill -9 -f gunicorn`, among others) and its signal handlers. This runner never kills by pattern."""
        if self._suite is None:
            for name in SUITE_ENV_VARS:
                os.environ.pop(name, None)
            sys.path.insert(0, REPO)
            handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
            import test_distributed_suite
            atexit.unregister(test_distributed_suite.cleanup_all)
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
            self._suite = test_distributed_suite
        return self._suite

    @staticmethod
    def _env(extra):
        return {**LT.clean_env(), **dict(extra or {})}

    def run(self, argv, ns="", stdin="", env=None, timeout=None):
        full = (["ip", "netns", "exec", ns] if ns else []) + list(argv)
        feed = {"input": stdin} if stdin else {"stdin": subprocess.DEVNULL}
        try:
            cp = subprocess.run(full, capture_output=True, text=True, check=False, env=self._env(env),
                                timeout=timeout or self.COMMAND_TIMEOUT_S, **feed)
        except subprocess.TimeoutExpired:
            return Result(-1, "", "timeout")
        except OSError as exc:
            return Result(127, "", str(exc))
        return Result(cp.returncode, cp.stdout, cp.stderr)

    def popen(self, argv, ns="", env=None, stdout=None, stderr=None, cwd=None):
        full = (["ip", "netns", "exec", ns] if ns else []) + list(argv)
        return RealProc(subprocess.Popen(full, stdin=subprocess.DEVNULL, env=self._env(env), start_new_session=True,
                                         stdout=subprocess.DEVNULL if stdout is None else stdout,
                                         stderr=subprocess.DEVNULL if stderr is None else stderr, cwd=cwd))

    def prim(self, name, *args):
        s = self.suite()
        {"bridge": s.create_host_bridge, "server_ns": s.create_server_ns, "client_ns": s.create_client_ns,
         "netem": s.apply_tc}[name](*args)

    def time(self):
        return time.time()

    def monotonic(self):
        return time.monotonic()

    def sleep(self, seconds):
        time.sleep(seconds)

    def read_text(self, path):
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    def exists(self, path):
        return os.path.exists(path)

    def stat(self, path):
        try:
            st = os.stat(path)
        except OSError:
            return None
        return st.st_ino, st.st_size

    def is_root(self):
        return os.geteuid() == 0

    def nofile_limit(self):
        return resource.getrlimit(resource.RLIMIT_NOFILE)

    def clk_tck(self):
        return os.sysconf("SC_CLK_TCK")

    def facts(self):
        def first_line(argv):
            r = self.run(argv)
            lines = (r.out or r.err).strip().splitlines()
            return lines[0] if lines else None
        mem = next((int(line.split()[1]) // 1024 for line in self.read_text("/proc/meminfo").splitlines()
                    if line.startswith("MemTotal:")), None)
        return {"uname": " ".join(platform.uname()), "cpus": os.cpu_count(), "mem_mib": mem,
                "python": sys.version.split()[0], "nginx": first_line(["nginx", "-v"]),
                "gunicorn": first_line([os.path.join(REPO, "venv", "bin", "python"), "-m", "gunicorn", "--version"])}

    def pin(self, cpus):
        os.sched_setaffinity(0, cpu_list(cpus))

    def pid(self):
        return os.getpid()

    @contextlib.contextmanager
    def shielded(self):
        """Ctrl-C, TERM and HUP are ignored inside (and the handlers put back after): a second interrupt while the testbed is
        being taken down would leave it standing, which the next run's preflight then refuses."""
        if threading.current_thread() is not threading.main_thread():
            yield
            return
        old = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
        try:
            yield
        finally:
            for sig, handler in old.items():
                signal.signal(sig, handler)


# --- what is left of any testbed -----------------------------------------------------------------

def _lines(result):
    return [line for line in result.out.splitlines() if line.strip()]


def _table(host, argv):
    """The non-empty lines a listing command prints; TableUnreadable when it does not run."""
    r = host.run(argv)
    if r.code != 0:
        raise TableUnreadable(f"`{' '.join(argv)}` exited {r.code}: {(r.err or r.out).strip()[:120]}")
    return _lines(r)


def program_of(argv):
    """What a process runs: the name of its first word (`nginx:` for Nginx's own process titles), or for a Python interpreter
    the script, or the module (`-m gunicorn`), it was given: the first word that is not an option, the options that take a value
    (`-W ignore`) skipped."""
    head = os.path.basename(argv[0].rstrip(":"))
    if head.startswith("python"):
        rest, i = argv[1:], 0
        while i < len(rest):
            word = rest[i]
            if word in INTERPRETER_VALUES:
                i += 2
                continue
            if not word.startswith("-"):
                return os.path.basename(word)
            i += 1
    return head


def process_leftovers(host):
    """Processes of any testbed that are still there, read from the process table by what each runs (`program_of`), never by
    a substring of its command line: the executor's own command line, or its parent's, may contain any word (a results
    directory called `gunicorn`), and a pattern would find it. The executor and the processes above it are left out whatever
    they run. Looking only; nothing here kills."""
    table = {}
    for line in _table(host, ["ps", "-eo", "pid=,ppid=,args="]):
        words = line.split()
        if len(words) >= 3 and words[0].isdigit() and words[1].isdigit():
            table[int(words[0])] = (int(words[1]), words[2:])
    mine, pid = set(), host.pid()
    while pid in table and pid not in mine:
        mine.add(pid)
        pid = table[pid][0]
    mine.add(host.pid())
    return [f"process {program_of(argv)} pid {pid}" for pid, (_, argv) in sorted(table.items())
            if pid not in mine and program_of(argv) in LEFTOVER_PROGRAMS]


def bpf_leftovers(host):
    """XDP programs the kernel still holds and the daemon's maps (DAEMON_MAPS), read with bpftool: what a daemon leaves when its
    program stays attached, is pinned, or is held by a process that outlived its run. Nothing else on this machine runs XDP. A
    listing that cannot be read raises TableUnreadable."""
    found = []
    for what, argv in (("prog", ["bpftool", "-j", "prog", "show"]), ("map", ["bpftool", "-j", "map", "show"])):
        r = host.run(argv)
        try:
            if r.code != 0:
                raise ValueError(f"exited {r.code}: {(r.err or r.out).strip()[:120]}")
            items = json.loads(r.out or "[]")
        except ValueError as exc:
            raise TableUnreadable(f"`{' '.join(argv)}` {exc}") from exc
        if what == "prog":
            found += [f"xdp program {p.get('id')} {p.get('name', '')}".rstrip() for p in items if p.get("type") == "xdp"]
        else:
            found += [f"bpf map {m.get('name')} (id {m.get('id')})" for m in items if m.get("name") in DAEMON_MAPS]
    return found


def leftovers(host, bpf=False):
    """What of any testbed is still there: namespaces and links of the suite's and of this runner's, and processes; with `bpf` (a
    run with a daemon), XDP programs and the daemon's maps too. Looking only; nothing here kills."""
    found = [f"netns {n}" for n in (line.split()[0] for line in _table(host, ["ip", "netns", "list"]))
             if LEFTOVER_NS.match(n)]
    found += [f"link {n}" for n in (line.split()[0].split("@")[0] for line in _table(host, ["ip", "-br", "link", "show"]))
              if LEFTOVER_LINKS.match(n)]
    return found + process_leftovers(host) + (bpf_leftovers(host) if bpf else [])


def namespace_pids(host, ns):
    return [int(p) for p in host.run(["ip", "netns", "pids", ns]).out.split() if p.isdigit()]


def _timed(host, argv):
    """Run `argv` on the host; the seconds it took."""
    began = host.monotonic()
    host.run(argv)
    return host.monotonic() - began


def destroy(host, namespaces, links, grace, log=None):
    """Take down `namespaces` and `links`: every process in a namespace (found with `ip netns pids`) gets TERM, then KILL
    after `grace` seconds if it is still there; then the namespaces go, then the links their deletion left. A `log` is told how
    long each step took (S3's teardown took 12.6 s, and nothing said where)."""
    say = log or (lambda message: None)
    began = host.monotonic()
    pids = [p for ns in namespaces for p in namespace_pids(host, ns)]
    listed, ended = host.monotonic() - began, 0.0
    if pids:
        host.run(["kill", "-TERM", *map(str, pids)])
        sent = host.monotonic()
        waited, alive = 0.0, pids
        while alive and waited < grace:
            host.sleep(0.1)
            waited += 0.1
            alive = [p for p in alive if host.exists(f"/proc/{p}")]
        if alive:
            say(f"KILL {len(alive)} processes of the namespaces that ignored TERM for {grace:g} s")
            host.run(["kill", "-KILL", *map(str, alive)])
            host.sleep(0.2)
        ended = host.monotonic() - sent
    say(f"teardown: {len(pids)} process(es) in {len(namespaces)} namespace(s): listed in {listed:.2f} s, ended in {ended:.2f} s")
    deleted = []
    for ns in namespaces:
        deleted.append(f"{ns} {_timed(host, ['ip', 'netns', 'del', ns]):.2f} s")
    say("teardown: namespaces deleted: " + ", ".join(deleted))
    deleted = []
    for link in links:
        deleted.append(f"{link} {_timed(host, ['ip', 'link', 'del', link]):.2f} s")
    say("teardown: links deleted: " + ", ".join(deleted))


def discover(host):
    """The namespaces and links of any testbed that is still there, as destroy() takes them."""
    found = leftovers(host)
    return ([f.split()[1] for f in found if f.startswith("netns ")],
            [f.split()[1] for f in found if f.startswith("link ")])


# --- the events of a run --------------------------------------------------------------------------

class EventLog:
    """executor.log: what happened and when, in seconds since the run began; also said to the console if `say` is given."""

    def __init__(self, path, host, say=None):
        self.path, self.host, self.say, self.t0 = path, host, say, host.time()
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def __call__(self, message):
        line = f"{self.host.time() - self.t0:9.3f} {message}"
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        if self.say:
            self.say(line)


def _utc(t):
    return datetime.datetime.fromtimestamp(t, datetime.UTC).isoformat(timespec="seconds")


def write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path + ".tmp", "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=1, sort_keys=True)
        fh.write("\n")
    os.replace(path + ".tmp", path)


# --- preflight and the environment ----------------------------------------------------------------

def git_state(host):
    def git(*args):
        r = host.run(["git", "-c", f"safe.directory={REPO}", "-C", REPO, *args])
        return r.out.rstrip() if r.code == 0 else None          # not strip(): the first status line starts with a space
    dirty = git("status", "--porcelain", "--untracked-files=no")
    return {"commit": git("rev-parse", "HEAD"), "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
            "dirty": None if dirty is None else bool(dirty), "dirty_files": dirty.splitlines()[:50] if dirty else []}


def preflight(host, plan, allow_dirty=False, clean=False):
    """The conditions of a run: root, the venv, enough descriptors, a clean tree, no leftovers. Refuses, builds nothing.
    The engine's pinned hash and the scope lock were checked when the plan was made (loadtools.build_plan)."""
    python = os.path.join(REPO, "venv", "bin", "python")
    if not host.is_root():
        raise PreflightRefused("needs root (namespaces): sudo ./venv/bin/python bench/executor.py run ...")
    if not host.exists(python):
        raise PreflightRefused(f"no Python venv at {python} (gunicorn runs from it)")
    soft, _ = host.nofile_limit()
    if soft < plan.settings["min_nofile"]:
        raise PreflightRefused(f"the open-file limit is {soft}, below {plan.settings['min_nofile']}")
    git = git_state(host)
    if git["dirty"] and not allow_dirty:
        raise PreflightRefused("uncommitted changes to tracked files (a result must map to a commit; --allow-dirty "
                               "records them): " + ", ".join(git["dirty_files"][:5]))
    bpf = plan.daemon is not None
    left = leftovers(host, bpf)
    if left and clean:
        namespaces, links = discover(host)
        destroy(host, namespaces, links, plan.settings["term_grace_s"])
        left = leftovers(host, bpf)
    if left:
        raise PreflightRefused("a testbed is still present (--clean takes down its namespaces and links):\n  " + "\n  ".join(left))
    return {"git": git, "nofile_soft": soft, "allow_dirty": allow_dirty}


PROVENANCE_FILES = ("origin.py", "loadgen.py", "loadtools.json", "population.py", "scenario.py", "executor.py")
# what a protected run's daemon is made of (paths in the checkout): hashed into the run's provenance
DAEMON_FILES = ("control_plane.py", "ban_events.py", "xdp_ddos_filter.c", "l7_engine.py", "l7_ingest.py", "GRU_ML_model.py",
                "training_results/feature_config_testbed.json")
# H-01 (T-017; fixed on fix/daemon-robustness): one request with a byte that is not UTF-8 ended the daemon's main loop, whose finally
# detached XDP and lifted every ban. A daemon launched for a result must come from a checkout that has the fix (docs/HG1C_DESIGN.md
# 15). The run records whether it has: the fix's first commit is an ancestor of HEAD, or both of the daemon's log tailers read
# undecodable bytes as U+FFFD (the fix's change, which a rebase keeps). A run without it is recorded and warned of, not refused.
DAEMON_FIX_H01 = "8db9827a2a0f78e29c689f8520ccc9f5482fcc92"
H01_TAILERS = ("tail_nginx_logs", "tail_nginx_error_logs")        # the daemon's two log tailers
H01_DECODE = re.compile(r"""\bopen\([^)]*\berrors\s*=\s*['"]replace['"]""")      # an open() that reads undecodable bytes as U+FFFD


def h01_tailers(source):
    """How many of the daemon's two log tailers (H01_TAILERS) open their log with errors='replace', whatever else the call says: 2 with
    the H-01 fix, on fix/daemon-robustness and with fix/rudy-client-ip's newline='\\n' alike (T-028 F-07), 0 without it. A signature
    of the fix's effect, not a count of one exact line."""
    found = 0
    for name in H01_TAILERS:
        body = re.search(rf"^def {name}\(.*?(?=^\S|\Z)", source, re.MULTILINE | re.DOTALL)
        found += bool(body and H01_DECODE.search(body.group(0)))
    return found


def daemon_provenance(host=None):
    """The daemon's files (sha256, None for one that is not there) and the H-01 record: whether the fix's commit is an ancestor of
    the checkout's HEAD (None when git cannot say: no host, or a commit it does not have), how many of the daemon's tailers read
    undecodable bytes as U+FFFD (2 with the fix), and whether either says the fix is in."""
    files = {name: sha256_file(os.path.join(REPO, name)) if os.path.exists(os.path.join(REPO, name)) else None for name in DAEMON_FILES}
    tailers = h01_tailers(_text(DAEMON)) if os.path.exists(DAEMON) else None
    ancestor = None
    if host is not None:
        r = host.run(["git", "-c", f"safe.directory={REPO}", "-C", REPO, "merge-base", "--is-ancestor", DAEMON_FIX_H01, "HEAD"])
        ancestor = {0: True, 1: False}.get(r.code)
    return {"files": files, "h01": {"fix_commit": DAEMON_FIX_H01, "fix_is_ancestor": ancestor, "tailers_replace_undecodable": tailers,
                                    "has_fix": ancestor is True or tailers == 2}}


def provenance(plan, host=None):
    """sha256 of what a result depends on, as the executor finds it: the files of bench/ that make the load and the origin, this
    runner, the Nginx configuration as it is in the repository (the mode's) and as rendered for this run, and the engine as the tool
    manifest pins it; for a run with a daemon, the daemon's files and the H-01 record (daemon_provenance)."""
    manifest = LT.load_manifest()
    files = {name: sha256_file(os.path.join(HERE, name)) for name in PROVENANCE_FILES}
    source = NGINX_CONF if plan.mode is None else os.path.join(REPO, MODES[plan.mode]["conf"])
    out = {"files": files, "nginx_source": plan.nginx_source, "nginx_source_sha256": sha256_file(source),
           "nginx_rendered_sha256": plan.nginx_conf_sha256, "engine_pinned_sha256": manifest["tools"]["loadgen"]["sha256"],
           "engine_is_pinned": files["loadgen.py"] == manifest["tools"]["loadgen"]["sha256"]}
    if plan.daemon is not None:
        out["daemon"] = daemon_provenance(host)
    return out


# docs/HG1C_DESIGN.md departure 30 (D-045): how long the timer gate waits after a refused probe before it probes again
TIMER_REPROBE_S = 30.0


def timer_probe(host, cpus, samples=200, interval=0.01):
    """The timer-lateness probe of the HG1a harness, pinned to `cpus`: how late the machine wakes a sleeper."""
    import loadtool_validate as V
    r = host.run(["taskset", "-c", cpus, sys.executable, V.__file__, "timer-probe", "--samples", str(samples),
                  "--interval", str(interval)], timeout=60)
    try:
        return json.loads(r.out)
    except ValueError:
        return None


def quiet_gate(host, wait_gate_min=30.0, say=None):
    """The uptime and load of the environment gate (docs/HG1B_MINIMAL_DESIGN.md 7.2 step 0; loadtool_validate.GATE: up 30 minutes,
    1-minute load below 0.3): waits up to `wait_gate_min` minutes for them, polling, and refuses with EnvironmentRefused when they
    are not met by then. Returns what was seen. A campaign's first run takes it through `environment`; the calibrator's origin step,
    which makes no run, takes it on its own (calibrate.Runner.quiet)."""
    import loadtool_validate as V
    seen = V.wait_for_gate(wait_gate_min, read_up=lambda: float(host.read_text("/proc/uptime").split()[0]),
                           read_load=lambda: float(host.read_text("/proc/loadavg").split()[0]), sleep=host.sleep,
                           clock=host.monotonic, say=say or (lambda m: None))
    if not seen["met"]:
        raise EnvironmentRefused(f"the machine is not quiet enough: uptime {seen['uptime_s']:.0f} s (needs "
                                 f"{seen['limit_uptime_s']}), load {seen['load1']:.2f} (needs below {seen['limit_load1']})")
    return seen


def timer_wait_text(wait_gate_min):
    """What a run's timer gate does with this wait, for the plans' text."""
    if wait_gate_min <= 0:
        return "one probe (--wait-gate 0)"
    return f"a refused probe is made again every {TIMER_REPROBE_S:g} s, for up to {wait_gate_min:g} min from the run's first probe"


def timer_gate(host, plan, wait_gate_min=30.0, say=None, note=None):
    """The timer of the legit streams' CPU, which every run takes (docs/HG1C_DESIGN.md departure 30, D-045): a probe must have p99
    below the plan's `timer_limit_ms`. After a refused probe it waits TIMER_REPROBE_S and probes again, until a probe passes or
    `wait_gate_min` minutes have passed since the first, so that 0 is one probe; a probe that cannot be read is a refused one. The
    limit does not move. Returns the passing probe and the record of every probe; EnvironmentRefused, with the same record and the
    last reading, after the last. `note` is given the record after each probe, so that a stop during the wait leaves the probes."""
    say, note = say or (lambda m: None), note or (lambda r: None)
    cpus, limit, raised = plan.pins["legit"], plan.timer_limit_ms, "timer_limit_ms" in plan.overrides
    first, probes = host.monotonic(), []
    while True:
        utc = _utc(host.time())
        probe = timer_probe(host, cpus)
        passed = probe is not None and probe["p99_ms"] < limit
        probes.append({"utc": utc, **{k: (probe or {}).get(k) for k in ("p50_ms", "p99_ms", "max_ms")}, "passed": passed})
        waited = host.monotonic() - first
        record = {"timer_limit_ms": limit, "timer_limit_is_override": raised, "timer_probes": probes,
                  "timer_refused_probes": sum(not p["passed"] for p in probes), "timer_waited_s": round(waited, 1)}
        reading = "unknown" if probe is None else f"{probe['p99_ms']:.1f} ms"
        said = "unreadable" if probe is None else f"p50 {probe['p50_ms']:g}, p99 {probe['p99_ms']:g}, max {probe['max_ms']:g} ms"
        verdict = "passed" if passed else f"refused, limit {limit:g} ms"
        say(f"timer probe {len(probes)} on CPU {cpus} at {utc}: {said}: {verdict}")
        note(record)
        if passed:
            return probe, record
        if waited >= wait_gate_min * 60:
            text = (f"timer wake-up on CPU {cpus} (the legit streams'): p99 {reading}, needs below {limit:g} ms"
                    + (" (set by --timer-limit-ms for a smoke test)" if raised else ""))
            if len(probes) > 1:
                text += f"; {len(probes)} probes over {waited:.0f} s (--wait-gate {wait_gate_min:g}), none passed"
            refused = EnvironmentRefused(text)
            refused.record = record
            raise refused
        host.sleep(TIMER_REPROBE_S)


def environment(host, plan, gate="full", wait_gate_min=30.0, say=None, note=None):
    """The environment gate (docs/HG1B_MINIMAL_DESIGN.md 7.2 step 0). The timer on the legit CPU must wake on time, always:
    p99 below the plan's `timer_limit_ms`, which is the calibration's validity.timer_p99_ms unless a smoke test set it (the
    limit used, and whether it was set, are recorded), within the wait of `timer_gate`, which every run may use in full. Uptime and
    load are the gate of a campaign's start (`gate="full"`:
    waits up to `wait_gate_min` for them, `quiet_gate`); between the runs of a campaign (`gate="timer"`) they are only recorded,
    since the load a run leaves is its own and would make every next run wait for it to decay. Refuses with EnvironmentRefused;
    the caller may wait and ask again. A plan that gives the executor a CPU of its own (PIN_PLAN_DAEMON: every run of a campaign
    with a daemon, the warm-up too) has that CPU's timer probed as well, after the gate, and recorded (`timer_executor`), never
    judged: the executor's reaper threads stamp the streams' exits, which the run's clock is made of (T-039 V-33)."""
    say = say or (lambda m: None)
    up, load = float(host.read_text("/proc/uptime").split()[0]), float(host.read_text("/proc/loadavg").split()[0])
    if gate == "full":
        seen = quiet_gate(host, wait_gate_min, say)
    else:
        seen = {"met": None, "uptime_s": up, "load1": load, "waited_s": 0.0}
    probe, timer = timer_gate(host, plan, wait_gate_min, say, note)
    own = plan.pins.get("executor")
    timers = {"timer_executor": timer_probe(host, own), "timer_executor_cpus": own} if own is not None else {}
    stat = host.read_text("/proc/stat").splitlines()[0].split()
    try:
        governor = host.read_text("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor").strip()
    except OSError:
        governor = None
    return {"gate_mode": gate, "gate": seen, "timer_legit": probe, **timer, **timers, "governor": governor,
            "steal_jiffies": int(stat[8]) if len(stat) > 8 else None, "jiffies": sum(map(int, stat[1:9]))}


# --- telemetry: recorded, not judged --------------------------------------------------------------

class Sampler:
    """One row a tick: the load, the busy share of each CPU and of all, the steal share, the CPU of the origin and of Nginx,
    and the listen-queue counters and sockets of the server namespace. Every read may fail; a failed read is an empty cell."""

    def __init__(self, host):
        self.host, self.rows, self.pids, self._last, self._ticks = host, [], {}, None, 0
        self.tck = host.clk_tck()
        self.daemon_pid = None           # a protected run's daemon: a Python process in server_ns, which is not the origin

    def groups(self):
        return ("origin", "nginx", "daemon") if self.daemon_pid else ("origin", "nginx")

    def attach(self):
        """Find the server namespace's processes, grouped by what they are (Nginx, the origin and a protected run's daemon)."""
        self.pids = {}
        for pid in namespace_pids(self.host, SERVER_NS):
            if pid == self.daemon_pid:
                self.pids[pid] = "daemon"
                continue
            try:
                comm = self.host.read_text(f"/proc/{pid}/comm").strip()
            except OSError:
                continue
            self.pids[pid] = "nginx" if comm.startswith("nginx") else "origin"

    def _cpu(self):
        out = {}
        for line in self.host.read_text("/proc/stat").splitlines():
            parts = line.split()
            if parts[0].startswith("cpu"):
                v = list(map(int, parts[1:]))
                out[parts[0]] = (sum(v[:8]), v[3] + v[4], v[7] if len(v) > 7 else 0)     # guest time is in user's already
        return out

    def _proc_jiffies(self):
        out = {"origin": 0, "nginx": 0}       # a daemon whose CPU could not be read has no entry, and no share in the row
        for pid, group in self.pids.items():
            try:
                f = self.host.read_text(f"/proc/{pid}/stat").rsplit(")", 1)[1].split()
                out[group] = out.get(group, 0) + int(f[11]) + int(f[12])                # utime + stime
            except (OSError, IndexError, ValueError):
                pass
        return out

    def _tcp(self):
        out = {"listen_overflows": None, "listen_drops": None, "tcp_inuse": None, "tcp_tw": None}
        pid = next(iter(self.pids), None)
        if pid is None:
            return out
        try:
            lines = self.host.read_text(f"/proc/{pid}/net/netstat").splitlines()
            for head, vals in zip(lines[::2], lines[1::2], strict=False):
                if head.startswith("TcpExt:"):
                    named = dict(zip(head.split()[1:], vals.split()[1:], strict=False))
                    out["listen_overflows"], out["listen_drops"] = int(named["ListenOverflows"]), int(named["ListenDrops"])
        except (OSError, ValueError, KeyError):
            pass
        try:
            for line in self.host.read_text(f"/proc/{pid}/net/sockstat").splitlines():
                if line.startswith("TCP:"):
                    w = line.split()
                    out["tcp_inuse"], out["tcp_tw"] = int(w[w.index("inuse") + 1]), int(w[w.index("tw") + 1])
        except (OSError, ValueError, IndexError):
            pass
        return out

    def sample(self, t_rel):
        if self._ticks and self._ticks % REATTACH_EVERY == 0:
            self.attach()
        self._ticks += 1
        row = {"t_epoch": round(self.host.time(), 3), "t_rel": round(t_rel, 3), "load1": None}
        try:
            row["load1"] = float(self.host.read_text("/proc/loadavg").split()[0])
            now = {"cpu": self._cpu(), "proc": self._proc_jiffies()}
        except (OSError, ValueError, IndexError):
            self.rows.append(row)
            return
        if self._last is not None:
            before, dt = self._last, max(row["t_epoch"] - self._last["t"], 1e-6)
            for name, (total, idle, steal) in now["cpu"].items():
                b = before["cpu"].get(name)
                if b and total > b[0]:
                    row[f"{name}_busy_pct"] = round(100.0 * (1 - (idle - b[1]) / (total - b[0])), 1)
                    if name == "cpu":
                        row["steal_pct"] = round(100.0 * (steal - b[2]) / (total - b[0]), 2)
            for group in self.groups():
                if group in before["proc"] and group in now["proc"]:
                    row[f"{group}_cpu_pct"] = round(100.0 * (now["proc"][group] - before["proc"][group]) / (self.tck * dt), 1)
        row.update(self._tcp())
        self._last = {**now, "t": row["t_epoch"]}
        self.rows.append(row)

    def write(self, path):
        names = ["t_epoch", "t_rel", "load1", "steal_pct", "origin_cpu_pct", "nginx_cpu_pct",
                 *(["daemon_cpu_pct"] if self.daemon_pid else []), "listen_overflows", "listen_drops", "tcp_inuse", "tcp_tw"]
        names += sorted({k for r in self.rows for k in r if k.endswith("_busy_pct")}, key=lambda k: (len(k), k))
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(names)
            for r in self.rows:
                w.writerow(["" if r.get(k) is None else r[k] for k in names])


def _limit(text, name):
    """(soft, hard) of a row of /proc/<pid>/limits, as numbers or the word `unlimited`."""
    for line in text.splitlines():
        if line.startswith(name):
            words = line[len(name):].split()
            return [int(w) if w.isdigit() else w for w in words[:2]]
    return None


def stack_facts(host, sampler):
    """What the stack was started with, read back from the running processes: for the origin and for Nginx, how many
    processes there are, the open-file limit they inherited and the CPUs they may run on (design 4.3: the limits are ambient,
    so this is where they are recorded)."""
    sampler.attach()
    out = {}
    for group in sampler.groups():
        pids = sorted(p for p, g in sampler.pids.items() if g == group)
        cpus, limits = set(), set()
        for pid in pids:
            try:
                status = host.read_text(f"/proc/{pid}/status")
                cpus.add(next(line.split(":", 1)[1].strip() for line in status.splitlines()
                              if line.startswith("Cpus_allowed_list:")))
                limits.add(tuple(_limit(host.read_text(f"/proc/{pid}/limits"), "Max open files") or ()))
            except (OSError, StopIteration):
                pass
        out[group] = {"processes": len(pids), "cpus_allowed": sorted(cpus),
                      "nofile_soft_hard": sorted(list(x) for x in limits)}
    return out


def aggregate_access_log(lines, t_zero):
    """Rows of server_requests.csv from the lines of the Nginx JSON access log: per second since `t_zero` of ARRIVAL, client
    class and status, how many requests and their mean and largest request time. Nginx writes a line when a request ends,
    in whole seconds (truncated); a request is put where it arrived: the log second plus half a second less the request
    time, as test_distributed_suite.aggregate_access_log does. The class is the address prefix of the population. Lines
    that are not JSON or lack a field are counted and left out."""
    cells, bad = {}, 0
    for line in lines:
        try:
            r = json.loads(line)
            ended = float(int(datetime.datetime.fromisoformat(r["timestamp"]).timestamp()))
            took = float(r["request_time"])
            ip = ipaddress.ip_address(r["client_ip"])
            klass = ("attack" if any(ip in n for n in P.ATTACK_NETS) else "legit" if any(ip in n for n in P.BENIGN_NETS)
                     else "other")
            key = (math.floor(ended + 0.5 - took - t_zero), klass, int(r["status"]))
        except (ValueError, KeyError, TypeError, OverflowError):
            bad += 1
            continue
        cell = cells.setdefault(key, [0, 0.0, 0.0])
        cell[0] += 1
        cell[1] += took
        cell[2] = max(cell[2], took)
    return [(sec, klass, status, n, total / n, top) for (sec, klass, status), (n, total, top) in sorted(cells.items())], bad


# --- the clocks of the streams --------------------------------------------------------------------

RECORDS_UNREADABLE = (OSError, EOFError, ValueError, IndexError, StopIteration, csv.Error, zlib.error)
WALL_GAP_NOTE_S = 0.05               # a wall time raised by more than this is said in the run's log


def estimate_t0(t_exit, wall_s, intended=0, per_request_s=0.0):
    """When a stream's schedule began, on the executor's clock, up to the time between the end of its loop and its exit
    (summary, records, interpreter shutdown). That time is nearly the same for every stream and cancels in the offsets; the
    part of it that grows with the number of requests can be taken off with `per_request_s` (S1 measures it; 0 until then).
    `wall_s` is the engine's wall time as consistent_wall holds it to the records."""
    return t_exit - wall_s + ENGINE_T0_OFFSET_S - per_request_s * intended


def last_done(path):
    """When the last request of a stream finished, in seconds after its schedule's zero: the largest finite t_done of an engine
    records file, None if no request finished. Raises one of RECORDS_UNREADABLE when the file cannot be read."""
    with gzip.open(path, "rt", encoding="utf-8", newline="") as fh:
        rows = csv.reader(fh)
        col = next(rows).index("t_done")
        return max((v for v in (float(row[col]) for row in rows) if math.isfinite(v)), default=None)


def consistent_wall(wall_s, last):
    """The wall time an engine reports, held to what its own records allow. The engine reads the schedule's zero (the clock plus
    50 ms) and, one statement later, the clock its wall time counts from; a process that is descheduled in between reports a wall
    time too short by that long, and its start comes out that much too late. S1b, 29 streams started together on one CPU: 0.05 to
    0.3 s in most of them, 2.0 s in one. The loop cannot end before its last request has, and its clock starts at least 50 ms
    before the zero, so the wall time is at least the last t_done plus those 50 ms. `last` is None when no request finished: the
    wall time stands."""
    return wall_s if last is None else max(wall_s, last + ENGINE_T0_OFFSET_S)


def pack_of(times, limit):
    """The most streams that began within `limit` of one another, and the rest. `times` maps a stream id to when it began. Of two
    packs of the same size the one nearer the median start is taken. Returns (the ids of the pack, the ids outside it), each
    in the order of their starts."""
    ids = sorted(times, key=lambda sid: (times[sid], sid))
    ts = [times[sid] for sid in ids]
    middle = statistics.median(ts)
    best, j = None, 0
    for i in range(len(ids)):
        j = max(j, i)
        while j + 1 < len(ids) and ts[j + 1] - ts[i] <= limit:
            j += 1
        key = (-(j - i + 1), abs((ts[i] + ts[j]) / 2 - middle), i)
        if best is None or key < best[0]:
            best = (key, i, j)
    _, i, j = best
    return ids[i:j + 1], ids[:i] + ids[j + 1:]


def stragglers_allowed(n, share):
    """How many of the `n` legit streams of a group may be stragglers: the whole number in `share` of them, and fewer than half of
    the group whatever the share, so that the pack is a majority and the group's zero is the median of more than half of its
    streams and not of a tie. (A product such as 0.29 x 100 is a hair under 29 in floating point, hence the tolerance.)"""
    return max(0, min(int(n * share + 1e-9), (n - 1) // 2))


def alignment(plan, found, tails=None):
    """The run's clocks from what the streams reported. `found` maps a stream id to (t_exit, wall_s, intended), the wall time as
    consistent_wall holds it to the records (collect does that); `tails` maps a stream id to how long its loop outlived its last
    request. Streams that start together (a kind and a `start_s`) are a group. Of the legit streams of a group the pack is the most
    that began within the limit of one another; the others are stragglers. The axis begins where the first group's pack does (its
    zero is the pack's median start). A group is sound when the pack is a majority of its streams (stragglers_allowed) and at most
    `straggler_share` of them are stragglers, each with a tail of at most `straggler_tail_s` (its engine ended its loop with its last
    request, so the estimate of its start is as good as the pack's, and the harm gate places its records by its own offset), when no
    two of its streams began further apart than `t0_range_limit_s`, and, unless it is the first group, when the pack's
    median start is within `group_start_limit_s` of where the plan puts it: the steps of a staged load at their times. The attack is
    sound when its median start is within `attack_start_limit_s` of the end of the baseline. Returns the offsets of the streams from the zero, the spread of
    the packs and the range of all the legit starts, the stragglers, the error of the attack's start, and the reasons for which the
    run is unsound (executor.ok is false when there are any)."""
    per = plan.settings["exit_delay_per_request_s"]
    t0 = {sid: estimate_t0(t_exit, wall, n, per) for sid, (t_exit, wall, n) in found.items()}
    legit = [x for x in plan.streams if x.kind == "legit" and x.id in t0]
    if not legit:
        return {"offsets": {}, "t0_spread_legit_s": None, "t0_range_legit_s": None, "stragglers": [], "attack_start_error_s": None,
                "reasons": ["no legit stream reported"], "zero": None}
    tails = tails or {}
    spread_limit, range_limit = plan.settings["t0_spread_limit_s"], plan.settings["t0_range_limit_s"]
    start_limit, group_limit = plan.settings["attack_start_limit_s"], plan.settings["group_start_limit_s"]
    share, tail_limit = plan.settings["straggler_share"], plan.settings["straggler_tail_s"]
    groups = collections.defaultdict(dict)
    for x in plan.streams:
        if x.id in t0:
            groups[(x.kind, x.start_s)][x.id] = t0[x.id]
    first = min(x.start_s for x in legit)
    packs = {key: pack_of(times, spread_limit) for key, times in groups.items() if key[0] == "legit"}
    zero = statistics.median(t0[sid] - first for sid in packs[("legit", first)][0])
    reasons, spreads, ranges, errors, stragglers = [], [], [], [], []
    for (kind, start), times in sorted(groups.items()):
        if kind == "legit":
            pack, out = packs[(kind, start)]
            kept = [times[sid] for sid in pack]
            median, spread, error = statistics.median(kept), max(kept) - min(kept), statistics.median(kept) - (zero + start)
            spreads.append(spread)
            ranges.append(max(times.values()) - min(times.values()))
            where = "" if start == first else f" that start at {start:g} s"
            allowed = stragglers_allowed(len(times), share)
            if len(out) > allowed:
                reasons.append(f"the legit streams{where} began {ranges[-1]:.2f} s apart (limit {spread_limit:g} s"
                               + (f"; {len(out)} of {len(times)} are outside the pack, at most {allowed} may be)" if allowed else ")"))
            if ranges[-1] > range_limit:
                reasons.append(f"the legit streams{where} began {ranges[-1]:.2f} s apart, further than the {range_limit:g} s within which "
                               f"a straggler may begin")
            for sid in sorted(out):
                tail = tails.get(sid, 0.0)
                stragglers.append({"id": sid, "offset_s": round(times[sid] - zero, 4), "from_pack_s": round(times[sid] - median, 4),
                                   "tail_s": tail})
                if len(out) <= allowed and tail > tail_limit:
                    reasons.append(f"legit stream {sid} began {times[sid] - median:+.2f} s from the others and its loop ended {tail:.2f} s "
                                   f"after its last request, so where it began cannot be told (limit {tail_limit:g} s)")
            if start != first and abs(error) > group_limit:
                reasons.append(f"the legit streams that start at {start:g} s began {error:+.2f} s from their start "
                               f"(limit {group_limit:g} s)")
        else:
            error = statistics.median(times.values()) - (zero + start)
            errors.append(error)
            if abs(error) > start_limit:
                reasons.append(f"the attack began {error:+.2f} s from the end of the baseline (limit {start_limit:g} s)")
    if any(x.kind == "attack" for x in plan.streams) and not errors:
        reasons.append("no attack stream reported")
    return {"offsets": {sid: v - zero for sid, v in t0.items()}, "t0_spread_legit_s": max(spreads), "t0_range_legit_s": max(ranges),
            "stragglers": stragglers, "attack_start_error_s": max(errors, key=abs) if errors else None, "reasons": reasons, "zero": zero}


# --- building the testbed -------------------------------------------------------------------------

def _skipped(host, when):
    """A command's condition: `absent:<path>` runs it only if the path is not there, `present:<path>` only if it is."""
    kind, _, path = when.partition(":")
    return (kind == "absent" and host.exists(path)) or (kind == "present" and not host.exists(path))


def _do(host, step, plan, log, procs):
    """One step of the plan. A command that fails raises SetupFailed with what it said."""
    if isinstance(step, Prim):
        host.prim(step.name, *step.args)
    elif isinstance(step, Mkdir):
        for path in step.paths:
            os.makedirs(path, exist_ok=True)
    elif isinstance(step, Write):
        if step.path != f"{plan.out}/nginx.conf" or _sha(plan.nginx_conf) != step.sha256:
            raise SetupFailed(f"{step.path}: the plan holds no text with that hash")
        with open(step.path, "w", encoding="utf-8") as fh:
            fh.write(plan.nginx_conf)
    elif step.when and _skipped(host, step.when):
        return
    elif step.keep:
        with open(f"{plan.out}/gunicorn.log", "ab") as err:
            procs["origin"] = host.popen(list(step.argv), ns=step.ns, env=dict(step.env) or None, stderr=err)
        log(f"started the origin as pid {procs['origin'].pid}")
    elif step.detach:
        start_daemon(host, step, plan, log)
    else:
        r = host.run(list(step.argv), ns=step.ns, stdin=step.stdin, env=dict(step.env) or None)
        if r.code != 0:
            raise SetupFailed(f"{' '.join(map(str, step.argv))[:120]} exited {r.code}: {(r.err or r.out).strip()[:200]}")


def start_daemon(host, step, plan, log):
    """Nginx, started the way the suite starts it: a process of its own with no pipe for its daemon to hold. Run to completion with
    its output captured, the call came back only at its timeout, three times in S3 (a daemon that keeps the pipes of such a call
    keeps it from returning: an inference, docs/HG1C_DESIGN.md 14). Its stderr goes to a file of the run, as the origin's does, so
    that a start that fails keeps its message. The launcher returns once the daemon has forked; the daemon is found again by
    namespace (the sampler, the teardown)."""
    path = f"{plan.out}/nginx_start.log"
    with open(path, "ab") as err:
        launcher = host.popen(list(step.argv), ns=step.ns, env=dict(step.env) or None, stderr=err)
    began = host.monotonic()
    while launcher.poll() is None and host.monotonic() - began < DAEMON_FORK_WAIT_S:
        host.sleep(0.05)
    shown = " ".join(map(str, step.argv))[:120]
    if launcher.poll() is None:                      # the teardown ends it with the rest of the namespace's processes
        raise SetupFailed(f"{shown} did not return within {DAEMON_FORK_WAIT_S:g} s: Nginx is not daemonising, or it hangs")
    if launcher.poll() != 0:
        raise SetupFailed(f"{shown} exited {launcher.poll()}: {_tail(path, 3)[:200]}")
    log(f"started Nginx (its launcher returned after {host.monotonic() - began:.2f} s)")


def verify_topology(host, plan):
    """What the suite's primitives left, read back: the addresses of each namespace against the plan, one MAC each, the
    server's address, and the netem qdisc of the profiles that have one. The suite's `run` swallows failures, so this is
    where a missing address shows."""
    problems, macs = [], {}
    for ns in plan.namespaces:
        r = host.run(["ip", "-j", "addr", "show", "dev", CLIENT_IF], ns=ns.name)
        try:
            have = sorted(a["local"] for i in json.loads(r.out) for a in i["addr_info"] if a["family"] == "inet")
        except (ValueError, KeyError, TypeError):
            problems.append(f"{ns.name}: no readable addresses ({(r.err or r.out).strip()[:80]})")
            continue
        want = sorted(ns.addresses)
        if have != want:
            problems.append(f"{ns.name}: {len(have)} addresses, expected {len(want)} (missing "
                            f"{len(set(want) - set(have))}, extra {len(set(have) - set(want))})")
        r = host.run(["ip", "-j", "link", "show", CLIENT_IF], ns=ns.name)
        try:
            mac = json.loads(r.out)[0]["address"]
        except (ValueError, KeyError, IndexError, TypeError):
            problems.append(f"{ns.name}: no readable MAC")
            continue
        if mac in macs:
            problems.append(f"{ns.name}: the MAC {mac} is also {macs[mac]}'s")
        macs[mac] = ns.name
        qdisc = host.run(["tc", "qdisc", "show", "dev", CLIENT_IF], ns=ns.name).out
        if (ns.profile != "perfect") != ("netem" in qdisc):
            problems.append(f"{ns.name}: {'no netem' if ns.profile != 'perfect' else 'a netem qdisc'} on a {ns.profile} link")
    r = host.run(["ip", "-j", "addr", "show", "dev", "veth_server"], ns=SERVER_NS)
    if SERVER_IP not in r.out:
        problems.append(f"{SERVER_NS}: no {SERVER_IP} on veth_server")
    return problems


# The links drop packets on their way out (netem: 2 % on mobile_3g, 5 % and 1 % corrupted on mobile_bad), so a ping that needs its one
# packet to arrive fails once in 17 on mobile_bad, and the eight pings of a testbed fail in one build of seven. Three packets, 0.2 s
# apart, and any reply (ping exits 0 if it has had one) leave about one in a thousand.
PING_COUNT, PING_INTERVAL_S, PING_WAIT_S = 3, 0.2, 3.0
PING_RUN_S = 10.0                    # the most a ping command may take: (PING_COUNT - 1) x PING_INTERVAL_S + PING_WAIT_S when no reply comes


def connectivity(host, plan):
    """Pings to the server from each namespace and from its last alias (the alias is then the source address): PING_COUNT packets
    each, and the namespace answers if any one is answered."""
    problems = []
    for ns in plan.namespaces:
        for source in dict.fromkeys([None, ns.addresses[-1]]):
            argv = ["ping", "-c", str(PING_COUNT), "-i", str(PING_INTERVAL_S), "-W", f"{PING_WAIT_S:g}",
                    *(["-I", source] if source else []), SERVER_IP]
            if host.run(argv, ns=ns.name, timeout=PING_RUN_S).code != 0:
                problems.append(f"{ns.name}: no answer from {SERVER_IP}" + (f" to {source}" if source else ""))
    return problems


def build_topology(host, plan, log, procs):
    t = host.monotonic()
    for step in plan.topology:
        _do(host, step, plan, log, procs)
    problems = verify_topology(host, plan) + connectivity(host, plan)
    if problems:
        raise SetupFailed("topology: " + "; ".join(problems))
    log(f"topology: {len(plan.namespaces)} namespaces, {sum(len(n.addresses) for n in plan.namespaces)} addresses, "
        f"verified in {host.monotonic() - t:.1f} s")


def _curl(host, path, headers=False, timeout=5):
    argv = ["curl", "-s", "--max-time", str(timeout), "-o", "/dev/null"]
    argv += ["-D", "-"] if headers else ["-w", "%{http_code}"]
    return host.run([*argv, HTTP_URL[:-1] + path], ns=SERVER_NS, timeout=timeout + 5)


def start_stack(host, plan, log, procs):
    """The origin, then Nginx; ready when the cheapest route answers 200 and every route answers with its own class, under
    this calibration. Then the warm-up. SetupFailed when the stack does not come up."""
    for step in plan.stack:
        _do(host, step, plan, log, procs)
    deadline = host.monotonic() + plan.settings["readiness_timeout_s"]
    while True:
        r = _curl(host, READY_PATH, timeout=2)
        if r.code == 0 and r.out.strip() == "200":
            break
        if procs["origin"].poll() is not None:
            raise SetupFailed(f"the origin exited with {procs['origin'].poll()} (see gunicorn.log)")
        if host.monotonic() > deadline:
            raise SetupFailed(f"the stack did not answer 200 at {READY_PATH} within {plan.settings['readiness_timeout_s']:g} s")
        host.sleep(0.3)
    tag = "placeholder" if plan.calibration_status != "frozen" else f"frozen:{plan.calibration_sha256[:8]}"
    for klass, path in plan.checks:
        head = {k.strip().lower(): v.strip() for line in _curl(host, path, headers=True).out.splitlines()
                if ":" in line for k, v in [line.split(":", 1)]}
        if head.get("x-route-class") != klass:
            raise SetupFailed(f"{path} answered with route class {head.get('x-route-class')!r}, not {klass}")
        if head.get("x-origin-calibration") != tag:
            raise SetupFailed(f"{path}: the origin runs calibration {head.get('x-origin-calibration')!r}, the plan's is {tag}")
    for _ in range(plan.settings["warmup_requests"]):
        for _, path in plan.checks:
            _curl(host, path)
    log(f"stack ready: {len(plan.checks)} routes answer with their own class under calibration {tag}; warmed up")


# --- the daemon of a protected run ---------------------------------------------------------------

def _text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def daemon_events(path):
    """The events a daemon wrote to its ban file (JSON lines: ban_events.py, docs/EVALUATION.md), oldest first; [] while there is
    none. A line that is not whole yet is skipped, as ban_events.read_events does."""
    events = []
    for line in _text(path).splitlines():
        with contextlib.suppress(ValueError):
            event = json.loads(line)
            if isinstance(event, dict) and "kind" in event:
                events.append(event)
    return events


def xdp_program(host):
    """The id of the program attached to veth_server in server_ns; None when there is none or the link cannot be read."""
    r = host.run(["ip", "-j", "link", "show", XDP_DEVICE], ns=SERVER_NS)
    try:
        return json.loads(r.out)[0]["xdp"]["prog"]["id"]
    except (ValueError, KeyError, IndexError, TypeError):
        return None


def start_mitigation(host, plan, log, procs, sampler):
    """A protected run's daemon (plan.daemon), once the stack is ready: started and held by its handle, its output in daemon.log;
    ready when it has said DAEMON_READY_LINE, its start event (with its own pid) is in the run's ban file and, with XDP, a program is
    attached to veth_server. SetupFailed when it exits first or is not ready within DAEMON_READY_TIMEOUT_S, saying what was missing.
    Returns what was seen at readiness (None without a daemon); from then on the sampler counts the daemon apart from the origin."""
    d = plan.daemon
    if d is None:
        return None
    with open(d.log, "ab") as out:
        proc = procs["daemon"] = host.popen(list(d.argv), ns=d.ns, env=dict(d.env), stdout=out, stderr=out, cwd=d.cwd)
    began, started = host.monotonic(), host.time()
    while True:
        said = DAEMON_READY_LINE in _text(d.log)
        start = next((e for e in daemon_events(d.events) if e["kind"] == "start" and e.get("pid") == proc.pid), None)
        prog = xdp_program(host) if d.backend == "xdp" else None
        if said and start is not None and (d.backend != "xdp" or prog is not None):
            break
        if proc.poll() is not None:
            raise SetupFailed(f"the daemon exited with {proc.poll()} before it was ready: {_tail(d.log, 2)[:240]}")
        if host.monotonic() - began > DAEMON_READY_TIMEOUT_S:
            missing = [what for what, ok in ((f"line '{DAEMON_READY_LINE}'", said), ("start event", start is not None),
                                             (f"XDP program on {XDP_DEVICE}", d.backend != "xdp" or prog is not None)) if not ok]
            raise SetupFailed(f"the daemon was not ready within {DAEMON_READY_TIMEOUT_S:g} s: no " + ", no ".join(missing))
        host.sleep(0.5)
    sampler.daemon_pid = proc.pid
    after = host.monotonic() - began
    log(f"started the daemon as pid {proc.pid}: ready after {after:.1f} s" + (f", XDP program {prog} on {XDP_DEVICE}" if prog else ""))
    return {"pid": proc.pid, "started_epoch_s": round(started, 3), "ready_epoch_s": round(host.time(), 3),
            "ready_after_s": round(after, 2), "xdp_prog_at_ready": prog, "start_event": start,
            "feed_at_ready": {path: host.stat(path) for path in (FEED_ACCESS_LOG, FEED_ERROR_LOG)}}


def feed_before(plan, host):
    """What the host's Nginx logs held before a run with a daemon, now in the run (FEED_BEFORE): bytes per file, None for one there
    was not. Recorded in the run's provenance (T-028 F-06)."""
    out = {}
    for path in (FEED_ACCESS_LOG, FEED_ERROR_LOG):
        seen = host.stat(f"{plan.out}/{FEED_BEFORE}/{os.path.basename(path)}")
        out[path] = None if seen is None else {"moved_to": f"{FEED_BEFORE}/{os.path.basename(path)}", "bytes": seen[1]}
    return out


def stop_daemon(host, procs, log):
    """The daemon this run holds (procs["daemon"]), stopped by its handle: SIGINT, which runs its finally (XDP detached, exit 0),
    KILL if it is still there after DAEMON_STOP_GRACE_S; then XDP is taken off veth_server whatever it did, as the suite does. The
    handle is let go, so that a second call does nothing. Returns the record of the stop; None if there was no daemon."""
    proc = procs.pop("daemon", None)
    if proc is None:
        return None
    began = host.monotonic()
    record = {"signal": None, "killed": False}
    if proc.poll() is None:
        record["signal"] = "INT"
        proc.interrupt()
        while proc.poll() is None and host.monotonic() - began < DAEMON_STOP_GRACE_S:
            host.sleep(0.1)
        if proc.poll() is None:
            log(f"KILL the daemon (pid {proc.pid}): SIGINT did not end it within {DAEMON_STOP_GRACE_S:g} s")
            proc.kill()
            record["killed"] = True
            host.sleep(0.2)
    off = host.run(["ip", "link", "set", "dev", XDP_DEVICE, "xdp", "off"], ns=SERVER_NS)
    record.update(exit=proc.poll(), exit_epoch_s=None if proc.exit_time is None else round(proc.exit_time, 3),
                  seconds=round(host.monotonic() - began, 2), xdp_off=off.code == 0)
    log(f"stopped the daemon (pid {proc.pid}) in {record['seconds']:.2f} s: exit {record['exit']}"
        + (", killed" if record["killed"] else "") + f"; XDP off {XDP_DEVICE}: " + ("done" if record["xdp_off"] else f"exit {off.code}"))
    return record


def daemon_validity(host, plan, procs, daemon, sampler, t_launch):
    """Why a protected run with a daemon is not sound (G11), looked at when the timeline is over and before the daemon is stopped,
    and what was seen. The daemon was ready before the first stream was launched, so before the attack; it must still be alive. With
    XDP, the program on veth_server must still be the one it attached at readiness. Its start event must say what the mode asks for
    (its backend and MODE_DAEMON), whatever its environment was; the run's ban file must be there; its CPU must have been sampled.
    None of these reads what the attack did to the server. `t_launch` is when the legit streams were launched."""
    d, proc = plan.daemon, procs.get("daemon")
    reasons = []
    alive = proc is not None and proc.poll() is None
    if not alive:
        when = "" if proc is None or proc.exit_time is None else f" at T+{proc.exit_time - t_launch:.1f} s after the launch"
        reasons.append(f"the daemon exited with {None if proc is None else proc.poll()}{when}, before the end of the run")
    prog = xdp_program(host) if d.backend == "xdp" else None
    if d.backend == "xdp" and prog != daemon["xdp_prog_at_ready"]:
        reasons.append(f"XDP: the program on {XDP_DEVICE} at the end of the run is {prog or 'none'}, not "
                       f"{daemon['xdp_prog_at_ready']}, the one attached at readiness")
    start = daemon["start_event"] or {}
    for key, value in {"backend": d.backend, **MODE_DAEMON}.items():
        if start.get(key) != value:
            reasons.append(f"the daemon's start event says {key} {start.get(key)}, the mode asks for {value}")
    if not os.path.exists(d.events):
        reasons.append(f"the ban file {os.path.basename(d.events)} is not there")
    shares, seconds, previous = [], 0.0, None
    for row in sampler.rows:
        if row.get("daemon_cpu_pct") is not None:
            shares.append(row["daemon_cpu_pct"])
            if previous is not None:
                seconds += row["daemon_cpu_pct"] / 100.0 * (row["t_epoch"] - previous)
        previous = row["t_epoch"]
    if not shares:
        reasons.append("the daemon's CPU was never sampled")
    cpu = {"samples": len(shares), "mean_pct": round(statistics.fmean(shares), 2) if shares else None,
           "max_pct": max(shares, default=None), "seconds": round(seconds, 2)}
    feed = {path: host.stat(path) for path in (FEED_ACCESS_LOG, FEED_ERROR_LOG)}
    for path, now in feed.items():                  # T-028 F-04: logrotate, or anything else, during the run
        then = (daemon.get("feed_at_ready") or {}).get(path)
        if then is None or now is None or now[0] != then[0]:
            reasons.append(f"the daemon's feed {path} was replaced or removed during the run (inode {then and then[0]} at readiness, "
                           f"{now and now[0]} at the end): the daemon lost what Nginx wrote meanwhile")
    own = host.stat(f"{plan.out}/nginx_access.log")
    access = feed[FEED_ACCESS_LOG]
    if own is not None and access is not None and access[1] < own[1]:
        reasons.append(f"the daemon's feed {FEED_ACCESS_LOG} holds {access[1]} bytes, less than the run's own access log ({own[1]}), "
                       "which Nginx writes line for line with it: it was truncated during the run")
    return reasons, {"alive_at_end": alive, "xdp_prog_at_end": prog, "cpu": cpu,
                     "feed_at_end": feed, "run_access_log_bytes": None if own is None else own[1]}


# --- the timeline and what it leaves --------------------------------------------------------------

def launch_streams(host, streams, log, procs):
    for s in streams:
        os.makedirs(s.workdir, exist_ok=True)
        with open(f"{s.workdir}/loadgen.stderr", "wb") as err:
            procs[s.id] = host.popen(list(s.argv), ns=s.ns, stderr=err)
    log(f"launched {len(streams)} {streams[0].kind} streams" if streams else "no streams to launch")


def left_output(stream):
    """Whether an engine left its summary and its records."""
    return os.path.exists(stream.summary) and os.path.exists(stream.records)


def run_timeline(host, plan, log, procs, sampler):
    """Launch every stream at its time (launch_due), sample once a second, and wait for all of them to exit. Returns the
    times of the first launch of each kind and the reasons the timeline went wrong (a stream that died, one that never ended).
    An engine exits when its last request is done (S1b), so a stream of a few tenths of a request per second ends long before
    its duration does; it has died only if it exits with an error, or leaving no output, more than EARLY_SLACK_S before its end."""
    s = plan.settings
    t_launch = host.time()
    waiting = sorted(plan.streams, key=lambda x: (launch_due(plan, x), x.id))
    launched, ends, reasons = {}, {}, []
    deadline = t_launch + s["startup_delay_legit_s"] + plan.timeline["total_s"] + DRAIN_S + s["term_grace_s"] + 10.0
    while True:
        now = host.time()
        due = []
        while waiting and t_launch + launch_due(plan, waiting[0]) <= now + 1e-9:
            due.append(waiting.pop(0))
        for kind in ("legit", "attack"):
            group = [x for x in due if x.kind == kind]
            if group:
                launched.setdefault(kind, now)
                launch_streams(host, group, log, procs)
                own = s["startup_delay_attack_s"] if kind == "attack" else s["startup_delay_legit_s"]
                ends.update({x.id: now + own + x.duration_s for x in group})
                if not sampler.pids:
                    sampler.attach()
        sampler.sample(now - t_launch)
        dead = [x for x in plan.streams if x.id in procs and procs[x.id].poll() is not None
                and now < ends[x.id] - EARLY_SLACK_S and (procs[x.id].poll() != 0 or not left_output(x))]
        if dead:
            reasons += [f"stream {x.id} exited with {procs[x.id].poll()} at T+{now - t_launch:.1f} s, "
                        f"{ends[x.id] - now:.0f} s before its end" + ("" if left_output(x) else ", leaving no output") for x in dead]
            break
        running = [x for x in plan.streams if x.id in procs and procs[x.id].poll() is None]
        if not running and not waiting:
            break
        if now > deadline:
            reasons.append(f"{len(running)} streams were still running {now - t_launch:.0f} s after the launch")
            break
        soonest = [t_launch + launch_due(plan, waiting[0]) - now] if waiting else []
        host.sleep(max(0.01, min([TICK_S, *soonest])))
    log(f"timeline over after {host.time() - t_launch:.1f} s" + (f"; {len(reasons)} problems" if reasons else ""))
    return launched, reasons


def stop_all(host, procs, plan, log):
    """TERM, then KILL after the grace, for the processes this run started and holds a handle of; the namespaces' other
    processes (Nginx, gunicorn's workers) go in the teardown."""
    live = [p for p in procs.values() if p.poll() is None]
    if not live:
        return
    began = host.monotonic()
    for p in live:
        p.terminate()
    waited = 0.0
    while any(p.poll() is None for p in live) and waited < plan.settings["term_grace_s"]:
        host.sleep(0.1)
        waited += 0.1
    for p in live:
        if p.poll() is None:
            log(f"KILL pid {p.pid}")
            p.kill()
    log(f"stopped {len(live)} process(es) of this run in {host.monotonic() - began:.2f} s")


def _tail(path, n=1):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = [x.strip() for x in fh.read().splitlines() if x.strip()]
        return " | ".join(lines[-n:])
    except OSError:
        return ""


def collect(plan, procs, launched, problems):
    """The run contract from what the streams left, with the executor's verdict on the run. Returns (the executor block, the
    stream rows of run.json, the zero of the axis). A run in which no legit stream left an output raises RunFailed:
    there is nothing to judge. Each stream's wall time is held to its records (consistent_wall) before its start is estimated;
    the block says by how much each was raised (`wall_gap_s`), how far the legit starts range (`t0_range_legit_s`) against how
    far the pack's do (`t0_spread_legit_s`), and which streams began outside the pack (`stragglers`). It keeps the exit stamp each
    start was estimated from (`exit_epoch_s`, seconds on the executor's clock, to the millisecond): with the time an engine last
    wrote its summary it says how long the exit took, which the offsets cannot (docs/HG1C_DESIGN.md 26)."""
    found, streams, reasons, gaps, tails = {}, [], list(problems), {}, {}
    for s in plan.streams:
        p = procs.get(s.id)
        if p is None:
            reasons.append(f"stream {s.id} was never launched")
            continue
        if p.poll() is None or not left_output(s):
            said = _tail(f"{s.workdir}/loadgen.stderr")
            reasons.append(f"stream {s.id} left no output (exit {p.poll()})" + (f": {said}" if said else ""))
            continue
        if p.poll() != 0:
            reasons.append(f"stream {s.id} exited with {p.poll()}")
        try:
            with open(s.summary, encoding="utf-8") as fh:
                summary = json.load(fh)
            wall, intended = float(summary["wall_s"]), int(summary["intended"])
        except (OSError, ValueError, KeyError, TypeError):
            reasons.append(f"stream {s.id}: unreadable summary")
            continue
        try:
            last = last_done(s.records)
        except RECORDS_UNREADABLE:
            reasons.append(f"stream {s.id}: unreadable records")
            continue
        checked = consistent_wall(wall, last)
        found[s.id], gaps[s.id] = (p.exit_time, checked, intended), round(checked - wall, 4)
        tails[s.id] = 0.0 if last is None else round(checked - (last + ENGINE_T0_OFFSET_S), 4)      # how long the loop outlived its last request
        streams.append(s)
    if not any(s.kind == "legit" for s in streams):
        raise RunFailed("no legit stream left an output: " + "; ".join(reasons))
    al = alignment(plan, found, tails)
    reasons += al["reasons"]
    block = {"ok": not reasons, "reasons": reasons, "t0_spread_legit_s": al["t0_spread_legit_s"],
             "t0_range_legit_s": al["t0_range_legit_s"], "stragglers": al["stragglers"],
             "attack_start_error_s": al["attack_start_error_s"], "estimator": "exit-minus-consistent-wall",
             "wall_gap_s": {sid: gaps[sid] for sid in sorted(gaps)},
             "exit_epoch_s": {sid: round(found[sid][0], 3) for sid in sorted(found)},
             "zero_epoch_s": None if al["zero"] is None else round(al["zero"], 4),
             "launch_attack_after_s": launch_attack_after(plan) if "attack" in launched else None}
    rows = [{"id": s.id, "kind": s.kind, "route_class": s.route_class, "netem": s.netem,
             "summary": os.path.relpath(s.summary, plan.out), "records": os.path.relpath(s.records, plan.out),
             "offset_s": round(al["offsets"][s.id], 4), "addresses": list(s.addresses)} for s in streams]
    return block, rows, al["zero"]


def finish_logs(plan, zero, log):
    """server_requests.csv from the Nginx access log, then the log compressed: it is large and read once."""
    path = f"{plan.out}/nginx_access.log"
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = fh.read().splitlines()
    rows, bad = aggregate_access_log(lines, zero) if zero is not None else ([], len(lines))
    with open(f"{plan.out}/server_requests.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["T_Rel_s", "Client_Class", "Status", "Requests", "Request_Time_Mean_s", "Request_Time_Max_s"])
        w.writerows([(sec, klass, status, n, f"{mean:.4f}", f"{top:.4f}") for sec, klass, status, n, mean, top in rows])
    with open(path, "rb") as src, gzip.open(path + ".gz", "wb") as dst:
        shutil.copyfileobj(src, dst)
    os.remove(path)
    log(f"nginx access log: {len(lines)} lines ({bad} unparsed), server_requests.csv written, log compressed")


def teardown(host, plan, log):
    """Everything of this run, by namespace; then a look at what is left. LeftoverError if anything is."""
    began = host.monotonic()
    names = [ns.name for ns in plan.namespaces] + [SERVER_NS]
    links = [outer_veth(ns.name) for ns in plan.namespaces] + [SERVER_VETH_HOST_END, BRIDGE]
    destroy(host, names, links, plan.settings["term_grace_s"], log)
    looked = host.monotonic()
    left = leftovers(host, plan.daemon is not None)
    if left:
        raise LeftoverError("still there after the teardown:\n  " + "\n  ".join(left))
    log("teardown complete: no namespace, link or process of the testbed is left "
        f"(leftover check {host.monotonic() - looked:.2f} s; {host.monotonic() - began:.1f} s in all)")


KEEP_ON_RETRY = ("plan.json", "executor.log", "environment.json")


def _reset(out):
    """The run directory as it was after the plan was written: what a failed setup attempt made is removed."""
    for name in os.listdir(out):
        if name not in KEEP_ON_RETRY:
            path = os.path.join(out, name)
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.remove(path)


def _failed(out, exc):
    with open(f"{out}/FAILED", "w", encoding="utf-8") as fh:
        fh.write(f"{type(exc).__name__}: {exc}\n")


def execute(plan, host, gate="full", allow_dirty=False, clean=False, wait_gate_min=30.0, say=None, sampler=None):
    """Carry out `plan`. Returns a RunResult and leaves the run contract in plan.out; ok is false when the executor found the
    run unsound (the gate then calls its block invalid). Raises RunFailed when the run could not be carried out, after the
    teardown; the campaign stops on that. A directory that already holds something is refused: one run, one directory."""
    out = plan.out
    if os.path.isdir(out) and os.listdir(out):
        raise PreflightRefused(f"{out} is not empty: a run directory is made for one run")
    os.makedirs(out, exist_ok=True)
    log = EventLog(f"{out}/executor.log", host, say)
    t_begin = host.monotonic()

    def gate_so_far(timer):                  # on disk through the wait: a stop during it leaves the probes (D-045, T-047 G-01)
        write_json(f"{out}/environment.json", {"gate_unfinished": True, "gate_mode": gate, **timer})

    try:
        pre = preflight(host, plan, allow_dirty, clean)
        env = environment(host, plan, gate, wait_gate_min, log, gate_so_far)
    except RunFailed as exc:
        log(f"refused: {exc}")
        _failed(out, exc)
        if getattr(exc, "record", None):
            write_json(f"{out}/environment.json", {"refused": str(exc), "gate_mode": gate, **exc.record})
        raise
    record = {**env, **pre, "facts": host.facts(), "calibration_sha256": plan.calibration_sha256,
              "scenario_sha256": plan.scenario_sha256, "provenance": provenance(plan, host), "checked_utc": _utc(host.time())}
    write_json(f"{out}/environment.json", record)
    write_json(f"{out}/plan.json", as_json(plan))
    log(f"run {plan.kind} of {plan.scenario}, seed {plan.seed}: preflight and environment passed")
    if plan.daemon is not None and not record["provenance"]["daemon"]["h01"]["has_fix"]:
        log(f"WARNING: this checkout's daemon lacks the H-01 fix ({DAEMON_FIX_H01[:7]}, fix/daemon-robustness): one request with a "
            "byte that is not UTF-8 can end it and lift every ban during the run. Recorded in environment.json (provenance.daemon.h01)")
    procs, sampler, daemon = {}, sampler or Sampler(host), None
    try:
        retries = 0
        while True:
            try:
                procs.clear()
                sampler.daemon_pid = None
                build_topology(host, plan, log, procs)
                start_stack(host, plan, log, procs)
                daemon = start_mitigation(host, plan, log, procs, sampler)
                if plan.daemon is not None:
                    record["provenance"]["daemon"]["feed_before"] = feed_before(plan, host)
                write_json(f"{out}/environment.json", {**record, "stack": stack_facts(host, sampler)})
                break
            except SetupFailed as exc:
                log(f"setup failed: {exc}")
                stop_daemon(host, procs, log)
                stop_all(host, procs, plan, log)
                teardown(host, plan, log)
                retries += 1
                if retries > MAX_SETUP_RETRIES:
                    raise                            # the last attempt's files stay: they say why it failed
                _reset(out)
                log(f"retrying the setup ({retries} of {MAX_SETUP_RETRIES})")
        launched, problems = run_timeline(host, plan, log, procs, sampler)
        if daemon is not None:
            unsound, seen = daemon_validity(host, plan, procs, daemon, sampler, launched.get("legit", host.time()))
            problems += unsound
            daemon.update(seen)
        stopped = stop_daemon(host, procs, log)
        stop_all(host, procs, plan, log)
        block, rows, zero = collect(plan, procs, launched, problems)
        raised = {sid: gap for sid, gap in block["wall_gap_s"].items() if gap > WALL_GAP_NOTE_S}
        if raised:
            log(f"wall time of {len(raised)} stream(s) raised to what their records need, by up to {max(raised.values()):.2f} s: "
                f"the engine was descheduled between reading the schedule's zero and its wall clock")
        if block["stragglers"]:
            log(f"{len(block['stragglers'])} legit stream(s) began outside the pack of the others, by up to "
                f"{max(abs(x['from_pack_s']) for x in block['stragglers']):.2f} s, and are placed by their own offsets: "
                + ", ".join(x["id"] for x in block["stragglers"]))
        sampler.write(f"{out}/server.csv")
        finish_logs(plan, zero, log)
        write_json(f"{out}/run.json", {
            "role": KINDS_OF_RUN[plan.kind], "mode": plan.mode, "started_utc": _utc(launched["legit"]),
            "daemon": None if daemon is None else {**daemon, "stop": stopped},
            "scenario": plan.scenario, "seed": plan.seed, "plan_sha256": plan.plan_sha256,
            "calibration_sha256": plan.calibration_sha256, "overrides": plan.overrides,
            "executor": {**block, "setup_retries": retries}, "streams": rows})
        log("run.json written; the run is " + ("sound" if block["ok"] else "UNSOUND: " + "; ".join(block["reasons"])))
        return RunResult(block["ok"], block["reasons"], out, retries, host.monotonic() - t_begin)
    except BaseException as exc:
        log(f"failed: {exc!r}")
        _failed(out, exc)
        raise
    finally:
        with host.shielded():
            stop_daemon(host, procs, log)
            stop_all(host, procs, plan, log)
            try:
                teardown(host, plan, log)
            except LeftoverError as exc:
                log(f"failed: {exc}")
                _failed(out, exc)
                raise


def smoke_topology(plan, host, say=None, allow_dirty=True, clean=False):
    """S2: build the topology of the plan, verify it, ping the server, take it down. No stack, no streams. Returns the
    seconds the build and the verification took."""
    out = plan.out
    if os.path.isdir(out) and os.listdir(out):
        raise PreflightRefused(f"{out} is not empty")
    os.makedirs(out, exist_ok=True)
    log = EventLog(f"{out}/executor.log", host, say)
    preflight(host, plan, allow_dirty, clean)
    try:
        t = host.monotonic()
        build_topology(host, plan, log, {})
        return host.monotonic() - t
    finally:
        with host.shielded():
            teardown(host, plan, log)


# --- S1: the clocks of the streams, measured on loopback ------------------------------------------

def _rss_mib(host, pid):
    """Resident memory of a process in MiB, 0 if it cannot be read (it has just gone)."""
    try:
        line = next(x for x in host.read_text(f"/proc/{pid}/status").splitlines() if x.startswith("VmRSS:"))
        return int(line.split()[1]) / 1024
    except (OSError, StopIteration, ValueError, IndexError):
        return 0.0


def _first_sent(path):
    """t_sent (seconds after the schedule's zero) of the first request that was sent, from an engine records file."""
    try:
        with gzip.open(path, "rt", encoding="utf-8", newline="") as fh:
            rows = csv.reader(fh)
            col = next(rows).index("t_sent")
            for row in rows:
                value = float(row[col])
                if math.isfinite(value):
                    return value
    except RECORDS_UNREADABLE:
        pass
    return None


def probe_streams(pop, attack):
    """The streams S1 runs: the legit streams of the population and, with `attack`, its attack streams. A population hands out
    tuples; this is a list."""
    return [*pop.of_kind("legit"), *(pop.of_kind("attack") if attack else ())]


def clock_probe(scn, cal, seed, duration, out, host=None, attack=False, say=print):
    """S1 (docs/HG1C_DESIGN.md 10): the legit streams of a scenario at their rates, pinned as in a run, each against its own
    scripted origin on loopback, and the estimator against what each origin saw first. Needs no root and no namespace.
    With `attack`, the attack streams of the scenario too, which have the large request counts the exit delay may depend
    on. Writes clock_probe.json to `out` and returns it: the start-up delay and spread of the streams after their launch,
    when each stream was launched, truly began and exited (seconds after the first launch; the commands are built before it,
    as a run's plan has them), the error of estimate_t0 against the first arrival at the origin as a run makes it (the wall time
    held to the records) and as S1 and S1b had it (the engine's wall time as it is), by how much the wall time was raised,
    memory and CPU per process, and a fit of the error against the number of requests."""
    import asyncio

    import loadtool_validate as V
    host = host or RealHost()
    pop, _ = SC.population_of(scn, cal, seed, attack=attack)
    streams = probe_streams(pop, attack)
    os.makedirs(out, exist_ok=True)
    origins, servers, ready = [], [], threading.Event()
    loop = asyncio.new_event_loop()

    def serve():
        asyncio.set_event_loop(loop)
        try:
            for _ in streams:
                origin = V.ScriptedOrigin(service_ms=1.0, jitter_ms=0.0, clock=time.time)
                servers.append(loop.run_until_complete(origin.start("127.0.0.1", 0)))
                origins.append(origin)
            ready.set()
            loop.run_forever()
        finally:
            for server in servers:
                server.close()
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.close()
            ready.set()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    ready.wait(30)
    jobs = []                         # the commands are built before the first launch, as a run's plan has them
    for s, o in zip(streams, origins, strict=True):
        workdir = os.path.join(out, "streams", s.id)
        spec = dataclasses.replace(P.to_load_spec(s, f"http://127.0.0.1:{o.port}/"), duration=duration,
                                   local_addrs=(), allow_loopback=True)
        jobs.append((s, workdir, list(LT.build_plan("loadgen", spec, workdir).steps[0].argv)))
    procs, launch_t, rss = {}, {}, {}
    try:
        for s, workdir, argv in jobs:
            os.makedirs(workdir, exist_ok=True)
            with open(f"{workdir}/loadgen.stderr", "wb") as err:
                launch_t[s.id] = host.time()
                procs[s.id] = host.popen(argv, stderr=err)
        end = host.time() + duration + DRAIN_S + 30
        while any(p.poll() is None for p in procs.values()) and host.time() < end:
            for sid, p in procs.items():
                if p.poll() is None:
                    rss[sid] = max(rss.get(sid, 0.0), _rss_mib(host, p.pid))
            host.sleep(0.5)
    finally:
        for p in procs.values():
            if p.poll() is None:
                p.kill()
        loop.call_soon_threadsafe(loop.stop)
        thread.join(10)
    rows = []
    first = min(launch_t.values(), default=0.0)          # the probe's own zero: the first launch
    for s, o in zip(streams, origins, strict=True):
        workdir = os.path.join(out, "streams", s.id)
        records = os.path.join(workdir, "loadgen.records.csv.gz")
        sent = _first_sent(records)
        try:
            with open(os.path.join(workdir, "loadgen.summary.json"), encoding="utf-8") as fh:
                summary = json.load(fh)
            last = last_done(records)
        except RECORDS_UNREADABLE:
            continue
        if o.t0 is None or sent is None or procs[s.id].exit_time is None:
            continue
        truth = o.t0 - sent               # the first arrival less the first send: the schedule's zero, to about a millisecond
        wall = consistent_wall(summary["wall_s"], last)
        exit_time = procs[s.id].exit_time
        rows.append({"id": s.id, "kind": s.kind, "rate": s.rate, "intended": summary["intended"],
                     "launch_s": launch_t[s.id] - first, "start_s": truth - first, "exit_s": exit_time - first,
                     "start_after_launch_s": truth - launch_t[s.id],
                     "estimator_minus_truth_s": estimate_t0(exit_time, wall) - truth,
                     "raw_estimator_minus_truth_s": estimate_t0(exit_time, summary["wall_s"]) - truth,
                     "wall_s": summary["wall_s"], "last_done_s": last, "wall_gap_s": wall - summary["wall_s"],
                     "cpu_s": (summary.get("cpu") or {}).get("process_s"), "rss_mib": rss.get(s.id)})
    result = clock_summary(rows, len(streams), duration)
    write_json(os.path.join(out, "clock_probe.json"), result)
    return result


def _spread(values):
    return {"min": min(values, default=None), "median": statistics.median(values) if values else None,
            "max": max(values, default=None), "spread": (max(values) - min(values)) if values else None}


def clock_summary(rows, n_streams, duration):
    """The figures of S1 from its per-stream rows: the start-up after launch, the estimator's bias and its scatter around
    the bias (what matters, since a common bias cancels in the offsets), and its dependence on the request count. Of the
    legit streams, which the run's validity rule compares with one another: when they were launched, when their loops
    truly began, and when the estimator says they did (its spread is what `alignment` measures; times from the first launch),
    and the same without the correction of the wall time. Errors and scatter are the corrected estimator's."""
    errors = [r["estimator_minus_truth_s"] for r in rows]
    bias = statistics.median(errors) if errors else None
    scatter = sorted(abs(e - bias) for e in errors) if errors else []
    legit_rows = [r for r in rows if r["kind"] == "legit"]
    legit = [r["estimator_minus_truth_s"] for r in legit_rows]
    fit = None
    if len(rows) >= 3 and len({r["intended"] for r in rows}) >= 2:
        slope, intercept = statistics.linear_regression([r["intended"] for r in rows], errors)
        fit = {"per_request_s": slope, "base_s": intercept}
    return {"streams": n_streams, "reported": len(rows), "duration_s": duration,
            "start_after_launch_s": _spread([r["start_after_launch_s"] for r in rows]),
            "estimator_bias_s": bias,
            "estimator_error_s": {"p50": LT.quantile(scatter, .5), "p95": LT.quantile(scatter, .95),
                                  "max": scatter[-1] if scatter else None},
            "legit_error_spread_s": (max(legit) - min(legit)) if legit else None,
            "legit_launch_s": _spread([r["launch_s"] for r in legit_rows]),
            "legit_true_start_s": _spread([r["start_s"] for r in legit_rows]),
            "legit_estimated_start_s": _spread([r["start_s"] + r["estimator_minus_truth_s"] for r in legit_rows]),
            "legit_raw_estimated_start_s": _spread([r["start_s"] + r["raw_estimator_minus_truth_s"] for r in legit_rows]),
            "wall_gap_s": _spread([r["wall_gap_s"] for r in rows]),
            "exit_delay_fit": fit,
            "rss_mib": {"max": max((r["rss_mib"] for r in rows if r["rss_mib"]), default=None),
                        "total": sum(r["rss_mib"] or 0 for r in rows) or None},
            "cpu_s_total": sum(r["cpu_s"] or 0 for r in rows), "rows": rows}


# --- the command line -----------------------------------------------------------------------------

def _timeline_arg(text):
    try:
        values = tuple(float(x) for x in text.split(","))
    except ValueError:
        values = ()
    if len(values) != 3 or not all(math.isfinite(v) and v > 0 for v in values):
        raise argparse.ArgumentTypeError("three positive seconds: BASELINE,ATTACK,RECOVERY")
    return values


def _plan_from_args(args):
    scn = SC.load(args.spec)
    cal = C.load(args.calibration)
    with open(args.spec, "rb") as fh:
        scenario_sha = hashlib.sha256(fh.read()).hexdigest()
    seed = scn.first_seed if args.seed is None else args.seed
    out = args.out or f"/var/tmp/ddos_campaigns/example/{args.kind}"
    return plan_run(scn, cal, args.kind, seed, out, args.calibration, scenario_sha, rho=args.rho, timeline=args.timeline,
                    timer_limit_ms=getattr(args, "timer_limit_ms", None))


def _add_plan_args(p, kind_required=True):
    p.add_argument("spec", help="a scenario record (bench/scenarios/*.json)")
    p.add_argument("--calibration", default=C.PLACEHOLDER, help="calibration record (default: the placeholder)")
    p.add_argument("--kind", choices=KINDS + MITIGATED_KINDS + tuple(MITIGATED + m for m in RESERVED_MODES), required=kind_required,
                   default="C", help="C, Cp, U, or a protected run M_<mode> (M_l7shadow and M_l7 are not built yet)")
    p.add_argument("--seed", type=int, default=None, help="the block's seed (default: the scenario's first)")
    p.add_argument("--out", help="the run directory (named after its kind)")
    p.add_argument("--rho", type=float, default=None, help="smoke test: the benign load in requests/s, instead of the calibration's")
    p.add_argument("--timeline", type=_timeline_arg, default=None, metavar="B,A,R",
                   help="smoke test: baseline, attack and recovery seconds, instead of the scenario's")


def _add_timer_limit(p):
    p.add_argument("--timer-limit-ms", type=float, default=None, metavar="MS",
                   help="smoke test: refuse the run if the timer on the legit CPU has p99 of this many ms or more, instead of the "
                        "calibration's validity.timer_p99_ms; recorded as an override, and the harm gate gives no verdict on it")


def _install_signal_handlers():
    """SIGTERM and SIGHUP end the run the way Ctrl-C does, through the `finally` that takes the testbed down."""
    def stop(signum, _frame):
        raise KeyboardInterrupt(f"signal {signum}")
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, stop)


def main(argv=None, host=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="command", required=True)
    p = sub.add_parser("plan", help="print what a run would do (offline, no root, no suite)")
    _add_plan_args(p)
    _add_timer_limit(p)
    p.add_argument("--json", action="store_true", help="print the plan as JSON (the plan.json of a run)")
    p = sub.add_parser("run", help="carry out one run (root; builds and takes down the testbed)")
    _add_plan_args(p)
    _add_timer_limit(p)
    p.add_argument("--allow-dirty", action="store_true", help="run with uncommitted changes; they are recorded")
    p.add_argument("--clean", action="store_true", help="take down the namespaces and links of an earlier testbed first")
    p.add_argument("--gate", choices=("full", "timer"), default="full",
                   help="full: wait for uptime and load as well (a campaign's first run); timer: the timer only")
    p.add_argument("--wait-gate", type=float, default=30.0, metavar="MIN", help="minutes to wait for uptime and load (the full gate) and, from the first probe, for a refused timer probe to pass; "
                   "0: one probe")
    p = sub.add_parser("smoke-topology", help="S2: build and verify the topology of a plan, then take it down (root)")
    _add_plan_args(p, kind_required=False)
    p.add_argument("--allow-dirty", action="store_true")
    p.add_argument("--clean", action="store_true")
    p = sub.add_parser("clock-probe", help="S1: the engine's start-up and the estimator's error, on loopback (no root)")
    _add_plan_args(p, kind_required=False)
    p.add_argument("--duration", type=float, default=30.0, help="seconds each stream runs (default 30)")
    p.add_argument("--attack", action="store_true", help="also the scenario's attack streams, at their rates")
    args = ap.parse_args(argv)
    try:
        if args.command == "plan":
            plan = _plan_from_args(args)
            print(json.dumps(as_json(plan), indent=1, sort_keys=True) if args.json else describe(plan), end="" if not args.json else "\n")
            return EXIT_OK
        if args.command == "clock-probe":
            scn, cal = SC.load(args.spec), C.load(args.calibration)
            seed = scn.first_seed if args.seed is None else args.seed
            out = args.out or "/var/tmp/ddos_campaigns/clock_probe"
            real = host or RealHost()
            real.pin(P.PIN_PLAN["daemon"])
            result = clock_probe(scn, cal, seed, args.duration, out, real, attack=args.attack)
            print(clock_text(result, out))
            return EXIT_OK if result["reported"] else EXIT_FAILED
        plan = _plan_from_args(args)
        real = host or RealHost()
        real.pin(P.executor_cpus(plan.pins))
        _install_signal_handlers()
        if args.command == "smoke-topology":
            seconds = smoke_topology(plan, real, print, args.allow_dirty, args.clean)
            print(f"topology of {plan.scenario} seed {plan.seed}: built and verified in {seconds:.1f} s, taken down, nothing left")
            return EXIT_OK
        result = execute(plan, real, args.gate, args.allow_dirty, args.clean, args.wait_gate, print)
        print(f"run {plan.kind} of {plan.scenario}: " + ("sound" if result.ok else "UNSOUND: " + "; ".join(result.reasons))
              + f" ({result.seconds:.0f} s, {result.setup_retries} setup retries) in {result.out}")
        if plan.overrides:
            print(f"OVERRIDES {plan.overrides}: a smoke test, not a result; the harm gate gives no verdict on it")
        with contextlib.suppress(OSError, ValueError, KeyError):         # the figures are a courtesy: the run is on disk
            print(figures_text(plan, C.load(plan.calibration_path)), end="")
        return EXIT_OK if result.ok else EXIT_UNSOUND
    except RunFailed as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_FAILED
    except (PlanError, SC.ScenarioError, C.RecordError, LT.ToolError, LT.ScopeError, OSError) as exc:
        print(exc, file=sys.stderr)
        return EXIT_USAGE


def figures_text(plan, cal):
    """The figures of a finished run as the harm gate reads them, for the first real records (S3, S4): Q and p95 over the judged links
    in the attack's window, the slip of the legit streams, and Q for each link profile, the judged ones marked. A control that
    counted the mobile links would sit near 89 % (docs/HG1C_DESIGN.md 4.1); this is where that is seen on real data."""
    sys.path.insert(0, os.path.join(REPO, "eval"))
    import harm_gate as H
    t = plan.timeline
    m = H.run_metrics(H.read_run(plan.out), cal, {k: t[k] for k in ("baseline_s", "attack_s", "recovery_s")})

    def num(x, spec):
        return "n/a" if x is None else format(x, spec)
    lo, hi = t["baseline_s"], t["baseline_s"] + t["attack_s"]
    p95, slip = m["p95_s"] and m["p95_s"] * 1000, m["slip_p99_s"] and m["slip_p99_s"] * 1000
    head = (f"figures over {lo:g}-{hi:g} s, the judged links ({', '.join(cal['judged_profiles'])}): Q {num(m['Q'], '.2f')} % of "
            f"{m['requests']} requests, p95 {num(p95, '.0f')} ms, slip p99 {num(slip, '.0f')} ms")
    lines = [head]
    for profile, v in m["by_profile"].items():
        lines.append(f"  {profile:<11} {'judged' if v['judged'] else 'not judged':<10} {v['n']:>6} requests, Q {num(v['Q'], '.1f')} %")
    return "\n".join(lines) + "\n"


def clock_text(result, out):
    """The probe's result for the terminal."""
    start, err = result["start_after_launch_s"], result["estimator_error_s"]

    def f(x, spec=".3f"):
        return "-" if x is None else format(x, spec)
    lines = [f"clock probe: {result['reported']} of {result['streams']} streams gave a reference ({result['duration_s']:g} s each)",
             f"  start after launch (s)  min {f(start['min'])}  median {f(start['median'])}  max {f(start['max'])}  spread {f(start['spread'])}",
             (f"  estimator bias {f(result['estimator_bias_s'])} s (common to all streams: cancels); scatter around it p50 "
              f"{f(err['p50'])}  p95 {f(err['p95'])}  max {f(err['max'])} s; legit streams' spread "
              f"{f(result['legit_error_spread_s'])} s")]
    launch, true, seen = result["legit_launch_s"], result["legit_true_start_s"], result["legit_estimated_start_s"]
    lines.append(f"  legit streams: launched over {f(launch['spread'])} s; loops began over {f(true['spread'])} s (min {f(true['min'])}, "
                 f"median {f(true['median'])}, max {f(true['max'])} after the first launch); the estimator puts them over "
                 f"{f(seen['spread'])} s ({f(result['legit_raw_estimated_start_s']['spread'])} s without the wall-time correction), "
                 f"which a run holds to {SETTINGS['t0_spread_limit_s']:g} s")
    gap = result["wall_gap_s"]
    lines.append(f"  wall time raised to what the records need: median {f(gap['median'])} s, max {f(gap['max'])} s "
                 f"(a process descheduled between the engine's two clock readings)")
    fit = result["exit_delay_fit"]
    if fit:
        lines.append(f"  error against requests: {fit['per_request_s'] * 1e6:.1f} us per request, {f(fit['base_s'])} s base")
    lines.append(f"  memory per process, largest {f(result['rss_mib']['max'], '.0f')} MiB, total {f(result['rss_mib']['total'], '.0f')} MiB; "
                 f"CPU of all {result['cpu_s_total']:.1f} s; written to {out}/clock_probe.json")
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
