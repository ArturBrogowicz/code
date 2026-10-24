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

The suite (test_distributed_suite.py) is used the way ml/capture_l7.py uses it: only its testbed primitives, imported
lazily after the checks (docs/HG1C_DESIGN.md 5). Everything the benchmark adds is here: the aliases, the stack, the
streams, the timeline, the telemetry, the cleanup and the leftovers. Nothing here kills a process by pattern.
"""
import argparse
import dataclasses
import hashlib
import json
import os
import re
import sys

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
NGINX_CONF = os.path.join(REPO, "nginx_unprotected.conf")
CERT, KEY = "/etc/ssl/certs/nginx-selfsigned.crt", "/etc/ssl/private/nginx-selfsigned.key"
GUNICORN = {"workers": 2, "threads": 8, "bind": "127.0.0.1:8080", "app": "origin:app"}
ORIGIN_SEED = 1
KINDS_OF_RUN = {"C": "control", "Cp": "placebo", "U": "attack"}
READY_PATH = O.SAMPLE_URLS["C0"]          # the origin has no route at "/": it answers 404 there
# proposals, frozen after S1 and S4 (docs/HG1C_DESIGN.md 6.6, 10) and recorded in every plan
SETTINGS = {"startup_delay_legit_s": 1.8, "startup_delay_attack_s": 0.3, "readiness_timeout_s": 30.0,
            "warmup_requests": 2, "t0_spread_limit_s": 0.5, "attack_start_limit_s": 0.5, "term_grace_s": 2.0,
            "min_nofile": 16384}


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
    when: str = ""                   # "" or "absent:<path>": only if that path does not exist
    keep: bool = False               # keep the process (gunicorn); every other command runs to completion
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


def render_nginx_conf(text, access_log, error_log):
    """`nginx_unprotected.conf` with only its two log paths changed: the stack of every earlier campaign, and a log
    that belongs to this run. A file that does not have exactly these two lines is refused, not guessed at."""
    for pattern, what in ((ACCESS_LOG, "access_log"), (ERROR_LOG, "error_log")):
        if len(pattern.findall(text)) != 1:
            raise PlanError(f"nginx configuration: expected exactly one {what} line of the host's default path")
    text = ACCESS_LOG.sub(lambda m: f"{m.group(1)}access_log {access_log} json_ml_format;", text)
    return ERROR_LOG.sub(lambda m: f"{m.group(1)}error_log {error_log} info;", text)


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


def stack_steps(out, calibration_path, python, pins, conf_sha256, bench=None):
    """The server stack in `server_ns`: the origin under gunicorn, then Nginx on the rendered configuration."""
    bench = bench or HERE
    pin = ("taskset", "-c", pins["server"])
    env = (("ORIGIN_CALIBRATION", calibration_path), ("ORIGIN_SEED", str(ORIGIN_SEED)))
    return (
        Mkdir((out, f"{out}/streams"), "the run directory"),
        Write(f"{out}/nginx.conf", conf_sha256, "nginx_unprotected.conf with its two log paths changed"),
        Cmd(("mkdir", "-p", "/var/log/nginx"), purpose="Nginx opens its compiled-in log path at start-up"),
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
        Cmd((*pin, "nginx", "-c", f"{out}/nginx.conf"), SERVER_NS, purpose="Nginx daemonises; it is found again by namespace"),
    )


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

def _legit_hash(streams):
    rows = [{"id": s.id, "route": s.route_class, "netem": s.netem, "process": s.process, "rate": s.rate,
             "period": s.period, "duty": s.duty, "seed": s.seed, "ns": s.ns_index, "addresses": list(s.addresses),
             "paths": list(s.paths), "start": s.start_s, "duration": s.duration_s}
            for s in sorted(streams, key=lambda s: s.id)]
    return _sha(json.dumps(rows, sort_keys=True, separators=(",", ":")))


def plan_run(scn, cal, kind, seed, out, calibration_path, scenario_sha256="", manifest=None, root=None, settings=None,
             python=None):
    """Everything a run will do, as data. `scn` is a bench/scenario.Scenario, `cal` a calibration record read from
    `calibration_path`, `kind` one of C, Cp and U, `out` the run's directory."""
    if kind not in KINDS:
        raise PlanError(f"kind: one of {', '.join(KINDS)}, got {kind!r}")
    if kind == "U" and scn.is_control:
        raise PlanError(f"{scn.id} is attack-free: it has no attack run")
    try:
        pop, level = SC.population_of(scn, cal, seed, attack=kind == "U")
    except SC.ScenarioError as exc:
        raise PlanError(str(exc)) from exc
    out = os.path.abspath(out) if not os.path.isabs(out) else out
    python = python or os.path.join(REPO, "venv", "bin", "python")
    pins = P.PIN_PLAN
    aliases = pop.alias_plan()
    namespaces = tuple(Namespace(ns_name(spec), spec.index, spec.netem, tuple(aliases[spec.index]))
                       for spec in pop.namespaces if spec.index in aliases)
    by_index = {ns.index: ns for ns in namespaces}
    with open(NGINX_CONF, encoding="utf-8") as fh:
        conf = render_nginx_conf(fh.read(), f"{out}/nginx_access.log", f"{out}/nginx_error.log")
    conf_sha256 = _sha(conf)
    streams = []
    for s in pop.streams:
        spec = P.to_load_spec(s, HTTP_URL)
        workdir = f"{out}/streams/{s.id}"
        launch = LT.build_plan("loadgen", spec, workdir, manifest, root)
        nofile = P.nofile_for(s, spec)
        streams.append(StreamLaunch(
            s.id, s.kind, s.route_class, s.netem, by_index[s.ns_index].name, s.start_s, s.duration_s, s.rate, s.seed,
            nofile, workdir, f"{workdir}/loadgen.summary.json", f"{workdir}/loadgen.records.csv.gz",
            ("prlimit", f"--nofile={nofile}", "--", *launch.steps[0].argv)))
    return RunPlan(
        scenario=scn.id, kind=kind, seed=seed, out=out, scenario_sha256=scenario_sha256,
        calibration_sha256=cal.get("sha256") or C.digest(cal), calibration_status=cal["status"],
        calibration_path=os.path.abspath(calibration_path),
        timeline=dataclasses.asdict(scn.timeline) | {"total_s": scn.timeline.total_s}, level=level,
        namespaces=namespaces, topology=topology_steps(namespaces),
        stack=stack_steps(out, os.path.abspath(calibration_path), python, pins, conf_sha256), checks=check_paths(),
        streams=tuple(streams), teardown=teardown_steps(namespaces), nginx_conf=conf, nginx_conf_sha256=conf_sha256,
        plan_sha256=_legit_hash(pop.of_kind("legit")), settings={**SETTINGS, **(settings or {})})


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
    keep = "keep " if x.keep else ""
    body = " ".join(_shown(a, python) for a in x.argv)
    stdin = f"  < {len(x.stdin.splitlines())} lines" if x.stdin else ""
    return f"{i:>3}. {keep}cmd   {where}{when}{env + ' ' if env else ''}{body}{stdin}    # {x.purpose}"


def launch_attack_after(plan):
    """Seconds after the launch of the legit streams at which the attack streams are launched, so that their loops start
    at the end of the baseline: the baseline plus the legit start-up delay less the attack's."""
    s = plan.settings
    return plan.timeline["baseline_s"] + s["startup_delay_legit_s"] - s["startup_delay_attack_s"]


def describe(plan, python=None):
    """The plan as text for `--plan`."""
    python = python or sys.executable
    t = plan.timeline
    attack = [s for s in plan.streams if s.kind == "attack"]
    legit = [s for s in plan.streams if s.kind == "legit"]
    banner = ("PLACEHOLDER: illustrative numbers, not measurements; nothing below is a result"
              if plan.calibration_status != "frozen" else "frozen")
    out = [f"== run {plan.kind} ({KINDS_OF_RUN[plan.kind]}) of {plan.scenario}, seed {plan.seed} ==",
           f"calibration   sha256:{plan.calibration_sha256[:8]} {banner}",
           f"scenario      sha256:{plan.scenario_sha256[:8] or '-'}"
           + (f", attack level {plan.level:g} x S" if plan.level is not None else ", no attack in this run"),
           f"run directory {plan.out}",
           f"timeline      the {len(legit)} legit streams are launched at L; their loops start about "
           f"{plan.settings['startup_delay_legit_s']:g} s later, which is T = 0, and run {t['total_s']:g} s"
           + (f"; the {len(attack)} attack streams are launched at L + {launch_attack_after(plan):g} s to start at "
              f"T = {t['baseline_s']:g} s and run {t['attack_s']:g} s" if attack else ""),
           f"plan hash     {plan.plan_sha256[:12]} (the legit streams: equal in C, Cp and U of a block)",
           f"nginx.conf    sha256:{plan.nginx_conf_sha256[:12]} (nginx_unprotected.conf with its two log paths changed)",
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


# --- the command line --------------------------------------------------------------------------

def _plan_from_args(args):
    scn = SC.load(args.spec)
    cal = C.load(args.calibration)
    with open(args.spec, "rb") as fh:
        scenario_sha = hashlib.sha256(fh.read()).hexdigest()
    seed = scn.first_seed if args.seed is None else args.seed
    out = args.out or f"/var/tmp/ddos_campaigns/example/{args.kind}"
    return plan_run(scn, cal, args.kind, seed, out, args.calibration, scenario_sha)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="command", required=True)
    p = sub.add_parser("plan", help="print what a run would do (offline, no root, no suite)")
    p.add_argument("spec", help="a scenario record (bench/scenarios/*.json)")
    p.add_argument("--calibration", default=C.PLACEHOLDER, help="calibration record (default: the placeholder)")
    p.add_argument("--kind", choices=KINDS, required=True)
    p.add_argument("--seed", type=int, default=None, help="the block's seed (default: the scenario's first)")
    p.add_argument("--out", help="the run directory it would write")
    p.add_argument("--json", action="store_true", help="print the plan as JSON (the plan.json of a run)")
    args = ap.parse_args(argv)
    try:
        plan = _plan_from_args(args)
    except (PlanError, SC.ScenarioError, C.RecordError, LT.ToolError, OSError) as exc:
        print(exc, file=sys.stderr)
        return 1
    print(json.dumps(as_json(plan), indent=1, sort_keys=True) if args.json else describe(plan), end="" if not args.json else "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
