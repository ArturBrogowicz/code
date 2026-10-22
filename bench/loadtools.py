#!/usr/bin/env python3
"""Wrapper for the HTTP load generators of the harm benchmark (docs/BENCHMARK_HARM_DESIGN.md, 8.4).

One place that knows how to run vegeta, k6 and the closed-loop wrk and how to read what they
report, so that every run goes through the same checks:

  * scope lock: the target must be an IP literal inside the testbed net 10.0.0.0/16 (loopback
    only on request, for the verification). Hostnames are refused, so no DNS lookup can send a
    run elsewhere, and no tool follows redirects, which could leave the net;
  * manifest (bench/loadtools.json): every tool is a pinned binary with its sha256. A binary
    that is missing or has changed is refused, and so is a tool whose status is not "verified"
    (--allow-unverified is for the verification harness itself);
  * k6 is always started with --no-usage-report (it reports anonymous usage otherwise), and no
    proxy variable reaches a tool (Go's default transport, which vegeta and k6 use, honours
    them, and a proxy would carry the run out of the net);
  * every run leaves provenance.json: the exact commands, the versions and hashes, the CPU time
    of the children and the commit of this repository.

The tools sit outside the repository (LOADTOOLS_DIR, default ~/loadtools). wrk2 is in the
manifest as unavailable: it builds here but panics in Lua when a run starts.

    ./venv/bin/python bench/loadtools.py list [--no-hash]
    ./venv/bin/python bench/loadtools.py plan TOOL --url http://10.0.0.1/ --rate 100 --duration 10
    ./venv/bin/python bench/loadtools.py parse TOOL DIR
    ./venv/bin/python bench/loadtools.py run TOOL --url ... --rate ... --duration ... --out DIR

list, plan and parse send nothing. `run` generates load; the unit tests never call it.
"""
import argparse
import csv
import dataclasses
import datetime
import hashlib
import ipaddress
import json
import os
import platform
import re
import resource
import subprocess
import sys
import time
import urllib.parse

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = os.path.join(REPO, "bench", "loadtools.json")
TESTBED_NET = ipaddress.ip_network("10.0.0.0/16")             # as in ml/l7_gen.py
LOOPBACK_NETS = (ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128"))
STATUSES = ("unavailable", "installed", "smoke-tested", "verified", "unfit")
RUNNABLE = ("verified",)                  # statuses a benchmark run accepts
VERSION_ARGS = {"vegeta": ["-version"], "k6": ["version"], "wrk": ["--version"],
                "loadgen": ["--version"]}
PROXY_VARS = ("http_proxy", "https_proxy", "all_proxy", "no_proxy")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ScopeError(ValueError):
    """The target or the source address is outside the testbed."""


class ToolError(RuntimeError):
    """A tool is missing, changed, unavailable, not verified, or printed something unreadable."""


# --- scope lock ---------------------------------------------------------------------------

def check_address(text, allow_loopback):
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        raise ScopeError(f"{text!r} is not an IP literal (hostnames are refused: no DNS)") from None
    nets = (TESTBED_NET,) + (LOOPBACK_NETS if allow_loopback else ())
    if not any(net.version == ip.version and ip in net for net in nets):
        raise ScopeError(f"{ip} is outside the testbed net {TESTBED_NET}"
                         + (" and loopback" if allow_loopback else ""))
    return str(ip)


def check_scope(url, allow_loopback=False):
    """(host, port) of an http(s) URL that points inside the testbed; ScopeError otherwise."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ScopeError(f"{url!r}: only http and https targets")
    if parts.username is not None or parts.password is not None:
        raise ScopeError(f"{url!r}: credentials in the URL")
    if not parts.hostname:
        raise ScopeError(f"{url!r}: no host")
    host = check_address(parts.hostname, allow_loopback)
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        raise ScopeError(f"{url!r}: bad port") from None
    return host, port


# --- what to run --------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class LoadSpec:
    url: str
    rate: float                       # requests/s; the closed-loop wrk ignores it
    duration: float                   # seconds
    method: str = "GET"
    headers: tuple = ()               # ("Name: value", ...)
    timeout: float = 10.0             # per request, seconds
    connections: int = 100            # wrk -c; vegeta -connections (idle pool)
    workers: int = 50                 # vegeta -workers; k6 preAllocatedVUs
    max_workers: int = 5000           # vegeta -max-workers; k6 maxVUs
    threads: int = 2                  # wrk -t
    local_addr: str = ""              # source address: vegeta -laddr, k6 --local-ips
    cpus: str = ""                    # taskset list, e.g. "4-7"
    allow_loopback: bool = False
    name: str = "load"                # run label


def validate(spec):
    """Check a spec before anything is built; ScopeError or ValueError."""
    check_scope(spec.url, spec.allow_loopback)
    if spec.local_addr:
        check_address(spec.local_addr, spec.allow_loopback)
    if not spec.rate > 0:
        raise ValueError(f"rate must be positive, got {spec.rate}")
    if not spec.duration >= 1:
        raise ValueError(f"duration must be at least 1 s, got {spec.duration}")
    if not spec.timeout > 0:
        raise ValueError(f"timeout must be positive, got {spec.timeout}")
    if spec.method not in ("GET", "HEAD"):
        raise ValueError(f"method {spec.method!r}: only GET and HEAD")
    if min(spec.connections, spec.workers, spec.threads) < 1 or spec.max_workers < spec.workers:
        raise ValueError("connections, workers and threads must be at least 1, and "
                         "max_workers at least workers")
    for h in spec.headers:
        if ":" not in h or "\n" in h or "\r" in h:
            raise ValueError(f"header {h!r}: expected 'Name: value' on one line")
    if spec.cpus and not re.fullmatch(r"[0-9]+([,-][0-9]+)*", spec.cpus):
        raise ValueError(f"cpus {spec.cpus!r}: expected a taskset list such as 4-7")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", spec.name):
        raise ValueError(f"name {spec.name!r}: letters, digits, '_', '.' and '-' only")


def rate_parts(rate):
    """(count, seconds) of whole numbers with count / seconds ~ rate: 100 -> (100, 1), 12.5 -> (25, 2)."""
    if float(rate).is_integer():
        return int(rate), 1
    for secs in (2, 4, 5, 10, 20, 50, 100):
        n = round(rate * secs)
        if n >= 1 and abs(n / secs - rate) <= 0.005 * rate:
            return n, secs
    return max(1, round(rate * 100)), 100


def _secs(x):
    return f"{x:g}s"


@dataclasses.dataclass
class Step:
    label: str
    argv: list
    env: dict = dataclasses.field(default_factory=dict)       # added to the environment
    stdout: str = ""                                          # file receiving stdout, "" = discard
    stderr: str = ""
    timeout: float = 0.0


@dataclasses.dataclass
class Plan:
    tool: str
    spec: LoadSpec
    workdir: str
    steps: list
    files: dict                       # logical name -> path of an output the parsers read
    inputs: dict = dataclasses.field(default_factory=dict)    # path -> text written before the run
    tool_info: dict = dataclasses.field(default_factory=dict)


# The k6 script is a constant: parameters arrive through -e, so a run is described by its
# command line alone. It imports nothing from the network. handleSummary writes the few numbers
# the wrapper needs in a layout of its own, plus the raw summary object for debugging, because
# the layout of k6's summary differs between versions ("values" nested or flat).
K6_SCRIPT = """\
import http from 'k6/http';
import { Counter } from 'k6/metrics';

const status = {
  '2xx': new Counter('status_2xx'),
  '3xx': new Counter('status_3xx'),
  '4xx': new Counter('status_4xx'),
  '5xx': new Counter('status_5xx'),
  other: new Counter('status_other'),
};

export const options = {
  discardResponseBodies: true,
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(50)', 'p(90)', 'p(95)', 'p(99)', 'p(99.9)'],
  scenarios: {
    load: {
      executor: 'constant-arrival-rate',
      rate: Number(__ENV.RATE),
      timeUnit: __ENV.TIME_UNIT,
      duration: __ENV.DURATION,
      preAllocatedVUs: Number(__ENV.PRE_VUS),
      maxVUs: Number(__ENV.MAX_VUS),
    },
  },
};

export default function () {
  const res = http.request(__ENV.METHOD, __ENV.URL, null, {
    headers: JSON.parse(__ENV.HEADERS),
    timeout: __ENV.TIMEOUT,
    redirects: 0,
  });
  const s = res.status;
  let k = 'other';
  if (s >= 200 && s < 300) k = '2xx';
  else if (s >= 300 && s < 400) k = '3xx';
  else if (s >= 400 && s < 500) k = '4xx';
  else if (s >= 500 && s < 600) k = '5xx';
  status[k].add(1);
}

function stat(data, name, key) {
  const m = data.metrics[name];
  if (!m) return null;
  const v = m.values || m;
  return v[key] === undefined ? null : v[key];
}

export function handleSummary(data) {
  const out = {
    schema: 1,
    duration_ms: data.state ? data.state.testRunDurationMs : null,
    requests: stat(data, 'http_reqs', 'count'),
    iterations: stat(data, 'iterations', 'count'),
    dropped_iterations: stat(data, 'dropped_iterations', 'count') || 0,
    status: {},
    latency_ms: {},
  };
  for (const k of Object.keys(status)) out.status[k] = stat(data, 'status_' + k, 'count') || 0;
  const keys = { avg: 'avg', min: 'min', p50: 'p(50)', p90: 'p(90)', p95: 'p(95)',
                 p99: 'p(99)', p999: 'p(99.9)', max: 'max' };
  for (const k of Object.keys(keys)) out.latency_ms[k] = stat(data, 'http_req_duration', keys[k]);
  return {
    [__ENV.OUT]: JSON.stringify(out),
    [__ENV.OUT + '.raw']: JSON.stringify(data),
  };
}
"""


# --- manifest -----------------------------------------------------------------------------

def validate_manifest(m):
    if m.get("schema") != 1 or not isinstance(m.get("tools"), dict):
        raise ToolError("manifest: schema 1 with a 'tools' table expected")
    for name, t in m["tools"].items():
        if t.get("kind") not in ("external", "system", "builtin"):
            raise ToolError(f"manifest: {name}: kind must be external, system or builtin")
        if t.get("status") not in STATUSES:
            raise ToolError(f"manifest: {name}: status must be one of {STATUSES}")
        if not (isinstance(t.get("version"), str) and isinstance(t.get("path"), str)):
            raise ToolError(f"manifest: {name}: version and path are required")
        if not SHA256.match(str(t.get("sha256", ""))):
            raise ToolError(f"manifest: {name}: sha256 must be 64 hex digits")
        if t["status"] in ("unavailable", "unfit") and not t.get("reason"):
            raise ToolError(f"manifest: {name}: status {t['status']} needs a reason")
    return m


def load_manifest(path=MANIFEST):
    with open(path) as f:
        return validate_manifest(json.load(f))


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tools_root(m, root=None):
    return os.path.expanduser(root or os.environ.get("LOADTOOLS_DIR") or m.get("root", "~/loadtools"))


def tool_file(m, name, root=None):
    t = m["tools"].get(name)
    if t is None:
        raise ToolError(f"unknown tool {name!r} (known: {', '.join(m['tools'])})")
    if t["kind"] == "builtin":                                # a file of this repository
        return os.path.join(REPO, t["path"])
    return t["path"] if os.path.isabs(t["path"]) else os.path.join(tools_root(m, root), t["path"])


def resolve_tool(m, name, root=None, allow_unverified=False, check=True):
    """Path of tool `name` after the manifest checks; ToolError when it must not be run."""
    path = tool_file(m, name, root)
    t = m["tools"][name]
    if t["status"] in ("unavailable", "unfit"):
        raise ToolError(f"{name} is {t['status']}: {t['reason']}")
    if t["status"] not in RUNNABLE and not allow_unverified:
        raise ToolError(f"{name} has status {t['status']!r}, not 'verified' "
                        "(--allow-unverified is for the verification only)")
    if check:
        if not (os.path.isfile(path) and (os.access(path, os.X_OK) or t["kind"] == "builtin")):
            raise ToolError(f"{name}: {path} is missing or not executable")
        got = sha256_file(path)
        if got != t["sha256"]:
            raise ToolError(f"{name}: sha256 {got[:12]}... differs from the manifest "
                            f"{t['sha256'][:12]}...; the binary changed")
    return path


def probe_version(m, name, root=None):
    """Run the tool's version command; (output, matches the pinned version)."""
    path = resolve_tool(m, name, root, allow_unverified=True)
    argv = [path] + VERSION_ARGS[name]
    if m["tools"][name]["kind"] == "builtin":
        argv = [sys.executable] + argv
    cp = subprocess.run(argv, capture_output=True, text=True, timeout=15, check=False)
    out = (cp.stdout + cp.stderr).strip()
    return out, m["tools"][name]["version"] in out


# --- command builders ---------------------------------------------------------------------

def _pin(spec):
    return ["taskset", "-c", spec.cpus] if spec.cpus else []


def _plan_vegeta(exe, spec, wd):
    n, secs = rate_parts(spec.rate)
    f = {k: os.path.join(wd, v) for k, v in
         {"targets": "vegeta.targets", "bin": "vegeta.bin", "report": "vegeta.report.json",
          "csv": "vegeta.csv"}.items()}
    attack = _pin(spec) + [
        exe, "attack", f"-rate={n}/{secs}s", f"-duration={_secs(spec.duration)}",
        f"-timeout={_secs(spec.timeout)}", f"-workers={spec.workers}",
        f"-max-workers={spec.max_workers}", f"-connections={spec.connections}",
        "-keepalive=true", "-http2=false", "-redirects=-1", "-max-body=0",
        f"-name={spec.name}", f"-targets={f['targets']}", f"-output={f['bin']}"]
    attack += [f"-header={h}" for h in spec.headers]
    if spec.local_addr:
        attack.append(f"-laddr={spec.local_addr}")
    steps = [
        Step("attack", attack, stderr=os.path.join(wd, "vegeta.stderr"),
             timeout=spec.duration + spec.timeout + 30),
        Step("report", [exe, "report", "-type=json", f"-output={f['report']}", f["bin"]],
             timeout=300),
        Step("encode", [exe, "encode", "-to=csv", f"-output={f['csv']}", f["bin"]], timeout=300),
    ]
    return steps, f, {f["targets"]: f"{spec.method} {spec.url}\n"}


def _plan_k6(exe, spec, wd):
    n, secs = rate_parts(spec.rate)
    f = {"script": os.path.join(wd, "k6.js"), "summary": os.path.join(wd, "k6.summary.json"),
         "stdout": os.path.join(wd, "k6.stdout"), "stderr": os.path.join(wd, "k6.stderr")}
    headers = json.dumps({h.split(":", 1)[0].strip(): h.split(":", 1)[1].strip()
                          for h in spec.headers}, separators=(",", ":"), sort_keys=True)
    env_args = {"URL": spec.url, "METHOD": spec.method, "HEADERS": headers, "RATE": str(n),
                "TIME_UNIT": _secs(secs), "DURATION": _secs(spec.duration),
                "TIMEOUT": _secs(spec.timeout), "PRE_VUS": str(spec.workers),
                "MAX_VUS": str(spec.max_workers), "OUT": f["summary"]}
    argv = _pin(spec) + [exe, "run", "--quiet", "--no-usage-report", "--no-color",
                         "--no-thresholds"]
    for k, v in env_args.items():
        argv += ["-e", f"{k}={v}"]
    if spec.local_addr:
        argv.append(f"--local-ips={spec.local_addr}")
    argv.append(f["script"])
    step = Step("run", argv, env={"K6_NO_USAGE_REPORT": "true"}, stdout=f["stdout"],
                stderr=f["stderr"], timeout=spec.duration + spec.timeout + 60)
    return [step], f, {f["script"]: K6_SCRIPT}


def _plan_wrk(exe, spec, wd):
    if spec.method != "GET" or spec.local_addr:
        raise ToolError("wrk: GET only and no source-address option")
    f = {"stdout": os.path.join(wd, "wrk.out")}
    argv = _pin(spec) + [exe, f"-t{spec.threads}", f"-c{spec.connections}",
                         f"-d{max(1, round(spec.duration))}s", "--timeout", _secs(spec.timeout),
                         "--latency"]
    for h in spec.headers:
        argv += ["-H", h]
    argv.append(spec.url)
    return ([Step("run", argv, stdout=f["stdout"], stderr=os.path.join(wd, "wrk.stderr"),
                  timeout=spec.duration + spec.timeout + 30)], f, {})


def _plan_loadgen(exe, spec, wd):
    f = {"summary": os.path.join(wd, "loadgen.summary.json"),
         "records": os.path.join(wd, "loadgen.records.csv.gz")}
    argv = _pin(spec) + [sys.executable, exe, "--url", spec.url, "--rate", f"{spec.rate:g}",
                         "--duration", f"{spec.duration:g}", "--timeout", f"{spec.timeout:g}",
                         "--max-inflight", str(spec.max_workers), "--pool", str(spec.connections),
                         "--method", spec.method, "--summary", f["summary"],
                         "--records", f["records"]]
    for h in spec.headers:
        argv += ["--header", h]
    if spec.local_addr:
        argv += ["--local-addr", spec.local_addr]
    if spec.allow_loopback:
        argv.append("--allow-loopback")
    return ([Step("run", argv, stderr=os.path.join(wd, "loadgen.stderr"),
                  timeout=spec.duration + spec.timeout + 60)], f, {})


BUILDERS = {"vegeta": _plan_vegeta, "k6": _plan_k6, "wrk": _plan_wrk, "loadgen": _plan_loadgen}


def build_plan(tool, spec, workdir, manifest=None, root=None, allow_unverified=False,
               check=True):
    """The commands that run `spec` with `tool`, without running anything."""
    validate(spec)
    m = manifest or load_manifest()
    if tool not in BUILDERS:
        raise ToolError(f"no command builder for {tool!r} (have: {', '.join(BUILDERS)})")
    exe = resolve_tool(m, tool, root, allow_unverified, check)
    steps, files, inputs = BUILDERS[tool](exe, spec, os.path.abspath(workdir))
    info = {k: v for k, v in m["tools"][tool].items() if k in ("version", "sha256", "status")}
    info["path"] = exe
    return Plan(tool, spec, os.path.abspath(workdir), steps, files, inputs, info)


# --- running ------------------------------------------------------------------------------

def _utc_now():
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _git(*args):
    try:
        cp = subprocess.run(["git", "-C", REPO, *args], capture_output=True, text=True,
                            timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return cp.stdout.strip() if cp.returncode == 0 else None


def clean_env(environ=None):
    """The environment the tools get: the caller's without proxy variables, and NO_PROXY=*."""
    env = {k: v for k, v in (os.environ if environ is None else environ).items()
           if k.lower() not in PROXY_VARS}
    env.update({"NO_PROXY": "*", "no_proxy": "*"})
    return env


def run_plan(plan, runner=subprocess.run):
    """Write the inputs, run the steps in order (stop at the first failure), write
    provenance.json and return it. `runner` is subprocess.run, replaceable in tests."""
    os.makedirs(plan.workdir, exist_ok=True)
    base_env = clean_env()
    for path, text in plan.inputs.items():
        with open(path, "w") as f:
            f.write(text)
    prov = {"schema": 1, "tool": plan.tool, "tool_info": plan.tool_info,
            "proxy_vars_removed": sorted(k for k in os.environ if k.lower() in PROXY_VARS),
            "spec": dataclasses.asdict(plan.spec), "started_utc": _utc_now(), "steps": [],
            "script_sha256": (hashlib.sha256(K6_SCRIPT.encode()).hexdigest()
                              if plan.tool == "k6" else None),
            "manifest_sha256": sha256_file(MANIFEST) if os.path.exists(MANIFEST) else None}
    cpu0 = resource.getrusage(resource.RUSAGE_CHILDREN)
    for step in plan.steps:
        t0 = time.monotonic()
        step_cpu0 = resource.getrusage(resource.RUSAGE_CHILDREN)
        rc = None
        with open(step.stdout or os.devnull, "wb") as so, open(step.stderr or os.devnull, "wb") as se:
            try:
                rc = runner(step.argv, env={**base_env, **step.env}, stdout=so, stderr=se,
                            timeout=step.timeout or None, check=False).returncode
            except subprocess.TimeoutExpired:
                rc = "timeout"
        step_cpu1 = resource.getrusage(resource.RUSAGE_CHILDREN)
        prov["steps"].append({"label": step.label, "argv": step.argv, "env": step.env,
                              "returncode": rc, "seconds": round(time.monotonic() - t0, 3),
                              "cpu_s": {"user": round(step_cpu1.ru_utime - step_cpu0.ru_utime, 3),
                                        "system": round(step_cpu1.ru_stime - step_cpu0.ru_stime, 3)}})
        if rc != 0:
            break
    cpu1 = resource.getrusage(resource.RUSAGE_CHILDREN)
    prov["ok"] = len(prov["steps"]) == len(plan.steps) and all(s["returncode"] == 0
                                                               for s in prov["steps"])
    prov["children_cpu_s"] = {"user": round(cpu1.ru_utime - cpu0.ru_utime, 3),
                              "system": round(cpu1.ru_stime - cpu0.ru_stime, 3)}
    dirty = _git("status", "--porcelain", "--untracked-files=no")
    prov["git"] = {"commit": _git("rev-parse", "HEAD"), "dirty": None if dirty is None else bool(dirty)}
    prov["host"] = {"uname": " ".join(platform.uname()), "cpus": os.cpu_count(),
                    "python": sys.version.split()[0]}
    prov["finished_utc"] = _utc_now()
    path = os.path.join(plan.workdir, "provenance.json")
    with open(path + ".tmp", "w") as f:
        json.dump(prov, f, indent=1)
        f.write("\n")
    os.replace(path + ".tmp", path)
    return prov


# --- reading what the tools report ---------------------------------------------------------

@dataclasses.dataclass
class ToolResult:
    tool: str
    requests: int                     # requests the tool says it issued
    responses: int                    # of which got an HTTP status
    ok2xx: int
    non2xx: int
    errors: int                       # no status: timeouts, refused or reset connections
    status: dict                      # vegeta: {"200": n}; k6 and wrk: {"2xx": n, ...} or less
    latency: dict                     # seconds: mean, min, p50, p90, p95, p99, max; None if absent
    quantiles: str                    # where the percentiles come from
    duration: float                   # seconds the tool says the test lasted
    dropped: int = 0                  # sends the tool itself reports as dropped (k6)
    extra: dict = dataclasses.field(default_factory=dict)

    def to_dict(self):
        return dataclasses.asdict(self)


def quantile(sorted_values, q):
    """Linear-interpolation quantile of a sorted list (numpy's default)."""
    if not sorted_values:
        return None
    pos = q * (len(sorted_values) - 1)
    lo = int(pos)
    hi = min(lo + 1, len(sorted_values) - 1)
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (pos - lo)


def _exact_latency(csv_path):
    """Latencies (s) of every row of a `vegeta encode -to=csv` file, plus those of 2xx rows,
    and the request timestamps (ns)."""
    allv, okv, stamps = [], [], []
    with open(csv_path, newline="") as f:
        for row in csv.reader(f):
            if len(row) < 3:
                raise ToolError(f"{csv_path}: expected the vegeta CSV columns, got {row[:3]}")
            ts, code, lat = int(row[0]), int(row[1]), int(row[2]) / 1e9
            allv.append(lat)
            if 200 <= code < 300:
                okv.append(lat)
            stamps.append(ts)
    return sorted(allv), sorted(okv), stamps


def sent_per_second(stamps):
    """Requests started in each second since the first one: how well the schedule was kept."""
    if not stamps:
        return []
    first = min(stamps)
    counts = [0] * ((max(stamps) - first) // 1_000_000_000 + 1)
    for ts in stamps:
        counts[(ts - first) // 1_000_000_000] += 1
    return counts


def _latency_dict(values):
    if not values:
        return {k: None for k in ("mean", "min", "p50", "p90", "p95", "p99", "max")}
    return {"mean": sum(values) / len(values), "min": values[0], "p50": quantile(values, .5),
            "p90": quantile(values, .9), "p95": quantile(values, .95),
            "p99": quantile(values, .99), "max": values[-1]}


def parse_vegeta(report_path, csv_path=None):
    try:
        with open(report_path) as f:
            rep = json.load(f)
        lat = rep["latencies"]
        codes = {str(k): int(v) for k, v in (rep.get("status_codes") or {}).items()}
        requests = int(rep["requests"])
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ToolError(f"{report_path}: not a vegeta JSON report ({exc})") from None
    errors = codes.get("0", 0)                          # code 0: no response
    ok2xx = sum(n for c, n in codes.items() if c.isdigit() and 200 <= int(c) < 300)
    responses = requests - errors
    latency = {"mean": lat["mean"] / 1e9, "min": lat["min"] / 1e9, "p50": lat["50th"] / 1e9,
               "p90": lat["90th"] / 1e9, "p95": lat["95th"] / 1e9, "p99": lat["99th"] / 1e9,
               "max": lat["max"] / 1e9}
    quantiles, extra = "tdigest", {"rate": rep.get("rate"), "throughput": rep.get("throughput"),
                                   "wait_s": rep.get("wait", 0) / 1e9,
                                   "error_set": (rep.get("errors") or [])[:5]}
    if csv_path:
        allv, okv, stamps = _exact_latency(csv_path)
        if len(allv) != requests:
            raise ToolError(f"{csv_path}: {len(allv)} rows but the report counts {requests}")
        latency, quantiles = _latency_dict(allv), "exact"
        extra["latency_2xx"] = _latency_dict(okv)
        extra["first_ts_ns"], extra["last_ts_ns"] = min(stamps), max(stamps)
        extra["sent_per_s"] = sent_per_second(stamps)
    return ToolResult("vegeta", requests, responses, ok2xx, responses - ok2xx, errors, codes,
                      latency, quantiles, rep["duration"] / 1e9, 0, extra)


def parse_k6(path):
    try:
        with open(path) as f:
            d = json.load(f)
        st = {k: int(v) for k, v in d["status"].items()}
        lat = d["latency_ms"]
        requests = int(d["requests"] or 0)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ToolError(f"{path}: not the summary written by bench/loadtools.py's k6 script "
                        f"({exc})") from None

    def sec(k):
        return None if lat.get(k) is None else lat[k] / 1e3

    latency = {"mean": sec("avg"), "min": sec("min"), "p50": sec("p50"), "p90": sec("p90"),
               "p95": sec("p95"), "p99": sec("p99"), "max": sec("max")}
    errors = st.get("other", 0)
    ok2xx = st.get("2xx", 0)
    responses = requests - errors
    return ToolResult("k6", requests, responses, ok2xx, responses - ok2xx, errors, st, latency,
                      "k6-trend", (d.get("duration_ms") or 0) / 1e3,
                      int(d.get("dropped_iterations") or 0),
                      {"iterations": d.get("iterations"), "p999": sec("p999")})


_UNIT = {"us": 1e-6, "ms": 1e-3, "s": 1.0, "m": 60.0, "h": 3600.0}
_WRK_TIME = r"([\d.]+)(us|ms|s|m|h)"


def _wrk_s(value, unit):
    return float(value) * _UNIT[unit]


def parse_wrk(path):
    try:
        with open(path) as f:
            text = f.read()
    except OSError as exc:
        raise ToolError(f"{path}: {exc}") from None
    total = re.search(r"^\s*(\d+) requests in " + _WRK_TIME, text, re.MULTILINE)
    if not total:
        raise ToolError(f"{path}: no '... requests in ...' line; is this wrk output?")
    requests = int(total.group(1))
    dist = {int(float(p)): _wrk_s(v, u) for p, v, u in
            re.findall(r"^\s*(\d+(?:\.\d+)?)%\s+" + _WRK_TIME + r"\s*$", text, re.MULTILINE)}
    thread = re.search(r"^\s*Latency\s+" + _WRK_TIME + r"\s+" + _WRK_TIME + r"\s+" + _WRK_TIME,
                       text, re.MULTILINE)
    errs = re.search(r"Socket errors: connect (\d+), read (\d+), write (\d+), timeout (\d+)", text)
    non2xx = re.search(r"Non-2xx or 3xx responses: (\d+)", text)
    errors = sum(int(x) for x in errs.groups()) if errs else 0
    non2xx = int(non2xx.group(1)) if non2xx else 0
    latency = {"mean": _wrk_s(thread.group(1), thread.group(2)) if thread else None,
               "min": None, "p50": dist.get(50), "p90": dist.get(90), "p95": None,
               "p99": dist.get(99),
               "max": _wrk_s(thread.group(5), thread.group(6)) if thread else None}
    rate = re.search(r"Requests/sec:\s+([\d.]+)", text)
    return ToolResult("wrk", requests, requests, requests - non2xx, non2xx, errors,
                      {"non-2xx-3xx": non2xx}, latency, "wrk-histogram",
                      _wrk_s(total.group(2), total.group(3)), 0,
                      {"rate": float(rate.group(1)) if rate else None, "closed_loop": True,
                       "p75": dist.get(75),
                       "note": "wrk counts 3xx as ok; ok2xx here is requests minus Non-2xx or 3xx"})


def parse_loadgen(path):
    try:
        with open(path) as f:
            d = json.load(f)
        st = {str(k): int(v) for k, v in d["status"].items()}
        errs = {k: int(v) for k, v in d["errors"].items()}
        lat = d["latency_s"]
        sent, dropped = int(d["sent"]), int(d["dropped"])
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ToolError(f"{path}: not a bench/loadgen.py summary ({exc})") from None
    responses = sum(st.values())
    ok2xx = sum(n for c, n in st.items() if 200 <= int(c) < 300)
    return ToolResult("loadgen", sent, responses, ok2xx, responses - ok2xx,
                      sum(n for k, n in errs.items() if k != "dropped"), st,
                      {k: lat[k] for k in ("mean", "min", "p50", "p90", "p95", "p99", "max")},
                      "exact-intended-time", d["wall_s"], dropped,
                      {"flags": d["flags"], "valid": d["valid"], "slip_s": d["slip_s"],
                       "service_s": d["service_s"], "cpu": d["cpu"], "spin_ms": d["spin_ms"],
                       "per_second": d["per_second"], "error_classes": errs})


def parse_dir(tool, workdir):
    """Re-read the outputs of an earlier run from its directory."""
    if tool == "vegeta":
        csv_path = os.path.join(workdir, "vegeta.csv")
        return parse_vegeta(os.path.join(workdir, "vegeta.report.json"),
                            csv_path if os.path.exists(csv_path) else None)
    if tool == "k6":
        return parse_k6(os.path.join(workdir, "k6.summary.json"))
    if tool == "wrk":
        return parse_wrk(os.path.join(workdir, "wrk.out"))
    if tool == "loadgen":
        return parse_loadgen(os.path.join(workdir, "loadgen.summary.json"))
    raise ToolError(f"no parser for {tool!r}")


# --- command line -------------------------------------------------------------------------

def _spec_from_args(a):
    return LoadSpec(url=a.url, rate=a.rate, duration=a.duration, method=a.method,
                    headers=tuple(a.header or ()), timeout=a.timeout, connections=a.connections,
                    workers=a.workers, max_workers=a.max_workers, threads=a.threads,
                    local_addr=a.local_addr, cpus=a.cpus, allow_loopback=a.allow_loopback,
                    name=a.name)


def _add_spec_args(ap):
    ap.add_argument("tool", choices=sorted(BUILDERS))
    ap.add_argument("--url", required=True)
    ap.add_argument("--rate", type=float, required=True)
    ap.add_argument("--duration", type=float, required=True)
    ap.add_argument("--method", default="GET")
    ap.add_argument("--header", action="append", help="'Name: value', repeatable")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--connections", type=int, default=100)
    ap.add_argument("--workers", type=int, default=50)
    ap.add_argument("--max-workers", type=int, default=5000)
    ap.add_argument("--threads", type=int, default=2)
    ap.add_argument("--local-addr", default="")
    ap.add_argument("--cpus", default="", help="taskset list, e.g. 4-7")
    ap.add_argument("--allow-loopback", action="store_true", help="verification only")
    ap.add_argument("--allow-unverified", action="store_true", help="verification only")
    ap.add_argument("--name", default="load")
    ap.add_argument("--manifest", default=MANIFEST)
    ap.add_argument("--root", default=None, help="tools directory (default LOADTOOLS_DIR)")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("list", help="the manifest, with the hash check of every binary")
    s.add_argument("--no-hash", action="store_true")
    s.add_argument("--manifest", default=MANIFEST)
    s.add_argument("--root", default=None)
    s = sub.add_parser("plan", help="print the commands of a run; sends nothing")
    _add_spec_args(s)
    s.add_argument("--no-check", action="store_true", help="skip the file and hash check")
    s = sub.add_parser("run", help="run it: generates load")
    _add_spec_args(s)
    s.add_argument("--out", required=True, help="directory for the outputs and provenance.json")
    s = sub.add_parser("parse", help="read the outputs of an earlier run")
    s.add_argument("tool", choices=sorted(BUILDERS))
    s.add_argument("dir")
    a = ap.parse_args(argv)

    try:
        if a.cmd == "list":
            m = load_manifest(a.manifest)
            for name, t in m["tools"].items():
                path = tool_file(m, name, a.root)
                if a.no_hash:
                    state = "not checked"
                elif not os.path.isfile(path):
                    state = "missing"
                else:
                    state = "hash ok" if sha256_file(path) == t["sha256"] else "HASH DIFFERS"
                print(f"{name:7} {t['version'][:22]:22} {t['status']:13} {state:12} {path}")
            return 0
        if a.cmd == "parse":
            print(json.dumps(parse_dir(a.tool, a.dir).to_dict(), indent=1))
            return 0
        spec = _spec_from_args(a)
        plan = build_plan(a.tool, spec, getattr(a, "out", "<workdir>"), load_manifest(a.manifest),
                          a.root, a.allow_unverified, check=not getattr(a, "no_check", False))
        if a.cmd == "plan":
            for step in plan.steps:
                print(" ".join(step.argv))
            return 0
        prov = run_plan(plan)
        print(json.dumps({"ok": prov["ok"], "provenance": os.path.join(plan.workdir,
                                                                       "provenance.json")}))
        if prov["ok"]:
            print(json.dumps(parse_dir(a.tool, plan.workdir).to_dict(), indent=1))
        return 0 if prov["ok"] else 1
    except (ScopeError, ToolError, ValueError) as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
