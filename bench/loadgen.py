#!/usr/bin/env python3
"""Open-loop HTTP load generator for the harm benchmark (docs/BENCHMARK_HARM_DESIGN.md, 8.2).

The requests to send, and when, are fixed before the first one leaves: a schedule of intended
send times (constant rate, Poisson, on/off pulses or a linear ramp) drawn from a seed. Nothing
the server does can change it. A response that is slow makes its own latency long, not the next
request late, and a request that cannot be started because max_inflight requests are already
outstanding is counted as dropped and flagged, never silently skipped.

  * latency is measured from the INTENDED send time (the correction for coordinated omission),
    so a stalled server or a late generator shows up as latency. The latency from the actual send
    is reported next to it, and so is the slip between the two;
  * each identity (a source address, optionally headers) has its own keep-alive pool of at most
    --pool idle connections; the source address is bound with bind(), so the server sees it;
  * the scope lock of bench/loadtools.py applies: an IP literal inside the testbed net, loopback
    only with --allow-loopback; no hostnames, no redirects (this client never follows one);
  * validity flags, written into the summary and never silent: schedule slip p99 above 50 ms,
    fewer than 99 % of the intended requests sent, generator CPU above 70 % of a core, descriptor
    or ephemeral-port exhaustion, any dropped request. --strict turns them into exit status 3.

On a VM whose idle vCPUs wake late, sleeping until the next send slips by tens or hundreds of
milliseconds. --spin-ms makes the scheduler busy-wait for the last part of each interval (and
the CPU flag ignores that time); a value larger than the gap between requests never sleeps.

    ./venv/bin/python bench/loadgen.py --url http://10.0.0.1/ --rate 100 --duration 10
        [--process constant|poisson|pulse|ramp] [--seed 1] [--ramp-to R] [--period 1 --duty .5]
        [--timeout 10] [--max-inflight 5000] [--pool 100] [--local-addr IP ...] [--path /p ...]
        [--header 'Name: value' ...] [--spin-ms 0] [--summary FILE] [--records FILE.csv.gz]
        [--plan] [--strict] [--allow-loopback]

--plan prints the schedule's statistics and sends nothing. The unit tests send a few hundred
requests to local servers of their own.
"""
import argparse
import array
import asyncio
import dataclasses
import errno
import gzip
import json
import math
import os
import random
import ssl
import sys
import time
import urllib.parse

try:
    import loadtools as LT
except ImportError:                       # run from the repository root
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import loadtools as LT

ENGINE_VERSION = "1"
OK, TIMEOUT, CONNECT, RESET, PROTOCOL, FD, PORT, DROPPED, OTHER = range(9)
ERR_NAMES = ("", "timeout", "connect", "reset", "protocol", "fd", "port", "dropped", "other")
LIMITS = {"slip_p99_s": 0.05, "sent_share": 0.99, "cpu_share": 0.70}


class ProtocolError(ValueError):
    """The server's answer is not HTTP/1.x the way this client reads it."""


# --- schedules -----------------------------------------------------------------------------

def schedule(process, rate, duration, seed=1, ramp_to=None, period=1.0, duty=0.5):
    """Intended send times in seconds since the start: ascending, all below `duration`.

    constant  one every 1/rate s, starting at 0
    poisson   exponential gaps drawn from `seed`
    pulse     `rate` is the mean over a `period`; the requests of a period are spread evenly
              over its first `duty` fraction and none are sent in the rest
    ramp      the rate changes linearly from `rate` to `ramp_to` over the run (either may be 0)
    """
    if not duration > 0:
        raise ValueError("duration must be positive")
    if process != "ramp" and not rate > 0:
        raise ValueError("rate must be positive")
    if process == "constant":
        return [i / rate for i in range(int(rate * duration + 1e-9))]
    if process == "poisson":
        rng, t, out = random.Random(seed), 0.0, []
        while True:
            t += rng.expovariate(rate)
            if t >= duration:
                return out
            out.append(t)
    if process == "pulse":
        if not (0 < duty <= 1 and period > 0):
            raise ValueError("pulse needs 0 < duty <= 1 and period > 0")
        per = int(rate * period + 1e-9)
        out, k = [], 0
        while k * period < duration:
            out += [t for j in range(per) if (t := k * period + j * duty * period / per) < duration]
            k += 1
        return out
    if process == "ramp":
        r1 = rate if ramp_to is None else ramp_to
        if rate < 0 or r1 < 0 or rate + r1 <= 0:
            raise ValueError("a ramp needs non-negative rates that are not both zero")
        n = int((rate + r1) / 2 * duration + 1e-9)
        if r1 == rate:
            return [k / rate for k in range(n)]
        a = (r1 - rate) / (2 * duration)               # N(t) = rate t + a t^2
        return [(-rate + math.sqrt(rate * rate + 4 * a * k)) / (2 * a) for k in range(n)]
    raise ValueError(f"unknown process {process!r}")


# --- HTTP/1.1, as much as this client needs -----------------------------------------------

def build_request(method, host, port, path, headers=()):
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}" + ("" if port in (80, 443) else f":{port}"),
             f"User-Agent: loadgen/{ENGINE_VERSION}", "Accept: */*", *headers]
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def parse_head(head):
    """(status, content_length or None, chunked, close) of a response head without its CRLFCRLF."""
    first, _, rest = head.partition(b"\r\n")
    parts = first.split(None, 2)
    if len(parts) < 2 or not parts[0].startswith(b"HTTP/1.") or not parts[1].isdigit():
        raise ProtocolError(f"bad status line {first[:60]!r}")
    length, chunked, close = None, False, parts[0] != b"HTTP/1.1"
    for line in rest.split(b"\r\n"):
        key, _, value = line.partition(b":")
        key, value = key.strip().lower(), value.strip().lower()
        if key == b"content-length":
            try:
                length = int(value)
            except ValueError:
                raise ProtocolError(f"bad Content-Length {value[:20]!r}") from None
        elif key == b"transfer-encoding" and b"chunked" in value:
            chunked = True
        elif key == b"connection":
            if b"close" in value:
                close = True
            elif b"keep-alive" in value:
                close = False
    return int(parts[1]), length, chunked, close


async def read_response(reader, method):
    """(status, bytes read, keep-alive) of one response."""
    head = await reader.readuntil(b"\r\n\r\n")
    status, length, chunked, close = parse_head(head[:-4])
    n = len(head)
    if method == "HEAD" or status in (204, 304) or 100 <= status < 200:
        pass
    elif chunked:
        while True:
            line = await reader.readuntil(b"\r\n")
            try:
                size = int(line.split(b";")[0], 16)
            except ValueError:
                raise ProtocolError(f"bad chunk size {line[:20]!r}") from None
            if size == 0:
                while await reader.readuntil(b"\r\n") != b"\r\n":      # trailers
                    pass
                break
            await reader.readexactly(size + 2)
            n += size
    elif length is not None:
        if length:
            await reader.readexactly(length)
        n += length
    else:
        n += len(await reader.read(-1))
        close = True
    return status, n, not close


def classify(exc, connecting=False):
    """The error class of an exception raised while a request was in flight."""
    if isinstance(exc, TimeoutError):
        return TIMEOUT
    if isinstance(exc, OSError) and exc.errno in (errno.EMFILE, errno.ENFILE):
        return FD
    if isinstance(exc, OSError) and exc.errno == errno.EADDRNOTAVAIL:
        return PORT
    if connecting and isinstance(exc, OSError):
        return CONNECT
    if isinstance(exc, (asyncio.IncompleteReadError, ConnectionError)):
        return RESET
    if isinstance(exc, (ProtocolError, asyncio.LimitOverrunError, ValueError)):
        return PROTOCOL
    return OTHER


# --- the engine ----------------------------------------------------------------------------

@dataclasses.dataclass
class Identity:
    name: str = "default"
    local_addr: str = ""              # source address to bind; "" = the system's choice
    headers: tuple = ()
    pool: list = dataclasses.field(default_factory=list)      # idle (reader, writer), newest last


@dataclasses.dataclass
class Config:
    url: str
    rate: float
    duration: float
    process: str = "constant"
    seed: int = 1
    ramp_to: float = None
    period: float = 1.0
    duty: float = 0.5
    timeout: float = 10.0
    max_inflight: int = 5000
    pool: int = 100                   # idle keep-alive connections kept per identity
    method: str = "GET"
    paths: tuple = ("/",)
    headers: tuple = ()
    local_addrs: tuple = ()
    allow_loopback: bool = False
    spin_ms: float = 0.0


class Engine:
    def __init__(self, cfg, sched=None):
        self.cfg = cfg
        self.host, self.port = LT.check_scope(cfg.url, cfg.allow_loopback)
        parts = urllib.parse.urlsplit(cfg.url)
        self.ssl = ssl._create_unverified_context() if parts.scheme == "https" else None
        if cfg.method not in ("GET", "HEAD"):
            raise ValueError("loadgen sends GET and HEAD only")
        self.sched = schedule(cfg.process, cfg.rate, cfg.duration, cfg.seed, cfg.ramp_to,
                              cfg.period, cfg.duty) if sched is None else sched
        addrs = cfg.local_addrs or ("",)
        for a in addrs:
            if a:
                LT.check_address(a, cfg.allow_loopback)
        self.idents = [Identity(a or "default", a, cfg.headers) for a in addrs]
        base = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        paths = [(base if p == "/" and base != "/" else p) for p in cfg.paths]
        self.requests = [[build_request(cfg.method, self.host, self.port, p, i.headers)
                          for p in paths] for i in self.idents]
        rng = random.Random(cfg.seed + 1)
        self.choice = [rng.randrange(len(paths)) for _ in self.sched]
        n = len(self.sched)
        nan = float("nan")
        self.t_int = array.array("d", self.sched)
        self.t_sent = array.array("d", [nan]) * n
        self.t_done = array.array("d", [nan]) * n
        self.status = array.array("H", [0]) * n
        self.nbytes = array.array("I", [0]) * n
        self.err = array.array("B", [OK]) * n
        self.reused = array.array("B", [0]) * n
        self.inflight = 0
        self.spin_s = 0.0
        self.t0 = None

    async def _connect(self, ident):
        kw = {"ssl": self.ssl} if self.ssl else {}
        if ident.local_addr:
            kw["local_addr"] = (ident.local_addr, 0)
        return await asyncio.open_connection(self.host, self.port, **kw)

    async def _exchange(self, ident, req):
        method = self.cfg.method
        for attempt in (0, 1):
            conn = ident.pool.pop() if attempt == 0 and ident.pool else None   # the retry: fresh
            reused = conn is not None
            if conn is None:
                try:
                    conn = await self._connect(ident)
                except OSError as exc:
                    exc.connecting = True
                    raise
            reader, writer = conn
            try:
                writer.write(req)
                status, n, keep = await read_response(reader, method)
            except (asyncio.IncompleteReadError, ConnectionError):
                writer.close()
                if reused and attempt == 0:          # the server had closed an idle connection
                    continue
                raise
            except BaseException:
                writer.close()
                raise
            if keep and len(ident.pool) < self.cfg.pool:
                ident.pool.append((reader, writer))
            else:
                writer.close()
            return status, n, reused
        raise AssertionError("unreachable")

    async def _fire(self, i):
        loop = asyncio.get_running_loop()
        k = i % len(self.idents)
        self.t_sent[i] = loop.time() - self.t0
        try:
            async with asyncio.timeout(self.cfg.timeout):
                s, n, reused = await self._exchange(self.idents[k], self.requests[k][self.choice[i]])
            self.status[i], self.nbytes[i], self.reused[i] = s, n, reused
        except Exception as exc:  # noqa: BLE001  whatever went wrong is this request's result
            self.err[i] = classify(exc, getattr(exc, "connecting", False))
        finally:
            self.t_done[i] = loop.time() - self.t0
            self.inflight -= 1

    async def _pace(self, due):
        loop = asyncio.get_running_loop()
        wait = due - loop.time()
        if wait <= 0:
            return loop.time()
        spin = self.cfg.spin_ms / 1000
        if wait > spin:
            await asyncio.sleep(wait - spin)
        if spin:
            s0 = loop.time()
            while loop.time() < due:
                await asyncio.sleep(0)
            self.spin_s += loop.time() - s0
        return loop.time()

    async def run(self):
        loop = asyncio.get_running_loop()
        self.t0 = loop.time() + 0.05
        cpu0, wall0 = time.process_time(), loop.time()
        tasks, behind = set(), 0
        for i, off in enumerate(self.sched):
            now = await self._pace(self.t0 + off)
            if self.inflight >= self.cfg.max_inflight:
                self.err[i] = DROPPED
                continue
            self.inflight += 1
            task = loop.create_task(self._fire(i))
            tasks.add(task)
            task.add_done_callback(tasks.discard)
            if now > self.t0 + off:                  # behind schedule: let the I/O run too
                behind += 1
                if behind % 32 == 0:
                    await asyncio.sleep(0)
        if tasks:
            await asyncio.wait(tasks, timeout=self.cfg.timeout + 2)
        for task in tasks:
            task.cancel()
        for ident in self.idents:
            while ident.pool:
                ident.pool.pop()[1].close()
        return {"wall_s": loop.time() - wall0, "cpu_s": time.process_time() - cpu0,
                "spin_s": self.spin_s}


# --- the summary ---------------------------------------------------------------------------

def _stats(values):
    v = sorted(values)
    if not v:
        return {k: None for k in ("mean", "min", "p50", "p90", "p95", "p99", "max")}
    return {"mean": sum(v) / len(v), "min": v[0], "p50": LT.quantile(v, .5),
            "p90": LT.quantile(v, .9), "p95": LT.quantile(v, .95), "p99": LT.quantile(v, .99),
            "max": v[-1]}


def _per_second(times, n_bins):
    bins = [0] * n_bins
    for t in times:
        b = int(t)
        if 0 <= b < n_bins:
            bins[b] += 1
    return bins


def summarise(eng, timing):
    """The summary dict of a finished run: counts, intended-time latency, slip, flags."""
    cfg, n = eng.cfg, len(eng.sched)
    sent = [i for i in range(n) if eng.t_sent[i] == eng.t_sent[i]]
    got = [i for i in sent if eng.err[i] == OK]
    status, errors = {}, {}
    for i in got:
        status[str(eng.status[i])] = status.get(str(eng.status[i]), 0) + 1
    for i in range(n):
        if eng.err[i] != OK:
            errors[ERR_NAMES[eng.err[i]]] = errors.get(ERR_NAMES[eng.err[i]], 0) + 1
    finished = [i for i in sent if eng.t_done[i] == eng.t_done[i]]
    dropped = errors.get("dropped", 0)
    slip = _stats([eng.t_sent[i] - eng.t_int[i] for i in sent])
    wall = max(timing["wall_s"], 1e-9)
    cpu_share = max(0.0, timing["cpu_s"] - timing["spin_s"]) / wall
    n_bins = int(max([eng.t_done[i] for i in finished] + [cfg.duration])) + 1
    flags = {"slip": slip["p99"] is not None and slip["p99"] > LIMITS["slip_p99_s"],
             "sent_short": n > 0 and len(sent) < LIMITS["sent_share"] * n,
             "cpu": cpu_share > LIMITS["cpu_share"],
             "descriptors": errors.get("fd", 0) > 0, "ports": errors.get("port", 0) > 0,
             "dropped": dropped > 0}
    return {
        "schema": 1, "tool": "loadgen", "version": ENGINE_VERSION, "url": cfg.url,
        "process": cfg.process, "rate": cfg.rate, "duration": cfg.duration, "seed": cfg.seed,
        "intended": n, "sent": len(sent), "dropped": dropped, "completed": len(got),
        "status": status, "errors": errors,
        "bytes": sum(eng.nbytes[i] for i in got), "reused_connections": sum(eng.reused[i] for i in got),
        "latency_s": _stats([eng.t_done[i] - eng.t_int[i] for i in finished]),
        "latency_2xx_s": _stats([eng.t_done[i] - eng.t_int[i] for i in got
                                 if 200 <= eng.status[i] < 300]),
        "service_s": _stats([eng.t_done[i] - eng.t_sent[i] for i in finished]),
        "slip_s": slip,
        "wall_s": timing["wall_s"], "cpu": {"process_s": timing["cpu_s"], "spin_s": timing["spin_s"],
                                            "share": cpu_share},
        "spin_ms": cfg.spin_ms, "max_inflight": cfg.max_inflight, "pool": cfg.pool,
        "identities": [i.local_addr or "default" for i in eng.idents],
        "per_second": {"intended": _per_second(eng.t_int, n_bins),
                       "sent": _per_second([eng.t_sent[i] for i in sent], n_bins),
                       "completed": _per_second([eng.t_done[i] for i in got], n_bins)},
        "limits": LIMITS, "flags": flags, "valid": not any(flags.values()),
        "python": sys.version.split()[0], "pid": os.getpid(),
    }


def write_records(eng, path):
    with gzip.open(path, "wt") as f:
        f.write("i,t_intended,t_sent,t_done,status,bytes,err,ident,reused\n")
        for i in range(len(eng.sched)):
            f.write(f"{i},{eng.t_int[i]:.6f},{eng.t_sent[i]:.6f},{eng.t_done[i]:.6f},"
                    f"{eng.status[i]},{eng.nbytes[i]},{ERR_NAMES[eng.err[i]]},"
                    f"{i % len(eng.idents)},{eng.reused[i]}\n")


# --- command line --------------------------------------------------------------------------

def plan_text(cfg, sched):
    per = _per_second(sched, int(cfg.duration) + 1)
    return (f"{cfg.process}: {len(sched)} requests over {cfg.duration:g} s "
            f"(first {sched[0]:.4f} s, last {sched[-1]:.4f} s)" if sched else
            f"{cfg.process}: no requests") + f"\nper second: {per}"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--version", action="store_true")
    ap.add_argument("--url")
    ap.add_argument("--rate", type=float)
    ap.add_argument("--duration", type=float)
    ap.add_argument("--process", default="constant", choices=("constant", "poisson", "pulse", "ramp"))
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--ramp-to", type=float, default=None)
    ap.add_argument("--period", type=float, default=1.0)
    ap.add_argument("--duty", type=float, default=0.5)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--max-inflight", type=int, default=5000)
    ap.add_argument("--pool", type=int, default=100)
    ap.add_argument("--method", default="GET")
    ap.add_argument("--path", action="append", help="request path, repeatable (default /)")
    ap.add_argument("--header", action="append", help="'Name: value', repeatable")
    ap.add_argument("--local-addr", action="append", help="source address of an identity, repeatable")
    ap.add_argument("--allow-loopback", action="store_true", help="verification only")
    ap.add_argument("--spin-ms", type=float, default=float(os.environ.get("LOADGEN_SPIN_MS", "0")))
    ap.add_argument("--summary")
    ap.add_argument("--records")
    ap.add_argument("--plan", action="store_true")
    ap.add_argument("--strict", action="store_true", help="exit 3 when a validity flag is raised")
    a = ap.parse_args(argv)
    if a.version:
        print(f"loadgen {ENGINE_VERSION}")
        return 0
    if not (a.url and a.rate and a.duration):
        ap.error("--url, --rate and --duration are required")
    try:
        cfg = Config(url=a.url, rate=a.rate, duration=a.duration, process=a.process, seed=a.seed,
                     ramp_to=a.ramp_to, period=a.period, duty=a.duty, timeout=a.timeout,
                     max_inflight=a.max_inflight, pool=a.pool, method=a.method,
                     paths=tuple(a.path or ("/",)), headers=tuple(a.header or ()),
                     local_addrs=tuple(a.local_addr or ()), allow_loopback=a.allow_loopback,
                     spin_ms=a.spin_ms)
        for h in cfg.headers:
            if ":" not in h or "\n" in h or "\r" in h:
                raise ValueError(f"header {h!r}: expected 'Name: value' on one line")
        eng = Engine(cfg)
    except (LT.ScopeError, ValueError) as exc:
        print(f"[-] refusing: {exc}", file=sys.stderr)
        return 2
    if a.plan:
        print(plan_text(cfg, eng.sched))
        return 0
    timing = asyncio.run(eng.run())
    summary = summarise(eng, timing)
    if a.records:
        write_records(eng, a.records)
    text = json.dumps(summary, indent=1)
    if a.summary:
        with open(a.summary, "w") as f:
            f.write(text + "\n")
    else:
        print(text)
    return 3 if a.strict and not summary["valid"] else 0


if __name__ == "__main__":
    sys.exit(main())
