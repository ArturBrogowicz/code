"""Profile R, the realistic "unprotected" server of P4 (docs/P4_SLOW_DESIGN.md §4.1, D-S1, D-S2),
checked statically: `nginx -t` and gunicorn need the VM (the smoke run). A small parser reads the
nginx files into (directive, arguments, block) trees; every value the design note names is
pinned, and so is what R keeps from the L7 harness (nginx_l7capture.conf) and what the limits
variant adds."""
import os
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R_FILE, LIMITS_FILE = "nginx_profile_r.conf", "nginx_profile_r_limits.conf"
LIMIT_NAMES = {"limit_req", "limit_conn", "limit_req_zone", "limit_conn_zone"}
DEPLOYED_ZONES = [["$binary_remote_addr", "zone=mylimit:10m", "rate=30r/s"],
                  ["$binary_remote_addr", "zone=connlimit:10m"]]
DEPLOYED_LIMITS = [("limit_req", ["zone=mylimit", "burst=100", "nodelay"]),
                   ("limit_conn", ["connlimit", "50"])]


def read(name):
    with open(os.path.join(REPO, name), encoding="utf-8") as fh:
        return fh.read()


def tokens(text):
    """nginx's tokens: words, quoted strings, ';', '{' and '}'; comments dropped."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif c == "#":
            end = text.find("\n", i)
            i = n if end < 0 else end
        elif c in "{};":
            out.append(c)
            i += 1
        elif c in "'\"":
            end = text.index(c, i + 1)
            out.append(text[i:end + 1])
            i = end + 1
        else:
            j = i
            while j < n and not text[j].isspace() and text[j] not in "{};'\"#":
                j += 1
            out.append(text[i:j])
            i = j
    return out


def parse(text):
    """[(name, args, block or None)]. ValueError on an unbalanced brace or a directive without
    its ';'."""
    toks = tokens(text)

    def block(i, nested):
        items = []
        while i < len(toks):
            if toks[i] == "}":
                if not nested:
                    raise ValueError("unbalanced }")
                return items, i + 1
            j = i
            while j < len(toks) and toks[j] not in (";", "{", "}"):
                j += 1
            if j == len(toks) or toks[j] == "}":
                raise ValueError(f"directive {toks[i]!r} without ';'")
            if toks[j] == ";":
                items.append((toks[i], toks[i + 1:j], None))
                i = j + 1
            else:
                inner, k = block(j + 1, True)
                items.append((toks[i], toks[i + 1:j], inner))
                i = k
        if nested:
            raise ValueError("unclosed {")
        return items, i

    return block(0, False)[0]


def get(items, name):
    return [(args, blk) for n, args, blk in items if n == name]


def one(items, name):
    [(args, _blk)] = get(items, name)
    return args


def flat(items):
    """Every simple directive in the tree, as (name, args), in order."""
    out = []
    for name, args, blk in items:
        if blk is None:
            out.append((name, args))
        else:
            out += flat(blk)
    return out


class Conf:
    def __init__(self, name):
        self.items = parse(read(name))
        self.events = one_block(self.items, "events")
        self.http = one_block(self.items, "http")
        servers = [blk for _a, blk in get(self.http, "server")]
        [self.public] = [s for s in servers if (["80"], None) in get(s, "listen")]
        self.others = [s for s in servers if s is not self.public]
        self.locations = {tuple(a): blk for a, blk in get(self.public, "location")}


def one_block(items, name):
    [(_args, blk)] = get(items, name)
    return blk


def log_formats(http):
    return {a[0]: a[1:] for a, _b in get(http, "log_format")}


class ProfileRTest(unittest.TestCase):
    def setUp(self):
        self.r = Conf(R_FILE)

    def test_the_values_of_the_design_note(self):
        r = self.r
        self.assertEqual((one(r.items, "worker_processes"), one(r.events, "worker_connections")),
                         (["2"], ["768"]))                      # 2 x 768 = 1,536 slots
        self.assertEqual({k: one(r.http, k) for k in (
            "client_body_timeout", "client_header_timeout", "keepalive_timeout", "send_timeout",
            "client_max_body_size", "large_client_header_buffers")},
            {"client_body_timeout": ["60s"], "client_header_timeout": ["60s"],
             "keepalive_timeout": ["75s"], "send_timeout": ["60s"],
             "client_max_body_size": ["1m"], "large_client_header_buffers": ["4", "8k"]})

    def test_upload_takes_10m_and_streams_only_there(self):
        locs = self.r.locations
        self.assertEqual(set(locs), {("/",), ("/upload",)})
        self.assertEqual(one(locs[("/upload",)], "client_max_body_size"), ["10m"])
        self.assertEqual(one(locs[("/upload",)], "proxy_request_buffering"), ["off"])
        self.assertEqual([a for n, a in flat(self.r.items) if n == "proxy_request_buffering"],
                         [["off"]])
        for loc in locs.values():
            self.assertEqual(one(loc, "proxy_pass"), ["http://127.0.0.1:8080"])

    def test_no_limits_on_r(self):
        self.assertEqual({n for n, _a in flat(self.r.items)} & LIMIT_NAMES, set())

    def test_everything_else_is_the_l7_harness(self):
        # Every directive of nginx_l7capture.conf but the knobs R changes, its limits and its one
        # access log is in R with the same arguments, and the location of the harness is R's
        # location / and, with the two upload settings, its /upload.
        base = Conf("nginx_l7capture.conf")
        changed = {"worker_processes", "worker_connections", "client_body_timeout",
                   "client_header_timeout", "keepalive_timeout", "send_timeout",
                   "client_max_body_size", "large_client_header_buffers", "access_log"}
        have = flat(self.r.items)
        for d in flat(base.items):
            if d[0] not in changed | LIMIT_NAMES:
                self.assertIn(d, have, d)
        loc = [(n, a) for n, a, _b in base.locations[("/",)] if n not in LIMIT_NAMES]
        self.assertEqual([(n, a) for n, a, _b in self.r.locations[("/",)]], loc)
        self.assertEqual([(n, a) for n, a, _b in self.r.locations[("/upload",)]],
                         [("client_max_body_size", ["10m"]), ("proxy_request_buffering", ["off"]),
                          *loc])

    def test_the_logs(self):
        r = self.r
        self.assertEqual(get(r.http, "access_log"),
                         [(["/var/log/nginx/ddos_ml_access.log", "json_ml_port"], None),
                          (["/var/log/nginx/l7_capture.log", "l7json"], None)])
        self.assertEqual(one(r.http, "error_log"), ["/var/log/nginx/error.log", "info"])
        formats = log_formats(r.http)
        self.assertEqual(formats["l7json"], log_formats(Conf("nginx_l7capture.conf").http)["l7json"])
        deployed = log_formats(one_block(parse(read("nginx.conf")), "http"))["json_ml_format"]
        port = "'\"port\":$remote_port,'"
        self.assertEqual([t for t in formats["json_ml_port"] if t != port], deployed)
        self.assertEqual(formats["json_ml_port"].index(port),
                         deployed.index("'\"client_ip\":\"$remote_addr\",'") + 1)

    def test_stub_status_listens_on_the_loopback_only(self):
        [s] = self.r.others
        self.assertEqual(get(s, "listen"), [(["127.0.0.1:8081"], None)])
        [(args, blk)] = get(s, "location")
        self.assertEqual(args, ["=", "/nginx_status"])
        self.assertEqual([(n, a) for n, a, _b in blk],
                         [("stub_status", []), ("allow", ["127.0.0.1"]), ("deny", ["all"])])
        self.assertNotIn("stub_status", [n for n, _a in flat(self.r.public)])


class LimitsVariantTest(unittest.TestCase):
    def test_it_is_r_plus_the_deployed_limits(self):
        r, lim = Conf(R_FILE), Conf(LIMITS_FILE)
        self.assertEqual([a for a, _b in get(lim.http, "limit_req_zone")
                          + get(lim.http, "limit_conn_zone")], DEPLOYED_ZONES)
        for path, loc in lim.locations.items():
            self.assertEqual([(n, a) for n, a, _b in loc if n in LIMIT_NAMES],
                             DEPLOYED_LIMITS, path)

        def without(items):
            return [(n, a, None if b is None else without(b)) for n, a, b in items
                    if n not in LIMIT_NAMES]
        self.assertEqual(without(lim.items), r.items)

    def test_the_limits_are_the_l7_harness_ones(self):
        base = Conf("nginx_l7capture.conf")
        self.assertEqual([a for a, _b in get(base.http, "limit_req_zone")
                          + get(base.http, "limit_conn_zone")], DEPLOYED_ZONES)
        self.assertEqual([(n, a) for n, a, _b in base.locations[("/",)] if n in LIMIT_NAMES],
                         DEPLOYED_LIMITS)


class GunicornTest(unittest.TestCase):
    def test_five_sync_workers_on_the_loopback(self):
        ns = {}
        exec(compile(read("gunicorn_profile_r.py"), "gunicorn_profile_r.py", "exec"), ns)  # noqa: S102
        self.assertEqual({k: ns[k] for k in ("bind", "workers", "worker_class", "threads",
                                             "timeout", "graceful_timeout", "keepalive",
                                             "backlog")},
                         {"bind": "127.0.0.1:8080", "workers": 5, "worker_class": "sync",
                          "threads": 1, "timeout": 30, "graceful_timeout": 30, "keepalive": 2,
                          "backlog": 2048})
        self.assertEqual(ns["workers"], 2 * 2 + 1)            # 2 x CPUs + 1, CPUs 0-1 (D-S2)
        self.assertEqual(f"http://{ns['bind']}",               # nginx's upstream, and only it
                         one(Conf(R_FILE).locations[("/upload",)], "proxy_pass")[0])


class ParserTest(unittest.TestCase):
    def test_it_refuses_broken_files(self):
        for text in ("http { a 1; ", "a 1; }", "http { a 1 }", "a 1"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse(text)

    def test_quoted_braces_are_arguments(self):
        self.assertEqual(parse("log_format f '{' '}';  # x { y\n"),
                         [("log_format", ["f", "'{'", "'}'"], None)])


if __name__ == "__main__":
    unittest.main()
