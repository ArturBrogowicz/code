"""The P1 runner's conf rendering (l7_conf.py; ledger D-028, review T-030 L7V2-09): a run's own copy of
nginx_unprotected.conf logs the L7 v2 fields, a run's own copy of nginx.conf carries the deny map and its 429, and
the tracked confs are never changed. Static: no nginx is started."""
import hashlib
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "bench"))
sys.path.insert(0, os.path.join(REPO, "ml"))
import test_l7_log_fields as LF

import l7_conf as C
import l7_denymap

RUN = "/var/tmp/ddos_campaigns/p1/b01_M_gru/l7v2"
# the tracked confs as the harm benchmark and the HG4 arms pinned them (base 75fbadc)
PINNED = {"nginx_unprotected.conf": "55f867904d18615b3f5405e3017ab17d425106d2e34d1b265ac4cf352135dfdb",
          "nginx.conf": "2eca9903be80d874b281a78dc0573223d31103e51d4d1c263064410d06375e7f"}


def sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def l7json(text):
    block = re.search(r"log_format l7json escape=json\n(.*?)'}';", text, re.DOTALL).group(1)
    return re.findall(r"'\"(\w+)\":\"?(\$\w+)\"?,?'", block)


def is_subsequence(lines, of):
    it = iter(of)
    return all(any(line == other for other in it) for line in lines)


class TrackedConfsTest(unittest.TestCase):
    def test_rendering_reads_the_tracked_confs_and_never_changes_them(self):
        paths = {name: os.path.join(REPO, name) for name in PINNED}
        self.assertEqual({n: sha(p) for n, p in paths.items()}, PINNED)
        confs = C.run_confs(RUN)
        self.assertEqual({n: sha(p) for n, p in paths.items()}, PINNED)
        self.assertEqual(set(confs), {"unprotected", "protected"})


class UnprotectedTest(unittest.TestCase):
    def setUp(self):
        self.orig = C.read(C.UNPROTECTED_CONF)
        self.text = C.unprotected(self.orig)

    def test_the_copy_logs_the_fields_nginx_conf_logs_in_the_same_lines(self):
        self.assertEqual(l7json(self.text), l7json(C.read(C.PROTECTED_CONF)))
        self.assertEqual(l7json(self.text)[-3:], list(LF.NEW.items()))
        block = re.search(r"log_format l7json escape=json\n(.*?)'}';", self.text, re.DOTALL).group(1)
        protected_block = re.search(r"log_format l7json escape=json\n(.*?)'}';", C.read(C.PROTECTED_CONF),
                                    re.DOTALL).group(1)
        self.assertEqual(block.splitlines()[-4:], protected_block.splitlines()[-4:])

    def test_only_those_lines_change_and_no_deny_map_is_added(self):
        added = [ln for ln in self.text.splitlines() if ln not in self.orig.splitlines()]
        self.assertEqual([ln.strip() for ln in added], ["'\"ua\":\"$http_user_agent\",'", "'\"ref\":\"$http_referer\",'",
                                                        "'\"sid\":\"$cookie_sid\",'",
                                                        "'\"sid_set\":\"$upstream_cookie_sid\"'"])
        self.assertEqual(len(self.text.splitlines()), len(self.orig.splitlines()) + 3)
        self.assertNotIn(C.DENY_VAR, self.text)
        self.assertIsNone(re.search(r"^\s*limit_(req|conn)\s", self.text, re.MULTILINE))   # still no limits
        self.assertEqual(self.text.count("# L7-SYSLOG-SINK"), 1)
        with self.assertRaises(C.ConfError):
            C.unprotected(self.text)                                   # rendered once only

    def test_a_conf_it_does_not_know_is_refused(self):
        for bad in (self.orig.replace("log_format l7json", "log_format other"),
                    self.orig.replace("'\"ua\":\"$http_user_agent\"'", "'\"ua\":\"$http_user_agent\",'")):
            with self.assertRaises(C.ConfError):
                C.unprotected(bad)


class ProtectedTest(unittest.TestCase):
    def setUp(self):
        self.orig = C.read(C.PROTECTED_CONF)
        self.text = C.protected(self.orig, RUN)

    def test_the_copy_has_the_deny_map_in_http_and_the_429_in_server(self):
        http, server = self.text.index("http {"), self.text.index("    server {")
        m = re.search(r"^    map \"\$remote_addr\|\$http_user_agent\|\$cookie_sid\" \$l7_deny \{\n"
                      r"        default 0;\n        include ([^;]+);\n    \}\n", self.text, re.MULTILINE)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), f"{RUN}/{l7_denymap.DENY_FILE}")
        self.assertTrue(http < m.start() < server)
        deny = re.search(r"^        if \(\$l7_deny\) \{\n            return 429;\n        \}\n", self.text,
                         re.MULTILINE)
        self.assertIsNotNone(deny)
        self.assertTrue(self.text.index("server_name") < deny.start() < self.text.index("location /"))
        self.assertIn(f"map_hash_bucket_size {C.MAP_HASH_BUCKET_SIZE};", self.text)
        self.assertIn(f"map_hash_max_size {C.MAP_HASH_MAX_SIZE};", self.text)

    def test_nothing_else_changes(self):
        self.assertTrue(is_subsequence(self.orig.splitlines(), self.text.splitlines()))
        self.assertEqual(self.text.count("{"), self.orig.count("{") + 2)
        self.assertEqual(self.text.count("}"), self.orig.count("}") + 2)
        self.assertEqual(l7json(self.text), l7json(self.orig))
        self.assertEqual(self.text.count("# L7-SYSLOG-SINK"), 1)
        with self.assertRaises(C.ConfError):
            C.protected(self.text, RUN)                                # rendered once only

    def test_the_bucket_holds_the_longest_key_the_writer_allows(self):
        longest = len(l7_denymap.map_key("255.255.255.255", "x" * l7_denymap.MAX_UA_BYTES, "0" * 32))
        element = 8 + (longest + 2 + 7) // 8 * 8                       # NGX_HASH_ELT_SIZE, src/core/ngx_hash.c:248
        self.assertGreaterEqual(C.MAP_HASH_BUCKET_SIZE, element + 8)
        self.assertEqual(C.DENY_FILE, l7_denymap.DENY_FILE)

    def test_only_a_plain_absolute_run_directory(self):
        for bad in ("relative/dir", "/tmp/a b", "/tmp/x;include /etc", '/tmp/"q"', "/tmp/../etc", "/tmp/${x}", "",
                    None):
            with self.subTest(bad=bad), self.assertRaises(C.ConfError):
                C.protected(self.orig, bad)
        self.assertIn("include /run/l7v2/deny.map;", C.protected(self.orig, "/run/l7v2/"))


class CompositionTest(unittest.TestCase):
    """The copies still take the daemon's socket sink (capture_l7.render_l7_sink) and the run's log paths
    (bench/executor.render_nginx_conf), as the runners render them today."""

    def test_the_sink_and_the_log_paths_still_render(self):
        import capture_l7
        import executor
        confs = C.run_confs(RUN)
        for kind, text in confs.items():
            with self.subTest(kind=kind):
                out = executor.render_nginx_conf(capture_l7.render_l7_sink(text, "/run/ddos_l7.sock"),
                                                 "/var/tmp/run/access.log", "/var/tmp/run/error.log", feed=True)
                self.assertIn("access_log syslog:server=unix:/run/ddos_l7.sock,nohostname,tag=l7 l7json;", out)
                self.assertIn("access_log /var/tmp/run/access.log json_ml_format;", out)
                self.assertEqual(out.count(C.DENY_VAR), 0 if kind == "unprotected" else 2)


if __name__ == "__main__":
    unittest.main()
