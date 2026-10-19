"""Static tests for the L7 syslog sink of the nginx confs (audit G-23). Offline: no nginx is
started and no namespace is created.

With no daemon bound to the datagram socket, nginx logs "[warn] send() to syslog failed while
logging request" for every request, so the default confs must carry no syslog access_log. The
runners that start the daemon with L7_SHADOW=1 (ml/eval_l7.py, ml/smoke_l7.py) render the sink
into the copy of nginx.conf they serve.
"""
import argparse
import inspect
import os
import re
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "ml"))
import capture_l7
import eval_l7
import smoke_l7

SOCK = "/run/ddos_l7.sock"
SINK_LINE = f"access_log syslog:server=unix:{SOCK},nohostname,tag=l7 l7json;"
DEPLOYED = ("nginx.conf", "nginx_unprotected.conf")


def read(name):
    with open(os.path.join(REPO, name), encoding="utf-8") as fh:
        return fh.read()


def active(text):
    """The conf without its comments (none of these confs has a '#' inside a string)."""
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def sink_lines(text):
    return re.findall(r"^[ \t]*access_log[ \t]+syslog:.*$", active(text), re.MULTILINE)


class DefaultConfsTest(unittest.TestCase):
    def test_no_syslog_access_log_in_any_default_conf(self):
        for name in (*DEPLOYED, "nginx_l7capture.conf"):
            text = active(read(name))
            self.assertEqual(sink_lines(text), [], name)
            self.assertNotIn("syslog:", text, name)
            self.assertNotIn("ddos_l7.sock", text, name)

    def test_file_log_and_l7json_format_stay(self):
        for name in DEPLOYED:
            text = active(read(name))
            self.assertIn("log_format l7json escape=json", text, name)
            self.assertIn("access_log /var/log/nginx/ddos_ml_access.log json_ml_format;",
                          text, name)

    def test_one_marker_after_the_l7json_format(self):
        # nginx resolves a log_format when it parses the access_log, so the sink must come
        # after the format; the marker is where the runners write it.
        for name in DEPLOYED:
            text = read(name)
            marked = [ln for ln in text.splitlines()
                      if ln.strip().startswith(capture_l7.L7_SINK_MARKER)]
            self.assertEqual(len(marked), 1, name)
            self.assertLess(text.index("log_format l7json"),
                            text.index(capture_l7.L7_SINK_MARKER), name)


class RenderTest(unittest.TestCase):
    def test_render_replaces_only_the_marker_line(self):
        for name in DEPLOYED:
            text = read(name)
            out = capture_l7.render_l7_sink(text, SOCK)
            changed = [(x, y) for x, y in zip(text.splitlines(), out.splitlines(), strict=True)
                       if x != y]
            self.assertEqual(len(changed), 1, name)
            self.assertTrue(changed[0][0].strip().startswith(capture_l7.L7_SINK_MARKER), name)
            self.assertEqual(changed[0][1], f"    {SINK_LINE}", name)
            self.assertEqual(sink_lines(out), [f"    {SINK_LINE}"], name)
            self.assertLess(out.index("log_format l7json"), out.index(SINK_LINE), name)

    def test_the_socket_path_is_the_callers(self):
        other = "/run/other-l7.sock"
        out = capture_l7.render_l7_sink(read("nginx.conf"), other)
        self.assertEqual(sink_lines(out), [f"    {SINK_LINE.replace(SOCK, other)}"])

    def test_the_marker_must_occur_exactly_once(self):
        with self.assertRaises(RuntimeError):
            capture_l7.render_l7_sink("http { }", SOCK)
        marker = capture_l7.L7_SINK_MARKER
        doubled = read("nginx.conf").replace(marker, f"{marker}\n    {marker}")
        with self.assertRaises(RuntimeError):
            capture_l7.render_l7_sink(doubled, SOCK)

    def test_unusable_socket_paths_are_refused(self):
        for bad in ("", "run/x.sock", "/run/x y.sock", "/run/x;y.sock", "/run/x,y.sock",
                    "/run/x\n.sock"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                capture_l7.render_l7_sink(read("nginx.conf"), bad)

    def test_the_daemons_default_socket_renders(self):
        import l7_ingest
        out = capture_l7.render_l7_sink(read("nginx.conf"), l7_ingest.DEFAULT_SOCKET_PATH)
        self.assertEqual(len(sink_lines(out)), 1)
        self.assertIn(f"unix:{l7_ingest.DEFAULT_SOCKET_PATH},", out)


class RunnersRenderTheSinkTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_deployed_conf_default_profile(self):
        path = capture_l7.write_deployed_conf(os.path.join(self.tmp.name, "n.conf"),
                                              "default", SOCK)
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        self.assertEqual(text, capture_l7.render_l7_sink(read("nginx.conf"), SOCK))
        self.assertEqual(len(sink_lines(text)), 1)

    def test_deployed_conf_tolerant_profile_keeps_the_sink(self):
        path = capture_l7.write_deployed_conf(os.path.join(self.tmp.name, "n.conf"),
                                              "tolerant", SOCK)
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        self.assertEqual(len(sink_lines(text)), 1)
        self.assertIn("rate=82r/s", text)

    def test_eval_runner_serves_the_sink(self):
        for heuristics in ("default", "tolerant"):
            args = argparse.Namespace(duration=1.0, heuristics=heuristics)
            runner = eval_l7.EvalRunner(args, self.tmp.name, "/pkg")
            path = runner.write_nginx_conf(SOCK)
            self.assertEqual(os.path.basename(path), f"nginx_{heuristics}.conf")
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(len(sink_lines(fh.read())), 1, heuristics)

    def test_smoke_runner_serves_the_sink(self):
        path = smoke_l7.write_nginx_conf(self.tmp.name, SOCK)
        self.assertEqual(os.path.basename(path), "nginx_l7sink.conf")
        with open(path, encoding="utf-8") as fh:
            self.assertEqual(sink_lines(fh.read()), [f"    {SINK_LINE}"])

    def test_the_runners_start_nginx_from_the_rendered_conf(self):
        # Wiring (the stacks themselves need a VM): eval_l7 passes the rendered path to
        # `nginx -c`, smoke_l7 points the suite's S.NGINX_CONF at it, and both take the socket
        # path that the daemon is given.
        start = inspect.getsource(eval_l7.EvalRunner.start_stack)
        self.assertIn("conf = self.write_nginx_conf(socket_path)", start)
        self.assertIn('["nginx", "-c", conf]', start)
        self.assertIn('f"L7_SOCKET_PATH={socket_path}"', start)
        main = inspect.getsource(smoke_l7.main)
        self.assertIn('S.NGINX_CONF = write_nginx_conf(out_dir, os.environ["L7_SOCKET_PATH"])',
                      main)


if __name__ == "__main__":
    unittest.main()
