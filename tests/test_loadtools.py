"""Offline tests for bench/loadtools.py: the scope lock, the manifest checks, the command lines of
every builder, the readers of the three tools' reports and run_plan with a stub runner.

The samples the readers are tested on are written from the tools' documented formats (vegeta's
JSON tags, the summary object k6 hands to handleSummary, wrk's printout). The first verification
session on the VM checks them against real output. Nothing here starts a load tool or sends a
packet; the one real subprocess is `python -c`.
"""
import contextlib
import dataclasses
import hashlib
import io
import json
import os
import random
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "bench"))
import loadtools as LT

SPEC = LT.LoadSpec(url="http://10.0.0.1/", rate=100, duration=10, cpus="4-7",
                   local_addr="10.0.2.5", headers=("X-A: b",), name="smoke")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fake_root(tmp, status="verified"):
    """A tools directory with stand-in binaries, and a manifest that matches it."""
    files = {"vegeta": "vegeta-12.13.0/vegeta", "k6": "k6-2.3.0/k6"}
    tools = {}
    for name, rel in files.items():
        path = os.path.join(tmp, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(f"fake {name}".encode())
        os.chmod(path, 0o755)
        tools[name] = {"kind": "external", "version": "v1", "path": rel,
                       "sha256": sha(f"fake {name}".encode()), "status": status}
    wrk = os.path.join(tmp, "system", "wrk")
    os.makedirs(os.path.dirname(wrk), exist_ok=True)
    with open(wrk, "wb") as f:
        f.write(b"fake wrk")
    os.chmod(wrk, 0o755)
    tools["wrk"] = {"kind": "system", "version": "4", "path": wrk, "sha256": sha(b"fake wrk"),
                    "status": status}
    tools["loadgen"] = {"kind": "builtin", "version": "1", "path": "bench/loadgen.py",
                        "sha256": LT.sha256_file(os.path.join(REPO, "bench", "loadgen.py")),
                        "status": status}
    tools["wrk2"] = {"kind": "external", "version": "x", "path": "wrk2/wrk2",
                     "sha256": sha(b"x"), "status": "unavailable", "reason": "Lua panic"}
    return {"schema": 1, "root": tmp, "tools": tools}


class ScopeTest(unittest.TestCase):
    def test_testbed_addresses_are_allowed(self):
        self.assertEqual(LT.check_scope("http://10.0.0.1/"), ("10.0.0.1", 80))
        self.assertEqual(LT.check_scope("http://10.0.2.9:8080/x?y=1"), ("10.0.2.9", 8080))
        self.assertEqual(LT.check_scope("https://10.0.1.3/"), ("10.0.1.3", 443))

    def test_everything_else_is_refused(self):
        for url in ("http://8.8.8.8/", "http://example.com/", "http://10.1.0.1/",
                    "http://10.0.0.1.evil.example/", "http://2130706433/", "http://010.0.0.1/",
                    "http://0.0.0.0/", "http://[::1]/", "http://127.0.0.1/", "ftp://10.0.0.1/",
                    "http://user:pw@10.0.0.1/", "http://10.0.0.1:99999/", "//10.0.0.1/",
                    "10.0.0.1", "http:///x", "http://[fe80::1%25eth0]/"):
            with self.subTest(url=url), self.assertRaises(LT.ScopeError):
                LT.check_scope(url)

    def test_loopback_only_on_request(self):
        self.assertEqual(LT.check_scope("http://127.0.0.1:18081/", True), ("127.0.0.1", 18081))
        self.assertEqual(LT.check_scope("http://[::1]/", True)[0], "::1")
        self.assertEqual(LT.check_scope("http://10.0.0.1/", True)[0], "10.0.0.1")
        for url in ("http://192.168.1.1/", "http://10.1.0.1/", "http://example.com/"):
            with self.subTest(url=url), self.assertRaises(LT.ScopeError):
                LT.check_scope(url, True)

    def test_the_source_address_is_checked_too(self):
        with self.assertRaises(LT.ScopeError):
            LT.validate(dataclasses.replace(SPEC, local_addr="192.168.0.5"))
        with self.assertRaises(LT.ScopeError):
            LT.validate(dataclasses.replace(SPEC, local_addr="127.0.0.1"))
        LT.validate(dataclasses.replace(SPEC, local_addr="127.0.0.1", allow_loopback=True,
                                        url="http://127.0.0.1/"))


class SpecTest(unittest.TestCase):
    def test_a_valid_spec_passes(self):
        LT.validate(SPEC)

    def test_bad_values_are_refused(self):
        bad = {"rate": 0, "duration": 0.5, "timeout": 0, "method": "POST",
               "headers": ("no colon",), "cpus": "a-b", "name": "has space",
               "workers": 0, "max_workers": 10}
        for key, value in bad.items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                LT.validate(dataclasses.replace(SPEC, **{key: value}))
        with self.assertRaises(ValueError):
            LT.validate(dataclasses.replace(SPEC, headers=("X: a\r\nHost: evil",)))
        with self.assertRaises(ValueError):
            LT.validate(dataclasses.replace(SPEC, rate=float("nan")))

    def test_rate_parts(self):
        self.assertEqual(LT.rate_parts(100), (100, 1))
        self.assertEqual(LT.rate_parts(12.5), (25, 2))
        self.assertEqual(LT.rate_parts(0.5), (1, 2))
        n, s = LT.rate_parts(33.3)
        self.assertLessEqual(abs(n / s - 33.3), 0.005 * 33.3)
        n, s = LT.rate_parts(0.0123)
        self.assertGreaterEqual(n, 1)


class ManifestTest(unittest.TestCase):
    def test_the_committed_manifest_is_valid(self):
        m = LT.load_manifest()
        self.assertEqual(set(m["tools"]), {"vegeta", "k6", "wrk", "loadgen", "wrk2"})

    def test_stage_1_facts_are_pinned(self):
        t = LT.load_manifest()["tools"]
        self.assertEqual(t["vegeta"]["version"], "v12.13.0")
        self.assertEqual(t["vegeta"]["archive_sha256"],
                         "e8759ce45c14e18374bdccd3ba6068197bc3a9f9b7e484db3837f701b9d12e61")
        self.assertEqual(t["k6"]["version"], "v2.3.0")
        self.assertEqual(t["k6"]["archive_sha256"],
                         "39c3117b6af817592dcd0ce4242105c0a7af10948c2a425306f0be8f7a8a8ab1")
        self.assertEqual(t["wrk2"]["status"], "unavailable")
        self.assertIn("PANIC", t["wrk2"]["reason"])
        self.assertEqual(t["wrk"]["kind"], "system")

    def test_the_builtin_engine_is_pinned_to_its_file(self):
        import loadgen
        t = LT.load_manifest()["tools"]["loadgen"]
        self.assertEqual(t["kind"], "builtin")
        self.assertEqual(t["sha256"], LT.sha256_file(os.path.join(REPO, "bench", "loadgen.py")),
                         "bench/loadgen.py changed: pin its new sha256 in bench/loadtools.json "
                         "and verify it again")
        self.assertEqual(t["version"], loadgen.ENGINE_VERSION)

    def test_nothing_is_runnable_before_the_verification(self):
        for name, t in LT.load_manifest()["tools"].items():
            if t["status"] in LT.RUNNABLE:
                self.fail(f"{name} is marked verified: that needs the V-test results first")

    def test_invalid_manifests(self):
        with tempfile.TemporaryDirectory() as tmp:
            good = fake_root(tmp)
        LT.validate_manifest(json.loads(json.dumps(good)))
        for mutate in (lambda m: m.update(schema=2),
                       lambda m: m["tools"]["vegeta"].update(status="great"),
                       lambda m: m["tools"]["vegeta"].update(sha256="abc"),
                       lambda m: m["tools"]["vegeta"].update(kind="other"),
                       lambda m: m["tools"]["wrk2"].pop("reason"),
                       lambda m: m["tools"]["k6"].pop("path")):
            m = json.loads(json.dumps(good))
            mutate(m)
            with self.assertRaises(LT.ToolError):
                LT.validate_manifest(m)

    def test_resolve_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            m = fake_root(tmp)
            self.assertEqual(LT.resolve_tool(m, "vegeta", tmp),
                             os.path.join(tmp, "vegeta-12.13.0", "vegeta"))
            self.assertEqual(LT.resolve_tool(m, "wrk", tmp), os.path.join(tmp, "system", "wrk"))
            with self.assertRaisesRegex(LT.ToolError, "unavailable.*Lua panic"):
                LT.resolve_tool(m, "wrk2", tmp, allow_unverified=True)
            with self.assertRaisesRegex(LT.ToolError, "unknown tool"):
                LT.resolve_tool(m, "ab", tmp)

    def test_a_changed_or_missing_binary_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            m = fake_root(tmp)
            path = os.path.join(tmp, "k6-2.3.0", "k6")
            with open(path, "ab") as f:
                f.write(b" tampered")
            with self.assertRaisesRegex(LT.ToolError, "binary changed"):
                LT.resolve_tool(m, "k6", tmp)
            LT.resolve_tool(m, "k6", tmp, check=False)           # the hash check is the point
            os.remove(path)
            with self.assertRaisesRegex(LT.ToolError, "missing"):
                LT.resolve_tool(m, "k6", tmp)

    def test_only_verified_tools_run_unless_asked(self):
        with tempfile.TemporaryDirectory() as tmp:
            m = fake_root(tmp, status="smoke-tested")
            with self.assertRaisesRegex(LT.ToolError, "not 'verified'"):
                LT.resolve_tool(m, "vegeta", tmp)
            LT.resolve_tool(m, "vegeta", tmp, allow_unverified=True)
            m["tools"]["vegeta"].update(status="unfit", reason="failed V2")
            with self.assertRaisesRegex(LT.ToolError, "unfit"):
                LT.resolve_tool(m, "vegeta", tmp, allow_unverified=True)

    def test_probe_version_compares_with_the_pin(self):
        with tempfile.TemporaryDirectory() as tmp:
            m = fake_root(tmp)
            script = b"#!/bin/sh\necho 'Version: v12.13.0'\n"
            path = os.path.join(tmp, "vegeta-12.13.0", "vegeta")
            with open(path, "wb") as f:
                f.write(script)
            m["tools"]["vegeta"].update(sha256=sha(script), version="v12.13.0")
            out, ok = LT.probe_version(m, "vegeta", tmp)
            self.assertEqual((out, ok), ("Version: v12.13.0", True))
            m["tools"]["vegeta"]["version"] = "v13.0.0"
            self.assertFalse(LT.probe_version(m, "vegeta", tmp)[1])

    def test_a_builtin_tool_is_a_file_of_the_repository(self):
        with tempfile.TemporaryDirectory() as tmp:
            m = fake_root(tmp)
            self.assertEqual(LT.resolve_tool(m, "loadgen", tmp),
                             os.path.join(REPO, "bench", "loadgen.py"))
            self.assertEqual(LT.probe_version(m, "loadgen", tmp), ("loadgen 1", True))
            m["tools"]["loadgen"]["version"] = "2"
            self.assertFalse(LT.probe_version(m, "loadgen", tmp)[1])
            m["tools"]["loadgen"]["sha256"] = "0" * 64
            with self.assertRaisesRegex(LT.ToolError, "binary changed"):
                LT.resolve_tool(m, "loadgen", tmp)

    def test_the_tools_directory_comes_from_the_environment(self):
        m = {"root": "~/somewhere", "tools": {}}
        self.assertTrue(LT.tools_root(m).endswith("somewhere"))
        old = os.environ.get("LOADTOOLS_DIR")
        os.environ["LOADTOOLS_DIR"] = "/opt/elsewhere"
        try:
            self.assertEqual(LT.tools_root(m), "/opt/elsewhere")
            self.assertEqual(LT.tools_root(m, "/explicit"), "/explicit")
        finally:
            if old is None:
                del os.environ["LOADTOOLS_DIR"]
            else:
                os.environ["LOADTOOLS_DIR"] = old


class BuilderTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.m = fake_root(self.tmp)
        self.wd = os.path.join(self.tmp, "run")
        self.addCleanup(self._tmp.cleanup)

    def plan(self, tool, spec=SPEC, **kw):
        return LT.build_plan(tool, spec, self.wd, self.m, self.tmp, **kw)

    def test_vegeta_command_lines(self):
        p = self.plan("vegeta")
        exe, wd = os.path.join(self.tmp, "vegeta-12.13.0", "vegeta"), self.wd
        self.assertEqual(p.steps[0].argv, [
            "taskset", "-c", "4-7", exe, "attack", "-rate=100/1s", "-duration=10s",
            "-timeout=10s", "-workers=50", "-max-workers=5000", "-connections=100",
            "-keepalive=true", "-http2=false", "-redirects=-1", "-max-body=0", "-name=smoke",
            f"-targets={wd}/vegeta.targets", f"-output={wd}/vegeta.bin", "-header=X-A: b",
            "-laddr=10.0.2.5"])
        self.assertEqual(p.steps[1].argv, [exe, "report", "-type=json",
                                           f"-output={wd}/vegeta.report.json", f"{wd}/vegeta.bin"])
        self.assertEqual(p.steps[2].argv, [exe, "encode", "-to=csv", f"-output={wd}/vegeta.csv",
                                           f"{wd}/vegeta.bin"])
        self.assertEqual(p.inputs, {f"{wd}/vegeta.targets": "GET http://10.0.0.1/\n"})
        self.assertEqual(set(p.files), {"targets", "bin", "report", "csv"})

    def test_vegeta_never_follows_redirects_and_uses_http_1(self):
        argv = self.plan("vegeta").steps[0].argv
        self.assertIn("-redirects=-1", argv)
        self.assertIn("-http2=false", argv)

    def test_k6_command_line(self):
        p = self.plan("k6")
        exe, wd = os.path.join(self.tmp, "k6-2.3.0", "k6"), self.wd
        step = p.steps[0]
        self.assertEqual(step.argv, [
            "taskset", "-c", "4-7", exe, "run", "--quiet", "--no-usage-report", "--no-color",
            "--no-thresholds", "-e", "URL=http://10.0.0.1/", "-e", "METHOD=GET",
            "-e", 'HEADERS={"X-A":"b"}', "-e", "RATE=100", "-e", "TIME_UNIT=1s",
            "-e", "DURATION=10s", "-e", "TIMEOUT=10s", "-e", "PRE_VUS=50", "-e", "MAX_VUS=5000",
            "-e", f"OUT={wd}/k6.summary.json", "--local-ips=10.0.2.5", f"{wd}/k6.js"])
        self.assertEqual(step.env, {"K6_NO_USAGE_REPORT": "true"})
        self.assertEqual(p.inputs, {f"{wd}/k6.js": LT.K6_SCRIPT})

    def test_k6_never_reports_usage_and_the_script_stays_on_the_net(self):
        step = self.plan("k6").steps[0]
        self.assertIn("--no-usage-report", step.argv)
        self.assertEqual(step.env["K6_NO_USAGE_REPORT"], "true")
        self.assertNotIn("http://", LT.K6_SCRIPT)                # no URL, no remote import
        self.assertNotIn("https://", LT.K6_SCRIPT)
        self.assertIn("redirects: 0", LT.K6_SCRIPT)
        self.assertIn("constant-arrival-rate", LT.K6_SCRIPT)
        self.assertIn("handleSummary", LT.K6_SCRIPT)

    def test_k6_fractional_rate_becomes_a_ratio(self):
        argv = self.plan("k6", dataclasses.replace(SPEC, rate=12.5, headers=())).steps[0].argv
        self.assertIn("RATE=25", argv)
        self.assertIn("TIME_UNIT=2s", argv)
        self.assertIn("HEADERS={}", argv)

    def test_wrk_command_line(self):
        spec = dataclasses.replace(SPEC, local_addr="", connections=50, threads=2)
        argv = self.plan("wrk", spec).steps[0].argv
        self.assertEqual(argv, ["taskset", "-c", "4-7", os.path.join(self.tmp, "system", "wrk"),
                                "-t2", "-c50", "-d10s", "--timeout", "10s", "--latency",
                                "-H", "X-A: b", "http://10.0.0.1/"])

    def test_wrk_refuses_what_it_cannot_do(self):
        with self.assertRaises(LT.ToolError):
            self.plan("wrk")                                     # SPEC has a source address
        with self.assertRaises(LT.ToolError):
            self.plan("wrk", dataclasses.replace(SPEC, local_addr="", method="HEAD"))

    def test_loadgen_command_line(self):
        p = self.plan("loadgen")
        wd = self.wd
        self.assertEqual(p.steps[0].argv, [
            "taskset", "-c", "4-7", sys.executable, os.path.join(REPO, "bench", "loadgen.py"),
            "--url", "http://10.0.0.1/", "--rate", "100", "--duration", "10", "--timeout", "10",
            "--max-inflight", "5000", "--pool", "100", "--method", "GET",
            "--summary", f"{wd}/loadgen.summary.json", "--records", f"{wd}/loadgen.records.csv.gz",
            "--header", "X-A: b", "--local-addr", "10.0.2.5"])
        self.assertEqual(p.inputs, {})
        loop = self.plan("loadgen", dataclasses.replace(SPEC, url="http://127.0.0.1:1/",
                                                        local_addr="", allow_loopback=True))
        self.assertIn("--allow-loopback", loop.steps[0].argv)
        self.assertNotIn("--allow-loopback", p.steps[0].argv)

    def test_no_pinning_without_cpus(self):
        argv = self.plan("vegeta", dataclasses.replace(SPEC, cpus="")).steps[0].argv
        self.assertEqual(argv[0], os.path.join(self.tmp, "vegeta-12.13.0", "vegeta"))

    def test_the_scope_lock_applies_before_anything_is_built(self):
        for url in ("http://8.8.8.8/", "http://example.com/"):
            with self.assertRaises(LT.ScopeError):
                self.plan("vegeta", dataclasses.replace(SPEC, url=url))
        with self.assertRaises(LT.ScopeError):
            self.plan("vegeta", dataclasses.replace(SPEC, url="http://127.0.0.1/"))
        self.plan("vegeta", dataclasses.replace(SPEC, url="http://127.0.0.1/", local_addr="",
                                                allow_loopback=True))

    def test_tools_that_must_not_run_are_refused(self):
        with self.assertRaises(LT.ToolError):
            self.plan("wrk2")                                    # no builder
        self.m["tools"]["k6"]["status"] = "smoke-tested"
        with self.assertRaisesRegex(LT.ToolError, "not 'verified'"):
            self.plan("k6")
        self.plan("k6", allow_unverified=True)
        self.m["tools"]["k6"].update(status="unavailable", reason="r")
        with self.assertRaisesRegex(LT.ToolError, "unavailable"):
            self.plan("k6", allow_unverified=True)

    def test_a_changed_binary_stops_the_plan(self):
        with open(os.path.join(self.tmp, "vegeta-12.13.0", "vegeta"), "ab") as f:
            f.write(b"x")
        with self.assertRaises(LT.ToolError):
            self.plan("vegeta")
        self.plan("vegeta", check=False)

    def test_building_a_plan_writes_nothing(self):
        self.plan("vegeta")
        self.assertFalse(os.path.exists(self.wd))


VEGETA_REPORT = {
    "latencies": {"total": 1641000000, "mean": 1641000, "50th": 1052000, "90th": 2709000,
                  "95th": 4887000, "99th": 13138000, "max": 28659000, "min": 79189},
    "bytes_in": {"total": 3000, "mean": 3}, "bytes_out": {"total": 0, "mean": 0},
    "earliest": "2026-10-22T07:48:00Z", "latest": "2026-10-22T07:48:10Z",
    "end": "2026-10-22T07:48:10Z", "duration": 9990000000, "wait": 555845,
    "requests": 1000, "rate": 100.1, "throughput": 100.09, "success": 1.0,
    "status_codes": {"200": 1000}, "errors": [],
}

K6_SUMMARY = {
    "schema": 1, "duration_ms": 10003.2, "requests": 1001, "iterations": 1001,
    "dropped_iterations": 0,
    "status": {"2xx": 1001, "3xx": 0, "4xx": 0, "5xx": 0, "other": 0},
    "latency_ms": {"avg": 1.02, "min": 0.077, "p50": 0.83, "p90": 1.8, "p95": 2.4, "p99": 4.1,
                   "p999": 6.0, "max": 6.37},
}

WRK_OUT = """\
Running 10s test @ http://10.0.0.1/
  2 threads and 100 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     2.50ms    1.20ms  45.10ms   91.20%
    Req/Sec    20.01k     1.23k   24.10k    75.00%
  Latency Distribution
     50%    2.10ms
     75%    2.80ms
     90%    3.90ms
     99%    8.70ms
  399001 requests in 10.00s, 59.50MB read
  Socket errors: connect 1, read 2, write 3, timeout 4
  Non-2xx or 3xx responses: 12
Requests/sec:  39896.74
Transfer/sec:      5.95MB
"""


def write(path, text):
    with open(path, "w") as f:
        f.write(text)


class ParserTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    def test_quantile_matches_numpy(self):
        import numpy as np
        rng = random.Random(7)
        for n in (1, 2, 5, 101, 1000):
            values = sorted(rng.random() for _ in range(n))
            for q in (0, .01, .5, .9, .99, 1):
                self.assertAlmostEqual(LT.quantile(values, q), float(np.percentile(values, q * 100)),
                                       places=12)
        self.assertIsNone(LT.quantile([], .5))

    def test_vegeta_report(self):
        path = os.path.join(self.tmp, "r.json")
        write(path, json.dumps(VEGETA_REPORT))
        r = LT.parse_vegeta(path)
        self.assertEqual((r.requests, r.responses, r.ok2xx, r.non2xx, r.errors),
                         (1000, 1000, 1000, 0, 0))
        self.assertAlmostEqual(r.latency["p50"], 0.001052)
        self.assertAlmostEqual(r.latency["p99"], 0.013138)
        self.assertAlmostEqual(r.duration, 9.99)
        self.assertEqual(r.quantiles, "tdigest")

    def test_vegeta_report_with_failures(self):
        rep = dict(VEGETA_REPORT, requests=1000, status_codes={"200": 900, "503": 90, "0": 10},
                   errors=["Get http://x: timeout"])
        path = os.path.join(self.tmp, "r.json")
        write(path, json.dumps(rep))
        r = LT.parse_vegeta(path)
        self.assertEqual((r.responses, r.ok2xx, r.non2xx, r.errors), (990, 900, 90, 10))
        self.assertEqual(r.extra["error_set"], ["Get http://x: timeout"])

    def test_vegeta_csv_gives_exact_quantiles(self):
        rep = dict(VEGETA_REPORT, requests=5, status_codes={"200": 3, "503": 1, "0": 1})
        rows = [(1_000_000_000, 200, 1_000_000), (1_010_000_000, 200, 2_000_000),
                (1_020_000_000, 200, 3_000_000), (1_030_000_000, 503, 4_000_000),
                (1_040_000_000, 0, 100_000_000)]
        write(os.path.join(self.tmp, "r.json"), json.dumps(rep))
        write(os.path.join(self.tmp, "r.csv"),
              "".join(f"{ts},{code},{lat},0,3,,,smoke,{i},GET,http://10.0.0.1/,\n"
                      for i, (ts, code, lat) in enumerate(rows)))
        r = LT.parse_vegeta(os.path.join(self.tmp, "r.json"), os.path.join(self.tmp, "r.csv"))
        self.assertEqual(r.quantiles, "exact")
        self.assertAlmostEqual(r.latency["p50"], 0.003)
        self.assertAlmostEqual(r.latency["p90"], 0.004 + (0.1 - 0.004) * 0.6)
        self.assertAlmostEqual(r.latency["max"], 0.1)
        self.assertAlmostEqual(r.extra["latency_2xx"]["max"], 0.003)
        self.assertEqual((r.extra["first_ts_ns"], r.extra["last_ts_ns"]),
                         (1_000_000_000, 1_040_000_000))
        self.assertEqual(r.extra["sent_per_s"], [5])

    def test_sent_per_second(self):
        s = 1_000_000_000
        self.assertEqual(LT.sent_per_second([]), [])
        self.assertEqual(LT.sent_per_second([5 * s, 5 * s + 1, 6 * s - 1, 6 * s, 8 * s + 5]),
                         [3, 1, 0, 1])

    def test_vegeta_csv_that_disagrees_with_the_report_is_refused(self):
        write(os.path.join(self.tmp, "r.json"), json.dumps(VEGETA_REPORT))
        write(os.path.join(self.tmp, "r.csv"), "1,200,1000000,0,3,,,a,0,GET,u,\n")
        with self.assertRaisesRegex(LT.ToolError, "1 rows but the report counts 1000"):
            LT.parse_vegeta(os.path.join(self.tmp, "r.json"), os.path.join(self.tmp, "r.csv"))

    def test_unreadable_reports_are_refused(self):
        write(os.path.join(self.tmp, "bad.json"), "{not json")
        write(os.path.join(self.tmp, "other.json"), "{}")
        for fn, name in ((LT.parse_vegeta, "bad.json"), (LT.parse_vegeta, "other.json"),
                         (LT.parse_vegeta, "missing.json"), (LT.parse_k6, "bad.json"),
                         (LT.parse_k6, "other.json"), (LT.parse_wrk, "bad.json"),
                         (LT.parse_wrk, "missing.out")):
            with self.subTest(fn=fn.__name__, name=name), self.assertRaises(LT.ToolError):
                fn(os.path.join(self.tmp, name))

    def test_k6_summary(self):
        write(os.path.join(self.tmp, "s.json"), json.dumps(K6_SUMMARY))
        r = LT.parse_k6(os.path.join(self.tmp, "s.json"))
        self.assertEqual((r.requests, r.responses, r.ok2xx, r.non2xx, r.errors, r.dropped),
                         (1001, 1001, 1001, 0, 0, 0))
        self.assertAlmostEqual(r.latency["p50"], 0.00083)
        self.assertAlmostEqual(r.latency["p99"], 0.0041)
        self.assertAlmostEqual(r.duration, 10.0032)
        self.assertEqual(r.extra["iterations"], 1001)

    def test_k6_summary_with_failures_and_drops(self):
        s = json.loads(json.dumps(K6_SUMMARY))
        s.update(requests=1000, dropped_iterations=37)
        s["status"].update({"2xx": 800, "5xx": 150, "other": 50})
        s["latency_ms"]["p99"] = None
        write(os.path.join(self.tmp, "s.json"), json.dumps(s))
        r = LT.parse_k6(os.path.join(self.tmp, "s.json"))
        self.assertEqual((r.responses, r.ok2xx, r.non2xx, r.errors, r.dropped),
                         (950, 800, 150, 50, 37))
        self.assertIsNone(r.latency["p99"])

    def test_loadgen_summary(self):
        s = {"sent": 990, "dropped": 10, "completed": 980, "wall_s": 10.2,
             "status": {"200": 900, "503": 80}, "errors": {"timeout": 10, "dropped": 10},
             "latency_s": {"mean": 0.02, "min": 0.001, "p50": 0.005, "p90": 0.01, "p95": 0.02,
                           "p99": 0.5, "max": 0.9},
             "slip_s": {"p99": 0.01}, "service_s": {"p99": 0.4}, "cpu": {"share": 0.4},
             "spin_ms": 0, "per_second": {"sent": [99] * 10},
             "flags": {"slip": False, "dropped": True}, "valid": False}
        write(os.path.join(self.tmp, "l.json"), json.dumps(s))
        r = LT.parse_loadgen(os.path.join(self.tmp, "l.json"))
        self.assertEqual((r.requests, r.responses, r.ok2xx, r.non2xx, r.errors, r.dropped),
                         (990, 980, 900, 80, 10, 10))
        self.assertEqual(r.latency["p99"], 0.5)
        self.assertEqual(r.quantiles, "exact-intended-time")
        self.assertEqual((r.extra["valid"], r.extra["flags"]["dropped"]), (False, True))
        self.assertEqual(r.extra["error_classes"], {"timeout": 10, "dropped": 10})
        write(os.path.join(self.tmp, "loadgen.summary.json"), json.dumps(s))
        self.assertEqual(LT.parse_dir("loadgen", self.tmp).tool, "loadgen")
        write(os.path.join(self.tmp, "bad.json"), "{}")
        with self.assertRaises(LT.ToolError):
            LT.parse_loadgen(os.path.join(self.tmp, "bad.json"))

    def test_wrk_output(self):
        write(os.path.join(self.tmp, "w.out"), WRK_OUT)
        r = LT.parse_wrk(os.path.join(self.tmp, "w.out"))
        self.assertEqual((r.requests, r.non2xx, r.errors, r.ok2xx), (399001, 12, 10, 398989))
        self.assertAlmostEqual(r.latency["p50"], 0.0021)
        self.assertAlmostEqual(r.latency["p90"], 0.0039)
        self.assertAlmostEqual(r.latency["p99"], 0.0087)
        self.assertAlmostEqual(r.latency["mean"], 0.0025)
        self.assertAlmostEqual(r.latency["max"], 0.0451)
        self.assertAlmostEqual(r.duration, 10.0)
        self.assertAlmostEqual(r.extra["rate"], 39896.74)
        self.assertTrue(r.extra["closed_loop"])

    def test_wrk_output_in_other_units(self):
        text = WRK_OUT.replace("2.10ms", "850.00us").replace("10.00s,", "1.50m,")
        write(os.path.join(self.tmp, "w.out"), text)
        r = LT.parse_wrk(os.path.join(self.tmp, "w.out"))
        self.assertAlmostEqual(r.latency["p50"], 0.00085)
        self.assertAlmostEqual(r.duration, 90.0)

    def test_parse_dir_finds_the_files_a_plan_writes(self):
        write(os.path.join(self.tmp, "vegeta.report.json"), json.dumps(VEGETA_REPORT))
        self.assertEqual(LT.parse_dir("vegeta", self.tmp).quantiles, "tdigest")
        write(os.path.join(self.tmp, "k6.summary.json"), json.dumps(K6_SUMMARY))
        self.assertEqual(LT.parse_dir("k6", self.tmp).tool, "k6")
        write(os.path.join(self.tmp, "wrk.out"), WRK_OUT)
        self.assertEqual(LT.parse_dir("wrk", self.tmp).tool, "wrk")
        with self.assertRaises(LT.ToolError):
            LT.parse_dir("wrk2", self.tmp)


class RunPlanTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    def plan(self, steps, tool="vegeta", inputs=None):
        return LT.Plan(tool, SPEC, os.path.join(self.tmp, "run"), steps, {}, inputs or {},
                       {"version": "v1", "sha256": "0" * 64, "status": "verified", "path": "x"})

    def test_steps_run_in_order_and_leave_provenance(self):
        out = os.path.join(self.tmp, "run", "out.txt")
        py = [sys.executable, "-c"]
        plan = self.plan([LT.Step("one", py + ["print('hi')"], stdout=out),
                          LT.Step("two", py + ["import sys; print('e', file=sys.stderr)"],
                                  stderr=os.path.join(self.tmp, "run", "err.txt"))],
                         inputs={os.path.join(self.tmp, "run", "in.txt"): "text"})
        prov = LT.run_plan(plan)
        self.assertTrue(prov["ok"])
        self.assertEqual([s["returncode"] for s in prov["steps"]], [0, 0])
        with open(out) as f:
            self.assertEqual(f.read(), "hi\n")
        with open(os.path.join(self.tmp, "run", "err.txt")) as f:
            self.assertEqual(f.read(), "e\n")
        with open(os.path.join(self.tmp, "run", "in.txt")) as f:
            self.assertEqual(f.read(), "text")
        with open(os.path.join(self.tmp, "run", "provenance.json")) as f:
            on_disk = json.load(f)
        self.assertEqual(on_disk["steps"][0]["argv"], py + ["print('hi')"])
        self.assertEqual(on_disk["spec"]["url"], "http://10.0.0.1/")
        self.assertEqual(on_disk["tool_info"]["status"], "verified")
        for key in ("started_utc", "finished_utc", "children_cpu_s", "git", "host",
                    "manifest_sha256"):
            self.assertIn(key, on_disk)
        self.assertIsNone(on_disk["script_sha256"])

    def test_the_first_failure_stops_the_run(self):
        py = [sys.executable, "-c"]
        plan = self.plan([LT.Step("bad", py + ["raise SystemExit(3)"]),
                          LT.Step("never", py + ["print(1)"])])
        prov = LT.run_plan(plan)
        self.assertFalse(prov["ok"])
        self.assertEqual([s["label"] for s in prov["steps"]], ["bad"])
        self.assertEqual(prov["steps"][0]["returncode"], 3)

    def test_a_step_that_times_out_is_recorded(self):
        plan = self.plan([LT.Step("slow", [sys.executable, "-c", "import time; time.sleep(30)"],
                                  timeout=0.5)])
        prov = LT.run_plan(plan)
        self.assertFalse(prov["ok"])
        self.assertEqual(prov["steps"][0]["returncode"], "timeout")

    def test_step_environment_is_added_to_the_inherited_one(self):
        seen = {}

        def runner(argv, env, stdout, stderr, timeout, check):
            seen.update(env=env, timeout=timeout, check=check)
            return type("CP", (), {"returncode": 0})()

        plan = self.plan([LT.Step("k", ["x"], env={"K6_NO_USAGE_REPORT": "true"}, timeout=5)],
                         tool="k6")
        prov = LT.run_plan(plan, runner=runner)
        self.assertEqual(seen["env"]["K6_NO_USAGE_REPORT"], "true")
        self.assertIn("PATH", seen["env"])
        self.assertEqual((seen["timeout"], seen["check"]), (5, False))
        self.assertEqual(prov["script_sha256"], hashlib.sha256(LT.K6_SCRIPT.encode()).hexdigest())

    def test_proxy_variables_never_reach_a_tool(self):
        seen = {}

        def runner(argv, env, stdout, stderr, timeout, check):
            seen.update(env)
            return type("CP", (), {"returncode": 0})()

        saved = {k: os.environ.get(k) for k in ("HTTP_PROXY", "https_proxy", "NO_PROXY")}
        os.environ.update({"HTTP_PROXY": "http://proxy.example:3128",
                           "https_proxy": "http://proxy.example:3128", "NO_PROXY": "10.0.0.0/8"})
        try:
            prov = LT.run_plan(self.plan([LT.Step("x", ["x"])]), runner=runner)
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        self.assertNotIn("HTTP_PROXY", seen)
        self.assertNotIn("https_proxy", seen)
        self.assertEqual((seen["NO_PROXY"], seen["no_proxy"]), ("*", "*"))
        self.assertIn("PATH", seen)
        self.assertEqual(prov["proxy_vars_removed"], ["HTTP_PROXY", "NO_PROXY", "https_proxy"])
        env = LT.clean_env({"A": "1", "ALL_PROXY": "x", "http_proxy": "y"})
        self.assertEqual(env, {"A": "1", "NO_PROXY": "*", "no_proxy": "*"})


class CliTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.addCleanup(self._tmp.cleanup)
        self.m = fake_root(self.tmp)
        self.manifest = os.path.join(self.tmp, "m.json")
        write(self.manifest, json.dumps(self.m))

    def call(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = LT.main(list(argv))
        return rc, out.getvalue(), err.getvalue()

    def base(self, cmd, tool="vegeta", url="http://10.0.0.1/"):
        return [cmd, tool, "--url", url, "--rate", "100", "--duration", "10", "--manifest",
                self.manifest, "--root", self.tmp, "--allow-unverified"]

    def test_plan_prints_the_commands_and_sends_nothing(self):
        rc, out, _ = self.call(*self.base("plan"))
        self.assertEqual(rc, 0)
        lines = out.strip().splitlines()
        self.assertEqual(len(lines), 3)
        self.assertIn("attack -rate=100/1s -duration=10s", lines[0])
        self.assertTrue(lines[1].endswith("vegeta.bin") and " report " in lines[1])

    def test_plan_refuses_a_target_outside_the_testbed(self):
        rc, out, err = self.call(*self.base("plan", url="http://8.8.8.8/"))
        self.assertEqual(rc, 2)
        self.assertEqual(out, "")
        self.assertIn("outside the testbed net", err)

    def test_plan_refuses_an_unverified_tool_without_the_flag(self):
        argv = [a for a in self.base("plan") if a != "--allow-unverified"]
        self.m["tools"]["vegeta"]["status"] = "smoke-tested"
        write(self.manifest, json.dumps(self.m))
        rc, _, err = self.call(*argv)
        self.assertEqual(rc, 2)
        self.assertIn("not 'verified'", err)

    def test_run_refuses_before_it_runs_anything(self):
        rc, _out, err = self.call(*self.base("run", url="http://example.com/"), "--out",
                                 os.path.join(self.tmp, "o"))
        self.assertEqual(rc, 2)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "o")))
        self.assertIn("not an IP literal", err)

    def test_list_shows_status_and_hash_state(self):
        rc, out, _ = self.call("list", "--manifest", self.manifest, "--root", self.tmp)
        self.assertEqual(rc, 0)
        rows = {line.split()[0]: line for line in out.strip().splitlines()}
        self.assertIn("hash ok", rows["vegeta"])
        self.assertIn("missing", rows["wrk2"])
        self.assertIn("unavailable", rows["wrk2"])
        with open(os.path.join(self.tmp, "k6-2.3.0", "k6"), "ab") as f:
            f.write(b"x")
        self.assertIn("HASH DIFFERS", self.call("list", "--manifest", self.manifest,
                                                "--root", self.tmp)[1])
        self.assertIn("not checked", self.call("list", "--no-hash", "--manifest", self.manifest,
                                               "--root", self.tmp)[1])

    def test_parse_reads_an_earlier_run(self):
        write(os.path.join(self.tmp, "wrk.out"), WRK_OUT)
        rc, out, _ = self.call("parse", "wrk", self.tmp)
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["requests"], 399001)
        rc, _, err = self.call("parse", "k6", self.tmp)
        self.assertEqual(rc, 2)
        self.assertIn("k6.summary.json", err)


if __name__ == "__main__":
    unittest.main()
