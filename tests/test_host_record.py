"""The host against the record (docs/RECALIBRATION_2026-11_DESIGN.md K5, D2): a VM step refuses when the kernel release or MemTotal
(within 1 %) differs from a frozen record's host, and a calibration session refuses a step whose kernel or memory differs from its first
step's. Offline commands are unaffected. On the simulated host only."""
import contextlib
import io
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
for sub in ("bench", "eval"):
    sys.path.insert(0, os.path.join(REPO, sub))
import calibrate as K
import calibration as C
import executor as X
import gate_campaign as GC
import sim_host as S

RECORD = os.path.join(REPO, "bench", "calibration", "ddos-mitigation-2026-11-04.json")
HG4 = os.path.join(REPO, "bench", "scenarios", "cheap_static_flood_hg4.json")
NOW = {"uname": "Linux ddos-mitigation 7.0.0-42-generic #42-Ubuntu SMP PREEMPT_DYNAMIC Thu Nov  5 2026 x86_64 ", "mem_mib": 7422}


def run(main, *argv, host=None):
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.object(X.signal, "signal"), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv), host=host) if host is not None else main(list(argv))
    return code, out.getvalue(), err.getvalue()


class RuleTest(unittest.TestCase):
    def test_the_kernel_release_is_the_third_word_of_uname(self):
        self.assertEqual(C.kernel_release(C.load(RECORD)["host"]["uname"]), "7.0.0-38-generic")
        self.assertEqual(C.kernel_release(NOW["uname"]), "7.0.0-42-generic")
        self.assertIsNone(C.kernel_release("Linux"))

    def test_the_record_of_2026_11_04_is_refused_on_the_host_as_it_is_now_with_both_reasons(self):
        with self.assertRaises(C.RecordError) as ctx:
            C.require_host(C.load(RECORD), NOW)
        text = str(ctx.exception)
        self.assertIn("this host is not the one the record was measured on: kernel 7.0.0-42-generic, and the record cff6e515 was "
                      "measured on 7.0.0-38-generic; MemTotal 7422 MiB, and the record cff6e515 was measured with 9426 MiB (more than "
                      "1% apart)", text)
        self.assertIn("calibrate this host anew", text)

    def test_memtotal_within_1_percent_is_the_same_host(self):
        host = C.load(RECORD)["host"]
        same = {"uname": host["uname"]}
        self.assertEqual(C.host_problems(host, {**same, "mem_mib": 9426}), [])
        self.assertEqual(C.host_problems(host, {**same, "mem_mib": 9332}), [], "94 MiB is within 94.26")
        self.assertEqual(len(C.host_problems(host, {**same, "mem_mib": 9331})), 1)
        self.assertEqual(len(C.host_problems(host, {**same, "mem_mib": 9521})), 1)
        self.assertEqual(len(C.host_problems(host, {"uname": NOW["uname"], "mem_mib": 9426})), 1)
        self.assertEqual(C.HOST_MEM_SHARE, 0.01)

    def test_a_placeholder_is_never_refused(self):
        C.require_host(C.load(C.PLACEHOLDER), NOW)


class StepTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_the_drift_step_refuses_a_simulated_7_0_0_42_host_before_any_run(self):
        host = S.SimHost(facts=NOW)
        out = os.path.join(self.tmp.name, "d")
        code, _, err = run(K.main, "drift", "--calibration", RECORD, "--out", out, host=host)
        self.assertEqual(code, K.EXIT_STOPPED)
        self.assertIn("CalibrationStop: this host is not the one the record was measured on: kernel 7.0.0-42-generic", err)
        self.assertFalse(os.path.exists(out))
        self.assertFalse([c for c in host.commands if c[0] == "prim"], "nothing was built")

    def test_a_gate_campaign_refuses_it_too(self):
        host = S.SimHost(facts=NOW)
        out = os.path.join(self.tmp.name, "c")
        code, _, err = run(GC.main, "run", HG4, "--calibration", RECORD, "--out", out, "--modes", "xdp", "--simulate", "pass",
                           host=host)
        self.assertEqual(code, GC.EXIT_STOPPED)
        self.assertIn("CampaignError: this host is not the one the record was measured on", err)
        self.assertFalse(os.path.exists(os.path.join(out, GC.CAMPAIGN)))

    def test_and_so_does_a_single_run_of_the_executor(self):
        host = S.SimHost(facts=NOW)
        code, _, err = run(X.main, "run", HG4, "--calibration", RECORD, "--kind", "C", "--out", os.path.join(self.tmp.name, "r", "C"),
                           host=host)
        self.assertEqual(code, X.EXIT_FAILED)
        self.assertIn("PreflightRefused: this host is not the one the record was measured on", err)

    def test_the_records_own_host_is_not_refused(self):
        for facts in ({}, {"mem_mib": 9400}):
            with self.subTest(facts=facts):
                with mock.patch.object(K, "drift_step_single", return_value={"ok": True}) as step:
                    code, _, _ = run(K.main, "drift", "--calibration", RECORD, "--out", os.path.join(self.tmp.name, "ok"),
                                     host=S.SimHost(facts=facts))
                self.assertEqual(code, K.EXIT_OK)
                step.assert_called_once()

    def test_a_session_refuses_a_step_on_another_kernel_or_memory_than_its_first(self):
        out = os.path.join(self.tmp.name, "s")
        self.assertEqual(run(K.main, "origin", "--out", out, "--simulate")[0], K.EXIT_OK)
        first = K.read_json(os.path.join(out, K.SESSION_HOST))
        self.assertEqual((first["kernel"], first["mem_mib"], first["first_step"]), ("7.0.0-38-generic", 9426, "origin"))
        for facts, said in ((NOW, "kernel 7.0.0-42-generic, and the session's first step (origin) was measured on 7.0.0-38-generic"),
                            ({"mem_mib": 7422}, "MemTotal 7422 MiB, and the session's first step (origin) was measured with 9426 MiB")):
            with self.subTest(facts=facts):
                code, _, err = run(K.main, "capacity", "--out", out, "--levels", "80,160", "--step-s", "10", "--repeats", "1",
                                   host=S.SimHost(facts=facts, origin_costs=dict(C.load(C.PLACEHOLDER)["route_costs_ms"])))
                self.assertEqual(code, K.EXIT_STOPPED)
                self.assertIn("this host is not the one the session began on: " + said, err)
                self.assertFalse(os.path.exists(os.path.join(out, "capacity")), "refused before any run")
        code, _, err = run(K.main, "origin", "--out", out, host=S.SimHost(facts=NOW))
        self.assertEqual(code, K.EXIT_STOPPED, "the origin step made again on another host too")

    def test_offline_commands_are_unaffected(self):
        """plan, freeze, the campaign's plan, publishing and judging again read no host."""
        self.assertEqual(run(K.main, "plan", host=S.SimHost(facts=NOW))[0], K.EXIT_OK)
        self.assertEqual(run(GC.main, "plan", HG4, "--calibration", RECORD, "--modes", "xdp", host=S.SimHost(facts=NOW))[0],
                         GC.EXIT_OK)
        recorded = K.read_json(os.path.join(REPO, "results", "2026-11-11_harm-drift-check", "drift_20261108", "drift", "drift.json"))
        self.assertEqual(K.judge_drift(C.load(RECORD), recorded)["reasons"], recorded["reasons"])
        with mock.patch.object(C, "require_host", side_effect=AssertionError("a host was read")):
            self.assertEqual(run(K.main, "plan")[0], K.EXIT_OK)
            self.assertEqual(run(GC.main, "plan", HG4, "--calibration", RECORD, "--modes", "xdp")[0], GC.EXIT_OK)
            code, _, err = run(K.main, "freeze", "--dir", self.tmp.name, "--out", os.path.join(self.tmp.name, "x.json"))
            self.assertEqual(code, K.EXIT_STOPPED)
            self.assertIn("run `capacity` first", err, "the freeze refuses for its own reason, not the host's")


if __name__ == "__main__":
    unittest.main()
