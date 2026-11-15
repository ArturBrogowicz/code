"""The record names its PC (K10, the user's D-096 of 2026-11-14): the VM has run on two PCs with the same kernel and MemTotal, the desktop
(Intel i7-10700F, VirtualBox 7.2.4) the record of 2026-11-04 was measured on and the laptop (AMD Ryzen 7 7730U, VirtualBox 7.2.10) that
runs every measurement until 2026-12-03. A record of schema 2 carries the CPU model and VirtualBox's host version in its `host`, the
freeze writes them from the session's runs, and K5's checks refuse another PC against a frozen record and within a calibration session,
naming both values. The record of 2026-11-04 (schema 1) names no PC and is judged as before. On the simulated host and fixtures only."""
import contextlib
import copy
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
for sub in ("bench", "bench/packets", "eval"):
    sys.path.insert(0, os.path.join(REPO, sub))
import calibrate as K
import calibration as C
import calibration_fixtures as CF
import executor as X
import gate_campaign as GC
import prechecks as PC
import sim_host as S
import test_executor_run as TER

RECORD = os.path.join(REPO, "bench", "calibration", "ddos-mitigation-2026-11-04.json")
HG4 = os.path.join(REPO, "bench", "scenarios", "cheap_static_flood_hg4.json")
DESKTOP = {"cpu_model": "Intel(R) Core(TM) i7-10700F CPU @ 2.90GHz", "vbox_host_version": "7.2.4r170995"}
LAPTOP = {"cpu_model": "AMD Ryzen 7 7730U with Radeon Graphics", "vbox_host_version": "7.2.10r174163"}
# what the guest's kernel logged at the boot of 2026-11-14 11:41Z (journalctl -k -b 0 -o cat), shortened
JOURNAL = ("ACPI: DSDT 0x00000000DFFF0370 002353 (v02 VBOX   VBOXBIOS 00000002 VBOX 0002A853)\n"
           "smpboot: CPU0: AMD Ryzen 7 7730U with Radeon Graphics (family: 0x19, model: 0x50, stepping: 0x0)\n"
           "vboxguest: host-version: 7.2.10r174163 0x8000000f\n"
           "vboxguest: misc device minor 263, IRQ 20, I/O port d040, MMIO at 00000000f0400000 (size 0x400000)\n")
CPUINFO = ("processor\t: 0\nvendor_id\t: AuthenticAMD\nmodel name\t: AMD Ryzen 7 7730U with Radeon Graphics\ncpu MHz\t\t: 1996.250\n\n"
           "processor\t: 1\nvendor_id\t: AuthenticAMD\nmodel name\t: AMD Ryzen 7 7730U with Radeon Graphics\n")
NOW = {"uname": "Linux ddos-mitigation 7.0.0-42-generic #42-Ubuntu SMP PREEMPT_DYNAMIC x86_64", "mem_mib": 7422}     # K5's test
ON_LAPTOP = "this host is not the one the record was measured on: CPU AMD Ryzen 7 7730U with Radeon Graphics, and the record {sha} was " \
            "measured on Intel(R) Core(TM) i7-10700F CPU @ 2.90GHz; VirtualBox host 7.2.10r174163, and the record {sha} was measured " \
            "under 7.2.4r170995"


def run(main, *argv, host=None):
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.object(X.signal, "signal"), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv), host=host) if host is not None else main(list(argv))
    return code, out.getvalue(), err.getvalue()


def record_v2(tmp, cal=None, pc=None):
    """A frozen record of schema 2 (with knees, for the campaign and the executor) whose host is the simulated host's own but for
    `pc`, written to `tmp`/record.json: (record, path)."""
    cal = CF.frozen_v2(cal or CF.placeholder_with_knees(), host={**CF.SAMPLE_HOST, **(pc or DESKTOP)})
    path = os.path.join(tmp, "record.json")
    C.dump(cal, path)
    return cal, path


class PinnedTest(unittest.TestCase):
    def test_the_pc_keys_the_shape_and_the_programmes_pc(self):
        self.assertEqual(C.PC_KEYS, ("cpu_model", "vbox_host_version"))
        self.assertEqual(C.HOST_SHAPE_V2, {**C.HOST_SHAPE, "cpu_model": str, "vbox_host_version": str})
        self.assertNotIn("cpu_model", C.HOST_SHAPE, "schema 1 is judged as before")
        self.assertEqual(PC.PROGRAMME_HOST, {"uname": "Linux ddos-mitigation 7.0.0-42-generic x86_64", "mem_mib": 7422, **LAPTOP})
        self.assertEqual(S.SIM_PC, DESKTOP)
        self.assertEqual(CF.SAMPLE_PC, DESKTOP)
        self.assertEqual({k: S.SimHost().facts()[k] for k in C.PC_KEYS}, DESKTOP)


class ReadTest(unittest.TestCase):
    def test_the_cpu_model_is_the_first_model_name_of_cpuinfo(self):
        self.assertEqual(C.cpu_model(CPUINFO), LAPTOP["cpu_model"])
        self.assertEqual(C.cpu_model("model name\t:   Intel(R) Core(TM)  i7-10700F CPU @ 2.90GHz  \n"), DESKTOP["cpu_model"])
        for text in ("", None, "processor\t: 0\n", "model name\t:   \n"):
            with self.subTest(text=text):
                self.assertIsNone(C.cpu_model(text))

    def test_virtualboxs_host_version_is_read_from_the_boots_kernel_log(self):
        self.assertEqual(C.vbox_host_version(JOURNAL), "7.2.10r174163")
        self.assertEqual(C.vbox_host_version("[    2.1] vboxguest: host-version: 7.2.4r170995 0x8000000f\n"), "7.2.4r170995")
        for text in ("", None, "vboxguest: misc device minor 263\n"):
            with self.subTest(text=text):
                self.assertIsNone(C.vbox_host_version(text))

    def test_the_real_host_reads_them_from_cpuinfo_and_the_journal_else_dmesg(self):
        class Real(X.RealHost):
            def __init__(self, journal, dmesg):
                super().__init__()
                self.logs, self.calls = {"journalctl": journal, "dmesg": dmesg}, []

            def run(self, argv, ns="", stdin="", env=None, timeout=None):
                self.calls.append(argv)
                return X.Result(0, self.logs.get(argv[0], "nginx version: nginx/1.28.3"), "")

            def read_text(self, path):
                return {"/proc/meminfo": "MemTotal:        7600852 kB\n", "/proc/cpuinfo": CPUINFO}[path]

        host = Real(JOURNAL, "")
        facts = host.facts()
        self.assertEqual({k: facts[k] for k in ("mem_mib", *C.PC_KEYS)}, {"mem_mib": 7422, **LAPTOP})
        self.assertIn(["journalctl", "-k", "-b", "0", "-o", "cat", "--no-pager"], host.calls)
        self.assertNotIn(["dmesg"], host.calls, "the journal had it")
        self.assertEqual(Real("", JOURNAL).facts()["vbox_host_version"], "7.2.10r174163")
        self.assertIsNone(Real("", "").facts()["vbox_host_version"])

    def test_the_prechecks_read_them_the_same_way_and_report_them(self):
        texts = {"/proc/meminfo": "MemTotal:        7600852 kB\n", "/proc/cpuinfo": CPUINFO, "/proc/uptime": "3600.0 100.0\n"}
        with mock.patch.object(PC, "_read", side_effect=texts.__getitem__), \
                mock.patch.object(PC, "_sh", side_effect=lambda argv, timeout=90: JOURNAL if argv[0] == "journalctl" else ""):
            facts = PC._facts()
            self.assertEqual({k: facts[k] for k in ("mem_mib", *C.PC_KEYS)}, {"mem_mib": 7422, **LAPTOP})
            with tempfile.TemporaryDirectory() as tmp, mock.patch.object(PC.os, "uname",
                                                                         return_value=("Linux", "ddos-mitigation", "7.0.0-42-generic",
                                                                                       "#42-Ubuntu", "x86_64")):
                checks = dict(PC.run_all("R1", tmp, 90))
                said = io.StringIO()
                with contextlib.redirect_stdout(said):
                    PC.main(["--packet", "R1", "--session", tmp])
        host = ("host (kernel 7.0.0-42-generic, MemTotal 7422 MiB, CPU AMD Ryzen 7 7730U with Radeon Graphics, VirtualBox host "
                "7.2.10r174163)")
        self.assertEqual(checks[host], [], "the laptop is the programme's PC (D-096)")
        self.assertIn("OK  " + host + "\n", said.getvalue())


class RecordTest(unittest.TestCase):
    def test_the_record_of_2026_11_04_still_loads_with_its_hash_and_names_no_pc(self):
        cal = C.load(RECORD)
        self.assertEqual((cal["schema"], cal["sha256"][:8]), (1, "cff6e515"))
        self.assertEqual(C.pc_unnamed(cal["host"]), list(C.PC_KEYS))

    def test_it_is_not_used_to_refuse_on_the_pc(self):
        cal = C.load(RECORD)
        own = {"uname": cal["host"]["uname"], "mem_mib": cal["host"]["mem_mib"]}
        for pc in (LAPTOP, DESKTOP, {"cpu_model": None, "vbox_host_version": None}):
            with self.subTest(pc=pc):
                self.assertEqual(C.host_problems(cal["host"], {**own, **pc}), [])
                C.require_host(cal, {**own, **pc})
        problems = C.host_problems(cal["host"], {**NOW, **LAPTOP})       # on the laptop as it is now: K5's two reasons, no more
        self.assertEqual([p.split()[0] for p in problems], ["kernel", "MemTotal"])
        self.assertFalse([p for p in problems if "CPU" in p or "VirtualBox" in p])

    def test_the_published_drift_checks_are_judged_as_before(self):
        cal = C.load(RECORD)
        root = os.path.join(REPO, "results", "2026-11-11_harm-drift-check")
        for name in ("drift_20261108", "drift_20261108.second", "drift_20261108_q1", "drift_20261111c_q1", "drift_20261111c_q1.second"):
            with self.subTest(attempt=name):
                recorded = K.read_json(os.path.join(root, name, "drift", "drift.json"))
                self.assertEqual(K.judge_drift(cal, recorded), {"ok": recorded["ok"], "reasons": recorded["reasons"]})

    def test_a_record_of_schema_2_must_name_its_pc(self):
        cal = CF.frozen_v2()
        self.assertEqual({k: cal["host"][k] for k in C.PC_KEYS}, DESKTOP)
        for key in C.PC_KEYS:
            for value, said in ((None, "missing " + key), ("", f"host.{key}: a non-empty string"), (7, f"host.{key}: a non-empty string")):
                with self.subTest(key=key, value=value):
                    host = copy.deepcopy(CF.SAMPLE_HOST_V2)
                    if value is None:
                        del host[key]
                    else:
                        host[key] = value
                    with self.assertRaisesRegex(C.RecordError, said):
                        CF.frozen_v2(host=host)
        CF.frozen(host=CF.SAMPLE_HOST)                    # schema 1 needs none

    def test_another_pc_is_refused_naming_both_values(self):
        cal = CF.frozen_v2()
        facts = {"uname": CF.SAMPLE_HOST["uname"], "mem_mib": CF.SAMPLE_HOST["mem_mib"]}
        C.require_host(cal, {**facts, **DESKTOP})
        with self.assertRaises(C.RecordError) as ctx:
            C.require_host(cal, {**facts, **LAPTOP})
        self.assertIn(ON_LAPTOP.format(sha=cal["sha256"][:8]), str(ctx.exception))
        self.assertIn("calibrate this host anew", str(ctx.exception))
        what = "the record x"
        self.assertEqual(C.host_problems(cal["host"], {**facts, **DESKTOP, "cpu_model": LAPTOP["cpu_model"]}, what),
                         [("CPU AMD Ryzen 7 7730U with Radeon Graphics, and the record x was measured on Intel(R) Core(TM) i7-10700F "
                           "CPU @ 2.90GHz")])
        self.assertEqual(C.host_problems(cal["host"], {**facts, **DESKTOP, "vbox_host_version": "7.2.10r174163"}, what),
                         ["VirtualBox host 7.2.10r174163, and the record x was measured under 7.2.4r170995"])
        self.assertEqual(C.host_problems(cal["host"], {**facts, **DESKTOP, "vbox_host_version": None}, what),
                         ["VirtualBox host not read, and the record x was measured under 7.2.4r170995"])
        self.assertEqual(C.host_problems(cal["host"], {**facts, "cpu_model": " Intel(R) Core(TM)  i7-10700F CPU @ 2.90GHz",
                                                       "vbox_host_version": "7.2.4r170995"}, what), [], "blanks are not a PC")


class StepTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_the_drift_step_refuses_the_other_pc_before_any_run(self):
        cal, path = record_v2(self.tmp.name)
        host = S.SimHost(facts=LAPTOP)
        out = os.path.join(self.tmp.name, "d")
        code, _, err = run(K.main, "drift", "--calibration", path, "--out", out, host=host)
        self.assertEqual(code, K.EXIT_STOPPED)
        self.assertIn("CalibrationStop: " + ON_LAPTOP.format(sha=cal["sha256"][:8]), err)
        self.assertFalse(os.path.exists(out))
        self.assertFalse([c for c in host.commands if c[0] == "prim"], "nothing was built")

    def test_a_gate_campaign_and_an_executor_run_refuse_it_too(self):
        cal, path = record_v2(self.tmp.name)
        out = os.path.join(self.tmp.name, "c")
        code, _, err = run(GC.main, "run", HG4, "--calibration", path, "--out", out, "--modes", "xdp", "--simulate", "pass",
                           host=S.SimHost(facts=LAPTOP))
        self.assertEqual(code, GC.EXIT_STOPPED)
        self.assertIn("CampaignError: " + ON_LAPTOP.format(sha=cal["sha256"][:8]), err)
        self.assertFalse(os.path.exists(os.path.join(out, GC.CAMPAIGN)))
        code, _, err = run(X.main, "run", HG4, "--calibration", path, "--kind", "C", "--out", os.path.join(self.tmp.name, "r", "C"),
                           host=S.SimHost(facts={"vbox_host_version": LAPTOP["vbox_host_version"]}))
        self.assertEqual(code, X.EXIT_FAILED)
        self.assertIn("PreflightRefused: this host is not the one the record was measured on: VirtualBox host 7.2.10r174163, and the "
                      f"record {cal['sha256'][:8]} was measured under 7.2.4r170995", err)

    def test_the_records_own_pc_is_not_refused(self):
        _, path = record_v2(self.tmp.name)
        with mock.patch.object(K, "drift_step", return_value={"ok": True}) as step:
            code, _, _ = run(K.main, "drift", "--calibration", path, "--out", os.path.join(self.tmp.name, "ok"), host=S.SimHost())
        self.assertEqual(code, K.EXIT_OK)
        step.assert_called_once()

    def test_a_session_names_its_pc_in_its_first_step_and_refuses_another(self):
        out = os.path.join(self.tmp.name, "s")
        self.assertEqual(run(K.main, "origin", "--out", out, "--simulate")[0], K.EXIT_OK)
        first = K.read_json(os.path.join(out, K.SESSION_HOST))
        self.assertEqual({k: first[k] for k in C.PC_KEYS}, DESKTOP)
        costs = dict(C.load(C.PLACEHOLDER)["route_costs_ms"])
        cpu = ("CPU AMD Ryzen 7 7730U with Radeon Graphics, and the session's first step (origin) was measured on Intel(R) Core(TM) "
               "i7-10700F CPU @ 2.90GHz")
        vbox = "VirtualBox host 7.2.10r174163, and the session's first step (origin) was measured under 7.2.4r170995"
        for facts, said in (({"cpu_model": LAPTOP["cpu_model"]}, cpu), ({"vbox_host_version": LAPTOP["vbox_host_version"]}, vbox)):
            with self.subTest(facts=facts):
                code, _, err = run(K.main, "capacity", "--out", out, "--levels", "80,160", "--step-s", "10", "--repeats", "1",
                                   host=S.SimHost(facts=facts, origin_costs=costs))
                self.assertEqual(code, K.EXIT_STOPPED)
                self.assertIn("this host is not the one the session began on: " + said, err)
                self.assertIn("A calibration is made on one host and one PC", err)
                self.assertFalse(os.path.exists(os.path.join(out, "capacity")), "refused before any run")
        code, _, err = run(K.main, "origin", "--out", out, host=S.SimHost(facts=LAPTOP))
        self.assertEqual(code, K.EXIT_STOPPED, "the origin step made again on the other PC too")

    def test_a_session_cannot_begin_on_a_host_whose_pc_cannot_be_read(self):
        out = os.path.join(self.tmp.name, "s")
        code, _, err = run(K.main, "origin", "--out", out, host=S.SimHost(facts={"vbox_host_version": None}))
        self.assertEqual(code, K.EXIT_STOPPED)
        self.assertIn("this host's PC cannot be read (vbox_host_version): a session names its PC in its first step (K10)", err)
        self.assertFalse(os.path.exists(os.path.join(out, K.SESSION_HOST)))
        self.assertFalse(os.path.exists(os.path.join(out, "origin")))

    def test_offline_commands_are_unaffected(self):
        with mock.patch.object(C, "pc_problems", side_effect=AssertionError("a PC was judged")):
            self.assertEqual(run(K.main, "plan", host=S.SimHost(facts=LAPTOP))[0], K.EXIT_OK)
            self.assertEqual(run(GC.main, "plan", HG4, "--calibration", RECORD, "--modes", "xdp", host=S.SimHost(facts=LAPTOP))[0],
                             GC.EXIT_OK)
            code, _, err = run(K.main, "freeze", "--dir", self.tmp.name, "--out", os.path.join(self.tmp.name, "x.json"))
            self.assertEqual(code, K.EXIT_STOPPED)
            self.assertIn("run `capacity` first", err)


class FreezeTest(unittest.TestCase):
    def test_the_freeze_writes_the_pc_the_sessions_runs_recorded(self):
        host = K.host_of(env_of(LAPTOP), CF.SAMPLE_HOST["pins"])
        self.assertEqual({k: host[k] for k in C.PC_KEYS}, LAPTOP)
        cal = CF.frozen_v2(host=host)
        self.assertEqual({k: cal["host"][k] for k in C.PC_KEYS}, LAPTOP)

    def test_a_run_that_does_not_name_its_pc_cannot_be_frozen(self):
        for pc, said in (({}, "cpu_model, vbox_host_version"), ({"cpu_model": LAPTOP["cpu_model"]}, "vbox_host_version"),
                         ({**LAPTOP, "vbox_host_version": None}, "vbox_host_version")):
            with self.subTest(pc=pc), self.assertRaisesRegex(K.CalibrationStop, f"does not name the PC the runs were made on "
                                                                                 f"\\({said}\\): a record names its PC \\(K10\\)"):
                K.host_of(env_of(pc), CF.SAMPLE_HOST["pins"])


def env_of(pc):
    """An environment.json of a run on the laptop's kernel and memory with `pc` in its facts (as test_calibrate's ENV)."""
    env = {"facts": {"uname": "Linux ddos-mitigation 7.0.0-42-generic x86_64", "cpus": 8, "mem_mib": 7422, **pc, "python": "3.14.4",
                     "nginx": "nginx version: nginx/1.28.3", "gunicorn": "gunicorn (version 26.2.0)"},
           "provenance": {"files": {"origin.py": "a" * 64, "loadgen.py": "b" * 64}, "nginx_source_sha256": "c" * 64},
           "stack": {"origin": {"nofile_soft_hard": [[524288, 524288]]}}}
    return json.loads(json.dumps(env))


class EnvironmentTest(TER.RunCase):
    def test_each_runs_environment_record_keeps_the_pc(self):
        for pc in (LAPTOP, DESKTOP):
            with self.subTest(pc=pc):
                plan, _, result = self.go("C", host=S.SimHost(facts=pc), plan_args={"name": pc["cpu_model"][:3] + "/C"})
                self.assertTrue(result.ok, result.reasons)
                env = json.loads(self.read(plan, "environment.json"))
                self.assertEqual({k: env["facts"][k] for k in C.PC_KEYS}, pc)


if __name__ == "__main__":
    unittest.main()
