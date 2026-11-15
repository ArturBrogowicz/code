"""R1's speed hold on the PC that runs the programme (K11, a proposal the user approves before it is committed; D-096): on the laptop the
costs of 2026-11-04 were measured on another CPU, so R1 holds against the medians of HS1's series on this PC (per CPU and route), with
H1's band of +-10 %, two pairs in a row agreeing within 5 %, at most 45 min. The medians file's sha256 is printed and kept in the
session; a file that names another PC, or other knobs, is refused; a record that names no PC (schema 1, the record of 2026-11-04) is
never a speed reference. On the simulated host and fixtures only."""
import argparse
import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
for sub in ("bench", "bench/packets", "eval"):
    sys.path.insert(0, os.path.join(REPO, sub))
import calibration as C
import calibration_fixtures as CF
import hostcheck as HC
import sim_host as S

RECORD = os.path.join(REPO, "bench", "calibration", "ddos-mitigation-2026-11-04.json")
SCRIPT = os.path.join(REPO, "bench", "packets", "packet.sh")
GOLDEN = os.path.join(HERE, "golden", "packets")
DESKTOP = {"cpu_model": "Intel(R) Core(TM) i7-10700F CPU @ 2.90GHz", "vbox_host_version": "7.2.4r170995"}
LAPTOP = {"cpu_model": "AMD Ryzen 7 7730U with Radeon Graphics", "vbox_host_version": "7.2.10r174163"}
COSTS = dict(C.load(C.PLACEHOLDER)["route_costs_ms"])
R1 = {"lo": -0.10, "hi": 0.10, "agree": 0.05, "max_min": 45.0}


def sha256_file(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def medians_doc(pc=None, scale=None, cpus=("0", "1"), verdict="PASS", **estimator):
    """HS1's medians.json (docs/HS1_PREREG.md 7, schema hs1-medians/1) of a series on `pc` (default the laptop) whose probe was this
    checkout's origin with the knobs of the record of 2026-11-04 (as bench/vm/hs1_probe.py takes them), 21 repeats; the medians are
    the placeholder's costs, CPU c's scaled by scale[c]."""
    est = {"function": "bench/origin.py time_routes", "repeats": 21,
           "origin_sha256": sha256_file(os.path.join(REPO, "bench", "origin.py")), "probe_sha256": "e" * 64,
           "knobs_from": "bench/calibration/ddos-mitigation-2026-11-04.json", "record_sha256": sha256_file(RECORD), **estimator}
    med = {cpu: {k: {"median_ms": v * (scale or {}).get(cpu, 1.0), "n": 36, "min_ms": v, "max_ms": v} for k, v in COSTS.items()}
           for cpu in cpus}
    return {"schema": "hs1-medians/1", "run_dir": "/home/artur/agent_workspace/host/hs1_x", "verdict": verdict,
            "usable_as_reference": verdict == "PASS", "host": {**(pc or LAPTOP), "kernel": "7.0.0-42-generic", "memtotal_kb": "7600852",
                                                               "tsc_mhz": "1996.250", "boot_id": "b" * 32},
            "estimator": est, "window": {"start_utc": "2026-11-15T09:00:00+00:00", "end_utc": "2026-11-15T12:00:00+00:00",
                                         "complete_sample_times": 36, "interval_s": 300},
            "medians_ms": med, "reported_only": {"7": med.get("0", {})}}


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.session = os.path.join(self.tmp.name, "S")

    def write(self, doc, name="medians.json"):
        path = os.path.join(self.tmp.name, name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=1, sort_keys=True)
        with open(path, "rb") as fh:
            return path, hashlib.sha256(fh.read()).hexdigest()

    def hold(self, host, **kw):
        args = argparse.Namespace(**{"calibration": C.PLACEHOLDER, "reference": None, "medians": None, "session": self.session,
                                     **R1, "every_s": 300.0, **kw})
        said = io.StringIO()
        with contextlib.redirect_stdout(said):
            code = HC.speed_hold_main(args, host)
        return code, said.getvalue()

    def stored(self):
        with open(os.path.join(self.session, HC.SPEED_REFERENCE), encoding="utf-8") as fh:
            return json.load(fh)


class PinnedTest(unittest.TestCase):
    def test_the_rule_and_the_packets_line(self):
        self.assertEqual(HC.R1_HOLD, R1)
        self.assertEqual(HC.SPEED_REFERENCE, "speed_reference.json")
        self.assertEqual(HC.MEDIANS_SCHEMA, "hs1-medians/1")
        self.assertEqual(HC.SPEED_REPEATS, 21, "HS1's probe takes the hold's repeats (docs/HS1_PREREG.md 3)")
        with open(os.path.join(GOLDEN, "R1.txt"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("step 1      ./venv/bin/python -B bench/hostcheck.py speed-hold --calibration bench/calibration/placeholder.json "
                      "--medians HS1_MEDIANS --session /S --lo -0.10 --hi 0.10 --agree 0.05 --max-min 45\n", text)

    def test_the_old_record_is_never_a_speed_reference_in_a_packet(self):
        for name in os.listdir(GOLDEN):
            with open(os.path.join(GOLDEN, name), encoding="utf-8") as fh:
                self.assertNotIn("2026-11-04", fh.read(), name)
        with open(SCRIPT, encoding="utf-8") as fh:
            self.assertNotIn("ddos-mitigation-2026-11-04", fh.read())


class DeviationTest(unittest.TestCase):
    def test_a_reference_per_cpu_judges_each_cpu_against_its_own(self):
        probe = {"cpus": {"0": {"C3": 33.0, "C5": 165.0}, "1": {"C3": 31.0, "C5": 150.0}}}
        per_cpu = {"0": {"C3": 30.0, "C5": 150.0}, "1": {"C3": 31.0, "C5": 160.0}, "7": {"C3": 1.0, "C5": 1.0}}
        want = ((33 / 30 - 1 + 165 / 150 - 1) / 2 + (31 / 31 - 1 + 150 / 160 - 1) / 2) / 2
        self.assertAlmostEqual(HC.speed_deviation(probe, per_cpu), want, places=12)
        flat = {"C3": 30.0, "C5": 150.0}                                  # a record's or origin.json's costs: every CPU's
        self.assertAlmostEqual(HC.speed_deviation(probe, flat), ((0.1 + 0.1) / 2 + (31 / 30 - 1 + 0.0) / 2) / 2, places=12)
        self.assertIsNone(HC.speed_deviation(probe, {"0": per_cpu["0"]}), "a CPU without a reference cannot be judged")


class MediansFileTest(Case):
    def test_a_good_file_gives_each_cpus_costs(self):
        path, sha = self.write(medians_doc(scale={"1": 1.05}))
        ref = HC.load_medians(path)
        self.assertEqual(ref["sha256"], sha)
        self.assertEqual({k: ref["host"][k] for k in C.PC_KEYS}, LAPTOP)
        self.assertEqual(ref["costs"]["0"], COSTS)
        self.assertAlmostEqual(ref["costs"]["1"]["C5"], COSTS["C5"] * 1.05, places=12)
        self.assertEqual(sorted(ref["costs"]), ["0", "1"], "the hold probes CPUs 0 and 1; CPU 7 is reported only")

    def test_what_a_file_lacks_is_named(self):
        good = {"median_ms": 30.0}
        cases = (({**medians_doc(), "schema": "hs1-medians/2"}, "schema hs1-medians/1"),
                 ({k: v for k, v in medians_doc().items() if k != "host"}, "lacks host"),
                 ({**medians_doc(), "host": {"cpu_model": LAPTOP["cpu_model"]}}, "host.vbox_host_version"),
                 ({**medians_doc(), "host": {**LAPTOP, "cpu_model": ""}}, "host.cpu_model"),
                 ({k: v for k, v in medians_doc().items() if k != "estimator"}, "estimator"),
                 ({k: v for k, v in medians_doc().items() if k != "usable_as_reference"}, "usable_as_reference"),
                 (medians_doc(cpus=("0",)), "medians_ms.1"),
                 ({**medians_doc(), "medians_ms": {"0": {"C3": good}, "1": {"C3": good, "C5": good}}}, "medians_ms.0.C5.median_ms"),
                 ({**medians_doc(), "medians_ms": {"0": {"C3": good, "C5": {"median_ms": 0}}, "1": {"C3": good, "C5": good}}},
                  "medians_ms.0.C5.median_ms"),
                 ({**medians_doc(), "medians_ms": {"0": {"C3": good, "C5": 150.0}, "1": {"C3": good, "C5": good}}},
                  "medians_ms.0.C5.median_ms"),
                 ([1, 2], "a JSON object"))
        for doc, said in cases:
            with self.subTest(said=said):
                path, _ = self.write(doc)
                with self.assertRaisesRegex(HC.SpeedReferenceError, said):
                    HC.load_medians(path)
        with open(os.path.join(self.tmp.name, "bad.json"), "w", encoding="utf-8") as fh:
            fh.write("{")
        with self.assertRaisesRegex(HC.SpeedReferenceError, "not JSON"):
            HC.load_medians(os.path.join(self.tmp.name, "bad.json"))


class HoldTest(Case):
    def test_it_holds_on_this_pc_prints_the_sha256_and_keeps_it_in_the_session(self):
        path, sha = self.write(medians_doc())
        code, said = self.hold(S.SimHost(facts=LAPTOP, origin_costs=COSTS), medians=path)
        self.assertEqual(code, 0, said)
        self.assertIn(f"speed hold: reference HS1's medians {path}, sha256 {sha}, PC AMD Ryzen 7 7730U with Radeon Graphics, "
                      "VirtualBox host 7.2.10r174163\n", said)
        self.assertIn("speed hold: held after 2 probe pairs, 300 s (band -10% to +10%, agreeing within 5%)", said)
        stored = self.stored()
        self.assertEqual((stored["path"], stored["sha256"], stored["host"]), (path, sha, medians_doc()["host"]))
        self.assertEqual(stored["estimator"]["repeats"], 21)
        self.assertEqual(stored["rule"], R1)
        self.assertEqual(stored["reference_costs_ms"], {"0": COSTS, "1": COSTS})
        self.assertEqual([h["held"] for h in stored["holds"]], [True])
        self.assertEqual(len(stored["holds"][0]["pairs"]), 2)

    def test_each_cpu_is_judged_against_its_own_median(self):
        """CPU 1's median is 8 % below what the host reads there now and CPU 0's equal: d = +4 %, held; at 25 % below, d = +12.5 %."""
        for scale, held in (({"1": 1 / 1.08}, True), ({"1": 1 / 1.25}, False)):
            with self.subTest(scale=scale):
                path, _ = self.write(medians_doc(scale=scale), f"m{held}.json")
                code, said = self.hold(S.SimHost(facts=LAPTOP, origin_costs=COSTS), medians=path,
                                       session=os.path.join(self.tmp.name, f"S{held}"))
                self.assertEqual(code, 0 if held else HC.EXIT_HOST_UNFIT, said)
                self.assertIn("+4.0%" if held else "+12.5%", said)

    def test_the_band_and_the_agreement(self):
        path, _ = self.write(medians_doc())
        code, said = self.hold(S.SimHost(facts=LAPTOP, origin_costs=COSTS, origin_slow=lambda t: 0.12), medians=path)
        self.assertEqual(code, HC.EXIT_HOST_UNFIT)
        self.assertIn("speed hold: NOT held", said)
        self.assertEqual([h["held"] for h in self.stored()["holds"]], [False], "the hold that did not hold is kept too")
        swing = (0.08, 0.08, -0.04, -0.04)          # pairs alternate +8 % and -4 %: both in the band, 12 % apart
        code, _ = self.hold(S.SimHost(facts=LAPTOP, origin_costs=COSTS, origin_noise=swing), medians=path)
        self.assertEqual(code, HC.EXIT_HOST_UNFIT, "two pairs in a row must agree within 5 %")
        code, _ = self.hold(S.SimHost(facts=LAPTOP, origin_costs=COSTS, origin_noise=swing), medians=path, agree=0.15)
        self.assertEqual(code, 0)
        self.assertEqual([h["held"] for h in self.stored()["holds"]], [False, False, True])

    def test_a_file_of_another_pc_is_refused_naming_both_values_before_any_probe(self):
        path, sha = self.write(medians_doc(pc=DESKTOP))
        host = S.SimHost(facts=LAPTOP, origin_costs=COSTS)
        code, said = self.hold(host, medians=path)
        self.assertEqual(code, HC.EXIT_REFUSED)
        self.assertIn(f"speed hold: refused: CPU AMD Ryzen 7 7730U with Radeon Graphics, and HS1's series ({sha[:8]}) was measured on "
                      f"Intel(R) Core(TM) i7-10700F CPU @ 2.90GHz; VirtualBox host 7.2.10r174163, and HS1's series ({sha[:8]}) was "
                      "measured under 7.2.4r170995", said)
        self.assertEqual(host.origin_calls, 0, "nothing was probed")
        self.assertFalse(os.path.exists(os.path.join(self.session, HC.SPEED_REFERENCE)))

    def test_a_series_that_did_not_pass_or_another_estimator_is_refused(self):
        here = sha256_file(os.path.join(REPO, "bench", "origin.py"))
        cases = ((medians_doc(verdict="FAIL"), "HS1's series was judged FAIL: its medians are not usable as a reference"),
                 (medians_doc(repeats=5), "HS1's probe took 5 repeats, the hold 21"),
                 (medians_doc(origin_sha256="f" * 64), f"HS1's probe ran bench/origin.py ffffffff, this checkout's is {here[:8]}"),
                 (medians_doc(record_sha256="0" * 64), (f"bench/calibration/ddos-mitigation-2026-11-04.json is "
                                                        f"{sha256_file(RECORD)[:8]} here, HS1's probe read 00000000")),
                 (medians_doc(knobs_from="bench/calibration/nothing.json"), "the knobs HS1's probe took cannot be read"))
        for doc, said in cases:
            with self.subTest(said=said):
                path, _ = self.write(doc)
                host = S.SimHost(facts=LAPTOP, origin_costs=COSTS)
                code, out = self.hold(host, medians=path)
                self.assertEqual(code, HC.EXIT_REFUSED, out)
                self.assertIn(said, out)
                self.assertEqual(host.origin_calls, 0)
        path, _ = self.write(medians_doc())
        other = os.path.join(self.tmp.name, "knobs.json")
        with open(other, "w", encoding="utf-8") as fh:
            json.dump({"knobs": {**C.load(C.PLACEHOLDER)["knobs"], "search_rows": 1}}, fh)
        code, out = self.hold(S.SimHost(facts=LAPTOP, origin_costs=COSTS), medians=path, calibration=other)
        self.assertEqual(code, HC.EXIT_REFUSED)
        self.assertIn("HS1's probe took other knobs than the hold's (search_rows)", out)

    def test_a_session_keeps_one_reference(self):
        path, sha = self.write(medians_doc())
        self.assertEqual(self.hold(S.SimHost(facts=LAPTOP, origin_costs=COSTS), medians=path)[0], 0)
        self.assertEqual(self.hold(S.SimHost(facts=LAPTOP, origin_costs=COSTS), medians=path)[0], 0)
        self.assertEqual(len(self.stored()["holds"]), 2)
        other, other_sha = self.write(medians_doc(scale={"0": 1.01}), "other.json")
        code, said = self.hold(S.SimHost(facts=LAPTOP, origin_costs=COSTS), medians=other)
        self.assertEqual(code, HC.EXIT_REFUSED)
        self.assertIn(f"the session holds against the HS1 medians {sha[:8]} ({path}); this file is {other_sha[:8]}: a session has one "
                      "speed reference", said)
        self.assertEqual(self.stored()["sha256"], sha)

    def test_a_hold_stopped_by_term_keeps_the_pairs_it_made_in_the_session(self):
        """T-115 LOW 10: TERM (which the hold's main turns into the interrupt, as the executor's does) or INT stops the hold; the probe
        pairs it made are kept in speed_reference.json with the stop, and it exits 130. Before, they were only in the log."""
        path, sha = self.write(medians_doc())

        class Stopped(S.SimHost):                   # TERM arrives in the wait after the second pair (the host 20 % slow: no hold yet)
            def sleep(self, seconds):
                if self.origin_calls >= 4:
                    raise KeyboardInterrupt("signal 15")
                super().sleep(seconds)
        code, said = self.hold(Stopped(facts=LAPTOP, origin_costs=COSTS, origin_slow=lambda t: 0.2), medians=path)
        self.assertEqual((code, HC.EXIT_INTERRUPTED), (130, 130), said)
        stop = self.stored()["holds"][-1]
        self.assertEqual((stop["held"], stop["stopped"]), (False, "interrupted (signal 15) after 2 probe pairs"))
        self.assertEqual([round(p["d"], 6) for p in stop["pairs"]], [0.2, 0.2])
        self.assertEqual(self.stored()["sha256"], sha)
        self.assertIn(f"speed hold: stopped, interrupted (signal 15) after 2 probe pairs; they are kept in "
                      f"{os.path.join(self.session, HC.SPEED_REFERENCE)}", said)
        with mock.patch.object(HC, "speed_hold", side_effect=KeyboardInterrupt), contextlib.redirect_stdout(io.StringIO()):
            code, _ = self.hold(S.SimHost(facts=LAPTOP, origin_costs=COSTS), medians=path)
        self.assertEqual(code, 130)
        self.assertEqual(self.stored()["holds"][-1]["stopped"], "interrupted (INT) after 0 probe pairs", "an INT before any pair")

    def test_the_holds_main_turns_term_into_the_interrupt(self):
        with open(os.path.join(REPO, "bench", "hostcheck.py"), encoding="utf-8") as fh:
            text = fh.read()
        body = text[text.index("def speed_hold_main("):text.index("\ndef main(")]
        self.assertIn("host = X.RealHost()\n        X._install_signal_handlers()", body)

    def test_a_file_that_is_not_there_or_not_a_reference_is_refused_before_any_probe(self):
        """T-116 (from T-115's list of speed-hold's exits): a --medians, --reference or --calibration that is not there, or a --reference
        with no route costs, is a refusal (exit 2, a line naming the file) before any probe. It was a traceback (exit 1); and under
        --reference a missing --calibration was not read at all: the probes failed on it and the hold waited out its 30 min."""
        path, _ = self.write(medians_doc())
        missing = os.path.join(self.tmp.name, "nothing.json")
        origin, nocosts, bare = (os.path.join(self.tmp.name, n) for n in ("origin.json", "nocosts.json", "bare.json"))
        for p, doc in ((origin, {"route_costs_ms": COSTS}), (nocosts, {"step": "origin"}), (bare, {"status": "placeholder"})):
            with open(p, "w", encoding="utf-8") as fh:
                json.dump(doc, fh)
        cases = (("--medians", {"medians": missing}, f"{missing}: cannot be read (FileNotFoundError: No such file or directory)"),
                 ("--reference", {"reference": missing}, f"--reference {missing} cannot be read (FileNotFoundError"),
                 ("--calibration with --medians", {"medians": path, "calibration": missing}, f"--calibration {missing} cannot be read"),
                 ("--calibration with --reference", {"reference": origin, "calibration": missing},
                  f"--calibration {missing} cannot be read"),
                 ("--calibration without knobs", {"reference": origin, "calibration": bare}, f"--calibration {bare} has no knobs"),
                 ("--reference without costs", {"reference": nocosts}, f"--reference {nocosts} has no route_costs_ms"))
        for label, kw, said in cases:
            with self.subTest(label):
                host = S.SimHost(facts=LAPTOP, origin_costs=COSTS)
                code, out = self.hold(host, **{"agree": None, "max_min": 30.0, **kw})
                self.assertEqual(code, HC.EXIT_REFUSED, out)
                self.assertIn("speed hold: refused: " + said, out)
                self.assertEqual(host.origin_calls, 0, "nothing was probed")

    def test_a_record_that_names_no_pc_is_never_a_speed_reference(self):
        code, said = self.hold(S.SimHost(facts=LAPTOP, origin_costs=COSTS), reference=RECORD, calibration=RECORD)
        self.assertEqual(code, HC.EXIT_REFUSED)
        self.assertIn("speed hold: refused: the record cff6e515 is of schema 1 and names no PC: it is never a speed reference (K11)", said)

    def test_a_record_of_another_pc_is_refused_and_of_this_pc_held_against(self):
        for pc, want in ((DESKTOP, HC.EXIT_REFUSED), (LAPTOP, 0)):
            with self.subTest(pc=pc):
                cal = CF.frozen_v2(host={**CF.SAMPLE_HOST, **pc})
                path = os.path.join(self.tmp.name, "record.json")
                C.dump(cal, path)
                code, said = self.hold(S.SimHost(facts=LAPTOP, origin_costs=dict(cal["route_costs_ms"])), reference=path,
                                       calibration=path, agree=None, max_min=30.0)
                self.assertEqual(code, want, said)
                if want:
                    self.assertIn(f"CPU AMD Ryzen 7 7730U with Radeon Graphics, and the record {cal['sha256'][:8]} was measured on", said)


class PacketTest(unittest.TestCase):
    def script(self, *args, env=None):
        clean = {k: v for k, v in os.environ.items() if k != "HS1_MEDIANS"}
        return subprocess.run(["bash", SCRIPT, *args], capture_output=True, text=True, check=False, timeout=60,
                              env={**clean, **(env or {})})

    def test_r1_needs_the_medians_and_takes_them_from_the_command_line_or_the_environment(self):
        r = self.script("R1", "--session", "/S", "--commit", "abcdef0")       # the pinned commit is asked for first (K14)
        self.assertEqual(r.returncode, 2)
        self.assertIn("packet.sh: R1 holds against HS1's medians on this PC (K11): --medians FILE or HS1_MEDIANS=FILE", r.stderr)
        r = self.script("R1", "--print", "--session", "/S", "--medians", "/M")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("--medians /M --session /S --lo -0.10 --hi 0.10 --agree 0.05 --max-min 45\n", r.stdout)
        self.assertIn("reference   HS1's medians /M on this PC: its sha256 printed by the hold and kept in /S/speed_reference.json",
                      r.stdout)
        r = self.script("R1", "--print", "--session", "/S", env={"HS1_MEDIANS": "/E"})
        self.assertIn("--medians /E --session /S", r.stdout)
        if os.geteuid() != 0:
            r = self.script("R1", "--session", "/S", "--commit", "abcdef0", env={"HS1_MEDIANS": "/E"})
            self.assertEqual(r.returncode, 2)
            self.assertIn("the steps need root", r.stderr, "past the medians' check")
        r = self.script("R2a", "--print", "--session", "/S")
        self.assertNotIn("--medians", r.stdout, "only R1 holds against HS1's medians")


if __name__ == "__main__":
    unittest.main()
