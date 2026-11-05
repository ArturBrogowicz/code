"""The P3 capture runs an L7 v2 population (ml/capture_l7.py; docs/L7V2_DESIGN.md §4.3, §5.1). Offline: the commands are
built against a fake suite and nothing is started; --plan runs in-process."""
import argparse
import contextlib
import gzip
import io
import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "ml"), os.path.join(REPO, "eval")):
    sys.path.insert(0, _p)
import capture_l7
import l7_pools
import l7v2_harm


class FakeSuite:
    PYTHON_VENV = "/venv/bin/python"
    SERVER_IP = "10.0.0.1"

    @staticmethod
    def _srv(cmd):
        return ["taskset", "-c", "0-1", *cmd]


def args(population, role="pilot", seed=9201, **kw):
    return argparse.Namespace(version="2026-11-smoke1", seed=seed, seed_role=role, population=population,
                              heuristics="tolerant", scale=1, p3_gate_seeds=2, calibration=None, knees=None, **kw)


class WiringTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.l7v2 = capture_l7.p3_plan(args("l7v2"))
        cls.smoke = capture_l7.p3_plan(args("smoke"))

    def test_the_costed_backend_on_loopback_with_its_record(self):
        argv = capture_l7.gunicorn_argv(FakeSuite, self.l7v2["server"])
        cal = self.l7v2["server"]["calibration"]
        self.assertEqual(cal["status"], "placeholder")
        self.assertEqual(argv[:6], ["taskset", "-c", "0-1", "env", "L7_BACKEND=costed", f"L7_CALIBRATION={cal['path']}"])
        self.assertEqual(argv[argv.index("-b") + 1], "127.0.0.1:8080")
        self.assertEqual(argv[-1], capture_l7.WEBAPP)

    def test_the_smoke_capture_keeps_its_command(self):
        argv = capture_l7.gunicorn_argv(FakeSuite, self.smoke["server"])
        self.assertNotIn("env", argv)
        self.assertEqual(argv[argv.index("-b") + 1], "0.0.0.0:8080")
        self.assertNotIn("calibration", self.smoke["server"])

    def test_benign_plan_kinds_write_records_and_nothing_else_does(self):
        with tempfile.TemporaryDirectory() as d:
            cap = capture_l7.P3Capture(args("l7v2"), d, os.path.join(d, "staging"), self.l7v2)
            for e in self.l7v2["entities"]:
                cmd = cap.entity_cmd(FakeSuite, e, 60.0)
                want = e["role"] == "benign" and e["kind_or_family"] in capture_l7.RECORDED_KINDS
                self.assertEqual("--records" in cmd, want, e["kind_or_family"])
                if want:
                    path = cmd[cmd.index("--records") + 1]
                    self.assertEqual(os.path.basename(path), capture_l7.records_name(e["entity_id"]))
            cap = capture_l7.P3Capture(args("smoke"), d, os.path.join(d, "staging"), self.smoke)
            self.assertFalse(any("--records" in cap.entity_cmd(FakeSuite, e, 60.0) for e in self.smoke["entities"]))

    def test_records_are_collected_gzipped_and_named_as_the_metric_reads_them(self):
        e = next(e for e in self.l7v2["entities"] if e["kind_or_family"] == "tpcw_browsing")
        with tempfile.TemporaryDirectory() as d:
            staging = os.path.join(d, "stage")
            os.makedirs(staging)
            raw = os.path.join(staging, capture_l7.records_name(e["entity_id"]))
            with open(raw, "w") as fh:
                fh.write(",".join(l7v2_harm.RECORD_COLUMNS) + "\n")
            with open(os.path.join(staging, "access.log"), "w") as fh:
                fh.write("")
            files = capture_l7.collect_records(staging, d)
            self.assertEqual([f["path"] for f in files], [os.path.basename(raw) + ".gz"], "a plain name")
            with gzip.open(os.path.join(d, files[0]["path"]), "rt") as fh:
                self.assertEqual(fh.readline().strip(), ",".join(l7v2_harm.RECORD_COLUMNS))
            self.assertEqual(capture_l7.collect_records(os.path.join(d, "none"), d), [])

    def test_a_training_plan_without_knees_is_refused(self):
        with self.assertRaises(SystemExit):
            capture_l7.p3_plan(args("l7v2", role="train", seed=1001))

    def test_plan_mode_prints_the_population(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(capture_l7.main_p3(args("l7v2", plan=True)), 0)
        self.assertIn("population l7v2-v1", out.getvalue())
        self.assertEqual(l7_pools.POPULATIONS["l7v2"]["backend"], "costed")


if __name__ == "__main__":
    unittest.main()
