"""Unit tests for ml/l7_baselines.py (P5b baselines B0-B4, docs/L7_GRU_DESIGN.md §7.2).
Offline: synthetic recordings; B4 uses a tiny baseline trained on a synthetic dataset."""
import gzip
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l7_testutil as U

sys.path.insert(0, os.path.join(U.REPO, "ml"))
import l7_baselines as B


def write_recording(path, objs, poll_every=1.0):
    """An L7_RECORD file: records in time order, with a poll tick every second."""
    objs = sorted(objs, key=lambda o: o["msec"])
    lines, next_poll = [], None
    for o in objs:
        if next_poll is None:
            next_poll = o["msec"] + poll_every
        while o["msec"] >= next_poll:
            lines.append({"rx": next_poll, "poll": True, "suppressing": False, "banned": []})
            next_poll += poll_every
        lines.append({"rx": o["msec"], "obj": o})
    lines.append({"rx": next_poll, "poll": True, "suppressing": False, "banned": []})
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "wt", encoding="utf-8") as fh:
        fh.writelines(json.dumps(x) + "\n" for x in lines)
    return path


def burst(ip, ua, n, t0, span, **kw):
    return [U.obj(ip=ip, ua=ua, msec=t0 + span * i / n, **kw) for i in range(n)]


class RateBaselineTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="l7bl_")
        self.addCleanup(shutil.rmtree, self.d, True)
        objs = (burst("10.0.2.1", "bot", 30, 1000.0, 0.9)                 # 30 in 1 s, one UA
                + burst("10.0.1.9", "uaA", 15, 1000.0, 0.9)               # 2 users, 15 each
                + burst("10.0.1.9", "uaB", 15, 1000.05, 0.9)
                + burst("10.0.1.3", "slow", 60, 1000.0, 59.0)             # 1 rps for a minute
                + burst("10.0.2.2", "steady", 600, 1100.0, 30.0, lreq="REJECTED"))  # 20 rps
        write_recording(os.path.join(self.d, "l7_record.jsonl"), objs)
        self.res = B.compute(self.d)
        self.f = self.res["families"]

    def test_peak_per_ip_vs_per_key(self):
        self.assertEqual(self.f["B0"]["peak1s>20"], ["10.0.1.9", "10.0.2.1", "10.0.2.2"])
        self.assertEqual(self.f["B1"]["peak1s>20"], ["10.0.2.1", "10.0.2.2"])  # NAT split by UA
        self.assertEqual(self.f["B0"]["peak1s>50"], [])

    def test_sustained_separates_a_burst_from_a_steady_rate(self):
        self.assertEqual(self.f["B2"]["ip:mean10s>10"], ["10.0.2.2"])
        self.assertEqual(self.f["B2"]["ip:mean60s>2"], ["10.0.2.2"])

    def test_token_bucket(self):
        self.assertEqual(self.f["B3"]["ip:r=15,b=100"], ["10.0.2.2"])     # 20 rps for 30 s
        self.assertIn("10.0.2.1", self.f["B3"]["ip:r=5,b=10"])            # a 30-request burst
        self.assertNotIn("10.0.1.3", self.f["B3"]["ip:r=5,b=10"])

    def test_shaped_and_counts(self):
        self.assertEqual(self.res["shaped_ips"], ["10.0.2.2"])
        self.assertEqual(self.res["requests"], 30 + 15 + 15 + 60 + 600)
        self.assertNotIn("B4", self.f)                       # no baseline package given

    def test_gz_recording_and_cli(self):
        d = tempfile.mkdtemp(prefix="l7blgz_")
        self.addCleanup(shutil.rmtree, d, True)
        write_recording(os.path.join(d, "l7_record.jsonl.gz"),
                        burst("10.0.2.1", "bot", 30, 1000.0, 0.9))
        import subprocess
        r = subprocess.run([sys.executable, os.path.join(U.REPO, "ml", "l7_baselines.py"), d],
                           capture_output=True, text=True, check=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(d, "baselines.json"), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["families"]["B0"]["peak1s>20"], ["10.0.2.1"])


class HgbReplayTest(unittest.TestCase):
    def test_b4_replays_the_saved_baseline(self):
        import test_l7_train as TT
        import train_l7 as T
        ds = tempfile.mkdtemp(prefix="l7ds_")
        pkg = tempfile.mkdtemp(prefix="l7pkg_")
        run = tempfile.mkdtemp(prefix="l7run_")
        for d in (ds, pkg, run):
            self.addCleanup(shutil.rmtree, d, True)
        TT.synth_dataset(ds)
        T.run(ds, pkg, seed=1, epochs=1, hidden=8, layers=1,
              variants=("no_size_no_server_timing",))
        with open(os.path.join(ds, "access.log"), encoding="utf-8") as fh:
            objs = [json.loads(line) for line in fh]
        # The synthetic attackers send 40 requests in 2 s: too few 1 s polls for the
        # 3-consecutive policy. Spread every IP's requests 0.25 s apart instead.
        seen = {}
        for o in objs:
            seen[o["ip"]] = seen.get(o["ip"], -1) + 1
            o["msec"] = 1000.0 + 0.25 * seen[o["ip"]]
        write_recording(os.path.join(run, "l7_record.jsonl"), objs)
        res = B.compute(run, pkg)
        self.assertIn("B4", res["families"])
        self.assertGreater(res["hgb"]["windows"], 0)
        self.assertEqual(res["hgb"]["variant"], "no_size_no_server_timing")
        self.assertEqual(len(res["families"]["B4"]), len(B.HGB_THRESHOLDS))
        # the attackers' POST /login windows are what the tiny baseline learned
        low = res["families"]["B4"][f"p>0.5x{T.CONSECUTIVE}"]
        self.assertTrue(any(ip.startswith("10.0.2.") for ip in low))


if __name__ == "__main__":
    unittest.main()
