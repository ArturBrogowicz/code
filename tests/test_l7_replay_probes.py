"""Unit tests for ml/replay_l7.py and ml/l7_probes.py (Phase P2). Offline."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l7_testutil as U

sys.path.insert(0, os.path.join(U.REPO, "ml"))
import l7_probes as P
import replay_l7 as R
import torch

import l7_engine as E
import l7_features as F
import l7_ingest
import l7_scorer

torch.set_num_threads(1)


def access_log_lines(n_per_ip=12):
    """A plain l7json access log (no poll ticks): a bot POSTing, a user GETting."""
    lines = []
    for i in range(n_per_ip):
        lines.append(json.dumps(U.obj(ip="10.0.2.7", ua="bot", method="POST", msec=100.0 + i)))
        lines.append(json.dumps(U.obj(ip="10.0.1.7", ua="browser", method="GET",
                                      msec=100.2 + i, uri=f"/p{i}")))
    return lines


class ReplayTest(unittest.TestCase):
    def test_synthetic_polls_without_ticks(self):
        eng = E.build_engine(None, min_events=3)
        events = R.replay(E.read_stream(access_log_lines()), eng, poll_every=1.0)
        sums = R._sums(events)
        self.assertGreater(sums["polls"], 10)
        self.assertGreater(sums["windows"], 0)
        self.assertEqual(sums["suppressed_polls"], 0)

    def test_stub_model_flags_only_the_bot(self):
        eng = E.L7ShadowEngine(l7_ingest.L7WindowStore(), scorer=U.StubScorer(), min_events=3)
        events = R.replay(E.read_stream(access_log_lines()), eng)
        report = R.summarise(events)
        self.assertEqual(report["would_ban_ips_by_class"], {"attack": ["10.0.2.7"]})

    def test_compare_live_detects_a_mismatch(self):
        live = [{"kind": "l7_would_ban", "ip": "1.1.1.1", "ua_h": 1, "hits": 3,
                 "n_events": 5, "p": 0.99},
                {"kind": "l7_gru_poll", "polls": 3, "windows": 3}]
        same = [dict(e) for e in live]
        self.assertTrue(R.compare_live(live, same)["match"])
        other = [dict(e) for e in live]
        other[0]["p"] = 0.5
        self.assertFalse(R.compare_live(live, other)["match"])

    def test_cli_writes_events_and_features_csv(self):
        d = tempfile.mkdtemp(prefix="l7cli_")
        self.addCleanup(shutil.rmtree, d, True)
        src = os.path.join(d, "access.log")
        with open(src, "w", encoding="utf-8") as fh:
            fh.write("\n".join(access_log_lines()) + "\n")
        out, csv_path = os.path.join(d, "ev.jsonl"), os.path.join(d, "win.csv")
        res = subprocess.run([sys.executable, os.path.join(U.REPO, "ml", "replay_l7.py"), src,
                              "--out", out, "--features-csv", csv_path, "--min-events", "3"],
                             capture_output=True, text=True, check=False,
                             env={**os.environ, "PYTHONPYCACHEPREFIX": "/tmp/l7pyc"})
        self.assertEqual(res.returncode, 0, res.stderr)
        report = json.loads(res.stdout)
        self.assertGreater(report["totals"]["windows"], 0)
        with open(csv_path, encoding="utf-8") as fh:
            header = fh.readline().strip().split(",")
            rows = fh.readlines()
        self.assertEqual(header[:5], ["t_poll", "ip", "ua_h", "class", "p"])
        self.assertEqual(len(rows), report["totals"]["windows"])


class CompareLiveCliTest(unittest.TestCase):
    def test_cli_cuts_the_uncovered_tail_of_a_killed_run(self):
        import ban_events
        d = tempfile.mkdtemp(prefix="l7cmp_")
        self.addCleanup(shutil.rmtree, d, True)
        pkg = os.path.join(d, "pkg")
        U.tiny_package(pkg, seq_len=8)
        rec_path, ev_path = os.path.join(d, "rec.jsonl"), os.path.join(d, "ev.jsonl")
        rec, ev = E.EngineRecorder(rec_path), ban_events.EventLog(ev_path)
        eng = E.build_engine(pkg, min_events=3)
        for step in range(20):
            now = 5000.0 + step
            for ip, ua in (("10.0.2.3", "bot"), ("10.0.1.3", "browser")):
                o = U.obj(ip=ip, ua=ua, msec=now - 0.2, method="POST" if ua == "bot" else "GET")
                rec.record(o, now - 0.2)
                eng.on_record(l7_ingest.normalise(o))
            rec.poll(now, False, ())
            for e in eng.poll(now, False, ()):
                if e.pop("kind") == "l7_would_ban":
                    ev.emit("l7_would_ban", **e)
            if step % 5 == 4 and step < 15:          # summaries stop after poll 14
                ev.emit("l7_gru_poll", **eng.take_summary())
        rec.close()
        ev.close()
        res = subprocess.run([sys.executable, os.path.join(U.REPO, "ml", "replay_l7.py"),
                              rec_path, "--model", pkg, "--min-events", "3",
                              "--compare-live", ev_path], capture_output=True, text=True,
                             check=False, env={**os.environ, "PYTHONPYCACHEPREFIX": "/tmp/l7pyc"})
        self.assertEqual(res.returncode, 0, res.stdout[-800:] + res.stderr[-800:])
        cmp = json.loads(res.stdout)["compare_live"]
        self.assertTrue(cmp["match"])
        self.assertEqual(cmp["live"]["polls"], 15)            # polls 15-19 were cut
        self.assertEqual(cmp["cutoff"], 5014.0)


class ProbeTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="l7probe_")
        self.addCleanup(shutil.rmtree, self.dir, True)
        lines = []
        for k in range(4):
            for i in range(15):
                lines.append(json.dumps(U.obj(ip=f"10.0.1.{k}", ua=f"ua{k}", msec=100 + i * 0.9 + k,
                                              uri=f"/x{i % 4}", rlen=100,
                                              method="POST" if k % 2 else "GET")))
        self.items = list(E.read_stream(lines))

    def test_windows_from_items_stride(self):
        w = P.windows_from_items(self.items, seq_len=8, min_events=5, stride=5)
        # per key 15 records: windows at record 5, 10, 15 → 3 per key, 4 keys
        self.assertEqual(len(w), 12)
        self.assertTrue(all(len(x) <= 8 for x in w))

    def test_exact_transforms_pass_with_a_real_gru(self):
        U.tiny_package(self.dir, seq_len=8)
        scorer = l7_scorer.L7Scorer.load(self.dir)
        windows = P.windows_from_items(self.items, scorer.seq_len)
        report = P.run_probes(scorer, windows)
        for name in ("ua_swap", "uri_bijection", "time_offset"):
            self.assertTrue(report[name]["pass"], (name, report[name]))
            self.assertLessEqual(report[name]["max_abs_dp"], P.EXACT_TOL)

    def test_size_shortcut_is_caught(self):
        # A "model" that keys on request size — the XDP model's failure mode.
        stub = U.StubScorer(seq_len=8, col="log_rlen", cut=5.0)   # rlen 100 → log1p ≈ 4.6
        windows = P.windows_from_items(self.items, stub.seq_len)
        base = stub.score([F.window_matrix(w, 8, stub.cols) for w in windows])
        self.assertTrue((base < stub.threshold).all())             # small requests: benign
        report = P.run_probes(stub, windows)
        self.assertFalse(report["pad_request"]["pass"])             # padding flips decisions
        self.assertGreater(report["pad_request"]["flip_rate"], 0.5)
        self.assertTrue(report["ua_swap"]["pass"])
        self.assertFalse(report["all_pass"])


if __name__ == "__main__":
    unittest.main()
