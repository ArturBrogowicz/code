"""The L7 v2 client-side harm metric (eval/l7v2_harm.py) and the client-side records (ml/l7_gen.py --records),
docs/L7V2_DESIGN.md section 5. Offline: synthetic runs and blocks are written under temporary directories, and the
generator is driven against a fake session."""
import copy
import csv
import gzip
import json
import math
import os
import random
import sys
import tempfile
import unittest
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "ml"), os.path.join(REPO, "eval"), os.path.join(REPO, "tests"),
           os.path.join(REPO, "bench")):
    sys.path.insert(0, _p)
import calibration_fixtures as CF
import l7_gen
import l7v2_harm as H

import l7_backend
import l7_dataset as D

T0 = 1_000_000.0
TIMELINE = {"baseline_s": 30.0, "attack_s": 120.0, "recovery_s": 30.0}
DUR = 180.0
NAV = {"level": 30, "first_visit_s": [0.0, 20.0], "nav": "tpcw:browsing", "think_mean_s": 7.0}


def entities(seed):
    rows = []
    for i, netem in enumerate(("perfect", "broadband", "perfect", "broadband", "mobile_3g", "perfect")):
        e = {"entity_id": f"2026-11-p1:{seed}:{i}", "index": i, "subseed": i, "role": "benign",
             "kind_or_family": "search_user" if i == 5 else "browser_page", "mechanism": None, "held_out": False,
             "address": f"10.0.17.{i + 1}", "namespace": "n", "netem": netem, "port": 80, "params": dict(NAV),
             "client_seed": 1000 * seed + i, "schedule": {"start_s": 0.0, "stop_s": DUR, "phase": None}}
        e["plan_sha256"] = D.entity_plan_sha256(e)
        rows.append(e)
    return rows


def write_run(run_dir, role, klass, seed, harm=0.0, server_harm=None, ok=True, drop_view=None, late_view=None):
    """One synthetic run: every planned request answered 200; in the attack window a share `harm` of the requests
    take 2.5 s at the client (over every SLO but C5's) and, unless server_harm says otherwise, at the server too."""
    os.makedirs(os.path.join(run_dir, "records"))
    ents = entities(seed)
    rng = random.Random(seed * 7 + len(role))
    log = []
    lo, hi = T0 + TIMELINE["baseline_s"], T0 + TIMELINE["baseline_s"] + TIMELINE["attack_s"]
    for e in ents:
        planned = H.planned_views(e, DUR)
        origin = T0 + e["schedule"]["start_s"]
        with open(os.path.join(run_dir, "records", e["entity_id"].replace(":", "_") + ".csv"), "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(H.RECORD_COLUMNS)
            for (u, v), (t_rel, classes) in sorted(planned.items()):
                if drop_view == (e["index"], u, v):
                    continue
                t_nom = origin + t_rel
                t_sent = t_nom + (15.0 if late_view == (e["index"], u, v) else 0.05)
                for wave, klass_r in enumerate(classes):
                    slow = lo <= t_sent < hi and rng.random() < harm
                    client = 2.5 if slow else 0.02
                    server = client if server_harm is None else (2.5 if slow and server_harm else 0.02)
                    w.writerow([t_sent, t_sent, t_sent + client, 200, "", klass_r, u, v, wave, t_nom, origin])
                    log.append(json.dumps({"msec": t_sent + server, "rt": server, "ip": e["address"], "status": 200,
                                           "method": "GET", "uri": "/page/1" if klass_r == "C1" else "/static/a.css",
                                           "ua": "x"}) + "\n")
    with gzip.open(os.path.join(run_dir, D.ACCESS_LOG_GZ), "wt") as fh:
        fh.writelines(log)
    manifest = {"format": D.DATASET_FORMAT_V2, "entities": ents, "timeline": {"t0_wall": T0},
                "ip_map": D.ip_map_from_entities(ents)}
    with open(os.path.join(run_dir, D.MANIFEST_FILE), "w") as fh:
        json.dump(manifest, fh)
    with open(os.path.join(run_dir, "run.json"), "w") as fh:
        json.dump({"role": role, "class": klass, "checks": {"ok": ok, "reasons": [] if ok else ["a client never started"]}},
                  fh)


def write_block(root, block, cal, harm, attempt=1, **kw):
    d = os.path.join(root, f"b{block:02d}a{attempt}")
    os.makedirs(d)
    seed = 3000 + block
    with open(os.path.join(d, "block.json"), "w") as fh:
        json.dump({"block": block, "attempt": attempt, "seed": seed, "calibration_sha256": cal["sha256"],
                   "timeline": TIMELINE, "order": ["C", "Cp", "U_C3b"]}, fh)
    write_run(os.path.join(d, "C"), "control", None, seed)
    write_run(os.path.join(d, "Cp"), "placebo", None, seed)
    write_run(os.path.join(d, "U_C3b"), "attack", "C3b", seed, harm=harm, **kw)
    return d


PLANNED = {(0, 0): (0.0, ["C1", "C0"]), (0, 1): (10.0, ["C1"]), (0, 2): (20.0, ["C3", "C0"]), (0, 3): (30.0, ["C1"])}


class NeverSentTest(unittest.TestCase):

    def row(self, view, t_sent, klass="C1"):
        return {"t_intended": t_sent, "t_sent": t_sent, "t_done": t_sent + 0.01, "status": 200.0, "err": "",
                "route_class": klass, "user": 0, "view": view, "wave": 0, "t_nominal": 0.0, "t_origin": 1000.0}

    def test_views_due_in_the_window_that_never_started_fail(self):
        rows = [self.row(0, 1000.0), self.row(1, 1011.0)]
        out = H.with_never_sent(rows, PLANNED, 1000.0, (1005.0, 1035.0), after_s=10.0)
        failed = [r for r in out if r["err"] == H.NEVER_SENT]
        self.assertEqual(sorted((r["view"], r["route_class"], r["t_intended"]) for r in failed),
                         [(2, "C0", 1020.0), (2, "C3", 1020.0), (3, "C1", 1030.0)])
        self.assertEqual(len(out), 5, "the two sent rows stay")

    def test_a_view_started_too_late_counts_as_never_sent_once(self):
        rows = [self.row(2, 1031.0, "C3"), self.row(2, 1031.1, "C0")]
        out = H.with_never_sent(rows, PLANNED, 1000.0, (1015.0, 1025.0), after_s=10.0)
        self.assertEqual([(r["err"], r["t_intended"]) for r in out], [(H.NEVER_SENT, 1020.0)] * 2)

    def test_the_guard_is_the_pre_registered_ten_seconds(self):
        self.assertEqual(H._rule()["never_sent_after_s"], 10.0)


class MetricsTest(unittest.TestCase):
    def test_q_p95_classes_profiles_and_unjudged(self):
        cal = CF.placeholder()
        rows = []
        for i in range(100):
            rows.append({"t_intended": 1010.0 + i * 0.1, "t_sent": 1010.0 + i * 0.1,
                         "t_done": 1010.0 + i * 0.1 + (0.5 if i < 10 else 0.05), "status": 200.0, "err": "",
                         "route_class": "C1", "netem": "perfect"})
        rows.append({"t_intended": 1015.0, "t_sent": math.nan, "t_done": math.nan, "status": math.nan,
                     "err": H.NEVER_SENT, "route_class": "C3", "netem": "broadband"})
        rows.append({"t_intended": 1015.0, "t_sent": 1015.0, "t_done": 1015.01, "status": 200.0, "err": "",
                     "route_class": "C1", "netem": "mobile_bad"})
        rows.append({"t_intended": 1015.0, "t_sent": 1015.0, "t_done": 1015.01, "status": 200.0, "err": "",
                     "route_class": "", "netem": "perfect"})
        m = H.metrics(rows, cal, (1000.0, 1100.0), 1000.0, 120.0)
        self.assertEqual((m["requests"], m["ok"]), (101, 90))
        self.assertAlmostEqual(m["Q"], 100 * 90 / 101)
        self.assertEqual(m["failures"], {"never_sent": 1, "slow": 10})
        self.assertEqual(m["unjudged_route"], 1)
        self.assertEqual(sorted(m["by_class"]), ["C1", "C3"])
        self.assertFalse(m["by_profile"]["mobile_bad"]["judged"])
        self.assertAlmostEqual(m["p95_s"], 0.05, places=6)


class BlockTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.frozen = CF.frozen()

    def campaign(self, root, harm, n=10, **kw):
        for b in range(1, n + 1):
            write_block(root, b, self.frozen, harm, **kw)
        return H.analyse(root, self.frozen, "C3b")

    def test_a_harmful_class_is_admitted(self):
        with tempfile.TemporaryDirectory() as root:
            res = self.campaign(root, harm=0.5)
        self.assertEqual(res["verdict"], "ADMITTED", res["reasons"])
        self.assertTrue(res["criteria"]["Q"]["passed"])
        self.assertFalse(res["placebo"]["passed"])
        self.assertEqual(res["blocks_valid"], 10)

    def test_a_harmless_class_is_v_d(self):
        with tempfile.TemporaryDirectory() as root:
            res = self.campaign(root, harm=0.0)
        self.assertEqual(res["verdict"], "V-D: no harm")
        self.assertFalse(res["admitted"])

    def test_client_harm_the_server_never_saw_invalidates_the_blocks(self):
        with tempfile.TemporaryDirectory() as root:
            res = self.campaign(root, harm=0.5, server_harm=False)
        self.assertEqual(res["verdict"], "INVALID")
        self.assertIn("fewer than 10", "; ".join(res["reasons"]))

    def test_a_block_whose_run_was_not_sound_is_not_valid(self):
        with tempfile.TemporaryDirectory() as root:
            d = write_block(root, 1, self.frozen, 0.5, ok=False)
            got = H.assess_block(d, self.frozen)
        self.assertFalse(got["classes"]["C3b"]["valid"])
        self.assertIn("U_C3b: a client never started", got["classes"]["C3b"]["reasons"])

    def test_a_dropped_view_in_the_window_is_a_failure(self):
        with tempfile.TemporaryDirectory() as root:
            d = write_block(root, 1, self.frozen, 0.0, drop_view=(0, 0, 6))
            got = H.assess_block(d, self.frozen)
        planned = H.planned_views(entities(3001)[0], DUR)
        t_rel = planned[(0, 6)][0]
        u = got["runs"]["U_C3b"]["metrics"]
        if 30.0 <= t_rel < 150.0:
            self.assertEqual(u["failures"].get("never_sent"), len(planned[(0, 6)][1]))
        else:
            self.assertNotIn("never_sent", u["failures"])

    def test_no_verdict_on_a_placeholder_or_a_measured_record(self):
        measured, _, _ = l7_backend.load_record(os.path.join(REPO, "ml", "l7v2_records", "measured_hg2_3.json"))
        with tempfile.TemporaryDirectory() as root:
            write_block(root, 1, self.frozen, 0.5)
            blocks = [H.assess_block(os.path.join(root, d), self.frozen) for d in os.listdir(root)]
        for rec in (CF.placeholder(), measured):
            with self.assertRaises(l7_backend.RecordError):
                H.admission(blocks, rec, "C3b")
        dry = H.admission(blocks, {**copy.deepcopy(self.frozen), "status": "placeholder"}, "C3b", dry_run=True)
        self.assertEqual(dry["label"], "PLACEHOLDER")
        self.assertTrue(dry["dry_run"])


class FakeSession:
    def __init__(self):
        self.headers = {}

    def get(self, url, verify=False, timeout=10, headers=None):
        return mock.Mock(status_code=200)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class RecordsTest(unittest.TestCase):
    def test_the_generator_writes_rows_the_metric_reads(self):
        e = entities(3005)[0]
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.csv")
            rec = l7_gen.Recorder(path)
            with mock.patch.object(l7_gen, "RECORDER", rec), \
                    mock.patch.object(l7_gen, "_session", lambda ua, conns: FakeSession()), \
                    mock.patch.object(l7_gen.time, "sleep", lambda s: None):
                l7_gen.benign_browser_page("10.0.0.1", 80, e["params"], 60.0, random.Random(e["client_seed"]))
            rec.close()
            rows = H.read_client_records(path)
        planned = H.planned_views(e, 60.0)
        self.assertEqual(len(rows), sum(len(c) for _, c in planned.values()))
        self.assertEqual({(r["user"], r["view"]) for r in rows}, set(planned))
        for r in rows:
            self.assertEqual((r["t_intended"], r["status"], r["err"]), (r["t_sent"], 200.0, ""))
            self.assertAlmostEqual(r["t_nominal"] - r["t_origin"], planned[(r["user"], r["view"])][0], places=3)
        self.assertEqual(sorted(r["route_class"] for r in rows),
                         sorted(c for _, cs in planned.values() for c in cs))

    def test_records_are_refused_for_an_attack_or_a_non_plan_kind(self):
        for argv in (["--role", "attack", "--family", "C2"], ["--role", "benign", "--kind", "keepalive"]):
            with self.assertRaises(SystemExit):
                l7_gen.main([*argv, "--host", "10.0.0.1", "--duration", "1", "--records", "/nonexistent/r.csv",
                             "--plan"])


if __name__ == "__main__":
    unittest.main()
