"""Manifest schema 3: a time-indexed entity <-> address map for address reuse (docs/L7V2_DESIGN.md §6; the P3 note §5,
the M3 phase reusing the C2 phase's addresses), its labels, its readers and the disjointness checker. Offline: fixture
captures are written under temporary directories."""
import json
import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p in (REPO, os.path.join(REPO, "ml"), os.path.join(REPO, "tests")):
    sys.path.insert(0, p)
import l7_disjoint
import l7_testutil as U
import p3_fixtures as FX
import rebuild_l7_dataset as RB
import train_l7

import l7_dataset as D

T0 = 1000.0
VERSION = "2026-11-test"


def reuse_entities(seed=3201, overlap=False, cross_role=False):
    """Two benign, one C2 entity at [5, 25) and one C3b@M3 entity at [30, 50) on the C2 entity's address."""
    ents = FX.entities(VERSION, seed, n_benign=2, n_attack=2, families=("C2", "C3a"))
    c2 = next(e for e in ents if e["kind_or_family"] == "C2")
    c2["schedule"] = {"start_s": 5.0, "stop_s": 25.0, "phase": "C2"}
    m3 = dict(c2, entity_id=f"{VERSION}:{seed}:{len(ents)}", index=len(ents), kind_or_family="C3b@M3",
              mechanism="nav", held_out=True, client_seed=99,
              schedule={"start_s": 20.0 if overlap else 30.0, "stop_s": 50.0, "phase": "C3b@M3"})
    if cross_role:
        m3["role"] = "benign"
    ents.append(m3)
    for e in ents:
        e["plan_sha256"] = D.entity_plan_sha256(e)
    return ents, c2, m3


def log_text(ents):
    out = []
    for e in ents:
        lo, hi = e["schedule"]["start_s"], min(e["schedule"]["stop_s"], 60.0)
        for j in range(int(hi - lo)):
            ua = "bot-" + e["kind_or_family"] if e["role"] == "attack" else "browser"
            out.append(json.dumps(U.obj(ip=e["address"], ua=ua, method="GET", uri=f"/page/{j % 5}",
                                        msec=T0 + lo + j + 0.5, status=200, bsent=600), sort_keys=True) + "\n")
    return "".join(out)


def capture_v3(root, ents, seed=3201, seed_role="eval", t0=T0, started="2026-11-03T10:00:00Z"):
    d = os.path.join(root, f"s{seed}")
    os.makedirs(d, exist_ok=True)
    FX.write_gz(os.path.join(d, D.ACCESS_LOG_GZ), log_text(ents))
    FX.write_gz(os.path.join(d, D.ERROR_LOG_GZ), "")
    files = [D.file_record(os.path.join(d, n), n) for n in (D.ACCESS_LOG_GZ, D.ERROR_LOG_GZ)]
    timeline = {"lead_in_s": 5.0, "phases": [], "tail_s": 10.0, "ready": True, "completed": True}
    if t0 is not None:
        timeline["t0_wall"] = t0
    m = D.make_manifest_v2(
        dataset_version=VERSION, capture_id=f"s{seed}", seed=seed, seed_role=seed_role, started_utc=started,
        ended_utc=started.replace("10:00", "10:17"), duration_s=60.0,
        code={"commit": FX.COMMIT, "branch": "feat/l7v2-traffic", "dirty": False, "dirty_files": [],
              "inputs_sha256": {"ml/l7_gen.py": "0" * 64}},
        server={"config_id": "A"}, host={"uname": "test"},
        pool={"range": "10.0.16.0/20", "permutation_seed": seed, "role_map": {e["address"]: e["role"] for e in ents}},
        timeline=timeline, entities=ents, files=files, schema=3)
    with open(os.path.join(d, D.MANIFEST_FILE), "w", encoding="utf-8") as fh:
        json.dump(m, fh, indent=1)
    return d, m


class SchemaThreeTest(unittest.TestCase):
    def test_a_reused_address_round_trips_with_its_time_index(self):
        ents, c2, m3 = reuse_entities()
        with tempfile.TemporaryDirectory() as root:
            d, m = capture_v3(root, ents)
            self.assertEqual((m["format"], m["schema"]), (D.DATASET_FORMAT_V3, 3))
            self.assertEqual(D.manifest_problems(m), [])
            got, _ = D.read_dataset(d)
            self.assertEqual(got["manifest_sha256"], m["manifest_sha256"])
        rows = m["address_map"][c2["address"]]
        self.assertEqual([(r["entity_id"], r["start_s"], r["stop_s"]) for r in rows],
                         [(c2["entity_id"], 5.0, 25.0), (m3["entity_id"], 30.0, 50.0)])
        entry = m["ip_map"][c2["address"]]
        self.assertEqual(entry, {"class": "attack", "time_indexed": True,
                                 "entity_ids": sorted([c2["entity_id"], m3["entity_id"]])})
        self.assertNotIn("entity_id", entry, "no reader can take one entity's label for the other's")

    def test_each_defect_is_caught(self):
        cases = {"overlap": reuse_entities(overlap=True)[0], "two roles": reuse_entities(cross_role=True)[0]}
        with tempfile.TemporaryDirectory() as root:
            for name, ents in cases.items():
                _, m = capture_v3(os.path.join(root, name.replace(" ", "_")), ents)
                self.assertTrue(D.manifest_problems(m), name)
            _, m = capture_v3(os.path.join(root, "t0"), reuse_entities()[0], t0=None)
            self.assertIn("timeline.t0_wall missing", "; ".join(D.manifest_problems(m)))
            _, m = capture_v3(os.path.join(root, "map"), reuse_entities()[0])
            m["address_map"][next(iter(m["address_map"]))][0]["stop_s"] = 59.0
            FX.resign(m)
            self.assertIn("address_map does not match the entities", D.manifest_problems(m))

    def test_schema_two_still_refuses_a_duplicate_address(self):
        ents = reuse_entities()[0]
        with tempfile.TemporaryDirectory() as root, self.assertRaises(D.ManifestError) as caught:
            FX.capture(root, VERSION, 3201, "eval", ents)          # a schema-2 manifest
        self.assertIn(D.NEEDS_SCHEMA_3, str(caught.exception))

    def test_labels_by_time(self):
        ents, c2, m3 = reuse_entities()
        with tempfile.TemporaryDirectory() as root:
            _, m = capture_v3(root, ents)
        label = D.labeler(m)
        self.assertEqual(label(c2["address"], 10.0), ("attack", "C2", False, c2["entity_id"]))
        self.assertEqual(label(c2["address"], 30.0), ("attack", "C3b@M3", True, m3["entity_id"]))
        self.assertEqual(label(c2["address"], 27.0)[0], "other", "between the intervals")
        self.assertEqual(label(c2["address"], None)[0], "other", "no time, no label on a reused address")
        benign = next(e for e in ents if e["role"] == "benign")
        self.assertEqual(label(benign["address"], 1e9), ("benign", None, False, benign["entity_id"]))
        self.assertEqual(label("10.9.9.9", 1.0)[0], "other")

    def test_schema_one_and_two_labels_are_unchanged(self):
        ents = FX.entities(VERSION, 2001, held_out_family="f_h")
        with tempfile.TemporaryDirectory() as root:
            _, m2 = FX.capture(root, VERSION, 2001, "val", ents)
        label = D.labeler(m2)
        for ip, entry in m2["ip_map"].items():
            self.assertEqual(label(ip, 3.0), (*D.label_for(ip, m2["ip_map"]), entry["entity_id"]))
        m1 = {"ip_map": D.build_ip_map([{"ip": "10.0.1.1", "kind": "keepalive"}],
                                       [{"ip": "10.0.2.1", "family": "scraper", "held_out": True}])}
        label1 = D.labeler(m1)
        self.assertEqual(label1("10.0.2.1"), ("attack", "scraper", True, "10.0.2.1"))
        self.assertEqual(label1("10.0.1.1", 5.0), ("benign", None, False, "10.0.1.1"))


class ReadersTest(unittest.TestCase):
    def test_the_trainer_labels_a_reused_address_per_entity(self):
        ents, c2, m3 = reuse_entities()
        with tempfile.TemporaryDirectory() as root:
            d, _ = capture_v3(root, ents)
            _, recs = train_l7.load_records(d)
        mine = [r for r in recs if r["ip"] == c2["address"]]
        self.assertEqual({r["_entity"] for r in mine}, {c2["entity_id"], m3["entity_id"]})
        for r in mine:
            want = (c2["entity_id"], "C2", False) if r["msec"] < T0 + 26 else (m3["entity_id"], "C3b@M3", True)
            self.assertEqual((r["_entity"], r["_family"], r["_held"]), want)
            self.assertEqual(r["_kof"], want[1])

    def test_the_trainer_reads_schema_two_as_before(self):
        ents = FX.entities(VERSION, 2001)
        with tempfile.TemporaryDirectory() as root:
            d, m = FX.capture(root, VERSION, 2001, "val", ents)
            _, recs = train_l7.load_records(d)
        for r in recs:
            entry = m["ip_map"][r["ip"]]
            self.assertEqual((r["_entity"], r["_kof"]), (entry["entity_id"], entry["family"] or entry["kind"]))

    def test_rebuild_labels_list_a_reused_address_in_time_order(self):
        ents, c2, m3 = reuse_entities()
        with tempfile.TemporaryDirectory() as root:
            d, m = capture_v3(root, ents)
            lab = RB.labels([(d, m)])[m["capture_id"]]
        self.assertEqual([r["entity_id"] for r in lab[c2["address"]]], [c2["entity_id"], m3["entity_id"]])
        benign = next(e for e in ents if e["role"] == "benign")
        self.assertEqual(lab[benign["address"]]["entity_id"], benign["entity_id"])

    def test_the_disjointness_checker_accepts_schema_three_and_fails_closed_on_bad_reuse(self):
        with tempfile.TemporaryDirectory() as root:
            vdir = os.path.join(root, VERSION)
            tr, _ = FX.capture(vdir, VERSION, 1001, "train", FX.entities(VERSION, 1001), started="2026-11-01T10:00:00Z",
                               ended="2026-11-01T10:15:00Z")
            va, _ = FX.capture(vdir, VERSION, 2001, "val", FX.entities(VERSION, 2001), started="2026-11-01T11:00:00Z",
                               ended="2026-11-01T11:15:00Z")
            ev, _ = capture_v3(os.path.join(root, "ok"), reuse_entities()[0])
            self.assertEqual(l7_disjoint.check({"train": [tr], "val": [va], "eval": [ev]}), [])
            bad, _ = capture_v3(os.path.join(root, "bad"), reuse_entities(seed=3202, overlap=True)[0], seed=3202)
            fails = l7_disjoint.check({"train": [tr], "val": [va], "eval": [bad]})
            self.assertTrue(fails and all(f.startswith("1 ") for f in fails), fails)
            self.assertIn("overlaps", fails[0])


if __name__ == "__main__":
    unittest.main()
