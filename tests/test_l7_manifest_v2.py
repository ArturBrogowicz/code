"""Manifest schema 2 (docs/P3_DATASET_DESIGN.md §4.4): one row per entity, derived ip_map and schedule, the
hashes recomputed on validation, and a reader that takes the gzipped log. Offline, temporary directories."""
import copy
import gzip
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import p3_fixtures as FX

import l7_dataset as D

V = "2026-11-t1"


class SchemaTwoTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="p3m_")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.ents = FX.entities(V, 1001, held_out_family=None)
        self.dir, self.m = FX.capture(self.root, V, 1001, "train", self.ents)

    def test_valid_manifest_round_trips(self):
        m, log = D.read_dataset(self.dir)
        self.assertEqual(m, self.m)
        self.assertTrue(log.endswith(D.ACCESS_LOG_GZ))
        self.assertEqual(D.validate_manifest(m), m)
        self.assertEqual(m["ip_map"][self.ents[0]["address"]]["entity_id"], f"{V}:1001:0")
        self.assertEqual(D.label_for(self.ents[-1]["address"], m["ip_map"])[0], D.ATTACK)
        self.assertEqual(D.families(m, held_out=False), ["f_a", "f_b"])
        acc = next(f for f in m["files"] if f["path"] == D.ACCESS_LOG_GZ)
        with gzip.open(os.path.join(self.dir, D.ACCESS_LOG_GZ), "rb") as fh:
            self.assertEqual(acc["lines"], fh.read().count(b"\n"))

    def bad(self, mutate, resign=True):
        m = copy.deepcopy(self.m)
        mutate(m)
        if resign:
            FX.resign(m)
        with self.assertRaises(D.ManifestError):
            D.validate_manifest(m)
        return D.manifest_problems(m)

    def test_each_defect_is_caught(self):
        self.bad(lambda m: m.pop("seed_role"))
        self.bad(lambda m: m["code"].update(dirty=True))
        self.bad(lambda m: m["code"].update(dirty=None))                     # unknown means fail
        self.bad(lambda m: m.update(seed_role="test"))
        self.bad(lambda m: m["entities"][0].update(entity_id="x:1:0"))
        self.bad(lambda m: m["entities"][1].update(address=m["entities"][0]["address"]))
        self.bad(lambda m: m["entities"][0]["params"].update(level=60))      # plan changed, hash not
        self.bad(lambda m: m["entities"][0]["schedule"].update(stop_s=999.0))
        self.bad(lambda m: m["pool"]["role_map"].update({"10.0.99.1": "benign"}))
        self.bad(lambda m: m["ip_map"].popitem())
        self.bad(lambda m: m["schedule"].pop())
        self.bad(lambda m: m.update(files=[]))
        self.bad(lambda m: m.update(dataset_version="v1"))
        probs = self.bad(lambda m: m.update(notes="edited"), resign=False)
        self.assertEqual(probs, ["manifest_sha256 does not match the manifest"])

    def test_plan_hash_ignores_ids_and_positions(self):
        a = self.ents[0]
        b = dict(a, entity_id=f"{V}:9201:5", index=5, subseed=1, namespace="l7n9_perfect")
        self.assertEqual(D.entity_plan_sha256(a), D.entity_plan_sha256(b))
        self.assertNotEqual(D.entity_plan_sha256(a), D.entity_plan_sha256(dict(a, client_seed=1)))
        self.assertEqual(D.canonical_json({"b": 1, "a": [1, 2]}), b'{"a":[1,2],"b":1}')

    def test_schema_one_reads_the_published_gzip_form(self):
        d = tempfile.mkdtemp(prefix="p3v1_")
        self.addCleanup(shutil.rmtree, d, True)
        ip_map = D.build_ip_map([{"ip": "10.0.1.1", "kind": "k", "profile": "perfect"}],
                                [{"ip": "10.0.2.1", "family": "f", "held_out": False}])
        m = D.make_manifest(seed=1, duration_s=60.0, ip_map=ip_map,
                            schedule=[{"ip": "10.0.2.1", "start_s": 1.0, "stop_s": 2.0}], provenance={})
        D.write_dataset_manifest(os.path.join(d, D.MANIFEST_FILE), m)
        FX.write_gz(os.path.join(d, "access.log.gz"), json.dumps({"ip": "10.0.1.1"}) + "\n")
        _, log = D.read_dataset(d)
        self.assertTrue(log.endswith("access.log.gz"))
        with D.open_log(log) as fh:
            self.assertEqual(json.loads(fh.readline())["ip"], "10.0.1.1")
        with open(os.path.join(d, "access.log"), "w", encoding="utf-8") as fh:
            fh.write("")
        self.assertTrue(D.read_dataset(d)[1].endswith("access.log"))        # the plain file wins

    def test_trainer_reads_a_gzipped_schema_two_capture(self):
        import train_l7 as T
        _, recs = T.load_records(self.dir)
        self.assertEqual({r["_cls"] for r in recs}, {D.BENIGN, D.ATTACK})
        self.assertEqual(len(recs), 40 * len(self.ents))


if __name__ == "__main__":
    unittest.main()
