"""The disjointness checker fails closed (docs/P3_DATASET_DESIGN.md §4.7): a clean fixture passes, and each rule
fires on a fixture built to break it. Temporary directories only."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import p3_fixtures as FX

sys.path.insert(0, os.path.join(FX.REPO, "ml"))
import l7_disjoint as X

import l7_dataset as D

V = "2026-11-t1"
EARLY = ("2026-11-02T10:00:00Z", "2026-11-02T10:15:00Z")
LATE = ("2026-11-03T10:00:00Z", "2026-11-03T10:17:00Z")


def read_bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


def read_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


class Fixture(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="p3dj_")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.vdir = os.path.join(self.root, V)

    def cap(self, seed, role, *, when=EARLY, ents=None, **kw):
        ents = ents if ents is not None else FX.entities(V, seed)
        return FX.capture(self.vdir, V, seed, role, ents, started=when[0], ended=when[1],
                          capture_id=kw.pop("capture_id", None), **kw)[0]

    def clean(self):
        return {"train": [self.cap(1001, "train"), self.cap(1002, "train")], "val": [self.cap(2001, "val")],
                "eval": [self.cap(3201, "eval", when=LATE, ents=FX.entities(V, 3201, held_out_family="f_h"))]}

    def rules(self, splits, **kw):
        return {f.split()[0] for f in X.check(splits, **kw)}


class PassTest(Fixture):
    def test_clean_fixture_passes(self):
        splits = self.clean()
        self.assertEqual(X.check(splits), [])
        self.assertTrue(X.require(splits))

    def test_cli(self):
        s = self.clean()
        args = [sys.executable, os.path.join(FX.REPO, "ml", "l7_disjoint.py"), "--check", "--train", *s["train"],
                "--val", *s["val"], "--eval", *s["eval"]]
        r = subprocess.run(args, capture_output=True, text=True, check=False)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("PASS", r.stdout)
        r = subprocess.run(args[:-2] + ["--eval", s["train"][0]], capture_output=True, text=True, check=False)
        self.assertEqual(r.returncode, 1)
        self.assertIn("refusing", r.stdout)


class RuleTest(Fixture):
    def test_1_missing_field_or_unreadable(self):
        s = self.clean()
        path = os.path.join(s["val"][0], D.MANIFEST_FILE)
        m = read_json(path)
        del m["started_utc"]
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(FX.resign(m), fh)
        self.assertEqual(self.rules(s), {"1"})
        s["val"] = [os.path.join(self.root, "absent")]
        self.assertEqual(self.rules(s), {"1"})
        with self.assertRaises(X.DisjointnessError):
            X.require(s)

    def test_2_and_3_a_seed_in_two_splits(self):
        s = self.clean()
        s["eval"].append(self.cap(1001, "eval", when=LATE, capture_id="s1001-again"))
        got = self.rules(s)
        self.assertTrue({"2", "3", "4", "5"} <= got, got)

    def test_3_a_seed_twice_within_a_split(self):
        s = self.clean()
        s["train"].append(self.cap(1001, "train", capture_id="s1001-b", ents=FX.entities(V, 1001, base=40)))
        self.assertIn("3", self.rules(s))

    def test_4_and_5_a_replayed_plan_under_new_ids(self):
        s = self.clean()
        replay = []
        for e in FX.entities(V, 1001):                        # the same plans, the eval seed's ids
            e = dict(e, entity_id=f"{V}:3202:{e['index']}")
            replay.append(e)
        s["eval"].append(self.cap(3202, "eval", when=LATE, ents=replay))
        self.assertEqual(self.rules(s), {"4", "5"})

    def test_5_one_plan_shared(self):
        s = self.clean()
        ents = FX.entities(V, 3202)
        ents[0] = dict(FX.entities(V, 1001)[0], entity_id=f"{V}:3202:0")
        s["eval"].append(self.cap(3202, "eval", when=LATE, ents=ents))
        self.assertEqual(self.rules(s), {"5"})

    def test_6_evaluation_recorded_before_training_ended(self):
        s = self.clean()
        s["eval"] = [self.cap(3202, "eval", when=("2026-11-02T10:10:00Z", "2026-11-02T10:27:00Z"))]
        self.assertEqual(self.rules(s), {"6"})

    def test_7_generator_commit_differs_within_a_version(self):
        s = self.clean()
        s["val"].append(self.cap(2002, "val", commit="f" * 40))
        self.assertEqual(self.rules(s), {"7"})

    def test_8_a_flipped_byte_in_a_file(self):
        s = self.clean()
        path = os.path.join(s["train"][1], D.ACCESS_LOG_GZ)
        blob = bytearray(read_bytes(path))
        blob[len(blob) // 2] ^= 0x01
        with open(path, "wb") as fh:
            fh.write(blob)
        self.assertEqual(self.rules(s), {"8"})
        self.assertEqual(self.rules(s, verify_files=False), set())

    def test_9_held_out_in_training(self):
        s = self.clean()
        s["train"].append(self.cap(1003, "train", ents=FX.entities(V, 1003, held_out_family="f_h")))
        self.assertEqual(self.rules(s), {"9"})

    def test_10_split_file_and_selection(self):
        s = self.clean()
        split = os.path.join(self.root, "split.json")
        sha = X.write_split(split, s)
        sel = os.path.join(self.root, "selection.json")
        with open(sel, "w", encoding="utf-8") as fh:
            json.dump({"split_sha256": sha}, fh)
        self.assertEqual(self.rules(s, split_file=split, selection_file=sel), set())
        with open(sel, "w", encoding="utf-8") as fh:
            json.dump({"split_sha256": "0" * 64}, fh)
        self.assertEqual(self.rules(s, split_file=split, selection_file=sel), {"10"})
        self.assertEqual(self.rules(s, split_file=split), {"10"})              # a missing selection fails
        rec = X.split_record(s)
        self.assertEqual(rec["entities"][f"{V}:2001:0"], "val")

    def test_11_role_and_pre_registration(self):
        s = self.clean()
        s["val"] = [self.cap(1003, "train")]                  # a training capture used as validation
        self.assertIn("11", self.rules(s))
        s = self.clean()
        s["train"].append(self.cap(1005, "train"))            # not a pre-registered training seed
        self.assertEqual(self.rules(s), {"11"})

    def test_12_empty_split(self):
        s = self.clean()
        s["val"] = []
        self.assertEqual(self.rules(s), {"12"})


if __name__ == "__main__":
    unittest.main()
