"""Rebuild from the manifests (docs/P3_DATASET_DESIGN.md §4.6): two rebuilds are byte-identical, and a single
flipped byte in any input stops the rebuild before anything is derived. Temporary directories only."""
import filecmp
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
import l7_store
import rebuild_l7_dataset as R

import l7_dataset as D

V = "2026-11-t1"


def read_bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


def read_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


class RebuildTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="p3rb_")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.vdir = os.path.join(self.root, V)
        FX.capture(self.vdir, V, 1001, "train", FX.entities(V, 1001))
        FX.capture(self.vdir, V, 2001, "val", FX.entities(V, 2001))
        l7_store.write_sha256sums(self.vdir)

    def test_two_rebuilds_are_byte_identical(self):
        a, b = os.path.join(self.root, "out_a"), os.path.join(self.root, "out_b")
        sa, sb = R.rebuild(self.vdir, a), R.rebuild(self.vdir, b)
        self.assertEqual(sa, sb)
        names = sorted(os.listdir(a))
        self.assertEqual(names, ["labels.json", "rebuild.json", "split.json", "split.sha256", "windows.json"])
        self.assertEqual(filecmp.cmpfiles(a, b, names, shallow=False)[0], names)
        with open(os.path.join(a, "split.sha256"), encoding="utf-8") as fh:
            self.assertEqual(fh.read().split()[0], l7_store.sha256_file(os.path.join(a, "split.json")))
        split = read_json(os.path.join(a, "split.json"))
        self.assertEqual(split["entities"][f"{V}:1001:0"], "train")
        self.assertEqual(split["entities"][f"{V}:2001:3"], "val")
        lab = read_json(os.path.join(a, "labels.json"))
        self.assertEqual(lab["s1001"]["10.0.27.1"]["role"], "benign")
        win = read_json(os.path.join(a, "windows.json"))
        self.assertTrue(all(v["windows"] > 0 for v in win["captures"]["s1001"].values()))

    def flip_stops(self, rel):
        vdir = os.path.join(self.root, "copy", V)
        shutil.copytree(self.vdir, vdir)
        path = os.path.join(vdir, rel)
        blob = bytearray(read_bytes(path))
        blob[len(blob) // 2] ^= 0x01
        with open(path, "wb") as fh:
            fh.write(blob)
        with self.assertRaises(R.RebuildError, msg=rel):
            R.rebuild(vdir, os.path.join(self.root, "copy_out"))
        self.assertFalse(os.path.exists(os.path.join(self.root, "copy_out")), rel)    # nothing derived
        shutil.rmtree(os.path.join(self.root, "copy"))

    def test_a_flipped_byte_in_any_input_stops_it(self):
        for rel in ("s1001/manifest.json", "s1001/access.log.gz", "s2001/error.log.gz", "SHA256SUMS"):
            self.flip_stops(rel)

    def test_a_forged_manifest_with_updated_sums_still_stops_it(self):
        path = os.path.join(self.vdir, "s2001", D.MANIFEST_FILE)
        m = read_json(path)
        m["entities"][0]["role"] = "attack"                       # relabel one entity
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(m, fh)
        l7_store.write_sha256sums(self.vdir)                       # the sums agree with the forgery
        with self.assertRaises(R.RebuildError):
            R.rebuild(self.vdir, os.path.join(self.root, "out"))

    def test_cli_and_out_inside_the_version_refused(self):
        r = subprocess.run([sys.executable, os.path.join(FX.REPO, "ml", "rebuild_l7_dataset.py"), self.vdir,
                            "--out", os.path.join(self.root, "cli_out")], capture_output=True, text=True, check=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("split.json", r.stdout)
        with self.assertRaises(R.RebuildError):
            R.rebuild(self.vdir, os.path.join(self.vdir, "derived"))
        os.remove(os.path.join(self.vdir, "s1001", D.ACCESS_LOG_GZ))
        r = subprocess.run([sys.executable, os.path.join(FX.REPO, "ml", "rebuild_l7_dataset.py"), self.vdir,
                            "--out", os.path.join(self.root, "cli_out2")], capture_output=True, text=True, check=False)
        self.assertEqual(r.returncode, 1)
        self.assertIn("rebuild stopped", r.stderr)


if __name__ == "__main__":
    unittest.main()
