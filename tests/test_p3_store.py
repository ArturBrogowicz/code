"""The P3 dataset store and the capture runner's pure parts (docs/P3_DATASET_DESIGN.md §4.5, D-D1). Everything is
written under temporary directories; nothing runs as root and no namespace is made."""
import gzip
import inspect
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "ml"))
import capture_l7
import l7_store as ST

import l7_dataset as D


def read_bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


def read_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


class StorePathTest(unittest.TestCase):
    def test_refused_under_purged_trees_and_the_repository(self):
        roots = ST.refused_roots(REPO)
        for store in ("/var/tmp/ddos_l7_datasets", "/tmp/x", REPO, os.path.join(REPO, "results")):
            with self.assertRaises(ST.StoreError, msg=store):
                ST.version_dir(store, "2026-11-v1", roots)
        self.assertEqual(ST.version_dir("/home/artur/datasets/l7", "2026-11-v1", roots),
                         "/home/artur/datasets/l7/2026-11-v1")
        with self.assertRaises(ST.StoreError):
            ST.version_dir("/home/artur/datasets/l7", "../x", roots)
        self.assertIn('"/home/artur/datasets/l7"', inspect.getsource(capture_l7.main))   # the CLI default
        self.assertEqual(ST.DEFAULT_STORE, "/home/artur/datasets/l7")

    def test_cli_refuses_a_var_tmp_store_before_anything_else(self):
        r = subprocess.run([sys.executable, os.path.join(REPO, "ml", "capture_l7.py"), "--version", "2026-11-v1",
                            "--seed", "9201", "--seed-role", "pilot", "--gate-seeds", "2",
                            "--store", "/var/tmp/p3"], capture_output=True, text=True, check=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("refused", r.stderr)

    def test_capture_id(self):
        st = time.strptime("2026-11-02T10:05:09Z", "%Y-%m-%dT%H:%M:%SZ")
        self.assertEqual(ST.capture_id(9201, st), "s9201-20261102T100509Z")


class StoreFilesTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="p3store_")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.vdir = os.path.join(self.root, "2026-11-v1")

    def staged(self, cid, text=b'{"ip":"10.0.16.5"}\n' * 3):
        cap, staging = ST.make_capture_dir(self.vdir, cid)
        with open(os.path.join(staging, "access.log"), "wb") as fh:
            fh.write(text)
        return cap, staging

    def test_capture_dirs_are_never_reused(self):
        self.staged("s9201-x")
        with self.assertRaises(FileExistsError):
            ST.make_capture_dir(self.vdir, "s9201-x")

    def test_finalize_gzips_verifies_and_removes_only_its_staging(self):
        cap, staging = self.staged("s9201-a")
        keep = os.path.join(cap, "nginx_l7capture.conf")
        with open(keep, "w", encoding="utf-8") as fh:
            fh.write("conf\n")
        recs = ST.finalize_logs(staging, cap)
        self.assertFalse(os.path.exists(staging))
        self.assertTrue(os.path.exists(keep))
        self.assertEqual([r["path"] for r in recs], ["access.log.gz", "error.log.gz"])
        self.assertEqual(recs[0]["lines"], 3)
        self.assertEqual(recs[1]["lines"], 0)                       # an absent log is recorded empty
        with gzip.open(os.path.join(cap, "access.log.gz"), "rb") as fh:
            self.assertEqual(fh.read(), b'{"ip":"10.0.16.5"}\n' * 3)
        cap2, staging2 = self.staged("s9201-b")
        ST.finalize_logs(staging2, cap2)
        for name in ("access.log.gz", "error.log.gz"):              # deterministic bytes
            self.assertEqual(ST.sha256_file(os.path.join(cap, name)), ST.sha256_file(os.path.join(cap2, name)))

    def test_a_bad_copy_keeps_the_staging_directory(self):
        cap, staging = self.staged("s9201-c")

        def corrupt(src, dst):
            with gzip.open(dst, "wb") as fh:
                fh.write(b"other\n")
        with mock.patch.object(ST, "gzip_file", corrupt), self.assertRaises(ST.StoreError):
            ST.finalize_logs(staging, cap)
        self.assertTrue(os.path.exists(os.path.join(staging, "access.log")))

    def test_finalize_refuses_a_foreign_directory(self):
        cap, _staging = self.staged("s9201-d")
        other = tempfile.mkdtemp(prefix="notstaging_", dir=self.root)
        with self.assertRaises(ST.StoreError):
            ST.finalize_logs(other, cap)
        self.assertTrue(os.path.isdir(other))

    def test_sha256sums_cover_every_file_and_catch_changes(self):
        cap, staging = self.staged("s9201-e")
        ST.finalize_logs(staging, cap)
        ST.write_sha256sums(self.vdir, "s9201-e")
        listed = ST.read_sha256sums(self.vdir)
        self.assertEqual(sorted(listed), ["s9201-e/access.log.gz", "s9201-e/error.log.gz"])
        self.assertEqual(ST.sha256sums_problems(self.vdir), [])
        path = os.path.join(cap, "access.log.gz")
        blob = bytearray(read_bytes(path))
        blob[-1] ^= 1
        with open(path, "wb") as fh:
            fh.write(blob)
        self.assertEqual(ST.sha256sums_problems(self.vdir), ["s9201-e/access.log.gz: sha256 differs from SHA256SUMS"])
        with open(os.path.join(cap, "extra.txt"), "w", encoding="utf-8") as fh:
            fh.write("x")
        self.assertIn("s9201-e/extra.txt: not listed in SHA256SUMS", ST.sha256sums_problems(self.vdir))
        os.remove(os.path.join(cap, "error.log.gz"))
        self.assertIn("s9201-e/error.log.gz: listed but missing", ST.sha256sums_problems(self.vdir))

    def test_hand_back(self):
        cap, staging = self.staged("s9201-f")
        ST.finalize_logs(staging, cap)
        self.assertEqual(ST.hand_back(cap, 1000, 1000), 0 if os.geteuid() != 0 else 3)
        with mock.patch.object(ST.os, "geteuid", return_value=0), mock.patch.object(ST.os, "chown") as ch:
            self.assertEqual(ST.hand_back(cap, 1000, 1001), 3)
        self.assertEqual({c.args[1:] for c in ch.call_args_list}, {(1000, 1001)})
        with self.assertRaises(ST.StoreError):
            ST.store_owner(os.path.join(self.root, "absent"))
        self.assertEqual(ST.store_owner(self.root), (os.stat(self.root).st_uid, os.stat(self.root).st_gid))


class ResealTest(unittest.TestCase):
    """Review T-029 P3-06: a new capture is added to SHA256SUMS only if the existing sums still hold."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="p3reseal_")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.vdir = os.path.join(self.root, "2026-11-v1")

    staged = StoreFilesTest.staged

    def sealed(self):
        for cid in ("s9201-g", "s9202-h"):
            cap, staging = self.staged(cid)
            ST.finalize_logs(staging, cap)
            ST.write_sha256sums(self.vdir, cid)
        return read_bytes(os.path.join(self.vdir, ST.SUMS))

    def test_a_new_capture_is_added_to_verified_sums(self):
        self.sealed()
        self.assertEqual(sorted(ST.read_sha256sums(self.vdir)), ["s9201-g/access.log.gz", "s9201-g/error.log.gz",
                                                                 "s9202-h/access.log.gz", "s9202-h/error.log.gz"])
        self.assertEqual(ST.sha256sums_problems(self.vdir), [])

    def test_a_changed_or_stray_file_refuses_the_reseal(self):
        before = self.sealed()
        path = os.path.join(self.vdir, "s9201-g", "error.log.gz")
        with open(path, "ab") as fh:
            fh.write(b"x")
        cap, staging = self.staged("s9203-i")
        ST.finalize_logs(staging, cap)
        with self.assertRaises(ST.StoreError):
            ST.write_sha256sums(self.vdir, "s9203-i")
        self.assertEqual(read_bytes(os.path.join(self.vdir, ST.SUMS)), before)     # left as it was
        with open(os.path.join(self.vdir, "stray.txt"), "w", encoding="utf-8") as fh:
            fh.write("x")
        with self.assertRaises(ST.StoreError):
            ST.write_sha256sums(self.vdir, "s9203-i")

    def test_without_sums_only_the_new_capture_may_be_present(self):
        cap, staging = self.staged("s9201-j")
        ST.finalize_logs(staging, cap)
        cap2, staging2 = self.staged("s9202-k")
        ST.finalize_logs(staging2, cap2)
        with self.assertRaises(ST.StoreError):
            ST.write_sha256sums(self.vdir, "s9202-k")
        self.assertFalse(os.path.exists(os.path.join(self.vdir, ST.SUMS)))


class RunnerPartsTest(unittest.TestCase):
    def test_no_world_writable_logs_and_the_error_log_moves(self):
        src = inspect.getsource(capture_l7.P3Capture)
        for needle in ("0o666", "os.chmod", '"chmod"'):
            self.assertNotIn(needle, src)
        conf = capture_l7.render_conf("/s/access.log", "tolerant", "/s/error.log")
        self.assertIn("access_log /s/access.log l7json;", conf)
        self.assertIn("error_log /s/error.log info;", conf)
        self.assertNotIn("/var/log/nginx/error.log", conf)
        self.assertIn("error_log /var/log/nginx/error.log info;", capture_l7.render_conf("/s/a.log"))

    def test_alias_batch_and_entity_command(self):
        self.assertEqual(capture_l7.alias_batch(["10.0.16.5", "10.0.20.9"]),
                         "addr add 10.0.16.5/16 dev veth_in\naddr add 10.0.20.9/16 dev veth_in\n")
        S = mock.Mock(PYTHON_VENV="/v/python", SERVER_IP="10.0.0.1")
        e = {"role": "attack", "kind_or_family": "scraper", "port": 443, "client_seed": 77,
             "params": {"rps": 12.5, "port": 443}, "address": "10.0.23.4"}
        cap = capture_l7.P3Capture(mock.Mock(), "/x", "/x/.staging-1", {"entities": []})
        cmd = cap.entity_cmd(S, e, 200.0)
        self.assertEqual(cmd[cmd.index("--source") + 1], "10.0.23.4")
        self.assertEqual(cmd[cmd.index("--seed") + 1], "77")
        self.assertEqual(cmd[cmd.index("--family") + 1], "scraper")
        self.assertEqual(cap.access_log, "/x/.staging-1/access.log")

    def test_leftovers_include_p3_namespaces(self):
        listing = "l7n0_perfect (id: 1)\nl7n3_mobile_bad (id: 2)\nl7n_x (id: 3)\nb_10_0_1_1 (id: 4)\n"
        links = ["vo_l7n0_perfect", "vo_l7n3_mobile_", "vo_l7nx", "eth0"]
        ns, veths = capture_l7.l7_leftovers(listing, links)
        self.assertEqual(sorted(ns), ["b_10_0_1_1", "l7n0_perfect", "l7n3_mobile_bad"])
        self.assertEqual(sorted(veths), ["vo_l7n0_perfect", "vo_l7n3_mobile_"])
        self.assertTrue(D.VERSION_RE.match("2026-11-v1"))


if __name__ == "__main__":
    unittest.main()
