"""Guards added after the review of the P3 pipeline (T-029). Address reuse (P3-09): schema 2 maps one address to one
entity, so two entities on one address, or one entity carrying a pool of users, are refused with the reason "needs
schema 3" (schema 3 is built on feat/l7v2-traffic). Temporary directories only."""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import p3_fixtures as FX

sys.path.insert(0, os.path.join(FX.REPO, "ml"))
import l7_disjoint as X

import l7_dataset as D

V = "2026-11-t1"
LATE = ("2026-11-03T10:00:00Z", "2026-11-03T10:17:00Z")


class GuardFixture(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="p3g_")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.vdir = os.path.join(self.root, V)

    def cap(self, seed, role, ents=None, **kw):
        return FX.capture(self.vdir, V, seed, role, ents if ents is not None else FX.entities(V, seed), **kw)[0]

    def splits(self, **over):
        s = {"train": [self.cap(1001, "train")], "val": [self.cap(2001, "val")],
             "eval": [self.cap(3201, "eval", started=LATE[0], ended=LATE[1])]}
        s.update(over)
        return s

    def rules(self, splits):
        return {f.split()[0] for f in X.check(splits)}


class InvalidCaptureTest(GuardFixture):
    """Review T-029 P3-05: an attempt that failed is recorded, but no fit may use it."""

    def test_not_ready_not_completed_or_empty_captures_fail(self):
        for kw in ({"ready": False}, {"completed": False}, {"per": 0}):
            s = self.splits(val=[self.cap(2002, "val", capture_id=f"s2002-{next(iter(kw))}", **kw)])
            fails = X.check(s)
            self.assertEqual({f.split()[0] for f in fails}, {"14"}, kw)
            self.assertIn("invalid capture", fails[0])
        self.assertEqual(self.rules(self.splits()), set())


class FailClosedGapsTest(GuardFixture):
    """Review T-029 P3-08: timestamps, file paths and held-out flags are checked, not trusted."""

    def manifest(self, seed=1001, **kw):
        return FX.capture(self.vdir, V, seed, "train", FX.entities(V, seed), **kw)[1]

    def test_timestamps_must_be_utc_iso_and_ordered(self):
        for start, end in (("2026-11-02 10:00", "2026-11-02T10:15:00Z"), ("2026-11-02T10:00:00Z", "tomorrow"),
                           ("2026-11-02T10:00:00Z", "2026-11-02T09:59:59Z"), ("2026-13-02T10:00:00Z", LATE[1])):
            m = self.manifest()
            m.update(started_utc=start, ended_utc=end)
            probs = D.manifest_problems(FX.resign(m))
            self.assertTrue(any("utc" in p for p in probs), (start, end, probs))

    def test_file_paths_stay_inside_the_capture(self):
        for path in ("../s1002/access.log.gz", "/etc/passwd", "sub/access.log.gz", ".."):
            m = self.manifest()
            m["files"][1] = dict(m["files"][1], path=path)
            probs = D.manifest_problems(FX.resign(m))
            self.assertTrue(any("plain name" in p for p in probs), (path, probs))

    def test_held_out_flags_are_checked_against_the_frozen_lists(self):
        self.assertTrue({"api_bulk", "padded_flood", "credstuff", "slowread"} <= X.frozen_held_out())
        ents = FX.entities(V, 1002, kinds=("browse", "api_bulk"))       # flag false, kind frozen as held out
        s = self.splits(train=[self.cap(1002, "train", ents)])
        self.assertEqual(self.rules(s), {"9"})
        ev = FX.entities(V, 3202, families=("f_a", "credstuff"))
        s = self.splits(eval=[self.cap(3202, "eval", ev, started=LATE[0], ended=LATE[1])])
        self.assertEqual(self.rules(s), {"9"})


class AddressReuseTest(GuardFixture):
    def test_two_entities_on_one_address_need_schema_3(self):
        ents = FX.entities(V, 1001)
        m = D.make_manifest_v2(dataset_version=V, capture_id="x", seed=1001, seed_role="train",
                               started_utc=LATE[0], ended_utc=LATE[1], duration_s=60.0,
                               code={"commit": FX.COMMIT, "dirty": False, "inputs_sha256": {"a": "0" * 64}},
                               server={"config_id": "A"}, host={}, pool={"role_map": {}}, timeline={},
                               entities=ents, files=[])
        ents[1] = dict(ents[1], address=ents[0]["address"])
        ents[1]["plan_sha256"] = D.entity_plan_sha256(ents[1])
        m["entities"] = ents
        probs = D.manifest_problems(FX.resign(m))
        self.assertTrue(any("needs schema 3" in p for p in probs), probs)

    def test_an_entity_with_several_users_on_one_address_needs_schema_3(self):
        ents = FX.entities(V, 1002)
        ents[0] = dict(ents[0], params={"users": 12, "level": 30})
        ents[0]["plan_sha256"] = D.entity_plan_sha256(ents[0])
        s = self.splits(train=[self.cap(1002, "train", ents)])
        fails = X.check(s)
        self.assertEqual({f.split()[0] for f in fails}, {"13"})
        self.assertIn("needs schema 3", fails[0])
        self.assertIn("12 users", fails[0])
        self.assertEqual(self.rules(self.splits()), set())      # one user per address passes
        bad = FX.entities(V, 1003)
        bad[0] = dict(bad[0], params={"users": "12"})            # not an int: unknown means fail
        bad[0]["plan_sha256"] = D.entity_plan_sha256(bad[0])
        self.assertIn("13", self.rules(self.splits(train=[self.cap(1003, "train", bad)])))

    def test_the_design_note_records_the_guard(self):
        with open(os.path.join(FX.REPO, "docs", "P3_DATASET_DESIGN.md"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("address reuse needs schema 3", text)
        self.assertIn("feat/l7v2-traffic", text)
        self.assertIn("schema 3", D.NEEDS_SCHEMA_3)


if __name__ == "__main__":
    unittest.main()
