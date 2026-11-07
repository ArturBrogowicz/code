"""D-069 (2026-11-06T16:30Z): P4 runs Slowloris only, and slow POST is fenced by a recorded families setting, its code kept and still
tested (T-074). The runner, the ladder's reader, the validation's scorer and the outcome follow the block's families: none of them
asks for a slow-POST run in a block that runs ("loris",). Nothing touches the machine."""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
for _p in (HERE, REPO, os.path.join(REPO, "eval"), os.path.join(REPO, "ml")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import p4_fake_host as F
import p4_ladder as L
import p4_outcome as OUT
import p4_runner as R
import p4_validation as V
import test_p4_runner as TR

LORIS = ("loris",)
POINT = TR.POINT


def selection(root, knees=None, level=100):
    path = os.path.join(root, "selection.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"selection": {"point": list(POINT)}, "slow_pc_sha256": TR.sha(os.path.join(REPO, "slow_pc.py")),
                   "settings": {"sources": {"loris": level, "post": 0}, "halvings": 0, "calibration_sha256": TR.sha(R.PLACEHOLDER),
                                "knees_sha256": TR.sha(knees) if knees else None}}, fh)
    return path


def knees(root, family_set=LORIS, level=100, name="knees.json"):
    path = os.path.join(root, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"levels": {f: (level if f == "loris" else 5) for f in family_set}, "halvings": 0, "family_set": list(family_set),
                   "calibration_sha256": TR.sha(R.PLACEHOLDER)}, fh)
    return path


class ArmsTest(unittest.TestCase):
    def test_the_arms_of_a_selection_of_families(self):
        self.assertEqual(OUT.CUT_FAMILIES, ("loris",))
        self.assertEqual(OUT.arms_of(LORIS), ("C", "Cp", "C_M", "U_loris", "M_def_loris", "M_pc_loris"))
        self.assertEqual(OUT.needed_arms(LORIS), ("C", "Cp", "C_M", "U_loris", "M_pc_loris"))
        self.assertEqual(OUT.validation_runs(LORIS), ("C", "U_loris"))
        self.assertEqual((OUT.arms_of(), OUT.needed_arms(), OUT.validation_runs()), (OUT.ARMS, OUT.NEEDED_ARMS, R.slow_pc.VALIDATION_RUNS))
        self.assertEqual(OUT.check_families(["post", "loris"]), ("loris", "post"))
        for bad in ((), "loris", ("loris", "loris"), ("loris", "read")):
            with self.assertRaises(ValueError):
                OUT.check_families(bad)
        self.assertEqual(OUT.settings_families({"sources": {}}), OUT.FAMILIES, "a block from before the cut ran both")


class PlanTest(unittest.TestCase):
    def test_a_slowloris_campaign_runs_six_arms_and_records_its_families(self):
        block = R.plan_block("campaign", 3101, "/r", sources={"loris": 100}, thresholds=POINT, families=LORIS)
        self.assertEqual(sorted(block["order"]), sorted(OUT.arms_of(LORIS)))
        self.assertEqual(block["families"], LORIS)
        self.assertEqual(R.block_settings(block)["families"], ["loris"])
        self.assertEqual(R.plan_block("campaign", 3101, "/r", sources=TR.KNEE, thresholds=POINT)["families"], OUT.FAMILIES)
        self.assertNotEqual(block["order"], R.plan_block("campaign", 3101, "/r", sources=TR.KNEE, thresholds=POINT)["order"])

    def test_the_validation_the_smoke_and_the_ladder_follow_them(self):
        val = R.plan_block("validation", 4001, "/r", sources={"loris": 100}, families=LORIS)
        self.assertEqual(sorted(val["order"]), ["C", "U_loris"])
        self.assertEqual(sorted(R.plan_block("smoke", 9101, "/r", label="s1", families=LORIS)["order"]), ["C", "U_loris"])
        R.plan_block("ladder", 9101, "/r", sources={"loris": 100}, family="loris", label="l100r1", families=LORIS)

    def test_a_fenced_family_is_refused_everywhere(self):
        bad = [lambda: R.plan_block("campaign", 3101, "/r", sources=TR.KNEE, thresholds=POINT, families=LORIS),
               lambda: R.plan_block("validation", 4001, "/r", sources={"loris": 100, "post": 5}, families=LORIS),
               lambda: R.plan_block("smoke", 9101, "/r", label="s1", arms=["U_post"], families=LORIS),
               lambda: R.plan_block("ladder", 9102, "/r", sources={"post": 20}, family="post", label="l20r1", families=LORIS),
               lambda: R.plan_block("campaign", 3101, "/r", sources={"loris": 100}, thresholds=POINT, arms=["M_pc_post"],
                                    families=LORIS),
               lambda: R.plan_block("campaign", 3101, "/r", sources={"loris": 100}, thresholds=POINT, families=("read",))]
        for make in bad:
            with self.assertRaisesRegex(R.PlanError, "D-069|families"):
                make()

    def test_the_command_line_runs_the_cut_by_default(self):
        base = ["--phase", "campaign", "--seed", "3101", "--loris", "100", "--thresholds", "5,256,2", "--root", "/nonexistent/p4", "--plan"]
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(R.main(base), 0)
        self.assertIn("families ['loris']", out.getvalue())
        self.assertNotIn("_post", out.getvalue())
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(R.main([*base, "--post", "5"]), 2)
        self.assertIn("D-069", err.getvalue())
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(R.main([*base, "--post", "5", "--families", "loris,post"]), 0)
        self.assertIn("run M_pc_post", out.getvalue())
        self.assertFalse(os.path.exists("/nonexistent/p4"))


class ReRunTest(unittest.TestCase):
    def check(self, arms, invalid=()):
        rows = [{"phase": "campaign", "block": 3101, "attempt": 1, "label": "", "arm": a, "valid": a not in invalid,
                 "dir": f"campaign/b3101_a1/{a}"} for a in arms]
        block = R.plan_block("campaign", 3101, "/nonexistent/root", attempt=2, sources={"loris": 100}, thresholds=POINT, families=LORIS)
        with mock.patch.object(R, "read_index", return_value=rows), \
                mock.patch.object(R, "run_record", return_value={"control_reasons": []}):
            R.check_attempt(block)

    def test_a_re_run_reads_the_needed_arms_of_its_families(self):
        with self.assertRaisesRegex(R.PlanError, "allows no re-run"):
            self.check(OUT.arms_of(LORIS))                       # no slow-POST arm ran, and none was needed
        self.check(OUT.arms_of(LORIS), invalid=("U_loris",))
        with self.assertRaisesRegex(R.PlanError, "allows no re-run"):
            self.check(OUT.arms_of(LORIS), invalid=("M_def_loris",))


class ExecuteTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def test_the_knees_must_be_read_on_the_blocks_families(self):
        block = R.plan_block("validation", 4001, self.root, sources={"loris": 100}, families=LORIS,
                             knees=knees(self.root, family_set=OUT.FAMILIES, name="both.json"))
        with self.assertRaisesRegex(R.PlanError, r"read the ladder of the families \['loris', 'post'\]"):
            R.check_knees(block, TR.HostThatMeasures())
        R.check_knees(R.plan_block("validation", 4001, self.root, sources={"loris": 100}, families=LORIS, knees=knees(self.root)),
                      TR.HostThatMeasures())

    def test_a_slowloris_ladder_is_read_without_a_slow_post_run(self):
        for level, harm in ((100, 0), (175, 1)):
            for repeat in (1, 2):
                R.run_block(F.FakeHost(modelled_attackers=harm),
                            R.plan_block("ladder", 9101, self.root, sources={"loris": level}, family="loris", label=f"l{level}r{repeat}",
                                         families=LORIS))
        rec = L.knees(self.root, R.PLACEHOLDER)
        self.assertEqual((rec["levels"], rec["family_set"]), ({"loris": 175}, ["loris"]))
        R.run_block(F.FakeHost(modelled_attackers=1),
                    R.plan_block("ladder", 9102, self.root, sources={"post": 5}, family="post", label="l5r1"))
        with self.assertRaisesRegex(ValueError, "a ladder holds one setting"):
            L.knees(self.root, R.PLACEHOLDER)

    def test_a_slowloris_validation_is_scored_on_c_and_u_loris(self):
        for seed in R.slow_pc.VALIDATION_SEEDS:
            res = R.run_block(F.FakeHost(poll_every_s=5.0, modelled_attackers=4),
                              R.plan_block("validation", seed, self.root, sources={"loris": 100}, families=LORIS))
            self.assertEqual(sorted(a for a, _r in res), ["C", "U_loris"])
        self.assertEqual(V.validation_families(self.root), LORIS)
        manifests, _attempts = V.runs_from_index(self.root)
        runs = [V.load_run(m) for m in manifests]
        V.check_runs(runs, LORIS)
        with self.assertRaisesRegex(ValueError, "must be exactly"):
            V.check_runs(runs)
        out = os.path.join(self.root, "selection.json")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertIn(V.main([self.root, "--json", out]), (0, 2))
        with open(out, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["settings"]["families"], ["loris"])

    def test_a_slowloris_campaign_block_is_judged_on_slowloris_alone(self):
        block = R.plan_block("campaign", 3101, self.root, sources={"loris": 100}, thresholds=POINT, families=LORIS,
                             selection=selection(self.root))
        res = R.run_block(F.FakeHost(modelled_attackers=6), block)
        self.assertTrue(all(r["ok"] for _a, r in res), [(a, r["reasons"]) for a, r in res if not r["ok"]])
        with open(os.path.join(block["dir"], "block.json"), encoding="utf-8") as fh:
            meta = json.load(fh)
        self.assertEqual((meta["families"], meta["settings"]["families"]), (["loris"], ["loris"]))
        runs = os.path.join(self.root, "runs.jsonl")
        R.summarize_root(self.root, R.PLACEHOLDER, runs, dry_run=True)
        with open(runs, encoding="utf-8") as fh:
            records = [json.loads(line) for line in fh]
        verdict = OUT.outcome(records, dry_run=True)
        self.assertEqual((verdict["families_run"], sorted(verdict["families"])), (["loris"], ["loris"]))
        self.assertEqual(verdict["M7"], "invalid (1 of 10 valid)")
        self.assertEqual(verdict["judged_attempts"], {3101: 1}, "no slow-POST arm was needed")
        stray = dict(records[0], arm="U_post")
        with self.assertRaisesRegex(ValueError, "a record of U_post, in a campaign of the families"):
            OUT.outcome([*records, stray], dry_run=True)


if __name__ == "__main__":
    unittest.main()
