"""P4's ladder (eval/p4_ladder.py; docs/P4_SLOW_DESIGN.md §5; review T-057 T057-04), on the fake host's runs: the knee and the halvings are read from
the run index, and the file opens the validation. Nothing touches the machine."""
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
for _p in (HERE, REPO, os.path.join(REPO, "eval"), os.path.join(REPO, "ml")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import p4_fake_host as F
import p4_ladder as L
import p4_runner as R

ATTACK, NO_ATTACK = 1, 0     # modelled attackers: the fake harms while an attack connection is held


class LadderCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def run_level(self, family, level, repeat, harms=ATTACK, seed=9101, attempt=1, halvings=0, calibration=R.PLACEHOLDER, **host):
        block = R.plan_block("ladder", seed, self.root, sources={family: level}, family=family, label=f"l{level}r{repeat}", attempt=attempt,
                             halvings=halvings, calibration=calibration)
        return R.run_block(F.FakeHost(modelled_attackers=harms, **host), block)

    def ladder(self, family, *rows):
        for level, first, second in rows:
            self.run_level(family, level, 1, first)
            self.run_level(family, level, 2, second)

    def read(self):
        return L.knees(self.root, R.PLACEHOLDER)


class KneeTest(LadderCase):
    def test_the_knee_is_the_lowest_level_that_harms_in_2_of_2_repeats(self):
        self.ladder("loris", (100, NO_ATTACK, NO_ATTACK), (175, ATTACK, NO_ATTACK), (250, ATTACK, ATTACK))
        self.ladder("post", (5, ATTACK, ATTACK))
        rec = self.read()
        self.assertEqual((rec["levels"], rec["no_knee"], rec["halvings"]), ({"loris": 250, "post": 5}, {}, 0))
        self.assertEqual(rec["families"]["loris"]["passing"], [250.0])
        self.assertEqual(rec["calibration_sha256"], R.sha256_file(R.PLACEHOLDER))
        self.assertEqual(len(rec["controls"]), 8)

    def test_a_third_repeat_or_another_seed_is_refused(self):
        """Review T-063 T063-05: a third repeat could turn a passing level into a failing one, and one on another seed could re-roll it."""
        self.ladder("loris", (100, ATTACK, ATTACK))
        with self.assertRaisesRegex(R.PlanError, r"the label 'l100r3' is not one of \['l100r1', 'l100r2'\]"):
            self.run_level("loris", 100, 3)
        with self.assertRaisesRegex(R.PlanError, "ladder l100r2 ran on seed 9101: a repeat is re-run on its own seed"):
            self.run_level("loris", 100, 2, seed=9102)

    def test_a_repeat_with_no_sound_attempt_stops_the_reader_until_it_is_re_run(self):
        """Review T-063 T063-01, D-067: an invalid U at loris 100 r2 counted as harm 0, so the knee moved to 175 with exit 0."""
        self.ladder("post", (5, ATTACK, ATTACK))
        self.run_level("loris", 100, 1)
        self.run_level("loris", 100, 2, attack_fails=True)
        self.ladder("loris", (175, ATTACK, ATTACK))
        out = os.path.join(self.root, "knees.json")
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(L.main([self.root, "--calibration", R.PLACEHOLDER, "--out", out]), 2)
        self.assertIn("loris 100: repeat l100r2 on seed 9101 has no sound attempt", err.getvalue())
        self.assertIn("re-run it, with its reason (D-067)", err.getvalue())
        self.assertFalse(os.path.exists(out))
        self.run_level("loris", 100, 2, attempt=2)
        self.assertEqual(self.read()["levels"]["loris"], 100, "its re-run counts")

    def test_the_knee_cannot_pass_on_one_sound_repeat(self):
        self.ladder("post", (5, ATTACK, ATTACK))
        self.run_level("loris", 100, 1)
        self.run_level("loris", 100, 2, attack_fails=True)
        with self.assertRaisesRegex(ValueError, "loris 100: repeat l100r2"):
            self.read()

    def test_no_knee_needs_two_sound_repeats_at_every_level_that_ran(self):
        self.ladder("post", (5, ATTACK, ATTACK))
        self.ladder("loris", (100, NO_ATTACK, NO_ATTACK))
        self.run_level("loris", 175, 1, NO_ATTACK)
        with self.assertRaisesRegex(ValueError, r"loris: no level passes, but level\(s\) \[175\] have fewer than 2 sound repeats"):
            self.read()
        self.run_level("loris", 175, 2, NO_ATTACK, attack_fails=True)
        with self.assertRaisesRegex(ValueError, "loris 175: repeat l175r2"):
            self.read()
        self.run_level("loris", 175, 2, NO_ATTACK, attempt=2)
        self.assertEqual(self.read()["levels"]["loris"], None)

    def test_a_missing_repeat_above_the_knee_is_named_and_does_not_stop_it(self):
        self.ladder("post", (5, ATTACK, ATTACK))
        self.ladder("loris", (100, ATTACK, ATTACK))
        self.run_level("loris", 175, 1, attack_fails=True)
        rec = self.read()
        self.assertEqual(rec["levels"]["loris"], 100)
        self.assertEqual(rec["families"]["loris"]["unsound_above_knee"], [(175, 9101, "l175r1")])

    def test_a_level_skipped_under_the_knee_is_refused(self):
        self.ladder("loris", (175, ATTACK, ATTACK))
        self.ladder("post", (5, ATTACK, ATTACK))
        with self.assertRaisesRegex(ValueError, "level.*100.*under it"):
            self.read()

    def test_a_family_with_no_knee_yet_is_named_incomplete(self):
        # D-073 (1), D-074: a ladder that stopped under its top is incomplete, and names the level that runs next (exit 3).
        self.ladder("loris", (100, NO_ATTACK, NO_ATTACK))
        self.ladder("post", (5, ATTACK, ATTACK))
        rec = self.read()
        self.assertEqual(rec["levels"], {"loris": None, "post": 5})
        self.assertFalse(rec["no_knee"]["loris"]["top_level_run"])
        self.assertEqual((rec["results"]["loris"]["status"], rec["results"]["loris"]["next_level"]), ("incomplete", 175))
        out = os.path.join(self.root, "knees.json")
        with contextlib.redirect_stdout(io.StringIO()) as said:
            self.assertEqual(L.main([self.root, "--calibration", R.PLACEHOLDER, "--out", out]), 3)
        self.assertIn("loris: no knee yet: level 175 runs next", said.getvalue())
        with self.assertRaisesRegex(R.PlanError, "loris has no knee .*level 175 runs next"):
            R.check_knees(R.plan_block("validation", 4001, self.root, sources={"loris": 100, "post": 5}, knees=out), F.FakeHost())

    def test_an_unhealthy_control_stops_it_and_is_named(self):
        self.ladder("post", (5, ATTACK, ATTACK))
        self.run_level("loris", 100, 1, harm=lambda _t: True)
        self.run_level("loris", 100, 2)
        out = os.path.join(self.root, "knees.json")
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(L.main([self.root, "--calibration", R.PLACEHOLDER, "--out", out]), 2)
        self.assertIn("unhealthy ladder controls [(9101, 'l100r1')]", err.getvalue())
        self.assertFalse(os.path.exists(out))

    def test_a_ladder_holds_one_halving_count_one_record_and_both_families(self):
        self.ladder("post", (5, ATTACK, ATTACK))
        with self.assertRaisesRegex(ValueError, "no run of loris"):
            self.read()
        self.run_level("loris", 100, 1)
        self.run_level("loris", 100, 2, halvings=1, seed=9102)
        with self.assertRaisesRegex(ValueError, r"\[0, 1\] halvings"):
            self.read()
        other = os.path.join(self.root, "other.json")
        with open(R.PLACEHOLDER, encoding="utf-8") as fh, open(other, "w", encoding="utf-8") as out:
            out.write(fh.read() + "\n")
        with self.assertRaisesRegex(ValueError, "ran under calibration"):
            L.knees(self.root, other)

    def test_the_tool_starts_on_its_own(self):
        run = subprocess.run([sys.executable, os.path.join(REPO, "eval", "p4_ladder.py"), self.root, "--calibration", R.PLACEHOLDER, "--out", "x"],
                             env={"PATH": os.environ.get("PATH", "")}, capture_output=True, text=True, check=False, cwd=self.root)
        self.assertEqual(run.returncode, 2, run.stderr)
        self.assertIn("the index holds no ladder run", run.stderr)

    def test_no_ladder_is_refused(self):
        with self.assertRaisesRegex(ValueError, "no ladder run"):
            self.read()

    def test_the_file_opens_the_validation_at_its_knee_and_no_other(self):
        self.ladder("loris", (100, ATTACK, ATTACK))
        self.ladder("post", (5, NO_ATTACK, NO_ATTACK), (10, ATTACK, ATTACK))
        out = os.path.join(self.root, "knees.json")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(L.main([self.root, "--calibration", R.PLACEHOLDER, "--out", out]), 0)
        with open(out, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["levels"], {"loris": 100, "post": 10})
        res = R.run_block(F.FakeHost(modelled_attackers=1), R.plan_block("validation", 4001, self.root, sources={"loris": 100, "post": 10}, knees=out))
        self.assertEqual(len(res), 3)
        with self.assertRaisesRegex(R.PlanError, "are not the ladder's knees"):
            R.run_block(F.FakeHost(), R.plan_block("validation", 4002, self.root, sources={"loris": 175, "post": 10}, knees=out))


if __name__ == "__main__":
    unittest.main()
