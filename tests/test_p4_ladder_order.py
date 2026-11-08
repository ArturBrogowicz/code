"""D-073 (1), D-073 (5) and D-074 (2026-11-07T08:33Z): the extended loris ladder runs a level above its first three only once no lower level
is a knee; each family's reading has a status; no knee up to the reachable top is a reported result (rule A), a level not reachable is named
and never read as no harm, and an incomplete ladder gives no reading (T-074). Nothing touches the machine."""
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
import p4_traffic as PT
import test_p4_runner as TR

LORIS = ("loris",)
CLEAN, HARM = [0.2, 0.3], [1.4, 1.1]     # harm per repeat: under and over the gate's either-or (calibrate.harm, floor 1.0)
LEVELS = PT.FAMILIES["loris"]["levels"]


def ladder(rows):
    return {n: list(h) for n, h in rows}


class ResultTest(unittest.TestCase):
    def test_the_knee(self):
        res, _k = L._result("loris", ladder([(100, CLEAN), (175, CLEAN), (250, HARM)]), {}, ())
        self.assertEqual((res["status"], res["level"]), ("knee", 250))

    def test_no_knee_up_to_the_top_is_rule_a(self):
        res, _k = L._result("loris", ladder((n, CLEAN) for n in LEVELS), {}, ())
        self.assertEqual((res["status"], res["level"], res["top"], res["next_level"]), ("no knee", None, 500, None))

    def test_a_ladder_that_stopped_under_its_top_is_incomplete(self):
        for ran, following in ((LEVELS[:3], 300), (LEVELS[:5], 500), (LEVELS[:1], 175)):
            res, _k = L._result("loris", ladder((n, CLEAN) for n in ran), {}, ())
            self.assertEqual((res["status"], res["next_level"]), ("incomplete", following), ran)

    def test_a_top_not_reachable_ends_the_ladder_below_it_and_is_named(self):
        res, _k = L._result("loris", ladder((n, CLEAN) for n in LEVELS[:5]), {}, (500,))
        self.assertEqual((res["status"], res["top"], res["not_reachable"]), ("no knee", 400, [500]))

    def test_a_hole_or_a_short_level_is_still_refused(self):
        with self.assertRaisesRegex(ValueError, "repeat l400r2 on seed 9101 has no sound attempt"):
            L._result("loris", ladder((n, CLEAN) for n in LEVELS[:4]) | {400: [0.1]}, {400: [(9101, "l400r2")]}, ())
        with self.assertRaisesRegex(ValueError, r"level\(s\) \[400\] have fewer than 2 sound repeats"):
            L._result("loris", ladder((n, CLEAN) for n in LEVELS[:4]) | {400: [0.1]}, {}, ())


class UnreachableTest(unittest.TestCase):
    def spec(self, **kw):
        return {"levels": [500], "why": "2026-11-09: P4-S s2's free memory", "s2": "smoke/s2/U_loris",
                "s2_started": "2026-11-08T10:00:00Z", **kw}

    def test_only_the_top_above_the_always_run_levels_and_not_run_with_a_dated_why(self):
        harms = {"loris": ladder((n, CLEAN) for n in LEVELS[:5])}
        L.check_unreachable({"loris": self.spec()}, LORIS, harms, {"loris": {}}, ladder_start="2026-11-09T00:00:00Z")
        for kw, why in (({"levels": [400]}, "only loris's top, 500"), ({"why": "s2 failed"}, "--why naming the dated reading")):
            with self.assertRaisesRegex(ValueError, why):
                L.check_unreachable({"loris": self.spec(**kw)}, LORIS, harms, {"loris": {}})
        ran = {"loris": ladder((n, CLEAN) for n in LEVELS)}
        with self.assertRaisesRegex(ValueError, "loris 500 has run"):
            L.check_unreachable({"loris": self.spec()}, LORIS, ran, {"loris": {}})
        with self.assertRaisesRegex(ValueError, "only post's top, 40"):
            L.check_unreachable({"post": self.spec(levels=[20])}, OUT.FAMILIES, {"post": {}}, {"post": {}})

    def test_the_s2_run_and_its_date_are_required_D080(self):
        # D-080 (T078-06): --unreachable names the s2 run, and its reading must precede the ladder's first run.
        harms = {"loris": ladder((n, CLEAN) for n in LEVELS[:5])}
        with self.assertRaisesRegex(ValueError, "needs --s2 naming the P4-S s2 run directory"):
            L.check_unreachable({"loris": {"levels": [500], "why": "2026-11-09: x"}}, LORIS, harms, {"loris": {}})
        with self.assertRaisesRegex(ValueError, "has no run.json with a started_utc"):
            L.check_unreachable({"loris": self.spec(s2_started=None)}, LORIS, harms, {"loris": {}}, ladder_start="2026-11-09T00:00:00Z")
        with self.assertRaisesRegex(ValueError, r"dated 2026-11-10T00:00:00Z, after the ladder's first run 2026-11-09T00:00:00Z"):
            L.check_unreachable({"loris": self.spec(s2_started="2026-11-10T00:00:00Z")}, LORIS, harms, {"loris": {}},
                                ladder_start="2026-11-09T00:00:00Z")


class S2DatingTest(unittest.TestCase):
    """D-080 (T078-06): knees reads the s2 run's run.json and the ladder's first-run time, and refuses an s2 reading dated after it."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        os.makedirs(os.path.join(self.root, "smoke", "s2", "U_loris"))
        self.rows = [{"phase": "ladder", "started_utc": "2026-11-09T00:00:00Z"}]

    def s2(self, started):
        with open(os.path.join(self.root, "smoke", "s2", "U_loris", "run.json"), "w", encoding="utf-8") as fh:
            json.dump({"started_utc": started}, fh)

    def knees(self, started):
        self.s2(started)
        harms = {"loris": ladder((n, CLEAN) for n in LEVELS[:5])}       # no knee up to 400; 500 proposed not reachable
        with mock.patch.object(L, "_ladder", return_value=("frozen", "x", 0, LORIS, harms, {"loris": {}}, [])), \
                mock.patch.object(R, "read_index", return_value=self.rows):
            return L.knees(self.root, R.PLACEHOLDER,
                           {"loris": {"levels": [500], "why": "2026-11-09: s2 memory", "s2": "smoke/s2/U_loris"}})

    def test_a_reading_before_the_ladder_is_accepted_and_recorded(self):
        rec = self.knees("2026-11-08T10:00:00Z")
        res = rec["results"]["loris"]
        self.assertEqual((res["status"], res["top"], res["not_reachable"]), ("no knee", 400, [500]))
        self.assertEqual((res["s2_run"], res["s2_started"]), ("smoke/s2/U_loris", "2026-11-08T10:00:00Z"))

    def test_a_reading_after_the_ladders_first_run_is_refused(self):
        with self.assertRaisesRegex(ValueError, "after the ladder's first run"):
            self.knees("2026-11-09T12:00:00Z")

    def test_the_command_line_requires_s2(self):
        with contextlib.redirect_stderr(io.StringIO()) as err, self.assertRaises(SystemExit):
            L.main([self.root, "--calibration", R.PLACEHOLDER, "--out", os.path.join(self.root, "k.json"),
                    "--unreachable", "500", "--why", "2026-11-09: s2"])
        self.assertIn("--unreachable needs --s2", err.getvalue())


class OrderTest(unittest.TestCase):
    def allowed(self, rows, level):
        with mock.patch.object(R, "read_index", return_value=[{"phase": "ladder"}]), \
                mock.patch.object(L, "_ladder", return_value=("frozen", "x", 0, LORIS, {"loris": ladder(rows)}, {"loris": {}}, [])):
            L.next_allowed("/nonexistent", R.PLACEHOLDER, "loris", level)

    def test_the_first_three_levels_always_run(self):
        for n in LEVELS[:3]:
            L.next_allowed("/nonexistent", R.PLACEHOLDER, "loris", n)

    def test_a_higher_level_waits_for_every_lower_one(self):
        self.allowed([(n, CLEAN) for n in LEVELS[:3]], 300)
        self.allowed([(n, CLEAN) for n in LEVELS[:4]], 400)
        self.allowed([(n, CLEAN) for n in LEVELS[:5]], 500)
        with self.assertRaisesRegex(ValueError, r"\[400\] has not"):
            self.allowed([(n, CLEAN) for n in LEVELS[:4]], 500)
        with self.assertRaisesRegex(ValueError, r"\[300\] has not"):
            self.allowed([*[(n, CLEAN) for n in LEVELS[:3]], (300, [0.2])], 400)
        with self.assertRaisesRegex(ValueError, r"\[100, 175, 250\] have not"):
            L.next_allowed(tempfile.gettempdir() + "/nonexistent-p4", R.PLACEHOLDER, "loris", 300)

    def test_no_level_above_a_knee_runs(self):
        with self.assertRaisesRegex(ValueError, "175 is the knee"):
            self.allowed([(100, CLEAN), (175, HARM), (250, HARM)], 300)
        self.allowed([(100, CLEAN), (175, [1.4, 0.3]), (250, CLEAN)], 300)          # harm in 1 of 2 is no knee

    def test_slow_post_keeps_its_fourth_level_rule(self):
        with mock.patch.object(R, "read_index", return_value=[{"phase": "ladder"}]), \
                mock.patch.object(L, "_ladder", return_value=("frozen", "x", 0, OUT.FAMILIES, {"post": ladder([(5, CLEAN), (10, HARM), (20, HARM)])},
                                                              {"post": {}}, [])), \
                self.assertRaisesRegex(ValueError, "10 is the knee"):
            L.next_allowed("/nonexistent", R.PLACEHOLDER, "post", 40)


class RunnerOrderTest(unittest.TestCase):
    """The runner asks before it runs a ladder block, on the fake host's runs."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def run_level(self, level, repeat, harm=0, **kw):
        block = R.plan_block("ladder", 9101, self.root, sources={"loris": level}, family="loris", label=f"l{level}r{repeat}", families=LORIS)
        return R.run_block(F.FakeHost(modelled_attackers=harm, **kw), block)

    def test_300_waits_for_the_three_below_and_is_refused_above_a_knee(self):
        with self.assertRaisesRegex(R.PlanError, r"ladder: loris 300 runs only once every lower level has 2 sound repeats"):
            self.run_level(300, 1)
        self.assertFalse(os.path.exists(os.path.join(self.root, "ladder", "b9101_a1_l300r1")), "nothing was started")
        for n in (100, 175):
            self.run_level(n, 1)
            self.run_level(n, 2)
        self.run_level(250, 1, harm=1)
        self.run_level(250, 2, harm=1)
        with self.assertRaisesRegex(R.PlanError, "250 is the knee"):
            self.run_level(300, 1)
        rec = L.knees(self.root, R.PLACEHOLDER)
        self.assertEqual((rec["results"]["loris"]["status"], rec["levels"]), ("knee", {"loris": 250}))


class ReadingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def record(self, results, rows=None, name="knees.json"):
        rec = {"format": L.FORMAT, "levels": {f: r.get("level") for f, r in results.items()}, "results": results, "halvings": 0,
               "family_set": list(results), "calibration_sha256": TR.sha(R.PLACEHOLDER),
               "families": {f: {"rows": rows or []} for f in results}}
        path = os.path.join(self.root, name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(rec, fh)
        return path, rec

    def test_rule_a_is_a_reported_result(self):
        path, rec = self.record({"loris": {"status": "no knee", "level": None, "top": 500, "next_level": None, "not_reachable": []}},
                                rows=[[n, CLEAN] for n in LEVELS])
        verdict = OUT.no_knee_verdict(rec)
        self.assertEqual(verdict["M7"], "not applicable: no harmful attack (D-074, rule A)")
        self.assertEqual(verdict["families"]["loris"]["reading"],
                         "Slowloris below the default rules' thresholds did not harm profile R up to 500 sources (D-074, rule A): "
                         "no validation and no campaign")
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(OUT.main(["--knees", path]), 0)
        self.assertIn("did not harm profile R up to 500 sources", out.getvalue())
        self.assertIn("500 sources: harm per repeat [0.2, 0.3]", out.getvalue())
        with self.assertRaisesRegex(R.PlanError, r"loris has no knee in .*up to 500 sources: P4 reads it as a result.*no validation and no campaign"):
            R.check_knees(R.plan_block("validation", 4001, self.root, sources={"loris": 100}, families=LORIS, knees=path), TR.HostThatMeasures())

    def test_a_level_not_reachable_is_named_and_is_not_no_harm(self):
        path, rec = self.record({"loris": {"status": "no knee", "level": None, "top": 400, "next_level": None, "not_reachable": [500],
                                           "why_not_reachable": "2026-11-09: s2's free memory"}})
        verdict = OUT.no_knee_verdict(rec)
        self.assertIn("up to 400 sources", verdict["families"]["loris"]["reading"])
        self.assertEqual(verdict["families"]["loris"]["not_reachable"],
                         [{"level": 500, "status": "not reachable", "why": "2026-11-09: s2's free memory"}])
        with contextlib.redirect_stdout(io.StringIO()) as out:
            OUT.main(["--knees", path])
        self.assertIn("500 sources: not reachable (2026-11-09: s2's free memory), which is not no harm", out.getvalue())

    def test_an_incomplete_ladder_gives_no_reading(self):
        path, rec = self.record({"loris": {"status": "incomplete", "level": None, "top": None, "next_level": 300, "not_reachable": []}})
        with self.assertRaisesRegex(ValueError, "level 300 runs next"):
            OUT.no_knee_verdict(rec)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(OUT.main(["--knees", path]), 2)
        with self.assertRaisesRegex(R.PlanError, "the ladder is incomplete: level 300 runs next"):
            R.check_knees(R.plan_block("validation", 4001, self.root, sources={"loris": 100}, families=LORIS, knees=path), TR.HostThatMeasures())

    def test_a_knee_leaves_the_verdict_to_the_campaign_and_runs_or_knees_must_be_given(self):
        _path, rec = self.record({"loris": {"status": "knee", "level": 250, "top": None, "next_level": None, "not_reachable": []}})
        self.assertEqual(OUT.no_knee_verdict(rec)["M7"], "the campaign's: every family has a knee")
        with self.assertRaises(ValueError):
            OUT.no_knee_verdict({"levels": {"loris": None}})
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            OUT.main([])


if __name__ == "__main__":
    unittest.main()
