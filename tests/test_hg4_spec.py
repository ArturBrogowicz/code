"""HG4's spec at twice the new knee (bench/hg4_spec.py; docs/RECALIBRATION_2026-11_DESIGN.md K8, docs/HG1C_DESIGN.md departures 39 and
40). The shipped spec is what K8 wrote on the record of 2026-11-16 (cheap knee 4, level 8; T-122). The tool itself is tested on the spec
as AP-8 pinned it before K8 (level 4, twice the knee of 2), rebuilt here byte for byte: unchanged while the knee is 2, at 2 x any other
knee with a description of the plan's numbers, and refused where the protected arm would ban nothing. No test writes the shipped spec.
Offline."""
import contextlib
import copy
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
for sub in ("bench", "eval"):
    sys.path.insert(0, os.path.join(REPO, sub))
import calibration as C
import gate_campaign as GC
import hg4_spec as G
import scenario as SC

RECORD = os.path.join(REPO, "bench", "calibration", "ddos-mitigation-2026-11-04.json")         # cheap knee 2: the pre-K8 spec's record
NEW_RECORD = os.path.join(REPO, "bench", "calibration", "ddos-mitigation-2026-11-16.json")     # cheap knee 4: K8 ran on it (T-122)
PRE_K8_SHA256 = "f343364accc8a27d31da3233212142eb6aa7f5d577ea01e03744b392d10d4f4d"    # as AP-8 pinned it (T-092), before K8
SPEC_SHA256 = "aa43c8444ea6097681cb8da1d3174c070ccaf74b141cb989e636dd2a602e644c"      # as K8 wrote it on NEW_RECORD (T-122)
PRE_K8_DESCRIPTION = ("HG4's control where the rules win (D-071, R-020): the plain flood of the cheap dynamic route from 5 sources at "
                      "level 4, twice the frozen knee of 2, so that each source is well above limit_req's 30 r/s and the L7 rule's 50 r/s. "
                      "HG3 confirms the family at its knee with cheap_static_flood.")


def pre_k8(shipped):
    """The spec before K8: the shipped one at level 4 with AP-8's description (its sha256 is PRE_K8_SHA256, checked below)."""
    spec = copy.deepcopy(shipped)
    spec["description"] = PRE_K8_DESCRIPTION
    spec["intensity"]["level"] = 4
    return spec


def with_knee(knee):
    """The record of 2026-11-04 with another knee of the cheap flood, frozen again: a stand-in for a new record."""
    cal = copy.deepcopy(C.load(RECORD))
    cal["knees"]["cheap_static_flood"] = knee
    cal.pop("sha256")
    return C.freeze(cal, "2026-11-20T10:00:00Z")


def run(main, *argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


def sha256_of(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


class Hg4SpecTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        with open(G.SPEC, encoding="utf-8") as fh:
            self.shipped = json.load(fh)
        self.old = pre_k8(self.shipped)
        self.old_path = os.path.join(self.tmp.name, "cheap_static_flood_hg4.json")
        with open(self.old_path, "w", encoding="utf-8") as fh:
            fh.write(G.text_of(self.old))

    def test_the_pre_k8_spec_is_rebuilt_byte_for_byte(self):
        self.assertEqual(sha256_of(self.old_path), PRE_K8_SHA256)

    def test_the_shipped_spec_is_what_k8_writes_on_the_record_of_2026_11_16(self):
        with open(G.SPEC, "rb") as fh:
            raw = fh.read()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), SPEC_SHA256)
        self.assertEqual(G.text_of(self.shipped).encode(), raw, "the spec's own layout")
        new = C.load(NEW_RECORD)
        self.assertEqual(new["knees"]["cheap_static_flood"], 4.0)
        spec, changed, _ = G.spec_for(new, self.old)
        self.assertTrue(changed)
        self.assertEqual(G.text_of(spec).encode(), raw, "K8 on the new record writes exactly the shipped spec")
        spec, changed, a = G.spec_for(new, self.shipped)
        self.assertEqual((changed, spec["intensity"]["level"]), (False, 8))
        self.assertAlmostEqual(a["per_source_rate"], 119.25, places=2)
        self.assertEqual((a["rules"]["limit_req_sheds"], a["rules"]["l7_rule_bans"]), (True, True))
        code, out, err = run(G.main, "--calibration", NEW_RECORD)          # no --write: the default --spec, read only
        self.assertEqual((code, err), (G.EXIT_OK, ""))
        self.assertIn(f"{G.SPEC}: unchanged", out, "the default --spec is the shipped spec")
        copy_path = os.path.join(self.tmp.name, "shipped.json")
        with open(copy_path, "wb") as fh:
            fh.write(raw)
        code, out, _ = run(G.main, "--calibration", NEW_RECORD, "--spec", copy_path, "--write")
        self.assertEqual(code, G.EXIT_OK)
        self.assertIn("unchanged", out)
        self.assertEqual(sha256_of(copy_path), SPEC_SHA256)

    def test_at_the_knee_of_2_the_pre_k8_spec_stays_byte_for_byte(self):
        spec, changed, a = G.spec_for(C.load(RECORD), self.old)
        self.assertEqual((changed, spec["intensity"]["level"]), (False, 4))
        self.assertAlmostEqual(a["per_source_rate"], 61.67, places=2, msg="departure 39's 61.7 req/s")
        code, out, _ = run(G.main, "--calibration", RECORD, "--spec", self.old_path, "--write")
        self.assertEqual(code, G.EXIT_OK)
        self.assertIn("unchanged", out)
        self.assertEqual(sha256_of(self.old_path), PRE_K8_SHA256)

    def test_at_another_knee_it_takes_twice_it_and_the_plans_numbers(self):
        cal = with_knee(4.0)
        spec, changed, _ = G.spec_for(cal, self.old)
        self.assertTrue(changed)
        self.assertEqual(spec["intensity"]["level"], 8)
        self.assertEqual({k: v for k, v in spec.items() if k not in ("description", "intensity")},
                         {k: v for k, v in self.old.items() if k not in ("description", "intensity")})
        self.assertEqual(SC.problems_of(spec), [])
        text = spec["description"]
        plan = SC.plan(SC.from_record(spec), cal)["attack"]
        limit_req = next(t for t in plan["thresholds"] if t["name"] == "limit_req")
        self.assertIn(f"about {plan['per_source_rate']:.1f} req/s a source", text)
        self.assertIn(f"about {limit_req['ratio']:.2f} x limit_req's 30 r/s", text)
        self.assertIn(f"so it sheds about {round(100 * plan['rules']['reject_share'])} %", text)
        self.assertIn("above the L7 rule's 50 r/s, so the rule bans", text)
        self.assertIn(f"twice the frozen knee of 4 on the record of 2026-11-20 ({cal['sha256'][:8]})", text)
        self.assertIn("D-071", text)

    def test_the_campaigns_plan_exits_0_on_the_new_record_with_the_written_spec(self):
        cal = with_knee(4.0)
        cal_path, spec_path = os.path.join(self.tmp.name, "new.json"), os.path.join(self.tmp.name, "written.json")
        C.dump(cal, cal_path)
        with open(spec_path, "w", encoding="utf-8") as fh:
            fh.write(G.text_of(self.old))
        code, out, err = run(G.main, "--calibration", cal_path, "--spec", spec_path, "--write")
        self.assertEqual((code, err), (G.EXIT_OK, ""), out)
        self.assertEqual(SC.load(spec_path).intensity["level"], 8)
        code, out, err = run(GC.main, "plan", spec_path, "--calibration", cal_path, "--modes", "xdp")
        self.assertEqual((code, err), (GC.EXIT_OK, ""))
        self.assertIn("attack level 8", out)
        self.assertNotIn("`run` refuses this", out)
        code, out, _ = run(GC.main, "plan", self.old_path, "--calibration", cal_path, "--modes", "xdp")
        self.assertIn("`run` refuses this: cheap_static_flood_hg4 is at level 4", out, "the old spec on the new record")

    def test_the_shipped_spec_plans_on_the_record_of_2026_11_16_and_is_refused_on_that_of_2026_11_04(self):
        code, out, err = run(GC.main, "plan", G.SPEC, "--calibration", NEW_RECORD, "--modes", "xdp")
        self.assertEqual((code, err), (GC.EXIT_OK, ""))
        self.assertIn("attack level 8", out)
        self.assertNotIn("`run` refuses this", out)
        _, out, _ = run(GC.main, "plan", G.SPEC, "--calibration", RECORD, "--modes", "xdp")
        self.assertIn("`run` refuses this: cheap_static_flood_hg4 is at level 8", out, "the shipped spec on the old record")

    def test_where_the_protected_arm_would_ban_nothing_it_refuses_and_the_user_decides(self):
        cal = with_knee(1.0)
        spec, changed, a = G.spec_for(cal, self.old)
        self.assertEqual((changed, spec["intensity"]["level"], a["rules"]["l7_rule_bans"]), (True, 2, False))
        path = os.path.join(self.tmp.name, "low.json")
        C.dump(cal, path)
        code, _, err = run(G.main, "--calibration", path, "--spec", self.old_path, "--write")
        self.assertEqual(code, G.EXIT_REFUSED)
        self.assertIn("the user decides before P2-1", err)
        self.assertEqual(sha256_of(self.old_path), PRE_K8_SHA256, "nothing written")
        self.assertEqual(sha256_of(G.SPEC), SPEC_SHA256)

    def test_the_multiple_is_departure_39s_and_no_golden_plan_prints_the_spec(self):
        self.assertEqual(GC.HG4_KNEE_MULTIPLE, {"cheap_static_flood": 2})
        self.assertEqual(G.GOLDENS, ())
        golden = os.path.join(HERE, "golden")
        for name in os.listdir(golden):
            if name.endswith(".plan.txt"):
                with open(os.path.join(golden, name), encoding="utf-8") as fh:
                    text = fh.read()
                for spec in (self.shipped, self.old):
                    self.assertNotIn(spec["description"], text, name)

    def test_a_placeholder_or_a_record_without_the_knee_is_refused(self):
        with self.assertRaisesRegex(ValueError, "a frozen record with a knee"):
            G.spec_for(C.load(C.PLACEHOLDER), self.shipped)


if __name__ == "__main__":
    unittest.main()
