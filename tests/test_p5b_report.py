"""Unit tests for ml/p5b_report.py — the pre-registered P5b verdict (§7.2), on synthetic
fixture runs. Written before any P5b evaluation run exists."""
import json
import math
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "ml"))
import p5b_report as R

BENIGN = {"10.0.1.1": "browser_page", "10.0.1.2": "keepalive", "10.0.1.3": "crawler_polite",
          "10.0.1.4": "api_bulk"}
FAST = {"10.0.2.1": "subthreshold_flood", "10.0.2.2": "subthreshold_flood",
        "10.0.2.3": "scraper", "10.0.2.6": "padded_flood"}
OTHER = {"10.0.2.4": "slowloris", "10.0.2.7": "credstuff"}
ALL_FAST = sorted(FAST)


def b0_grid(at_zero=("10.0.2.2", "10.0.2.3"), with_benign=("10.0.1.1",)):
    """B0: a strict setting catching `at_zero` with no benign, a loose one that also
    flags `with_benign` while catching every fast attacker."""
    return {"peak1s>40": sorted(at_zero), "peak1s>20": sorted([*ALL_FAST, *with_benign]),
            "peak1s>50": []}


def make_run(root, name, *, gru=ALL_FAST, gru_benign=(), det=None, shaped=(), fams=None,
             soak=False, benign_events=0, duration=360.0):
    d = os.path.join(root, name)
    os.makedirs(d)
    ip_map = {ip: {"class": "benign", "kind": k, "held_out": k == "api_bulk"}
              for ip, k in BENIGN.items()}
    ip_map.update({ip: {"class": "attack", "family": f, "held_out": f == "padded_flood"}
                   for ip, f in {**FAST, **OTHER}.items()})
    det = det if det is not None else {"10.0.2.7": "l7_rate"}
    analysis = {"would_ban_ips": sorted([*gru, *gru_benign]), "det_banned_ips": det,
                "benign_would_ban_count": benign_events, "benign_ips_total": len(BENIGN),
                "by_family": {}}
    fams = dict(fams) if fams is not None else {f: {"x": []} for f in R.FAMILIES[1:]}
    fams.setdefault("B0", b0_grid())
    for fname, obj in (("summary.json", {"analysis": analysis, "duration_s": duration,
                                         "soak": soak}),
                       ("manifest.json", {"ip_map": ip_map}),
                       ("baselines.json", {"families": fams, "shaped_ips": list(shaped)})):
        with open(os.path.join(d, fname), "w", encoding="utf-8") as fh:
            json.dump(obj, fh)
    return d


class VerdictTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="p5b_")
        self.addCleanup(shutil.rmtree, self.root, True)

    def runs(self, n=5, **kw):
        sub = tempfile.mkdtemp(dir=self.root)          # A1..An, fresh per call
        return [R.load_run(make_run(sub, f"A{i}", **kw)) for i in range(1, n + 1)]

    def soak(self, events=0, duration=600.0):
        d = make_run(tempfile.mkdtemp(dir=self.root), "C", gru=(), benign_events=events,
                     duration=duration, soak=True)
        return {"summary": R.load_run(d)["summary"]}

    def test_mcnemar(self):
        self.assertEqual(R.mcnemar_one_sided(0, 0), 1.0)
        self.assertAlmostEqual(R.mcnemar_one_sided(5, 0), 1 / 32)
        self.assertAlmostEqual(R.mcnemar_one_sided(7, 1), 9 / 256)
        self.assertAlmostEqual(R.mcnemar_one_sided(4, 0), 1 / 16)
        self.assertAlmostEqual(R.mcnemar_one_sided(2, 3), sum(math.comb(5, k) for k in (2, 3, 4, 5)) / 32)

    def test_decisive_when_gru_beats_every_family(self):
        rep = R.evaluate(self.runs(), self.soak())
        self.assertEqual(rep["comparison_set"], 20)
        self.assertEqual(rep["gru"], {"caught": 20, "benign_flagged": 0})
        self.assertTrue(rep["V0_informative"]["pass"])
        self.assertEqual(rep["V3_baselines"]["B0"]["param"], "peak1s>40")   # 0-benign oracle
        self.assertEqual(rep["V3_baselines"]["B0"]["caught"], 10)
        self.assertEqual(rep["outcome"], "advantage shown - decisive")

    def test_indicative_when_not_significant(self):
        strong = {f: {"near": ["10.0.2.1", "10.0.2.2", "10.0.2.3"]} for f in R.FAMILIES[1:]}
        rep = R.evaluate(self.runs(fams=strong), self.soak())
        self.assertEqual(rep["V3_baselines"]["B2"]["gru_only"], 5)
        self.assertAlmostEqual(rep["V3_baselines"]["B2"]["mcnemar_p"], round(1 / 32, 5))
        b0_only = {"B0": {"peak1s>40": ["10.0.2.1", "10.0.2.2", "10.0.2.3"],
                          "peak1s>20": [*ALL_FAST, "10.0.1.1"]}}
        rep = R.evaluate(self.runs(n=3, fams={**strong, **b0_only}), self.soak())
        self.assertEqual(rep["outcome"], "advantage shown - indicative")     # 3 vs 0: p 1/8

    def test_keying_or_burst_when_a_rate_family_matches(self):
        fams = {f: {"none": []} for f in R.FAMILIES}
        fams["B2"] = {"ip:mean10s>15": ALL_FAST}               # sustained rate catches all
        rep = R.evaluate(self.runs(fams=fams), self.soak())
        self.assertFalse(rep["V3_baselines"]["B2"]["gru_beats"])
        self.assertTrue(rep["V3_baselines"]["B0"]["gru_beats"])
        self.assertEqual(rep["outcome"], "advantage from keying or burst handling, not learning")

    def test_no_advantage_when_only_the_tabular_baseline_matches(self):
        fams = {f: {"none": []} for f in R.FAMILIES}
        fams["B4"] = {"p>0.9x3": ALL_FAST}
        rep = R.evaluate(self.runs(fams=fams), self.soak())
        self.assertEqual(rep["outcome"], "no advantage")

    def test_uninformative_when_b0_separates(self):
        fams = {f: {"none": []} for f in R.FAMILIES}
        fams["B0"] = b0_grid(at_zero=ALL_FAST)
        rep = R.evaluate(self.runs(fams=fams), self.soak())
        self.assertFalse(rep["V0_informative"]["pass"])
        self.assertEqual(rep["outcome"], "uninformative")

    def test_v2_benign_budget_and_soak(self):
        rep = R.evaluate(self.runs(gru_benign=("10.0.1.4",)), self.soak())   # 5/20 = 25 %
        self.assertFalse(rep["V2_usable"]["benign_within_budget"])
        self.assertEqual(rep["outcome"], "no advantage")
        rep = R.evaluate(self.runs(), self.soak(events=12, duration=600.0))  # 12 / (4 x 1/6 h)
        self.assertEqual(rep["V2_usable"]["soak_fp_per_client_hour"], 18.0)
        self.assertEqual(rep["outcome"], "no advantage")

    def test_oracle_respects_the_gru_benign_count(self):
        # With the GRU at 0 benign, B0's loose setting (all attackers + 1 benign) is
        # not allowed; with the GRU at 1 benign per run it is.
        rep = R.evaluate(self.runs(), self.soak())
        self.assertEqual(rep["V3_baselines"]["B0"]["fp"], 0)
        rep = R.evaluate(self.runs(gru_benign=("10.0.1.1",)), self.soak())
        self.assertEqual(rep["V3_baselines"]["B0"]["param"], "peak1s>20")
        self.assertEqual(rep["V3_baselines"]["B0"]["caught"], 20)

    def test_v1_exclusions_are_listed(self):
        runs = self.runs(n=1, det={"10.0.2.1": "l7_rate", "10.0.1.2": "l4_slowconn"},
                         shaped=("10.0.1.3",))
        rep = R.evaluate(runs, self.soak())
        self.assertEqual(rep["comparison_set"], 3)
        self.assertEqual(rep["benign_ips"], 2)
        whys = {e["ip"]: e["why"] for e in rep["v1_exclusions"]["A1"]}
        self.assertEqual(whys, {"10.0.2.1": "det-banned (l7_rate)",
                                "10.0.1.2": "det-banned (l4_slowconn)",
                                "10.0.1.3": "shaped by nginx"})

    def test_incomplete_without_b4_or_soak(self):
        fams = {f: {"none": []} for f in R.FAMILIES[:-1]}
        self.assertEqual(R.evaluate(self.runs(fams=fams), self.soak())["outcome"],
                         "incomplete (missing B4)")
        self.assertEqual(R.evaluate(self.runs(), None)["outcome"], "incomplete (no soak run)")

    def test_cli_writes_reports(self):
        args = [f"--run=A{i}={make_run(self.root, f'X{i}')}" for i in range(1, 3)]
        soak = make_run(self.root, "S", gru=(), soak=True, duration=600.0)
        out, md = os.path.join(self.root, "r.json"), os.path.join(self.root, "r.md")
        r = subprocess.run([sys.executable, os.path.join(REPO, "ml", "p5b_report.py"), *args,
                            f"--soak=C={soak}", "--out", out, "--md", md],
                           capture_output=True, text=True, check=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(out, encoding="utf-8") as fh:
            self.assertIn("outcome", json.load(fh))
        with open(md, encoding="utf-8") as fh:
            self.assertIn("**Outcome:", fh.read())


if __name__ == "__main__":
    unittest.main()
