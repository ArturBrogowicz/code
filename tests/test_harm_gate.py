"""Offline tests for eval/harm_gate.py: the figures of a run, the validity profiles, the pre-registered rule at its
boundaries, the re-run rule, the placebo, HRR and the report (docs/HG1B_MINIMAL_DESIGN.md 5.6).

The blocks are synthetic and say so: a population is drawn by bench/population.py, the intended times are the
engine's own schedules, and a small server model decides which requests fail or slow down. The files written are
the run contract (5.5). One test runs the real engine for a moment, to parse its real records.
"""
import contextlib
import copy
import io
import json
import math
import os
import shutil
import sys
import tempfile
import unittest

import numpy as np
import pandas as pd

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for sub in ("bench", "eval", "tests"):
    sys.path.insert(0, os.path.join(REPO, sub))
import calibration as C
import harm_gate as H
import loadgen as LG
import population as P
from test_loadtool_validate import RunningOrigin

PLACEHOLDER = C.load(C.PLACEHOLDER)
FROZEN = C.freeze(PLACEHOLDER, "2026-10-24T08:00:00Z")
TIMELINE = {"baseline_s": 10.0, "attack_s": 10.0, "recovery_s": 10.0}
RHO = 40.0
IDENTITIES = 16
OK_FLAGS = {"slip": False, "sent_short": False, "cpu": False, "descriptors": False, "ports": False, "dropped": False}
PASS_EFFECTS = {"U": {"fail_p": 0.3}, "M_x": {"fail_p": 0.1}}


# --- a synthetic server and the files an executor would write -------------------------------------

def population(seed):
    return P.draw("calib", seed, RHO, IDENTITIES, ("costly_search_flood", 5, 20.0),
                  P.Timeline(TIMELINE["baseline_s"], TIMELINE["attack_s"], TIMELINE["recovery_s"]))


def write_stream(run_dir, stream, rng, cal, effect, summary_edit=None):
    """One stream's records and summary. Of the legit requests that fall in the attack window `effect` makes a share
    `fail_p` time out and slows the rest by `slow`; `slip` is the generator's lateness."""
    lo, hi = TIMELINE["baseline_s"], TIMELINE["baseline_s"] + TIMELINE["attack_s"]
    sched = np.array(LG.schedule(stream.process, stream.rate, stream.duration_s, stream.seed,
                                 period=stream.period, duty=stream.duty))
    n = len(sched)
    slip = effect.get("slip", 0.002) * (0.5 + rng.random(n))
    sent = sched + slip
    service = cal["route_costs_ms"][stream.route_class] / 1000.0 * rng.lognormal(0.0, 0.2, n)
    status = np.full(n, 200)
    err = np.full(n, "", dtype=object)
    hit = (sched + stream.start_s >= lo) & (sched + stream.start_s < hi) & (stream.kind == "legit")
    bad = hit & (rng.random(n) < effect.get("fail_p", 0.0))
    service = np.where(hit & ~bad, service * effect.get("slow", 1.0), service)
    done = sent + service
    err[bad], status[bad], done[bad] = "timeout", 0, sent[bad] + 10.0
    pd.DataFrame({"i": np.arange(n), "t_intended": sched, "t_sent": sent, "t_done": done, "status": status,
                  "bytes": 100, "err": err, "ident": np.arange(n) % len(stream.addresses), "reused": 1}
                 ).to_csv(os.path.join(run_dir, "streams", f"{stream.id}.records.csv.gz"), index=False,
                          compression="gzip", na_rep="nan", float_format="%.6f")
    summary = {"schema": 1, "tool": "loadgen", "intended": n, "sent": n, "dropped": 0, "completed": int((~bad).sum()),
               "slip_s": {"p99": float(np.quantile(slip, 0.99)) if n else None}, "cpu": {"share": 0.02},
               "flags": dict(OK_FLAGS), "valid": True}
    if summary_edit:
        summary_edit(stream, summary)
    with open(os.path.join(run_dir, "streams", f"{stream.id}.summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh)
    return {"id": stream.id, "kind": stream.kind, "route_class": stream.route_class,
            "summary": f"streams/{stream.id}.summary.json", "records": f"streams/{stream.id}.records.csv.gz",
            "offset_s": stream.start_s if stream.kind == "attack" else 0.0}


def write_run(block_dir, name, pop, seed, cal, effect, summary_edit=None):
    run_dir = os.path.join(block_dir, name)
    os.makedirs(os.path.join(run_dir, "streams"))
    rng = np.random.default_rng([seed, sum(map(ord, name))])
    attack_present = name == H.ATTACK or name.startswith(H.MITIGATED)
    streams = [write_stream(run_dir, s, rng, cal, effect, summary_edit)
               for s in pop.streams if s.kind == "legit" or attack_present]
    role = H.ROLE_OF.get(name, "mitigated")
    with open(os.path.join(run_dir, "run.json"), "w", encoding="utf-8") as fh:
        json.dump({"role": role, "mode": name[len(H.MITIGATED):] if role == "mitigated" else None,
                   "started_utc": "2026-10-24T08:00:00Z", "streams": streams}, fh)


def write_block(root, number, cal, effects=None, attempt=1, seed=None, scenario="synthetic", summary_edit=None):
    """A block directory: the control, the placebo, the attack and a mitigated run for each M_<mode> in `effects`."""
    effects = effects or {}
    seed = number if seed is None else seed
    pop = population(seed)
    block_dir = os.path.join(root, f"b{number:02d}_a{attempt}")
    os.makedirs(block_dir)
    made = [H.CONTROL, H.PLACEBO, H.ATTACK]
    for run in [*made, *[n for n in effects if n.startswith(H.MITIGATED)]]:
        edit = summary_edit(run) if callable(summary_edit) else None
        write_run(block_dir, run, pop, seed, cal, effects.get(run, {}), edit)
    k = number % 3
    with open(os.path.join(block_dir, "block.json"), "w", encoding="utf-8") as fh:
        json.dump({"scenario": scenario, "block": number, "attempt": attempt, "seed_namespace": "calib", "seed": seed,
                   "calibration_sha256": cal["sha256"], "timeline": TIMELINE, "order": made[k:] + made[:k]}, fh)


def json_of(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def edit_json(path, change):
    data = json_of(path)
    change(data)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)


def legit_summary(block_dir, run):
    """The path of the summary of the first legit stream of a run."""
    meta = json_of(os.path.join(block_dir, run, "run.json"))
    return os.path.join(block_dir, run, next(s["summary"] for s in meta["streams"] if s["kind"] == "legit"))


def block_dirs(root):
    return [os.path.join(root, d) for d in sorted(os.listdir(root))]


def point_at(root, cal):
    """Say in every block.json that the blocks were run under `cal`."""
    for d in block_dirs(root):
        edit_json(os.path.join(d, "block.json"), lambda j: j.update(calibration_sha256=cal["sha256"]))


def with_profile(profile):
    cal = copy.deepcopy(FROZEN)
    cal["validity"]["profile"] = profile
    return C.freeze(cal)


_TMP = tempfile.TemporaryDirectory()
BASE = {}
_ANALYSES = {}


def setUpModule():
    for name, effects in (("pass", PASS_EFFECTS), ("fail", {}), ("small", {"U": {"fail_p": 0.04}}),
                          ("latency", {"U": {"slow": 3.0}})):
        BASE[name] = os.path.join(_TMP.name, name)
        os.makedirs(BASE[name])
        for number in range(1, 11):
            write_block(BASE[name], number, FROZEN, effects)


def tearDownModule():
    _TMP.cleanup()


class WithCopies(unittest.TestCase):
    """A fresh copy of one of the base campaigns to damage."""

    def copy_of(self, name):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = os.path.join(tmp.name, name)
        shutil.copytree(BASE[name], root)
        return root

    def analyse(self, root, cal=FROZEN, **kw):
        if root in BASE.values():                                  # the base campaigns are never changed: analyse once
            key = (root, cal["sha256"], tuple(sorted(kw.items())))
            if key not in _ANALYSES:
                _ANALYSES[key] = H.analyse(root, cal, **kw)
            return _ANALYSES[key]
        return H.analyse(root, cal, **kw)

    def block(self, result, number):
        return next(b for b in result["blocks"] if b["block"] == number)


# --- the rule ------------------------------------------------------------------------------------

class CriterionTest(unittest.TestCase):
    GATE = FROZEN["gate"]

    def test_the_floor_is_inclusive(self):
        at = H.criterion([9.0, 11.0] * 5, 10.0, self.GATE)
        self.assertAlmostEqual(at["mean"], 10.0)
        self.assertTrue(at["passed"])
        under = H.criterion([9.0, 11.0] * 4 + [9.0, 10.9], 10.0, self.GATE)
        self.assertFalse(under["mean_ok"])
        self.assertFalse(under["passed"])

    def test_an_interval_that_reaches_zero_does_not_pass(self):
        d = [60.0, -40.0, 50.0, -30.0, 40.0, -20.0, 30.0, 10.0, 20.0, 0.0]          # mean 12, wide spread
        c = H.criterion(d, 10.0, self.GATE)
        self.assertGreaterEqual(c["mean"], 10.0)
        self.assertLess(c["lo"], 0)
        self.assertFalse(c["interval_ok"])
        self.assertFalse(c["passed"])

    def test_the_sign_share_at_its_boundary(self):
        eight = H.criterion([30.0] * 8 + [-1.0] * 2, 10.0, self.GATE)
        self.assertAlmostEqual(eight["same_sign_share"], 0.8)
        self.assertTrue(eight["passed"])
        seven = H.criterion([30.0] * 7 + [-1.0] * 3, 10.0, self.GATE)
        self.assertAlmostEqual(seven["same_sign_share"], 0.7)
        self.assertTrue(seven["mean_ok"] and seven["interval_ok"])
        self.assertFalse(seven["share_ok"] or seven["passed"])

    def test_a_negative_effect_is_not_harm(self):
        c = H.criterion([-20.0, -21.0, -19.0, -22.0, -20.0], 10.0, self.GATE)
        self.assertFalse(c["passed"])
        self.assertFalse(c["mean_ok"])

    def test_fewer_than_two_blocks_cannot_be_evaluated(self):
        for d in ([], [50.0]):
            c = H.criterion(d, 10.0, self.GATE)
            self.assertEqual((c["evaluable"], c["passed"], c["n"]), (False, False, len(d)))

    def test_the_interval_level_is_the_gates(self):
        d = [12.0, 9.0, 15.0, 8.0, 11.0, 13.0, 7.0, 14.0, 10.0, 12.0]
        wide = H.criterion(d, 10.0, {**self.GATE, "ci_level": 0.999})
        narrow = H.criterion(d, 10.0, {**self.GATE, "ci_level": 0.5})
        self.assertLess(wide["lo"], narrow["lo"])
        self.assertGreater(wide["hi"], narrow["hi"])


# --- the figures of one run ----------------------------------------------------------------------

def hand_run(tmp, rows_by_stream):
    """A run with the given legit records: {stream id: (route class, offset_s, [(t_int, t_sent, t_done, status, err)])}."""
    streams = []
    for sid, (route, offset, rows) in rows_by_stream.items():
        df = pd.DataFrame(rows, columns=["t_intended", "t_sent", "t_done", "status", "err"])
        df.insert(0, "i", range(len(df)))
        path = os.path.join(tmp, sid + ".csv.gz")
        df.to_csv(path, index=False, compression="gzip", na_rep="nan")
        streams.append({"id": sid, "kind": "legit", "route_class": route, "records": path, "offset_s": offset,
                        "summary": {}})
    return {"dir": tmp, "streams": streams}


SHORT = {"baseline_s": 2.0, "attack_s": 3.0, "recovery_s": 5.0}


class RunMetricsTest(unittest.TestCase):
    def metrics(self, rows_by_stream, cal=FROZEN, **kw):
        with tempfile.TemporaryDirectory() as tmp:
            return H.run_metrics(hand_run(tmp, rows_by_stream), cal, SHORT, **kw)

    def test_q_counts_what_completed_2xx_within_the_slo_of_its_class(self):
        # C1 has an SLO of 300 ms, C0 of 100 ms; the window is [2, 5)
        m = self.metrics({"a": ("C1", 0.0, [
            (2.0, 2.0, 2.2, 200, ""),            # 200 ms: ok
            (2.5, 2.5, 2.8, 200, ""),            # exactly 300 ms: ok, the SLO is inclusive
            (3.0, 3.0, 3.31, 200, ""),           # 310 ms: slow
            (3.5, 3.5, 3.6, 503, ""),            # non-2xx
            (4.0, 4.0, 14.0, 0, "timeout")]),    # timed out
            "b": ("C0", 0.0, [(4.5, 4.5, 4.55, 200, "")])})
        self.assertEqual((m["requests"], m["ok"], m["lost"]), (6, 3, 3))
        self.assertAlmostEqual(m["Q"], 50.0)
        self.assertEqual(m["failures"], {"non_2xx": 1, "slow": 1, "timeout": 1})
        self.assertEqual(m["by_class"]["C1"]["Q"], 40.0)
        self.assertEqual(m["by_class"]["C0"]["Q"], 100.0)

    def test_the_service_time_is_taken_from_the_send_not_from_the_intended_time(self):
        m = self.metrics({"a": ("C1", 0.0, [(2.0, 3.5, 3.6, 200, "")])})        # sent 1.5 s late, served in 100 ms
        self.assertEqual(m["Q"], 100.0)
        self.assertAlmostEqual(m["p95_s"], 0.1)
        self.assertAlmostEqual(m["p95_from_intended_s"], 1.6)                     # recorded next to it
        self.assertAlmostEqual(m["slip_p99_s"], 1.5)

    def test_the_window_is_half_open_and_the_offset_moves_it(self):
        edge = [(1.999, 1.999, 2.0, 200, ""), (2.0, 2.0, 2.0, 200, ""), (4.999, 4.999, 5.0, 200, ""),
                (5.0, 5.0, 5.0, 200, "")]
        self.assertEqual(self.metrics({"a": ("C1", 0.0, edge)})["requests"], 2)
        moved = [(1.6, 1.6, 1.7, 200, ""), (4.6, 4.6, 4.7, 200, ""), (4.9, 4.9, 5.0, 200, "")]
        self.assertEqual(self.metrics({"a": ("C1", 0.0, moved)})["requests"], 2)
        self.assertEqual(self.metrics({"a": ("C1", 0.5, moved)})["requests"], 1)       # t_run = t_intended + 0.5

    def test_requests_never_sent_or_dropped_fail_and_are_named(self):
        nan = float("nan")
        rows = [(2.0, nan, nan, 0, "dropped"), (2.5, nan, nan, 0, ""), (3.0, 3.0, 3.1, 200, ""),
                (3.5, 3.5, 3.6, 0, "reset")]
        m = self.metrics({"a": ("C1", 0.0, rows)})
        self.assertEqual((m["requests"], m["ok"]), (4, 1))
        self.assertEqual(m["failures"], {"dropped": 1, "never_sent": 1, "reset": 1})

    def test_p95_is_over_the_successes_and_interpolates_like_the_engine(self):
        rows = [(2.0 + i * 0.1, 2.0 + i * 0.1, 2.0 + i * 0.1 + 0.01 * (i + 1), 200, "") for i in range(10)]
        m = self.metrics({"a": ("C1", 0.0, rows)})
        self.assertAlmostEqual(m["p95_s"], 0.0955)              # 0.01 .. 0.10, position 0.95 * 9 = 8.55
        self.assertAlmostEqual(m["p50_s"], 0.055)

    def test_a_window_without_requests_has_no_q(self):
        m = self.metrics({"a": ("C1", 0.0, [(0.5, 0.5, 0.6, 200, "")])})
        self.assertEqual((m["requests"], m["Q"], m["p95_s"]), (0, None, None))

    def test_a_route_class_without_an_slo_is_an_error(self):
        with self.assertRaisesRegex(H.GateError, "no SLO"):
            self.metrics({"a": ("C9", 0.0, [(2.0, 2.0, 2.1, 200, "")])})

    def test_the_slo_scale_moves_the_verdict_on_a_request_not_the_data(self):
        rows = [(2.0, 2.0, 2.2, 200, ""), (3.0, 3.0, 3.25, 200, "")]                # 200 and 250 ms against 300 ms
        self.assertEqual(self.metrics({"a": ("C1", 0.0, rows)})["Q"], 100.0)
        self.assertEqual(self.metrics({"a": ("C1", 0.0, rows)}, slo_scale=0.8)["Q"], 50.0)          # 240 ms
        self.assertEqual(self.metrics({"a": ("C1", 0.0, rows)}, slo_scale=0.6)["Q"], 0.0)           # 180 ms

    def test_the_second_by_second_figures_of_a_run(self):
        # one request a second; the window is seconds 2-4; the one of second 3 fails; the run lasts 10 s
        rows = [(float(s), float(s), s + 0.1, 200 if s != 3 else 503, "") for s in range(10)]
        m = self.metrics({"a": ("C1", 0.0, rows)})
        self.assertEqual(m["q_per_s"], [100.0, 100.0, 100.0, 0.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0])
        self.assertEqual((m["degraded_s"], m["degraded_in_attack_s"]), (1, 1))
        self.assertEqual(m["first_degraded_s"], 1.0)             # second 3; the attack began at 2
        self.assertEqual(m["recovery_s"], 0.0)                   # seconds 5-9 are all good

    def test_time_resolved_figures_from_synthetic_bins(self):
        n = [10] * 12
        r = H.time_resolved(n, [10] * 12, 2.0, 5.0)
        self.assertEqual((r["degraded_s"], r["first_degraded_s"], r["recovery_s"]), (0, None, 0.0))
        # degraded from second 3 to second 6; five good seconds from second 7 on
        r = H.time_resolved(n, [10, 10, 10, 9, 9, 9, 9, 10, 10, 10, 10, 10], 2.0, 5.0)
        self.assertEqual((r["degraded_s"], r["degraded_in_attack_s"]), (4, 2))
        self.assertEqual((r["first_degraded_s"], r["recovery_s"]), (1.0, 2.0))
        # a bad second in the middle of the recovery restarts the count, and no five good seconds are left
        r = H.time_resolved(n, [10, 10, 10, 9, 9, 9, 10, 10, 10, 9, 10, 10], 2.0, 5.0)
        self.assertIsNone(r["recovery_s"])
        # exactly 99 % counts as good, 94 % as degraded
        r = H.time_resolved([100] * 12, [100, 100, 100, 94, 94, 94, 99, 99, 99, 99, 99, 100], 2.0, 5.0)
        self.assertEqual((r["degraded_s"], r["recovery_s"]), (3, 1.0))
        # exactly 95 % is not degraded (the second must fall below it)
        r = H.time_resolved([100] * 12, [100, 100, 100, 95, 95, 95, 100, 100, 100, 100, 100, 100], 2.0, 5.0)
        self.assertEqual((r["degraded_s"], r["first_degraded_s"]), (0, None))
        # a second without requests is neither degraded nor good
        quiet = [10, 10, 10, 10, 10, 10, 0, 10, 10, 10, 10, 10]
        r = H.time_resolved(quiet, quiet, 2.0, 5.0)
        self.assertEqual((r["degraded_s"], r["recovery_s"]), (0, 2.0))


# --- validity ------------------------------------------------------------------------------------

def stream(sid="s1", kind="legit", **over):
    summary = {"cpu": {"share": 0.1}, "intended": 1000, "sent": 1000, "dropped": 0, "flags": dict(OK_FLAGS),
               "slip_s": {"p99": 0.002}}
    for key, value in over.items():
        if key in ("descriptors", "ports"):
            summary["flags"][key] = value
        elif key == "cpu":
            summary["cpu"]["share"] = value
        elif key == "slip":
            summary["slip_s"]["p99"] = value
        else:
            summary[key] = value
    return {"id": sid, "kind": kind, "summary": summary}


class ValidityTest(unittest.TestCase):
    def check(self, *streams, slip=0.002, control=0.002, cal=FROZEN):
        return H.validity({"dir": "r", "streams": list(streams)}, cal, slip, control)

    def test_a_clean_run_passes_both_profiles(self):
        v = self.check(stream(), stream("a", "attack"))
        self.assertEqual(v, {"relative": {"ok": True, "reasons": []}, "strict": {"ok": True, "reasons": []}})

    def test_each_shared_rule_fails_both_profiles(self):
        for name, s in (("cpu", stream(cpu=0.71)), ("sent", stream(sent=989)), ("descriptors", stream(descriptors=True)),
                        ("ports", stream(ports=True))):
            with self.subTest(rule=name):
                v = self.check(s)
                self.assertFalse(v["relative"]["ok"] or v["strict"]["ok"])
                self.assertEqual(len(v["relative"]["reasons"]), 1)

    def test_the_boundaries_are_inclusive_where_the_design_says_so(self):
        self.assertTrue(self.check(stream(cpu=0.70))["relative"]["ok"])
        self.assertTrue(self.check(stream(sent=990))["relative"]["ok"])
        self.assertTrue(self.check(stream(intended=0, sent=0))["relative"]["ok"])
        self.assertTrue(self.check(stream(slip=0.25))["relative"]["ok"])
        self.assertFalse(self.check(stream(slip=0.251))["relative"]["ok"])

    def test_only_a_legit_stream_may_not_drop_under_the_relative_profile(self):
        self.assertFalse(self.check(stream(dropped=1))["relative"]["ok"])
        v = self.check(stream("a", "attack", dropped=3))
        self.assertTrue(v["relative"]["ok"])
        self.assertFalse(v["strict"]["ok"])

    def test_the_relative_profile_allows_slip_the_strict_one_does_not(self):
        v = self.check(stream(slip=0.08), slip=0.08, control=0.08)
        self.assertTrue(v["relative"]["ok"])
        self.assertFalse(v["strict"]["ok"])
        self.assertIn("slip p99 80 ms above 50 ms", v["strict"]["reasons"][0])

    def test_slip_is_a_difference_to_the_control(self):
        self.assertTrue(self.check(stream(slip=0.1), slip=0.1, control=0.05)["relative"]["ok"])          # +50 ms
        v = self.check(stream(slip=0.1), slip=0.1, control=0.0499)
        self.assertFalse(v["relative"]["ok"])
        self.assertIn("exceeds the control's", v["relative"]["reasons"][0])
        self.assertTrue(self.check(stream(), slip=0.5, control=None)["relative"]["ok"])                   # the control itself

    def test_a_summary_that_lacks_a_field_is_an_error_naming_it(self):
        s = stream()
        del s["summary"]["cpu"]
        with self.assertRaisesRegex(H.GateError, "lacks 'cpu'"):
            self.check(s)


class ControlHealthTest(unittest.TestCase):
    def healthy(self, q=100.0, p95=0.01):
        return {"Q": q, "by_class": {"C1": {"p95_s": p95}, "C3": {"p95_s": 0.5}}}

    def test_a_healthy_control(self):
        self.assertEqual(H.control_health(self.healthy(), FROZEN), [])
        self.assertEqual(H.control_health(self.healthy(q=99.0), FROZEN), [])           # inclusive

    def test_each_failure_is_named(self):
        self.assertIn("below 99 %", H.control_health(self.healthy(q=98.9), FROZEN)[0])
        self.assertIn("class C1 p95 301 ms is above its SLO of 300 ms", H.control_health(self.healthy(p95=0.301), FROZEN)[0])
        self.assertEqual(H.control_health(self.healthy(p95=0.300), FROZEN), [])
        self.assertIn("n/a", H.control_health({"Q": None, "by_class": {}}, FROZEN)[0])
        self.assertIn("no successful request",
                      H.control_health({"Q": 100.0, "by_class": {"C1": {"p95_s": None}}}, FROZEN)[0])


# --- the gate on whole campaigns -----------------------------------------------------------------

class VerdictTest(WithCopies):
    def test_a_harmful_attack_passes_on_q_and_the_placebo_does_not(self):
        r = self.analyse(BASE["pass"])
        self.assertEqual((r["verdict"], r["blocks_valid"], r["blocks_total"], r["reruns"]), ("PASS", 10, 10, 0))
        q = r["criteria"]["Q"]
        self.assertTrue(q["passed"])
        self.assertAlmostEqual(q["mean"], 30.0, delta=4.0)
        self.assertGreater(q["lo"], 20.0)
        self.assertGreaterEqual(q["same_sign_share"], 0.8)
        self.assertFalse(r["criteria"]["p95"]["passed"])                         # the survivors are not slower
        self.assertFalse(r["placebo"]["passed"])
        self.assertEqual(r["reasons"], [])
        self.assertFalse(r["dry_run"])

    def test_the_blocks_carry_the_paired_figures(self):
        r = self.analyse(BASE["pass"])
        for b in r["blocks"]:
            c, cp, u = (b["runs"][n]["metrics"] for n in ("C", "Cp", "U"))
            self.assertEqual((c["Q"], cp["Q"]), (100.0, 100.0))
            self.assertAlmostEqual(b["dQ"], c["Q"] - u["Q"])
            self.assertEqual(b["dQ_placebo"], 0.0)
            self.assertAlmostEqual(b["dL"], math.log2(u["p95_s"] / c["p95_s"]))
            self.assertTrue(b["valid"] and b["runs"]["U"]["strict_ok"])
            self.assertGreater(u["degraded_in_attack_s"], 0)
            self.assertEqual(c["degraded_s"], 0)
            self.assertEqual(set(u["failures"]), {"timeout"})
        self.assertEqual([b["block"] for b in r["blocks"]], list(range(1, 11)))
        self.assertEqual([b["seed"] for b in r["blocks"]], list(range(1, 11)))

    def test_no_effect_is_a_fail(self):
        r = self.analyse(BASE["fail"])
        self.assertEqual((r["verdict"], r["blocks_valid"], r["reasons"]), ("FAIL", 10, []))
        self.assertFalse(r["criteria"]["Q"]["passed"] or r["criteria"]["p95"]["passed"])

    def test_a_harm_below_the_floor_is_a_fail_even_when_it_is_significant(self):
        r = self.analyse(BASE["small"])
        q = r["criteria"]["Q"]
        self.assertEqual(r["verdict"], "FAIL")
        self.assertLess(q["mean"], 10.0)
        self.assertGreater(q["lo"], 0.0)                          # clearly nonzero, and still not harm
        self.assertTrue(q["interval_ok"] and q["share_ok"] and not q["mean_ok"])

    def test_slower_but_not_failing_passes_on_the_latency_criterion_alone(self):
        r = self.analyse(BASE["latency"])
        self.assertEqual(r["verdict"], "PASS")
        self.assertFalse(r["criteria"]["Q"]["passed"])
        self.assertAlmostEqual(r["criteria"]["Q"]["mean"], 0.0, delta=0.01)
        p = r["criteria"]["p95"]
        self.assertTrue(p["passed"])
        self.assertAlmostEqual(p["mean"], math.log2(3.0), delta=0.25)

    def test_a_run_with_no_success_has_no_p95_and_q_carries_the_verdict(self):
        small = copy.deepcopy(FROZEN)
        small["gate"]["min_blocks"] = 3
        small = C.freeze(small)
        with tempfile.TemporaryDirectory() as tmp:
            for number in (1, 2, 3):
                write_block(tmp, number, small, {"U": {"fail_p": 1.0}})
            r = H.analyse(tmp, small)
            self.assertEqual(r["verdict"], "PASS")
            self.assertTrue(all(b["dL"] is None and b["dQ"] == 100.0 for b in r["blocks"]))
            self.assertEqual((r["criteria"]["Q"]["mean"], r["criteria"]["p95"]["evaluable"]), (100.0, False))
            only = H.analyse(tmp, small, metrics=("p95",))
        self.assertEqual(only["verdict"], "INVALID")
        self.assertIn("no criterion could be evaluated", only["reasons"])

    def test_the_metrics_option_selects_the_criteria(self):
        self.assertEqual(self.analyse(BASE["latency"], metrics=("Q",))["verdict"], "FAIL")
        self.assertEqual(self.analyse(BASE["latency"], metrics=("p95",))["verdict"], "PASS")
        self.assertEqual(list(self.analyse(BASE["pass"], metrics=("Q",))["criteria"]), ["Q"])
        self.assertEqual(self.analyse(BASE["pass"], metrics=("p95",))["verdict"], "FAIL")

    def test_a_placebo_that_passes_is_reported_and_does_not_change_the_verdict(self):
        root = self.copy_of("pass")
        for d in block_dirs(root):                                 # the placebo run is as harmed as the attack
            shutil.rmtree(os.path.join(d, "Cp"))
            shutil.copytree(os.path.join(d, "U"), os.path.join(d, "Cp"))
            edit_json(os.path.join(d, "Cp", "run.json"), lambda j: j.update(role="placebo"))
        r = self.analyse(root)
        self.assertEqual(r["verdict"], "PASS")
        self.assertTrue(r["placebo"]["passed"])
        self.assertTrue(r["placebo"]["criteria"]["Q"]["passed"])
        self.assertIn("PASSED: the gate is not specific", H.to_markdown(r))

    def test_the_figures_do_not_depend_on_the_directory_names(self):
        a = self.analyse(BASE["pass"])
        root = self.copy_of("pass")
        for number in range(1, 11):
            os.rename(os.path.join(root, f"b{number:02d}_a1"), os.path.join(root, f"z{11 - number:02d}"))
        b = self.analyse(root)
        self.assertEqual((a["verdict"], a["criteria"]), (b["verdict"], b["criteria"]))


class ValidBlocksAndRerunsTest(WithCopies):
    def spoil(self, root, number, attempt=1, run="U", **summary):
        edit_json(legit_summary(os.path.join(root, f"b{number:02d}_a{attempt}"), run), lambda j: j.update(summary))

    def rerun(self, root, number, **kw):
        write_block(root, number, FROZEN, PASS_EFFECTS, attempt=2, **kw)

    def replace(self, root, number, effects, **kw):
        shutil.rmtree(os.path.join(root, f"b{number:02d}_a1"))
        write_block(root, number, FROZEN, effects, **kw)

    def test_a_failed_block_re_run_once_with_its_seed_counts(self):
        root = self.copy_of("pass")
        self.spoil(root, 4, cpu={"share": 0.95})
        self.rerun(root, 4)
        r = self.analyse(root)
        self.assertEqual((r["verdict"], r["blocks_valid"], r["blocks_total"], r["reruns"]), ("PASS", 10, 10, 1))
        self.assertEqual([a["block"] for a in r["attempts"]], [4])
        self.assertTrue(any("CPU share 0.95" in x for x in r["attempts"][0]["reasons"]), r["attempts"][0]["reasons"])
        self.assertEqual(self.block(r, 4)["attempt"], 2)

    def test_a_failed_block_that_is_not_re_run_leaves_nine_and_the_gate_invalid(self):
        root = self.copy_of("pass")
        self.spoil(root, 4, cpu={"share": 0.95})
        r = self.analyse(root)
        self.assertEqual((r["verdict"], r["blocks_valid"], r["blocks_total"]), ("INVALID", 9, 10))
        self.assertIn("9 valid blocks, fewer than the 10 the gate needs", r["reasons"])

    def test_a_valid_block_is_never_re_run(self):
        root = self.copy_of("pass")
        self.rerun(root, 5)
        r = self.analyse(root)
        self.assertEqual(r["verdict"], "INVALID")
        self.assertIn("block 5: re-run although attempt 1 was valid", r["reasons"])

    def test_a_re_run_keeps_the_seed(self):
        root = self.copy_of("pass")
        self.spoil(root, 4, cpu={"share": 0.95})
        self.rerun(root, 4, seed=99)
        r = self.analyse(root)
        self.assertEqual(r["verdict"], "INVALID")
        self.assertIn("block 4: the re-run used another seed", r["reasons"])

    def test_at_most_two_re_runs_in_a_gate(self):
        root = self.copy_of("pass")
        for number in (2, 4, 6):
            self.spoil(root, number, cpu={"share": 0.95})
            self.rerun(root, number)
        r = self.analyse(root)
        self.assertEqual((r["verdict"], r["blocks_valid"], r["reruns"]), ("INVALID", 10, 3))
        self.assertIn("3 blocks were re-run; at most 2 in a gate", r["reasons"])
        for attempt in (1, 2):                                      # without block 6 there are only two re-runs
            shutil.rmtree(os.path.join(root, f"b06_a{attempt}"))
        two = self.analyse(root)
        self.assertEqual(two["reruns"], 2)
        self.assertFalse(any("blocks were re-run" in x for x in two["reasons"]), two["reasons"])

    def test_a_second_attempt_that_fails_again_is_not_a_third_chance(self):
        root = self.copy_of("pass")
        self.spoil(root, 4, cpu={"share": 0.95})
        self.rerun(root, 4, summary_edit=lambda run: (lambda st, sm: sm.update(cpu={"share": 0.95})) if run == "U" else None)
        r = self.analyse(root)
        self.assertEqual((r["verdict"], r["blocks_valid"]), ("INVALID", 9))

    def test_one_scenario_one_calibration(self):
        root = self.copy_of("pass")
        write_block(root, 11, FROZEN, PASS_EFFECTS, scenario="another")
        r = self.analyse(root)
        self.assertEqual(r["verdict"], "INVALID")
        self.assertTrue(any("more than one scenario" in x for x in r["reasons"]), r["reasons"])
        root = self.copy_of("pass")
        edit_json(os.path.join(root, "b03_a1", "block.json"), lambda j: j.update(calibration_sha256="ab" * 32))
        r = self.analyse(root)
        self.assertEqual(r["verdict"], "INVALID")
        self.assertTrue(any("is not the one given" in x for x in r["reasons"]), r["reasons"])

    def test_attempts_must_be_numbered_from_one(self):
        root = self.copy_of("pass")
        edit_json(os.path.join(root, "b03_a1", "block.json"), lambda j: j.update(attempt=2))
        r = self.analyse(root)
        self.assertEqual(r["verdict"], "INVALID")
        self.assertTrue(any("are not 1, 2" in x for x in r["reasons"]), r["reasons"])

    def test_each_cause_of_an_invalid_block_is_named(self):
        cases = {
            "legit drop": ("U", {"dropped": 4}, "a legit stream dropped 4 requests"),
            "short": ("Cp", {"sent": 0}, "sent 0 of"),
            "descriptors": ("C", {"flags": {**OK_FLAGS, "descriptors": True}}, "out of descriptors"),
            "ports": ("U", {"flags": {**OK_FLAGS, "ports": True}}, "out of ports"),
            "gross slip": ("C", {"slip_s": {"p99": 0.3}}, "above the gross ceiling"),
        }
        for label, (run, change, fragment) in cases.items():
            with self.subTest(case=label):
                root = self.copy_of("pass")
                self.spoil(root, 2, run=run, **change)
                b = self.block(self.analyse(root), 2)
                self.assertFalse(b["valid"])
                self.assertTrue(any(fragment in x for x in b["reasons"]), b["reasons"])

    def test_a_late_generator_in_the_attack_run_alone_is_caught_by_the_difference_to_the_control(self):
        root = self.copy_of("pass")
        self.replace(root, 7, {**PASS_EFFECTS, "U": {"fail_p": 0.3, "slip": 0.12}})      # the control's slip is about 3 ms
        b = self.block(self.analyse(root), 7)
        self.assertFalse(b["valid"])
        self.assertTrue(any("exceeds the control's" in x for x in b["reasons"]), b["reasons"])
        self.assertFalse(any("gross ceiling" in x for x in b["reasons"]), b["reasons"])

    def test_an_unhealthy_control_invalidates_its_block(self):
        root = self.copy_of("pass")
        self.replace(root, 5, {**PASS_EFFECTS, "C": {"fail_p": 0.05}})       # the control is harmed in its own window
        b = self.block(self.analyse(root), 5)
        self.assertFalse(b["valid"])
        self.assertTrue(any(x.startswith("control: Q(C)") for x in b["reasons"]), b["reasons"])

    def test_a_missing_run_is_a_failed_block(self):
        root = self.copy_of("pass")
        shutil.rmtree(os.path.join(root, "b03_a1", "Cp"))
        b = self.block(self.analyse(root), 3)
        self.assertFalse(b["valid"])
        self.assertIn("run Cp is missing", b["reasons"])
        self.assertTrue(any(x.startswith("order") for x in b["reasons"]), b["reasons"])
        self.assertIsNone(b["dQ_placebo"])

    def test_the_profile_in_the_calibration_judges_the_run(self):
        root = self.copy_of("pass")
        self.spoil(root, 2, slip_s={"p99": 0.08})                  # above the strict 50 ms, below the gross ceiling
        r = self.analyse(root)
        self.assertEqual((r["profile"], r["blocks_valid"]), ("relative", 10))
        self.assertFalse(self.block(r, 2)["runs"]["U"]["strict_ok"])         # computed, not judging
        strict = with_profile("strict")
        point_at(root, strict)
        r = self.analyse(root, cal=strict)
        self.assertEqual((r["profile"], r["blocks_valid"], r["verdict"]), ("strict", 9, "INVALID"))
        self.assertTrue(any("slip p99 80 ms above 50 ms" in x for x in self.block(r, 2)["reasons"]))


class HrrTest(WithCopies):
    def test_hrr_after_a_pass_with_a_bootstrap_interval(self):
        r = self.analyse(BASE["pass"])
        self.assertEqual(len(r["hrr"]), 1)
        h = r["hrr"][0]
        self.assertEqual((h["mode"], h["n"]), ("x", 10))
        self.assertAlmostEqual(h["hrr"], (90.0 - 70.0) / (100.0 - 70.0), delta=0.12)
        self.assertLess(h["lo"], h["hrr"])
        self.assertGreater(h["hi"], h["hrr"])
        self.assertEqual(h["dropped_draws"], 0)
        self.assertFalse(r["hrr_withheld"])

    def test_hrr_is_the_ratio_of_block_means(self):
        r = self.analyse(BASE["pass"])
        qs = [(b["runs"]["C"]["metrics"]["Q"], b["runs"]["U"]["metrics"]["Q"], b["runs"]["M_x"]["metrics"]["Q"])
              for b in r["blocks"]]
        c, u, m = (sum(col) / len(qs) for col in zip(*qs, strict=True))
        self.assertAlmostEqual(r["hrr"][0]["hrr"], (m - u) / (c - u))

    def test_hrr_is_deterministic(self):
        self.assertEqual(self.analyse(BASE["pass"])["hrr"], self.analyse(BASE["pass"])["hrr"])

    def test_no_hrr_without_a_pass(self):
        root = self.copy_of("fail")
        for d in block_dirs(root):
            shutil.copytree(os.path.join(BASE["pass"], os.path.basename(d), "M_x"), os.path.join(d, "M_x"))
        r = self.analyse(root)
        self.assertEqual(r["verdict"], "FAIL")
        self.assertIsNone(r["hrr"])
        self.assertTrue(r["hrr_withheld"])
        self.assertIn("HRR is not computed", H.to_markdown(r))

    def test_hrr_ignores_a_mitigated_run_that_is_not_valid(self):
        root = self.copy_of("pass")
        for number in (1, 2):
            edit_json(legit_summary(os.path.join(root, f"b{number:02d}_a1"), "M_x"), lambda j: j.update(cpu={"share": 0.99}))
        r = self.analyse(root)
        self.assertEqual(r["hrr"][0]["n"], 8)
        self.assertEqual((r["verdict"], r["blocks_valid"]), ("PASS", 10))           # a bad M run does not spoil the block

    def test_the_hrr_of_a_denominator_that_is_not_positive_is_none(self):
        row = {"runs": {"C": {"metrics": {"Q": 90.0}}, "U": {"metrics": {"Q": 95.0}},
                        "M_x": {"metrics": {"Q": 99.0}, "valid": True}}}
        self.assertIsNone(H.hrr([row, row, row], "x")["hrr"])
        self.assertEqual(H.hrr([], "x"), {"mode": "x", "n": 0, "hrr": None})


# --- the calibration, the files and the report ---------------------------------------------------

class CalibrationGateTest(WithCopies):
    def test_a_placeholder_gets_no_verdict_unless_the_run_is_a_dry_run(self):
        root = self.copy_of("pass")
        point_at(root, PLACEHOLDER)
        with self.assertRaisesRegex(C.RecordError, "placeholder"):
            H.analyse(root, PLACEHOLDER)
        r = H.analyse(root, PLACEHOLDER, dry_run=True)
        self.assertEqual((r["verdict"], r["dry_run"], r["calibration"]["status"]), ("PASS", True, "placeholder"))
        md = H.to_markdown(r)
        self.assertIn("DRY RUN on a placeholder calibration", md)
        self.assertIn("(dry run)", md)

    def test_a_frozen_calibration_is_not_a_dry_run_even_if_asked(self):
        r = self.analyse(BASE["pass"], dry_run=True)
        self.assertFalse(r["dry_run"])
        self.assertNotIn("DRY RUN", H.to_markdown(r))

    def test_the_constants_are_the_calibrations(self):
        loose = copy.deepcopy(FROZEN)
        loose["gate"]["floor_pp"] = 40.0
        loose = C.freeze(loose)
        root = self.copy_of("pass")
        point_at(root, loose)
        r = H.analyse(root, loose)
        self.assertEqual(r["verdict"], "FAIL")                      # 30 pp is below a floor of 40
        self.assertEqual((r["criteria"]["Q"]["floor"], r["gate"]["floor_pp"]), (40.0, 40.0))

    def test_the_minimum_number_of_blocks_is_the_calibrations(self):
        small = copy.deepcopy(FROZEN)
        small["gate"]["min_blocks"] = 6
        small = C.freeze(small)
        root = self.copy_of("pass")
        for number in range(7, 11):
            shutil.rmtree(os.path.join(root, f"b{number:02d}_a1"))
        point_at(root, small)
        r = H.analyse(root, small)
        self.assertEqual((r["verdict"], r["blocks_valid"]), ("PASS", 6))
        self.assertEqual(self.analyse(root, cal=FROZEN)["verdict"], "INVALID")        # and the hash is another one


class ContractTest(WithCopies):
    def test_a_directory_without_blocks(self):
        with tempfile.TemporaryDirectory() as tmp, self.assertRaisesRegex(H.GateError, "no block.json"):
            H.analyse(tmp, FROZEN)

    def test_a_block_that_does_not_follow_the_contract_is_an_error_naming_the_file(self):
        root = self.copy_of("pass")
        edit_json(os.path.join(root, "b01_a1", "block.json"), lambda j: j.pop("seed"))
        with self.assertRaisesRegex(H.GateError, r"b01_a1/block\.json: needs"):
            self.analyse(root)
        root = self.copy_of("pass")
        edit_json(os.path.join(root, "b01_a1", "block.json"), lambda j: j.update(timeline={"baseline_s": 10}))
        with self.assertRaisesRegex(H.GateError, "timeline"):
            self.analyse(root)

    def test_a_run_whose_name_and_role_disagree(self):
        root = self.copy_of("pass")
        edit_json(os.path.join(root, "b01_a1", "U", "run.json"), lambda j: j.update(role="control"))
        with self.assertRaisesRegex(H.GateError, "a run called U has role attack"):
            self.analyse(root)

    def test_a_run_without_a_legit_stream_and_a_stream_of_unknown_kind(self):
        root = self.copy_of("pass")
        edit_json(os.path.join(root, "b01_a1", "C", "run.json"), lambda j: j.update(streams=[]))
        with self.assertRaisesRegex(H.GateError, "no legit stream"):
            self.analyse(root)
        root = self.copy_of("pass")
        edit_json(os.path.join(root, "b01_a1", "C", "run.json"), lambda j: j["streams"][0].update(kind="bot"))
        with self.assertRaisesRegex(H.GateError, "kind 'bot'"):
            self.analyse(root)

    def test_records_that_lack_a_column_and_json_that_is_not(self):
        root = self.copy_of("pass")
        run = json_of(os.path.join(root, "b01_a1", "C", "run.json"))
        pd.DataFrame({"t_intended": [1.0]}).to_csv(os.path.join(root, "b01_a1", "C", run["streams"][0]["records"]),
                                                   index=False, compression="gzip")
        with self.assertRaisesRegex(H.GateError, "no column"):
            self.analyse(root)
        root = self.copy_of("pass")
        with open(os.path.join(root, "b01_a1", "C", "run.json"), "w", encoding="utf-8") as fh:
            fh.write("{nope")
        with self.assertRaisesRegex(H.GateError, "run.json"):
            self.analyse(root)

    def test_the_order_must_be_the_runs_made(self):
        root = self.copy_of("pass")
        edit_json(os.path.join(root, "b02_a1", "block.json"), lambda j: j.update(order=["C", "U"]))
        b = self.block(self.analyse(root), 2)
        self.assertFalse(b["valid"])
        self.assertTrue(any(x.startswith("order") for x in b["reasons"]), b["reasons"])


class ReportTest(WithCopies):
    def test_the_markdown_report(self):
        md = H.to_markdown(self.analyse(BASE["pass"]))
        self.assertIn("# Harm gate: synthetic (calib)", md)
        self.assertIn("**Verdict: PASS**", md)
        self.assertIn("10 valid blocks of 10, 0 re-run(s)", md)
        self.assertIn("| dQ (pp) | 10 |", md)
        self.assertIn("did not pass, as it must not", md)
        rows = [line for line in md.splitlines() if line.startswith("| ") and line.split("|")[1].strip().isdigit()]
        self.assertEqual(len(rows), 10)
        self.assertIn("## HRR", md)
        self.assertIn("Strict profile", md)
        self.assertNotIn("nan", md.lower())

    def test_the_report_of_an_invalid_gate_says_why(self):
        root = self.copy_of("pass")
        edit_json(legit_summary(os.path.join(root, "b04_a1"), "U"), lambda j: j.update(cpu={"share": 0.95}))
        md = H.to_markdown(self.analyse(root))
        self.assertIn("**Verdict: INVALID**", md)
        self.assertIn("9 valid blocks, fewer than the 10 the gate needs", md)
        self.assertIn("Blocks and attempts that are not valid", md)
        self.assertIn("CPU share 0.95", md)

    def test_the_json_record_round_trips(self):
        r = self.analyse(BASE["pass"])
        self.assertEqual(json.loads(json.dumps(r)), r)
        self.assertEqual(r["gate"], {k: FROZEN["gate"][k] for k in C.GATE_KEYS})


class CommandLineTest(WithCopies):
    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = H.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def calibration_file(self, tmp, cal):
        path = os.path.join(tmp, "cal.json")
        C.dump(cal, path)
        return path

    def test_it_prints_the_verdict_and_writes_both_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            md, js = os.path.join(tmp, "r.md"), os.path.join(tmp, "r.json")
            code, out, err = self.run_main(BASE["pass"], "--calibration", self.calibration_file(tmp, FROZEN),
                                           "--md", md, "--json", js)
            self.assertEqual((code, err), (0, ""))
            self.assertEqual(out, "PASS: 10 valid blocks of 10\n")
            with open(md, encoding="utf-8") as fh:
                self.assertIn("**Verdict: PASS**", fh.read())
            self.assertEqual(json_of(js)["verdict"], "PASS")

    def test_an_invalid_gate_still_exits_0_and_says_so(self):
        root = self.copy_of("pass")
        shutil.rmtree(os.path.join(root, "b10_a1"))
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = self.run_main(root, "--calibration", self.calibration_file(tmp, FROZEN))
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("INVALID: 9 valid blocks of 9; 9 valid blocks, fewer than"), out)

    def test_a_placeholder_needs_dry_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            cal = self.calibration_file(tmp, PLACEHOLDER)
            code, out, err = self.run_main(BASE["pass"], "--calibration", cal)
            self.assertEqual((code, out), (1, ""))
            self.assertIn("placeholder", err)
            code, out, _ = self.run_main(BASE["pass"], "--calibration", cal, "--dry-run")
            self.assertEqual(code, 0)
            self.assertIn("INVALID (dry run)", out)                      # the blocks name another calibration

    def test_errors_exit_1_with_a_message(self):
        with tempfile.TemporaryDirectory() as tmp:
            cal = self.calibration_file(tmp, FROZEN)
            self.assertEqual(self.run_main(os.path.join(tmp, "none"), "--calibration", cal)[0], 1)
            self.assertEqual(self.run_main(tmp, "--calibration", cal)[0], 1)
            self.assertEqual(self.run_main(tmp, "--calibration", os.path.join(tmp, "missing.json"))[0], 1)
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                H.main([tmp, "--calibration", cal, "--metrics", "p99"])

    def test_the_metrics_option(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = self.run_main(BASE["latency"], "--calibration", self.calibration_file(tmp, FROZEN),
                                         "--metrics", "Q")
            self.assertEqual((code, out), (0, "FAIL: 10 valid blocks of 10\n"))


class RealEngineRecordsTest(unittest.TestCase):
    def test_the_records_the_engine_writes_are_the_records_the_gate_reads(self):
        with RunningOrigin(service_ms=1, jitter_ms=0) as o, tempfile.TemporaryDirectory() as tmp:
            summary, records = os.path.join(tmp, "s.json"), os.path.join(tmp, "r.csv.gz")
            with contextlib.redirect_stdout(io.StringIO()):
                code = LG.main(["--url", f"http://127.0.0.1:{o.port}/", "--allow-loopback", "--rate", "60",
                                "--duration", "1.0", "--summary", summary, "--records", records, "--seed", "5"])
            self.assertEqual(code, 0)
            rec = H.read_records(records)
            self.assertEqual(len(rec["t_intended"]), json_of(summary)["intended"])
            run = {"dir": tmp, "streams": [{"id": "s", "kind": "legit", "route_class": "C1", "records": records,
                                            "offset_s": 0.0, "summary": json_of(summary)}]}
            m = H.run_metrics(run, FROZEN, {"baseline_s": 0.3, "attack_s": 0.5, "recovery_s": 0.2})
            self.assertGreater(m["requests"], 10)                        # about 30 in the window; no punctuality asserted
            self.assertEqual(m["failures"].get("dropped", 0), 0)
            self.assertIn("ok", H.validity(run, FROZEN, m["slip_p99_s"], None)["relative"])


class EndToEndTest(unittest.TestCase):
    def test_a_population_becomes_streams_becomes_the_run_contract_becomes_a_verdict(self):
        pop = population(3)
        legit = pop.of_kind("legit")
        self.assertTrue(legit)
        run = json_of(os.path.join(BASE["pass"], "b03_a1", "U", "run.json"))
        self.assertEqual({s["id"] for s in run["streams"]}, {s.id for s in pop.streams})
        self.assertEqual({s["route_class"] for s in run["streams"] if s["kind"] == "legit"}, {s.route_class for s in legit})
        self.assertEqual({s["offset_s"] for s in run["streams"] if s["kind"] == "attack"}, {10.0})
        control = json_of(os.path.join(BASE["pass"], "b03_a1", "C", "run.json"))
        self.assertEqual({s["kind"] for s in control["streams"]}, {"legit"})
        r = H.analyse(BASE["pass"], FROZEN)
        self.assertEqual(r["verdict"], "PASS")
        # the same schedules in the three runs of a block: the pairing is by common random numbers
        expected = sum(1 for s in legit
                       for t in LG.schedule(s.process, s.rate, s.duration_s, s.seed, period=s.period, duty=s.duty)
                       if 10.0 <= t < 20.0)
        runs = self.block_runs(r, 3)
        self.assertEqual([runs[n]["metrics"]["requests"] for n in ("C", "Cp", "U")], [expected] * 3)

    @staticmethod
    def block_runs(result, number):
        return next(b for b in result["blocks"] if b["block"] == number)["runs"]


if __name__ == "__main__":
    unittest.main()
