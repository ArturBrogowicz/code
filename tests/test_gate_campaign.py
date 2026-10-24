"""The gate campaign (bench/gate_campaign.py), run on the simulated host: the blocks and their orders, the re-run rule, resuming,
the refusals, and the whole protocol ending in a verdict of eval/harm_gate.py. The harm in these campaigns is made by the
simulated server and has a known size, so a PASS or a FAIL here says the protocol works, and nothing about any server."""
import contextlib
import copy
import dataclasses
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
for sub in ("bench", "eval"):
    sys.path.insert(0, os.path.join(REPO, sub))
import calibration as C
import calibration_fixtures as CF
import executor as X
import gate_campaign as GC
import harm_gate as H
import scenario as SC
import sim_host as S

SPEC = os.path.join(REPO, "bench", "scenarios", "costly_search_sub_threshold.json")
CONTROL_SPEC = os.path.join(REPO, "bench", "scenarios", "benign_control.json")
SHORT = (6.0, 6.0, 6.0)
RHO = 20.0
SPEC_SHA = GC.sha256_of(SPEC)


def three_block_cal(**gate):
    """The placeholder frozen with a gate that needs three blocks, so that a campaign of three can end in a verdict."""
    cal = copy.deepcopy(CF.placeholder())
    cal["gate"].update(min_blocks=3, **gate)
    return CF.frozen(cal)


def interrupt_after(seconds):
    """An `on_sleep` hook that raises KeyboardInterrupt once, the first time the host sleeps after `seconds`."""
    fired = []

    def hook(host):
        if host.t > seconds and not fired:
            fired.append(True)
            raise KeyboardInterrupt("signal 2")
    return hook


def without_times(meta):
    """block.json without the clock times, which differ between a campaign and the same one resumed."""
    meta = copy.deepcopy(meta)
    meta.pop("finished_utc", None)
    for run in meta.get("runs", {}).values():
        run.pop("seconds", None)
    return meta


class CampaignCase(unittest.TestCase):
    CAL = three_block_cal()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.scn = SC.load(SPEC)
        self.cal_path = os.path.join(self.tmp.name, "calibration.json")
        C.dump(self.CAL, self.cal_path)
        self.say = []

    def options(self, **kw):
        kw = {"blocks": 3, "warmup": False, "rho": RHO, "timeline": SHORT, "simulate": "pass", **kw}
        return GC.Options(**kw)

    def host(self, effects="pass", cal=None, **kw):
        cal = cal or self.CAL
        return S.SimHost(server=S.SyntheticServer(cal, SHORT, S.EFFECT_PRESETS[effects]), tag=S.origin_tag(cal), **kw)

    def run_campaign(self, out="camp", host=None, cal=None, scn=None, spec_sha=SPEC_SHA, **kw):
        cal = cal or self.CAL
        return GC.run_campaign(scn or self.scn, cal, self.cal_path, spec_sha, os.path.join(self.tmp.name, out),
                               host or self.host(cal=cal), self.options(**kw), say=self.say.append)

    def path(self, *parts):
        return os.path.join(self.tmp.name, "camp", *parts)

    def json(self, *parts):
        with open(self.path(*parts), encoding="utf-8") as fh:
            return json.load(fh)

    def dirs(self, out="camp"):
        return sorted(d for d in os.listdir(os.path.join(self.tmp.name, out)) if os.path.isdir(os.path.join(self.tmp.name, out, d)))


class OrderTest(unittest.TestCase):
    scn = SC.load(SPEC)

    def test_an_order_is_a_permutation_of_the_three_runs(self):
        for block in range(1, 11):
            self.assertEqual(sorted(GC.run_order(self.scn, block, 1)), ["C", "Cp", "U"])

    def test_an_order_can_be_recomputed(self):
        self.assertEqual(GC.run_order(self.scn, 4, 2), GC.run_order(self.scn, 4, 2))

    def test_every_order_occurs_and_the_attempt_matters(self):
        seen = {tuple(GC.run_order(self.scn, b, 1)) for b in range(1, 61)}
        self.assertEqual(len(seen), 6)
        self.assertTrue(any(GC.run_order(self.scn, b, 1) != GC.run_order(self.scn, b, 2) for b in range(1, 20)))

    def test_the_scenario_is_part_of_the_draw(self):
        other = SC.load(os.path.join(REPO, "bench", "scenarios", "cheap_static_flood.json"))
        self.assertTrue(any(GC.run_order(self.scn, b, 1) != GC.run_order(other, b, 1) for b in range(1, 30)))

    def test_block_directories_sort_in_block_order(self):
        names = [os.path.basename(GC.block_dir("/x", b, a)) for b in (2, 10, 1) for a in (1, 2)]
        self.assertEqual(sorted(names), ["b01_a1", "b01_a2", "b02_a1", "b02_a2", "b10_a1", "b10_a2"])


class PlanTextTest(CampaignCase):
    def text(self, cal=None, **kw):
        return GC.describe(self.scn, cal or self.CAL, SPEC_SHA, self.options(**kw))

    def test_it_says_what_the_campaign_is_and_what_it_costs(self):
        text = self.text(blocks=None, warmup=True, rho=None, timeline=None, simulate=None)
        self.assertIn("== gate campaign: costly_search_sub_threshold (calib), 10 blocks ==", text)
        self.assertIn("31 runs at about 150 s = 1.3 h; each re-run adds 7.5 min", text)
        self.assertIn("warm-up      one unscored C run at seed 1, in warmup/", text)
        self.assertIn("needs 3 valid blocks", text)
        self.assertNotIn("OVERRIDES", text)
        self.assertNotIn("SIMULATED", text)

    def test_every_block_has_its_seed_and_its_first_order(self):
        text = self.text(blocks=None)
        for block in range(1, 11):
            self.assertIn(f"{block:>5}  {self.scn.first_seed + block - 1:>4}  " + ", ".join(GC.run_order(self.scn, block, 1)), text)

    def test_a_smoke_test_and_a_simulation_say_so(self):
        text = self.text()
        self.assertIn("OVERRIDES", text)
        self.assertIn("a smoke test, not a result", text)
        self.assertIn("SIMULATED    the simulated host, preset pass", text)
        self.assertIn("timeline     baseline_s 6, attack_s 6, recovery_s 6", text)

    def test_a_placeholder_is_a_dry_run(self):
        self.assertIn("PLACEHOLDER: a dry run", self.text(cal=CF.placeholder()))

    def test_fewer_blocks_than_the_gate_needs_are_warned_about(self):
        self.assertIn("WARNING: 2 blocks are fewer than the 3 the gate needs", self.text(blocks=2))
        self.assertNotIn("WARNING", self.text(blocks=3))

    def test_the_number_of_blocks_is_between_one_and_the_scenarios(self):
        for bad in (0, 11, -1):
            with self.subTest(blocks=bad), self.assertRaises(GC.CampaignError):
                GC.block_count(self.scn, GC.Options(blocks=bad))
        self.assertEqual(GC.block_count(self.scn, GC.Options()), 10)
        self.assertEqual(GC.block_count(self.scn, GC.Options(blocks=1)), 1)


class WholeCampaignTest(CampaignCase):
    """One campaign that passes and one that fails, made once."""

    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.TemporaryDirectory()
        cls.scn = SC.load(SPEC)
        cls.states = {}
        for name in ("pass", "fail", "small"):
            cal_path = os.path.join(cls.root.name, "calibration.json")
            C.dump(cls.CAL, cal_path)
            host = S.SimHost(server=S.SyntheticServer(cls.CAL, SHORT, S.EFFECT_PRESETS[name]), tag=S.origin_tag(cls.CAL))
            cls.states[name] = GC.run_campaign(cls.scn, cls.CAL, cal_path, SPEC_SHA, os.path.join(cls.root.name, name), host,
                                               GC.Options(blocks=3, warmup=False, rho=RHO, timeline=SHORT, simulate=name),
                                               say=lambda m: None)

    @classmethod
    def tearDownClass(cls):
        cls.root.cleanup()

    def dir(self, name, *parts):
        return os.path.join(self.root.name, name, *parts)

    def test_an_effect_over_the_floor_passes(self):
        gate = self.states["pass"]["gate"]
        self.assertEqual((gate["verdict"], gate["blocks_valid"], gate["blocks_total"], gate["reruns"]), ("PASS", 3, 3, 0))
        self.assertEqual(self.states["pass"]["state"], "complete")

    def test_no_effect_fails_and_a_small_one_fails(self):
        for name in ("fail", "small"):
            with self.subTest(effect=name):
                gate = self.states[name]["gate"]
                self.assertEqual((gate["verdict"], gate["blocks_valid"], gate["reruns"]), ("FAIL", 3, 0))

    def test_the_directory_is_what_the_gate_reads(self):
        result = H.analyse(self.dir("pass"), self.CAL)
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual([b["block"] for b in result["blocks"]], [1, 2, 3])
        self.assertEqual(result["reasons"], [])

    def test_the_layout_is_a_directory_per_attempt_with_a_run_per_kind_and_a_done_in_each(self):
        names = sorted(os.listdir(self.dir("pass")))
        self.assertEqual(names, ["SIMULATED", "b01_a1", "b02_a1", "b03_a1", "campaign.json", "gate.json", "gate.md"])
        for block in ("b01_a1", "b02_a1", "b03_a1"):
            self.assertEqual(sorted(os.listdir(self.dir("pass", block))), ["C", "Cp", "U", "block.json"])
            for kind in X.KINDS:
                self.assertTrue(os.path.exists(self.dir("pass", block, kind, GC.DONE)))
                self.assertTrue(os.path.exists(self.dir("pass", block, kind, "run.json")))

    def test_block_json_is_what_the_gate_requires_and_says_how_the_block_was_made(self):
        with open(self.dir("pass", "b02_a1", "block.json"), encoding="utf-8") as fh:
            meta = json.load(fh)
        for key in H.BLOCK_KEYS:
            self.assertIn(key, meta)
        self.assertEqual((meta["block"], meta["attempt"], meta["seed"], meta["seed_namespace"]), (2, 1, 2, "calib"))
        self.assertEqual(meta["timeline"], {"baseline_s": 6.0, "attack_s": 6.0, "recovery_s": 6.0})
        self.assertEqual(meta["calibration_sha256"], self.CAL["sha256"])
        self.assertEqual(meta["scenario_sha256"], SPEC_SHA)
        self.assertEqual(meta["order"], meta["planned_order"])
        self.assertEqual(meta["planned_order"], GC.run_order(self.scn, 2, 1))
        self.assertTrue(meta["complete"])
        self.assertIsNone(meta["aborted"])
        self.assertEqual(meta["overrides"], {"rho_rps": RHO, "timeline_s": [6.0, 6.0, 6.0]})

    def test_the_three_runs_of_a_block_have_the_same_legit_streams(self):
        for block in ("b01_a1", "b02_a1", "b03_a1"):
            hashes = set()
            for kind in X.KINDS:
                with open(self.dir("pass", block, kind, "run.json"), encoding="utf-8") as fh:
                    hashes.add(json.load(fh)["plan_sha256"])
            self.assertEqual(len(hashes), 1, block)

    def test_the_runs_are_in_the_order_the_block_says(self):
        with open(self.dir("pass", "b01_a1", "block.json"), encoding="utf-8") as fh:
            order = json.load(fh)["order"]
        started = []
        for kind in order:
            with open(self.dir("pass", "b01_a1", kind, "run.json"), encoding="utf-8") as fh:
                started.append(json.load(fh)["started_utc"])
        self.assertEqual(started, sorted(started))

    def test_a_valid_block_is_never_re_run(self):
        self.assertFalse([d for d in os.listdir(self.dir("pass")) if d.endswith("_a2")])

    def test_campaign_json_is_the_record_of_it(self):
        state = self.states["pass"]
        with open(self.dir("pass", GC.CAMPAIGN), encoding="utf-8") as fh:
            on_disk = json.load(fh)
        self.assertEqual(on_disk["state"], "complete")
        self.assertEqual(on_disk["simulated"], "pass")
        self.assertEqual([(a["block"], a["attempt"], a["valid"]) for a in on_disk["attempts"]], [(1, 1, True), (2, 1, True), (3, 1, True)])
        self.assertEqual(on_disk["fingerprint"]["calibration_sha256"], self.CAL["sha256"])
        self.assertEqual(on_disk["gate"], state["gate"])
        self.assertIn("commit", on_disk["git"])

    def test_the_report_is_written_beside_the_data_and_says_it_is_simulated(self):
        with open(self.dir("pass", "gate.md"), encoding="utf-8") as fh:
            md = fh.read()
        self.assertTrue(md.startswith("> **SIMULATED.**"))
        self.assertIn("**Verdict: PASS**", md)
        with open(self.dir("pass", "gate.json"), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["verdict"], "PASS")
        self.assertTrue(os.path.exists(self.dir("pass", GC.SIMULATED)))

    def test_status_reads_a_directory(self):
        text = GC.status_text(self.dir("pass"))
        self.assertIn("campaign costly_search_sub_threshold (calib), 3 blocks", text)
        self.assertIn("SIMULATED", text)
        self.assertIn("state complete", text)
        self.assertIn("block  2 attempt 1 seed 2: valid", text)
        self.assertIn("gate PASS: 3 valid blocks of 3", text)

    def test_status_of_a_directory_that_is_not_a_campaign(self):
        with self.assertRaises(GC.CampaignError):
            GC.status_text(self.root.name)


class RerunRuleTest(CampaignCase):
    def test_a_failed_block_is_re_run_once_with_its_seed(self):
        host = self.host(fault_schedule={1: {"stream_dies": 1}})
        state = self.run_campaign(host=host)
        self.assertEqual(self.dirs(), ["b01_a1", "b01_a2", "b02_a1", "b03_a1"])
        first, second = self.json("b01_a1", "block.json"), self.json("b01_a2", "block.json")
        self.assertEqual((first["seed"], second["seed"]), (1, 1))
        self.assertEqual(first["order"], [], "the first run died before it made a run.json")
        self.assertEqual(first["aborted"], first["planned_order"][0])
        self.assertEqual(second["planned_order"], GC.run_order(self.scn, 1, 2))
        self.assertEqual(state["reruns"], 1)
        self.assertEqual((state["gate"]["verdict"], state["gate"]["blocks_valid"], state["gate"]["reruns"]), ("PASS", 3, 1))
        self.assertEqual([(a["block"], a["attempt"], a["valid"]) for a in state["attempts"]],
                         [(1, 1, False), (1, 2, True), (2, 1, True), (3, 1, True)])

    def test_the_attempt_ends_where_the_run_failed(self):
        host = self.host(fault_schedule={1: {"stream_dies": 1}})
        self.run_campaign(host=host)
        self.assertEqual(sorted(os.listdir(self.path("b01_a1"))), sorted([GC.run_order(self.scn, 1, 1)[0], "block.json"]))
        self.assertTrue(any("the attempt ends here" in m for m in self.say))

    def test_the_gate_agrees_with_the_campaign_about_the_rerun(self):
        host = self.host(fault_schedule={1: {"stream_dies": 1}})
        self.run_campaign(host=host)
        result = H.analyse(self.path(), self.CAL)
        self.assertEqual((result["reruns"], result["reasons"]), (1, []))
        self.assertEqual([(a["block"], a["attempt"]) for a in result["attempts"]], [(1, 1)])
        self.assertFalse(result["attempts"][0]["valid"])

    def test_a_second_failure_is_not_re_run_and_the_campaign_stops_when_it_cannot_reach_its_blocks(self):
        host = self.host(fault_schedule={1: {"stream_dies": 1}, 2: {"stream_dies": 1}})
        state = self.run_campaign(host=host)
        self.assertEqual(self.dirs(), ["b01_a1", "b01_a2"], "no third attempt, and the campaign stopped")
        self.assertEqual(state["state"], "stopped")
        self.assertIn("cannot reach the 3 the gate needs", state["stopped"])
        self.assertEqual(state["gate"]["verdict"], "INVALID")
        self.assertEqual(state["gate"]["blocks_valid"], 0)

    def test_keep_going_runs_the_remaining_blocks_and_the_gate_calls_it_invalid(self):
        host = self.host(fault_schedule={1: {"stream_dies": 1}, 2: {"stream_dies": 1}})
        state = self.run_campaign(host=host, keep_going=True)
        self.assertEqual(self.dirs(), ["b01_a1", "b01_a2", "b02_a1", "b03_a1"])
        self.assertEqual(state["state"], "complete")
        gate = state["gate"]
        self.assertEqual((gate["verdict"], gate["blocks_valid"], gate["blocks_total"]), ("INVALID", 2, 3))
        self.assertTrue(any("2 valid blocks, fewer than the 3 the gate needs" in r for r in gate["reasons"]))

    def test_at_most_the_gates_re_runs_in_all(self):
        # topologies: block 1 attempt 1 is the 1st, its re-run the 2nd-4th; block 2 attempt 1 the 5th, its re-run the 6th-8th;
        # block 3 attempt 1 the 9th: three failed first attempts, two re-runs allowed
        host = self.host(fault_schedule={1: {"stream_dies": 1}, 5: {"stream_dies": 1}, 9: {"stream_dies": 1}})
        state = self.run_campaign(host=host)
        self.assertEqual(self.dirs(), ["b01_a1", "b01_a2", "b02_a1", "b02_a2", "b03_a1"])
        self.assertEqual(state["reruns"], 2)
        self.assertEqual(state["state"], "complete")
        gate = state["gate"]
        self.assertEqual((gate["verdict"], gate["blocks_valid"], gate["blocks_total"], gate["reruns"]), ("INVALID", 2, 3, 2))
        self.assertEqual(H.analyse(self.path(), self.CAL)["reasons"], gate["reasons"])

    def test_an_unsound_run_ends_its_attempt_and_the_block_is_re_run(self):
        started = []

        def startup(sid, index, kind):                   # the 8th stream the campaign starts is 0.9 s late, in its first run only
            started.append(sid)
            return (1.8 if kind == "legit" else 0.3) + (0.9 if len(started) == 8 else 0.0)
        state = self.run_campaign(host=self.host(startup_s=startup))
        first = self.json("b01_a1", "block.json")
        self.assertEqual(len(first["order"]), 1, "the first run was made and found unsound; the others were not made")
        self.assertEqual(first["aborted"], first["planned_order"][0])
        self.assertIn("apart", "; ".join(first["runs"][first["aborted"]]["reasons"]))
        self.assertEqual(state["reruns"], 1)
        self.assertEqual(state["gate"]["verdict"], "PASS")
        attempt = state["attempts"][0]
        self.assertFalse(attempt["valid"])
        self.assertTrue(any(r.startswith(f"{first['aborted']}: executor: ") for r in attempt["reasons"]), attempt["reasons"])

    def test_an_unhealthy_control_makes_a_block_invalid_and_it_is_re_run_within_the_limit(self):
        host = self.host(effects="pass")
        host.server.effects = {"C": {"fail_p": 0.5}, "Cp": {"fail_p": 0.5}, "U": {"fail_p": 0.5}}
        host.server.window = (0.0, 18.0)               # the control fails over the whole run, so it is not healthy
        state = self.run_campaign(host=host, keep_going=True)
        self.assertEqual(self.dirs(), ["b01_a1", "b01_a2", "b02_a1", "b02_a2", "b03_a1"])
        self.assertEqual(state["reruns"], 2)
        self.assertEqual(state["gate"]["verdict"], "INVALID")
        self.assertTrue(any("control" in r for r in state["attempts"][0]["reasons"]))


class WarmupTest(CampaignCase):
    def test_the_warm_up_is_an_unscored_control_run_beside_the_blocks(self):
        state = self.run_campaign(warmup=True)
        self.assertEqual(self.dirs(), ["b01_a1", "b02_a1", "b03_a1", "warmup"])
        self.assertTrue(os.path.exists(self.path("warmup", "C", GC.DONE)))
        self.assertEqual(self.json("warmup", "C", "run.json")["seed"], self.scn.first_seed)
        self.assertEqual(self.json("warmup", "C", "run.json")["role"], "control")
        self.assertTrue(state["warmup"]["ok"])
        self.assertEqual(state["gate"]["blocks_total"], 3, "the gate does not see it")

    def test_without_it_there_is_no_directory(self):
        self.run_campaign(warmup=False)
        self.assertNotIn("warmup", self.dirs())
        self.assertIsNone(self.json(GC.CAMPAIGN)["warmup"])

    def test_the_first_run_waits_for_the_full_gate_and_the_rest_for_the_timer(self):
        with mock.patch.object(GC.X, "execute", wraps=X.execute) as spy:
            self.run_campaign(warmup=True)
        modes = [c.args[2] for c in spy.call_args_list]
        self.assertEqual(len(modes), 10)
        self.assertEqual(modes, ["full"] + ["timer"] * 9)

    def test_without_a_warm_up_the_first_block_run_takes_the_full_gate(self):
        with mock.patch.object(GC.X, "execute", wraps=X.execute) as spy:
            self.run_campaign(warmup=False)
        self.assertEqual([c.args[2] for c in spy.call_args_list], ["full"] + ["timer"] * 8)

    def test_a_warm_up_that_fails_stops_the_campaign(self):
        host = self.host(fault_schedule={1: {"stream_dies": 1}})
        with self.assertRaises(GC.CampaignError) as ctx:
            self.run_campaign(host=host, warmup=True)
        self.assertIn("warm-up run failed", str(ctx.exception))
        self.assertEqual(self.json(GC.CAMPAIGN)["state"], "stopped")
        self.assertEqual(self.dirs(), ["warmup"])

    def test_a_warm_up_that_is_made_is_not_made_again(self):
        with self.assertRaises(KeyboardInterrupt):
            self.run_campaign(host=self.host(on_sleep=interrupt_after(30.0)), warmup=True)
        self.assertTrue(os.path.exists(self.path("warmup", "C", GC.DONE)), "the warm-up finished before the interrupt")
        with mock.patch.object(GC.X, "execute", wraps=X.execute) as spy:
            self.run_campaign(warmup=True)
        made = [os.path.basename(os.path.dirname(c.args[0].out)) for c in spy.call_args_list]
        self.assertNotIn("warmup", made)
        self.assertEqual(len(made), 9)
        self.assertEqual(spy.call_args_list[0].args[2], "full", "the first run of this process waits for the full gate again")


class ResumeTest(CampaignCase):
    def test_an_interrupted_campaign_resumes_to_the_result_of_an_uninterrupted_one(self):
        whole = self.run_campaign(out="whole")
        with self.assertRaises(KeyboardInterrupt):
            self.run_campaign(out="split", host=self.host(on_sleep=interrupt_after(70.0)))
        with open(os.path.join(self.tmp.name, "split", GC.CAMPAIGN), encoding="utf-8") as fh:
            interrupted = json.load(fh)
        self.assertEqual(interrupted["state"], "interrupted")
        self.assertIn("resumes", interrupted["stopped"])
        resumed = self.run_campaign(out="split")
        self.assertEqual(resumed["state"], "complete")
        self.assertEqual(self.dirs("split"), self.dirs("whole"))
        a, b = H.analyse(os.path.join(self.tmp.name, "whole"), self.CAL), H.analyse(os.path.join(self.tmp.name, "split"), self.CAL)
        self.assertEqual(a["verdict"], b["verdict"])
        for x, y in zip(a["blocks"], b["blocks"], strict=True):
            for key in ("block", "seed", "attempt", "valid", "dQ", "dL", "dQ_placebo", "order"):
                self.assertEqual(x[key], y[key], key)
            for kind in X.KINDS:
                self.assertEqual(x["runs"][kind]["metrics"]["Q"], y["runs"][kind]["metrics"]["Q"])
        for block in ("b01_a1", "b02_a1", "b03_a1"):
            with open(os.path.join(self.tmp.name, "whole", block, "block.json"), encoding="utf-8") as fh:
                left = without_times(json.load(fh))
            with open(os.path.join(self.tmp.name, "split", block, "block.json"), encoding="utf-8") as fh:
                right = without_times(json.load(fh))
            self.assertEqual(left, right, block)
        self.assertEqual(whole["gate"], resumed["gate"])

    def test_the_run_that_was_cut_short_is_removed_and_made_again(self):
        with self.assertRaises(KeyboardInterrupt):
            self.run_campaign(host=self.host(on_sleep=interrupt_after(30.0)))
        cut = [os.path.join(self.path(d), k) for d in self.dirs() for k in X.KINDS if os.path.isdir(os.path.join(self.path(d), k))
               and not os.path.exists(os.path.join(self.path(d), k, GC.DONE))]
        self.assertEqual(len(cut), 1)
        self.assertTrue(os.path.exists(os.path.join(cut[0], "FAILED")))
        with mock.patch.object(GC.X, "execute", wraps=X.execute) as spy:
            self.run_campaign()
        self.assertFalse(os.path.exists(os.path.join(cut[0], "FAILED")))
        self.assertTrue(os.path.exists(os.path.join(cut[0], GC.DONE)))
        done_before = 1
        self.assertEqual(len(spy.call_args_list), 9 - done_before)
        self.assertTrue(any("removing the unfinished run" in m for m in self.say))

    def test_a_finished_campaign_resumed_makes_nothing(self):
        first = self.run_campaign()
        with mock.patch.object(GC.X, "execute", wraps=X.execute) as spy:
            again = self.run_campaign()
        self.assertEqual(spy.call_count, 0)
        self.assertEqual(again["gate"], first["gate"])
        self.assertEqual(again["state"], "complete")

    def test_a_campaign_resumes_only_as_it_began(self):
        self.run_campaign()
        for change, key in (({"blocks": 2}, "blocks"), ({"rho": 30.0}, "rho_rps"), ({"warmup": True}, "warmup"),
                            ({"timeline": (7.0, 6.0, 6.0)}, "timeline"), ({"settings": (("t0_spread_limit_s", 0.4),)}, "settings")):
            with self.subTest(change=change), self.assertRaises(GC.CampaignError) as ctx:
                self.run_campaign(**change)
            self.assertIn("other settings", str(ctx.exception))
            self.assertIn(key, str(ctx.exception))

    def test_another_calibration_or_another_scenario_is_another_campaign(self):
        self.run_campaign()
        with self.assertRaises(GC.CampaignError) as ctx:
            self.run_campaign(cal=three_block_cal(max_reruns=1))
        self.assertIn("calibration_sha256", str(ctx.exception))
        with self.assertRaises(GC.CampaignError) as ctx:
            self.run_campaign(spec_sha="0" * 64)
        self.assertIn("scenario_sha256", str(ctx.exception))

    def test_a_directory_that_is_not_a_campaign_is_not_used(self):
        os.makedirs(self.path())
        with open(self.path("notes.txt"), "w", encoding="utf-8") as fh:
            fh.write("results of something else")
        with self.assertRaises(GC.CampaignError):
            self.run_campaign()
        self.assertEqual(os.listdir(self.path()), ["notes.txt"])

    def test_a_block_made_with_other_clients_is_refused_before_anything_runs(self):
        original = X.plan_run

        def tampered(scn, cal, kind, *a, **k):
            plan = original(scn, cal, kind, *a, **k)
            return plan if kind != "Cp" else dataclasses.replace(plan, plan_sha256="f" * 64)
        host = self.host()
        with mock.patch.object(GC.X, "plan_run", tampered), self.assertRaises(GC.CampaignError) as ctx:
            self.run_campaign(host=host)
        self.assertIn("the legit streams of C, Cp and U differ", str(ctx.exception))
        self.assertEqual(host.prims, [])


class StopTest(CampaignCase):
    def state(self, out="camp"):
        with open(os.path.join(self.tmp.name, out, GC.CAMPAIGN), encoding="utf-8") as fh:
            return json.load(fh)

    def test_a_refusal_before_the_first_run_stops_the_campaign_and_the_same_command_resumes_it(self):
        with self.assertRaises(X.PreflightRefused):
            self.run_campaign(host=self.host(root=False))
        state = self.state()
        self.assertEqual(state["state"], "stopped")
        self.assertIn("PreflightRefused", state["stopped"])
        self.assertEqual(state["attempts"], [])
        resumed = self.run_campaign()
        self.assertEqual((resumed["state"], resumed["gate"]["verdict"]), ("complete", "PASS"))
        self.assertIsNone(self.state()["stopped"])

    def test_a_timer_that_goes_bad_mid_campaign_stops_it_and_the_made_runs_are_kept(self):
        def degrade(host):
            if host.t > 60.0:
                host.timer_p99_ms = 50.0
        with self.assertRaises(X.EnvironmentRefused):
            self.run_campaign(host=self.host(on_sleep=degrade))
        kept = sorted(os.path.join(d, k) for d in self.dirs() for k in X.KINDS
                      if os.path.exists(self.path(d, k, GC.DONE)))
        self.assertGreaterEqual(len(kept), 2)
        self.assertEqual(self.state()["state"], "stopped")
        with mock.patch.object(GC.X, "execute", wraps=X.execute) as spy:
            resumed = self.run_campaign()
        self.assertEqual(spy.call_count, 9 - len(kept))
        self.assertEqual(resumed["gate"]["verdict"], "PASS")

    def test_a_setup_that_cannot_be_built_stops_the_campaign_and_does_not_count_as_a_failed_block(self):
        with self.assertRaises(X.SetupFailed):
            self.run_campaign(host=self.host(faults={"missing_address": None}))
        self.assertEqual(self.state()["state"], "stopped")
        self.assertEqual(self.state()["reruns"], 0)
        self.assertFalse([d for d in self.dirs() if d.endswith("_a2")])

    def test_a_leftover_after_a_teardown_stops_the_campaign(self):
        with self.assertRaises(X.LeftoverError):
            self.run_campaign(host=self.host(faults={"leftover_nginx_after_teardown": None}))
        self.assertIn("LeftoverError", self.state()["stopped"])

    def test_a_table_that_cannot_be_read_stops_the_campaign(self):
        with self.assertRaises(X.TableUnreadable):
            self.run_campaign(host=self.host(faults={"table_unreadable": None}))
        self.assertEqual(self.state()["state"], "stopped")

    def test_ctrl_c_is_recorded_and_the_testbed_taken_down(self):
        host = self.host(on_sleep=interrupt_after(10.0))
        with self.assertRaises(KeyboardInterrupt):
            self.run_campaign(host=host)
        self.assertEqual(self.state()["state"], "interrupted")
        self.assertEqual(host.testbed(), {"namespaces": [], "links": [], "processes": []})


class CalibrationTest(CampaignCase):
    def test_a_placeholder_is_refused_without_dry_run_and_nothing_is_made(self):
        with self.assertRaises(GC.CampaignError) as ctx:
            GC.run_campaign(self.scn, CF.placeholder(), C.PLACEHOLDER, SPEC_SHA, self.path(), S.SimHost(), self.options())
        self.assertIn("placeholder", str(ctx.exception))
        self.assertFalse(os.path.exists(self.path()))

    def test_a_dry_run_on_a_placeholder_is_labelled_everywhere(self):
        cal = CF.placeholder()
        cal["gate"]["min_blocks"] = 3
        host = S.SimHost(server=S.SyntheticServer(cal, SHORT, S.EFFECT_PRESETS["pass"]), tag="placeholder")
        state = GC.run_campaign(self.scn, cal, C.PLACEHOLDER, SPEC_SHA, self.path(), host, self.options(dry_run=True),
                                say=self.say.append)
        self.assertTrue(state["gate"]["dry_run"])
        with open(self.path("gate.md"), encoding="utf-8") as fh:
            md = fh.read()
        self.assertIn("DRY RUN on a placeholder calibration", md)
        self.assertIn("(dry run)", md)
        self.assertEqual(self.json(GC.CAMPAIGN)["fingerprint"]["calibration_status"], "placeholder")

    def test_the_tag_of_the_origin_follows_the_calibration(self):
        self.assertEqual(S.origin_tag(CF.placeholder()), "placeholder")
        self.assertEqual(S.origin_tag(self.CAL), f"frozen:{self.CAL['sha256'][:8]}")


class CommandLineTest(CampaignCase):
    def cli(self, *args, host=None):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(X.signal, "signal"), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = GC.main(list(args), host=host)
        return code, out.getvalue(), err.getvalue()

    def base(self, *extra, out="camp"):
        return ["run", SPEC, "--calibration", self.cal_path, "--out", os.path.join(self.tmp.name, out), "--blocks", "3", "--rho", "20",
                "--timeline", "6,6,6", "--no-warmup", *extra]

    def test_plan_prints_the_campaign(self):
        code, out, _ = self.cli("plan", SPEC, "--calibration", self.cal_path, "--blocks", "3")
        self.assertEqual(code, GC.EXIT_OK)
        self.assertIn("== gate campaign: costly_search_sub_threshold (calib), 3 blocks ==", out)

    def test_a_simulated_campaign_runs_to_a_verdict(self):
        code, out, err = self.cli(*self.base("--simulate", "pass"))
        self.assertEqual((code, err), (GC.EXIT_OK, ""))
        self.assertIn("gate: PASS (simulated), 3 valid blocks of 3, 0 re-run(s)", out)

    def test_a_simulated_campaign_with_no_effect_fails_the_gate(self):
        code, out, _ = self.cli(*self.base("--simulate", "fail"))
        self.assertEqual(code, GC.EXIT_OK)
        self.assertIn("gate: FAIL (simulated)", out)

    def test_a_simulated_fault_shows_the_re_run_rule(self):
        code, out, _ = self.cli(*self.base("--simulate", "pass", "--simulate-fault", "stream_dies:1"))
        self.assertEqual(code, GC.EXIT_OK)
        self.assertIn("1 re-run(s)", out)
        self.assertTrue(os.path.isdir(os.path.join(self.tmp.name, "camp", "b01_a2")))

    def test_the_simulated_faults_are_parsed(self):
        self.assertEqual(GC.parse_faults(["stream_dies:2", "ping_fails"]), {"stream_dies": 2, "ping_fails": None})
        self.assertEqual(GC.parse_faults(None), {})

    def test_a_refusal_exits_two_and_says_why(self):
        code, _, err = self.cli(*self.base(), host=S.SimHost(root=False))
        self.assertEqual(code, GC.EXIT_STOPPED)
        self.assertIn("PreflightRefused", err)

    def test_a_campaign_that_stops_exits_two(self):
        code, _, err = self.cli(*self.base("--simulate", "pass", "--simulate-fault", "missing_address"))
        self.assertEqual(code, GC.EXIT_STOPPED)
        self.assertIn("SetupFailed", err)
        self.assertEqual(self.json(GC.CAMPAIGN)["state"], "stopped")

    def test_a_campaign_that_cannot_reach_its_blocks_stops_and_exits_two(self):
        host = self.host(fault_schedule={1: {"stream_dies": 1}, 2: {"stream_dies": 1}})
        code, out, err = self.cli(*self.base(), host=host)
        self.assertEqual((code, err), (GC.EXIT_STOPPED, ""))
        self.assertIn("gate: INVALID", out)
        self.assertEqual(self.json(GC.CAMPAIGN)["state"], "stopped")

    def test_an_attack_free_scenario_has_no_gate_campaign(self):
        code, _, err = self.cli("run", CONTROL_SPEC, "--calibration", self.cal_path, "--out", os.path.join(self.tmp.name, "x"),
                                "--simulate", "pass")
        self.assertEqual(code, GC.EXIT_STOPPED)
        self.assertIn("attack-free", err)

    def test_a_placeholder_needs_dry_run(self):
        code, _, err = self.cli("run", SPEC, "--out", os.path.join(self.tmp.name, "x"), "--simulate", "pass", "--blocks", "3",
                                "--no-warmup", "--timeline", "6,6,6", "--rho", "20")
        self.assertEqual(code, GC.EXIT_STOPPED)
        self.assertIn("--dry-run", err)

    def test_blocks_out_of_range_exit_two(self):
        code, _, err = self.cli("run", SPEC, "--calibration", self.cal_path, "--out", os.path.join(self.tmp.name, "x"),
                                "--blocks", "11", "--simulate", "pass", "--no-warmup")
        self.assertEqual(code, GC.EXIT_STOPPED)
        self.assertIn("--blocks", err)

    def test_an_unknown_effect_is_a_usage_error(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as ctx:
            GC.main(self.base("--simulate", "nonsense"))
        self.assertEqual(ctx.exception.code, 2)

    def test_status_prints_the_state(self):
        self.cli(*self.base("--simulate", "pass"))
        code, out, _ = self.cli("status", os.path.join(self.tmp.name, "camp"))
        self.assertEqual(code, GC.EXIT_OK)
        self.assertIn("gate PASS", out)

    def test_ctrl_c_exits_130_and_the_same_command_resumes(self):
        code, _, err = self.cli(*self.base("--allow-dirty"), host=self.host(on_sleep=interrupt_after(20.0)))
        self.assertEqual(code, GC.EXIT_INTERRUPTED)
        self.assertIn("resumes", err)
        code, out, _ = self.cli(*self.base("--allow-dirty"), host=self.host())
        self.assertEqual(code, GC.EXIT_OK)
        self.assertIn("gate: PASS", out)

    def test_a_real_run_pins_the_campaign_to_the_executors_cpu_and_installs_its_signal_handlers(self):
        host = self.host()
        with mock.patch.object(X.signal, "signal") as handlers, contextlib.redirect_stdout(io.StringIO()):
            GC.main(self.base("--allow-dirty"), host=host)
        self.assertEqual(host.pinned, "2")
        self.assertEqual({c.args[0] for c in handlers.call_args_list}, {X.signal.SIGTERM, X.signal.SIGHUP})

    def tearDown(self):
        shutil.rmtree(os.path.join(self.tmp.name, "camp"), ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
