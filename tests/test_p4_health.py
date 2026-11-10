"""D-073 (3), R-021 (2026-11-07T08:33Z): the halving rule of §4.2 reads C and C' of a health phase on pilot seed 9101 before the ladder, P1's
D-049 rule with D-058's guard; the ladder, the validation and the campaign run at its frozen factor; an unhealthy C inside the ladder makes
that attempt unsound and never fires the rule (T-074). Nothing touches the machine."""
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
import p4_health as H
import p4_ladder as L
import p4_runner as R
import p4_traffic as P
import test_p4_runner as TR

LORIS = ("loris",)
SICK = ["Q(C) is 98.00 %, below 99 %"]


def step(h, reasons=([], []), sound=True, server_q=(None, None), name=None):
    return {"dir": name or f"health/b9101_a1_h{h}", "halvings": h, "sound": sound, "reasons": list(reasons), "server_q": list(server_q)}


class RuleTest(unittest.TestCase):
    def test_the_pre_registered_rule(self):
        rule = P.prereg()["halving"]
        self.assertEqual((rule["seed"], rule["controls"], rule["max_reruns"], rule["floor"]["max_halvings"], rule["server_q_min"]),
                         (9101, ["C", "Cp"], 2, 2, 99.0))
        self.assertIn(rule["seed"], P.SEEDS["pilot"])
        self.assertEqual([P.browser_devices(h) for h in range(3)], [40, 20, 10])
        self.assertEqual(P.prereg()["format"], "p4-prereg/1")

    def test_the_steps_up_to_a_factor(self):
        self.assertEqual(P.next_step([]), {"decision": "run", "benign_halvings": None, "next_halvings": 0, "why": "the next step runs at 0 halvings"})
        self.assertEqual(P.next_step([step(0)])["benign_halvings"], 0)
        self.assertEqual(P.next_step([step(0, (SICK, []))])["next_halvings"], 1)
        self.assertEqual(P.next_step([step(0, ([], SICK)), step(1)])["benign_halvings"], 1)
        self.assertEqual(P.next_step([step(0, sound=False), step(0, sound=False), step(0)])["benign_halvings"], 0)

    def test_what_the_rule_refuses(self):
        for steps, why in (([step(0, sound=False)] * 3, "no reading in 3 attempts"),
                           ([step(0, (SICK, [])), step(1, (SICK, [])), step(2, (SICK, []))], "floor of 2 halvings"),
                           ([step(1)], "ran at 1 halvings while the rule stood at 0"),
                           ([step(0), step(0)], "a step ran after the rule stopped")):
            res = P.next_step(steps)
            self.assertEqual(res["decision"], "refused", steps)
            self.assertIn(why, res["why"])

    def test_d058s_guard_waits_for_a_dated_decision(self):
        stopped = [step(0, (SICK, []), server_q=(99.5, 99.9))]
        res = P.next_step(stopped)
        self.assertEqual((res["decision"], res["stopped_step"]), ("stopped", "health/b9101_a1_h0"))
        fire = {"health/b9101_a1_h0": {"action": "fire", "text": "2026-11-10: the user"}}
        self.assertEqual(P.next_step(stopped, fire)["next_halvings"], 1)
        again = {"health/b9101_a1_h0": {"action": "repeat", "text": "2026-11-10: the user"}}
        self.assertEqual(P.next_step([*stopped, step(0, name="health/b9101_a2_h0")], again)["benign_halvings"], 0)
        self.assertEqual(P.next_step([step(0, (SICK, []), server_q=(97.0, 99.9))])["next_halvings"], 1, "the server's own limit fires it")
        with self.assertRaisesRegex(ValueError, "names a dated decision"):
            H.parse_health_decision("health/b9101_a1_h0=fire:the user")
        self.assertEqual(H.parse_health_decision("d=repeat:2026-11-10 the user"), {"d": {"action": "repeat", "text": "2026-11-10 the user"}})


class PlanTest(unittest.TestCase):
    def test_a_health_step_is_the_rules_two_controls_on_its_seed(self):
        block = R.plan_block("health", 9101, "/r", halvings=1, families=LORIS)
        self.assertEqual((sorted(block["order"]), block["label"], block["dir"], block["halvings"]), (["C", "Cp"], "h1", "/r/health/b9101_a1_h1", 1))
        for run in block["runs"]:
            self.assertEqual((run["nginx"]["conf"], run["daemon"], run["family"]), ("nginx_profile_r.conf", None, None))
            self.assertEqual(sum(e["role"] == "benign" and e["kind_or_family"] == "tpcw_browsing" for e in run["entities"]), 20)
            self.assertFalse([e for e in run["entities"] if e["role"] == "attack"])
        bad = [lambda: R.plan_block("health", 9102, "/r"), lambda: R.plan_block("health", 9101, "/r", sources={"loris": 100}),
               lambda: R.plan_block("health", 9101, "/r", arms=["U_loris"]), lambda: R.plan_block("health", 9101, "/r", label="h3"),
               lambda: R.plan_block("health", 9101, "/r", thresholds=TR.POINT), lambda: R.plan_block("smoke", 9101, "/r", health="h.json")]
        for make in bad:
            with self.assertRaises((R.PlanError, P.PlanError)):
                make()


class HealthPhaseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        self.out = os.path.join(self.root, "health.json")

    def health(self, halvings=0, attempt=1, **host):
        return R.run_block(F.FakeHost(**host), R.plan_block("health", 9101, self.root, halvings=halvings, attempt=attempt, families=LORIS))

    def read(self, *decisions):
        with contextlib.redirect_stdout(io.StringIO()) as said:
            rc = H.main([self.root, "--calibration", R.PLACEHOLDER, "--out", self.out, *[f"--health-decision={d}" for d in decisions]])
        with open(self.out, encoding="utf-8") as fh:
            return rc, json.load(fh), said.getvalue()

    def test_healthy_controls_freeze_the_factor_the_ladder_runs_at(self):
        self.health()
        rc, rec, said = self.read()
        self.assertEqual((rc, rec["format"], rec["decision"], rec["benign_halvings"]), (0, "p4-health/1", "frozen", 0))
        self.assertEqual(rec["calibration_sha256"], TR.sha(R.PLACEHOLDER))
        self.assertEqual(sorted(rec["steps"][0]["controls"]), ["C", "Cp"])
        self.assertIn("frozen: both controls healthy at 0 halvings", said)
        block = R.plan_block("ladder", 9101, self.root, sources={"loris": 100}, family="loris", label="l100r1", families=LORIS, health=self.out)
        self.assertEqual(block["halvings"], 0)
        self.assertEqual(R.block_settings(block)["health_sha256"], TR.sha(self.out))
        with self.assertRaisesRegex(R.PlanError, r"--halvings 1, and the halving rule's factor is 0"):
            R.plan_block("ladder", 9101, self.root, sources={"loris": 100}, family="loris", label="l100r1", families=LORIS,
                         health=self.out, halvings=1)
        R.run_block(TR.HostThatMeasures(), block)

    def test_a_host_that_measures_needs_the_factor(self):
        block = R.plan_block("ladder", 9101, self.root, sources={"loris": 100}, family="loris", label="l100r1", families=LORIS)
        with self.assertRaisesRegex(R.PlanError, r"ladder: --health must name the halving rule's frozen factor"):
            R.run_block(TR.HostThatMeasures(), block)
        self.assertFalse(os.path.exists(os.path.join(self.root, "ladder")), "nothing was started")
        R.run_block(F.FakeHost(), block)                                    # a host that measures nothing may go without it

    def test_a_file_without_a_factor_or_of_another_record_is_refused(self):
        self.health(harm=lambda _t: True)                               # the fake logs no failed request: no server-side Q to stop on
        rc, rec, _said = self.read()
        self.assertEqual((rc, rec["decision"], rec["next_halvings"]), (0, "run", 1))
        with self.assertRaisesRegex(R.PlanError, "no frozen factor .*run"):
            R.plan_block("ladder", 9101, self.root, sources={"loris": 100}, family="loris", label="l100r1", families=LORIS, health=self.out)
        other = os.path.join(self.root, "other.json")
        with open(R.PLACEHOLDER, encoding="utf-8") as fh, open(other, "w", encoding="utf-8") as out:
            out.write(fh.read() + "\n")
        with self.assertRaisesRegex(R.PlanError, "another calibration record"):
            R.plan_block("ladder", 9101, self.root, sources={"loris": 100}, family="loris", label="l100r1", families=LORIS,
                         health=self.out, calibration=other)

    def test_a_dated_decision_fires_the_rule_and_the_next_step_runs_halved(self):
        real = H.control_reading

        def server_fine(run_dir, cal):                                  # D-058: the clients failed and the server answered in time
            out = real(run_dir, cal)
            return {**out, "server_q": 99.5} if out.get("reasons") else out
        self.health(harm=lambda _t: True)
        with mock.patch.object(H, "control_reading", server_fine):
            rc, rec, _said = self.read()
            self.assertEqual((rc, rec["decision"], rec["stopped_step"]), (1, "stopped", rec_dir(self.root)))
            rc, rec, _said = self.read(f"{rec_dir(self.root)}=fire:2026-11-10 the user")
            self.assertEqual((rc, rec["decision"], rec["next_halvings"]), (0, "run", 1))
            self.health(halvings=1)
            rc, rec, _said = self.read(f"{rec_dir(self.root)}=fire:2026-11-10 the user")
        self.assertEqual((rc, rec["decision"], rec["benign_halvings"]), (0, "frozen", 1))
        block = R.plan_block("ladder", 9101, self.root, sources={"loris": 100}, family="loris", label="l100r1", families=LORIS, health=self.out)
        self.assertEqual((block["halvings"], P.browser_devices(block["halvings"])), (1, 20))

    def test_the_factor_file_is_bound_to_its_root_and_health_index_D080(self):
        # D-080 (T078-08): a factor file is refused for another root, or when the health index it read has changed.
        self.health()
        self.read()                                                     # writes self.out, frozen in self.root
        with tempfile.TemporaryDirectory() as other,                 self.assertRaisesRegex(R.PlanError, r"was produced under the root .* not .*D-080"):
            R.plan_block("ladder", 9101, other, sources={"loris": 100}, family="loris", label="l100r1", families=LORIS, health=self.out)
        R.plan_block("ladder", 9101, self.root, sources={"loris": 100}, family="loris", label="l100r1", families=LORIS, health=self.out)
        with open(os.path.join(self.root, "index.jsonl"), "a", encoding="utf-8") as fh:   # the health phase changed
            fh.write(json.dumps({"phase": "health", "event": "started", "block": 9101, "attempt": 9}) + "\n")
        with self.assertRaisesRegex(R.PlanError, "health index digest does not match"):
            R.plan_block("ladder", 9101, self.root, sources={"loris": 100}, family="loris", label="l100r1", families=LORIS, health=self.out)

    def test_an_off_rule_health_step_is_refused_before_it_runs(self):
        # D-080 (T078-07): the first step runs at 0 halvings; a step at 1 is refused before it runs.
        with self.assertRaisesRegex(R.PlanError, r"health: the rule's next step runs at 0 halvings, not 1"):
            R.run_block(F.FakeHost(), R.plan_block("health", 9101, self.root, halvings=1, families=LORIS))
        self.assertFalse(os.path.exists(os.path.join(self.root, "health")), "nothing was started")
        self.health()                                                   # frozen at 0
        with self.assertRaisesRegex(R.PlanError, r"health: the rule is frozen .*no further step runs"):
            R.run_block(F.FakeHost(), R.plan_block("health", 9101, self.root, halvings=0, attempt=2, families=LORIS))

    def test_an_unsound_step_is_repeated_without_a_reason_asked(self):
        self.health(stack_ready=False)
        rc, rec, _said = self.read()
        self.assertEqual((rc, rec["decision"], rec["next_halvings"], rec["steps"][0]["sound"]), (0, "run", 0, False))
        self.health(attempt=2)
        self.assertEqual(self.read()[1]["benign_halvings"], 0)


def rec_dir(root):
    return min({x["block_dir"] for x in R.read_index(root) if x["phase"] == "health"})


class LadderControlTest(unittest.TestCase):
    """An unhealthy C inside the ladder is an unsound attempt, re-run with that reason; it never fires the rule."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def run_level(self, level, repeat, attackers=1, attempt=1, **host):
        block = R.plan_block("ladder", 9101, self.root, sources={"loris": level}, family="loris", label=f"l{level}r{repeat}",
                             families=LORIS, attempt=attempt)
        return R.run_block(F.FakeHost(modelled_attackers=attackers, **host), block)

    def test_the_repeat_reads_as_missing_until_it_is_re_run(self):
        self.run_level(100, 1, harm=lambda _t: True)
        self.run_level(100, 2)
        with self.assertRaisesRegex(ValueError, r"loris 100: repeat l100r1 .* no sound attempt.*its C was unhealthy \(D-073 \(3\)\)"):
            L.knees(self.root, R.PLACEHOLDER)
        self.run_level(100, 1, attempt=2)                                  # the unhealthy C is its reason (check_attempt)
        rec = L.knees(self.root, R.PLACEHOLDER)
        self.assertEqual(rec["levels"], {"loris": 100})
        # D-080 (T078-05): the superseded attempt 1, whose C was unhealthy, is listed too, with its reasons
        listed = [(c["label"], c["attempt"], bool(c["reasons"]), c["judged"]) for c in rec["controls"]]
        self.assertEqual(listed, [("l100r1", 2, False, True), ("l100r1", 1, True, False), ("l100r2", 1, False, True)])
        with self.assertRaisesRegex(R.PlanError, "allows no re-run"):
            self.run_level(100, 2, attempt=2)

    def test_a_ladder_c_is_re_run_for_an_unhealthy_c_at_most_max_reruns_times(self):
        # D-080 (T078-05): at most the record's gate.max_reruns (2) re-runs for an unhealthy C, then the repeat has no sound attempt.
        import l7_backend
        cap = l7_backend.load_record(R.PLACEHOLDER)[0]["gate"]["max_reruns"]
        self.assertEqual(cap, 2)
        for attempt in range(1, cap + 2):                   # attempts 1..cap+1, each C unhealthy, all allowed (cap re-runs)
            self.run_level(100, 1, harm=lambda _t: True, attempt=attempt)
        with self.assertRaisesRegex(R.PlanError, r"at most 2 re-runs for an unhealthy C \(D-080\); the repeat has no sound attempt"):
            self.run_level(100, 1, harm=lambda _t: True, attempt=cap + 2)
        with self.assertRaisesRegex(ValueError, "loris 100: repeat l100r1 .* no sound attempt"):
            L.knees(self.root, R.PLACEHOLDER)


if __name__ == "__main__":
    unittest.main()
