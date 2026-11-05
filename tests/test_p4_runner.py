"""The P4 runner (eval/p4_runner.py; docs/P4_SLOW_DESIGN.md §4.3, §8, §10, §13), offline: plans as data, and whole
blocks executed on the fake host of tests/p4_fake_host.py, whose outputs go through eval/p4_validation.py and
eval/p4_outcome.py unchanged. Nothing touches the machine."""
import contextlib
import gzip
import hashlib
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
import p4_outcome as OUT
import p4_runner as R
import p4_traffic as PT
import p4_validation as V

import slow_pc

KNEE = {"loris": 100, "post": 5}
POINT = (5, 256, 2)


def sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def index(root):
    return R.read_index(root)


def selection_file(where, point=POINT, sources=None, halvings=0, calibration=None):
    """The validation's record, as far as the runner reads it (eval/p4_validation.py --json)."""
    path = os.path.join(where, "selection.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"selection": {"point": list(point) if point else None}, "slow_pc_sha256": sha(os.path.join(REPO, "slow_pc.py")),
                   "settings": {"sources": {"loris": 0, "post": 0, **KNEE, **(sources or {})}, "halvings": halvings,
                                "calibration_sha256": sha(calibration or R.PLACEHOLDER)}}, fh)
    return path


class PlanTest(unittest.TestCase):
    def setUp(self):
        self.block = R.plan_block("campaign", 3101, "/r", sources=KNEE, thresholds=POINT)
        self.runs = {r["arm"]: r for r in self.block["runs"]}

    def test_the_nine_arms_in_a_seeded_order(self):
        self.assertEqual(len(self.block["order"]), 9)                     # with C_M, re-registered by D-041
        self.assertEqual(sorted(self.block["order"]), sorted(OUT.ARMS))
        self.assertEqual(self.block["order"], R.plan_block("campaign", 3101, "/x", sources=KNEE,
                                                           thresholds=POINT)["order"])
        orders = {tuple(R.plan_block("campaign", s, "/r", sources=KNEE, thresholds=POINT)["order"])
                  for s in OUT.BLOCK_SEEDS}
        self.assertGreater(len(orders), 1)
        self.assertEqual(self.block["dir"], "/r/campaign/b3101_a1")

    def test_nginx_and_the_daemon_per_arm(self):
        for arm, run in self.runs.items():
            conf = run["nginx"]["conf"]
            d = run["daemon"]
            if arm in ("C", "Cp") or arm.startswith("U_"):
                self.assertEqual((conf, d), ("nginx_profile_r.conf", None), arm)
                continue
            self.assertEqual(conf, "nginx_profile_r_limits.conf", arm)
            env = d["env"]
            self.assertEqual({k: env[k] for k in ("XDP_GRU", "GRU_ONLY", "L7_SHADOW", "MITIGATION_BACKEND",
                                                  "SLOW_PC_KILL_FILE")},
                             {"XDP_GRU": "0", "GRU_ONLY": "0", "L7_SHADOW": "0", "MITIGATION_BACKEND": "xdp",
                              "SLOW_PC_KILL_FILE": "/run/l7v2/kill"})
            self.assertEqual(env["BAN_EVENTS"], f"/r/campaign/b3101_a1/{arm}/ban_events.jsonl")
            self.assertEqual(d["argv"][:3], ["taskset", "-c", "2"])
            self.assertEqual(d["argv"][-1], os.path.join(REPO, "control_plane.py"))
            if arm.startswith("M_def_"):
                self.assertEqual((env["HEURISTIC_PROFILE"], env["SLOW_PC"]), ("default", "0"))
                self.assertNotIn("SLOW_PC_RECORD", env)
            else:
                self.assertEqual({k: env[k] for k in ("HEURISTIC_PROFILE", "SLOW_PC", "SLOW_PC_ENFORCE", "SLOW_PC_T",
                                                      "SLOW_PC_F", "SLOW_PC_K")},
                                 {"HEURISTIC_PROFILE": "tolerant", "SLOW_PC": "1", "SLOW_PC_ENFORCE": "1",
                                  "SLOW_PC_T": "5", "SLOW_PC_F": "256", "SLOW_PC_K": "2"})
                self.assertEqual(env["SLOW_PC_RECORD"], f"/r/campaign/b3101_a1/{arm}/slow_pc.jsonl.gz")
                self.assertTrue(run["enforcing"])

    def test_the_stack_on_cpus_0_1_and_its_provenance(self):
        for run in self.runs.values():
            g = run["gunicorn"]
            self.assertEqual(g["argv"][:3], ["taskset", "-c", "0-1"])
            self.assertEqual(g["argv"][-5:], ["gunicorn", "-c", os.path.join(REPO, "gunicorn_profile_r.py"),
                                              "--chdir", REPO])
            self.assertEqual(g["env"], {"L7_CALIBRATION": R.PLACEHOLDER})
            self.assertEqual(run["nginx"]["start"][:3], ["taskset", "-c", "0-1"])
            files = run["provenance"]["files_sha256"]
            self.assertEqual(files, {n: sha(os.path.join(REPO, n)) for n in ("nginx_profile_r.conf",
                                                                             "nginx_profile_r_limits.conf",
                                                                             "gunicorn_profile_r.py")})
            self.assertEqual(run["provenance"]["calibration"]["sha256"], sha(R.PLACEHOLDER))
            self.assertEqual(run["timeline"], {"baseline_s": 30, "attack_s": 210, "recovery_s": 30})

    def test_the_population_of_each_run(self):
        count = {arm: (sum(e["role"] == "benign" for e in r["entities"]),
                       sum(e["role"] == "attack" for e in r["entities"])) for arm, r in self.runs.items()}
        self.assertEqual(count["C"], (60, 0))
        self.assertEqual(count["Cp"], (60, 0))
        self.assertEqual(count["U_loris"], (60, 100))
        self.assertEqual(count["M_pc_post"], (60, 5))
        self.assertEqual(count["C_M"], (60, 0))
        loris = self.runs["U_loris"]
        self.assertEqual(loris["roles"], PT.roles(loris["entities"]))
        self.assertEqual(sorted(set(loris["roles"].values()) - {"attack"}),
                         ["api_bulk", "cgnat", "crawler_polite", "search_user", "slow_uploader", "tpcw_browsing",
                          "uploader"])
        for x in loris["launches"]:
            argv = x["argv"]
            self.assertEqual(argv[:3], ["taskset", "-c", "3-7"])
            self.assertEqual(argv[argv.index("--host") + 1], "10.0.0.1")
            e = next(e for e in loris["entities"] if e["entity_id"] == x["entity_id"])
            self.assertEqual(argv[argv.index("--source") + 1], e["address"])
            self.assertEqual(x["start_s"], 30.0 if e["role"] == "attack" else 0.0)
            self.assertEqual(float(argv[argv.index("--duration") + 1]), 210.0 if e["role"] == "attack" else 270.0)
            recorded = e["kind_or_family"] in ("tpcw_browsing", "cgnat_browsers", "search_user", "api_bulk",
                                               "crawler_polite")
            self.assertEqual("--records" in argv, recorded, e["kind_or_family"])
        slow = [n for n in loris["namespaces"] if n["profile"] == PT.NETEM_SLOW]
        self.assertEqual([len(n["addresses"]) for n in slow], [1, 1], "a qdisc per slow uploader (review T-047 P-12)")
        self.assertEqual(len({n["name"][:12] for n in loris["namespaces"]}), len(loris["namespaces"]), "the host's veth names")
        self.assertTrue(all(len(n["addresses"]) <= R.MAX_ALIASES for n in loris["namespaces"]))
        self.assertEqual(sum(len(n["addresses"]) for n in loris["namespaces"]), 160)

    def test_the_protected_control_is_m_pc_without_the_attack(self):
        cm, mpc, c = self.runs["C_M"], self.runs["M_pc_loris"], self.runs["C"]
        self.assertEqual((cm["nginx"]["conf"], cm["family"], cm["enforcing"], cm["thresholds"]),
                         ("nginx_profile_r_limits.conf", None, True, list(POINT)))
        arm_free = {k: v for k, v in cm["daemon"]["env"].items() if k not in ("BAN_EVENTS", "SLOW_PC_RECORD")}
        self.assertEqual(arm_free, {k: v for k, v in mpc["daemon"]["env"].items()
                                    if k not in ("BAN_EVENTS", "SLOW_PC_RECORD")})
        self.assertEqual(cm["entities"], c["entities"], "seeded with the block, the same benign population")
        self.assertEqual(cm["namespaces"], c["namespaces"])
        self.assertFalse([x for x in cm["launches"] if x["role"] == "attack"])

    def test_a_smoke_run_of_the_protected_control(self):
        block = R.plan_block("smoke", 9101, "/r", arms=["C_M"], thresholds=(20, 16, 6), label="s3")
        [run] = block["runs"]
        self.assertEqual((run["nginx"]["conf"], run["daemon"]["mode"], run["daemon"]["env"]["SLOW_PC_T"]),
                         ("nginx_profile_r_limits.conf", "pc", "20"))
        with self.assertRaises(R.PlanError):
            R.plan_block("smoke", 9101, "/r", arms=["C_M"])
        with self.assertRaises(R.PlanError):
            R.plan_block("smoke", 9101, "/r", arms=["C_M"], thresholds=(7, 16, 6))
        with self.assertRaises(R.PlanError):
            R.plan_block("validation", 4001, "/r", sources=KNEE, arms=["C_M"])

    def test_validation_and_ladder_runs(self):
        val = R.plan_block("validation", 4001, "/r", sources=KNEE)
        self.assertEqual(sorted(val["order"]), sorted(slow_pc.VALIDATION_RUNS))
        for run in val["runs"]:
            self.assertEqual(run["nginx"]["conf"], "nginx_profile_r.conf")
            env = run["daemon"]["env"]
            self.assertEqual((env["HEURISTIC_PROFILE"], env["SLOW_PC"], env["SLOW_PC_ENFORCE"]), ("tolerant", "1", "0"))
            self.assertIn("SLOW_PC_RECORD", env)
            self.assertFalse(run["enforcing"])
        lad = R.plan_block("ladder", 9102, "/r", sources={"loris": 0, "post": 20}, family="post", label="l20r1")
        self.assertEqual(sorted(lad["order"]), ["C", "U_post"])
        self.assertEqual(lad["dir"], "/r/ladder/b9102_a1_l20r1")
        u = next(r for r in lad["runs"] if r["arm"] == "U_post")
        self.assertEqual(sum(e["role"] == "attack" for e in u["entities"]), 20)
        self.assertTrue(all(r["daemon"] is None for r in lad["runs"]))

    def test_what_judges_data_is_refused_unless_frozen(self):
        bad = [lambda: R.plan_block("campaign", 3101, "/r", sources=KNEE),                     # no thresholds
               lambda: R.plan_block("campaign", 3101, "/r", sources=KNEE, thresholds=(7, 64, 2)),
               lambda: R.plan_block("campaign", 3101, "/r", sources={"loris": 120, "post": 5}, thresholds=POINT),
               lambda: R.plan_block("campaign", 4001, "/r", sources=KNEE, thresholds=POINT),
               lambda: R.plan_block("validation", 4001, "/r", sources=KNEE, thresholds=POINT),
               lambda: R.plan_block("validation", 3101, "/r", sources=KNEE),
               lambda: R.plan_block("ladder", 9101, "/r", sources=KNEE),                       # no family
               lambda: R.plan_block("ladder", 9101, "/r", sources={"loris": 99}, family="loris"),
               lambda: R.plan_block("smoke", 3101, "/r", sources=KNEE),
               lambda: R.plan_block("smoke", 9101, "/r", arms=["M_pc_loris"])]
        for make in bad:
            with self.assertRaises((R.PlanError, PT.PlanError)):
                make()

    def test_plan_prints_and_touches_nothing(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = R.main(["--phase", "campaign", "--seed", "3101", "--loris", "100", "--post", "5",
                         "--thresholds", "5,256,2", "--root", "/nonexistent/p4", "--plan"])
        self.assertEqual(rc, 0)
        text = out.getvalue()
        self.assertIn("P4 campaign block 3101 attempt 1", text)
        self.assertIn("run M_pc_loris: nginx nginx_profile_r_limits.conf, daemon pc", text)
        self.assertIn("SLOW_PC_ENFORCE=1", text)
        self.assertFalse(os.path.exists("/nonexistent/p4"))
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(R.main(["--phase", "campaign", "--seed", "3101", "--plan"]), 2)

    def test_stub_status_is_parsed(self):
        self.assertEqual(R.parse_stub_status(F.STUB.format(a=7, n=11, r=40, w=5)),
                         {"active": 7, "accepts": 11, "handled": 11, "requests": 40, "reading": 0, "writing": 2,
                          "waiting": 5})
        self.assertIsNone(R.parse_stub_status("502 Bad Gateway"))


class ArmOrderTest(unittest.TestCase):
    """Review T-047 P-13: the arm order is fixed by phase and seed; a label must not change it."""

    def test_a_label_is_refused_in_the_campaign_and_the_validation(self):
        with self.assertRaisesRegex(R.PlanError, "no --label"):
            R.plan_block("campaign", 3101, "/r", sources=KNEE, thresholds=POINT, label="x")
        with self.assertRaisesRegex(R.PlanError, "no --label"):
            R.plan_block("validation", 4001, "/r", sources=KNEE, label="x")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(R.main(["--phase", "campaign", "--seed", "3101", "--loris", "100", "--post", "5", "--thresholds",
                                     "5,256,2", "--label", "x", "--plan"]), 2)
        self.assertEqual(R.plan_block("smoke", 9101, "/r", label="s1", arms=["C"])["dir"], "/r/smoke/b9101_a1_s1")
        first = R.plan_block("campaign", 3101, "/r", sources=KNEE, thresholds=POINT)["order"]
        self.assertEqual(R.plan_block("campaign", 3101, "/r", sources=KNEE, thresholds=POINT, attempt=2)["order"], first)

    def test_summarize_refuses_another_order(self):
        with tempfile.TemporaryDirectory() as root:
            R.run_block(F.FakeHost(modelled_attackers=1),
                        R.plan_block("campaign", 3101, root, sources=KNEE, thresholds=POINT, arms=["C", "Cp", "U_post"],
                                     selection=selection_file(root)))
            path = os.path.join(root, "campaign", "b3101_a1", "block.json")
            with open(path, encoding="utf-8") as fh:
                meta = json.load(fh)
            meta["order"] = list(reversed(meta["order"]))
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(meta, fh)
            with self.assertRaisesRegex(ValueError, "seeded order"):
                R.summarize_root(root, R.PLACEHOLDER, os.path.join(root, "runs.jsonl"), dry_run=True)


class AttemptRuleTest(unittest.TestCase):
    """D-050 (review T-047 P-03): --attempt N needs a reason in the index, and the campaign holds 2 re-runs."""

    def row(self, arm, attempt=1, valid=True, block=3101, phase="campaign", label=""):
        return {"phase": phase, "block": block, "attempt": attempt, "label": label, "arm": arm, "valid": valid,
                "dir": f"{phase}/b{block}_a{attempt}/{arm}"}

    def full(self, attempt=1, block=3101, invalid=()):
        return [self.row(arm, attempt, arm not in invalid, block) for arm in OUT.ARMS]

    def check(self, rows, attempt=2, phase="campaign", seed=3101, reasons=(), **kw):
        kw = {"sources": KNEE, "thresholds": POINT, **kw} if phase == "campaign" else {"sources": KNEE, **kw}
        block = R.plan_block(phase, seed, "/nonexistent/root", attempt=attempt, **kw)
        with mock.patch.object(R, "read_index", return_value=rows), \
                mock.patch.object(R, "run_record", return_value={"control_reasons": list(reasons)}):
            R.check_attempt(block)

    def test_the_first_attempt_is_always_free_and_must_be_the_first(self):
        self.check([], attempt=1)
        with self.assertRaisesRegex(R.PlanError, "the next is 1"):
            self.check([], attempt=2)
        with self.assertRaisesRegex(R.PlanError, "the next is 2"):
            self.check(self.full(invalid=("C",)), attempt=3)
        self.check(self.full(block=3102), attempt=1)                              # another block's attempts are its own

    def test_a_complete_attempt_cannot_be_made_again(self):
        with self.assertRaisesRegex(R.PlanError, "allows no re-run"):
            self.check(self.full())

    def test_an_invalid_m_def_is_no_reason(self):
        with self.assertRaisesRegex(R.PlanError, "allows no re-run"):
            self.check(self.full(invalid=("M_def_loris", "M_def_post")))

    def test_an_invalid_or_missing_needed_arm_is_a_reason(self):
        for arm in OUT.NEEDED_ARMS:
            self.check(self.full(invalid=(arm,)))
        self.check([x for x in self.full() if x["arm"] != "U_post"])              # the runner died before it

    def test_an_unhealthy_c_is_a_reason(self):
        self.check(self.full(), reasons=["Q(C) is 98.00 %, below 99 %"])

    def test_the_campaign_holds_two_re_runs(self):
        two = self.full(block=3102) + self.full(2, 3102, ("C",)) + self.full(3, 3102)
        with self.assertRaisesRegex(R.PlanError, "already holds 2 re-runs"):
            self.check(two + self.full(invalid=("C",)))
        one = self.full(invalid=("C",), block=3103) + self.full(2, 3103)
        self.check(one + self.full(invalid=("C",)))

    def test_the_validation_needs_a_reason_too_and_the_smoke_does_not(self):
        rows = [self.row(arm, phase="validation", block=4001) for arm in slow_pc.VALIDATION_RUNS]
        with self.assertRaisesRegex(R.PlanError, "allows no re-run"):
            self.check(rows, phase="validation", seed=4001)
        rows[0] = dict(rows[0], valid=False)
        self.check(rows, phase="validation", seed=4001)
        block = R.plan_block("smoke", 9101, "/nonexistent/root", attempt=2, label="s1", arms=["C"])
        with mock.patch.object(R, "read_index", return_value=[self.row("C", phase="smoke", block=9101, label="s1")]):
            R.check_attempt(block)

    def test_the_command_line_says_no(self):
        with tempfile.TemporaryDirectory() as root, contextlib.redirect_stderr(io.StringIO()) as err, \
                contextlib.redirect_stdout(io.StringIO()):
            rc = R.main(["--phase", "campaign", "--seed", "3101", "--loris", "100", "--post", "5", "--thresholds", "5,256,2",
                         "--attempt", "2", "--root", root], host=F.FakeHost())
        self.assertEqual(rc, 2)
        self.assertIn("the next is 1", err.getvalue())


class HostThatMeasures(F.FakeHost):
    """The fake's model under a host that says it measures: what the frozen rule sees of a real one."""
    simulated = False


def frozen_record(where, name="frozen.json"):
    """A synthetic frozen record (tests/calibration_fixtures.py); the real one is not this branch's to commit (D-061)."""
    import calibration as CAL
    import calibration_fixtures
    path = os.path.join(where, name)
    CAL.dump(calibration_fixtures.frozen(), path)
    return path


class FrozenRecordTest(unittest.TestCase):
    """T-052b, the rule of eval/harm_gate.py and eval/l7v2_harm.py: no campaign and no verdict on a record that is not frozen."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        self.frozen = frozen_record(self.root)

    def campaign(self, seed=3101, arms=("C", "U_post"), **kw):
        kw.setdefault("calibration", self.frozen)
        if "selection" not in kw:
            kw["selection"] = selection_file(self.root, calibration=kw["calibration"])
        return R.plan_block("campaign", seed, self.root, sources=KNEE, thresholds=POINT, arms=list(arms), **kw)

    def test_a_campaign_on_a_host_that_measures_refuses_the_placeholder_before_anything_runs(self):
        host = HostThatMeasures()
        with self.assertRaisesRegex(R.PlanError, "no verdict is given on it"):
            R.run_block(host, self.campaign(calibration=R.PLACEHOLDER))
        self.assertEqual((host.commands, host.prims, host.procs), ([], [], []))
        self.assertFalse(os.path.exists(os.path.join(self.root, "campaign")))
        self.assertFalse(os.path.exists(os.path.join(self.root, "index.jsonl")))

    def test_a_measured_record_is_refused_as_well(self):
        import l7_backend
        with mock.patch.object(l7_backend, "load_record", return_value=({"status": "measured"}, "measured", "measured:x")), \
                self.assertRaisesRegex(R.PlanError, "no verdict is given on it"):
            R.check_frozen({"phase": "campaign", "calibration": "m.json"}, HostThatMeasures())

    def test_the_command_line_refuses_the_default_record(self):
        with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            rc = R.main(["--phase", "campaign", "--seed", "3101", "--loris", "100", "--post", "5", "--thresholds", "5,256,2",
                         "--selection", selection_file(self.root), "--root", self.root], host=HostThatMeasures())
        self.assertEqual(rc, 2)
        self.assertIn("no verdict is given on it", err.getvalue())
        self.assertIn("NOT FROZEN: a real host refuses this campaign", out.getvalue())

    def test_a_frozen_record_runs_and_its_verdict_is_given(self):
        res = R.run_block(HostThatMeasures(modelled_attackers=1), self.campaign())
        self.assertTrue(all(r["ok"] for _a, r in res), res)
        out = os.path.join(self.root, "runs.jsonl")
        R.summarize_root(self.root, self.frozen, out)
        with open(out, encoding="utf-8") as fh:
            records = [json.loads(line) for line in fh]
        self.assertEqual({r["settings"]["calibration_status"] for r in records}, {"frozen"})
        verdict = OUT.outcome(records)
        self.assertEqual((verdict["dry_run"], verdict["calibration"]["status"]), (False, "frozen"))
        self.assertEqual(verdict["calibration"]["sha256"], sha(self.frozen))

    def test_a_simulated_campaign_needs_no_frozen_record_and_is_labelled(self):
        R.run_block(F.FakeHost(modelled_attackers=1), self.campaign(calibration=R.PLACEHOLDER))
        out = os.path.join(self.root, "runs.jsonl")
        with self.assertRaisesRegex(ValueError, "no verdict is given on it"):
            R.summarize_root(self.root, R.PLACEHOLDER, out)
        R.summarize_root(self.root, R.PLACEHOLDER, out, dry_run=True)
        with open(out, encoding="utf-8") as fh:
            records = [json.loads(line) for line in fh]
        with self.assertRaisesRegex(ValueError, "no verdict is given on it"):
            OUT.outcome(records)
        self.assertTrue(OUT.outcome(records, dry_run=True)["dry_run"])

    def test_summarize_on_the_command_line(self):
        R.run_block(F.FakeHost(modelled_attackers=1), self.campaign(calibration=R.PLACEHOLDER))
        out = os.path.join(self.root, "runs.jsonl")
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(R.main(["--summarize", self.root, out]), 2)
        self.assertIn("no verdict is given on it", err.getvalue())
        self.assertEqual(R.main(["--summarize", self.root, out, "--dry-run"]), 0)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            R.main(["--phase", "campaign", "--seed", "3101", "--dry-run"])

    def test_smoke_ladder_and_validation_may_name_any_record_and_say_which(self):
        for phase, seed, kw in (("smoke", 9101, {"arms": ["C"], "label": "s"}), ("validation", 4001, {"sources": KNEE}),
                                ("ladder", 9102, {"sources": {"post": 20}, "family": "post", "label": "l"})):
            for path, status in ((R.PLACEHOLDER, "placeholder"), (self.frozen, "frozen")):
                root = os.path.join(self.root, f"{phase}_{status}")
                os.makedirs(root)
                host = HostThatMeasures(modelled_attackers=1)
                block = R.plan_block(phase, seed, root, calibration=path, **kw)
                R.run_block(host, block)
                with open(os.path.join(block["dir"], "block.json"), encoding="utf-8") as fh:
                    settings = json.load(fh)["settings"]
                self.assertEqual((settings["calibration_status"], settings["calibration_sha256"]), (status, sha(path)), phase)
                with open(os.path.join(block["runs"][0]["out"], "run.json"), encoding="utf-8") as fh:
                    self.assertEqual(json.load(fh)["provenance"]["calibration"]["sha256"], sha(path))
                self.assertTrue(host.procs, "it ran")

    def test_a_validation_under_another_record_cannot_feed_the_campaign(self):
        """T-052 (1)'s check holds this already: the frozen rule makes it a dead end, so the plan says so before the VM hours."""
        block = self.campaign(selection=selection_file(self.root, calibration=R.PLACEHOLDER))
        with self.assertRaisesRegex(R.PlanError, "calibration_sha256 differ"):
            R.run_block(HostThatMeasures(), block)
        text = R.describe(R.plan_block("validation", 4001, self.root, sources=KNEE))
        self.assertIn("(placeholder)", text)
        self.assertIn("NOT FROZEN: no campaign can follow this validation", text)
        self.assertNotIn("NOT FROZEN", R.describe(R.plan_block("validation", 4001, self.root, sources=KNEE, calibration=self.frozen)))
        self.assertNotIn("NOT FROZEN", R.describe(R.plan_block("smoke", 9101, self.root, arms=["C"])))

    def test_a_record_that_cannot_be_read_is_refused_at_the_plan(self):
        with self.assertRaisesRegex(R.PlanError, "the calibration record"):
            R.plan_block("smoke", 9101, self.root, arms=["C"], calibration=os.path.join(self.root, "absent.json"))
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            rc = R.main(["--phase", "smoke", "--seed", "9101", "--arms", "C", "--calibration", os.path.join(self.root, "absent.json"), "--plan"])
        self.assertEqual(rc, 2)
        self.assertIn("the calibration record", err.getvalue())


class SelectionTest(unittest.TestCase):
    """§13 row 4 (review T-047 P-08): the campaign runs what the validation chose, and nothing else that is on the grid."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def refused(self, why, **kw):
        kw = {"sources": KNEE, "thresholds": POINT, "arms": ["C"], **kw}
        with self.assertRaisesRegex(R.PlanError, why):
            R.run_block(F.FakeHost(), R.plan_block("campaign", 3101, self.root, **kw))
        self.assertFalse(os.path.exists(os.path.join(self.root, "campaign")), "nothing was started")

    def test_a_campaign_needs_it_and_a_plan_does_not(self):
        self.refused("--selection must name")
        self.assertIn("order", R.plan_block("campaign", 3101, self.root, sources=KNEE, thresholds=POINT))

    def test_only_the_campaign_takes_it(self):
        with self.assertRaisesRegex(R.PlanError, "the campaign's"):
            R.plan_block("validation", 4001, self.root, sources=KNEE, selection="x.json")

    def test_another_point_of_the_grid_is_refused(self):
        self.refused("are not the validation's selection", selection=selection_file(self.root, (20, 16, 6)))

    def test_a_validation_that_chose_nothing_ends_it(self):
        path = selection_file(self.root)
        with open(path, encoding="utf-8") as fh:
            sel = json.load(fh)
        sel["selection"]["point"] = None
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(sel, fh)
        self.refused("chose no point", selection=path)

    def test_another_detector_is_refused(self):
        path = selection_file(self.root)
        with open(path, encoding="utf-8") as fh:
            sel = json.load(fh)
        sel["slow_pc_sha256"] = "0" * 64
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(sel, fh)
        self.refused("another slow_pc.py", selection=path)

    def test_another_scale_halving_count_or_calibration_is_refused(self):
        self.refused("sources differ", selection=selection_file(self.root, sources={"loris": 175}))
        self.refused("halvings differ", selection=selection_file(self.root, halvings=1))
        other = os.path.join(self.root, "other.json")
        with open(R.PLACEHOLDER, encoding="utf-8") as fh, open(other, "w", encoding="utf-8") as out:
            out.write(fh.read() + "\n")
        self.refused("calibration_sha256 differ", selection=selection_file(self.root, calibration=other))

    def test_an_unreadable_record_is_refused(self):
        self.refused("is not a record", selection=os.path.join(self.root, "absent.json"))
        path = os.path.join(self.root, "garbled.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("{}")
        self.refused("is not a record", selection=path)

    def test_the_block_names_it_so_a_campaign_holds_one(self):
        host = F.FakeHost()
        path = selection_file(self.root)
        R.run_block(host, R.plan_block("campaign", 3101, self.root, sources=KNEE, thresholds=POINT, arms=["C"], selection=path))
        with open(os.path.join(self.root, "campaign", "b3101_a1", "block.json"), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["settings"]["selection_sha256"], sha(path))
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("\n")
        with self.assertRaisesRegex(R.PlanError, "selection_sha256"):
            R.run_block(host, R.plan_block("campaign", 3102, self.root, sources=KNEE, thresholds=POINT, arms=["C"], selection=path))

    def test_the_command_line_carries_it(self):
        base = ["--phase", "campaign", "--seed", "3101", "--loris", "100", "--post", "5", "--thresholds", "5,256,2", "--root", self.root]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(R.main(base, host=F.FakeHost()), 2)
        self.assertIn("--selection must name", err.getvalue())
        path = selection_file(self.root, sources={"loris": 100, "post": 5})
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(R.main([*base, "--selection", path, "--plan"], host=F.FakeHost()), 0)
        self.assertIn(f"selection {path}", out.getvalue())


class ViewSlipTest(unittest.TestCase):
    """Review T-050, post-verdict: the slip reads the client's own lateness and not the server's slowness, or a reason on it would
    make the harm itself invalid, the trap of stub_status (D-050)."""

    def setUp(self):
        self.planned = {(0, 0): (0.0, ["C0"], 5.0), (0, 1): (5.0, ["C0"], 5.0), (0, 2): (10.0, ["C0"], 5.0)}

    def row(self, view, sent, done):
        return {"user": 0, "view": view, "t_sent": sent, "t_done": done}

    def test_a_device_on_its_schedule(self):
        rows = [self.row(0, 100.0, 100.1), self.row(1, 105.1, 105.2), self.row(2, 110.2, 110.3)]
        slips = R.view_slips(rows, self.planned, 100.0, 370.0)
        self.assertEqual(sorted(slips), [(0, 0), (0, 1), (0, 2)])
        self.assertAlmostEqual(max(slips.values()), 0.0, places=6)

    def test_a_slow_or_refusing_server_is_no_slip(self):
        rows = [self.row(0, 100.0, 140.0), self.row(1, 145.0, 145.1), self.row(2, 150.1, 150.2)]    # 40 s to answer the first view
        self.assertAlmostEqual(max(R.view_slips(rows, self.planned, 100.0, 370.0).values()), 0.0, places=6)

    def test_a_stall_slips_the_view_after_it_and_no_other(self):
        rows = [self.row(0, 100.0, 100.1), self.row(1, 136.3, 136.4), self.row(2, 141.4, 141.5)]    # its 5-s sleep took 36.2 s
        slips = R.view_slips(rows, self.planned, 100.0, 370.0)
        self.assertAlmostEqual(slips[(0, 1)], 31.2, places=6)
        self.assertAlmostEqual(slips[(0, 2)], 0.0, places=6)

    def test_a_stall_to_the_end_is_late_by_what_was_left(self):
        slips = R.view_slips([self.row(0, 100.0, 100.1)], self.planned, 100.0, 130.0)
        self.assertAlmostEqual(slips[(0, 1)], 24.9, places=6)

    def test_a_view_left_unfinished_at_the_end_is_no_stall(self):
        """A banned device hangs in a view until its generator ends: the views after it were never due, or T050-16 returns by this door."""
        planned = {(0, 0): (0.0, ["C0", "C1"], 5.0), (0, 1): (5.0, ["C0"], 5.0), (0, 2): (10.0, ["C0"], 5.0)}
        slips = R.view_slips([self.row(0, 100.0, 110.0)], planned, 100.0, 170.0)
        self.assertEqual(sorted(slips), [(0, 0)])
        self.assertLess(slips[(0, 0)], R.STALL_BOUND_S)

    def test_a_view_due_after_the_end_is_not_late(self):
        self.assertEqual(sorted(R.view_slips([self.row(0, 100.0, 100.1)], self.planned, 100.0, 104.0)), [(0, 0)])


class ExecuteTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def block(self, phase, seed, **kw):
        kw.setdefault("sources", KNEE)
        if phase == "campaign":
            kw.setdefault("selection", selection_file(self.root, kw.get("thresholds"), kw["sources"], kw.get("halvings", 0),
                                                      kw.get("calibration")))
        return R.plan_block(phase, seed, self.root, **kw)

    def test_validation_runs_feed_p4_validation_unchanged(self):
        manifests = []
        for seed in slow_pc.VALIDATION_SEEDS:
            host = F.FakeHost(poll_every_s=5.0, modelled_attackers=4)
            res = R.run_block(host, self.block("validation", seed))
            self.assertTrue(all(r["ok"] for _a, r in res), res)
            bdir = os.path.join(self.root, "validation", f"b{seed}_a1")
            manifests += [os.path.join(bdir, arm, "slow_pc_manifest.json") for arm in slow_pc.VALIDATION_RUNS]
        with open(manifests[0], encoding="utf-8") as fh:
            m = json.load(fh)
        self.assertEqual((m["record"], m["daemon"]), ("slow_pc.jsonl.gz", {"HEURISTIC_PROFILE": "tolerant",
                                                                           "SLOW_PC": "1", "SLOW_PC_ENFORCE": "0"}))
        out = os.path.join(self.root, "selection.json")
        with contextlib.redirect_stdout(io.StringIO()):
            rc = V.main([self.root, "--json", out])
        with open(out, encoding="utf-8") as fh:
            sel = json.load(fh)
        self.assertIn(rc, (0, 2))
        self.assertEqual(len(sel["outcomes"]), len(slow_pc.GRID))
        self.assertEqual({a["judged"] for a in sel["attempts"]}, {1})
        self.assertEqual(sel["settings"]["sources"], {"loris": 100, "post": 5})
        self.assertEqual(sorted((r["seed"], r["arm"]) for r in sel["runs"]),
                         sorted((s, a) for s in slow_pc.VALIDATION_SEEDS for a in slow_pc.VALIDATION_RUNS))
        point = next(o for o in sel["outcomes"] if (o["T"], o["F"], o["K"]) == POINT)
        self.assertEqual(point["attack_addresses"], 2 * (4 + 4))       # 4 modelled sources per family and seed
        self.assertEqual(point["slow_uploader_closed"], 0)
        self.assertGreater(point["benign_connections"], 0)
        chosen = tuple(sel["selection"]["point"])                       # the validation's own record opens the campaign
        self.assertNotEqual(chosen, POINT)
        res = R.run_block(F.FakeHost(), R.plan_block("campaign", 3101, self.root, sources=KNEE, thresholds=chosen, arms=["C"],
                                                     selection=out))
        self.assertTrue(res[0][1]["ok"], res)
        with self.assertRaisesRegex(R.PlanError, "are not the validation's selection"):
            R.run_block(F.FakeHost(), R.plan_block("campaign", 3102, self.root, sources=KNEE, thresholds=POINT, arms=["C"],
                                                   selection=out))

    def test_a_campaign_block_feeds_p4_outcome_unchanged(self):
        host = F.FakeHost(modelled_attackers=6)
        res = R.run_block(host, self.block("campaign", 3101, thresholds=POINT))
        self.assertEqual([a for a, _r in res], R.plan_block("campaign", 3101, "/x", sources=KNEE,
                                                            thresholds=POINT)["order"])
        self.assertTrue(all(r["ok"] for _a, r in res), [(a, r["reasons"]) for a, r in res if not r["ok"]])
        runs_path = os.path.join(self.root, "runs.jsonl")
        R.summarize_root(self.root, R.PLACEHOLDER, runs_path, dry_run=True)
        with open(runs_path, encoding="utf-8") as fh:
            records = [json.loads(line) for line in fh]
        by = {r["arm"]: r for r in records}
        self.assertEqual(sorted(by), sorted(OUT.ARMS))
        self.assertTrue(all(len(r["q_per_s"]) == 270 and r["level_window"] == [120.0, 240.0] for r in records))
        self.assertGreater(by["C"]["Q"], by["U_loris"]["Q"])
        self.assertEqual((by["C"]["control_reasons"], by["U_loris"]["control_reasons"]), ([], None))
        self.assertEqual(set(by["M_pc_loris"]["banned"].values()), {"attack"})
        self.assertEqual(by["M_def_loris"]["banned"], {})
        self.assertGreater(by["M_pc_loris"]["q_level"], by["U_loris"]["q_level"])
        out = os.path.join(self.root, "verdict.json")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(OUT.main([runs_path, "--json", out, "--dry-run"]), 0)
        with open(out, encoding="utf-8") as fh:
            verdict = json.load(fh)
        self.assertEqual(verdict["M7"], "invalid (1 of 10 valid)")    # one block of the ten (D-035, V-02)
        self.assertEqual(verdict["families"]["loris"]["harm"]["valid_blocks"], 1)
        self.assertEqual(verdict["bans_by_arm"]["M_pc_loris"], {"attack": 6})
        idx = index(self.root)
        self.assertEqual([(x["arm"], x["valid"]) for x in idx], [(a, True) for a, _r in res])

    def test_the_runner_keeps_off_the_servers_and_the_daemons_cpus(self):
        """Review T-050 T050-17: pinned before it starts anything, and recorded."""
        host = F.FakeHost()
        block = self.block("smoke", 9101, arms=["C"], label="pin", sources={"loris": 0, "post": 0})
        R.run_block(host, block)
        self.assertEqual(host.commands[0], ("", ("pin", "3-7"), ""))
        self.assertEqual(block["runs"][0]["provenance"]["pins"]["runner"], "3-7")
        self.assertEqual((R.PINS["runner"], R.PINS["clients"], R.PINS["server"], R.PINS["daemon"]), ("3-7", "3-7", "0-1", "2"))

    def test_what_a_run_writes(self):
        host = F.FakeHost(modelled_attackers=2)
        R.run_block(host, self.block("campaign", 3102, thresholds=POINT, arms=None))
        run = os.path.join(self.root, "campaign", "b3102_a1", "M_pc_post")
        for name in ("plan.json", "run.json", "manifest.json", "slow_pc_manifest.json", "slow_pc.jsonl.gz",
                     "ban_events.jsonl", "daemon.log", "gunicorn.log", "stub_status.jsonl"):
            self.assertTrue(os.path.isfile(os.path.join(run, name)), name)
        with open(os.path.join(run, "run.json"), encoding="utf-8") as fh:
            meta = json.load(fh)
        self.assertEqual((meta["role"], meta["class"], meta["thresholds"]), ("mitigated", "post", list(POINT)))
        with open(os.path.join(self.root, "campaign", "b3102_a1", "C_M", "run.json"), encoding="utf-8") as fh:
            cm = json.load(fh)
        self.assertEqual((cm["role"], cm["class"], cm["thresholds"], cm["checks"]["ok"]),
                         ("protected_control", None, list(POINT), True))
        with open(os.path.join(run, "manifest.json"), encoding="utf-8") as fh:
            man = json.load(fh)
        self.assertGreater(man["timeline"]["t0_wall"], F.BASE_EPOCH)
        self.assertEqual(set(man["ip_map"]), set(man["roles"]))
        with gzip.open(os.path.join(run, "slow_pc.jsonl.gz"), "rt", encoding="utf-8") as fh:
            first = json.loads(fh.readline())
        self.assertTrue(first["enforce"])
        with open(os.path.join(run, "stub_status.jsonl"), encoding="utf-8") as fh:
            stub = [json.loads(line) for line in fh]
        self.assertGreaterEqual(len(stub), 270)
        self.assertIn("waiting", stub[0])
        self.assertTrue(host.ran("ip", "netns", "del", "server_ns"))
        moved = [c[1] for c in host.ran("mv", "-f")]
        self.assertIn(("mv", "-f", "/var/log/nginx/l7_capture.log", os.path.join(run, "access.log")), moved)
        slow_ns = [c for c in host.commands if c[1][:2] == ("tc", "qdisc")]
        self.assertTrue(slow_ns and all(c[1] == PT.NETEM_SLOW_ARGV for c in slow_ns))
        self.assertEqual(len({c[0] for c in slow_ns}), 2, "one namespace each")

    def test_every_attempt_is_indexed_with_its_reasons(self):
        host = F.FakeHost(kill_file=True, modelled_attackers=1)
        res = dict(R.run_block(host, self.block("campaign", 3103, thresholds=POINT)))
        for arm in OUT.ARMS:
            self.assertEqual(res[arm]["ok"], not (arm.startswith("M_pc_") or arm == "C_M"), arm)
        self.assertIn("the kill file /run/l7v2/kill exists", res["M_pc_loris"]["reasons"][0])
        idx = index(self.root)
        self.assertEqual(len(idx), 9)
        self.assertEqual({x["arm"] for x in idx if not x["valid"]}, {"M_pc_loris", "M_pc_post", "C_M"})
        with self.assertRaisesRegex(R.PlanError, "the next is 2"):
            R.run_block(F.FakeHost(), self.block("campaign", 3103, thresholds=POINT))
        R.run_block(F.FakeHost(modelled_attackers=1), self.block("campaign", 3103, thresholds=POINT, attempt=2))
        self.assertEqual(len(index(self.root)), 18)
        self.assertEqual({x["attempt"] for x in index(self.root)}, {1, 2})
        out = os.path.join(self.root, "runs.jsonl")
        R.summarize_root(self.root, R.PLACEHOLDER, out, dry_run=True)                       # D-035 (V-03): every attempt, valid or not
        with open(out, encoding="utf-8") as fh:
            records = [json.loads(line) for line in fh]
        self.assertEqual(sorted((r["attempt"], r["arm"]) for r in records),
                         sorted((a, arm) for a in (1, 2) for arm in OUT.ARMS))
        refused = [r for r in records if r["attempt"] == 1 and r["arm"].startswith("M_pc_")]
        self.assertTrue(all(not r["valid"] and r["Q"] is None for r in refused))
        verdict = OUT.outcome(records, dry_run=True)
        self.assertEqual(verdict["families"]["loris"]["mitigation"]["attempts"], 2)

    def one_run(self, name, phase="validation", seed=4002, arm="C", **kw):
        kw.setdefault("sources", KNEE)
        block = R.plan_block(phase, seed, os.path.join(self.root, name), **kw)
        return next(r for r in block["runs"] if r["arm"] == arm)

    def test_failures_make_a_run_invalid_and_the_testbed_is_taken_down(self):
        cases = {
            "daemon dies": (F.FakeHost(daemon_dies_at=100.0, modelled_attackers=1), "the daemon exited"),
            "stack": (F.FakeHost(stack_ready=False), "did not answer"),
            "leftovers": (F.FakeHost(netns=["server_ns"]), "leftover namespaces"),
            "not root": (F.FakeHost(root=False), "not root"),
            "topology": (F.FakeHost(fail_prim="client_ns"), "the runner failed: OSError"),
        }
        for name, (host, why) in cases.items():
            res = R.execute_run(host, self.one_run(name.replace(" ", "_")))
            self.assertFalse(res["ok"], name)
            self.assertTrue(any(why in r for r in res["reasons"]), (name, res["reasons"]))
            if name in ("leftovers", "not root"):
                self.assertFalse(host.ran("ip", "netns", "del"), name)
            else:
                self.assertTrue(host.ran("ip", "netns", "del", "server_ns"), name)
        res = R.execute_run(F.FakeHost(kill_appears_at=100.0, modelled_attackers=1),
                            self.one_run("kill_mid", "campaign", 3104, "M_pc_loris", thresholds=POINT))
        self.assertTrue(any("the kill file appeared at 100 s" in r for r in res["reasons"]), res["reasons"])
        run = self.one_run("gen_fails")
        bad = next(e["address"] for e in run["entities"] if e["kind_or_family"] == "uploader")
        res = R.execute_run(F.FakeHost(gen_fails=[bad], modelled_attackers=1), run)
        self.assertTrue(any("exited with code 3" in r for r in res["reasons"]), res["reasons"])

    def test_the_rule_must_poll_at_least_every_10_s(self):
        """D-035 (V-08): an M_pc (or validation) run whose rule logged no poll for more than 10 s is invalid."""
        self.assertEqual(R.SLOW_PC_POLL_GAP_S, 10.0)
        for every, ok in ((5.0, True), (9.5, True), (10.5, False), (15.0, False)):
            run = self.one_run(f"poll_{every}", "campaign", 3105, "M_pc_post", thresholds=POINT)
            res = R.execute_run(F.FakeHost(poll_every_s=every, modelled_attackers=1), run)
            silent = [r for r in res["reasons"] if "no successful poll" in r]
            self.assertEqual(not silent, ok, (every, res["reasons"]))
        res = R.execute_run(F.FakeHost(daemon_dies_at=150.0, modelled_attackers=1),
                            self.one_run("dies", "validation", 4001, "C"))
        self.assertTrue(any("no successful poll" in r for r in res["reasons"]), res["reasons"])
        res = R.execute_run(F.FakeHost(poll_every_s=30.0), self.one_run("no_rule", "campaign", 3105, "M_def_post",
                                                                        thresholds=POINT))
        self.assertFalse(any("no successful poll" in r for r in res["reasons"]), "M_def runs no rule")


    def test_the_limits_own_cost_comes_from_the_access_log(self):
        host = F.FakeHost(modelled_attackers=2, limit_refuses=0.2)
        res = R.run_block(host, self.block("campaign", 3106, thresholds=POINT))
        self.assertTrue(all(r["ok"] for _a, r in res), [(a, r["reasons"]) for a, r in res if not r["ok"]])
        out = os.path.join(self.root, "runs.jsonl")
        R.summarize_root(self.root, R.PLACEHOLDER, out, dry_run=True)
        with open(out, encoding="utf-8") as fh:
            by = {r["arm"]: r for r in map(json.loads, fh)}
        self.assertEqual(sum(c["refused"] for c in by["C"]["refused"]["by_role"].values()), 0)
        refused = by["C_M"]["refused"]
        self.assertGreater(refused["by_role"]["cgnat"]["refused"], 0)
        self.assertEqual({r for r, c in refused["by_role"].items() if c["refused"]}, {"cgnat"})
        self.assertEqual({"uploader", "slow_uploader"} - set(refused["by_role"]), set())
        self.assertEqual(sorted(refused["cgnat"]), ["CGNAT-12", "CGNAT-24"])
        self.assertTrue(all(c["refused"] > 0 for c in refused["cgnat"].values()))
        self.assertLessEqual(by["C_M"]["Q"], by["C"]["Q"])
        cost = OUT.outcome(list(by.values()), dry_run=True)["limits_cost"]
        self.assertEqual([r["block"] for r in cost["blocks"]], [3106])
        self.assertEqual(cost["blocks"][0]["refused_C"], 0)
        self.assertEqual(cost["refused_cgnat"].keys(), {"CGNAT-12", "CGNAT-24"})

    def test_refusals_reads_the_log_by_label_and_window(self):
        man = {"timeline": {"t0_wall": 1000.0}, "roles": {"10.0.17.3": "cgnat", "10.0.16.5": "search_user"},
               "entities": [{"address": "10.0.17.3", "kind_or_family": "cgnat_browsers", "params": {"users": 24}},
                            {"address": "10.0.16.5", "kind_or_family": "search_user", "params": {}}]}
        lines = [{"msec": 1050.5, "rt": 0.5, "ip": "10.0.17.3", "status": 503},
                 {"msec": 1051.0, "rt": 0.5, "ip": "10.0.17.3", "status": 200},
                 {"msec": 1051.0, "rt": 0.5, "ip": "10.0.16.5", "status": 429},
                 {"msec": 1010.0, "rt": 0.0, "ip": "10.0.17.3", "status": 503},    # before the window
                 {"msec": 1240.1, "rt": 0.0, "ip": "10.0.17.3", "status": 503},    # after it
                 {"msec": 1100.0, "rt": 0.1, "ip": "10.9.9.9", "status": 503}]     # no label
        path = os.path.join(self.root, "access.log")
        with open(path, "w", encoding="utf-8") as fh:
            fh.writelines(json.dumps(x) + "\n" for x in lines)
            fh.write("not json\n")
        got = R.refusals(path, man, (30, 240))
        self.assertEqual(got["by_role"], {"cgnat": {"requests": 2, "refused": 1},
                                          "search_user": {"requests": 1, "refused": 1},
                                          "unlabelled": {"requests": 1, "refused": 1}})
        self.assertEqual(got["cgnat"], {"CGNAT-24": {"address": "10.0.17.3", "requests": 2, "refused": 1}})


    def test_an_unhealthy_control_is_judged_when_the_records_are_made(self):
        """D-046: every request fails in this fake run. Its C is sound as a run and is not healthy."""
        res = dict(R.run_block(F.FakeHost(harm=lambda _t: True, modelled_attackers=1),
                               self.block("campaign", 3107, thresholds=POINT)))
        self.assertTrue(res["C"]["ok"], res["C"]["reasons"])
        out = os.path.join(self.root, "runs.jsonl")
        R.summarize_root(self.root, R.PLACEHOLDER, out, dry_run=True)
        with open(out, encoding="utf-8") as fh:
            by = {r["arm"]: r for r in map(json.loads, fh)}
        self.assertTrue(by["C"]["valid"])
        self.assertIn("below 99 %", by["C"]["control_reasons"][0])
        verdict = OUT.outcome(list(by.values()), dry_run=True)
        self.assertEqual(verdict["families"]["loris"]["harm"]["valid_blocks"], 0)
        self.assertEqual(verdict["M7"], "invalid (0 of 10 valid)")
        self.assertEqual([u["block"] for u in verdict["unhealthy_controls"]], [3107])


    def test_a_mid_life_stall_leaves_a_reason_in_run_json(self):
        """Review T-050, post-verdict: a generator's end is absolute, so a stall at 100 s only lost views, booked in Q with no reason."""
        run = self.one_run("stall", "campaign", 3106, "C", thresholds=POINT)
        device = next(e for e in run["entities"] if e["kind_or_family"] == "tpcw_browsing")
        res = R.execute_run(F.FakeHost(gen_stall={device["address"]: (100.0, 31.2)}), run)
        self.assertFalse(res["ok"])
        self.assertTrue(any("a client stalled" in r and device["entity_id"] in r for r in res["reasons"]), res["reasons"])
        with open(os.path.join(run["out"], "run.json"), encoding="utf-8") as fh:
            meta = json.load(fh)
        self.assertEqual(meta["checks"]["reasons"], res["reasons"])
        self.assertGreater(meta["stall"]["largest_view_slip_s"], 20.0)
        self.assertGreaterEqual(meta["stall"]["views_over_bound"], 1)
        self.assertEqual(meta["stall"]["entity"], device["entity_id"])

    def test_a_short_stall_is_read_and_is_no_reason(self):
        run = self.one_run("short", "campaign", 3106, "C", thresholds=POINT)
        device = next(e for e in run["entities"] if e["kind_or_family"] == "tpcw_browsing")
        res = R.execute_run(F.FakeHost(gen_stall={device["address"]: (100.0, 3.0)}), run)
        self.assertEqual(res["reasons"], [])
        with open(os.path.join(run["out"], "run.json"), encoding="utf-8") as fh:
            stall = json.load(fh)["stall"]
        self.assertGreater(stall["largest_view_slip_s"], 1.0)
        self.assertEqual(stall["views_over_bound"], 0)

    def test_a_healthy_run_reads_no_slip_and_the_harm_is_no_stall(self):
        for harm in (None, lambda _t: True):
            run = self.one_run(f"healthy_{harm is None}", "campaign", 3106, "U_loris", thresholds=POINT)
            self.assertEqual(R.execute_run(F.FakeHost(harm=harm, modelled_attackers=1), run)["reasons"], [])
            with open(os.path.join(run["out"], "run.json"), encoding="utf-8") as fh:
                stall = json.load(fh)["stall"]
            self.assertLess(stall["largest_view_slip_s"], 1.0)
            self.assertGreater(stall["views"], 1000)
            self.assertEqual(stall["no_records"], [])

    def test_the_bound_is_the_never_sent_rule_and_the_grace(self):
        import l7v2_harm
        self.assertEqual(R.STALL_BOUND_S, l7v2_harm._rule()["never_sent_after_s"])
        self.assertEqual(R.STALL_BOUND_S, R.STOP_GRACE_S)

    def test_nginx_starts_with_no_pipe_for_its_daemon_to_hold(self):
        """Review T-057 T057-01: on this VM's nginx a start run to completion with its output captured comes back only at the 120-s timeout,
        so a runner that does that gets "nginx did not start" in every run, and the old fake answered it at once with 0."""
        host = F.FakeHost()
        self.assertEqual(tuple(host.run(["taskset", "-c", "0-1", "nginx", "-c", "x.conf"], ns="server_ns"))[:3], (-1, "", "timeout"))
        self.assertEqual(host.t, 120.0)
        host, run = F.FakeHost(), self.one_run("no_pipe", "campaign", 3106, "C", thresholds=POINT)
        self.assertEqual(R.execute_run(host, run)["reasons"], [])
        self.assertEqual([c[2] for c in host.commands if c[1] == tuple(run["nginx"]["start"])], ["popen"])
        self.assertTrue(os.path.isfile(os.path.join(run["out"], "nginx_start.log")))

    def test_a_failed_start_says_why_and_keeps_its_message(self):
        run = self.one_run("emerg", "campaign", 3106, "C", thresholds=POINT)
        res = R.execute_run(F.FakeHost(nginx_fails=True), run)
        self.assertRegex(res["reasons"][0], r"^nginx did not start: .* exited 1: nginx: \[emerg\] unknown directive")
        with open(os.path.join(run["out"], "nginx_start.log"), encoding="utf-8") as fh:
            self.assertIn("[emerg]", fh.read())

    def test_a_launcher_that_never_returns_is_named(self):
        res = R.execute_run(F.FakeHost(nginx_hangs=True), self.one_run("hangs", "campaign", 3106, "C", thresholds=POINT))
        self.assertRegex(res["reasons"][0], r"^nginx did not start: .* did not return within 10 s")

    def test_gunicorn_dying_in_mid_run_makes_the_run_invalid(self):
        """D-063: a dead backend read as harm: the run went on, every request failed, and run.json said nothing."""
        for arm in ("U_post", "C"):
            run = self.one_run(f"dies_{arm}", "campaign", 3106, arm, thresholds=POINT)
            res = R.execute_run(F.FakeHost(gunicorn_dies=(100.0, 1, ""), modelled_attackers=1), run)
            self.assertFalse(res["ok"])
            self.assertEqual([r for r in res["reasons"] if "gunicorn" in r], ["gunicorn exited at 100 s (code 1)"])
            with open(os.path.join(run["out"], "run.json"), encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["checks"]["reasons"], res["reasons"])

    def test_the_reason_names_what_the_log_shows(self):
        boot = "[ERROR] Worker (pid:7) exited with code 3.\n[ERROR] Reason: Worker failed to boot.\n"
        refusal = "origin.CalibrationError: C0: 0.005 ms against 0.05 ms frozen\n" + boot
        for name, text, want in (("boot", boot, "gunicorn exited at 150 s (code 3): a worker failed to boot (gunicorn.log)"),
                                 ("refusal", refusal, "gunicorn exited at 150 s (code 3): the origin refused its calibration record (gunicorn.log)")):
            run = self.one_run(name, "campaign", 3106, "U_post", thresholds=POINT)
            res = R.execute_run(F.FakeHost(gunicorn_dies=(150.0, 3, text), modelled_attackers=1), run)
            self.assertIn(want, res["reasons"])

    def test_gunicorn_dying_after_the_loops_last_look_is_seen_once(self):
        run = self.one_run("late", "campaign", 3106, "C", thresholds=POINT)
        res = R.execute_run(F.FakeHost(gunicorn_dies=(270.2, 1, "")), run)
        self.assertEqual(res["reasons"], ["gunicorn exited at 270 s (code 1)"])

    def test_the_runner_stopping_gunicorn_is_no_reason(self):
        run = self.one_run("healthy", "campaign", 3106, "C", thresholds=POINT)
        self.assertEqual(R.execute_run(F.FakeHost(), run)["reasons"], [])

    def test_a_refused_master_never_serves(self):
        """D-063 (2): the record refused in gunicorn's master: named at once, with no traffic, no daemon and no 30-s wait."""
        run = self.one_run("refused", "campaign", 3106, "M_pc_post", thresholds=POINT)
        host = F.FakeHost(gunicorn_refuses="[INFO] Starting gunicorn 26.2.0\nCalibrationError: C0: 0.005 ms against 0.05 ms frozen\n")
        res = R.execute_run(host, run)
        self.assertEqual(res["reasons"], ["gunicorn exited before the traffic (code 1): the origin refused its calibration record (gunicorn.log)"])
        self.assertEqual({p.kind for p in host.procs}, {"server"})
        self.assertLess(host.t, 5.0)
        self.assertTrue(host.ran("ip", "netns", "del", "server_ns"))
        self.assertFalse(os.path.exists(os.path.join(run["out"], "stub_status.jsonl")))

    def test_nginx_gone_at_the_runs_end_makes_the_run_invalid(self):
        """stub_status records its errors and judges nothing (D-050), so a dead nginx said nothing either."""
        run = self.one_run("nginx", "campaign", 3106, "U_post", thresholds=POINT)
        res = R.execute_run(F.FakeHost(nginx_gone=True, modelled_attackers=1), run)
        self.assertEqual(res["reasons"], ["nginx was not running at the run's end: its quit exited 1"])
        run = self.one_run("never_began", "campaign", 3106, "C", thresholds=POINT)
        res = R.execute_run(F.FakeHost(nginx_gone=True, stack_ready=False), run)
        self.assertEqual(len(res["reasons"]), 1, "a run that never began has no end to speak of")

    def test_a_generator_with_no_records_is_a_reason(self):
        run = self.one_run("no_records", "campaign", 3106, "C", thresholds=POINT)
        device = next(e for e in run["entities"] if e["kind_or_family"] == "search_user")
        host = F.FakeHost()
        real = host._write_records
        host._write_records = lambda p: None if p.ip == device["address"] else real(p)
        res = R.execute_run(host, run)
        self.assertTrue(any(f"1 benign generators left no readable records, the first {device['entity_id']}" in r
                            for r in res["reasons"]), res["reasons"])

    def test_a_runner_stall_before_the_attack_launches_it_late(self):
        run = self.one_run("late_launch", "campaign", 3106, "U_post", thresholds=POINT)
        res = R.execute_run(F.FakeHost(runner_stall=(20.0, 31.0), modelled_attackers=1), run)
        self.assertTrue(any("s late (more than 10 s)" in r and "launched" in r for r in res["reasons"]), res["reasons"])
        with open(os.path.join(run["out"], "run.json"), encoding="utf-8") as fh:
            stall = json.load(fh)["stall"]
        self.assertGreater(stall["largest_launch_lag_s"], 10.0)
        self.assertGreater(stall["largest_loop_gap_s"], 30.0)

    def test_a_runner_stall_after_its_launches_is_read_and_changes_nothing(self):
        run = self.one_run("late_loop", "campaign", 3106, "U_post", thresholds=POINT)
        res = R.execute_run(F.FakeHost(runner_stall=(100.0, 31.0), modelled_attackers=1), run)
        self.assertEqual(res["reasons"], [])
        with open(os.path.join(run["out"], "run.json"), encoding="utf-8") as fh:
            stall = json.load(fh)["stall"]
        self.assertLess(stall["largest_launch_lag_s"], 1.5)
        self.assertGreater(stall["largest_loop_gap_s"], 30.0)

    def test_a_run_that_never_began_has_no_stall_to_read(self):
        run = self.one_run("not_root")
        R.execute_run(F.FakeHost(root=False), run)
        with open(os.path.join(run["out"], "run.json"), encoding="utf-8") as fh:
            self.assertIsNone(json.load(fh)["stall"])

    def test_the_slip_reaches_the_record_and_the_outcome(self):
        R.run_block(F.FakeHost(modelled_attackers=1), self.block("campaign", 3101, thresholds=POINT, arms=["C", "U_post"]))
        out = os.path.join(self.root, "runs.jsonl")
        R.summarize_root(self.root, R.PLACEHOLDER, out, dry_run=True)
        with open(out, encoding="utf-8") as fh:
            records = list(map(json.loads, fh))
        self.assertTrue(all(r["view_slip_s"] is not None for r in records))
        self.assertEqual(OUT.outcome(records, dry_run=True)["largest_view_slip"]["view_slip_s"], max(r["view_slip_s"] for r in records))

    def test_a_run_record_says_why_it_is_invalid(self):
        """Review T-050 T050-16: the outcome names what emptied the comparison with M_def."""
        block = self.block("campaign", 3101, thresholds=POINT, arms=["C", "M_def_loris"])
        pool = next(e["address"] for e in block["runs"][0]["entities"] if e["kind_or_family"] == "cgnat_browsers")
        R.run_block(F.FakeHost(gen_late={pool: 30.0}, modelled_attackers=1), block)
        out = os.path.join(self.root, "runs.jsonl")
        R.summarize_root(self.root, R.PLACEHOLDER, out, dry_run=True)
        with open(out, encoding="utf-8") as fh:
            by = {r["arm"]: r for r in map(json.loads, fh)}
        self.assertFalse(by["M_def_loris"]["valid"])
        self.assertIn("was still running 10 s after its end", by["M_def_loris"]["reasons"][0])
        self.assertIn("was still running 10 s after its end", OUT.outcome(list(by.values()), dry_run=True)["invalid_runs"][0]["reasons"][0])

    def test_a_generator_late_past_the_grace_makes_the_run_invalid(self):
        """Why review T-047 P-01 blocked P4-S: this is what a slow uploader that outlives its duration did to every run."""
        run = self.one_run("late")
        slow = next(e["address"] for e in run["entities"] if e["kind_or_family"] == "slow_uploader")
        res = R.execute_run(F.FakeHost(gen_late={slow: 30.0}), run)
        self.assertTrue(any("was still running 10 s after its end" in r for r in res["reasons"]), res["reasons"])
        ok = R.execute_run(F.FakeHost(gen_late={slow: 5.0}), self.one_run("in_time"))
        self.assertEqual(ok["reasons"], [])


    def test_stub_status_is_recorded_and_judges_nothing(self):
        """D-050 (review T-047 P-02): exhausted slots are the harm, so a stub that stops answering is data, not invalidity."""
        host = F.FakeHost(stub_fails=(30.0, 240.0), modelled_attackers=1)
        run = self.one_run("stub", "campaign", 3106, "U_loris", thresholds=POINT)
        res = R.execute_run(host, run)
        self.assertEqual(res["reasons"], [])
        with open(os.path.join(run["out"], "stub_status.jsonl"), encoding="utf-8") as fh:
            rows = [json.loads(line) for line in fh]
        self.assertGreater(sum(1 for r in rows if "error" in r), 100)
        self.assertGreater(sum(1 for r in rows if "active" in r), 30)
        self.assertFalse(hasattr(R, "STUB_STATUS_MIN_SHARE"))

    def test_the_samples_keep_to_the_second_and_the_attack_to_its_time(self):
        """A sample that takes a whole second must not stretch the timeline: still one a second, the attack on time."""
        host = F.FakeHost(stub_fails=(0.0, 60.0), modelled_attackers=1)
        run = self.one_run("drift", "campaign", 3106, "U_post", thresholds=POINT)
        R.execute_run(host, run)
        with open(os.path.join(run["out"], "stub_status.jsonl"), encoding="utf-8") as fh:
            times = [json.loads(line)["t"] for line in fh]
        self.assertEqual(times[:61], [float(k) for k in range(61)])
        attack = next(p for p in host.procs if p.kind == "gen" and p.role == "attack")
        self.assertEqual(attack.start - host.run_t0, 30.0)


    def test_a_run_whose_runner_dies_still_counts(self):
        """Review T-047 P-07: the index line comes before the run, so a ban in a run that died cannot be hidden by a re-run."""
        block = self.block("campaign", 3108, thresholds=POINT, arms=["M_pc_loris"])
        cgnat = next(e["address"] for e in block["runs"][0]["entities"] if e["kind_or_family"] == "cgnat_browsers")

        def dies(_host, plan):
            self.assertTrue(os.path.isfile(os.path.join(plan["out"], "plan.json")))
            self.assertEqual(index(self.root)[-1]["arm"], "M_pc_loris")        # already there
            with open(plan["daemon"]["env"]["BAN_EVENTS"], "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"kind": "ban", "ip": cgnat, "t_wall": 1.0}) + "\n")
            raise KeyboardInterrupt

        with mock.patch.object(R, "execute_run", dies), self.assertRaises(KeyboardInterrupt):
            R.run_block(F.FakeHost(), block)
        [row] = index(self.root)
        self.assertEqual((row["ended"], row["valid"]), (False, False))
        self.assertIn("the runner died", row["reasons"][0])
        out = os.path.join(self.root, "runs.jsonl")
        R.summarize_root(self.root, R.PLACEHOLDER, out, dry_run=True)
        with open(out, encoding="utf-8") as fh:
            [rec] = [json.loads(line) for line in fh]
        self.assertEqual((rec["valid"], rec["Q"], rec["banned"]), (False, None, {cgnat: "cgnat"}))
        m = OUT.outcome([rec], dry_run=True)["families"]["loris"]["mitigation"]
        self.assertEqual(m["benign_banned"], [[3108, cgnat, "cgnat"]])

    def test_a_run_the_index_does_not_hold_is_refused(self):
        os.makedirs(os.path.join(self.root, "campaign", "b3108_a1", "M_pc_loris"))
        with self.assertRaisesRegex(ValueError, "the index does not hold"):
            R.summarize_root(self.root, R.PLACEHOLDER, os.path.join(self.root, "runs.jsonl"), dry_run=True)

    def test_the_index_reads_a_cut_last_line_and_refuses_any_other(self):
        started = {"event": "started", "phase": "campaign", "block": 3108, "attempt": 1, "label": "", "arm": "C", "dir": "d"}
        path = os.path.join(self.root, "index.jsonl")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(started) + '\n{"event": "ended", "pha')
        self.assertEqual([x["ended"] for x in R.read_index(self.root)], [False])
        with open(path, "w", encoding="utf-8") as fh:
            fh.write('{"event": "cut\n' + json.dumps(started) + "\n")
        with self.assertRaisesRegex(ValueError, "cannot be read"):
            R.read_index(self.root)


    def test_a_rule_that_never_reads_is_not_alive(self):
        """Review T-047 P-05: an `ss` that always fails still logs its reports. Such a run must not read as the rule's verdict."""
        def silence(name, fails):
            run = self.one_run(name, "campaign", 3105, "M_pc_post", thresholds=POINT)
            res = R.execute_run(F.FakeHost(ss_fails=fails, modelled_attackers=1), run)
            return [r for r in res["reasons"] if "no successful poll" in r]
        self.assertTrue(silence("blind", True))
        self.assertTrue(silence("blind_15s", (100.0, 115.0)))
        self.assertFalse(silence("blind_5s", (100.0, 105.0)))

    def test_a_validation_run_needs_a_socket_of_each_benign_role(self):
        """Review T-047 P-09: invalid in the runner, so the seed can be re-run; the scorer alone would be a dead end, since a re-run
        of a valid attempt is refused (D-050)."""
        res = R.execute_run(F.FakeHost(no_socket_of={"crawler_polite"}), self.one_run("no_crawler"))
        self.assertTrue(any("no socket of crawler_polite" in r for r in res["reasons"]), res["reasons"])
        self.assertEqual(R.execute_run(F.FakeHost(), self.one_run("all_roles"))["reasons"], [])
        smoke = self.one_run("smoke", "smoke", 9101, "C", label="s", sources={"loris": 0, "post": 0})
        self.assertEqual(R.execute_run(F.FakeHost(no_socket_of={"crawler_polite"}), smoke)["reasons"], [], "a smoke run judges nothing")

    def test_a_validation_run_with_a_blind_rule_is_invalid_too(self):
        res = R.execute_run(F.FakeHost(ss_fails=True), self.one_run("blind_val"))
        self.assertTrue(any("no successful poll" in r for r in res["reasons"]), res["reasons"])

    def test_an_enforcing_run_must_have_enforced(self):
        run = self.one_run("shadow", "campaign", 3105, "M_pc_loris", thresholds=POINT)
        res = R.execute_run(F.FakeHost(kill_appears_at=100.0, modelled_attackers=1), run)
        self.assertTrue(any("did not enforce throughout" in r for r in res["reasons"]), res["reasons"])


    def test_an_unreadable_ban_record_makes_the_run_invalid(self):
        """Review T-047 P-17 (4): a garbled line could be a ban, and a missing file read as no bans in a judged attempt."""
        for arm in ("M_pc_loris", "M_def_post", "C_M"):
            run = self.one_run(f"garbled_{arm}", "campaign", 3106, arm, thresholds=POINT)
            res = R.execute_run(F.FakeHost(garbled_bans=True, modelled_attackers=1), run)
            self.assertTrue(any("2 lines of the ban events cannot be read" in r for r in res["reasons"]), res["reasons"])
            run = self.one_run(f"gone_{arm}", "campaign", 3106, arm, thresholds=POINT)
            res = R.execute_run(F.FakeHost(ban_file_lost=True, modelled_attackers=1), run)
            self.assertTrue(any("ban events are gone" in r for r in res["reasons"]), res["reasons"])
        run = self.one_run("no_daemon", "campaign", 3106, "U_loris", thresholds=POINT)
        self.assertEqual(R.execute_run(F.FakeHost(garbled_bans=True, ban_file_lost=True, modelled_attackers=1), run)["reasons"], [])

    def test_an_unreadable_ban_record_reaches_the_outcome(self):
        with mock.patch.object(R, "check_attempt"):
            R.run_block(F.FakeHost(garbled_bans=True, modelled_attackers=1), self.block("campaign", 3101, thresholds=POINT, arms=["C_M", "U_post"]))
            R.run_block(F.FakeHost(ban_file_lost=True, modelled_attackers=1), self.block("campaign", 3102, thresholds=POINT, arms=["C", "M_pc_post"]))
        out = os.path.join(self.root, "runs.jsonl")
        R.summarize_root(self.root, R.PLACEHOLDER, out, dry_run=True)
        with open(out, encoding="utf-8") as fh:
            by = {r["arm"]: r for r in map(json.loads, fh)}
        self.assertEqual((by["C_M"]["ban_problem"], by["U_post"]["ban_problem"]), ("2 lines cannot be read", None))
        self.assertEqual((by["M_pc_post"]["ban_problem"], by["C"]["ban_problem"]), ("the file is gone", None))
        self.assertFalse(by["C_M"]["valid"] or by["M_pc_post"]["valid"])
        m = OUT.outcome(list(by.values()), dry_run=True)["families"]["post"]["mitigation"]
        self.assertEqual(m["ban_records_unreadable"], [[3101, 1, "C_M", "2 lines cannot be read"], [3102, 1, "M_pc_post", "the file is gone"]])
        self.assertFalse(m["c"])

    def test_a_run_that_never_had_a_daemon_up_has_no_ban_problem(self):
        block = self.block("campaign", 3108, thresholds=POINT, arms=["C_M", "M_pc_loris"])

        def dies(_host, _plan):
            raise KeyboardInterrupt

        with mock.patch.object(R, "execute_run", dies), self.assertRaises(KeyboardInterrupt):
            R.run_block(F.FakeHost(), block)
        R.run_block(F.FakeHost(kill_file=True), self.block("campaign", 3109, thresholds=POINT, arms=["M_pc_loris"]))
        out = os.path.join(self.root, "runs.jsonl")
        R.summarize_root(self.root, R.PLACEHOLDER, out, dry_run=True)
        with open(out, encoding="utf-8") as fh:
            records = list(map(json.loads, fh))
        self.assertEqual({(r["block"], r["valid"], r["ban_problem"]) for r in records}, {(3108, False, None), (3109, False, None)})

    def test_an_attack_that_never_connected_makes_the_run_invalid(self):
        """Review T-047 P-06: such an M_pc would pass (a) and (b), and such a U would read "not harmful"."""
        for arm in ("U_loris", "M_pc_loris"):
            run = self.one_run(f"no_attack_{arm}", "campaign", 3106, arm, thresholds=POINT)
            res = R.execute_run(F.FakeHost(attack_fails=True, modelled_attackers=1), run)
            self.assertTrue(any("could not open connections on this machine" in r for r in res["reasons"]), res["reasons"])
            self.assertTrue(any("the attack opened 0 of its 600 connections" in r for r in res["reasons"]), res["reasons"])

    def test_connections_the_server_refuses_are_the_harm_not_invalidity(self):
        run = self.one_run("refused", "campaign", 3106, "U_loris", thresholds=POINT)
        self.assertEqual(R.execute_run(F.FakeHost(attack_opened_share=0.6, modelled_attackers=1), run)["reasons"], [])
        with open(os.path.join(run["out"], "run.json"), encoding="utf-8") as fh:
            attack = json.load(fh)["attack"]
        self.assertEqual((attack["planned"], attack["opened"], attack["failed_opens"]), (600, 400, 200))
        run = self.one_run("too_few", "campaign", 3106, "U_loris", thresholds=POINT)
        res = R.execute_run(F.FakeHost(attack_opened_share=0.4, modelled_attackers=1), run)
        self.assertTrue(any("the attack opened 200 of its 600" in r for r in res["reasons"]), res["reasons"])

    def test_an_attack_generator_without_stats_is_a_reason(self):
        run = self.one_run("no_stats", "campaign", 3106, "U_post", thresholds=POINT)
        res = R.execute_run(F.FakeHost(attack_opened_share=None, modelled_attackers=1), run)
        self.assertTrue(any("attack generators left no stats" in r for r in res["reasons"]), res["reasons"])
        run = self.one_run("no_attack_arm")
        self.assertEqual(R.execute_run(F.FakeHost(attack_fails=True), run)["reasons"], [])

    def test_the_attack_generators_are_told_where_to_write(self):
        run = self.one_run("argv", "campaign", 3106, "U_post", thresholds=POINT)
        for x in run["launches"]:
            self.assertEqual("--stats" in x["argv"], x["role"] == "attack")


    def test_a_block_at_other_settings_is_refused(self):
        """Review T-047 P-08: another scale, T, F, K or calibration in one campaign, or in one block's next attempt."""
        host = F.FakeHost(modelled_attackers=1)
        R.run_block(host, self.block("campaign", 3101, thresholds=POINT, arms=["C"]))
        other = os.path.join(self.root, "other.json")
        with open(R.PLACEHOLDER, encoding="utf-8") as fh, open(other, "w", encoding="utf-8") as out:
            out.write(fh.read() + "\n")
        for kw, what in (({"sources": {"loris": 175, "post": 5}}, "sources"), ({"thresholds": (20, 16, 6)}, "thresholds"),   # each with a record that matches it
                         ({"halvings": 1}, "halvings"), ({"calibration": other}, "calibration_sha256")):
            block = self.block("campaign", 3102, **{"thresholds": POINT, "arms": ["C"], **kw})
            with self.assertRaisesRegex(R.PlanError, what):
                R.run_block(host, block)
        self.assertEqual(sorted(os.listdir(os.path.join(self.root, "campaign"))), ["b3101_a1"])
        R.run_block(host, self.block("campaign", 3102, thresholds=POINT, arms=["C"]))

    def test_summarize_refuses_another_calibration(self):
        R.run_block(F.FakeHost(), self.block("campaign", 3101, thresholds=POINT, arms=["C"]))
        other = os.path.join(self.root, "other.json")
        with open(R.PLACEHOLDER, encoding="utf-8") as fh, open(other, "w", encoding="utf-8") as out:
            out.write(fh.read() + "\n")
        out_path = os.path.join(self.root, "runs.jsonl")
        with self.assertRaisesRegex(ValueError, "ran under calibration"):
            R.summarize_root(self.root, other, out_path, dry_run=True)
        R.summarize_root(self.root, R.PLACEHOLDER, out_path, dry_run=True)
        with open(out_path, encoding="utf-8") as fh:
            [rec] = [json.loads(line) for line in fh]
        self.assertEqual(rec["settings"]["sources"], KNEE)

    def test_the_daemon_under_test_is_hashed(self):
        run = self.one_run("hash", "campaign", 3101, "M_pc_post", thresholds=POINT)
        code = run["provenance"]["code_sha256"]
        self.assertEqual(code["control_plane.py"], sha(os.path.join(REPO, "control_plane.py")))
        self.assertEqual(sorted(code), sorted(R.CODE_FILES))
        R.execute_run(F.FakeHost(modelled_attackers=1), run)
        with open(os.path.join(run["out"], "run.json"), encoding="utf-8") as fh:
            meta = json.load(fh)
        self.assertTrue(meta["daemon_provenance"]["h01"]["has_fix"])
        self.assertIn("control_plane.py", meta["daemon_provenance"]["files"])
        self.assertIn("git", meta)

    def test_a_daemon_without_the_h01_fix_makes_the_run_invalid(self):
        run = self.one_run("no_fix", "campaign", 3101, "M_pc_post", thresholds=POINT)
        with mock.patch("executor.daemon_provenance", return_value={"files": {}, "h01": {"has_fix": False}}):
            res = R.execute_run(F.FakeHost(modelled_attackers=1), run)
        self.assertTrue(any("H-01 fix" in r for r in res["reasons"]), res["reasons"])


if __name__ == "__main__":
    unittest.main()
