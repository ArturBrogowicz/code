"""P2's gate campaign with the host check (docs/RECALIBRATION_2026-11_DESIGN.md K4 and 5.1, applied to campaigns as K9; the user's D5 of
2026-11-13, docs/HG1C_DESIGN.md departure 41): every sound run judged by H1 and H3-H7, a host-invalid run set aside as
<run>.hostinvalid<k>, kept, and made again in place without using one of the gate's two re-runs, the pause and the resume. On the
simulated host only."""
import contextlib
import io
import json
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
for sub in ("bench", "eval"):
    sys.path.insert(0, os.path.join(REPO, sub))
import executor as X
import gate_campaign as GC
import harm_gate as H
import hostcheck as HC
import population as P
import sim_host as S
import test_gate_campaign as TG

APP = [(1000, 1874, 60.0, "/home/artur/.claude/remote/srv/x/server --serve")]


class CampaignHostCheckTest(TG.CampaignCase):
    def checked(self, **kw):
        return self.run_campaign(host_check=True, **kw)

    def test_a_quiet_host_judges_every_run_and_changes_nothing_else(self):
        plain = self.run_campaign(out="plain")
        state = self.checked()
        self.assertEqual((state["state"], state["reruns"]), ("complete", 0))
        self.assertEqual(state["gate"]["verdict"], plain["gate"]["verdict"])
        for d in [d for d in self.dirs() if H.BLOCK_DIR.match(d)]:
            for kind in X.KINDS:
                done = self.json(d, kind, GC.DONE)
                self.assertTrue(done["host"]["ok"], done["host"]["reasons"])
                self.assertEqual(sorted(done["host"]["rules"]), ["H1", "H3", "H4", "H5", "H6", "H7"])
                self.assertIn("speed", self.json(d, kind, "run.json"))
        self.assertTrue(state["fingerprint"]["host_check"])
        self.assertEqual(sorted(os.listdir(self.path("monitors", "1"))), ["chrony.txt", "journal.txt", "mpstat.txt", "pidstat.txt"])

    def test_a_host_invalid_run_is_made_again_in_place_and_uses_no_rerun(self):
        """D5: the run inside the load is set aside and made again after the hold; the block stays attempt 1, the re-runs 0."""
        host = self.host(other_load=lambda t: APP if t < S.BASE_EPOCH + 15 else [])
        state = self.checked(host=host)
        self.assertEqual((state["state"], state["reruns"]), ("complete", 0))
        self.assertEqual([(a["block"], a["attempt"]) for a in state["attempts"]], [(1, 1), (2, 1), (3, 1)])
        first = GC.run_order(self.scn, 1, 1)[0]
        aside = self.path("b01_a1", first + ".hostinvalid1")
        self.assertTrue(os.path.isdir(aside), os.listdir(self.path("b01_a1")))
        with open(os.path.join(aside, "HOSTINVALID"), encoding="utf-8") as fh:
            self.assertIn("H6:", fh.read())
        self.assertFalse(self.json("b01_a1", first + ".hostinvalid1", GC.DONE)["host"]["ok"])
        self.assertTrue(self.json("b01_a1", first, GC.DONE)["host"]["ok"])
        self.assertTrue(self.json("b01_a1", first + ".hostinvalid1", "HOLD.json")["held"])
        self.assertEqual(sorted(H.assess_block(self.path("b01_a1"), self.CAL)["runs"]), sorted(X.KINDS), "never judged")
        self.assertEqual(state["gate"]["verdict"], "PASS")
        self.assertEqual(state["gate"]["reruns"], 0)

    def test_the_remake_does_not_start_once_the_packets_budget_is_used(self):
        host = self.host(other_load=lambda t: APP if t < S.BASE_EPOCH + 15 else [])
        with self.assertRaisesRegex(GC.Paused, "budget of 3 min"):
            self.checked(host=host, stop_after_min=3.0)
        self.assertEqual(self.json(GC.CAMPAIGN)["state"], "paused")
        first = GC.run_order(self.scn, 1, 1)[0]
        self.assertTrue(os.path.isdir(self.path("b01_a1", first + ".hostinvalid1")))
        self.assertFalse(os.path.exists(self.path("b01_a1", first)))
        self.assertEqual(self.checked()["reruns"], 0)

    def test_three_in_a_row_pause_the_campaign_and_the_same_command_resumes_it(self):
        with self.assertRaisesRegex(HC.HostUnfit, r"paused: host unfit \(3 host-invalid runs in a row"):
            self.checked(host=self.host(other_load=lambda t: APP))
        state = self.json(GC.CAMPAIGN)
        self.assertEqual(state["state"], "paused")
        self.assertIn("host unfit", state["stopped"])
        first = GC.run_order(self.scn, 1, 1)[0]
        self.assertEqual(sorted(n for n in os.listdir(self.path("b01_a1")) if HC.ASIDE in n),
                         [f"{first}.hostinvalid{k}" for k in (1, 2, 3)])
        resumed = self.checked()
        self.assertEqual((resumed["state"], resumed["reruns"]), ("complete", 0))
        self.assertTrue(os.path.isdir(self.path("b01_a1", f"{first}.hostinvalid3")), "every set-aside run stays, to be published")

    def test_the_command_line_runs_with_it_and_exits_5_when_the_host_is_unfit(self):
        out, err = io.StringIO(), io.StringIO()
        host = self.host(other_load=lambda t: APP)
        with mock.patch.object(X.signal, "signal"), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = GC.main(["run", TG.SPEC, "--calibration", self.cal_path, "--out", self.path(), "--blocks", "3", "--no-warmup",
                            "--rho", str(TG.RHO), "--timeline", "6,6,6", "--simulate", "pass"], host=host)
        self.assertEqual(code, GC.EXIT_HOST_UNFIT)
        self.assertIn("HostUnfit: paused: host unfit", err.getvalue())
        self.assertEqual(host.alive(), [], "the monitors are stopped")
        with mock.patch.object(X.signal, "signal"), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = GC.main(["run", TG.SPEC, "--calibration", self.cal_path, "--out", self.path("plain"), "--blocks", "3", "--no-warmup",
                            "--rho", str(TG.RHO), "--timeline", "6,6,6", "--simulate", "pass", "--no-host-check"], host=self.host(
                                other_load=lambda t: APP))
        self.assertEqual(code, GC.EXIT_OK, "a smoke test's --no-host-check judges nothing")

    def test_the_plan_says_so(self):
        text = GC.describe(self.scn, self.CAL, TG.SPEC_SHA, self.options(host_check=True))
        self.assertIn("host check   every run: the speed bracket on CPUs 0 and 1 (H1, 10%) and the monitors' rules H3-H7 on CPU 2; a "
                      "host-invalid run is kept as <run>.hostinvalid<k> and made again in place after a speed hold, using no re-run (D5, "
                      "departure 41); 3 in a row or 4 in a packet pause it (exit 5)", text)
        self.assertNotIn("host check", GC.describe(self.scn, self.CAL, TG.SPEC_SHA, self.options()))
        self.assertTrue(GC.options_of(GC.main.__globals__["argparse"].Namespace(
            blocks=None, no_warmup=False, confirm_2x_knee=False, rho=None, timeline=None, timer_limit_ms=None, modes=())).host_check)

    def test_a_campaign_resumes_only_with_the_check_it_began_with_and_one_of_before_reads_as_without(self):
        self.run_campaign(blocks=1, keep_going=True)
        state = self.json(GC.CAMPAIGN)
        self.assertFalse(state["fingerprint"]["host_check"])
        with self.assertRaisesRegex(GC.CampaignError, r"other settings \(host_check\)"):
            self.checked(blocks=1, keep_going=True)
        del state["fingerprint"]["host_check"]
        X.write_json(self.path(GC.CAMPAIGN), state)
        self.assertEqual(self.run_campaign(blocks=1, keep_going=True)["state"], "complete")

    def test_a_legit_ban_in_a_set_aside_protected_run_still_counts(self):
        d = self.path("b01_a1")
        os.makedirs(os.path.join(d, "M_xdp.hostinvalid1"))
        with open(os.path.join(d, "M_xdp.hostinvalid1", H.BAN_FILE), "w", encoding="utf-8") as fh:
            legit = str(next(P.BENIGN_NETS[0].hosts()))
            fh.write(json.dumps({"kind": "ban", "ip": legit, "t_wall": 1.0, "reason": "rate"}) + "\n")
        rows = H.campaign_benign_bans(self.path(), [], "M_xdp")
        self.assertEqual([(r["ip"], r["file"], r["run_valid"]) for r in rows],
                         [(legit, "b01_a1/M_xdp.hostinvalid1/" + H.BAN_FILE, None)])

    def test_departure_41_dates_d5_and_says_what_it_costs(self):
        with open(os.path.join(REPO, "docs", "HG1C_DESIGN.md"), encoding="utf-8") as fh:
            rows = [line for line in fh if line.startswith("| 41 |")]
        self.assertEqual(len(rows), 1)
        for phrase in ("Dated amendment of 2026-11-13", "D5", '"Accept (Recommended)"', "before any P2 data", "`<run>.hostinvalid<k>`",
                       "none of the gate's two re-runs", "kept and published", "paused: host unfit", "What this costs",
                       "Q, a p95 or a harm"):
            self.assertIn(phrase, rows[0])


if __name__ == "__main__":
    unittest.main()
