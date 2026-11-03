"""The P4 validation scorer (eval/p4_validation.py; docs/P4_SLOW_DESIGN.md §6.4, §13 row 3), on synthetic
records written exactly as the daemon writes them (slow_pc.record_member). Offline and pure.

The fixture is a validation set of 2 seeds x (C, U_loris, U_post), 60 one-second polls each. Benign: a
browser device (answered keep-alive), a CGNAT pool on :443 answered through the access log, a request
waiting on a slow server, a slow uploader at 2,000 B/s and one at 500 B/s. Attacks: 2 Slowloris
addresses x 3 connections (30 B every 2 s after 100 B, about 15 B/s plus the head) and 2 slow-POST
addresses x 2 connections (16 B every 3 s after 300 B). Worked out by hand:
  * F = 16: Slowloris stays above 16 B/s for the whole run (closed at no T); slow POST falls below it at
    an age of 29 s, so K = 2 bans those 2 addresses per seed;
  * F = 64 or 256: both families are closed T + 3 s after the first poll; K = 2 bans all 4 addresses per
    seed, K = 3 the Slowloris ones, K = 4 and 6 none;
  * F = 1024 closes the 500 B/s slow uploader, which breaks a constraint at every such point.
So 48 points are feasible, 8/8 is the best share, and the tie-breaks pick (20, 64, 2).
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from fractions import Fraction

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "eval"))
import p4_validation as V

import slow_pc as P

NGINX = 'users:(("nginx",pid=4242,fd=17))'
ROLES = {"10.0.1.1": "browser", "10.0.4.1": "cgnat", "10.0.1.9": "browser",
         "10.0.5.1": "slow_uploader", "10.0.5.2": "slow_uploader",
         "10.0.3.1": "attack", "10.0.3.2": "attack", "10.0.6.1": "attack", "10.0.6.2": "attack"}


def sock(ip, port, sport=80, acked=1, received=100, segs=1):
    return (f"0      0      10.0.0.1:{sport}   {ip}:{port} {NGINX}\n\t cubic bytes_acked:{acked} "
            f"bytes_received:{received} data_segs_in:{segs}\n")


def dribble(first, every, size, t, opened=0.5):
    n = int((t - opened) // every)
    return first + size * n, 1 + n


def world(arm, t):
    out = [sock("10.0.1.1", 40000 + i, acked=5200, received=600 + 10 * int(t), segs=2 + int(t) // 4)
           for i in range(6)]
    out += [sock("10.0.4.1", 43000 + i, 443, acked=4100, received=900 + 40 * int(t), segs=3 + int(t))
            for i in range(12)]
    out.append(sock("10.0.1.9", 40100, received=380, segs=1))                      # waiting on the server
    out.append(sock("10.0.5.1", 44000, received=600 + 2000 * int(t), segs=2 + 2 * int(t)))
    out.append(sock("10.0.5.2", 44001, received=600 + 500 * int(t), segs=2 + int(t)))
    if arm == "U_loris":
        for ip in ("10.0.3.1", "10.0.3.2"):
            for i in range(3):
                received, segs = dribble(100, 2.0, 30, t)
                out.append(sock(ip, 41000 + i, received=received, segs=segs))
    if arm == "U_post":
        for ip in ("10.0.6.1", "10.0.6.2"):
            for i in range(2):
                received, segs = dribble(300, 3.0, 16, t)
                out.append(sock(ip, 45000 + i, received=received, segs=segs))
    return "".join(out)


def write_run(tmp, seed, arm, roles=ROLES, polls=60, failed=(), valid=True):
    """A run directory as the runner will write it: the record and the manifest."""
    d = os.path.join(tmp, f"{seed}_{arm}")
    os.makedirs(d)
    items = [["10.0.4.1", 43000 + i, P.l7_ingest.stable_hash32(f"ua{i}"), 0.5] for i in range(12)]
    with open(os.path.join(d, "slow_pc.jsonl.gz"), "wb") as fh:
        for k in range(1, polls + 1):
            t = float(k)
            text = None if k in failed else world(arm, t)
            fh.write(P.record_member(t, text, items if k == 1 else [], [], False))
    with open(os.path.join(d, "slow_pc_manifest.json"), "w", encoding="utf-8") as fh:
        json.dump({"seed": seed, "arm": arm, "record": "slow_pc.jsonl.gz", "roles": roles,
                   "daemon": V.VALIDATION_DAEMON}, fh)
    with open(os.path.join(d, "run.json"), "w", encoding="utf-8") as fh:
        json.dump({"checks": {"ok": valid, "reasons": [] if valid else ["the daemon exited at 47 s (code 1)"]}}, fh)
    return os.path.join(d, "slow_pc_manifest.json")


def index_rows(rows):
    """ROOT/index.jsonl's two lines for each (seed, attempt, arm, dir, valid)."""
    out = []
    for seed, attempt, arm, where, valid in rows:
        row = {"phase": "validation", "block": seed, "attempt": attempt, "label": "", "arm": arm, "dir": where}
        out.append(json.dumps({"event": "started", **row}))
        out.append(json.dumps({"event": "ended", **row, "valid": valid, "reasons": [], "ended_utc": "t"}))
    return "\n".join(out) + "\n"


class ValidationSetCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.manifests = [write_run(cls.tmp.name, s, a) for s in P.VALIDATION_SEEDS
                         for a in P.VALIDATION_RUNS]
        cls.runs = [V.load_run(m) for m in cls.manifests]
        cls.outcomes, cls.secondary = V.score(cls.runs)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()


class ScoreTest(ValidationSetCase):
    def test_the_counts_at_points_worked_out_by_hand(self):
        o = self.outcomes
        # 4 attacking addresses per seed; 6 + 12 + 1 + 1 + 1 = 21 benign connections per run.
        self.assertEqual({(x.attack_addresses, x.benign_connections) for x in o.values()}, {(8, 126)})
        self.assertEqual(o[(20, 64, 2)], P.Outcome(8, 8, 0, 126, 0, 0))
        self.assertEqual(o[(20, 64, 3)], P.Outcome(8, 4, 0, 126, 0, 0))     # Slowloris: 3 connections
        self.assertEqual(o[(5, 256, 6)], P.Outcome(8, 0, 0, 126, 0, 0))
        self.assertEqual(o[(5, 16, 2)], P.Outcome(8, 4, 0, 126, 0, 0))      # slow POST only
        self.assertEqual(o[(5, 1024, 2)], P.Outcome(8, 8, 0, 126, 6, 6))    # 10.0.5.2 in every run

    def test_the_selection_on_the_fixture(self):
        sel = P.select_thresholds(self.outcomes)
        self.assertEqual(sel, P.Selection((20, 64, 2), Fraction(1), 48))

    def test_the_secondary_figure_is_the_share_within_30_s(self):
        self.assertEqual(V.SECONDARY_DEADLINE_S, 30.0)
        self.assertEqual(self.secondary[(20, 64, 2)], 8)                    # banned at 24 s
        self.assertEqual(self.secondary[(5, 16, 2)], 4)                     # slow POST: 30 s, inclusive
        self.assertEqual(self.outcomes[(5, 16, 2)].attack_banned_in_time, 4)

    def test_a_failed_read_is_a_skipped_poll(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = V.load_run(write_run(tmp, 4001, "U_loris", failed=range(5, 15)))
        counts = V.score_run(run["polls"], run["roles"], [(5, 64, 2)])[(5, 64, 2)]
        self.assertEqual((counts["attack_addresses"], counts["attack_banned_in_time"]), (2, 2))


class InputTest(ValidationSetCase):
    def test_the_runs_must_be_exactly_the_frozen_validation_set(self):
        V.check_runs(self.runs)
        for runs in (self.runs[1:], self.runs + self.runs[:1],
                     [{**r, "seed": 4003} if r["seed"] == 4002 else r for r in self.runs]):
            with self.assertRaises(ValueError):
                V.check_runs(runs)

    def test_every_address_seen_needs_a_role(self):
        roles = {k: v for k, v in ROLES.items() if k != "10.0.6.2"}
        with tempfile.TemporaryDirectory() as tmp:
            run = V.load_run(write_run(tmp, 4001, "U_post", roles=roles))
            with self.assertRaises(ValueError):
                V.score_run(run["polls"], run["roles"])
            for bad in ({"10.0.1.1": ""}, {"10.0.1.1": 3}, ["attack"]):
                path = write_run(tempfile.mkdtemp(dir=tmp), 4001, "C", roles=bad)
                with self.assertRaises(ValueError):
                    V.load_run(path)

    def test_the_command_line_writes_the_record(self):
        out = os.path.join(self.tmp.name, "selection.json")
        with open(os.path.join(self.tmp.name, "index.jsonl"), "w", encoding="utf-8") as fh:
            fh.write(index_rows([(s, 1, a, f"{s}_{a}", True) for s in P.VALIDATION_SEEDS for a in P.VALIDATION_RUNS]))
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            rc = V.main([self.tmp.name, "--json", out])
        self.assertIn("chosen T=20 s, F=64 B/s, K=2: 8/8 attacking addresses banned within 90 s "
                      "(8 within 30 s); 48 of 64 points meet the constraints", printed.getvalue())
        with open(out, encoding="utf-8") as fh:
            rec = json.load(fh)
        self.assertEqual((rc, rec["selection"]), (0, {"point": [20, 64, 2], "share": "1",
                                                      "feasible": 48}))
        self.assertEqual(len(rec["outcomes"]), 64)
        self.assertEqual((rec["deadline_s"], rec["secondary_deadline_s"]), (90.0, 30.0))
        self.assertEqual(len(rec["runs"]), 6)
        self.assertEqual(len(rec["slow_pc_sha256"]), 64)
        self.assertEqual(rec["attempts"], [{"seed": s, "judged": 1, "superseded": []} for s in P.VALIDATION_SEEDS])



class WhichRunsTest(unittest.TestCase):
    """Review T-047 P-09: the scorer judges valid runs only, and the index, not the command line, says which attempt."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def attempt(self, seed, attempt, invalid=()):
        rows = []
        for arm in P.VALIDATION_RUNS:
            where = f"a{attempt}"
            os.makedirs(os.path.join(self.root, where), exist_ok=True)
            write_run(os.path.join(self.root, where), seed, arm, polls=2, valid=arm not in invalid)
            rows.append((seed, attempt, arm, os.path.join(where, f"{seed}_{arm}"), arm not in invalid))
        return rows

    def write_index(self, rows):
        with open(os.path.join(self.root, "index.jsonl"), "w", encoding="utf-8") as fh:
            fh.write(index_rows(rows))

    def test_an_invalid_run_is_not_scored(self):
        path = write_run(self.root, 4001, "C", polls=2, valid=False)
        with self.assertRaisesRegex(ValueError, "an invalid run is not scored"):
            V.load_run(path)
        os.remove(os.path.join(self.root, "4001_C", "run.json"))
        with self.assertRaisesRegex(ValueError, "no run.json"):
            V.load_run(path)

    def test_the_last_attempt_with_every_run_valid_is_judged_and_the_rest_are_listed(self):
        self.write_index(self.attempt(4001, 1, invalid=("U_post",)) + self.attempt(4001, 2) + self.attempt(4002, 3))
        manifests, attempts = V.runs_from_index(self.root)
        self.assertEqual(attempts, [{"seed": 4001, "judged": 2, "superseded": [1]},
                                    {"seed": 4002, "judged": 3, "superseded": []}])
        self.assertEqual(len(manifests), 6)
        self.assertTrue(all(f"{os.sep}a2{os.sep}" in m for m in manifests[:3]))

    def test_a_seed_without_a_complete_attempt_is_refused(self):
        self.write_index(self.attempt(4001, 1) + self.attempt(4002, 1, invalid=("C",)))
        with self.assertRaisesRegex(ValueError, "seed 4002: no attempt"):
            V.runs_from_index(self.root)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(V.main([self.root]), 2)
        self.assertIn("seed 4002", err.getvalue())


class ValidationDaemonTest(unittest.TestCase):
    """D-035 (V-04): M_pc's daemon mode without enforcement, recorded and checked; no foreign ban."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_the_mode_is_pinned_and_another_is_refused(self):
        self.assertEqual(V.VALIDATION_DAEMON, {"HEURISTIC_PROFILE": "tolerant", "SLOW_PC": "1", "SLOW_PC_ENFORCE": "0"})
        path = write_run(self.tmp.name, 4001, "C")
        with open(path, encoding="utf-8") as fh:
            m = json.load(fh)
        for daemon in (None, {**V.VALIDATION_DAEMON, "HEURISTIC_PROFILE": "default"},
                       {**V.VALIDATION_DAEMON, "SLOW_PC_ENFORCE": "1"}):
            bad = dict(m) if daemon is None else dict(m, daemon=daemon)
            if daemon is None:
                bad.pop("daemon")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(bad, fh)
            with self.assertRaisesRegex(ValueError, "D-035"):
                V.load_run(path)

    def polls(self, banned, enforce=False):
        return [{"t": 1.0, "ss": world("U_loris", 1.0), "l7": [], "banned": banned, "enforce": enforce}]

    def test_a_record_with_a_benign_address_banned_is_refused(self):
        self.assertTrue(V.score_run(self.polls(["10.0.3.1"]), ROLES, [(5, 64, 2)]))      # an attacker: fine
        for ip in ("10.0.4.1", "10.0.5.1", "10.0.1.1", "10.9.9.9"):
            with self.assertRaisesRegex(ValueError, "not attackers"):
                V.score_run(self.polls(["10.0.3.1", ip]), ROLES, [(5, 64, 2)])
        failed = [{"t": 2.0, "ss": None, "l7": [], "banned": ["10.0.4.1"], "enforce": False}]
        with self.assertRaisesRegex(ValueError, "not attackers"):
            V.score_run(failed, ROLES, [(5, 64, 2)])

    def test_an_enforcing_record_is_refused(self):
        with self.assertRaisesRegex(ValueError, "enforced"):
            V.score_run(self.polls([], enforce=True), ROLES, [(5, 64, 2)])


if __name__ == "__main__":
    unittest.main()
