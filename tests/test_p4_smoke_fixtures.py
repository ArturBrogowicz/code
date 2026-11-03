"""The P4 smoke run's fixtures as tests (eval/p4_smoke.py; docs/P4_SLOW_DESIGN.md §9 "a parser fixture", §7.1, F-S3).

Offline. The checks run now on synthetic snapshots in the documented layout; the two tests of the recordings run as
soon as the smoke run (P4-S, T3, NOT RUN) commits them under tests/fixtures/p4_smoke/, and say they wait until then:
  * ss_tinpH.txt + labels.json: one real `ss -tinpH` output of server_ns with a keep-alive, a backlog, a :443 and a
    Slowloris socket, read by the parser of slow_pc.py as the rule needs it (F-S3);
  * ss_before_kill.txt + ss_after_kill.txt + kill_filter.txt: the daemon's per-connection `ss -K` filter closed
    exactly the one socket it named."""
import contextlib
import gzip
import io
import json
import os
import random
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
for _p in (HERE, REPO, os.path.join(REPO, "eval")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import p4_smoke as S
import test_daemon_slow_pc as DS

import slow_pc

FIXTURES = os.path.join(HERE, "fixtures", "p4_smoke")
NGINX = 'users:(("nginx",pid=4242,fd=17))'
LABELS = {"keepalive": "10.0.16.5:40001", "backlog": "10.0.16.6:40002", "tls": "10.0.17.9:43001",
          "slowloris": "10.0.18.3:41000"}


def line(ip, port, sport=80, owner=NGINX, **info):
    fields = {"bytes_sent": 0, "bytes_acked": 1, "bytes_received": 0, "segs_out": 2, "segs_in": 3,
              "data_segs_in": 0, "lastsnd": 900, "lastrcv": 900, "lastack": 900, "notsent": 0, "rcv_space": 14480}
    fields.update(info)
    tcp = " ".join(f"{k}:{v}" for k, v in fields.items() if v is not None)
    head = f"0      0      10.0.0.1:{sport}   {ip}:{port} {owner}".rstrip()
    return f"{head}\n\t cubic wscale:7,7 rto:204 rtt:0.05/0.025 mss:1448 {tcp} send 2.3Gbps app_limited\n"


def synthetic(without=None):
    """A snapshot in the documented layout with the four kinds the smoke run must record, and six Slowloris
    connections of one address, so that a filter that named an address would name six (`without`: one of their
    ports left out, as after a kill)."""
    text = line("10.0.16.5", 40001, bytes_sent=5300, bytes_acked=5301, bytes_received=640, data_segs_in=2)
    text += line("10.0.16.6", 40002, owner="", bytes_acked=1, bytes_received=None, data_segs_in=None)
    text += line("10.0.17.9", 43001, 443, bytes_sent=4100, bytes_acked=4101, bytes_received=900, data_segs_in=3)
    text += "".join(line("10.0.18.3", 41000 + i, bytes_received=130, data_segs_in=2) for i in range(6)
                    if 41000 + i != without)
    return text


class FixtureCheckTest(unittest.TestCase):
    def test_a_fixture_in_the_documented_layout_passes(self):
        problems, notes = S.fixture_problems(synthetic(), LABELS)
        self.assertEqual(problems, [])
        self.assertEqual(notes, ["backlog: ss printed no bytes_received, data_segs_in"])

    def test_a_mislabelled_or_unreadable_fixture_fails(self):
        swapped = dict(LABELS, backlog=LABELS["keepalive"], keepalive=LABELS["backlog"])
        problems, _n = S.fixture_problems(synthetic(), swapped)
        self.assertEqual(len(problems), 2, problems)
        problems, _n = S.fixture_problems(synthetic() + "garbage line without addresses\n", LABELS)
        self.assertTrue(problems[0].startswith("1 socket lines the parser could not read"))
        self.assertTrue(S.fixture_problems(synthetic(), {"keepalive": LABELS["keepalive"]})[0])
        self.assertTrue(S.fixture_problems(synthetic(), dict(LABELS, tls="10.9.9.9:1"))[0])

    def test_the_fixture_is_cut_from_a_shadow_runs_record(self):
        roles = {"10.0.16.5": "tpcw_browsing", "10.0.16.6": "search_user", "10.0.17.9": "cgnat", "10.0.18.3": "attack"}
        with tempfile.TemporaryDirectory() as tmp:
            rec = os.path.join(tmp, "slow_pc.jsonl.gz")
            with open(rec, "wb") as fh:
                fh.write(slow_pc.record_member(1.0, line("10.0.16.5", 40001, bytes_acked=5301), [], [], False))
                fh.write(slow_pc.record_member(2.0, None, [], [], False))
                fh.write(slow_pc.record_member(3.0, synthetic(), [], [], False))
            text, labels = S.fixture_from_record(rec, roles)
            self.assertEqual(text, synthetic())
            self.assertEqual(S.fixture_problems(text, labels)[0], [])
            self.assertEqual(labels["slowloris"].split(":")[0], "10.0.18.3")
            with gzip.open(rec, "wb") as fh:
                fh.write(b"")
            self.assertIsNone(S.fixture_from_record(rec, roles))


class KillFilterTest(DS.SlowPcCase):
    def test_each_term_of_the_daemons_filter_names_exactly_one_socket(self):
        d = self.daemon(**DS.ENFORCE)
        world = DS.loris_world()
        self.run_world(d, 10, lambda t: "" if d.proc.matching("ss", "-K") else world(t))
        [call] = [c for c in d.proc.matching("ss", "-K", "-t")]
        expr = call[-1]
        snapshot = world(d.clock.now) + line(DS.IP, 50000, bytes_acked=5000) + line(DS.IP, 41000, 443)
        terms = expr.split(" or ")
        self.assertEqual(len(terms), 6)
        named = [S.filter_matches(t, snapshot) for t in terms]
        self.assertTrue(all(len(n) == 1 for n in named), named)
        self.assertEqual(sorted(n[0] for n in named), sorted((DS.IP, 41000 + i, "10.0.0.1", 80) for i in range(6)))
        self.assertNotIn((DS.IP, 50000, "10.0.0.1", 80), S.filter_matches(expr, snapshot))
        self.assertNotIn((DS.IP, 41000, "10.0.0.1", 443), S.filter_matches(expr, snapshot))

    def test_a_recorded_kill_is_judged(self):
        before = synthetic()
        expr = "( dst 10.0.18.3 and dport = :41002 and sport = :80 )"
        after = synthetic(without=41002)
        self.assertEqual(S.kill_problems(before, after, expr), [])
        self.assertTrue(S.kill_problems(before, before, expr))                     # nothing went
        two = expr + " or ( dst 10.0.18.3 and dport = :41003 and sport = :80 )"
        self.assertTrue(S.kill_problems(before, after, two))                        # two named
        with self.assertRaises(ValueError):
            S.kill_filter_keys("dst 10.0.18.3")                                     # an address filter is refused


class SmokeReadingsTest(unittest.TestCase):
    """Review T-047 P-10, P-14: the worker kills of a control, and who ended which connections."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.run_dir = self.tmp.name

    def write(self, name, text):
        with open(os.path.join(self.run_dir, name), "w", encoding="utf-8") as fh:
            fh.write(text)

    def test_worker_kills_and_nginxs_errors_are_counted(self):
        self.write("gunicorn.log", "[1] [CRITICAL] WORKER TIMEOUT (pid:7)\n[2] [INFO] Booting worker\n[3] [CRITICAL] WORKER TIMEOUT (pid:8)\n")
        self.write("error.log", "x client timed out (110) while reading\ny upstream prematurely closed connection while\n"
                                "z client timed out (110) while reading\n")
        got = S.worker_kills(self.run_dir)
        self.assertEqual((got["worker_kills"], got["error_log"]["client timed out"],
                          got["error_log"]["upstream prematurely closed"]), (2, 2, 1))
        self.assertEqual(S.worker_kills(os.path.join(self.run_dir, "absent"))["worker_kills"], 0)

    def test_who_ended_which_connection(self):
        ents = [{"address": "10.0.18.3", "role": "attack", "kind_or_family": "slowpost", "p4_role": "attack"},
                {"address": "10.0.16.5", "role": "benign", "kind_or_family": "cgnat_browsers", "p4_role": "cgnat"}]
        self.write("manifest.json", json.dumps({"entities": ents}))
        early = line("10.0.18.3", 41000, bytes_acked=1) + line("10.0.18.3", 41001, bytes_acked=1) + \
            line("10.0.18.3", 41002, bytes_acked=1) + line("10.0.18.3", 41003, bytes_acked=1) + \
            line("10.0.16.5", 40001, bytes_acked=5000)
        later = line("10.0.18.3", 41000, bytes_acked=250) + line("10.0.18.3", 41001, bytes_acked=1) + \
            line("10.0.18.3", 41002, bytes_acked=1) + line("10.0.16.5", 40001, bytes_acked=5000)
        last = line("10.0.18.3", 41002, bytes_acked=1) + line("10.0.16.5", 40001, bytes_acked=5000)
        polls = [(1.0, early), (11.0, later), (21.0, last), (31.0, None), (41.0, last)]
        with open(os.path.join(self.run_dir, "slow_pc.jsonl.gz"), "wb") as fh:
            fh.writelines(slow_pc.record_member(t, text, [], [], True) for t, text in polls)
        self.write("ban_events.jsonl", json.dumps({"kind": "slow_pc_close", "enforced": True, "ip": "10.0.18.3", "port": 41001,
                                                   "sport": 80}) + "\n" + "not json\n")
        got = S.connection_summary(self.run_dir)
        post = got["slowpost"]
        self.assertEqual((post["connections"], post["answered_above_64_B"]), (4, 1))
        self.assertEqual(post["ended_by"], {"rule": 1, "held to the end": 1, "answered": 1, "unanswered": 1})
        self.assertEqual(post["lifetime_s"]["max"], 40.0)
        self.assertEqual(got["cgnat"]["ended_by"]["held to the end"], 1)
        self.assertEqual(got["cgnat"]["answered_above_64_B"], 1)

    def test_the_command_line(self):
        self.write("gunicorn.log", "WORKER TIMEOUT\n")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(S.main(["workers", self.run_dir]), 0)
        self.assertEqual(json.loads(out.getvalue())["worker_kills"], 1)


class RecordedFixtureTest(unittest.TestCase):
    """The recordings of the smoke run (P4-S), once committed."""

    def load(self, *names):
        paths = [os.path.join(FIXTURES, n) for n in names]
        if not all(os.path.isfile(p) for p in paths):
            self.skipTest(f"NOT RUN: {', '.join(names)} are recorded by the P4-S smoke run (T3) under {FIXTURES}")
        out = []
        for p in paths:
            with open(p, encoding="utf-8") as fh:
                out.append(json.load(fh) if p.endswith(".json") else fh.read())
        return out

    def test_the_recorded_ss_output_parses_as_the_rule_needs(self):
        text, labels = self.load("ss_tinpH.txt", "labels.json")
        problems, notes = S.fixture_problems(text, labels)
        self.assertEqual(problems, [], notes)

    def test_the_recorded_kill_closed_exactly_the_named_socket(self):
        before, after, expr = self.load("ss_before_kill.txt", "ss_after_kill.txt", "kill_filter.txt")
        self.assertEqual(S.kill_problems(before, after, expr.strip()), [])


class ParserLayoutTest(unittest.TestCase):
    def test_random_token_orders_parse_the_same(self):
        rng = random.Random(5)
        base = synthetic()
        want = S.slow_pc.parse_ss(base)[0]
        lines = base.splitlines(keepends=True)
        for _ in range(20):
            shuffled = []
            for ln in lines:
                if ln.startswith("\t"):
                    toks = ln.split()
                    rng.shuffle(toks)
                    ln = "\t " + " ".join(toks) + "\n"
                shuffled.append(ln)
            self.assertEqual(S.slow_pc.parse_ss("".join(shuffled))[0], want)


if __name__ == "__main__":
    unittest.main()
