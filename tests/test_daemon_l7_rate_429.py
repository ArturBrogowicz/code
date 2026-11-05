"""D-054 (review T-048, T048-07): the daemon's access-log rule beside the enforcing arm. Its error branch bans an address with
no CGNAT guard, no 30-s wait, no rate cap and no kill-switch lift, so with L7_ENFORCE=1 it must not count the arm's own 429s,
or a level-1 deny turns into such a ban. The real main-loop body through tests/daemon_harness.py, as the review's probe
P8; bans_by_engine, for every arm. Offline: fakes only.
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "ml"))
import daemon_harness as H
import test_daemon_l7_enforce as DE
import test_l7_rstar as RS

import ban_events
import l7_arms as L
import l7_conf
import l7_denymap as D
import l7_enforce as A
import l7_engine

IP = "10.0.18.9"
BURST = [(0.04, IP, 429)] * 12                                 # 12 requests in 0.5 s, every one answered 429


class ErrorBranchTest(DE.L7Case):
    def enforcing(self):
        return self.daemon(**DE.ENFORCE)

    def test_a_denied_keys_429s_do_not_ban_it_with_the_arm_on(self):
        d = self.enforcing()
        d.l7_requests(BURST)
        self.assertEqual((d.bans(), d.blacklist.ips()), ([], set()))
        d.l7_requests(BURST * 3)                               # however long it goes on
        self.assertEqual(d.bans(), [])

    def test_without_the_arm_nothing_changes(self):
        d = self.daemon()
        self.assertFalse(d.L7_ENFORCE)
        d.l7_requests(BURST)
        self.assertEqual([(b["ip"], b["engine"]) for b in d.bans()], [(IP, "l7_rate")])

    def test_every_other_error_still_counts_with_the_arm_on(self):
        for status in (400, 403, 404, 500):
            with self.subTest(status=status):
                d = self.enforcing()
                d.l7_requests([(0.04, IP, status)] * 12)
                self.assertEqual([b["engine"] for b in d.bans()], ["l7_rate"])
        d = self.enforcing()
        d.l7_requests([(0.04, IP, 503)] * 12)                  # never an error, with or without the arm
        self.assertEqual(d.bans(), [])

    def test_a_429_is_no_error_for_the_ratio_either(self):
        # 3 errors in 12 requests with the arm on: 25 %, under the branch's 80 %; without it, 100 %
        mixed = [(0.04, IP, 429)] * 9 + [(0.04, IP, 404)] * 3
        d = self.enforcing()
        d.l7_requests(mixed)
        self.assertEqual(d.bans(), [])
        d = self.daemon()
        d.l7_requests(mixed)
        self.assertEqual(len(d.bans()), 1)

    def test_the_rate_branch_is_as_it_was(self):
        # a key above the rule's rate is banned, denied or not; the branch counts requests, not errors
        d = self.enforcing()
        d.l7_requests([(0.01, IP, 429)] * 51)
        self.assertEqual([(b["ip"], b["engine"], b["value"]) for b in d.bans()], [(IP, "l7_rate", 51.0)])

    def test_the_status_is_the_rendered_confs(self):
        self.assertEqual(self.daemon().L7_DENY_STATUS, l7_conf.DENY_STATUS)


class BansByEngineTest(DE.L7Case):
    def test_the_arms_summary_reports_the_daemons_bans_per_engine(self):
        path, sha = RS.write_selection(os.path.join(self._tmpdir(), "sel"), "cost_budget")
        d = self.daemon(**{**DE.ENFORCE, "L7_SELECTION": path, "L7_SELECTION_SHA256": sha, "L7_ARM": L.RSTAR})
        d.ns.update(l7_denymap=D, l7_enforce=A, l7_arms=L, l7_engine=l7_engine)
        d.ns["L7_SOCKET_GROUP"] = os.getgid()
        d.call("l7_enforce_init")
        d.call("l7_enforce_poll")
        self.assertEqual(d.events("l7_enforce_poll")[-1]["bans_by_engine"], {})
        d.call("ban_ip", "10.0.2.1", reason="Per-IP SYN flood (300 SYN/s)", engine="l4_syn")
        d.l7_requests([(0.04, "10.0.2.2", 404)] * 12)
        d.call("ban_ip", "10.0.2.3", reason="L7 v2 arm R*: test", engine=ban_events.L7V2_ENGINE)
        d.call("l7_enforce_stop")                              # the run's last summary, whatever the 5-s report's phase
        last = d.events("l7_enforce_poll")[-1]
        self.assertEqual(last["bans_by_engine"], {"l4_syn": 1, "l7_rate": 1, "l7v2": 1})
        self.assertEqual(ban_events.bans_by_engine(d.events()), last["bans_by_engine"])

    def _tmpdir(self):
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return tmp.name

    def test_a_daemon_without_the_arm_runs_as_before_and_its_log_gives_the_same_reading(self):
        d = H.Daemon({})
        self.addCleanup(d.close)
        d.l7_requests(BURST)
        self.assertEqual(d.events("l7_enforce_poll"), [])
        self.assertEqual(ban_events.bans_by_engine(d.events()), {"l7_rate": 1})
        self.assertEqual(ban_events.bans_by_engine(d.events(), since=d.events("ban")[0]["t_wall"] + 1), {})


if __name__ == "__main__":
    unittest.main()
