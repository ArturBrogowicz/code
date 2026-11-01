"""kill_zombie_connections has a timeout (review T-039 V-08): the per-connection rule's thread calls it after each
ban, so a hung `ss -K dst <ip>` must neither block nor raise. On the fakes of tests/daemon_harness.py; nothing is
imported from control_plane.py and no `ss` runs."""
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import daemon_harness as H

IP = "10.0.3.1"


class KillTimeoutTest(unittest.TestCase):
    def setUp(self):
        self.d = H.Daemon({})
        self.addCleanup(self.d.close)

    def test_the_call_has_a_two_second_timeout(self):
        seen, run = [], self.d.proc.run

        def spy(argv, **kw):
            seen.append((list(argv), kw.get("timeout")))
            return run(argv, **kw)
        self.d.proc.run = spy
        self.d.call("kill_zombie_connections", IP)
        self.assertEqual(seen, [(["ss", "-K", "dst", IP], 2)])

    def test_a_hung_call_is_given_up_without_raising(self):
        self.d.proc.failures[("ss", "-K", "dst")] = subprocess.TimeoutExpired(["ss", "-K", "dst", IP], 2)
        self.d.call("kill_zombie_connections", IP)             # returns: the caller's ban stands
        self.assertEqual(self.d.proc.matching("ss", "-K", "dst"), [["ss", "-K", "dst", IP]])


if __name__ == "__main__":
    unittest.main()
