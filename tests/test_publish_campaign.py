"""Offline test for eval/publish_campaign.py: a published campaign carries the load the server received
(server_requests.csv), which EXP-C's offered-load table is computed from.

Needs the venv (pandas, scipy, matplotlib):  venv/bin/python -m unittest discover -s tests -v
"""
import csv
import os
import sys
import tempfile
import unittest
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "eval"))
try:
    import publish_campaign as PUB
    from test_campaign_analysis import make_run
    HAVE_STACK = True
except ImportError:                      # system python without pandas/scipy/matplotlib: skip
    HAVE_STACK = False


@unittest.skipUnless(HAVE_STACK, "needs the venv (pandas, scipy, matplotlib)")
class PublishServerRequestsTest(unittest.TestCase):
    def test_publishing_copies_the_server_requests_and_lists_them_in_the_checksums(self):
        with tempfile.TemporaryDirectory() as tmp:
            campaign, repo = os.path.join(tmp, "campaign"), os.path.join(tmp, "repo")
            os.makedirs(os.path.join(repo, "results"))
            for seed in (1, 2):
                make_run(campaign, "xdp", f"run{seed}", seed, [1] * 10)
                make_run(campaign, "unprotected", f"run{seed}", seed, [1] * 5 + [0] * 5)
            with open(os.path.join(campaign, "xdp", "run1", "server_requests.csv"), "w", newline="") as fh:
                w = csv.writer(fh)
                w.writerow(["Data_Scenario", "Mode", "T_Epoch_s", "T_Rel_s", "Client_Class", "Status", "Requests",
                            "Request_Time_Mean_s", "Request_Time_Max_s"])
                w.writerow(["Distributed HTTP Flood", "xdp", 1000, 0, "bot", "200", 5, 0.001, 0.002])
            with mock.patch.object(PUB, "REPO", repo), \
                    mock.patch.object(sys, "argv", ["publish_campaign.py", campaign, "--name", "demo"]), \
                    mock.patch("builtins.print"):
                PUB.main()
            published = os.path.join(repo, "results", "demo")
            copied = os.path.join(published, "xdp", "run1", "server_requests.csv")
            self.assertTrue(os.path.isfile(copied))
            self.assertFalse(os.path.exists(os.path.join(published, "xdp", "run2", "server_requests.csv")))
            with open(os.path.join(published, "SHA256SUMS")) as fh:
                self.assertIn("  xdp/run1/server_requests.csv\n", fh.read())


if __name__ == "__main__":
    unittest.main()
