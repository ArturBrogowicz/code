"""L7 v2 benign sessions (ml/l7_benign.py session_users; ml/l7v2_prereg.json arrivals.lifetimes, re-registered 2026-10-31
under D-034, review T-038 finding T038-01): a benign key lives one session, sessions end and new ones begin throughout the
run, and a returning user is a new key. Offline and pure."""
import itertools
import os
import random
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "ml"), os.path.join(REPO, "eval")):
    sys.path.insert(0, _p)
import l7_benign as B
import l7v2_prereg

import l7_webapp

RULE = l7v2_prereg.load()["arrivals"]["lifetimes"]
TP = {"level": 30, "first_visit_s": [0.0, 10.0], "think_mean_s": 7.4}


def plan(kind, params, duration=900.0, seed=5):
    return B.plan_client(kind, params, duration, random.Random(seed))


class SessionTest(unittest.TestCase):
    def check_sessions(self, users, duration, ua=None):
        starts = [u["views"][0]["t"] for u in users if u["views"]]
        self.assertEqual(starts, sorted(starts))
        for a, b in itertools.pairwise(users):
            if a["views"] and b["views"]:
                self.assertGreaterEqual(b["views"][0]["t"] - a["views"][-1]["t"], RULE["gap_s"][0] - 1e-6)
        for u in users:
            if ua is not None:
                self.assertEqual(u["ua"], ua, "the device keeps its UA")
            ts = [v["t"] for v in u["views"]]
            self.assertLessEqual(ts[-1] - ts[0], RULE["law"]["hi"])
            self.assertLess(ts[-1], duration)
        for u in users[1:]:
            self.assertGreaterEqual(duration - u["views"][0]["t"], RULE["min_left_s"] - 1e-6)

    def test_a_device_runs_sessions_each_with_a_fresh_browser_state(self):
        p = plan("tpcw_browsing", {**TP, "sessions": True})
        users = p["users"]
        self.assertGreater(len(users), 1)
        self.check_sessions(users, 900.0, ua=users[0]["ua"])
        wave1, _fonts = l7_webapp.site_assets(30)
        for k, u in enumerate(users):
            self.assertEqual((u["device"], u["session"]), (0, k))
            first = u["views"][0]
            self.assertIsNone(first["ref"], "a session starts with a direct navigation")
            self.assertEqual(first["waves"][0], ["/"], "a TPC-W session starts at Home")
            self.assertEqual(sorted(first["waves"][1]), sorted(wave1), "an empty cache: the first view loads every asset")

    def test_every_l7v2_session_kind(self):
        for kind in ("tpcw_shopping", "zipf_browser", "search_user", "exporter", "flash_crowd"):
            with self.subTest(kind=kind):
                users = plan(kind, {**TP, "sessions": True}, seed=11)["users"]
                self.assertTrue(users)
                self.check_sessions([u for u in users if u["views"]], 900.0, ua=users[0]["ua"])

    def test_a_cgnat_users_sessions(self):
        p = plan("cgnat_browsers", {"users": 12, "level": 30, "first_visit_s": [0.0, 600.0], "nav": "tpcw:browsing",
                                    "sessions": True})
        devices = {}
        for u in p["users"]:
            devices.setdefault(u["device"], []).append(u)
        self.assertEqual(sorted(devices), list(range(12)))
        for users in devices.values():
            self.assertEqual([u["session"] for u in users], list(range(len(users))))
            self.check_sessions(users, 900.0, ua=users[0]["ua"])
        self.assertGreater(len(p["users"]), 12)

    def test_without_the_flag_the_plan_is_unchanged(self):
        for kind in ("tpcw_browsing", "search_user", "exporter", "cgnat_browsers"):
            params = {**TP, "users": 3, "nav": "tpcw:browsing"} if kind == "cgnat_browsers" else dict(TP)
            with self.subTest(kind=kind):
                a = plan(kind, params)
                self.assertEqual(len(a["users"]), 3 if kind == "cgnat_browsers" else 1)
                self.assertFalse(any("session" in u for u in a["users"]))

    def test_the_harm_replay_sees_every_session(self):
        import l7v2_harm
        e = {"kind_or_family": "tpcw_browsing", "params": {**TP, "sessions": True}, "client_seed": 5}
        planned = l7v2_harm.planned_views(e, 900.0)
        users = plan("tpcw_browsing", {**TP, "sessions": True})["users"]
        self.assertEqual({u for u, _v in planned}, set(range(len(users))))
        self.assertEqual(planned[(1, 0)][0], users[1]["views"][0]["t"], "a session's first view is due at its start")


if __name__ == "__main__":
    unittest.main()
