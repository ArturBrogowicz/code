"""T048-10: RuleStats' per-address table of keys is bounded, in O(1) per request, and exact up to its bound. A client rotating its
cookie used to make every request O(n) once above 4,096 keys inside the lookback. Offline."""
import os
import random
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "ml"))
import l7v2_rules as R

IP = "10.0.18.9"
COSTS = {"C1": 8.0}


def record(t, sid):
    return {"msec": t, "rt": 0.01, "ip": IP, "ua_h": 1, "sid_h": sid, "rc": "C1", "status": 200}


class SeenTableTest(unittest.TestCase):
    def test_a_client_rotating_its_cookie_cannot_grow_it(self):
        stats = R.RuleStats(COSTS)
        for n in range(R.SEEN_MAX * 2 + 500):
            stats.observe(record(1000.0 + n * 0.001, n))
            if n % 100 == 0:
                stats.poll()
        stats.poll()
        self.assertEqual(len(stats._ip[IP]["seen"]), R.SEEN_MAX)
        self.assertEqual(R.SEEN_MAX, 4096)

    def test_up_to_its_bound_it_answers_as_an_unbounded_table_does(self):
        rng = random.Random(10)
        t, truth = 1000.0, {}
        stats = R.RuleStats(COSTS)
        for _n in range(20000):
            t += rng.expovariate(1 / 0.05)
            sid = rng.randrange(1500)                                  # below the bound, with returns past the lookback
            if rng.random() < 0.02:
                t += 310.0
            v2 = (IP, 1, sid)
            new = v2 not in truth or t - truth[v2] > stats.lookback
            truth[v2] = t
            stats.observe(record(t, sid))
            stats.poll()
            self.assertEqual(new, stats._ip[IP]["pop"][-1][1])

    def test_it_stays_ordered_by_last_seen_so_the_oldest_goes_first(self):
        stats = R.RuleStats(COSTS)
        for n in range(R.SEEN_MAX):
            stats.observe(record(1000.0 + n * 0.001, n))
        stats.observe(record(1010.0, 0))                               # key 0 comes back: now the most recent
        stats.observe(record(1010.1, R.SEEN_MAX + 1))                  # one too many: key 1 goes, not key 0
        stats.poll()
        seen = stats._ip[IP]["seen"]
        self.assertIn((IP, 1, 0), seen)
        self.assertNotIn((IP, 1, 1), seen)


if __name__ == "__main__":
    unittest.main()
