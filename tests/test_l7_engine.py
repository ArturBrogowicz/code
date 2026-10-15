"""Unit tests for l7_engine.py (shadow decision engine; Phase P2). Offline.

A deterministic stub scorer (window mostly POST → p 0.99, else 0.01) drives the
decision policy; detection quality is out of scope until a model is trained (P4).
"""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l7_testutil as U

import l7_engine as E
import l7_ingest

BOT = "10.0.2.1"
USER = "10.0.1.1"


def engine(scorer=None, min_events=3, idle=60.0, **kw):
    store = l7_ingest.L7WindowStore(maxlen=20, idle_timeout=idle)
    return E.L7ShadowEngine(store, scorer=scorer, min_events=min_events, **kw)


def add(eng, ip, n, t, method="POST", ua="bot", step=0.1):
    for i in range(n):
        eng.on_record(U.rec(ip=ip, ua=ua, method=method, msec=t + i * step))


class PolicyTest(unittest.TestCase):
    def test_would_ban_once_after_consecutive_hits(self):
        stub = U.StubScorer()
        eng = engine(stub)
        add(eng, BOT, 3, 1.0)
        self.assertEqual(eng.poll(1.5), [])                 # hit 1
        add(eng, BOT, 1, 2.0)
        self.assertEqual(eng.poll(2.5), [])                 # hit 2
        add(eng, BOT, 1, 3.0)
        evs = eng.poll(3.5)                                 # hit 3 → would-ban
        self.assertEqual(len(evs), 1)
        ev = evs[0]
        self.assertEqual((ev["kind"], ev["ip"], ev["hits"]), ("l7_would_ban", BOT, 3))
        self.assertEqual(ev["n_events"], 5)
        self.assertFalse(ev["ip_banned"])
        add(eng, BOT, 1, 4.0)
        self.assertEqual(eng.poll(4.5), [])                 # hit 4: no repeat event
        self.assertEqual(eng.totals["would_bans"], 1)

    def test_streak_resets_below_threshold(self):
        eng = engine(U.StubScorer())
        add(eng, BOT, 3, 1.0)
        eng.poll(1.5)
        add(eng, BOT, 4, 2.0, method="GET")                 # window now mostly GET → p low
        eng.poll(2.5)
        self.assertEqual(eng.hits[(BOT, l7_ingest.stable_hash32("bot"))], 0)

    def test_only_dirty_keys_scored_in_one_batch(self):
        stub = U.StubScorer()
        eng = engine(stub)
        add(eng, BOT, 3, 1.0)
        add(eng, USER, 3, 1.0, method="GET", ua="browser")
        eng.poll(1.5)
        add(eng, BOT, 1, 2.0)                               # only BOT changes
        eng.poll(2.5)
        self.assertEqual(stub.calls, [2, 1])                # one call per poll

    def test_min_events_and_ip_banned_flag(self):
        eng = engine(U.StubScorer(consecutive=1), min_events=4)
        add(eng, BOT, 3, 1.0)
        self.assertEqual(eng.poll(1.5), [])
        self.assertEqual(eng.take_summary()["too_short"], 1)
        add(eng, BOT, 1, 2.0)
        evs = eng.poll(2.5, banned={BOT})
        self.assertTrue(evs and evs[0]["ip_banned"])

    def test_keys_split_by_user_agent(self):
        stub = U.StubScorer()
        eng = engine(stub)
        add(eng, BOT, 3, 1.0, ua="A")
        add(eng, BOT, 3, 1.0, ua="B", method="GET")
        eng.poll(1.5)
        self.assertEqual(stub.calls, [2])                   # same IP, two windows


class FeaturesOnlyTest(unittest.TestCase):
    def test_counts_windows_without_scoring(self):
        seen = []
        eng = engine(None, window_hook=lambda now, key, recs, p: seen.append(p))
        add(eng, BOT, 3, 1.0)
        self.assertEqual(eng.poll(1.5), [])
        s = eng.take_summary()
        self.assertEqual((s["windows"], s["model"], s["max_p"]), (1, None, None))
        self.assertEqual(seen, [None])


class GatingTest(unittest.TestCase):
    def test_suppression_pauses_scoring_and_forgets_streaks(self):
        stub = U.StubScorer()
        eng = engine(stub)
        add(eng, BOT, 3, 1.0)
        eng.poll(1.5)                                       # hit 1
        self.assertEqual(eng.hits[(BOT, l7_ingest.stable_hash32("bot"))], 1)
        add(eng, BOT, 1, 2.0)
        self.assertEqual(eng.poll(2.5, suppressing=True), [])
        self.assertEqual(eng.hits, {})                      # streaks forgotten
        self.assertEqual(stub.calls, [1])                   # nothing scored while suppressing
        self.assertEqual(eng.take_summary()["suppressed_polls"], 1)

    def test_age_gate_after_flood(self):
        eng = engine(U.StubScorer())
        add(eng, BOT, 3, 10.0)                              # requests during the flood
        eng.poll(10.5, suppressing=True)
        eng.poll(11.0)                                      # flood over: trust_after = 11.0
        self.assertEqual(eng.trust_after, 11.0)
        add(eng, BOT, 1, 11.5)                              # 3 old + 1 new → 75 % old → gated
        eng.poll(12.0)
        s = eng.take_summary()
        self.assertEqual((s["gated_age"], s["windows"]), (1, 0))
        add(eng, BOT, 3, 12.5)                              # 3 old + 4 new → 43 % old → scored
        eng.poll(13.0)
        s = eng.take_summary()
        self.assertEqual((s["gated_age"], s["windows"]), (0, 1))


class EvictionTest(unittest.TestCase):
    def test_idle_keys_evicted_inside_poll(self):
        eng = engine(U.StubScorer(), idle=10.0, evict_every=5.0)
        add(eng, BOT, 3, 100.0)
        eng.poll(100.5)                                     # starts the eviction clock
        eng.poll(106.0)                                     # idle 6 s: kept
        self.assertEqual(eng.store.stats()["active_keys"], 1)
        eng.poll(112.0)                                     # idle 12 s: evicted
        self.assertEqual(eng.store.stats()["active_keys"], 0)
        self.assertEqual(eng.hits, {})


class SummaryTest(unittest.TestCase):
    def test_summary_top_and_reset(self):
        eng = engine(U.StubScorer(), top_k=1)
        add(eng, BOT, 3, 1.0)
        add(eng, USER, 3, 1.0, method="GET", ua="browser")
        eng.poll(1.5)
        s = eng.take_summary()
        self.assertEqual(len(s["top"]), 1)
        self.assertEqual(s["top"][0]["ip"], BOT)            # the highest p first
        self.assertEqual(s["model"], "stub")
        self.assertEqual(s["t_last_poll"], 1.5)             # the replay cut point
        empty = eng.take_summary()                          # reset after take
        self.assertEqual((empty["windows"], empty["t_last_poll"]), (0, None))


class RecordReplayTest(unittest.TestCase):
    """A recorded session replayed through a fresh engine reproduces its decisions."""

    def test_replay_is_deterministic(self):
        sys.path.insert(0, os.path.join(U.REPO, "ml"))
        import replay_l7

        d = tempfile.mkdtemp(prefix="l7rec_")
        self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, "rec.jsonl")
        rec = E.EngineRecorder(path)
        live = engine(U.StubScorer())
        events = []
        t = 1000.0
        for step in range(40):                  # 40 polls, a flood from poll 15 to 20
            now = t + step
            for ip, meth, ua in ((BOT, "POST", "bot"), (USER, "GET", "browser")):
                o = U.obj(ip=ip, method=meth, ua=ua, msec=now - 0.3)
                rec.record(o, now - 0.3)
                live.on_record(l7_ingest.normalise(o))
            suppressing = 15 <= step < 20
            rec.poll(now, suppressing, (USER,) if step > 30 else ())
            events.extend(live.poll(now, suppressing, (USER,) if step > 30 else ()))
            if step % 5 == 4:
                events.append({"kind": "l7_gru_poll", **live.take_summary()})
        events.append({"kind": "l7_gru_poll", "final": True, **live.take_summary()})
        rec.close()

        with open(path, encoding="utf-8") as fh:
            replayed = replay_l7.replay(E.read_stream(fh), engine(U.StubScorer()))
        cmp = replay_l7.compare_live(events, replayed)
        self.assertTrue(cmp["match"], cmp)
        self.assertGreater(cmp["would_bans_live"], 0)       # the session exercised bans
        self.assertGreater(cmp["live"]["suppressed_polls"], 0)


if __name__ == "__main__":
    unittest.main()
