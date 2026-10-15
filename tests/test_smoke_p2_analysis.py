"""Offline test of the P2 gate analysis (ml/smoke_l7.py analyse_p2). No VM, no traffic.

A simulated daemon session writes a recording and events exactly like the live
shadow monitor, and is "killed" after its last summary: polls (and possible
would-bans) recorded after the last summary must be cut, and the rest must replay
to the identical decisions.
"""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l7_testutil as U

sys.path.insert(0, os.path.join(U.REPO, "ml"))
import smoke_l7
import torch

import ban_events
import l7_engine as E
import l7_ingest

torch.set_num_threads(1)


class AnalyseP2Test(unittest.TestCase):
    def test_cut_at_last_summary_and_replay_matches(self):
        d = tempfile.mkdtemp(prefix="p2ana_")
        self.addCleanup(shutil.rmtree, d, True)
        pkg = smoke_l7.make_untrained_package(os.path.join(d, "pkg"))
        events_path = os.path.join(d, "ban_events.jsonl")
        record_path = os.path.join(d, "l7_record.jsonl")
        ev = ban_events.EventLog(events_path)
        rec = E.EngineRecorder(record_path)
        eng = E.build_engine(pkg)
        t0 = 1_800_000_000.0                      # simulated clock, not wall time
        for step in range(30):
            now = t0 + step
            for ip, meth, ua in (("10.0.2.9", "POST", "bot"), ("10.0.1.9", "GET", "browser")):
                o = U.obj(ip=ip, method=meth, ua=ua, msec=now - 0.2, uri=f"/{step % 3}")
                rec.record(o, now - 0.2)
                eng.on_record(l7_ingest.normalise(o))
            suppressing = 10 <= step < 14
            rec.poll(now, suppressing, ())
            for e in eng.poll(now, suppressing, ()):
                if e.pop("kind") == "l7_would_ban":
                    ev.emit("l7_would_ban", **e)
            if step % 5 == 4 and step < 25:       # the last summary covers poll 24
                ev.emit("l7_gru_poll", **eng.take_summary())
        rec.close()                               # killed: no exit-time summary
        ev.close()

        res = smoke_l7.analyse_p2(d, events_path, record_path, pkg)
        self.assertTrue(res["determinism"]["match"], res["determinism"])
        self.assertLess(res["replayed_lines"], res["recorded_lines"])   # polls 25-29 cut
        self.assertEqual(res["live_totals"]["polls"], 25)
        self.assertEqual(res["live_totals"]["suppressed_polls"], 4)
        for name in ("ua_swap", "uri_bijection", "time_offset"):
            self.assertTrue(res["probes"][name]["pass"], (name, res["probes"][name]))
        self.assertTrue(os.path.getsize(res["windows_csv"]) > 0)
        self.assertEqual(res["non_deterministic_bans"], [])


if __name__ == "__main__":
    unittest.main()
