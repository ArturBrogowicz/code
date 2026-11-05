"""The L7 shadow thread with an L7 v2 view engine (L7_SHADOW=1 and a view package), on the fakes of
tests/daemon_harness.py: the real l7_shadow_monitor reads scripted datagrams through the real L7ViewEngine (a stub
scorer). Before the fix, its 5-s `l7_shadow` report passed `truncated` twice (the ingest counters' truncated
datagrams and the key store's truncated keys): TypeError, a supervised restart every 5 s, and the engine's state lost
each time, so a key needed its 4 views within 5 s to be scored at all. The fixtures here serve
tests/test_daemon_l7_enforce.py too. Offline: nothing is imported from control_plane.py.
"""
import json
import os
import sys
import types
import unittest

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, REPO)
import daemon_harness as H

import l7_engine
import l7_features as F
import l7_ingest

BOT, BROWSER, POOL = "10.0.17.5", "10.0.16.5", "10.0.18.9"
BOT_UA = "Bot/2.0 (compatible, deep-linker)"
SID, SID2, SID3 = "b" * 32, "c" * 32, "d" * 32


class RefStub:
    """A view-level model stub: p = 0.99 for a window whose pages mostly name no known Referer (a deep-linking bot),
    else 0.01. Its package metadata names the arm."""

    level = "view"

    def __init__(self, threshold=0.5, consecutive=2):
        self.cols, self.max_views, self.seq_len = list(F.TOKEN_COLUMNS), 8, 8
        self.threshold, self.consecutive, self.sha256 = threshold, consecutive, "5" * 64
        self.cfg = {"meta": {"arm": "view_gru"}}
        self.calls = []

    def score(self, batch):
        batch = np.asarray(batch, np.float32)
        self.calls.append(len(batch))
        j, valid = self.cols.index("ref_known"), batch[..., 0]
        mean = (batch[..., j] * valid).sum(axis=1) / np.maximum(valid.sum(axis=1), 1)
        return np.where(mean < 0.5, 0.99, 0.01).astype(np.float32)


def rec(ip, uri, start, ua=BOT_UA, sid=SID, ref="", rt=0.02):
    """One l7json record as nginx.conf logs it."""
    return {"msec": round(start + rt, 3), "ip": ip, "port": 40000, "method": "GET", "uri": uri, "status": 200,
            "rt": rt, "ua": ua, "ref": ref, "sid": sid, "sid_set": ""}


def bot(ip=BOT, t0=1000.0, until=1100.0, gap=3.0, sid=SID, ua=BOT_UA):
    """A deep-linking bot: a page with no Referer every `gap` s, then a search from it."""
    out, n = [], 0
    while t0 + gap * n < until:
        t = t0 + gap * n
        out += [rec(ip, f"/page/{100 + n}", t, ua=ua, sid=sid),
                rec(ip, "/search?q=alpha", t + 0.3, ua=ua, sid=sid, ref=f"http://10.0.0.1/page/{100 + n}")]
        n += 1
    return out


def browser(ip=BROWSER, t0=1000.5, until=1100.0, gap=6.0, sid=SID2, ua="Mozilla/5.0 Browser"):
    """A browser that follows its own links: every page names the previous one."""
    out, prev, n = [], None, 0
    while t0 + gap * n < until:
        page = "/" if n == 0 else f"/page/{n % 3}"
        out.append(rec(ip, page, t0 + gap * n, ua=ua, sid=sid, ref=f"http://10.0.0.1{prev}" if prev else ""))
        out.append(rec(ip, f"/static/site6/p{n}/img0.png", t0 + gap * n + 0.2, ua=ua, sid=sid,
                       ref=f"http://10.0.0.1{page}"))
        prev, n = page, n + 1
    return out


class FakeReader:
    """The L7 socket: yields the scripted datagrams in time order, with an idle timeout (None) every second, moving the
    daemon's clock; `tick(t)` runs at each whole second (where the enforcing arm's thread steps)."""

    rcvbuf = 4 << 20

    def __init__(self, d, records, until, tick=None):
        self.d, self.tick, self.closed = d, tick, False
        items = [(r["msec"], json.dumps(r).encode()) for r in records]
        items += [(float(t) + 0.999, None) for t in range(int(d.clock.now), int(until) + 1)]
        self.items = sorted(items, key=lambda x: x[0])

    def messages(self, stop=None, timeout=0.5, yield_timeouts=False):
        second = int(self.d.clock.now)
        for t, data in self.items:
            while int(t) > second:
                second += 1
                self.d.clock.now = max(self.d.clock.now, float(second))
                if self.tick:
                    self.tick(second)
            self.d.clock.now = max(self.d.clock.now, t)
            yield data

    def close(self):
        self.closed = True


def run_shadow(d, records, until, scorer=None, tick=None):
    """The daemon's real l7_shadow_monitor over `records` through a real L7ViewEngine, scored by the detector the
    daemon hands build_engine (the enforcing arm's), else by `scorer` (a RefStub by default); returns the engine."""
    built = []

    def build_engine(_model=None, scorer=None, default=scorer):
        built.append(l7_engine.L7ViewEngine(l7_ingest.L7KeyStore(max_views=8), scorer=scorer or default or RefStub()))
        return built[-1]
    reader = FakeReader(d, records, until, tick)
    ingest = types.SimpleNamespace(**{k: getattr(l7_ingest, k) for k in dir(l7_ingest) if not k.startswith("__")})
    d.reader_calls = []
    ingest.SyslogDatagramReader = lambda path, **kw: d.reader_calls.append((path, kw)) or reader
    d.ns["l7_ingest"] = ingest
    d.ns["l7_engine"] = types.SimpleNamespace(build_engine=build_engine, EngineRecorder=l7_engine.EngineRecorder)
    d.call("l7_shadow_monitor", "/run/ddos_l7.sock")
    return built[-1]


class ViewShadowReportTest(unittest.TestCase):
    def test_the_shadow_thread_reports_a_view_engine_and_keeps_its_state(self):
        d = H.Daemon({"L7_SHADOW": "1"})
        self.addCleanup(d.close)
        d.clock.now = 999.0
        engine = run_shadow(d, bot() + browser(), until=1060.0)
        reports = d.events("l7_shadow")
        self.assertGreaterEqual(len(reports), 11)                       # every 5 s over 60 s, one engine throughout
        self.assertEqual({r["truncated"] for r in reports}, {0})        # the ingest's truncated datagrams
        self.assertEqual({r["store_truncated"] for r in reports}, {0})  # the key store's truncated keys
        self.assertEqual(reports[-1]["active_keys"], 2)
        [wb] = d.events("l7_would_ban")
        self.assertEqual((wb["ip"], wb["level"]), (BOT, "view"))
        self.assertEqual(engine.totals["would_bans"], 1)


class HostileFieldTypesTest(unittest.TestCase):
    """T-042 E07: a text field of another JSON type (only a forged datagram can carry one) used to raise in normalise,
    or make the engine's dirty keys unsortable, and so restart the shadow thread with a fresh engine."""

    HOSTILE = ({"ip": 167772161}, {"ip": ["10.0.17.5"]}, {"ua": 7}, {"ua": ["x"]}, {"uri": {"a": 1}},
               {"sid": 12345}, {"sid_set": True}, {"method": 1.5}, {"ref": ["http://x/"]}, {"client_ip": 1})

    def test_normalise_drops_them_and_keeps_nginxs_records_as_they_were(self):
        good = rec(BOT, "/page/1", 1000.0)
        base = l7_ingest.normalise(good)
        for bad in self.HOSTILE:
            with self.subTest(bad=bad):
                self.assertIsNone(l7_ingest.normalise({**good, **bad}))
        self.assertEqual(l7_ingest.normalise(dict(good)), base)
        self.assertEqual(l7_ingest.normalise({**good, "sid": None, "ref": None})["sid_h"], l7_ingest.NO_SID)

    def test_the_shadow_thread_keeps_its_engine_through_them(self):
        d = H.Daemon({"L7_SHADOW": "1"})
        self.addCleanup(d.close)
        d.clock.now = 999.0
        hostile = [{**rec(BOT, "/page/1", 1000.0 + 2 * n), **bad} for n, bad in enumerate(self.HOSTILE * 3)]
        engine = run_shadow(d, bot() + browser() + hostile, until=1060.0)
        [wb] = d.events("l7_would_ban")
        self.assertEqual((wb["ip"], engine.totals["would_bans"]), (BOT, 1))
        self.assertEqual(d.events("daemon_error"), [])
        self.assertEqual({type(k[0]) for k in engine.store._recs}, {str})


class HostileNumbersTest(unittest.TestCase):
    """T048-09: {"msec": 1e999} gave inf and a ZeroDivisionError in the rules' statistics; {"msec": 10**400} an OverflowError in
    l7_ingest._num for every arm. Each restarted the shadow thread with a fresh engine."""

    NUMBERS = (1e999, -1e999, 10**400, -(10**400), float("nan"), "nan", "inf", "1e999")

    def test_normalise_drops_a_record_with_a_non_finite_number_in_any_numeric_field(self):
        good = rec(BOT, "/page/1", 1000.0)
        base = l7_ingest.normalise(good)
        for field in ("msec", "rt", "status", "conn", "creq", "uct", "urt", "rlen", "bsent"):
            for bad in self.NUMBERS:
                with self.subTest(field=field, bad=str(bad)[:12]):
                    self.assertIsNone(l7_ingest.normalise({**good, field: bad}))
        self.assertEqual(l7_ingest.normalise(dict(good)), base)
        self.assertEqual(l7_ingest.normalise({**good, "urt": "-", "uct": "0.1, 0.2"})["uct"], 0.1 + 0.2)   # as before

    def hostile(self, bot_at=1000.0):
        out = []
        for n, bad in enumerate(self.NUMBERS * 3):
            for field in ("msec", "rt"):
                r = {**rec(BOT, "/export", bot_at + 2 * n), field: bad}
                out.append({**r, "msec": bot_at + 2 * n} if field == "rt" else r)
        return out

    def daemon(self):
        d = H.Daemon({"L7_SHADOW": "1"})
        self.addCleanup(d.close)
        d.clock.now = 999.0
        return d

    def test_the_view_engine_keeps_its_state_through_them(self):
        d = self.daemon()
        reader = FakeReader(d, bot() + browser(), 1060.0)
        for r in self.hostile():
            reader.items.append((r["msec"] if isinstance(r["msec"], float) and r["msec"] == r["msec"] and abs(r["msec"]) < 1e9
                                 else 1000.0, json.dumps(r).encode()))
        reader.items.sort(key=lambda x: x[0])
        engine = l7_engine.L7ViewEngine(l7_ingest.L7KeyStore(max_views=8), scorer=RefStub())
        ingest = types.SimpleNamespace(**{k: getattr(l7_ingest, k) for k in dir(l7_ingest) if not k.startswith("__")})
        ingest.SyslogDatagramReader = lambda _path, **_kw: reader
        d.ns["l7_ingest"] = ingest
        d.ns["l7_engine"] = types.SimpleNamespace(build_engine=lambda *_a, **_k: engine, EngineRecorder=l7_engine.EngineRecorder)
        d.call("l7_shadow_monitor", "/run/ddos_l7.sock")               # it would raise through here before the fix
        [wb] = d.events("l7_would_ban")
        self.assertEqual((wb["ip"], engine.totals["would_bans"]), (BOT, 1))
        self.assertEqual(d.events("daemon_error"), [])


if __name__ == "__main__":
    unittest.main()
