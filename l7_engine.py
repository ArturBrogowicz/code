"""Shadow decision engine for the L7 GRU (docs/L7_GRU_DESIGN.md §5.6, §8; Phase P2).

OBSERVE-ONLY. The engine never bans and has no access to the ban path. It
returns `l7_would_ban` events that the daemon logs, so the L7 GRU can be judged on
live and replayed traffic before it is ever allowed to enforce (P6).

Per poll (the daemon polls every ~1 s):
  1. Idle keys are evicted on a fixed cadence of the poll clock.
  2. Load awareness (§5.6):
     * Flood suppression: while the L3/L4 engines report a volumetric flood, the
       engine scores nothing and forgets hit streaks.
     * Age gate: after the flood, windows whose requests mostly started before the
       flood ended are skipped (their timing was distorted by the flood).
  3. Every key that received requests since the last poll and holds >= min_events
     requests is encoded (l7_features) and scored in ONE batch.
  4. Decision policy: P(attack) > threshold in `consecutive` successively scored
     windows of a key → one `l7_would_ban` (the key is (IP, ua_hash); a real ban
     would map to the IP, which XDP enforces on).

With no model package the engine runs features-only: it builds the matrices (so its
cost is measured) but scores nothing.

Determinism: windows are scored in sorted key order, and eviction runs inside
poll(), so the same stream of records and poll ticks gives the same events. The
recording format below captures exactly that stream (records, plus poll ticks
with the flood state and the banned IPs), and ml/replay_l7.py replays it.
"""
import json

import numpy as np

import l7_features as F
import l7_ingest

DEFAULT_MIN_EVENTS = 5
DEFAULT_THRESHOLD = 0.95
DEFAULT_CONSECUTIVE = 3
DEFAULT_EVICT_EVERY = 5.0      # s of poll clock
CONTAMINATION_MAX = 0.5        # age gate: skip windows with more pre-trust requests than this


class L7ShadowEngine:
    def __init__(self, store, scorer=None, cols=None, seq_len=None,
                 min_events=DEFAULT_MIN_EVENTS, threshold=None, consecutive=None,
                 top_k=5, evict_every=DEFAULT_EVICT_EVERY, window_hook=None):
        self.store = store
        self.scorer = scorer
        # Optional callback hook(now, key, records, p) for every window that reaches
        # scoring (p is None in features-only mode); replay/analysis tools use it.
        self.window_hook = window_hook
        if scorer is not None:
            self.cols = list(scorer.cols)
            self.seq_len = scorer.seq_len
            default_thr, default_cons = scorer.threshold, scorer.consecutive
        else:
            self.cols = list(cols) if cols else F.columns()
            self.seq_len = seq_len or store.maxlen
            default_thr, default_cons = DEFAULT_THRESHOLD, DEFAULT_CONSECUTIVE
        self.threshold = default_thr if threshold is None else float(threshold)
        self.consecutive = default_cons if consecutive is None else int(consecutive)
        self.min_events = min_events
        self.top_k = top_k
        self.evict_every = evict_every
        self.dirty = set()
        self.hits = {}
        self.trust_after = 0.0
        self.was_suppressing = False
        self._last_evict = None
        self._agg = self._new_agg()
        self.totals = {"polls": 0, "windows": 0, "would_bans": 0}

    @staticmethod
    def _new_agg():
        # t_last_poll: the poll clock of the last poll this aggregate covers, so a
        # replay can be cut exactly where a (possibly killed) live run's summaries end.
        return {"polls": 0, "suppressed_polls": 0, "windows": 0, "too_short": 0,
                "gated_age": 0, "over": 0, "would_bans": 0, "evicted": 0,
                "max_p": None, "t_last_poll": None, "_top": {}}

    def on_record(self, rec, now=None):
        """Add a normalised record (l7_ingest.normalise); mark its key for scoring."""
        key = self.store.add(rec, now=now)
        self.dirty.add(key)
        return key

    def contaminated_share(self, records):
        """Share of a window's requests that started before the last flood ended."""
        if not self.trust_after:
            return 0.0
        return sum(1 for r in records if F.start_time(r) < self.trust_after) / len(records)

    def poll(self, now, suppressing=False, banned=()):
        """Run one decision step at wall time `now`; return a list of event dicts
        (each with a "kind"). `suppressing` is the L3/L4 flood state; `banned` the
        IPs already banned by any engine (recorded in would-ban events, not used
        for the decision)."""
        agg = self._agg
        agg["polls"] += 1
        agg["t_last_poll"] = now
        self.totals["polls"] += 1
        if self._last_evict is None:
            self._last_evict = now
        elif now - self._last_evict >= self.evict_every:
            for key in self.store.evict_keys(now):
                self.hits.pop(key, None)
                self.dirty.discard(key)
                agg["evicted"] += 1
            self._last_evict = now

        if suppressing:
            if not self.was_suppressing:
                self.hits.clear()            # a flood began: streaks are unreliable
            self.was_suppressing = True
            agg["suppressed_polls"] += 1
            self.dirty.clear()
            return []
        if self.was_suppressing:             # the flood just ended
            self.trust_after = now
            self.was_suppressing = False

        ready = []
        for key in sorted(self.dirty):       # sorted: deterministic batch composition
            window = self.store.window(key)
            if not window or len(window) < self.min_events:
                agg["too_short"] += 1
                continue
            recs = list(window)
            if self.contaminated_share(recs) > CONTAMINATION_MAX:
                agg["gated_age"] += 1
                continue
            ready.append((key, recs))
        self.dirty.clear()
        if not ready:
            return []
        batch = np.stack([F.window_matrix(r, self.seq_len, self.cols) for _, r in ready])
        agg["windows"] += len(ready)
        self.totals["windows"] += len(ready)
        if self.scorer is None:              # features-only shadow
            if self.window_hook is not None:
                for key, recs in ready:
                    self.window_hook(now, key, recs, None)
            return []

        events = []
        banned = set(banned)
        for (key, recs), p in zip(ready, self.scorer.score(batch), strict=True):
            p = float(p)
            if self.window_hook is not None:
                self.window_hook(now, key, recs, p)
            over = p > self.threshold
            hits = self.hits.get(key, 0) + 1 if over else 0
            self.hits[key] = hits
            agg["over"] += over
            if agg["max_p"] is None or p > agg["max_p"]:
                agg["max_p"] = p
            best = agg["_top"].get(key)
            if best is None or p > best[0]:
                agg["_top"][key] = (p, hits, len(recs))
            if hits == self.consecutive:
                ip, ua = key
                agg["would_bans"] += 1
                self.totals["would_bans"] += 1
                events.append({"kind": "l7_would_ban", "ip": ip, "ua_h": ua,
                               "p": round(p, 6), "hits": hits, "n_events": len(recs),
                               "ip_banned": ip in banned, "threshold": self.threshold,
                               "consecutive": self.consecutive, "t_poll": now})
        return events

    def take_summary(self):
        """Return and reset the aggregate since the last call (the periodic
        `l7_gru_poll` event)."""
        agg, self._agg = self._agg, self._new_agg()
        top = sorted(agg.pop("_top").items(), key=lambda kv: -kv[1][0])[:self.top_k]
        agg["top"] = [{"ip": k[0], "ua_h": k[1], "p": round(v[0], 6), "hits": v[1], "n": v[2]}
                      for k, v in top]
        if agg["max_p"] is not None:
            agg["max_p"] = round(agg["max_p"], 6)
        # Which model scored (package weights SHA-256), or None in features-only mode.
        agg["model"] = (self.scorer.sha256 or "unknown") if self.scorer is not None else None
        agg["trust_after"] = self.trust_after or None
        return agg


# ───────────────────────── recording format (engine input) ─────────────────────────
# One JSON object per line:
#   {"rx": <wall s>, "obj": {...parsed log object...}}          a request record
#   {"rx": <wall s>, "poll": true, "suppressing": b, "banned": [ips]}   a poll tick
# Replaying the lines in order through a fresh engine reproduces its decisions.

class EngineRecorder:
    """Append the engine's exact input stream to a JSONL file (L7_RECORD)."""

    def __init__(self, path):
        self.path = path
        # Long-lived handle, closed by close(): no context manager.
        self._fh = open(path, "a", encoding="utf-8", buffering=1 << 16)  # noqa: SIM115

    def record(self, obj, rx):
        self._fh.write(json.dumps({"rx": round(rx, 6), "obj": obj}, separators=(",", ":")) + "\n")

    def poll(self, now, suppressing, banned):
        self._fh.write(json.dumps({"rx": round(now, 6), "poll": True,
                                   "suppressing": bool(suppressing),
                                   "banned": sorted(banned)}, separators=(",", ":")) + "\n")
        self._fh.flush()

    def close(self):
        self._fh.close()


def build_engine(model_path=None, window=None, idle_timeout=None, **kwargs):
    """Build the window store and engine the same way for the daemon and the
    replay tool. With a model package, the store's window length is the package's
    seq_len (the model was trained on windows of that length)."""
    scorer = None
    if model_path:
        from l7_scorer import L7Scorer  # torch is imported only when a model is used
        scorer = L7Scorer.load(model_path)
    maxlen = scorer.seq_len if scorer else (window or l7_ingest.DEFAULT_WINDOW)
    store = l7_ingest.L7WindowStore(
        maxlen=maxlen, idle_timeout=idle_timeout or l7_ingest.DEFAULT_IDLE_TIMEOUT)
    return L7ShadowEngine(store, scorer=scorer, **kwargs)


def read_stream(lines, parse_line=None):
    """Yield ("record", obj) and ("poll", now, suppressing, banned) items from a
    recording, a plain JSON-lines access log (file sink), or syslog-framed lines.
    `parse_line` parses a non-recording line (default: l7_ingest.parse_l7_line)."""
    if parse_line is None:
        parse_line = l7_ingest.parse_l7_line
    for line in lines:
        line = line.strip()
        if not line:
            continue
        item = None
        if line.startswith("{"):
            try:
                item = json.loads(line)
            except ValueError:
                item = None
        if isinstance(item, dict) and item.get("poll") is True:
            yield ("poll", float(item["rx"]), bool(item.get("suppressing")),
                   tuple(item.get("banned") or ()))
        elif isinstance(item, dict) and isinstance(item.get("obj"), dict):
            yield ("record", item["obj"])
        else:
            obj = item if isinstance(item, dict) else parse_line(line)
            if obj is not None:
                yield ("record", obj)
