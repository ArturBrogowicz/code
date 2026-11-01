"""R*'s live path (docs/L7V2_DESIGN.md 9.5, 10 and 19; ml/l7v2_rules_prereg_v3.json r_star_live; T-025e): the rule arm at
its own (IP, UA) level, with the engine's interface, so that the L7 shadow thread and the enforcing arm treat it like the
view engine.

Observe-only, like l7_engine: it returns `l7_would_ban` events that the daemon logs and the arm (l7_enforce.Arm) acts on.
Every record feeds ml/l7v2_rules.RuleStats; every poll gives one row per (IP, UA) key with a request since the previous
poll, each statistic's maximum over those requests; the row is scored with the rule (detector.score, p in {0, 1}), and p
> theta in k consecutive rows of a key is a decision. A suppressing poll (an L3/L4 flood) clears every key's run and
decides nothing, as the view engine's does. The statistics and the rule are the replay's own objects, not a copy of
them; ml/l7v2_replay.RulePath is the reference for the policy, and tests/test_l7_rstar.py keeps the two deciding the
same keys at the same polls, on generated streams and on a recording the daemon's own shadow thread wrote.

A key is decided when its run reaches k, so the first decision of a key is RulePath's, which keeps only that one; as in
the view engine, a key whose run breaks and reaches k again is decided again.

One addition to the replay's path, for a process that runs on untrusted input: at most MAX_KEYS (IP, UA) keys and
MAX_IPS addresses are kept (the least recently seen go first, counted as `evicted`). Parity holds while `evicted` is 0.
"""
from collections import OrderedDict

import numpy as np

MAX_KEYS = 65536
MAX_IPS = 65536
TOP_K = 5


class L7RuleEngine:
    """The (IP, UA) rule path behind the view engine's interface: on_record, poll, take_summary, store.stats, scorer,
    threshold, consecutive and level. `detector` is an l7_arms.RuleDetector."""

    level = "rule"

    def __init__(self, detector, max_keys=MAX_KEYS, max_ips=MAX_IPS):
        self.scorer = detector
        self.threshold, self.consecutive = detector.threshold, detector.consecutive
        self.rule_stats = detector.new_stats()
        self.store = self                     # the shadow thread reports engine.store.stats()
        self.max_keys, self.max_ips = max_keys, max_ips
        self.hits = {}
        self.was_suppressing = False
        self.evicted = 0
        self._keys, self._ips = OrderedDict(), OrderedDict()
        self._gone_keys, self._gone_ips = [], []
        self._agg = self._new_agg()
        self.totals = {"polls": 0, "windows": 0, "would_bans": 0}

    @staticmethod
    def _new_agg():
        return {"polls": 0, "suppressed_polls": 0, "windows": 0, "over": 0, "would_bans": 0, "max_p": None,
                "t_last_poll": None, "_top": {}}

    def on_record(self, rec, now=None):
        """Add a normalised record (l7_ingest.normalise); returns its (IP, UA) key."""
        key = (rec["ip"], rec["ua_h"])
        self._touch(self._keys, key, self.max_keys, self._gone_keys)
        self._touch(self._ips, key[0], self.max_ips, self._gone_ips)
        self.rule_stats.observe(rec)
        return key

    def _touch(self, table, item, cap, gone):
        table[item] = None
        table.move_to_end(item)
        if len(table) > cap:
            gone.append(table.popitem(last=False)[0])
            self.evicted += 1

    def _forget(self):
        """Drop the state of what was evicted since the last poll: only now, as its queued records have just been
        processed; what came back in the meantime stays."""
        for key in self._gone_keys:
            if key not in self._keys:
                self.rule_stats._key.pop(key, None)
                self.hits.pop(key, None)
        for ip in self._gone_ips:
            if ip not in self._ips:
                self.rule_stats._ip.pop(ip, None)
        self._gone_keys, self._gone_ips = [], []

    def poll(self, now, suppressing=False, banned=()):
        """One decision step at wall time `now`: the poll's rows through the section-9 policy; a list of event dicts."""
        agg = self._agg
        agg["polls"] += 1
        agg["t_last_poll"] = now
        self.totals["polls"] += 1
        rows = self.rule_stats.poll()
        if self._gone_keys or self._gone_ips:
            self._forget()
        if suppressing:
            if not self.was_suppressing:
                self.hits.clear()             # a flood began: streaks are unreliable
            self.was_suppressing = True
            agg["suppressed_polls"] += 1
            return []
        self.was_suppressing = False
        if not rows:
            return []
        agg["windows"] += len(rows)
        self.totals["windows"] += len(rows)
        events = []
        banned = set(banned)
        for (key, t, row), p in zip(rows, self.scorer.score(np.stack([r for _k, _t, r in rows])), strict=True):
            p = float(p)
            over = p > self.threshold
            hits = self.hits.get(key, 0) + 1 if over else 0
            self.hits[key] = hits
            agg["over"] += over
            if agg["max_p"] is None or p > agg["max_p"]:
                agg["max_p"] = p
            if over:
                agg["_top"][key] = hits
            if hits == self.consecutive:
                agg["would_bans"] += 1
                self.totals["would_bans"] += 1
                events.append({"kind": "l7_would_ban", "level": "rule", "ip": key[0], "ua_h": key[1], "p": p,
                               "hits": hits, "t_row": t, "ip_banned": key[0] in banned, "threshold": self.threshold,
                               "consecutive": self.consecutive, "t_poll": now})
        return events

    def take_summary(self):
        """Return and reset the aggregate since the last call (the periodic `l7_gru_poll` event)."""
        agg, self._agg = self._agg, self._new_agg()
        top = sorted(agg.pop("_top").items(), key=lambda kv: (-kv[1], kv[0]))[:TOP_K]
        agg["top"] = [{"ip": k[0], "ua_h": k[1], "hits": h} for k, h in top]
        agg["model"] = self.scorer.sha256
        agg["level"] = "rule"
        return agg

    def stats(self):
        """The `l7_shadow` report's fields of this path; `late` counts records that completed before one already
        processed (RuleStats processes them all the same)."""
        return {"active_keys": len(self._keys), "distinct_ips": len(self._ips), "late": self.rule_stats.late,
                "evicted": self.evicted}
