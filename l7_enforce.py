"""The L7 v2 enforcing arm (docs/L7V2_DESIGN.md 9.1-9.2, D-V7; T-025c): what the daemon does with the L7 engine's
would-ban decisions when L7_ENFORCE=1. Off by default.

The engine (l7_engine.L7ViewEngine) stays observe-only. The daemon logs each of its `l7_would_ban` events as before
and, with L7_ENFORCE=1, hands it to Arm.submit; the arm acts in its own supervised thread (control_plane's
l7_enforce_monitor, one Arm.step per second), so every action follows a logged would-ban event, and the shadow thread
never bans. The shadow thread also shows the arm every request it ingests (Arm.observe): the raw strings of the key
(l7_denymap.RawKeys), the UA and sid hashes per IP (IpKeys) and whether a denied key keeps sending.

The decision policy (9.1, 9.2), for a would-ban of the key (IP, ua_h, sid_h):
  * no action on an allowlisted IP (the server's own addresses, SERVER_ADDRESSES, and the monitoring identities the
    runner names in L7_ALLOWLIST), on a key already acted on, or on an IP already banned by any engine;
  * the key-age gate: no action on a key younger than KEY_AGE_S, counted from the start of its first request seen;
    the decision waits and is acted on once the key is that old;
  * level 1, the key is denied at nginx: its line is added to deny.map (l7_denymap.DenyMap), which is written, and
    nginx reloaded through the injected `reload` callable, at most once per RELOAD_MIN_S with every change since the
    last reload in one batch. A key whose raw strings fail the write rules of 9.4 is "unenforceable": it is logged as
    a miss (l7_enforce_miss) and can reach level 2 only;
  * level 2, an XDP ban of the IP through the injected `ban` (the daemon's ban_ip, engine ban_events.L7V2_ENGINE, the
    daemon's TTL) and `close` (its kill_zombie_connections): only when the key keeps sending, a request that started
    LEVEL2_AFTER_S or more after its deny took effect (the reload that published it; for an unenforceable key, after
    the decision), AND its IP is single-key: fewer than GUARD_KEYS distinct UA hashes and fewer than GUARD_KEYS
    distinct sids in the last KEYS_WINDOW_S. An IP with more keys is never XDP-banned by this arm (the CGNAT guard,
    9.2), and an IP the arm has not seen counts as one with more.
  * a deny ends DENY_TTL_S after it was added (l7_denymap.DenyMap.expire).

Safeguards (9.3):
  * the kill switch, read every step: while `killed()` is true (the daemon: the file L7_KILL_FILE exists, by default
    /run/l7v2/kill like SLOW_PC_KILL_FILE) no new action is taken (decisions are logged as skipped, "killed"), and
    on the step that sees it appear the deny map is emptied with one reload and the XDP bans this arm made are lifted
    through the injected `lift`, which leaves every other engine's bans (L3/L4, slow_pc) alone;
  * rate caps: at most MAX_LEVEL2_PER_MIN level-2 bans in any 60 s and l7_denymap.MAX_DENIES active denies; beyond
    either, an l7_enforce_capped event and no action (a capped level-2 ban is tried again at the next step);
  * no deny outlives its daemon: start() empties a map an earlier daemon left (one reload), stop() empties the map
    when the daemon stops (one reload), as detaching XDP lifts every ban.

Events (ban_events.EventLog; documented in docs/EVALUATION.md): l7_enforce_arm, l7_deny, l7_deny_end,
l7_enforce_skip, l7_enforce_miss, l7_enforce_capped, l7_reload, l7_enforce_poll, and the daemon's own `ban` for
level 2. They carry hashes, never a raw User-Agent or session id.

Standard library only, like l7_ingest and l7_denymap; everything that touches nginx, XDP or the event log is injected,
so the tests use fakes.
"""
import ipaddress
import re
import threading
import time
from collections import OrderedDict

import ban_events
import l7_denymap
import l7_ingest

KEY_AGE_S = 20.0               # 9.1: no action on a key younger than this
LEVEL2_AFTER_S = 30.0          # 9.2: level 2 only for a key still sending this long after its deny
GUARD_KEYS = 3                 # 9.2: an IP with this many distinct UA hashes, or sids, is never XDP-banned
KEYS_WINDOW_S = 600.0          # 9.2: ... in the last 10 min
RELOAD_MIN_S = 10.0            # 9.2: a graceful reload at most once per 10 s
MAX_LEVEL2_PER_MIN = 20        # 9.3: level-2 bans in any 60 s at most
REPORT_INTERVAL_S = 5.0
MAX_IPS = 65536                # IpKeys' LRU bound
MAX_INBOX = 100000             # would-ban events waiting for the next step at most
SERVER_ADDRESSES = ("127.0.0.0/8", "10.0.0.1/32")    # loopback and the server's address in server_ns
SKIP_REASONS = ("not_armed", "killed", "allowlist", "already_denied", "ip_banned", "key_age", "cgnat_guard")


def allowlist(extra=""):
    """The allowlist: the server's own addresses and the comma-separated IPv4 addresses or networks in `extra`
    (L7_ALLOWLIST, the runner's monitoring identities). A malformed entry raises ValueError."""
    nets = [ipaddress.ip_network(n) for n in SERVER_ADDRESSES]
    for part in (extra or "").split(","):
        if part.strip():
            nets.append(ipaddress.IPv4Network(part.strip()))
    return tuple(nets)


def allowed(ip, nets):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


def redact(text):
    """An error text with every double-quoted string blanked: nginx quotes the offending map key, a raw UA."""
    return re.sub(r'"[^"]*"', '"…"', str(text))[:200]


class IpKeys:
    """Per IP, the most recent GUARD_KEYS distinct UA hashes and sids (a request without a session has none), each
    with the start of its latest request. Keeping only the most recent GUARD_KEYS values answers "fewer than
    GUARD_KEYS in the window?" exactly. Bounded LRU over IPs. Not thread-safe: the arm holds its lock."""

    def __init__(self, window=KEYS_WINDOW_S, keep=GUARD_KEYS, max_ips=MAX_IPS):
        self.window, self.keep, self.max_ips = window, keep, max_ips
        self._ips = OrderedDict()      # ip -> ({ua_h: t}, {sid_h: t})

    def __len__(self):
        return len(self._ips)

    def _bump(self, seen, value, t):
        seen[value] = max(seen.get(value, t), t)
        if len(seen) > self.keep:
            del seen[min(seen, key=seen.get)]

    def note(self, ip, ua_h, sid_h, t):
        entry = self._ips.get(ip)
        if entry is None:
            entry = self._ips[ip] = ({}, {})
            if len(self._ips) > self.max_ips:
                self._ips.popitem(last=False)
        else:
            self._ips.move_to_end(ip)
        self._bump(entry[0], ua_h, t)
        if sid_h != l7_ingest.NO_SID:
            self._bump(entry[1], sid_h, t)

    def counts(self, ip, now):
        """(distinct UA hashes, distinct sids) of `ip` seen in the window, each at most `keep`; None if unknown."""
        entry = self._ips.get(ip)
        if entry is None:
            return None
        return tuple(sum(1 for t in seen.values() if t >= now - self.window) for seen in entry)


class Arm:
    """The enforcing arm. observe() and submit() are called by the L7 shadow thread, step() by the arm's own thread;
    the shared tables are guarded by one lock, which is never held across a callback (reload, ban, close, events)."""

    def __init__(self, deny_map, *, reload, ban, close, banned, events, lift=None, killed=None, allow=(),
                 clock=time.time):
        self.denies = deny_map
        self.reload, self.ban, self.close, self.banned, self.events = reload, ban, close, banned, events
        self.lift = lift or (lambda _bans: [])
        self.killed = killed or (lambda: False)
        self.kill_on = False
        self.xdp_bans = {}             # ip -> the time ban_ip recorded for this arm's level-2 ban (for the kill switch)
        self.level2_times = []         # times of the level-2 bans in the last 60 s
        self.allow = tuple(allow) or allowlist()
        self.clock = clock
        self.lock = threading.Lock()
        self.raw = l7_denymap.RawKeys()
        self.ips = IpKeys()
        self.inbox = []
        self.tracked = {}              # key -> what the arm did with it (level 1 or a miss) and what followed
        self.waiting = {}              # key -> (event, start of its first request): held by the key-age gate
        self.armed, self.why, self.info = False, "no engine attached", {"arm": None}
        self.last_reload = None
        self.last_report = None
        self.changes = 0
        self.counts = dict.fromkeys(("would_bans", "denied", "missed", "level2", "guarded", "capped", "reloads",
                                     "reload_failed", "ended", "lifted", "inbox_dropped", "observe_errors"), 0)
        self.skips = dict.fromkeys(SKIP_REASONS, 0)
        self.first_error = None

    # --- the shadow thread's side -----------------------------------------------------------------------------------

    def attach(self, engine, refuse=None):
        """The engine whose decisions the arm acts on. Only an engine that scores (IP, UA, sid) keys with a model can
        be enforced; `refuse` is a reason given by the daemon (GRU_ONLY=1, say). Emits l7_enforce_arm."""
        scorer = getattr(engine, "scorer", None)
        meta = (getattr(scorer, "cfg", None) or {}).get("meta") or {}
        info = {"arm": meta.get("arm") or getattr(scorer, "arm", None), "arm_kind": getattr(scorer, "kind", None),
                "model": getattr(scorer, "sha256", None) or None,
                "selection_sha256": getattr(scorer, "selection_sha256", None),
                "level": getattr(engine, "level", "request"),
                "threshold": getattr(engine, "threshold", None), "consecutive": getattr(engine, "consecutive", None)}
        why = refuse
        if why is None and scorer is None:
            why = "no model: the engine runs features-only"
        elif why is None and info["level"] != "view":
            why = "a request-level engine keys by (IP, UA); the deny map needs (IP, UA, sid) keys"
        with self.lock:
            self.armed, self.why, self.info = why is None, why, info
        self.events.emit("l7_enforce_arm", armed=why is None, reason=why, **info)

    def observe(self, obj, rec):
        """One ingested request: its parsed log object and normalised record. It cannot raise (the shadow thread's
        engine must not be rebuilt for an error here); errors are counted."""
        try:
            key = l7_ingest.key_v2(rec)
            start = rec["msec"] - rec["rt"]
            ua, sid = l7_denymap.raw_strings(obj)
            with self.lock:
                self.raw.note(key, ua, sid, start)
                self.ips.note(key[0], key[1], key[2], start)
                tr = self.tracked.get(key)
                if tr is not None and (tr["last"] is None or start > tr["last"]):
                    tr["last"] = start
        except Exception as e:  # noqa: BLE001 - see the docstring
            self.counts["observe_errors"] += 1
            if self.first_error is None:
                self.first_error = f"{type(e).__name__}: {e}"[:200]

    def submit(self, event):
        """A logged `l7_would_ban` event (its fields, without "kind"), for the next step."""
        with self.lock:
            if len(self.inbox) >= MAX_INBOX:
                self.counts["inbox_dropped"] += 1
                return
            self.inbox.append(dict(event))

    # --- the arm's own thread ---------------------------------------------------------------------------------------

    def start(self, now=None):
        """At the daemon's start: a deny map an earlier daemon left behind is emptied, with one reload."""
        now = self.clock() if now is None else now
        try:
            with open(self.denies.path, "rb") as fh:
                stale = fh.read().count(b"\n")
        except OSError:
            stale = 0
        if stale:
            self.denies.dirty, self.changes = True, stale
            self._publish(now, force=True)

    def stop(self, now=None):
        """At the daemon's stop: every deny is lifted, with one reload (XDP's detach lifts the bans)."""
        now = self.clock() if now is None else now
        self._end(self.denies.clear(), now, "stop")
        self._publish(now, force=True)

    def step(self, now=None):
        """One step: the kill switch, the new decisions, the key-age gate, the deny TTL, the batched map write and
        reload, level 2."""
        now = self.clock() if now is None else now
        if self._kill_switch(now):
            self._publish(now)                    # a kill reload that failed is retried
            self._report(now)
            return
        with self.lock:
            inbox, self.inbox = self.inbox, []
            first = {self._key(ev): self.raw.first_seen(self._key(ev)) for ev in inbox}
        for ev in inbox:
            self.counts["would_bans"] += 1
            key = self._key(ev)
            if key in self.waiting:
                continue
            t_first = first.get(key)
            t_first = ev.get("t_poll", now) if t_first is None else t_first
            if now - t_first < KEY_AGE_S:
                self.waiting[key] = (ev, t_first)
                self._skip("key_age", ev, key_age_s=round(now - t_first, 3), until=round(t_first + KEY_AGE_S, 3))
                continue
            self._act(ev, now, t_first)
        for key, (ev, t_first) in list(self.waiting.items()):
            if now - t_first >= KEY_AGE_S:
                del self.waiting[key]
                self._act(ev, now, t_first)
        self._expire(now)
        self._publish(now)
        self._level2(now)
        self._report(now)

    def _kill_switch(self, now):
        """True while the kill switch is on: decisions are skipped; on its first step everything is lifted."""
        killed = bool(self.killed())
        if killed != self.kill_on:
            self.kill_on = killed
            if not killed:
                self.events.emit("l7_kill", on=False)
                return False
            cleared = self.denies.clear()
            self._end(cleared, now, "kill")
            for ev, _t in self.waiting.values():
                self._skip("killed", ev)
            self.waiting.clear()
            self._publish(now, force=True)
            lifted = list(self.lift(sorted(self.xdp_bans.items())))
            self.xdp_bans.clear()
            self.counts["lifted"] += len(lifted)
            self.events.emit("l7_kill", on=True, denies=len(cleared), bans_lifted=sorted(lifted))
        if killed:
            with self.lock:
                inbox, self.inbox = self.inbox, []
            for ev in inbox:
                self.counts["would_bans"] += 1
                self._skip("killed", ev)
        return killed

    def _end(self, entries, now, reason):
        """Forget the keys of these removed denies (and, on a kill or a stop, every key acted on): l7_deny_end each."""
        gone = {e.ident: e for e in entries}
        everything = reason in ("kill", "stop")
        with self.lock:
            ended = [(k, tr) for k, tr in self.tracked.items() if everything or tr["ident"] in gone
                     or tr["ident"] is None and now - tr["t_virtual"] > self.denies.ttl]
            for k, _tr in ended:
                del self.tracked[k]
        for _k, tr in ended:
            self.counts["ended"] += 1
            e = gone.get(tr["ident"])
            self.events.emit("l7_deny_end", reason=reason, denied=e is not None,
                             effective=e is not None and e.t_loaded is not None,
                             age_s=round(now - (e.t_added if e else tr["t_virtual"]), 3), **self._decision(tr["ev"]))
        if gone:
            self.changes += len(gone)

    @staticmethod
    def _key(ev):
        return (ev["ip"], ev["ua_h"], ev.get("sid_h", l7_ingest.NO_SID))

    def _decision(self, ev):
        """The fields every decision event carries: the key's hashes, the arm and its operating point, the score."""
        return {"ip": ev["ip"], "ua_h": ev["ua_h"], "sid_h": ev.get("sid_h", l7_ingest.NO_SID),
                "arm": self.info.get("arm"), "threshold": ev.get("threshold"), "consecutive": ev.get("consecutive"),
                "p": ev.get("p"), "t_poll": ev.get("t_poll")}

    def _skip(self, reason, ev, **extra):
        self.skips[reason] += 1
        self.events.emit("l7_enforce_skip", reason=reason, **self._decision(ev), **extra)

    def _act(self, ev, now, t_first):
        key, ip = self._key(ev), ev["ip"]
        if not self.armed:
            return self._skip("not_armed", ev, why=self.why)
        if allowed(ip, self.allow):
            return self._skip("allowlist", ev)
        if key in self.tracked:
            return self._skip("already_denied", ev)
        if self.banned(ip):
            return self._skip("ip_banned", ev)
        with self.lock:
            status, ua, sid = self.raw.lookup(key)
        age = round(now - t_first, 3)
        if status == "ok":
            got, entry = self.denies.add(ip, ua, sid, now)
            if got == "capped":
                self.counts["capped"] += 1
                return self.events.emit("l7_enforce_capped", what="deny", cap=self.denies.cap,
                                        active=len(self.denies), level=1, **self._decision(ev))
            if got == "refused":                  # the table keeps only passing keys; kept for safety
                status, ua = "unenforceable", entry
            else:
                if got == "added":
                    self.changes += 1
                self._track(key, ev, ident=entry.ident, t_virtual=None)
                self.counts["denied"] += 1
                return self.events.emit("l7_deny", level=1, shared=got == "present", key_age_s=age,
                                        active=len(self.denies), ttl_s=self.denies.ttl, **self._decision(ev))
        self.counts["missed"] += 1
        self._track(key, ev, ident=None, t_virtual=now)
        self.events.emit("l7_enforce_miss", rule=ua, level=1, key_age_s=age, **self._decision(ev))
        return None

    def _track(self, key, ev, ident, t_virtual):
        with self.lock:
            self.tracked[key] = {"ev": ev, "ident": ident, "t_virtual": t_virtual, "last": None,
                                 "escalated": False, "guarded": False}

    def _expire(self, now):
        self._end(self.denies.expire(now), now, "ttl")
        for ip in [ip for ip, t in self.xdp_bans.items() if now - t > 2 * self.denies.ttl]:
            del self.xdp_bans[ip]                 # long expired: the kill switch has nothing left to lift there

    def _publish(self, now, force=False):
        """Write the map and reload nginx if it changed, at most once per RELOAD_MIN_S (unless `force`)."""
        if not self.denies.dirty:
            return
        if not force and self.last_reload is not None and now - self.last_reload < RELOAD_MIN_S:
            return
        self.last_reload = now
        try:
            self.denies.write()
            ok, detail = self.reload()
        except Exception as e:  # noqa: BLE001 - a failed write or reload is reported and retried
            ok, detail = False, f"{type(e).__name__}: {e}"
        self.counts["reloads"] += 1
        if ok:
            self.denies.loaded(now)
        else:
            self.counts["reload_failed"] += 1
        self.events.emit("l7_reload", ok=bool(ok), entries=len(self.denies), changes=self.changes,
                         detail=redact(detail) if detail else None)
        if ok:
            self.changes = 0

    def _level2(self, now):
        self.level2_times = [t for t in self.level2_times if now - t < 60.0]
        capped = []
        with self.lock:
            due = []
            for key, tr in self.tracked.items():
                if tr["escalated"]:
                    continue
                if tr["ident"] is None:
                    t_eff = tr["t_virtual"]
                else:
                    entry = self.denies.get(tr["ident"])
                    t_eff = entry.t_loaded if entry is not None else None
                if t_eff is None or tr["last"] is None or tr["last"] < t_eff + LEVEL2_AFTER_S:
                    continue
                due.append((key, tr, t_eff, self.ips.counts(key[0], now)))
        for key, tr, t_eff, counts in due:
            ip, info = key[0], self._decision(tr["ev"])
            if counts is None or counts[0] >= GUARD_KEYS or counts[1] >= GUARD_KEYS:
                if not tr["guarded"]:
                    tr["guarded"] = True
                    self.counts["guarded"] += 1
                    self._skip("cgnat_guard", tr["ev"], level=2, ua_keys=counts and counts[0],
                               sid_keys=counts and counts[1])
                continue
            if self.banned(ip):
                tr["escalated"] = True
                continue
            if len(self.level2_times) >= MAX_LEVEL2_PER_MIN:
                capped.append(ip)                 # tried again at the next step
                continue
            tr["escalated"] = True
            self.counts["level2"] += 1
            self.level2_times.append(now)
            after = round(tr["last"] - t_eff, 3)
            banned_at = self.ban(ip, reason=f"L7 v2 arm {info['arm']}: key kept sending {after:g} s after its "
                                f"{'deny' if tr['ident'] else 'decision'} (p={info['p']} > {info['threshold']} in "
                                f"{info['consecutive']} windows)",
                     engine=ban_events.L7V2_ENGINE, level=2, value=info["p"], p=info["p"], threshold=info["threshold"],
                     consecutive=info["consecutive"], arm=info["arm"], ua_h=info["ua_h"], sid_h=info["sid_h"],
                     ua_keys=counts[0], sid_keys=counts[1], after_s=after, denied=tr["ident"] is not None)
            self.xdp_bans[ip] = banned_at
            self.close(ip)
        if capped:
            self.counts["capped"] += len(capped)
            self.events.emit("l7_enforce_capped", what="ban", n=len(capped), cap=MAX_LEVEL2_PER_MIN, level=2,
                             arm=self.info.get("arm"), ips=sorted(set(capped))[:50])

    def _report(self, now):
        if self.last_report is not None and now - self.last_report < REPORT_INTERVAL_S:
            return
        self.last_report = now
        with self.lock:
            sizes = {"raw_keys": len(self.raw), "raw_evicted": self.raw.evicted, "raw_ambiguous": self.raw.ambiguous,
                     "ips": len(self.ips), "tracked": len(self.tracked)}
        self.events.emit("l7_enforce_poll", armed=self.armed, killed=self.kill_on, active=len(self.denies),
                         waiting=len(self.waiting),
                         **sizes, **self.counts, skips=dict(self.skips), first_error=self.first_error)
