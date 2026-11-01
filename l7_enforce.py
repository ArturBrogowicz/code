"""The L7 v2 enforcing arm (docs/L7V2_DESIGN.md 9.1-9.2, D-V7; T-025c): what the daemon does with the L7 engine's
would-ban decisions when L7_ENFORCE=1. Off by default.

The engine (l7_engine.L7ViewEngine) stays observe-only. The daemon logs each of its `l7_would_ban` events as before
and, with L7_ENFORCE=1, hands it to Arm.submit; the arm acts in its own supervised thread (control_plane's
l7_enforce_monitor, one Arm.step per second), so every action follows a logged would-ban event, and the shadow thread
never bans. The shadow thread also shows the arm every request it ingests (Arm.observe): the raw strings of the key
(l7_denymap.RawKeys), the UA and sid hashes per IP (IpKeys) and whether a denied key keeps sending.

R* (T-025e) decides on (IP, UA) keys (l7_rule_engine.L7RuleEngine, level "rule"): attach() sets the arm's key level, and
everything below applies to the key (IP, ua_h) as it does to a learned arm's (IP, ua_h, sid_h). Its level 1 is a line in
deny_key.map, which covers every session of the key, and so every user behind it, on any address: D-043 charges a flagged
(IP, UA) key every user behind it, and D-040's guard, which is about a sid-less line of a key at the session level, does
not apply. Its level 2 is guarded as below.

The decision policy (9.1, 9.2), for a would-ban of the key (IP, ua_h, sid_h):
  * no decision at all on an address that is not a canonical dotted-quad IPv4 address (l7_denymap.ip_problem; skip
    reason "ip_format"; T-042 E01): nginx logs $remote_addr canonically, but the XDP ban path parses with inet_aton,
    which reads "10.0.4617", "012.0.18.9", "0xa.0.18.9" or "10.0.18.9 " as 10.0.18.9, so a forged spelling would
    bypass the allowlist and the CGNAT guard of the real address. The allowlist fails closed on such a spelling, and
    the guard counts canonical addresses only;
  * no action on an allowlisted IP (the server's own addresses, SERVER_ADDRESSES, and the monitoring identities the
    runner names in L7_ALLOWLIST), on a key already acted on, or on an IP already banned by any engine;
  * the key-age gate: no action on a key younger than KEY_AGE_S, counted from the start of its first request seen;
    the decision waits and is acted on once the key is that old;
  * level 1, the key is denied at nginx: its line is added to deny.map (l7_denymap.DenyMap), which is written, and
    nginx reloaded through the injected `reload` callable, at most once per RELOAD_MIN_S with every change since the
    last reload in one batch. A key whose raw strings fail the write rules of 9.4 is "unenforceable": it is logged as
    a miss (l7_enforce_miss) and can reach level 2 only. A key without a session (D-040, T-042 E02) is denied at
    level 1 only while its address is single-key: its line "ip|ua|" matches every cookie-less request from the address
    with that UA (in any case), the first request of another user's session included, so on a shared address it is a
    miss ("sid_less_shared"), and a line already written is withdrawn once the address turns shared;
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
    on the step that sees it appear the deny map is emptied and the XDP bans this arm made are lifted through the
    injected `lift`, which leaves every other engine's bans (L3/L4, slow_pc) alone. The emptied map's reload keeps the
    10-s spacing (T-042 E04), so it may come up to RELOAD_MIN_S later; only the daemon's stop reloads at once;
  * rate caps: at most MAX_LEVEL2_PER_MIN level-2 bans in any 60 s and l7_denymap.MAX_DENIES active denies; beyond
    either, an l7_enforce_capped event and no action (a capped level-2 ban is tried again at the next step);
  * no deny outlives its daemon: start() empties a map an earlier daemon left (one reload), stop() empties the map
    when the daemon stops (one reload), as detaching XDP lifts every ban.

Events (ban_events.EventLog; documented in docs/EVALUATION.md): l7_enforce_arm, l7_deny, l7_deny_end,
l7_enforce_skip, l7_enforce_miss, l7_enforce_capped, l7_reload, l7_enforce_poll, and the daemon's own `ban` for
level 2. They carry hashes, never a raw User-Agent or session id. R*'s also carry the rule arm, its statistics and their
thresholds at the decision, and `users_seen`: the distinct session ids seen under the (IP, UA) key so far (a request
without a session counts as one), the reading ml/l7v2_rules.key_costs falls back on without a plan, for the budget's
live reading (D-044 OC-2). One user may hold several sessions, so it reads high; the run's manifest gives the devices.

Standard library only, like l7_ingest and l7_denymap; everything that touches nginx, XDP or the event log is injected,
so the tests use fakes.
"""
import ipaddress
import os
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
MAX_USERS_PER_KEY = 4096       # R*: distinct session ids counted under an (IP, UA) key at most
SERVER_ADDRESSES = ("127.0.0.0/8", "10.0.0.1/32")    # loopback and the server's address in server_ns
SKIP_REASONS = ("not_armed", "killed", "ip_format", "allowlist", "already_denied", "ip_banned", "key_age",
                "cgnat_guard")


def allowlist(extra=""):
    """The allowlist: the server's own addresses and the comma-separated IPv4 addresses or networks in `extra`
    (L7_ALLOWLIST, the runner's monitoring identities). A malformed entry raises ValueError."""
    nets = [ipaddress.ip_network(n) for n in SERVER_ADDRESSES]
    for part in (extra or "").split(","):
        if part.strip():
            nets.append(ipaddress.IPv4Network(part.strip()))
    return tuple(nets)


def allowed(ip, nets):
    """True if `ip` is in the allowlist. Fails closed: an address that is not a canonical dotted-quad IPv4 address is
    treated as allowlisted (no action), since inet_aton would read it as another address (T-042 E01)."""
    if l7_denymap.ip_problem(ip):
        return True
    addr = ipaddress.IPv4Address(ip)
    return any(addr in n for n in nets)


def shared(counts):
    """The CGNAT guard's test on IpKeys.counts: an unseen address, or one with GUARD_KEYS UA hashes or sids, is shared."""
    return counts is None or counts[0] >= GUARD_KEYS or counts[1] >= GUARD_KEYS


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
        if l7_denymap.ip_problem(ip):
            return                             # canonical addresses only (T-042 E01)
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
        self.run_lock = threading.Lock()   # one of step() / start() / stop() at a time (T-042 E03)
        self.stopped = False
        self.raw = l7_denymap.RawKeys()
        self.ips = IpKeys()
        self.inbox = []
        self.tracked = {}              # key -> what the arm did with it (level 1 or a miss) and what followed
        self.waiting = {}              # key -> (event, start of its first request): held by the key-age gate
        self.armed, self.why, self.info = False, "no engine attached", {"arm": None}
        self.rule_level = False        # R*: the keys are (IP, ua_h), whatever the session
        self.users = OrderedDict()     # R*: (IP, ua_h) -> the session ids seen under it; bounded as the raw table is
        self.last_reload = None
        self.last_report = None
        self.changes = 0
        self.counts = dict.fromkeys(("would_bans", "denied", "missed", "level2", "guarded", "capped", "reloads",
                                     "reload_failed", "ended", "lifted", "inbox_dropped", "observe_errors"), 0)
        self.skips = dict.fromkeys(SKIP_REASONS, 0)
        self.first_error = None

    # --- the shadow thread's side -----------------------------------------------------------------------------------

    def attach(self, engine, refuse=None):
        """The engine whose decisions the arm acts on. Only an engine that scores (IP, UA, sid) keys with a model, or
        R*'s (IP, UA) path, can be enforced; `refuse` is a reason given by the daemon (GRU_ONLY=1, say). Emits
        l7_enforce_arm."""
        scorer = getattr(engine, "scorer", None)
        meta = (getattr(scorer, "cfg", None) or {}).get("meta") or {}
        info = {"arm": meta.get("arm") or getattr(scorer, "arm", None), "arm_kind": getattr(scorer, "kind", None),
                "model": getattr(scorer, "sha256", None) or None,
                "selection_sha256": getattr(scorer, "selection_sha256", None),
                "valid_for_claims": getattr(scorer, "valid_for_claims", None),
                "level": getattr(engine, "level", "request"),
                "threshold": getattr(engine, "threshold", None), "consecutive": getattr(engine, "consecutive", None)}
        why = refuse
        if why is None and scorer is None:
            why = "no model: the engine runs features-only"
        elif why is None and info["level"] not in ("view", "rule"):
            why = "a request-level engine keys by (IP, UA); the deny map needs (IP, UA, sid) keys"
        elif why is None and (info["level"] == "rule") != self.denies.key_level:
            why = f"a {info['level']}-level engine with a map of the other level ({self.denies.path})"
        if info["level"] == "rule":
            info.update(rule_arm=getattr(scorer, "rule_name", None), stat_threshold=getattr(scorer, "stat_thresholds", None),
                        calibration_sha256=getattr(scorer, "calibration_sha256", None))
        with self.lock:
            self.armed, self.why, self.info = why is None, why, info
            self.rule_level = info["level"] == "rule"
        self.events.emit("l7_enforce_arm", armed=why is None, reason=why, **info)

    def observe(self, obj, rec):
        """One ingested request: its parsed log object and normalised record. It cannot raise (the shadow thread's
        engine must not be rebuilt for an error here); errors are counted."""
        try:
            key = l7_ingest.key_v2(rec)
            start = rec["msec"] - rec["rt"]
            ua, sid = l7_denymap.raw_strings(obj)
            with self.lock:
                if self.rule_level:            # a rule's key is every session of (IP, UA)
                    self.raw.note(key[:2], ua, "", start)
                    self._note_user(key[:2], key[2])
                    tr = self.tracked.get(key[:2])
                else:
                    self.raw.note(key, ua, sid, start)
                    tr = self.tracked.get(key)
                self.ips.note(key[0], key[1], key[2], start)
                if tr is not None and (tr["last"] is None or start > tr["last"]):
                    tr["last"] = start
        except Exception as e:  # noqa: BLE001 - see the docstring
            self.counts["observe_errors"] += 1
            if self.first_error is None:
                self.first_error = f"{type(e).__name__}: {e}"[:200]

    def _note_user(self, key, sid_h):
        seen = self.users.get(key)
        if seen is None:
            seen = self.users[key] = set()
            if len(self.users) > self.raw.max_keys:
                self.users.popitem(last=False)
        else:
            self.users.move_to_end(key)
        if len(seen) < MAX_USERS_PER_KEY:
            seen.add(sid_h)

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
        with self.run_lock:
            self._start(self.clock() if now is None else now)

    def _start(self, now):
        stale = 0
        for name in l7_denymap.MAP_FILES:            # either map, whichever arm's daemon left it
            path = os.path.join(self.denies.run_dir, name)
            try:
                with open(path, "rb") as fh:
                    lines = fh.read().count(b"\n")
            except OSError:
                continue
            stale += lines
            if lines and path != self.denies.path:
                l7_denymap.write_atomic(path, b"")
        if stale:
            self.denies.dirty, self.changes = True, stale
            self._publish(now)                    # the first reload of this daemon: not held back

    def stop(self, now=None):
        """At the daemon's stop: every deny is lifted, with one reload (XDP's detach lifts the bans). It waits for a step
        in flight and no step runs after it (T-042 E03: a step racing the stop could write a map after it), so once it
        returns deny.map is empty."""
        with self.run_lock:
            self.stopped = True
            now = self.clock() if now is None else now
            self._end(self.denies.clear(), now, "stop")
            self._publish(now, force=True)

    def step(self, now=None):
        """One step: the kill switch, the new decisions, the key-age gate, the deny TTL, the batched map write and
        reload, level 2. Nothing after stop()."""
        with self.run_lock:
            if not self.stopped:
                self._step(self.clock() if now is None else now)

    def _step(self, now):
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
        self._guard_sid_less(now)
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
            self._publish(now)                    # paced like every reload (T-042 E04): a flapping file cannot storm
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

    def _key(self, ev):
        if self.rule_level:
            return (ev["ip"], ev["ua_h"])
        return (ev["ip"], ev["ua_h"], ev.get("sid_h", l7_ingest.NO_SID))

    def _decision(self, ev):
        """The fields every decision event carries: the key's hashes, the arm and its operating point, the score."""
        fields = {"ip": ev["ip"], "ua_h": ev["ua_h"],
                  "sid_h": None if self.rule_level else ev.get("sid_h", l7_ingest.NO_SID),
                  "arm": self.info.get("arm"), "threshold": ev.get("threshold"), "consecutive": ev.get("consecutive"),
                  "p": ev.get("p"), "t_poll": ev.get("t_poll")}
        if self.rule_level:
            with self.lock:
                users = len(self.users.get(self._key(ev), ()))
            fields.update(rule_arm=self.info.get("rule_arm"), statistic=ev.get("statistic"),
                          stat_threshold=ev.get("stat_threshold"), users_seen=users)
        return fields

    def _skip(self, reason, ev, **extra):
        self.skips[reason] += 1
        self.events.emit("l7_enforce_skip", reason=reason, **self._decision(ev), **extra)

    def _act(self, ev, now, t_first):
        key, ip = self._key(ev), ev["ip"]
        if not self.armed:
            return self._skip("not_armed", ev, why=self.why)
        if l7_denymap.ip_problem(ip):
            return self._skip("ip_format", ev)
        if allowed(ip, self.allow):
            return self._skip("allowlist", ev)
        if key in self.tracked:
            return self._skip("already_denied", ev)
        if self.banned(ip):
            return self._skip("ip_banned", ev)
        with self.lock:
            status, ua, sid = self.raw.lookup(key)
        age = round(now - t_first, 3)
        if status == "ok" and not sid and not self.rule_level:
            with self.lock:
                counts = self.ips.counts(ip, now)
            if shared(counts):
                status, ua = "unenforceable", "sid_less_shared"      # D-040
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

    def _guard_sid_less(self, now):
        """D-040: withdraw the line of a sid-less deny whose address has turned shared. Its keys stay tracked as misses
        from the time the line took effect, so they may still reach level 2 if the address is single-key again. Not R*'s
        lines, which cover every session of their key on purpose (D-043)."""
        if self.rule_level:
            return
        with self.lock:
            stale = [e.ident for e in self.denies if not e.sid and shared(self.ips.counts(e.ip, now))]
        if not stale:
            return
        gone = {e.ident: e for e in self.denies.remove(stale)}
        with self.lock:
            moved = [tr for tr in self.tracked.values() if tr["ident"] in gone]
            for tr in moved:
                e = gone[tr["ident"]]
                tr["ident"], tr["t_virtual"], tr["withdrawn"] = None, e.t_loaded if e.t_loaded else now, e
        for tr in moved:
            e = tr.pop("withdrawn")
            self.counts["guarded"] += 1
            self.events.emit("l7_deny_end", reason="cgnat_guard", denied=True, effective=e.t_loaded is not None,
                             age_s=round(now - e.t_added, 3), **self._decision(tr["ev"]))
        self.changes += len(gone)

    def _publish(self, now, force=False):
        """Write the map and reload nginx if it changed, at most once per RELOAD_MIN_S. Only stop() forces it: the
        daemon is ending, and one last reload empties nginx's map (T-042 E04: the kill switch's reload is paced)."""
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
            if l7_denymap.ip_problem(ip) or allowed(ip, self.allow):
                tr["escalated"] = True            # never tracked by _act; kept as a second fence (T-042 E01)
                continue
            if shared(counts):
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
                                f"{info['consecutive']} {'rows' if self.rule_level else 'windows'})",
                     engine=ban_events.L7V2_ENGINE, level=2, value=info["p"], p=info["p"], threshold=info["threshold"],
                     consecutive=info["consecutive"], arm=info["arm"], ua_h=info["ua_h"], sid_h=info["sid_h"],
                     ua_keys=counts[0], sid_keys=counts[1], after_s=after, denied=tr["ident"] is not None,
                     **{k: info[k] for k in ("rule_arm", "statistic", "stat_threshold", "users_seen") if k in info})
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
