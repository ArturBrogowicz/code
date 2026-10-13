"""Machine-readable mitigation events, one JSON object per line (JSON Lines).

The daemon (control_plane.py) appends an event for every ban, unban, daemon start
and GRU-suppression change. The test harness (test_distributed_suite.py) and the
evaluation tools (eval/) read them back, so time-to-mitigate, the engine that
banned each source and false positives come from this record rather than from
console scraping or pings (review findings F-07, F-08, F-25).

Standard library only and free of import-time side effects: the daemon (venv
python), the suite (system python3) and the unit tests all import it.

Every record has:
    t_wall     float  epoch seconds (time.time()) when the event was written
    t_mono_ns  int    CLOCK_MONOTONIC in ns (time.monotonic_ns())
    kind       str    "start" | "ban" | "unban" | "suppress_on" | "suppress_off"
                      | "gru_suppressed"
plus kind-specific fields (ip, engine, value, threshold, ...); the full schema is
documented in docs/EVALUATION.md.
"""

import hashlib
import json
import os
import threading
import time

DEFAULT_PATH = "/var/log/ddos/ban_events.jsonl"

# Detection engines of control_plane.py.
ENGINES = ("l4_syn", "l4_volumetric", "l4_slowconn", "l4_lowsyn",
           "l7_rate", "l7_rudy", "gru")

# Console labels, identical to the ones the suite derived from the [BAN] log line.
ENGINE_LABELS = {
    "l4_syn": "L4 SYN", "l4_volumetric": "L4 Volumetric", "l4_slowconn": "L4 SlowConn",
    "l4_lowsyn": "L4 Low-SYN", "l7_rate": "L7 Heuristic", "l7_rudy": "L7 R.U.D.Y.",
    "gru": "GRU ML", "unknown": "Unknown",
}


class EventLog:
    """Append-only JSONL writer, safe to share between the daemon's threads.

    Each event is written as one line and flushed immediately. A falsy path
    disables the log. Errors are reported once and never raised: losing an
    event must never stop the daemon from enforcing a ban.
    """

    def __init__(self, path):
        self.path = path or None
        self._lock = threading.Lock()
        self._fh = None
        self._warned = False
        if self.path:
            try:
                parent = os.path.dirname(self.path)
                if parent:
                    os.makedirs(parent, exist_ok=True)
                # Long-lived handle (closed by close()), so no context manager here.
                self._fh = open(self.path, "a", buffering=1, encoding="utf-8")  # noqa: SIM115
            except OSError as e:
                self._warn(e)

    @property
    def enabled(self):
        return self._fh is not None

    def emit(self, kind, **fields):
        """Append one event and return it (None when disabled or on error)."""
        if self._fh is None:
            return None
        record = {"t_wall": time.time(), "t_mono_ns": time.monotonic_ns(), "kind": kind}
        record.update(fields)
        line = json.dumps(record, separators=(",", ":"), default=str)
        try:
            with self._lock:
                self._fh.write(line + "\n")
        except (OSError, ValueError) as e:      # ValueError: write to a closed file
            self._warn(e)
            return None
        return record

    def close(self):
        with self._lock:
            if self._fh is not None:
                self._fh.close()
                self._fh = None

    def _warn(self, err):
        if not self._warned:
            self._warned = True
            print(f"[-] Ban-event log {self.path} unavailable ({err}); continuing without it.")


def read_events(path, kinds=None):
    """Events in `path`, oldest first. Blank or malformed lines are skipped (e.g. a
    partial last line while the daemon is still writing); a missing file gives []."""
    events = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(ev, dict) or "kind" not in ev or "t_wall" not in ev:
                    continue
                if kinds is None or ev["kind"] in kinds:
                    events.append(ev)
    except FileNotFoundError:
        return []
    return events


def first_bans(events, ips=None, since=None, until=None):
    """{ip: earliest "ban" event} for bans with since <= t_wall <= until.

    Several engines can ban the same IP almost at once (ban_ip() is not an atomic
    test-and-set, review D6); the earliest event is the one that mitigated it.
    """
    wanted = set(ips) if ips is not None else None
    first = {}
    for ev in events:
        if ev.get("kind") != "ban":
            continue
        ip, t = ev.get("ip"), ev.get("t_wall")
        if ip is None or t is None:
            continue
        if wanted is not None and ip not in wanted:
            continue
        if (since is not None and t < since) or (until is not None and t > until):
            continue
        if ip not in first or t < first[ip]["t_wall"]:
            first[ip] = ev
    return first


def engine_from_reason(reason):
    """Engine id for the free-text reason of a "[BAN] ... Reason: ..." log line, for
    daemon logs written before ban events existed. Order matters: the R.U.D.Y.
    reason also contains "Heuristic"."""
    for needle, engine in (("R.U.D.Y.", "l7_rudy"), ("GRU", "gru"),
                           ("Low-and-slow", "l4_lowsyn"), ("SYN flood", "l4_syn"),
                           ("Volumetric", "l4_volumetric"),
                           ("Slow connection", "l4_slowconn"), ("Heuristic", "l7_rate")):
        if needle in reason:
            return engine
    return "unknown"


def file_sha256(path):
    """Hex SHA-256 of a file, or None if it cannot be read."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()
