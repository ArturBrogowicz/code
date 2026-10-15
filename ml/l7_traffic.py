"""Benign and attack traffic for the L7 capture (docs/L7_GRU_DESIGN.md §6, §7; Phase P3).

Defines WHAT runs in the capture, not how the topology is built (that is
ml/capture_l7.py). Three concerns, all offline-testable:

  * benign client kinds — the diversity the FP budget needs (§6.2): one-shot curl,
    keep-alive browsing, HTTP/2 over TLS, API polling, large downloads, uploads, and
    a NAT gateway (several users behind one IP);
  * sub-threshold attack families — trained and held-out (§6.3);
  * calibrate() — the honest-calibration gate (§7): every TRAINED attack must provably
    stay under the daemon's deterministic BAN thresholds, so the scenario is a genuine
    threat the heuristics miss, not one they already stop. This is checked from the
    configured parameters, never from any model score.

These are closed-loop generators in an isolated namespace testbed; they exist to
label L7 training data for the defensive detector. Each is launched per namespace by
ml/capture_l7.py via the suite's run(); the script bodies here are small and
parametric, mirroring the low-and-slow generators already in test_distributed_suite.py.

THRESHOLDS mirrors the daemon (control_plane.py) and nginx.conf; a test cross-checks
the values so they cannot drift.
"""
import dataclasses
import json

# Deterministic BAN thresholds the daemon enforces, plus the nginx handling limits that
# shape (not ban) traffic. Sub-threshold = below the BAN thresholds (zero heuristic bans).
THRESHOLDS = {
    "l7_rate_ban_rps": 50,        # control_plane HEURISTIC_MAX_RPS: per-IP rps that BANS
    "slowconn_ban_conns": 8,      # control_plane SLOWCONN_CONN_THRESHOLD: idle ESTAB that BANS
    "rudy_ban_timeouts": 3,       # control_plane RUDY_TIMEOUT_THRESHOLD: body timeouts that BAN
    "nginx_limit_req_rps": 30,    # nginx limit_req rate: SHAPES above this (not a ban)
    "nginx_limit_conn": 50,       # nginx limit_conn: SHAPES above this (not a ban)
    "nginx_body_timeout_s": 5,    # client_body_timeout: a slower dribble => a body timeout
    "nginx_header_timeout_s": 5,  # client_header_timeout
    "nginx_max_body": 65536,      # client_max_body_size: a larger body => 413
}
# Headroom below a ban threshold we require of a trained attack, so jitter cannot cross it.
RPS_MARGIN = 5
CONN_MARGIN = 1


@dataclasses.dataclass(frozen=True)
class BenignSpec:
    kind: str
    port: int = 80                 # 80 or 443
    params: dict = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True)
class AttackSpec:
    family: str
    mechanism: str                 # "rate" (rps-bounded) | "conns" (held connections)
    held_out: bool = False
    params: dict = dataclasses.field(default_factory=dict)

    def as_schedule_entry(self, ip, start_s, stop_s):
        return {"ip": ip, "family": self.family, "held_out": self.held_out,
                "mechanism": self.mechanism, "start_s": round(start_s, 3),
                "stop_s": round(stop_s, 3), "params": dict(self.params)}


# ── Benign kinds (§6.2). Mix of ports and request patterns. ──
BENIGN_KINDS = [
    BenignSpec("curl_oneshot", 80, {"think_s": [1.0, 3.0], "paths": "mixed"}),
    BenignSpec("curl_oneshot", 443, {"think_s": [1.0, 3.0], "paths": "mixed"}),
    BenignSpec("keepalive", 443, {"think_s": [0.5, 2.0], "per_session": [4, 12],
                                  "paths": "browse"}),
    BenignSpec("keepalive", 80, {"think_s": [0.8, 2.5], "per_session": [3, 8],
                                 "paths": "browse"}),
    BenignSpec("http2", 443, {"think_s": [1.0, 2.0], "parallel": 6, "paths": "assets"}),
    BenignSpec("api_poll", 443, {"interval_s": [0.5, 1.5], "path": "/api/status"}),
    BenignSpec("downloader", 443, {"think_s": [5.0, 15.0], "path": "/download/large"}),
    BenignSpec("uploader", 80, {"think_s": [4.0, 10.0], "path": "/upload",
                                "body_bytes": [200, 60000]}),
    BenignSpec("nat_gateway", 443, {"users": 8, "think_s": [0.5, 3.0], "paths": "browse"}),
]

# ── Trained sub-threshold attack families (§6.3). All provably below a ban threshold. ──
TRAINED_ATTACKS = [
    AttackSpec("subthreshold_flood", "rate", params={"rps": 20, "port": 80, "paths": "mixed"}),
    AttackSpec("subthreshold_flood", "rate", params={"rps": 45, "port": 443, "paths": "mixed"}),
    AttackSpec("scraper", "rate", params={"rps": 25, "port": 443, "paths": "scrape"}),
    AttackSpec("slowloris", "conns", params={"conns": 6, "header_every_s": 3,
                                             "port": 80}),
    AttackSpec("slowpost", "conns", params={"conns": 6, "byte_every_s": 3,
                                            "body_bytes": 60000, "port": 80}),
]

# ── Held-out families (evaluation only; never in the training split). ──
HELDOUT_ATTACKS = [
    AttackSpec("padded_flood", "rate", True, {"rps": 30, "port": 443, "paths": "mixed",
                                              "pad_header_bytes": 500}),
    AttackSpec("credstuff", "rate", True, {"rps": 20, "port": 443, "path": "/login",
                                           "body_bytes": 120}),
    AttackSpec("slowread", "conns", True, {"conns": 6, "read_every_s": 3,
                                           "path": "/download/large", "port": 80}),
]


class CalibrationError(ValueError):
    """A trained attack is not provably below a deterministic ban threshold (§7)."""


def _check_spec(spec):
    """Return a per-spec calibration record; raise CalibrationError for a TRAINED
    attack that could trip a ban. Held-out specs are reported, not enforced."""
    p = spec.params
    rec = {"family": spec.family, "held_out": spec.held_out, "mechanism": spec.mechanism}
    violations = []
    if spec.mechanism == "rate":
        rps = p["rps"]
        rec["rps"] = rps
        rec["ban_threshold"] = THRESHOLDS["l7_rate_ban_rps"]
        rec["margin_ok"] = rps <= THRESHOLDS["l7_rate_ban_rps"] - RPS_MARGIN
        rec["nginx_shaped"] = rps > THRESHOLDS["nginx_limit_req_rps"]   # expected, not a ban
        if not rec["margin_ok"]:
            violations.append(f"rps {rps} not <= {THRESHOLDS['l7_rate_ban_rps']}-{RPS_MARGIN}")
    elif spec.mechanism == "conns":
        conns = p["conns"]
        rec["conns"] = conns
        rec["ban_threshold"] = THRESHOLDS["slowconn_ban_conns"]
        rec["margin_ok"] = conns <= THRESHOLDS["slowconn_ban_conns"] - CONN_MARGIN
        if not rec["margin_ok"]:
            violations.append(f"conns {conns} not <= {THRESHOLDS['slowconn_ban_conns']}-{CONN_MARGIN}")
        # A dribble must not trip a body/header timeout (that is the RUDY ban path).
        for key, limit in (("byte_every_s", "nginx_body_timeout_s"),
                           ("header_every_s", "nginx_header_timeout_s"),
                           ("read_every_s", "nginx_body_timeout_s")):
            if key in p:
                rec[key] = p[key]
                ok = p[key] < THRESHOLDS[limit]
                rec[f"{key}_ok"] = ok
                if not ok:
                    violations.append(f"{key} {p[key]} not < {THRESHOLDS[limit]}s "
                                      f"(would time out -> RUDY)")
        if "body_bytes" in p and p["body_bytes"] > THRESHOLDS["nginx_max_body"]:
            violations.append(f"body_bytes {p['body_bytes']} > client_max_body_size "
                              f"{THRESHOLDS['nginx_max_body']} (would 413)")
    else:
        violations.append(f"unknown mechanism {spec.mechanism}")
    rec["violations"] = violations
    return rec


def calibrate(trained=None, held_out=None, enforce=True):
    """Check every attack spec against the ban thresholds. Returns a report. With
    enforce=True, raise CalibrationError if any TRAINED spec has a violation."""
    trained = TRAINED_ATTACKS if trained is None else trained
    held_out = HELDOUT_ATTACKS if held_out is None else held_out
    report = {"thresholds": dict(THRESHOLDS),
              "trained": [_check_spec(s) for s in trained],
              "held_out": [_check_spec(s) for s in held_out]}
    bad = [r for r in report["trained"] if r["violations"]]
    report["calibrated"] = not bad
    if enforce and bad:
        raise CalibrationError(f"trained attacks not sub-threshold: {bad}")
    return report


def build_plan(seed, n_benign, duration_s, *, include_held_out=True, include_flood=True,
               benign_prefix="10.0.1", attack_prefix="10.0.2", warmup_s=10.0):
    """Assign IPs and start/stop times to benign clients and attackers (seeded).

    Benign clients run for the whole capture. Each attacker runs one window inside
    [warmup_s, duration_s], so the capture has clean pre-attack baseline. When
    include_flood, one extra attacker runs a short volumetric flood mid-capture, so
    benign traffic is seen distorted (the contaminated regime, §5.6).
    Returns (benign_clients, attackers, schedule, calibration_report).
    """
    import random
    rng = random.Random(seed)
    report = calibrate()                         # raises if a trained attack is mis-set

    benign_clients = []
    for i in range(n_benign):
        spec = BENIGN_KINDS[i % len(BENIGN_KINDS)]
        ip = f"{benign_prefix}.{i + 1}"
        benign_clients.append({"ip": ip, "kind": spec.kind, "port": spec.port,
                               "profile": None, "params": dict(spec.params),
                               "seed": rng.randrange(2**31)})

    specs = list(TRAINED_ATTACKS) + (list(HELDOUT_ATTACKS) if include_held_out else [])
    attackers, schedule = [], []
    for j, spec in enumerate(specs):
        ip = f"{attack_prefix}.{j + 1}"
        span = rng.uniform(40.0, 70.0)
        latest = max(warmup_s, duration_s - span)
        start = rng.uniform(warmup_s, latest) if latest > warmup_s else warmup_s
        stop = min(start + span, duration_s)
        attackers.append({"ip": ip, "family": spec.family, "held_out": spec.held_out,
                          "mechanism": spec.mechanism, "params": dict(spec.params),
                          "port": spec.params.get("port", 80), "seed": rng.randrange(2**31)})
        schedule.append(spec.as_schedule_entry(ip, start, stop))

    if include_flood:
        ip = f"{attack_prefix}.{len(specs) + 1}"
        spec = AttackSpec("volumetric_flood", "flood", params={"kind": "syn", "dur_s": 8})
        start = rng.uniform(warmup_s + 10, max(warmup_s + 11, duration_s - 20))
        attackers.append({"ip": ip, "family": spec.family, "held_out": False,
                          "mechanism": spec.mechanism, "params": dict(spec.params),
                          "port": 0, "seed": rng.randrange(2**31)})
        schedule.append(spec.as_schedule_entry(ip, start, start + spec.params["dur_s"]))

    return benign_clients, attackers, schedule, report


def summary(plan=None):
    """A short text summary of a plan or the default specs, for logs and review."""
    rep = calibrate(enforce=False)
    lines = [f"thresholds: {json.dumps(rep['thresholds'])}", "trained attacks:"]
    for r in rep["trained"]:
        lines.append(f"  {r['family']:20s} {r.get('rps', '')}{r.get('conns', '')} "
                     f"margin_ok={r['margin_ok']} viol={r['violations']}")
    lines.append("held-out attacks:")
    for r in rep["held_out"]:
        lines.append(f"  {r['family']:20s} viol={r['violations']}")
    return "\n".join(lines)


if __name__ == "__main__":
    print(summary())
