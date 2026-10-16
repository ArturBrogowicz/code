"""Request-sequence features for the L7 GRU (docs/L7_GRU_DESIGN.md §5.2; Phase P2).

One window = the last `seq_len` requests of one (IP, ua_hash) key, ordered by start
time, encoded as a (seq_len, C) float32 matrix. Shorter windows are LEFT-padded with
zero rows, so the most recent real request sits in the last time step, the one the
GRU classifier reads (GRU_ML_model: out[:, -1, :]). Column 0 is always `valid`
(1 = real request, 0 = padding).

numpy only, no torch. The daemon, the trainer (P4), the tabular baseline, and the
replay and probe tools all import this one implementation, including the scaling
transform (apply_scaling), so serving and training cannot drift apart: the
train/serve-skew lesson of the XDP model.

Anti-fingerprint discipline (§5.4):
* The User-Agent keys the window but is never a feature.
* The URI enters only as a repeat flag (did this path occur earlier in the window).
  Any renaming that keeps the access pattern leaves the features unchanged.
* Protocol capabilities (HTTP/2, TLS, session resumption) describe the client
  stack, not its behaviour, so that group is OFF by default.
* Sizes are log-scaled and form their own group, so a variant can drop them
  (as CF3 did for the XDP model).
"""
import math

import numpy as np

VALID = "valid"

# Feature groups in canonical column order. A model package records which groups
# (hence which columns) it was trained on; the scorer refuses a mismatch.
FEATURE_GROUPS = {
    "timing": ("log_iat",),                    # client-side: gaps between request starts
    "server_timing": ("log_rt", "log_urt"),    # server-side: also encodes origin load (R17)
    "completion": ("incomplete", "s_timeout"),
    "status": ("s2xx", "s3xx", "s4xx", "s5xx"),
    "method": ("m_get", "m_post", "m_other"),
    "size": ("log_rlen", "log_bsent", "size_ratio"),
    "connection": ("log_creq", "new_conn"),
    "uri": ("uri_repeat",),
    "ratelimit": ("lreq_limited",),
    "protocol": ("is_h2", "is_tls", "tls_reused"),
}
DEFAULT_GROUPS = ("timing", "server_timing", "completion", "status", "method", "size",
                  "connection", "uri", "ratelimit")
ALL_FEATURES = tuple(f for feats in FEATURE_GROUPS.values() for f in feats)
_IDX = {name: i for i, name in enumerate(ALL_FEATURES)}

IAT_CLIP = 3600.0        # s
RT_CLIP = 3600.0         # s
RLEN_CLIP = 1e7          # bytes
BSENT_CLIP = 1e9         # bytes
CREQ_CLIP = 1e4          # requests per connection
TIMEOUT_STATUSES = frozenset({408, 444, 499})   # client timed out / closed / no response
LIMITED = frozenset({"DELAYED", "REJECTED", "DELAYED_DRY_RUN", "REJECTED_DRY_RUN"})


def columns(groups=DEFAULT_GROUPS):
    """Matrix columns for a feature-group selection: ['valid', ...features]."""
    unknown = set(groups) - set(FEATURE_GROUPS)
    if unknown:
        raise ValueError(f"unknown feature groups: {sorted(unknown)}")
    return [VALID] + [f for g, feats in FEATURE_GROUPS.items() if g in groups for f in feats]


def start_time(rec):
    """Request start (wall clock): Nginx's $msec is written at completion."""
    return rec["msec"] - rec["rt"]


def _rows(recs):
    """Per-request features for records already sorted by start time, as an
    (n, len(ALL_FEATURES)) array. IAT and uri_repeat depend on earlier requests
    in the same window; everything else is per request."""
    a = np.zeros((len(recs), len(ALL_FEATURES)), dtype=np.float32)
    prev_start = None
    seen = set()
    ix = _IDX
    for i, r in enumerate(recs):
        start = r["msec"] - r["rt"]
        iat = 0.0 if prev_start is None else max(start - prev_start, 0.0)
        prev_start = start
        status = int(r["status"])
        method = r.get("method", "")
        rlen = math.log1p(min(max(r["rlen"], 0.0), RLEN_CLIP))
        bsent = math.log1p(min(max(r["bsent"], 0.0), BSENT_CLIP))
        row = a[i]
        row[ix["log_iat"]] = math.log1p(min(iat, IAT_CLIP))
        row[ix["log_rt"]] = math.log1p(min(max(r["rt"], 0.0), RT_CLIP))
        row[ix["log_urt"]] = math.log1p(min(max(r["urt"], 0.0), RT_CLIP))
        row[ix["incomplete"]] = 0.0 if r.get("compl") == "OK" else 1.0
        row[ix["s_timeout"]] = 1.0 if status in TIMEOUT_STATUSES else 0.0
        klass = status // 100
        if 2 <= klass <= 5:
            row[ix[f"s{klass}xx"]] = 1.0
        if method == "GET":
            row[ix["m_get"]] = 1.0
        elif method == "POST":
            row[ix["m_post"]] = 1.0
        else:
            row[ix["m_other"]] = 1.0
        row[ix["log_rlen"]] = rlen
        row[ix["log_bsent"]] = bsent
        row[ix["size_ratio"]] = bsent - rlen
        creq = r.get("creq", 0.0)
        row[ix["log_creq"]] = math.log1p(min(max(creq, 0.0), CREQ_CLIP))
        row[ix["new_conn"]] = 1.0 if creq <= 1 else 0.0
        uri = r.get("uri_h")
        row[ix["uri_repeat"]] = 1.0 if uri in seen else 0.0
        seen.add(uri)
        row[ix["lreq_limited"]] = 1.0 if r.get("lreq") in LIMITED else 0.0
        row[ix["is_h2"]] = 1.0 if str(r.get("proto", "")).startswith("HTTP/2") else 0.0
        row[ix["is_tls"]] = 1.0 if r.get("tls") else 0.0
        row[ix["tls_reused"]] = 1.0 if r.get("reused") == "r" else 0.0
    return a


def window_matrix(records, seq_len, cols):
    """Encode the last `seq_len` records (by arrival) as a left-padded
    (seq_len, len(cols)) float32 matrix, rows ordered by request start time."""
    recs = sorted(list(records)[-seq_len:], key=start_time)
    m = np.zeros((seq_len, len(cols)), dtype=np.float32)
    if not recs:
        return m
    feats = _rows(recs)
    pad = seq_len - len(recs)
    m[pad:, 0] = 1.0
    m[pad:, 1:] = feats[:, [_IDX[c] for c in cols[1:]]]
    return m


def apply_scaling(batch, mean, std):
    """Standardise a (B, T, C) or (T, C) batch with per-column mean/std; column 0
    (`valid`) is left as is and padding rows stay exactly zero. Used identically
    by the scorer and the trainer."""
    batch = np.asarray(batch, dtype=np.float32)
    mean = np.asarray(mean, dtype=np.float32).copy()
    std = np.asarray(std, dtype=np.float32).copy()
    mean[0], std[0] = 0.0, 1.0
    std[std == 0] = 1.0
    valid = batch[..., :1]
    out = (batch - mean) / std
    out[..., 0] = batch[..., 0]
    return out * valid


def window_summary(records, cols):
    """Non-sequential summary of a window, for the tabular baseline (decision 6):
    per-feature mean/std/max over the requests, plus count, time span, rate and
    the share of distinct URIs. Returns (vector, names)."""
    recs = sorted(records, key=start_time)
    feats = cols[1:]
    names = ([f"{f}_{s}" for f in feats for s in ("mean", "std", "max")]
             + ["n", "log_span", "log_rate", "uri_distinct_ratio"])
    if not recs:
        return np.zeros(len(names), dtype=np.float32), names
    a = _rows(recs)[:, [_IDX[c] for c in feats]]
    stats = np.stack([a.mean(axis=0), a.std(axis=0), a.max(axis=0)], axis=1).ravel()
    span = max(recs[-1]["msec"] - start_time(recs[0]), 1e-3)
    n = len(recs)
    extra = np.array([n, math.log1p(span), math.log1p(n / span),
                      len({r.get("uri_h") for r in recs}) / n], dtype=np.float32)
    return np.concatenate([stats.astype(np.float32), extra]), names
