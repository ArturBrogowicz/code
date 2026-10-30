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

L7 v2 (docs/L7V2_DESIGN.md 8.1-8.2; constants pre-registered in ml/l7v2_model_prereg.json):
* The discipline is extended: class-level semantics may enter, identities may not. The
  route class (rc, from the site map at ingest) gives the `nav` group: is_page, is_asset,
  is_costly, asset_refetch, page_revisit, ref_present, ref_known and log_page_gap. Like
  uri_repeat, refetch, revisit and ref_known look back within the window only, and they
  read hashes only through equality (ref_h against the uri_h of the window's pages).
* View tokens, for the two-level model: in start-time order (ties in arrival order), a
  page request (C1) opens a view and the key's following non-page requests belong to it
  until the next page request; a request while no page view is open (before the key's
  first page in the window) is a pageless token of its own. A token is complete when the
  next one starts (its dwell is the gap between the starts); the open token is never
  scored. token_matrix() encodes the last `max_views` complete tokens, recomputed from
  their own requests, as a left-padded (max_views, C) matrix; token_summary() gives the
  HGB and the LR the same tokens summarized, so a GRU win has to come from order.
* The sid keys the window (l7_ingest.key_v2) but is never a feature; nor is the UA.
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
    # L7 v2 navigation (appended last, so every earlier column keeps its index)
    "nav": ("is_page", "is_asset", "is_costly", "asset_refetch", "page_revisit", "ref_present",
            "ref_known", "log_page_gap"),
}
DEFAULT_GROUPS = ("timing", "server_timing", "completion", "status", "method", "size",
                  "connection", "uri", "ratelimit")
# L7 v2 per-request groups (design 8.2): the P5 defaults without server_timing (R17), plus nav.
V2_REQUEST_GROUPS = ("timing", "completion", "status", "method", "size", "connection", "uri",
                     "ratelimit", "nav")
ALL_FEATURES = tuple(f for feats in FEATURE_GROUPS.values() for f in feats)
_IDX = {name: i for i, name in enumerate(ALL_FEATURES)}

# The site map's classes (l7_ingest.route_class gives each record its rc).
PAGE_CLASSES = ("C1",)
ASSET_CLASSES = ("C0",)
COSTLY_CLASSES = ("C3", "C5")
PAGE_GAP_CLIP = 3600.0   # s

# View tokens (design 8.1).
MAX_VIEWS = 32
MIN_VIEWS = 4
DWELL_CLIP = 3600.0      # s
COUNT_CLIP = 10000       # requests per token
TOKEN_FEATURES = ("log_dwell", "log_n_req", "asset_share", "asset_refetch_share", "log_n_costly",
                  "page_view", "page_revisit", "ref_present", "ref_known", "s2xx_share",
                  "s3xx_share", "s4xx_share", "s5xx_share", "get_share", "post_share",
                  "other_share", "new_conn_share")
TOKEN_COLUMNS = (VALID, *TOKEN_FEATURES)
SUMMARY_COUNTS = ("n_views", "log_n_req_total", "log_span", "log_rate")
_TIDX = {name: i for i, name in enumerate(TOKEN_FEATURES)}

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
    pages, assets, last_page = set(), set(), None     # nav: the window's pages and assets so far
    ix = _IDX
    for i, r in enumerate(recs):
        start = r["msec"] - r["rt"]
        iat = 0.0 if prev_start is None else max(start - prev_start, 0.0)
        prev_start = start
        rc = r.get("rc")
        is_page, is_asset = rc in PAGE_CLASSES, rc in ASSET_CLASSES
        ref = r.get("ref_h")
        nav = a[i]
        nav[ix["is_page"]] = 1.0 if is_page else 0.0
        nav[ix["is_asset"]] = 1.0 if is_asset else 0.0
        nav[ix["is_costly"]] = 1.0 if rc in COSTLY_CLASSES else 0.0
        nav[ix["asset_refetch"]] = 1.0 if is_asset and r.get("uri_h") in assets else 0.0
        nav[ix["page_revisit"]] = 1.0 if is_page and r.get("uri_h") in pages else 0.0
        nav[ix["ref_present"]] = 1.0 if ref is not None else 0.0
        nav[ix["ref_known"]] = 1.0 if ref is not None and ref in pages else 0.0
        if last_page is not None:
            nav[ix["log_page_gap"]] = math.log1p(min(max(start - last_page, 0.0), PAGE_GAP_CLIP))
        if is_asset:
            assets.add(r.get("uri_h"))
        if is_page:
            pages.add(r.get("uri_h"))
            last_page = start
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


# ───────────────────────── L7 v2: view tokens (design 8.1) ─────────────────────────

def ordered(records):
    """Records in the view order: by request start time, ties in arrival order (sorted() is stable)."""
    return sorted(records, key=start_time)


def token_starts(recs):
    """Indices, into the start-ordered `recs`, of the requests that open a token: every page request, and every
    request while no page view is open (a pageless token). Slicing `recs` at one of these indices leaves the later
    boundaries unchanged, so a window cut at a token boundary tokenizes as the whole history does."""
    opens, page_open = [], False
    for i, r in enumerate(recs):
        if r.get("rc") in PAGE_CLASSES:
            opens.append(i)
            page_open = True
        elif not page_open:
            opens.append(i)
    return opens


def n_complete_tokens(records):
    """The number of complete (closed) tokens in a key's records: every token but the open last one."""
    return max(len(token_starts(ordered(records))) - 1, 0)


def _token_rows(recs, opens, max_views):
    """Features of the last `max_views` complete tokens of start-ordered `recs` (token boundaries `opens`), with the
    navigation history (pages, assets) taken within those tokens only."""
    n_closed = len(opens) - 1
    if n_closed <= 0:
        return np.zeros((0, len(TOKEN_FEATURES)), dtype=np.float32)
    first = max(0, n_closed - max_views)
    out = np.zeros((n_closed - first, len(TOKEN_FEATURES)), dtype=np.float32)
    pages, assets = set(), set()
    ix = _TIDX
    for row, j in enumerate(range(first, n_closed)):
        lo, hi = opens[j], opens[j + 1]
        opener = recs[lo]
        page = opener.get("rc") in PAGE_CLASSES
        ref = opener.get("ref_h")
        t = out[row]
        t[ix["log_dwell"]] = math.log1p(min(max(start_time(recs[hi]) - start_time(opener), 0.0), DWELL_CLIP))
        t[ix["page_view"]] = 1.0 if page else 0.0
        t[ix["page_revisit"]] = 1.0 if page and opener.get("uri_h") in pages else 0.0
        t[ix["ref_present"]] = 1.0 if ref is not None else 0.0
        t[ix["ref_known"]] = 1.0 if ref is not None and ref in pages else 0.0
        if page:
            pages.add(opener.get("uri_h"))
        n = hi - lo
        n_asset = refetch = costly = new_conn = get = post = 0
        status = [0, 0, 0, 0]
        for r in recs[lo:hi]:
            rc = r.get("rc")
            if rc in ASSET_CLASSES:
                n_asset += 1
                refetch += r.get("uri_h") in assets
                assets.add(r.get("uri_h"))
            elif rc in COSTLY_CLASSES:
                costly += 1
            klass = int(r["status"]) // 100
            if 2 <= klass <= 5:
                status[klass - 2] += 1
            method = r.get("method", "")
            get += method == "GET"
            post += method == "POST"
            new_conn += r.get("creq", 0.0) <= 1
        t[ix["log_n_req"]] = math.log1p(min(n, COUNT_CLIP))
        t[ix["asset_share"]] = n_asset / n
        t[ix["asset_refetch_share"]] = refetch / n_asset if n_asset else 0.0
        t[ix["log_n_costly"]] = math.log1p(min(costly, COUNT_CLIP))
        for k, name in enumerate(("s2xx_share", "s3xx_share", "s4xx_share", "s5xx_share")):
            t[ix[name]] = status[k] / n
        t[ix["get_share"]] = get / n
        t[ix["post_share"]] = post / n
        t[ix["other_share"]] = (n - get - post) / n
        t[ix["new_conn_share"]] = new_conn / n
    return out


def view_tokens(records, max_views=MAX_VIEWS):
    """The last `max_views` complete tokens of a key's records as a (n, len(TOKEN_FEATURES)) float32 array, oldest
    first, recomputed from the window's own requests."""
    recs = ordered(records)
    return _token_rows(recs, token_starts(recs), max_views)


def token_matrix(records, max_views=MAX_VIEWS, cols=TOKEN_COLUMNS):
    """Encode the last `max_views` complete tokens of a key's records as a left-padded (max_views, len(cols)) float32
    matrix: column 0 is `valid`, the most recent complete token sits in the last row."""
    cols = list(cols)
    m = np.zeros((max_views, len(cols)), dtype=np.float32)
    toks = view_tokens(records, max_views)
    n = len(toks)
    if n:
        m[max_views - n:, 0] = 1.0
        m[max_views - n:, 1:] = toks[:, [_TIDX[c] for c in cols[1:]]]
    return m


def summary_names(cols=TOKEN_COLUMNS):
    """The names of token_summary's vector."""
    return [f"{f}_{s}" for f in list(cols)[1:] for s in ("mean", "std", "max")] + list(SUMMARY_COUNTS)


def token_summary(matrix, cols=TOKEN_COLUMNS):
    """The non-sequential summary of a token matrix, for the HGB and the LR (design 8.2): per token feature the mean,
    std and max over the valid tokens, plus the token count, the window's requests (log), its span (log of the summed
    dwells) and its request rate (log). Returns (vector, names); a window of no valid token gives zeros."""
    cols = list(cols)
    names = summary_names(cols)
    X = np.asarray(matrix, dtype=np.float32)
    rows = X[X[:, 0] > 0][:, 1:]
    if not len(rows):
        return np.zeros(len(names), dtype=np.float32), names
    stats = np.stack([rows.mean(axis=0), rows.std(axis=0), rows.max(axis=0)], axis=1).ravel()
    feats = cols[1:]
    n_req = float(np.expm1(rows[:, feats.index("log_n_req")].astype(np.float64)).sum())
    span = float(np.expm1(rows[:, feats.index("log_dwell")].astype(np.float64)).sum())
    extra = np.array([len(rows), math.log1p(n_req), math.log1p(span), math.log1p(n_req / max(span, 1e-3))],
                     dtype=np.float32)
    return np.concatenate([stats.astype(np.float32), extra]), names


def shuffle_valid_rows(matrix, rng):
    """A copy of a (T, C) window matrix with its valid rows (column 0 > 0) permuted among themselves: the
    shuffled-GRU ablation's input (tokens shuffled within the window at scoring, design 10)."""
    X = np.array(matrix, dtype=np.float32, copy=True)
    idx = np.flatnonzero(X[:, 0] > 0)
    X[idx] = X[rng.permutation(idx)]
    return X
