"""Load and analyse an evaluation campaign (output of eval/run_campaign.py) or a single
run of test_distributed_suite.py.

Layout: <campaign>/<mode>/<run>/ holding provenance.json, availability_raw.csv,
availability.csv, metrics.csv, scenario_results.csv and ban_events.jsonl. A single
run directory (provenance.json at its top) is accepted as well.

Everything is deterministic (fixed bootstrap seed, fixed formatting), so re-analysing
published results reproduces the tables byte for byte. Run-level bootstrap intervals
from a handful of runs are indicative only: they cannot be wider than the spread of
those runs, which is why campaigns for the thesis should use >= 10 runs per mode.
"""
import json
import os
import re
import sys
from collections import Counter

import numpy as np
import pandas as pd

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)
import ban_events

MODE_ORDER = ["xdp", "iptables", "nginxlimits", "unprotected"]
MODE_NAMES = {"xdp": "XDP + daemon", "iptables": "iptables + daemon",
              "nginxlimits": "nginx limits only", "unprotected": "unprotected"}
PERIOD_ORDER = ["before", "during", "after"]
ATTACK_PHASES = r"Phase 2|Phase 3"          # Pre-Mitigation, Sustained Stress, Post-Mitigation
SERVER_COLUMNS = ["CPU_Nginx_Pct", "CPU_Total_Pct", "CPU_Daemon_Pct", "PPS_Rx",
                  "IP_InReceives", "PreStack_Dropped", "TCP_Estab", "TCP_SynRecv"]
BOOT_N = 2000
BOOT_SEED = 20261013


def natural_key(s):
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", str(s))]


def split_label(label):
    """(mode, cell) of a run label. A campaign recorded with `--loads` (EXP-C) labels a run `mode@cell`, e.g.
    `xdp@loadgen125`; a plain label is the closed-loop `wrk` default, whose cell is ''."""
    mode, _, cell = str(label).partition("@")
    return mode, cell


def cells(labels):
    """The load cells of a set of run labels, the closed-loop one ('') first, the others in natural order."""
    return sorted({split_label(m)[1] for m in labels}, key=natural_key)


def has_cells(labels):
    return any(split_label(m)[1] for m in labels)


def reference_label(reference, cell):
    """The label of the reference mode inside a load cell."""
    return reference + ("@" + cell if cell else "")


def mode_name(label):
    return MODE_NAMES.get(split_label(label)[0], split_label(label)[0])


def display_name(label):
    mode, cell = split_label(label)
    return f"{MODE_NAMES.get(mode, mode)} ({cell})" if cell else MODE_NAMES.get(mode, mode)


def ordered_modes(labels):
    """Run labels in table order: by load cell (closed-loop first), then the usual mode order, then the
    other modes alphabetically. Without cells that is the order campaigns have always had."""
    def key(label):
        mode, cell = split_label(label)
        return natural_key(cell), MODE_ORDER.index(mode) if mode in MODE_ORDER else len(MODE_ORDER), mode
    return sorted(set(labels), key=key)


def _read_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def find_runs(path):
    """[(mode, run, run_dir)] for every run under `path` (a campaign, or one run)."""
    if os.path.isfile(os.path.join(path, "provenance.json")):
        label = _read_json(os.path.join(path, "provenance.json"))["mode"]["label"]
        return [(label, os.path.basename(os.path.normpath(path)), path)]
    runs = []
    for mode_dir in sorted(os.listdir(path)):
        mdir = os.path.join(path, mode_dir)
        if not os.path.isdir(mdir):
            continue
        for run in sorted(os.listdir(mdir), key=natural_key):
            rdir = os.path.join(mdir, run)
            if os.path.isfile(os.path.join(rdir, "provenance.json")):
                label = _read_json(os.path.join(rdir, "provenance.json"))["mode"]["label"]
                runs.append((label, run, rdir))
    return runs


def load(path):
    """The campaign as DataFrames: runs, raw, agg, metrics, scenarios, events.

    raw gains Attack_Start (from scenario_results.csv) and rel_s = request start minus
    attack start, which the equal-exposure window analysis uses."""
    found = find_runs(path)
    if not found:
        raise SystemExit(f"no runs (provenance.json) under {path}")
    files = {"raw": "availability_raw.csv", "agg": "availability.csv",
             "metrics": "metrics.csv", "scenarios": "scenario_results.csv",
             "server_requests": "server_requests.csv"}
    tables = {k: [] for k in files}
    runs, events = [], []
    for mode, run, rdir in found:
        prov = _read_json(os.path.join(rdir, "provenance.json"))
        settings = prov.get("settings") or {}
        runs.append({"mode": mode, "run": run, "dir": rdir, "status": prov.get("status"),
                     "commit": (prov.get("git") or {}).get("commit"),
                     "operating_point": (prov.get("operating_point") or {}).get("name"),
                     "profile_seed": settings.get("PROFILE_SEED"),
                     "attack_duration": settings.get("ATTACK_DURATION")})
        for key, name in files.items():
            f = os.path.join(rdir, name)
            if os.path.isfile(f) and os.path.getsize(f) > 0:
                df = pd.read_csv(f)
                df.insert(0, "run", run)
                df.insert(0, "mode", mode)
                tables[key].append(df)
        for e in ban_events.read_events(os.path.join(rdir, "ban_events.jsonl")):
            events.append({"mode": mode, "run": run, "t_wall": e.get("t_wall"),
                           "kind": e.get("kind"), "ip": e.get("ip"), "engine": e.get("engine")})
    data = {k: (pd.concat(v, ignore_index=True) if v else pd.DataFrame()) for k, v in tables.items()}
    data["runs"] = pd.DataFrame(runs)
    data["events"] = pd.DataFrame(events)
    raw, scen = data["raw"], data["scenarios"]
    if not raw.empty and not scen.empty and "T_Start" in raw:
        timeline = scen[["mode", "run", "Data_Scenario", "Attack_Start"]].rename(
            columns={"Data_Scenario": "Scenario"})
        raw = raw.merge(timeline, on=["mode", "run", "Scenario"], how="left")
        raw["rel_s"] = raw["T_Start"] - raw["Attack_Start"]
        data["raw"] = raw
    return data


def _scenario_order(df, column="Scenario"):
    return list(pd.unique(df[column])) if not df.empty else []


def _sort(df, scenarios, extra=()):
    """Rows in suite scenario order, then mode order, then the given (column, order) keys."""
    if df.empty:
        return df
    keys = {"scenario": {s: i for i, s in enumerate(scenarios)},
            "mode": {m: i for i, m in enumerate(ordered_modes(df["mode"]))}}
    for col, order in extra:
        keys[col] = {v: i for i, v in enumerate(order)}
    return df.sort_values(list(keys), key=lambda s: s.map(keys[s.name])).reset_index(drop=True)


def _pooled(counts):
    ok, n = counts[..., 0].sum(axis=-1), counts[..., 1].sum(axis=-1)
    return np.divide(ok, n, out=np.full(np.shape(ok), np.nan), where=n > 0)


def _boot_ci(counts):
    """95 % percentile interval (in %) of pooled success, resampling whole runs.
    counts: array [(ok, n)] with one row per run."""
    counts = np.asarray(counts, dtype=float)
    if len(counts) == 0:
        return (np.nan, np.nan)
    rng = np.random.default_rng(BOOT_SEED)
    idx = rng.integers(0, len(counts), size=(BOOT_N, len(counts)))
    lo, hi = np.nanpercentile(_pooled(counts[idx]), [2.5, 97.5])
    return 100 * lo, 100 * hi


def _per_run_counts(rows):
    g = rows.groupby("run", sort=False).OK.agg(["sum", "count"])
    return g.loc[sorted(g.index, key=natural_key)]


def availability(raw):
    """Legit success per scenario, mode and period: pooled %, run-bootstrap 95 % CI,
    per-run %."""
    if raw.empty:
        return pd.DataFrame()
    rows = []
    for (scen, mode, period), g in raw.groupby(["Scenario", "mode", "Period"], sort=False):
        per_run = _per_run_counts(g)
        ok, n = int(per_run["sum"].sum()), int(per_run["count"].sum())
        lo, hi = _boot_ci(per_run[["sum", "count"]].to_numpy())
        rows.append({"scenario": scen, "mode": mode, "period": period, "runs": len(per_run),
                     "n": n, "ok": ok, "success_pct": 100 * ok / n if n else np.nan,
                     "ci_lo": lo, "ci_hi": hi,
                     "per_run_pct": "/".join(f"{100 * s / c:.0f}" for s, c in per_run.to_numpy())})
    return _sort(pd.DataFrame(rows), _scenario_order(raw), [("period", PERIOD_ORDER)])


def delta_vs_reference(raw, runs, reference="unprotected", period="during"):
    """Difference in success (percentage points) of every mode vs `reference`.

    When the runs of both modes carry PROFILE_SEEDs and share them (an interleaved
    campaign), runs with the same seed form a block and blocks are resampled together
    (paired). Otherwise each mode's runs are resampled independently. Fisher's exact
    test on pooled requests is reported too; it ignores run/client clustering."""
    try:
        from scipy.stats import fisher_exact
    except ImportError:                                   # optional dependency
        fisher_exact = None
    if raw.empty or reference not in set(raw["mode"]):
        return pd.DataFrame()
    seed_of = {(r.mode, r.run): r.profile_seed for r in runs.itertuples()}
    d = raw[raw.Period == period]
    rows = []
    for scen, gs in d.groupby("Scenario", sort=False):
        ref_runs = gs[gs["mode"] == reference]
        if ref_runs.empty:
            continue
        ref_counts = _per_run_counts(ref_runs)
        for mode in ordered_modes(gs["mode"]):
            if mode == reference:
                continue
            m_counts = _per_run_counts(gs[gs["mode"] == mode])
            seeds_m = {seed_of.get((mode, r)): tuple(v) for r, v in zip(m_counts.index, m_counts.to_numpy())}
            seeds_r = {seed_of.get((reference, r)): tuple(v) for r, v in zip(ref_counts.index, ref_counts.to_numpy())}
            common = sorted(k for k in set(seeds_m) & set(seeds_r) if k is not None)
            paired = (common and None not in seeds_m and None not in seeds_r
                      and len(seeds_m) == len(m_counts) and len(seeds_r) == len(ref_counts))
            rng = np.random.default_rng(BOOT_SEED)
            if paired:
                a = np.array([seeds_m[k] for k in common], dtype=float)
                b = np.array([seeds_r[k] for k in common], dtype=float)
                idx = rng.integers(0, len(common), size=(BOOT_N, len(common)))
                diffs = _pooled(a[idx]) - _pooled(b[idx])
                method = f"paired by PROFILE_SEED ({len(common)} blocks)"
            else:
                a, b = m_counts.to_numpy(dtype=float), ref_counts.to_numpy(dtype=float)
                ia = rng.integers(0, len(a), size=(BOOT_N, len(a)))
                ib = rng.integers(0, len(b), size=(BOOT_N, len(b)))
                diffs = _pooled(a[ia]) - _pooled(b[ib])
                method = "independent runs"
            lo, hi = np.nanpercentile(diffs, [2.5, 97.5])
            (ok_m, n_m), (ok_r, n_r) = m_counts.sum().to_numpy(), ref_counts.sum().to_numpy()
            p = (fisher_exact([[ok_m, n_m - ok_m], [ok_r, n_r - ok_r]])[1]
                 if fisher_exact else np.nan)
            rows.append({"scenario": scen, "mode": mode, "reference": reference,
                         "delta_pp": 100 * (ok_m / n_m - ok_r / n_r), "ci_lo": 100 * lo,
                         "ci_hi": 100 * hi, "method": method, "fisher_p": p})
    return _sort(pd.DataFrame(rows), _scenario_order(raw))


def delta_vs_reference_by_cell(raw, runs, reference="unprotected", period="during"):
    """delta_vs_reference inside each load cell of a `--loads` campaign: every label is compared with the
    `reference` mode of its own cell, never across load models. The first column, `cell`, is '' for the
    closed-loop default."""
    frames = []
    for cell in cells(raw["mode"]):
        part = raw[raw["mode"].map(lambda label, cell=cell: split_label(label)[1] == cell)]
        df = delta_vs_reference(part, runs, reference_label(reference, cell), period)
        if not df.empty:
            df.insert(0, "cell", cell)
            frames.append(df)
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


OFFERED_STATUSES = ("200", "503", "499")       # the rest of the statuses is summed as "other"
DEFAULT_WINDOW_S = 30                           # the attack's length when the run recorded none


def offered(server_requests, runs):
    """The load the server received from the bots (server_requests.csv: the Nginx access log by the second a
    request arrived), per scenario and run label over the first ATTACK_DURATION seconds of each run: the mean
    per second over the runs, the median second (the first, in which the generators start, left out) and
    the answers by status. Empty without the file."""
    if server_requests.empty:
        return pd.DataFrame()
    window = {(r.mode, r.run): (int(float(r.attack_duration)) if pd.notna(r.attack_duration)
                                and float(r.attack_duration) > 0 else DEFAULT_WINDOW_S)
              for r in runs.itertuples()}
    bots = server_requests[(server_requests.Client_Class == "bot") & server_requests.T_Rel_s.notna()]
    rows = []
    for (scen, mode), g in bots.groupby(["Data_Scenario", "mode"], sort=False):
        per_run = []
        for run, gr in g.groupby("run", sort=False):
            w = window[(mode, run)]
            gr = gr[(gr.T_Rel_s >= 0) & (gr.T_Rel_s < w)]
            by_second = gr.groupby(gr.T_Rel_s.astype(int)).Requests.sum().reindex(range(w), fill_value=0)
            by_status = gr.groupby(gr.Status.astype(str)).Requests.sum()
            known = {s: by_status.get(s, 0) for s in OFFERED_STATUSES}
            per_run.append({"w": w, "total": by_second.sum(), "median": by_second.iloc[1:].median() if w > 1 else np.nan,
                            **known, "other": by_status.sum() - sum(known.values())})
        n = len(per_run)
        w = per_run[0]["w"]
        rows.append({"scenario": scen, "mode": mode, "runs": n, "window_s": w,
                     "offered_per_s": sum(p["total"] / p["w"] for p in per_run) / n,
                     "offered_median_per_s": float(np.nanmean([p["median"] for p in per_run])),
                     "status_200_per_s": sum(p["200"] / p["w"] for p in per_run) / n,
                     "status_503_per_s": sum(p["503"] / p["w"] for p in per_run) / n,
                     "status_499_per_s": sum(p["499"] / p["w"] for p in per_run) / n,
                     "other_status_per_s": sum(p["other"] / p["w"] for p in per_run) / n})
    return _sort(pd.DataFrame(rows), _scenario_order(server_requests, "Data_Scenario"))


def _latency_row(values):
    v = values.astype(float)
    return {"n": len(v), "p50_ms": v.quantile(.5) if len(v) else np.nan,
            "p95_ms": v.quantile(.95) if len(v) else np.nan,
            "p99_ms": v.quantile(.99) if len(v) else np.nan}


def latency(raw, period="during"):
    """Latency (ms) of successful requests per scenario, mode and client profile (+ ALL)."""
    if raw.empty:
        return pd.DataFrame()
    ok = raw[(raw.Period == period) & (raw.OK == 1)]
    rows = []
    for (scen, mode), g in ok.groupby(["Scenario", "mode"], sort=False):
        for prof, gg in [("ALL", g)] + sorted(g.groupby("Profile"), key=lambda t: t[0]):
            rows.append({"scenario": scen, "mode": mode, "profile": prof,
                         **_latency_row(gg.Latency_ms)})
    profiles = ["ALL"] + sorted(set(ok.Profile)) if not ok.empty else ["ALL"]
    return _sort(pd.DataFrame(rows), _scenario_order(raw), [("profile", profiles)])


def window(raw, seconds):
    """Requests started in [0, seconds) after the attack start: the same exposure in
    every mode, whatever the harness did afterwards."""
    if raw.empty or "rel_s" not in raw:
        return pd.DataFrame()
    w = raw[(raw.rel_s >= 0) & (raw.rel_s < seconds)]
    rows = []
    for (scen, mode), g in w.groupby(["Scenario", "mode"], sort=False):
        for prof, gg in (("ALL", g), ("perfect", g[g.Profile == "perfect"])):
            served = gg[gg.OK == 1].Latency_ms
            rows.append({"scenario": scen, "mode": mode, "profile": prof, "window_s": seconds,
                         "n": len(gg), "success_pct": 100 * gg.OK.mean() if len(gg) else np.nan,
                         "p50_ms": served.quantile(.5) if len(served) else np.nan,
                         "p95_ms": served.quantile(.95) if len(served) else np.nan})
    return _sort(pd.DataFrame(rows), _scenario_order(raw), [("profile", ["ALL", "perfect"])])


def _json_values(series):
    out = []
    for js in series.dropna():
        if str(js).strip():
            v = json.loads(js)
            out.extend(v.values() if isinstance(v, dict) else v)
    return out


def detection(scenarios):
    """Per scenario and mode, from scenario_results.csv (ban events): bots banned, exact
    time-to-mitigate, first-ban engines, GRU bans and false positives."""
    if scenarios.empty:
        return pd.DataFrame()
    rows = []
    for (scen, mode), g in scenarios.groupby(["Data_Scenario", "mode"], sort=False):
        ttm = sorted(float(t) for t in _json_values(g.TTM_Exact_By_Bot))
        engines = Counter(_json_values(g.Engine_By_Bot))
        fps = sorted(set(_json_values(g.FP_IPs)))
        rows.append({
            "scenario": scen, "mode": mode, "runs": len(g), "bots": int(g.Bots.sum()),
            "banned": len(ttm),
            "ttm_median_s": float(np.median(ttm)) if ttm else np.nan,
            "ttm_min_s": ttm[0] if ttm else np.nan, "ttm_max_s": ttm[-1] if ttm else np.nan,
            "engines": ", ".join(f"{k}:{v}" for k, v in sorted(engines.items())),
            "gru_bans": engines.get("gru", 0), "fp_count": len(fps), "fp_ips": " ".join(fps),
            "fp_source": "/".join(sorted(set(g.FP_Source.dropna().astype(str)))),
            "exposure_mean_s": g.Exposure_s.mean(),
        })
    return _sort(pd.DataFrame(rows), _scenario_order(scenarios, "Data_Scenario"))


def server(metrics):
    """Mean server-side load over the attack phases (Phase 2, 2A, 3) per scenario and mode."""
    if metrics.empty:
        return pd.DataFrame()
    m = metrics[metrics.Phase.str.contains(ATTACK_PHASES)]
    cols = [c for c in SERVER_COLUMNS if c in m]
    out = m.groupby(["Scenario", "mode"], sort=False)[cols].mean().reset_index()
    out = out.rename(columns={"Scenario": "scenario"})
    return _sort(out, _scenario_order(metrics))


# ─────────────────────────────── Markdown summary ───────────────────────────────

def _f(x, fmt="{:.1f}", empty="—"):
    return empty if x is None or (isinstance(x, float) and np.isnan(x)) else fmt.format(x)


def _table(header, rows):
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    lines += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(lines)


def summary_markdown(title, data, tables, window_s, reference):
    runs = data["runs"]
    av, dl, lat, win, det, srv = (tables[k] for k in
                                  ("availability", "delta_vs_reference", "latency", "window",
                                   "detection", "server"))
    per_mode = runs.groupby("mode").size()
    out = [f"# Campaign analysis: {title}" if title else "# Campaign analysis", "",
           ("Generated by `eval/analyze_campaign.py` (deterministic: re-running it on this "
            "directory reproduces this file)."), ""]
    out.append(_table(["", ""], [
        ["Runs per mode", ", ".join(f"{display_name(m)}: {per_mode[m]}"
                                    for m in ordered_modes(per_mode.index))],
        ["Commit(s)", ", ".join(sorted(str(c)[:12] for c in runs.commit.dropna().unique())) or "—"],
        ["Operating point(s)", ", ".join(sorted(map(str, runs.operating_point.dropna().unique()))) or "—"],
        ["Attack duration", ", ".join(sorted({("historical (stop on ban)" if not d else f"{d:g} s")
                                              for d in runs.attack_duration.fillna(0)}))],
        ["Run status", ", ".join(f"{k}: {v}" for k, v in runs.status.fillna("?").value_counts().sort_index().items())],
    ]))
    if not av.empty:
        out += ["", "## Legitimate-client availability during the attack", ""]
        d = av[av.period == "during"]
        other = av.set_index(["scenario", "mode", "period"])
        rows = []
        for r in d.itertuples():
            b = other.success_pct.get((r.scenario, r.mode, "before"), np.nan)
            a = other.success_pct.get((r.scenario, r.mode, "after"), np.nan)
            rows.append([r.scenario, display_name(r.mode), f"**{_f(r.success_pct)} %**",
                         f"{_f(r.ci_lo)}–{_f(r.ci_hi)}", r.per_run_pct, r.n, _f(b), _f(a)])
        out.append(_table(["Scenario", "Mode", "During", "95 % CI (runs)", "Per run", "n",
                           "Before %", "After %"], rows))
    if not dl.empty and "cell" in dl.columns:
        out += ["", f"## Difference vs the {display_name(reference)} arm of the same load cell (during)", ""]
        out.append(_table(["Cell", "Scenario", "Mode", "Δ pp", "95 % CI", "Resampling", "Fisher p (pooled)"],
                          [[r.cell or "wrk", r.scenario, mode_name(r.mode), _f(r.delta_pp, "{:+.1f}"),
                            f"{_f(r.ci_lo, '{:+.1f}')} to {_f(r.ci_hi, '{:+.1f}')}", r.method,
                            _f(r.fisher_p, "{:.2g}")] for r in dl.itertuples()]))
    elif not dl.empty:
        out += ["", f"## Difference vs {display_name(reference)} (during)", ""]
        out.append(_table(["Scenario", "Mode", "Δ pp", "95 % CI", "Resampling", "Fisher p (pooled)"],
                          [[r.scenario, display_name(r.mode), _f(r.delta_pp, "{:+.1f}"),
                            f"{_f(r.ci_lo, '{:+.1f}')} to {_f(r.ci_hi, '{:+.1f}')}", r.method,
                            _f(r.fisher_p, "{:.2g}")] for r in dl.itertuples()]))
    if not lat.empty:
        out += ["", "## Latency of served requests during the attack (ms)", ""]
        piv = lat[lat.profile.isin(["perfect", "ALL"])]
        rows = []
        for (scen, mode), g in piv.groupby(["scenario", "mode"], sort=False):
            byp = {r.profile: r for r in g.itertuples()}

            def cell(p, byp=byp):
                if p not in byp:
                    return "—"
                return f"{_f(byp[p].p50_ms, '{:.0f}')} / {_f(byp[p].p95_ms, '{:.0f}')} (n={byp[p].n})"

            rows.append([scen, display_name(mode), cell("perfect"), cell("ALL")])
        out.append(_table(["Scenario", "Mode", "perfect clients p50 / p95", "all clients p50 / p95"],
                          rows))
    if not win.empty:
        out += ["", f"## Equal-exposure window: requests started 0–{window_s:g} s after attack start", ""]
        rows = []
        for (scen, mode), g in win.groupby(["scenario", "mode"], sort=False):
            byp = {r.profile: r for r in g.itertuples()}

            def cell(p, byp=byp):
                if p not in byp or not byp[p].n:
                    return "n=0"
                return (f"{_f(byp[p].success_pct)} % (n={byp[p].n}), "
                        f"p50 {_f(byp[p].p50_ms, '{:.0f}')} ms")

            rows.append([scen, display_name(mode), cell("perfect"), cell("ALL")])
        out.append(_table(["Scenario", "Mode", "perfect clients", "all clients"], rows))
    if not det.empty:
        out += ["", "## Detection (ban events)", ""]
        out.append(_table(["Scenario", "Mode", "Banned / bots", "TTM median (min–max) s",
                           "First-ban engines", "GRU bans", "False positives", "Exposure s"],
                          [[r.scenario, display_name(r.mode), f"{r.banned}/{r.bots}",
                            (f"{_f(r.ttm_median_s, '{:.2f}')} ({_f(r.ttm_min_s, '{:.2f}')}–"
                             f"{_f(r.ttm_max_s, '{:.2f}')})"), r.engines or "—", r.gru_bans,
                            f"{r.fp_count} [{r.fp_source}]" + (f": {r.fp_ips}" if r.fp_ips else ""),
                            _f(r.exposure_mean_s)] for r in det.itertuples()]))
    if not srv.empty:
        out += ["", "## Server load, mean over the attack phases", ""]
        cols = [c for c in SERVER_COLUMNS if c in srv]
        out.append(_table(["Scenario", "Mode"] + cols,
                          [[r["scenario"], display_name(r["mode"])]
                           + [_f(r[c], "{:.0f}") for c in cols] for _, r in srv.iterrows()]))
    off = tables.get("offered")
    has_offered = off is not None and not off.empty
    if has_offered:
        out += ["", "## Offered load at the server (bot addresses), mean per second over the attack", ""]
        out.append(_table(["Scenario", "Mode", "Runs", "Window s", "Offered /s", "Median second /s",
                           "200 /s", "503 /s", "499 /s", "Other /s"],
                          [[r.scenario, display_name(r.mode), r.runs, r.window_s, _f(r.offered_per_s, "{:.0f}"),
                            _f(r.offered_median_per_s, "{:.0f}"), _f(r.status_200_per_s, "{:.0f}"),
                            _f(r.status_503_per_s, "{:.0f}"), _f(r.status_499_per_s, "{:.0f}"),
                            _f(r.other_status_per_s, "{:.0f}")] for r in off.itertuples()]))
    out += ["", "## Notes", "",
            ("* Availability counts every legit request by the period in which it *started* "
             "(curl `--max-time 10`); a timeout counts as a failure."),
            ("* Confidence intervals resample whole runs; with few runs per mode they only "
             "reflect the spread of those runs. Fisher's test pools requests and ignores "
             "clustering by run and client."),
            ("* Time-to-mitigate is the first ban event of each bot minus the recorded attack "
             "start; false positives are ban events for legit clients (`ban events`), none by "
             "construction without a daemon (`no daemon`), or the legacy ping check (`ping`)."),
            ]
    if has_offered:
        out.append("* Offered load counts the request lines of the bot addresses in the Nginx access log by the "
                   "second a request arrived. A line is written when a request finishes, so above the server's "
                   "limit it is a floor of what reached the server. 503 is the status of a `limit_req` or "
                   "`limit_conn` rejection; 499 is a client that closed first.")
    out.append("")
    return "\n".join(out)
