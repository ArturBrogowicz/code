#!/usr/bin/env python3
"""Check the numbers of docs/REPORT_ADDENDUM_EXP0_EXP1.md against the published campaigns.

Offline and read-only. The addendum (2026-10-12) reports the prototype experiments EXP-1, 1b,
1c (sections C-I), EXP-2b (K) and the F-45 validation (L). Their data are published as

    results/2026-10-12_exp1-default-4modes_prototype       EXP-1, 1b, 1c
    results/2026-10-12_exp2b-knee-nginxtuned_prototype     EXP-2b
    results/2026-10-12_f45-ack-stall-validation_prototype  F-45
    results/2026-10-12_exp1d-calibration-sweep_raw         EXP-1d (raw files)
    results/2026-10-12_exp2a-knee_prototype                EXP-2a (for the totals of section M)
    results/2026-10-11_superseded-dup-mac                  the duplicate-MAC baseline

and this tool recomputes each quoted number from those files with the definitions of the
earlier session's analysis scripts, which are not in the repository: a request belongs to the
attack by its start time, measured from the Phase-1 metrics timestamp; "after the bans" is a
request started in [Phase 2, Phase 3 - 1 s); the server metrics are the means of the Phase 2,
Phase 2A (2/3) and Phase 3 rows (Phase 2A (2/3) and Phase 3 for the section C table); the time
to mitigate is the first ban of a bot minus the Phase-1 timestamp.

    ./venv/bin/python eval/check_addendum.py [--results results] [--md FILE] [--csv FILE]

Each row compares one line of an addendum table or one sentence with the recomputed value and
says match, differs or cannot be checked (the data it rests on is not in the repository). A
number matches when the recomputed value rounds to the quoted one at the quoted precision, or,
for a sentence that says "about", lies within the tolerance written in the row. The addendum's
[INFERENCE] statements are not rated.
"""
import argparse
import csv
import io
import os
import re
import sys

import numpy as np
import pandas as pd
from scipy.stats import fisher_exact

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import campaign as C

EXP1 = "2026-10-12_exp1-default-4modes_prototype"
EXP2A = "2026-10-12_exp2a-knee_prototype"
EXP2B = "2026-10-12_exp2b-knee-nginxtuned_prototype"
F45 = "2026-10-12_f45-ack-stall-validation_prototype"
CALIB = "2026-10-12_exp1d-calibration-sweep_raw"
BASELINE = "2026-10-11_superseded-dup-mac"

SCEN = ["Distributed SYN Flood", "Distributed Low & Slow SYN", "Distributed UDP Flood",
        "Distributed HTTP Flood", "Distributed ACK Flood", "Distributed IP Fragmentation Flood",
        "Distributed Slowloris", "Distributed R.U.D.Y.", "Distributed Yo-Yo",
        "Multi-Vector Distributed Attack"]
SHORT = dict(zip(SCEN, ["SYN", "LowSlowSYN", "UDP", "HTTP", "ACK", "Frag", "Slowloris", "RUDY",
                        "YoYo", "Multi"], strict=True))
ORDER = list(SHORT.values())
FLOODS = ["SYN", "UDP", "ACK", "Frag", "Multi"]                  # section C's "floods"
SUSTAINED = ["UDP", "ACK", "Frag", "Multi"]                      # the flood outlives the bans
NET_FLOODS = ["UDP", "ACK", "Frag"]
MODES3 = ["xdp", "iptables", "unprotected"]
MODES4 = ["xdp", "iptables", "nginxlimits", "unprotected"]
BOTS = [f"10.0.2.{i}" for i in range(1, 11)]
PHASES_C = r"Sustained Stress \(2/3\)|Phase 3"                   # server metrics of section C
PHASES_H = r"Phase 2:|Sustained Stress \(2/3\)|Phase 3"          # server metrics of sections H and I
MATCH, DIFFERS, UNCHECKED = "match", "differs", "cannot be checked"

# what the addendum quotes ---------------------------------------------------------------------
D_TTM = {       # section D, XDP: median, min, max of the exact time to mitigate (s)
    "SYN": (1.54, 0.64, 1.83), "LowSlowSYN": (3.74, 3.57, 3.98), "UDP": (0.62, 0.41, 0.92),
    "HTTP": (0.78, 0.11, 1.00), "ACK": (1.35, 0.12, 10.32), "Frag": (0.55, 0.42, 1.20),
    "Slowloris": (3.94, 3.26, 4.17), "RUDY": (3.77, 3.56, 4.04), "YoYo": (0.54, 0.15, 0.81),
    "Multi": (1.26, 0.05, 3.69)}
D_HARNESS = {   # section D: the harness's own Avg TTM in runs 1-3 (s); None = "N/A (0/5)"
    "SYN": [2.16, 1.17, 1.77], "LowSlowSYN": [3.62, 4.18, 4.14], "UDP": [1.19, 1.27, 1.14],
    "HTTP": [1.10, 1.70, 1.61], "ACK": [1.12, None, 1.42], "Frag": [1.20, 1.26, 1.45],
    "Slowloris": [4.21, 3.45, 4.35], "RUDY": [4.05, 3.81, 4.31], "YoYo": [1.58, 1.71, 1.71],
    "Multi": [1.73, 1.95, 1.63]}
D_ENGINES = {"l4_volumetric": 54, "l4_slowconn": 30, "l7_rate": 33, "l4_syn": 18, "l4_lowsyn": 15, "gru": 0}
H_TTM_IPT = {   # section H.3: median exact time to mitigate with iptables (s)
    "SYN": 1.70, "LowSlowSYN": 3.78, "UDP": 0.73, "HTTP": 0.97, "ACK": 0.95, "Frag": 0.45,
    "Slowloris": 3.70, "RUDY": 3.60, "YoYo": 0.86, "Multi": 0.52}
H1 = {          # section H.1: scenario -> mode -> (success %, requests); None where only the % is given
    "SYN": {"xdp": (100.0, 80), "iptables": (100.0, 98), "unprotected": (100.0, 260)},
    "LowSlowSYN": {"xdp": (100.0, 147), "iptables": (100.0, 134), "unprotected": (100.0, 713)},
    "UDP": {"xdp": (100.0, 388), "iptables": (100.0, 406), "unprotected": (99.8, 555)},
    "ACK": {"xdp": (100.0, 463), "iptables": (100.0, 406), "unprotected": (100.0, 536)},
    "Frag": {"xdp": (100.0, 393), "iptables": (100.0, 403), "unprotected": (100.0, 530)},
    "HTTP": {"xdp": (100.0, 70), "iptables": (100.0, 74), "unprotected": (100.0, 347)},
    "YoYo": {"xdp": (100.0, 73), "iptables": (100.0, 72), "unprotected": (100.0, 563)},
    "Slowloris": {"xdp": (100.0, None), "iptables": (100.0, None), "unprotected": (100.0, 903)},
    "RUDY": {"xdp": (100.0, None), "iptables": (100.0, None), "unprotected": (100.0, 913)},
    "Multi": {"xdp": (100.0, None), "iptables": (100.0, None), "unprotected": (100.0, 787)}}
H2_LAT = {      # section H.2.1: 'perfect' clients, requests started in [0, 2.5) s: (p50, p95) ms
    "HTTP": {"xdp": (2, 115), "iptables": (3, 280), "unprotected": (338, 677)},
    "YoYo": {"xdp": (2, 276), "iptables": (2, 265), "unprotected": (319, 577)},
    "Multi": {"xdp": (2, 7), "iptables": (3, 6), "unprotected": (40, 225)},
    "UDP": {"xdp": (3, 10), "iptables": (3, 135), "unprotected": (4, 10)}}
I2_LAT = {"HTTP": (40, 359), "YoYo": (14, 287), "Multi": (3, 22)}       # section I.2, Nginx limits only
I2_SUSTAINED = {   # section I.2: ((Nginx limits p50, p95), (unprotected p50, p95)), window [2.5 s, end)
    "HTTP": ((25, 199), (266, 547)), "YoYo": ((2, 81), (2, 354)), "Multi": ((3, 45), (41, 173))}


# ──────────────────────────────── loading ────────────────────────────────

def _epoch(series):
    return (pd.to_datetime(series) - pd.Timestamp("1970-01-01")).dt.total_seconds()


class Data:
    """Requests (with the phase timestamps of their scenario), metrics, scenario results and ban
    events of one campaign, with the earlier session's column names."""

    def __init__(self, raw, metrics, scenarios, events):
        self.metrics = metrics
        self.scenarios = scenarios
        self.events = events
        phases = []
        for (mode, run, scen), g in metrics.groupby(["mode", "run", "scen"], sort=False):
            ph = {}
            for phase, ts in zip(g.Phase, g.ts, strict=True):
                key = ("P1" if phase.startswith("Phase 1") else "P2" if phase.startswith("Phase 2:")
                       else "P3" if phase.startswith("Phase 3") else phase)
                ph[key] = ts
            phases.append({"mode": mode, "run": run, "scen": scen, "P1": ph.get("P1"),
                           "P2": ph.get("P2"), "P3": ph.get("P3")})
        self.phases = pd.DataFrame(phases)
        self.phases["during_len"] = self.phases.P3 - self.phases.P1
        self.raw = raw.merge(self.phases, on=["mode", "run", "scen"], how="left")
        self.raw["rel"] = self.raw.t_start - self.raw.P1

    def requests(self, mode=None, scen=None, period=None, rel=None, profile=None):
        d = self.raw
        if mode is not None:
            d = d[d["mode"] == mode]
        if scen is not None:
            d = d[d.scen == scen]
        if period is not None:
            d = d[d.Period == period]
        if rel is not None:
            d = d[(d.rel >= rel[0]) & (d.rel < rel[1])]
        if profile is not None:
            d = d[d.Profile == profile]
        return d

    def after_the_bans(self, mode, scen):
        """Requests started in [Phase 2, Phase 3 - 1 s)."""
        d = self.raw
        return d[(d["mode"] == mode) & (d.scen == scen) & (d.t_start >= d.P2) & (d.t_start < d.P3 - 1.0)]

    def bot_bans(self):
        """The first ban of every bot per (mode, run, scenario): time to mitigate (s from the
        Phase-1 timestamp) and engine. A ban belongs to the scenario whose
        [Phase 1 - 0.5 s, Phase 3 + 12 s] holds it."""
        ev = self.events
        rows = []
        for e in ev[(ev.kind == "ban") & ev.ip.isin(BOTS)].itertuples():
            w = self.phases[(self.phases["mode"] == e.mode) & (self.phases.run == e.run)
                            & (self.phases.P1 - 0.5 <= e.t_wall) & (e.t_wall <= self.phases.P3 + 12)]
            if len(w):
                rows.append({"mode": e.mode, "run": e.run, "scen": w.scen.iloc[0], "ip": e.ip,
                             "t": e.t_wall, "ttm": e.t_wall - w.P1.iloc[0], "engine": e.engine})
        first = pd.DataFrame(rows, columns=["mode", "run", "scen", "ip", "t", "ttm", "engine"])
        first = first.sort_values("t")
        return first.groupby(["mode", "run", "scen", "ip"], sort=False).first().reset_index()


def load_campaign(path):
    d = C.load(path)
    raw = d["raw"].copy()
    raw["t_start"] = raw["T_Start"]
    raw["scen"] = raw.Scenario.map(SHORT)
    m = d["metrics"].copy()
    m["ts"] = _epoch(m.Timestamp)
    m["scen"] = m.Scenario.map(SHORT)
    sc = d["scenarios"].copy()
    sc["scen"] = sc.Data_Scenario.map(SHORT)
    return Data(raw, m, sc, d["events"])


def load_baseline(path):
    """The duplicate-MAC campaign of 2026-10-11: raw CSVs only; a run starts where the scenario
    sequence restarts at the SYN flood."""
    files = {"xdp": ("mitigation_performance.csv", "performance"),
             "iptables": ("metrics_iptables.csv", "iptables"),
             "unprotected": ("metrics_unprotected.csv", "unprotected")}
    raws, mets = [], []
    for mode, (metrics_file, tag) in files.items():
        m = pd.read_csv(os.path.join(path, metrics_file))
        r = pd.read_csv(os.path.join(path, f"availability_raw_{tag}.csv"))
        for df in (m, r):
            block = (df.Scenario != df.Scenario.shift()).cumsum()
            restart = (block != block.shift()) & (df.Scenario == SCEN[0])
            df["run"] = restart.cumsum().map("run{}".format)
            df["scen"] = df.Scenario.map(SHORT)
            df["mode"] = mode
        m["ts"] = _epoch(m.Timestamp)
        r["t_start"] = _epoch(r.Timestamp) - r.Latency_ms / 1000
        r["HTTP_Code"] = r.HTTP_Code.astype(str).str.zfill(3)
        raws.append(r)
        mets.append(m)
    return Data(pd.concat(raws, ignore_index=True), pd.concat(mets, ignore_index=True), None, None)


# ──────────────────────────────── helpers ────────────────────────────────

def pct(d):
    return 100.0 * d.OK.mean() if len(d) else float("nan")


def quantile(d, q):
    served = d[d.OK == 1].Latency_ms
    return float(served.quantile(q)) if len(served) else float("nan")


def metric_means(data, phases_re, scen, mode, cols):
    m = data.metrics
    m = m[(m.scen == scen) & (m["mode"] == mode) & m.Phase.str.contains(phases_re)]
    return {c: float(m[c].mean()) for c in cols}


def sustained_window_end(data, scen):
    """End of the window in which neither Nginx-limits-only nor unprotected had any ban: the
    shortest of their attacks minus half a second."""
    ph = data.phases
    return float(ph[ph["mode"].isin(["nginxlimits", "unprotected"]) & (ph.scen == scen)].during_len.min() - 0.5)


def during_percent(data, mode, scen):
    return pct(data.requests(mode, scen, "during"))


def spaced(xs, nd=2):
    return " / ".join("N/A" if x is None else f"{x:.{nd}f}" for x in xs)


class Table:
    """The rows of the comparison, in addendum order."""

    def __init__(self):
        self.rows = []

    def add(self, ident, where, claim, said, got, verdict, note=""):
        self.rows.append({"id": ident, "where": where, "claim": claim, "addendum": said,
                          "recomputed": got, "verdict": verdict, "note": note})

    def nums(self, ident, where, claim, quoted, got, nd=1, unit="", note="", tol=None, sep=" / "):
        """Compare lists of numbers. Without `tol` each recomputed value must round to the quoted
        one at `nd` decimals; with `tol` it must lie within tol of it."""
        def close(q, g):
            if q is None or g is None or np.isnan(g):
                return False
            return abs(g - q) <= tol if tol is not None else abs(round(g, nd) - q) < 10 ** -(nd + 2)

        ok = len(quoted) == len(got) and all(close(q, g) for q, g in zip(quoted, got, strict=True))

        def show(xs):
            return sep.join("n/a" if x is None or np.isnan(x) else f"{x:.{nd}f}" for x in xs) + unit

        self.add(ident, where, claim, show(quoted), show(got), MATCH if ok else DIFFERS, note)

    def text(self, ident, where, claim, said, got, ok, note=""):
        self.add(ident, where, claim, said, got, MATCH if ok else DIFFERS, note)

    def unchecked(self, ident, where, claim, said, why):
        self.add(ident, where, claim, said, "—", UNCHECKED, why)


# ──────────────────────────────── sections A and B ────────────────────────────────

def _recorded(path):
    """Start and end (second of day) and the end state of a recorded provenance.txt."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()

    def seconds(label):
        m = re.search(rf"^{label} \d{{4}}-\d\d-\d\dT(\d\d):(\d\d):(\d\d)", text, re.MULTILINE)
        return int(m.group(1)) * 3600 + int(m.group(2)) * 60 + int(m.group(3))

    nginx = re.search(r"nginx processes after final cleanup: (\d+)|nginx=(\d+)", text)
    netns = re.search(r"netns after: (\d+)|netns=(\d+)", text)
    return {"start": seconds("start"), "end": seconds("end"),
            "nginx": int(next(g for g in nginx.groups() if g)), "netns": int(next(g for g in netns.groups() if g))}


def _minute_ok(quoted_hhmm, second_of_day):
    """The addendum's HH:MM is the recorded time truncated or rounded to the minute."""
    h, m = (int(x) for x in quoted_hhmm.split(":"))
    return second_of_day // 60 == h * 60 + m or (second_of_day + 30) // 60 == h * 60 + m


def _hms(second_of_day):
    return f"{second_of_day // 3600:02d}:{second_of_day % 3600 // 60:02d}:{second_of_day % 60:02d}"


def section_a(t, res):
    src = os.path.join(res, EXP1, "source")
    rec = {m: _recorded(os.path.join(src, f"provenance_{m}.txt")) for m in MODES4}
    tuned = _recorded(os.path.join(res, EXP2B, "source", "provenance.txt"))
    x, a, u, n = rec["xdp"], rec["iptables"], rec["unprotected"], rec["nginxlimits"]
    t.text("A-1", "A", "EXP-1 (XDP) ran 08:11:02 → 08:41:31 UTC", "08:11:02 → 08:41:31",
           f"{_hms(x['start'])} → {_hms(x['end'])}", (_hms(x["start"]), _hms(x["end"])) == ("08:11:02", "08:41:31"))
    t.text("A-2", "H", "EXP-1b (iptables, then unprotected) ran 08:57–10:05 UTC", "08:57 → 10:05",
           f"{_hms(a['start'])} → {_hms(u['end'])}", _minute_ok("08:57", a["start"]) and _minute_ok("10:05", u["end"]))
    t.text("A-3", "I", "EXP-1c (Nginx limits only) ran 10:15–10:53 UTC", "10:15 → 10:53",
           f"{_hms(n['start'])} → {_hms(n['end'])}", _minute_ok("10:15", n["start"]) and _minute_ok("10:53", n["end"]))
    t.text("A-4", "K", "EXP-2b ran 13:21–13:25 UTC", "13:21 → 13:25", f"{_hms(tuned['start'])} → {_hms(tuned['end'])}",
           _minute_ok("13:21", tuned["start"]) and _minute_ok("13:25", tuned["end"]))
    everything = [*rec.values(), tuned]
    t.text("A-5", "A, H, I, K", "end state of every mode: 0 Nginx processes and 0 network namespaces",
           "0 / 0 in all five", "; ".join(f"{r['nginx']}/{r['netns']}" for r in everything),
           all(r["nginx"] == 0 and r["netns"] == 0 for r in everything))
    t.unchecked("A-6", "A", "the VM had rebooted at about 08:06 UTC on 2026-10-12, which wiped /tmp",
                "about 08:06 UTC", "no record of the reboot in the published files")
    t.unchecked("B-1", "B", "EXP-0: three namespaces received the identical name-derived MAC; with the patch "
                "02:00:0a:00:01:0x", "12:af:eb:2d:8a:f2 ×3 / 02:00:0a:…",
                "EXP-0 left no data files (transient namespaces, no campaign directory)")


# ──────────────────────────────── section C ────────────────────────────────

def section_c(t, fix, base):
    t.nums("C-1", "C", "'during' success, baseline (duplicate MAC): SYN / LowSlowSYN / UDP / HTTP / ACK",
           [34.0, 91.6, 35.3, 89.0, 34.1], [during_percent(base, "xdp", s) for s in ("SYN", "LowSlowSYN", "UDP", "HTTP", "ACK")],
           1, " %")
    t.nums("C-2", "C", "same: Frag / Slowloris / R.U.D.Y. / Yo-Yo / Multi", [34.1, 95.0, 94.5, 90.0, 31.7],
           [during_percent(base, "xdp", s) for s in ("Frag", "Slowloris", "RUDY", "YoYo", "Multi")], 1, " %")
    t.nums("C-3", "C", "'during' success with unique MACs (XDP), every scenario", [100.0] * 10,
           [during_percent(fix, "xdp", s) for s in ORDER], 1, " %", sep=", ")
    n_during = [len(fix.requests("xdp", s, "during")) for s in ORDER]
    t.nums("C-4", "C", "requests per scenario 'during' (XDP): n = 70–463", [70, 463],
           [min(n_during), max(n_during)], 0, sep="–")
    t.nums("C-5", "C", "flood still running after the bans, baseline: UDP / ACK / Frag / Multi",
           [35.9, 31.9, 33.0, 32.7], [pct(base.after_the_bans("xdp", s)) for s in SUSTAINED], 1, " %")
    t.nums("C-6", "C", "same, unique MACs", [100.0] * 4, [pct(fix.after_the_bans("xdp", s)) for s in SUSTAINED], 0, " %")
    n_after = [len(fix.after_the_bans("xdp", s)) for s in SUSTAINED]
    t.nums("C-7", "C", "same: n = 325–385 each", [325, 385], [min(n_after), max(n_after)], 0, sep="–")
    first_base = [pct(base.requests("xdp", s, rel=(0, 1))) for s in FLOODS]
    t.nums("C-8", "C", "first second of floods (SYN/UDP/ACK/Frag/Multi), baseline: 10–20 %", [10, 20],
           [min(first_base), max(first_base)], 0, " %", sep="–")
    t.nums("C-9", "C", "same, unique MACs: 100 %", [100.0] * 5,
           [pct(fix.requests("xdp", s, rel=(0, 1))) for s in FLOODS], 0, " %")
    t.nums("C-10", "C", "first second, HTTP / Yo-Yo, baseline", [85.0, 82.4],
           [pct(base.requests("xdp", s, rel=(0, 1))) for s in ("HTTP", "YoYo")], 1, " %")
    t.nums("C-11", "C", "first second, HTTP / Yo-Yo, unique MACs", [100.0, 100.0],
           [pct(fix.requests("xdp", s, rel=(0, 1))) for s in ("HTTP", "YoYo")], 0, " %")
    t.nums("C-12", "C", "'before' / 'after', baseline", [95.9, 100.0],
           [pct(base.requests("xdp", period="before")), pct(base.requests("xdp", period="after"))], 1, " %")
    t.nums("C-13", "C", "'before' / 'after', unique MACs", [100.0, 100.0],
           [pct(fix.requests("xdp", period="before")), pct(fix.requests("xdp", period="after"))], 0, " %")
    failed_base = base.raw[(base.raw["mode"] == "xdp") & (base.raw.OK == 0)]
    failed_fix = fix.raw[(fix.raw["mode"] == "xdp") & (fix.raw.OK == 0)]
    t.nums("C-14", "C", "failed requests, all periods: 439 (all curl 000), then 0", [439, 0],
           [len(failed_base), len(failed_fix)], 0, note="HTTP codes of the failures in the baseline: "
           + ", ".join(sorted(failed_base.HTTP_Code.unique())))

    def per_run_flood_mean(d):
        x = d.raw[(d.raw["mode"] == "xdp") & (d.raw.Period == "during") & d.raw.scen.isin(FLOODS)]
        return x.groupby(["run", "scen"]).OK.mean().groupby("run").mean() * 100

    pb, pf = per_run_flood_mean(base), per_run_flood_mean(fix)
    t.nums("C-15", "C", "per-run mean flood 'during' success, baseline (SD 14.8)", [26.2, 21.4, 49.2, 14.8],
           [*pb, float(pb.std())], 1)
    t.nums("C-16", "C", "same, unique MACs (SD 0)", [100.0, 100.0, 100.0, 0.0], [*pf, float(pf.std())], 0)

    cols = ["PPS_Rx", "PreStack_Dropped", "IP_InReceives", "CPU_Total_Pct", "HotCore_CPU_Pct"]
    floods = [*NET_FLOODS, "Multi"]
    mb = {s: metric_means(base, PHASES_C, s, "xdp", cols) for s in floods}
    mf = {s: metric_means(fix, PHASES_C, s, "xdp", cols) for s in floods}
    t.nums("C-17", "C", "flood rate reaching veth_server (PPS, Phase 2A/3), baseline: UDP / ACK / Frag, M pps",
           [1.10, 1.01, 1.09], [mb[s]["PPS_Rx"] / 1e6 for s in NET_FLOODS], 2)
    t.nums("C-18", "C", "same, unique MACs", [1.55, 1.64, 1.61], [mf[s]["PPS_Rx"] / 1e6 for s in NET_FLOODS], 2)
    ip_b = [v["IP_InReceives"] for v in mb.values()]
    ip_f = [v["IP_InReceives"] for v in mf.values()]
    t.nums("C-19", "C", "IP_InReceives (pps) in the floods, baseline: 41–48", [41, 48], [min(ip_b), max(ip_b)], 0, sep="–")
    t.nums("C-20", "C", "same, unique MACs: 147–169", [147, 169], [min(ip_f), max(ip_f)], 0, sep="–")
    near = all(abs(v["PreStack_Dropped"] - v["PPS_Rx"]) / v["PPS_Rx"] < 0.001 for v in mf.values())
    t.text("C-21", "C", "PreStack_Dropped ≈ PPS (unique MACs)", "yes", "yes" if near else "no", near,
           "within 0.1 % in every flood")
    cpu_b = [mb[s]["CPU_Total_Pct"] for s in NET_FLOODS]
    cpu_f = [mf[s]["CPU_Total_Pct"] for s in NET_FLOODS]
    t.nums("C-22", "C", "CPU_Total during floods, baseline: 64–66 %", [64, 66], [min(cpu_b), max(cpu_b)], 0, " %", sep="–")
    t.nums("C-23", "C", "CPU_Total during floods, unique MACs: 55–59 %", [55, 59], [min(cpu_f), max(cpu_f)], 0, " %", sep="–")
    hot_b = [mb[s]["HotCore_CPU_Pct"] for s in NET_FLOODS]
    hot_f = [mf[s]["HotCore_CPU_Pct"] for s in NET_FLOODS]
    t.nums("C-24", "C", "hot core during floods, baseline: 100 %", [100, 100], [min(hot_b), max(hot_b)], 0, " %", sep="–")
    t.nums("C-25", "C", "hot core during floods, unique MACs: 98–100 %", [98, 100], [min(hot_f), max(hot_f)], 0, " %", sep="–")
    t.unchecked("C-26", "C", "kernel duplicate-address messages per run: 21–24 (baseline), 0 (unique MACs)", "21–24 / 0",
                "the kernel log is not in the published files (only a journal cursor was recorded)")
    rise = [100 * (mf[s]["PPS_Rx"] / mb[s]["PPS_Rx"] - 1) for s in NET_FLOODS]
    t.nums("C-27", "C", "the delivered attack rate rose by about 50 % (UDP / ACK / Frag; the addendum's reading is an "
           "[INFERENCE], the ratio is a measurement)", [50, 50, 50], rise, 0, " %", tol=15,
           note="'about 50 %' is checked within ±15 points")


# ──────────────────────────────── section D ────────────────────────────────

def section_d(t, fix, yesterday_gru):
    bans = fix.bot_bans()
    xdp = bans[bans["mode"] == "xdp"]
    for s in ORDER:
        v = xdp[xdp.scen == s].ttm
        t.nums(f"D-1.{s}", "D", f"exact time to mitigate, XDP, {s}: median / min / max, s", list(D_TTM[s]),
               [float(v.median()), float(v.min()), float(v.max())], 2)
    sc = fix.scenarios[fix.scenarios["mode"] == "xdp"]
    for s in ORDER:
        got = [None if pd.isna(v) else float(v) for v in sc[sc.scen == s].sort_values("run").TTM_Harness_Mean_s]
        want = D_HARNESS[s]
        ok = len(got) == 3 and all(
            (w is None and g is None) or (w is not None and g is not None and abs(w - g) <= 0.0051)
            for w, g in zip(want, got, strict=True))
        t.text(f"D-2.{s}", "D", f"harness-reported TTM, XDP, {s}, runs 1–3, s", spaced(want), spaced(got), ok)
    exact_mean = xdp.groupby(["run", "scen"]).ttm.mean()
    over = pd.DataFrame([(r.scen, r.TTM_Harness_Mean_s - exact_mean[(r.run, r.scen)])
                         for r in sc.itertuples() if not pd.isna(r.TTM_Harness_Mean_s)], columns=["scen", "diff"])
    flood_like = over[over.scen.isin(["SYN", "UDP", "ACK", "Frag", "Multi", "HTTP", "YoYo"])]
    t.nums("D-3", "D", "the harness overestimates the TTM by 0.52 s on average (0.65 s for floods, up to 1.26 s)",
           [0.52, 0.65, 1.26], [float(over["diff"].mean()), float(flood_like["diff"].mean()), float(over["diff"].max())], 2,
           note="harness Avg TTM minus the mean exact TTM of the five bots, per scenario-run (29 runs with a harness "
           "value); floods = all scenarios but Low & Slow SYN, Slowloris, R.U.D.Y.")
    got = {k: int((xdp.engine == k).sum()) for k in D_ENGINES}
    t.text("D-4", "D", "first-ban engine per bot, XDP, 150 bot-scenarios: L4 volumetric 54, SlowConn 30, L7 33, "
           "SYN 18, Low-SYN 15, GRU 0", ", ".join(f"{k} {v}" for k, v in D_ENGINES.items()),
           ", ".join(f"{k} {v}" for k, v in got.items()), got == D_ENGINES, f"{len(xdp)} first bans")
    xdp_bans = fix.events[(fix.events.kind == "ban") & (fix.events["mode"] == "xdp")]
    t.text("D-5", "D", "no bot was banned twice (XDP)", "0 repeated bans", f"{len(xdp_bans) - len(xdp)} repeated bans",
           len(xdp_bans) == len(xdp))
    legit = fix.events[(fix.events.kind == "ban") & fix.events.ip.str.startswith("10.0.1.", na=False)]
    t.text("D-6", "D", "no legit IP was banned in any EXP-1 scenario (no [BAN] 10.0.1.x line)", "0",
           str(int((legit["mode"] == "xdp").sum())), (legit["mode"] == "xdp").sum() == 0)
    n_gru = int((xdp.engine == "gru").sum())
    t.text("D-7", "D", "the GRU banned nothing in EXP-1 (yesterday: co-engine in 7/30 XDP scenario-runs)",
           "0 GRU bans (XDP); 7/30 yesterday", f"{n_gru} GRU bans (XDP); {yesterday_gru}/30 yesterday",
           n_gru == 0 and yesterday_gru == 7,
           "yesterday's count is the number of XDP scenario-runs whose Engines line names the GRU in "
           "test_console_logs.txt of the superseded campaign")


# ──────────────────────────────── section E ────────────────────────────────

def section_e(t, res, fix):
    run_dir = os.path.join(res, EXP1, "xdp", "run2")
    ph = fix.phases[(fix.phases["mode"] == "xdp") & (fix.phases.run == "run2") & (fix.phases.scen == "ACK")].iloc[0]
    lines = []
    with open(os.path.join(run_dir, "daemon.log"), encoding="utf-8") as fh:
        for ln in fh:
            m = re.match(r"^(\d+\.\d+) (.*)$", ln.rstrip("\n"))
            if m and -12 <= float(m.group(1)) - ph.P1 <= ph.during_len + 12:       # this scenario only
                lines.append((float(m.group(1)) - ph.P1, m.group(2)))
    bans = [(tt, x) for tt, x in lines if "[BAN]" in x]
    quiet_before = [tt for tt, x in lines if x.strip() and not re.search(r"\[(L4-DETECT|XDP|BAN)\]", x)
                    and tt < bans[0][0] - 1]
    rates = sorted(int(m.group(1)) for _, x in lines for m in [re.search(r"Rate: (\d+) pkts/s", x)] if m)
    span = max(tt for tt, _ in bans) - min(tt for tt, _ in bans)
    t.nums("E-1", "E", "the daemon printed nothing from −5.3 s to +10.32 s (relative to the attack start)",
           [-5.3, 10.32], [max(quiet_before), bans[0][0]], 2, tol=0.0501,
           note="last line before the bans, then the first ban; the first value is quoted at one decimal")
    t.text("E-2", "E", "all 5 bots banned in the same millisecond", "same ms", f"span {span * 1000:.0f} ms",
           len(bans) == 5 and span < 0.0015)
    t.nums("E-3", "E", "logged rates 1,350,230 … 1,471,750 pkts/s", [1350230, 1471750], [rates[0], rates[-1]], 0,
           sep=" … ")
    m = fix.metrics[(fix.metrics["mode"] == "xdp") & (fix.metrics.run == "run2") & (fix.metrics.scen == "ACK")]
    t.nums("E-4", "E", "CPU_Daemon_Pct during the stall: 182–226 %", [182, 226],
           [float(m.CPU_Daemon_Pct.iloc[1:].min()), float(m.CPU_Daemon_Pct.max())], 0, " %", sep="–")
    t.nums("E-5", "E", "daemon RSS grew 460 → 526 → 611 MB", [460, 526, 611],
           [float(m.RAM_Daemon_MB.iloc[0]), float(m.RAM_Daemon_MB.iloc[2]), float(m.RAM_Daemon_MB.max())], 0, " MB",
           sep=" → ")
    p2 = m[m.Phase.str.startswith("Phase 2:")].iloc[0]
    t.nums("E-6", "E", "at Phase 2: PreStack_Dropped = 0 and IP_InReceives = 582k pps", [0, 582],
           [float(p2.PreStack_Dropped), float(p2.IP_InReceives) / 1e3], 0)
    row = fix.scenarios[(fix.scenarios["mode"] == "xdp") & (fix.scenarios.run == "run2") & (fix.scenarios.scen == "ACK")].iloc[0]
    t.text("E-7", "E", "the harness reported 0/5 and FAIL", "0/5, FAIL", f"{int(row.Banned_Harness)}/5, {row.Result}",
           row.Banned_Harness == 0 and row.Result == "FAIL")
    b = fix.bot_bans()
    ack = b[b.scen == "ACK"]
    worst = ack[ack["mode"] == "xdp"].groupby("run").ttm.max()
    t.nums("E-8", "E", "runs 1 and 3 banned the same bots in 0.12 s and 1.35 s", [0.12, 1.35],
           [float(worst["run1"]), float(worst["run3"])], 2)
    slow_xdp = int((worst > 5).sum())
    slow_all = int((ack[ack["mode"].isin(["xdp", "iptables"])].groupby(["mode", "run"]).ttm.max() > 5).sum())
    t.text("E-9", "E", "a ~10 s blind spot at flood onset: 1 of 3 XDP ACK runs, 1 of 6 protected ACK runs", "1 of 3; 1 of 6",
           f"{slow_xdp} of 3; {slow_all} of 6", slow_xdp == 1 and slow_all == 1)
    with open(os.path.join(res, EXP1, "xdp", "run3", "console.log"), encoding="utf-8") as fh:
        ping_line = "FP: 10.0.1.9 (profile: mobile_bad)" in fh.read()
    legit_bans = int(((fix.events.ip == "10.0.1.9") & (fix.events.kind == "ban")).sum())
    t.text("E-10", "D", "run 3's ACK scenario still reported 'FP: 10.0.1.9 (mobile_bad)' with no ban of it",
           "FP 10.0.1.9, no ban",
           f"console FP line {'present' if ping_line else 'absent'}; ban events for 10.0.1.9: {legit_bans}",
           ping_line and legit_bans == 0)
    t.unchecked("E-11", "E", "the mechanism of the stall (new flows from hping3 -A, GIL-bound feed) and its fix",
                "[INFERENCE]", "a reading of control_plane.py, not a measurement; not rated")


# ──────────────────────────────── sections H and I ────────────────────────────────

def section_h(t, fix, base):
    bad, cells = [], 0
    for s, row in H1.items():
        for mode, (p, n) in row.items():
            d = fix.requests(mode, s, "during")
            cells += 1
            if abs(round(pct(d), 1) - p) > 0.05 or (n is not None and len(d) != n):
                bad.append(f"{s}/{mode}: {pct(d):.1f} % (n={len(d)}) vs {p} % (n={n})")
    t.text("H-1", "H.1", "'during' success per scenario and mode, percentage and n (30 cells)", "table H.1",
           f"{cells - len(bad)} of {cells} cells equal", not bad, "; ".join(bad))
    runs = ["run1", "run2", "run3"]
    protected_full = all(pct(fix.requests(m, s, "during").query("run == @r")) == 100.0
                         for m in ("xdp", "iptables") for s in ORDER for r in runs)
    unprotected_udp = {r: pct(fix.requests("unprotected", "UDP", "during").query("run == @r")) for r in runs}
    t.text("H-2", "H.1", "'every run is 100 %' (the table next to it shows one unprotected UDP-flood timeout)",
           "every run 100 %", "XDP and iptables: every run 100 %; unprotected UDP flood, run 2: "
           f"{unprotected_udp['run2']:.1f} %", protected_full and min(unprotected_udp.values()) == 100.0,
           "one unprotected UDP-flood request failed (run 2); the table's 99.8 % is consistent with that, the "
           "sentence is not")
    windows = {"0–1 s": (0, 1), "0–3 s": (0, 3), "3–10 s": (3, 10)}
    full = all(pct(fix.requests(m, s, rel=w)) == 100.0 for m in MODES3 for s in ORDER for w in windows.values())
    t.text("H-3", "H.1", "equal-exposure windows (0–1, 0–3, 3–10 s after the attack start) are 100 % in all modes",
           "100 % everywhere", f"100 % in all {len(MODES3) * len(ORDER) * len(windows)} cells" if full else "not all 100 %",
           full)
    p_values = []
    for s in ORDER:
        u = fix.requests("unprotected", s, "during")
        for m in ("xdp", "iptables"):
            a = fix.requests(m, s, "during")
            p_values.append(fisher_exact([[int(a.OK.sum()), int((a.OK == 0).sum())],
                                          [int(u.OK.sum()), int((u.OK == 0).sum())]])[1])
    t.text("H-4", "H.1", "Fisher exact p = 1 for every scenario, protected vs unprotected", "p = 1",
           f"min p = {min(p_values):.3g}", min(p_values) > 0.999999)
    after = [pct(fix.after_the_bans(m, s)) for s in SUSTAINED for m in MODES3]
    t.text("H-5", "H.1", "while the flood keeps running after Phase 2, success is 100 / 100 / 99.8–100 %",
           "100 / 100 / 99.8–100", f"{min(after):.1f}–{max(after):.1f} over all modes and floods",
           round(min(after), 1) == 99.8 and max(after) == 100.0)

    cols = ["CPU_Nginx_Pct", "CPU_Total_Pct", "PPS_Rx", "IP_InReceives", "PreStack_Dropped", "CPU_Daemon_Pct",
            "HotCore_CPU_Pct", "TCP_SynRecv"]
    mh = {(s, m): metric_means(fix, PHASES_H, s, m, cols) for s in ORDER for m in MODES4}
    reaching = [mh[(s, m)]["IP_InReceives"] / 1e6 for s in NET_FLOODS for m in ("iptables", "unprotected")]
    t.nums("H-6", "H.1", "floods of 1.0–1.44 M pps reach the IP stack (iptables and unprotected; H.2 quotes 1.07–1.44 M)",
           [1.0, 1.44], [min(reaching), max(reaching)], 2, sep="–", tol=0.075,
           note="the lower bound is quoted as 1.0 here and as 1.07 in H.2")
    for s, row in H2_LAT.items():
        for m, (p50, p95) in row.items():
            d = fix.requests(m, s, rel=(0, 2.5), profile="perfect")
            t.nums(f"H-7.{s}.{m}", "H.2.1", f"'perfect' clients, requests started in [0, 2.5) s, {s}, {m}: p50 / p95 ms",
                   [p50, p95], [quantile(d, .5), quantile(d, .95)], 0)
    un = fix.requests("unprotected", "HTTP", profile="perfect")
    un = un[(un.OK == 1) & (un.rel >= 0) & (un.rel < 18)]
    bins = un.groupby((np.floor(un.rel / 2) * 2).astype(int)).Latency_ms.agg(["median", "count"])
    bins = bins[bins["count"] >= 2]
    t.nums("H-8", "H.2.1", "unprotected HTTP-flood latency stays at 230–410 ms until the harness stops it ('perfect' "
           "clients, 2-s bins)", [230, 410], [float(bins["median"].min()), float(bins["median"].max())], 0, " ms",
           sep="–", tol=15, note="range of the 2-s bin medians; quoted to the nearest 10 ms")
    yy = fix.requests("unprotected", "YoYo", profile="perfect")
    yy = yy[(yy.OK == 1) & (yy.rel >= 0) & (yy.rel < 32)]
    ratios = []
    for cycle in range(4):
        g = yy[(yy.rel >= 8 * cycle) & (yy.rel < 8 * cycle + 8)]
        burst, gap = g[g.rel < 8 * cycle + 2].Latency_ms.median(), g[g.rel >= 8 * cycle + 2].Latency_ms.median()
        ratios.append(burst / max(1.0, gap))
    t.text("H-9", "H.2.1", "Yo-Yo latency spikes every 8 s with the wrk bursts (unprotected)", "a spike every 8 s",
           "median latency in the first 2 s of each 8-s cycle over the other 6 s: "
           + ", ".join(f"{r:.0f}×" for r in ratios), all(r > 20 for r in ratios))
    for s, (nginx_q, cpu_q) in {"HTTP": ([52, 55, 112], [25, 35, 88]), "YoYo": ([24, 52, 110], [16, 24, 87])}.items():
        t.nums(f"H-10.{s}", "H.2.2", f"Nginx CPU, % of a core, XDP / iptables / unprotected, {s}", nginx_q,
               [mh[(s, m)]["CPU_Nginx_Pct"] for m in MODES3], 0, " %")
        t.nums(f"H-11.{s}", "H.2.2", f"CPU_Total, XDP / iptables / unprotected, {s}", cpu_q,
               [mh[(s, m)]["CPU_Total_Pct"] for m in MODES3], 0, " %")
    ratio_p50 = [quantile(fix.requests("unprotected", s, rel=(0, 2.5), profile="perfect"), .5)
                 / quantile(fix.requests(m, s, rel=(0, 2.5), profile="perfect"), .5)
                 for s in ("HTTP", "YoYo") for m in ("xdp", "iptables")]
    t.text("H-12", "H.5", "protection gives about 100 times lower p50 under L7 floods (HTTP, Yo-Yo; 'perfect' clients)",
           "≈ 100×", f"{min(ratio_p50):.0f}–{max(ratio_p50):.0f}×", 67 <= min(ratio_p50) and max(ratio_p50) <= 200,
           "checked as an order of magnitude (a factor 1.5 either way)")
    half = [mh[("HTTP", m)]["CPU_Nginx_Pct"] / mh[("HTTP", "unprotected")]["CPU_Nginx_Pct"] for m in ("xdp", "iptables")]
    t.nums("H-13", "H.5", "Nginx CPU is about one half with the daemon (HTTP flood, XDP / iptables against unprotected)",
           [0.5, 0.5], half, 2, tol=0.1)
    drop = [mh[(s, "xdp")]["PreStack_Dropped"] / 1e6 for s in NET_FLOODS]
    t.nums("H-14", "H.2.3", "XDP drops 1.24–1.36 M pps pre-stack under UDP/ACK/Frag", [1.24, 1.36],
           [min(drop), max(drop)], 2, sep="–")
    ip_x = [mh[(s, "xdp")]["IP_InReceives"] / 1e3 for s in NET_FLOODS]
    t.nums("H-15", "H.2.3", "XDP's IP_InReceives mean is 108–199 k pps", [108, 199], [min(ip_x), max(ip_x)], 0, " k", sep="–")
    t.nums("H-16", "H.2.3", "iptables and unprotected pass 1.07–1.44 M pps into the IP layer", [1.07, 1.44],
           [min(reaching), max(reaching)], 2, sep="–")
    totals = [mh[(s, m)]["CPU_Total_Pct"] for s in NET_FLOODS for m in MODES3]
    t.nums("H-17", "H.2.3", "CPU_Total is similar across modes (41–58 %)", [41, 58], [min(totals), max(totals)], 0, " %",
           sep="–")
    t.nums("H-18", "H.2.4", "daemon CPU: iptables 105 % in the SYN flood, 62 % HTTP, 46 % Yo-Yo; XDP 37 % in the SYN flood",
           [105, 62, 46, 37], [mh[("SYN", "iptables")]["CPU_Daemon_Pct"], mh[("HTTP", "iptables")]["CPU_Daemon_Pct"],
                               mh[("YoYo", "iptables")]["CPU_Daemon_Pct"], mh[("SYN", "xdp")]["CPU_Daemon_Pct"]], 0, " %")
    b = fix.bot_bans()
    ipt = b[b["mode"] == "iptables"]
    t.nums("H-19", "H.3", "exact TTM medians with iptables, SYN … Multi (ten scenarios), s", [H_TTM_IPT[s] for s in ORDER],
           [float(ipt[ipt.scen == s].ttm.median()) for s in ORDER], 2)
    engines_x = b[b["mode"] == "xdp"].groupby("scen").engine.agg(lambda e: tuple(sorted(e.unique()))).sort_index()
    engines_i = ipt.groupby("scen").engine.agg(lambda e: tuple(sorted(e.unique()))).sort_index()
    same = bool((engines_x == engines_i).all())
    t.text("H-20", "H.3", "first-ban engines are identical in both modes", "identical", "identical" if same else "differ",
           same)
    ban_events = fix.events[(fix.events.kind == "ban") & fix.events["mode"].isin(["xdp", "iptables"])]
    n_bot_scenarios = int(b["mode"].isin(["xdp", "iptables"]).sum())
    n_gru, n_legit = int((ban_events.engine == "gru").sum()), int(ban_events.ip.str.startswith("10.0.1.").sum())
    t.text("H-21", "H.3", "GRU bans: 0, legit IPs banned: 0 (300 bot-scenarios across XDP + iptables)", "0, 0, 300",
           f"{n_gru}, {n_legit}, {n_bot_scenarios}", (n_gru, n_legit, n_bot_scenarios) == (0, 0, 300))
    t.nums("H-22", "H.3", "the F-45 stall did not recur in the three iptables ACK runs (max 1.09 s)", [1.09],
           [float(ipt[ipt.scen == "ACK"].ttm.max())], 2)
    syn = {m: mh[("Frag", m)]["TCP_SynRecv"] for m in MODES3}
    t.nums("H-23", "H.4", "SYN-RECV during the fragmentation flood: unprotected ≈ 2, protected modes ≈ 340",
           [2, 340, 340], [syn["unprotected"], syn["xdp"], syn["iptables"]], 0, tol=1.5)

    def frag_flood_samples(d, mode):
        m = d.metrics
        return m[(m.scen == "Frag") & (m["mode"] == mode) & m.Phase.str.contains(r"Phase 2|Phase 3")].TCP_SynRecv

    cap = {m: frag_flood_samples(base, m) for m in MODES3}
    t.text("H-24", "H.4", "unprotected SYN-RECV during the fragmentation flood was 512 (a constant) on 2026-10-11", "512",
           f"{int(cap['unprotected'].min())}–{int(cap['unprotected'].max())} in all {len(cap['unprotected'])} flood samples",
           cap["unprotected"].min() >= 512 and cap["unprotected"].max() <= 513)
    share = {m: float((cap[m] >= 510).mean()) for m in ("xdp", "iptables")}
    t.text("H-25", "H.4", "'the constant 512 seen in all modes on 2026-10-11' (fragmentation flood)", "512 in all modes",
           "XDP and iptables: ≥ 510 in " + " and ".join(f"{100 * v:.0f} %" for v in share.values())
           + " of the flood samples, ≈ 255–264 in the rest", all(v == 1.0 for v in share.values()),
           "only the unprotected mode is constant at 512; XDP and iptables show 512 in Phase 2 and 2A (1/3), then about "
           "255, the same 512 → 255 pattern as with unique MACs (H-23), so for them it is not a product of the L2 defect")
    http, yoyo = base.requests("unprotected", "HTTP", "during"), base.requests("unprotected", "YoYo", "during")

    def mean_of_runs(d):
        return float(d.groupby("run").OK.mean().mean() * 100)

    t.nums("H-26", "H.1", "yesterday's unprotected HTTP 58 % and Yo-Yo 77 % (duplicate-MAC baseline, 'during')", [58, 77],
           [pct(http), pct(yoyo)], 0, " %",
           note=f"pooled: HTTP {pct(http):.1f} %, Yo-Yo {pct(yoyo):.1f} %; the mean of the three per-run percentages "
           f"is {mean_of_runs(http):.1f} % and {mean_of_runs(yoyo):.1f} %")
    t.unchecked("H-27", "H.1", "the wrk traffic also flapped the FDB", "[INFERENCE]",
                "needs the bridge forwarding database, which was not recorded")


def section_i(t, fix):
    n = [len(fix.requests("nginxlimits", s, "during")) for s in ORDER]
    p = [during_percent(fix, "nginxlimits", s) for s in ORDER]
    t.nums("I-1", "I.1", "Nginx limits only: every scenario 100 %, n = 299–992", [100.0, 299, 992], [min(p), min(n), max(n)], 0)
    failed = fix.raw[fix.raw.OK == 0]
    t.text("I-2", "I.1", "the only failure in 12 runs is one unprotected UDP-flood request", "1 failure, unprotected UDP",
           f"{len(failed)} failure(s): " + ", ".join(f"{r.mode} {r.scen}" for r in failed.itertuples()),
           len(failed) == 1 and failed.iloc[0]["mode"] == "unprotected" and failed.iloc[0].scen == "UDP")
    for s, (p50, p95) in I2_LAT.items():
        d = fix.requests("nginxlimits", s, rel=(0, 2.5), profile="perfect")
        t.nums(f"I-3.{s}", "I.2", f"'perfect' clients in [0, 2.5) s, Nginx limits only, {s}: p50 / p95 ms", [p50, p95],
               [quantile(d, .5), quantile(d, .95)], 0)
    for s, (limits, unprotected) in I2_SUSTAINED.items():
        end = sustained_window_end(fix, s)
        got = []
        for m in ("nginxlimits", "unprotected"):
            d = fix.requests(m, s, rel=(2.5, end), profile="perfect")
            got += [quantile(d, .5), quantile(d, .95)]
        t.nums(f"I-4.{s}", "I.2", f"sustained flood without bans, window [2.5, {end:.1f}) s, {s}: Nginx limits p50 / p95, "
               "then unprotected p50 / p95, ms", [*limits, *unprotected], got, 0, note=f"window end {end:.1f} s")
    p50 = [quantile(fix.requests(m, s, rel=(0, 2.5), profile="perfect"), .5) for s in ("UDP", "ACK", "SYN") for m in MODES4]
    t.nums("I-5", "I.2", "network floods leave 'perfect'-client latency unchanged in every mode (p50 2–6 ms)", [2, 6],
           [min(p50), max(p50)], 0, " ms", sep="–", tol=1.0,
           note="p50 in [0, 2.5) s for UDP, ACK and SYN in all four modes; the smallest is 3 ms, inside the quoted range")
    http = fix.bot_bans()
    http = http[http.scen == "HTTP"]
    t.nums("I-6", "I.2", "the daemon's bans in the HTTP flood come at 0.1–1.8 s", [0.1, 1.8],
           [float(http.ttm.min()), float(http.ttm.max())], 1, " s", sep="–")
    cols = ["CPU_Nginx_Pct", "CPU_Total_Pct", "PPS_Rx", "IP_InReceives"]
    m = {(s, mode): metric_means(fix, PHASES_H, s, mode, cols) for s in ("HTTP", "YoYo") for mode in MODES4}
    t.nums("I-7", "I.3", "HTTP flood, Nginx CPU % of a core: XDP / iptables / Nginx limits / unprotected", [52, 55, 434, 112],
           [m[("HTTP", x)]["CPU_Nginx_Pct"] for x in MODES4], 0)
    t.nums("I-8", "I.3", "HTTP flood, CPU_Total", [25, 35, 94, 88], [m[("HTTP", x)]["CPU_Total_Pct"] for x in MODES4], 0, " %")
    t.nums("I-9", "I.3", "HTTP flood, packets/s reaching the server (k)", [5.0, 7.0, 48.7, 1.2],
           [m[("HTTP", x)]["PPS_Rx"] / 1e3 for x in MODES4], 1)
    t.nums("I-10", "I.3", "HTTP flood, IP_InReceives (k)", [7.2, 10.2, 59.5, 20.8],
           [m[("HTTP", x)]["IP_InReceives"] / 1e3 for x in MODES4], 1)
    t.nums("I-11", "I.3", "Yo-Yo, Nginx CPU %: XDP / iptables / Nginx limits / unprotected", [24, 52, 374, 110],
           [m[("YoYo", x)]["CPU_Nginx_Pct"] for x in MODES4], 0)
    t.nums("I-12", "I.3", "about 40 times more packets arrive with limit_req (48.7 k against 1.2 k packets/s)", [40],
           [m[("HTTP", "nginxlimits")]["PPS_Rx"] / m[("HTTP", "unprotected")]["PPS_Rx"]], 0, tol=2.5)
    t.nums("I-13", "I.4", "Nginx CPU with limits alone is about 4 times unprotected's (HTTP, Yo-Yo)", [4, 4],
           [m[(s, "nginxlimits")]["CPU_Nginx_Pct"] / m[(s, "unprotected")]["CPU_Nginx_Pct"] for s in ("HTTP", "YoYo")], 1,
           tol=0.7, note="'about 4 times' is checked within ±0.7")
    t.nums("I-14", "I.4", "with the daemon Nginx uses about 8 times less CPU than with limits alone (HTTP)", [8, 8],
           [m[("HTTP", "nginxlimits")]["CPU_Nginx_Pct"] / m[("HTTP", x)]["CPU_Nginx_Pct"] for x in ("xdp", "iptables")], 1,
           tol=0.5)
    end = sustained_window_end(fix, "HTTP")
    t.nums("I-15", "I.2", "limit_req alone gives about 10 times lower median latency than no protection under a sustained "
           "HTTP flood", [10],
           [quantile(fix.requests("unprotected", "HTTP", rel=(2.5, end), profile="perfect"), .5)
            / quantile(fix.requests("nginxlimits", "HTTP", rel=(2.5, end), profile="perfect"), .5)], 1, tol=1.0)


# ──────────────────────────────── sections K, L, M ────────────────────────────────

def section_k(t, res):
    d = load_campaign(os.path.join(res, EXP2B))
    during = d.requests("nginxlimits", "HTTP", "during")
    per_run = [pct(during[during.run == r]) for r in ("run1", "run2", "run3")]
    t.nums("K-1", "K", "Nginx limits tuned: 'during' availability ~62 % (59 / 78 / 49)", [62, 59, 78, 49],
           [pct(during), *per_run], 0, " %")
    m = metric_means(d, PHASES_H, "HTTP", "nginxlimits", ["CPU_Nginx_Pct", "PPS_Rx"])
    t.nums("K-2", "K", "Nginx CPU 96 % of cpu0 and 50.3 k packets/s reaching the server", [96, 50.3],
           [m["CPU_Nginx_Pct"], m["PPS_Rx"] / 1e3], 1, tol=0.55)
    t.nums("K-3", "K", "tuning gives 52 % → ~49–78 % (the per-run range of the tuned runs)", [49, 78],
           [min(per_run), max(per_run)], 0, " %", sep="–")


def section_l(t, res):
    d = load_campaign(os.path.join(res, F45))
    sc = d.scenarios.sort_values("run")
    t.text("L-1", "L", "six ACK-flood runs with the patched daemon, bots banned 5/5 in every run", "5/5 × 6",
           " ".join(f"{int(r.Banned_Events)}/5" for r in sc.itertuples()), bool((sc.Banned_Events == 5).all()))
    t.nums("L-2", "L", "harness Avg TTM of the six runs, s", [1.11, 1.16, 1.13, 1.16, 1.74, 1.28],
           [float(x) for x in sc.TTM_Harness_Mean_s], 2)
    b = d.bot_bans()
    last_p1 = float(b.groupby("run").ttm.max().max())
    p2 = d.phases.set_index("run").P2
    last_p2 = float(max(b[b.run == r].t.max() - p2[r] for r in b.run.unique()))
    t.add("L-3", "L", "exact last-ban TTM ≤ 0.97 s; max TTM across the six runs 0.97 s", "0.97 s",
          f"{last_p1:.2f} s from the Phase-1 timestamp (the attack start); {last_p2:.2f} s from the Phase-2 row",
          MATCH if round(last_p1, 2) == 0.97 else DIFFERS,
          "0.97 s is run 5's last ban measured from the Phase-2 row, which is written 1.1–1.3 s after the Phase-1 row; "
          "in the other five runs every ban precedes the Phase-2 row")
    stalls = int((b.groupby("run").ttm.max() > 5).sum())
    t.text("L-4", "L", "no run approached the ~10.3 s stall", "no stall",
           f"{stalls} run(s) over 5 s; the slowest is {last_p1:.2f} s", stalls == 0)
    t.unchecked("L-5", "L", "EXP-5: one BCC flow_map.items() pass costs 1.04 s at 262k entries (10k → 0.03 s, 50k → 0.20 s); "
                "items_lookup_batch() about 7× faster", "1.04 s / 0.15 s",
                "the benchmark output (outputs/exp5_bcc_iter_bench.txt) is not in the repository")
    return d


def section_m(t, res, fix, f45):
    e2a = load_campaign(os.path.join(res, EXP2A))
    counts = {}
    for label, d, modes in (("EXP-1/1b", fix, ["xdp", "iptables"]), ("EXP-2a", e2a, ["xdp", "iptables"]),
                            ("F-45", f45, ["xdp"])):
        b = d.bot_bans()
        ev = d.events[(d.events.kind == "ban") & d.events["mode"].isin(modes)]
        counts[label] = (int(b["mode"].isin(modes).sum()), int((ev.engine == "gru").sum()))
    sizes = tuple(v[0] for v in counts.values())
    n_gru = sum(v[1] for v in counts.values())
    t.text("M-1", "M", "0 GRU bans in about 390 bot-scenarios: 300 in EXP-1/1b, 60 in EXP-2a, 30 in the F-45 validation",
           "0 GRU bans; 300 + 60 + 30", f"{n_gru} GRU bans; {' + '.join(str(s) for s in sizes)}",
           n_gru == 0 and sizes == (300, 60, 30))
    degraded, last = [], float("nan")
    for cfg in sorted(os.listdir(os.path.join(res, CALIB))):
        path = os.path.join(res, CALIB, cfg, "availability_raw_unprotected.csv")
        if os.path.isfile(path):
            r = pd.read_csv(path)
            share = 100 * r[r.Period == "during"].OK.mean()
            if share < 100:
                degraded.append(cfg)
                last = share
    t.text("M-2", "J, M", "EXP-1d found the knee: the unprotected server degrades only at 1 worker/1 CPU, wrk -c400, 10 bots",
           "knee = w1t1_cpu0_c400_b10", f"degraded: {', '.join(degraded) or 'none'} ({last:.1f} %)",
           degraded == ["w1t1_cpu0_c400_b10"])


# ──────────────────────────────── driver ────────────────────────────────

def yesterday_gru_scenario_runs(path):
    """XDP scenario-runs of the 2026-10-11 console whose Engines line names the GRU."""
    ansi = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
    mode, n = None, 0
    with open(os.path.join(path, "test_console_logs.txt"), encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = ansi.sub("", line)
            m = re.match(r"^===== (\w+) run \d+/\d+ =====", line)
            if m:
                mode = m.group(1)
            if mode == "XDP" and "Engines:" in line and "GRU" in line:
                n += 1
    return n


def run(results):
    t = Table()
    fix = load_campaign(os.path.join(results, EXP1))
    base = load_baseline(os.path.join(results, BASELINE))
    section_a(t, results)
    section_c(t, fix, base)
    section_d(t, fix, yesterday_gru_scenario_runs(os.path.join(results, BASELINE)))
    section_e(t, results, fix)
    section_h(t, fix, base)
    section_i(t, fix)
    section_k(t, results)
    f45 = section_l(t, results)
    section_m(t, results, fix, f45)
    return t.rows


def counts(rows):
    return {v: sum(1 for r in rows if r["verdict"] == v) for v in (MATCH, DIFFERS, UNCHECKED)}


def to_markdown(rows):
    c = counts(rows)
    head = (f"{len(rows)} comparisons: **{c[MATCH]} match**, **{c[DIFFERS]} differ**, **{c[UNCHECKED]} cannot be "
            "checked**. Generated by `eval/check_addendum.py` from `results/` (deterministic).")
    out = ["# Claims of the 2026-10-12 addendum against the published prototype campaigns", "", head, "",
           "| # | § | Claim | Addendum says | Recomputed | Verdict |", "|---|---|---|---|---|---|"]
    for r in rows:
        cells = [str(r[k]).replace("|", "\\|") for k in ("id", "where", "claim", "addendum", "recomputed")]
        out.append("| " + " | ".join(cells) + f" | {r['verdict']} |")
    notes = [r for r in rows if r["note"]]
    if notes:
        out += ["", "## Notes", ""]
        out += [f"* **{r['id']}** ({r['verdict']}): {r['note']}" for r in notes]
    return "\n".join(out) + "\n"


def to_csv(rows):
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=["id", "where", "claim", "addendum", "recomputed", "verdict", "note"],
                       lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--results", default=os.path.join(os.path.dirname(HERE), "results"))
    ap.add_argument("--md", help="write the table as Markdown")
    ap.add_argument("--csv", help="write the table as CSV")
    args = ap.parse_args(argv)
    rows = run(args.results)
    text = to_markdown(rows)
    for path, content in ((args.md, text), (args.csv, to_csv(rows))):
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
    print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
