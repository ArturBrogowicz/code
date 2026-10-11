#!/usr/bin/env python3
"""Thesis figures from the distributed suite's service-availability CSVs.

Reads the availability_<mode>.csv files written by test_distributed_suite.py
(one row per scenario x period x profile, APPENDED across runs) and renders
publication figures of legitimate-client service availability. When a CSV holds
several runs, values are AVERAGED per (scenario, period/mode) and drawn mean +/-
SD with error bars; a single run draws the bare value. Colours use the Okabe-Ito
colour-blind-safe qualitative palette. Requires matplotlib + pandas.

Usage:
    # before/during/after success rate per scenario (one mode's CSV):
    python plot_availability.py [availability_csv] [out_png]
        defaults: /tmp/availability_performance.csv  availability_phases.png

    # DURING-attack success rate per scenario, XDP vs iptables vs unprotected
    # (reads /tmp/availability_{performance,iptables,unprotected}.csv):
    python plot_availability.py crossmode [out_png]
        default out: availability_crossmode.png

Each call also writes a vector .pdf alongside the .png (LaTeX-ready). To build
publication-grade averages, run the suite N times per mode (the CSVs append) and
re-run this script — it averages over whatever runs are present.
"""
import sys
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# Okabe-Ito colour-blind-safe palette (canonical CVD-safe qualitative set)
C = {"before": "#0072B2", "during": "#D55E00", "after": "#009E73"}  # blue / vermillion / green
INK, MUTED, GRID = "#222222", "#666666", "#DDDDDD"
ERRKW = dict(elinewidth=1.0, ecolor=MUTED, capsize=2.5, capthick=1.0)

SHORT = {
    "Distributed SYN Flood": "SYN Flood",
    "Distributed Low & Slow SYN": "Low & Slow SYN",
    "Distributed UDP Flood": "UDP Flood",
    "Distributed HTTP Flood": "HTTP Flood",
    "Distributed ACK Flood": "ACK Flood",
    "Distributed IP Fragmentation Flood": "Fragmentation",
    "Distributed Slowloris": "Slowloris",
    "Distributed R.U.D.Y.": "R.U.D.Y.",
    "Distributed Yo-Yo": "Yo-Yo",
    "Multi-Vector Distributed Attack": "Multi-Vector",
}
PERIODS = ["before", "during", "after"]


def _agg(vals):
    """(mean, std, n) over a list of values; (0.0, 0.0, 0) if empty."""
    a = np.asarray([v for v in vals if v is not None], dtype=float)
    if a.size == 0:
        return 0.0, 0.0, 0
    return float(a.mean()), float(a.std(ddof=0)), int(a.size)


def _runs_note(nmax):
    return f"mean ± SD over {nmax} runs" if nmax > 1 else "single run"


def _style(ax, xlabel, title):
    ax.set_xlim(0, 114)
    ax.set_xticks(range(0, 101, 20))
    ax.set_xlabel(xlabel, fontsize=10, color=INK)
    ax.set_title(title, fontsize=12.5, color=INK, loc="left", pad=12)
    ax.xaxis.grid(True, color=GRID, linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)
    for sp in ("top", "right"):
        ax.spines[sp].set_visible(False)
    for sp in ("left", "bottom"):
        ax.spines[sp].set_color(MUTED)
    ax.tick_params(colors=MUTED)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.07), frameon=False, ncol=3, fontsize=10)


def _save(fig, out_path):
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    fig.savefig(out_path.rsplit(".", 1)[0] + ".pdf", bbox_inches="tight")  # LaTeX-ready vector


def chart_phases(csv_path, out_path):
    df = pd.read_csv(csv_path)
    df = df[df["Profile"] == "ALL"]
    scenarios = list(dict.fromkeys(df["Scenario"]))          # suite order S1..S10
    labels = [SHORT.get(s, s) for s in scenarios]
    mean = {p: [] for p in PERIODS}
    sd = {p: [] for p in PERIODS}
    nmax = 0
    for s in scenarios:
        for p in PERIODS:
            vals = df[(df["Scenario"] == s) & (df["Period"] == p)]["Success_Rate_Pct"].tolist()
            m, d, n = _agg(vals)
            mean[p].append(m)
            sd[p].append(d)
            nmax = max(nmax, n)

    n_s = len(scenarios)
    y = np.arange(n_s)[::-1]
    h = 0.26
    off = {"before": +h, "during": 0.0, "after": -h}
    fig, ax = plt.subplots(figsize=(10, 8))
    for p in PERIODS:
        xerr = sd[p] if nmax > 1 else None
        ax.barh(y + off[p], mean[p], height=h * 0.9, color=C[p], label=p.capitalize(),
                xerr=xerr, error_kw=ERRKW, zorder=3)
        for yi, m, d in zip(y + off[p], mean[p], sd[p]):
            ax.text(m + (d if nmax > 1 else 0) + 1.8, yi, f"{m:.0f}%",
                    va="center", ha="left", fontsize=7.5, color=MUTED)
    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=10, color=INK)
    _style(ax, "Legitimate-client HTTP success rate (%)",
           "Service availability for legitimate clients under attack (XDP-protected)\n"
           + f"continuous HTTP success rate — before / during / after each attack  ({_runs_note(nmax)})")
    _save(fig, out_path)
    print(f"[+] wrote {out_path} (+ .pdf)  — {n_s} scenarios, {_runs_note(nmax)}")


def chart_crossmode(out_path):
    """DURING-attack success rate per scenario across the three deployment modes."""
    modes = [("XDP (eBPF)", "/tmp/availability_performance.csv", "#0072B2"),
             ("iptables",    "/tmp/availability_iptables.csv",    "#E69F00"),
             ("Unprotected", "/tmp/availability_unprotected.csv", "#999999")]
    series, order, nmax = [], None, 0
    for name, path, col in modes:
        try:
            d = pd.read_csv(path)
        except FileNotFoundError:
            series.append((name, {}, col)); continue
        d = d[(d["Period"] == "during") & (d["Profile"] == "ALL")]
        agg = {}
        for s in dict.fromkeys(d["Scenario"]):
            m, sd, n = _agg(d[d["Scenario"] == s]["Success_Rate_Pct"].tolist())
            agg[s] = (m, sd)
            nmax = max(nmax, n)
        series.append((name, agg, col))
        if order is None:
            order = list(dict.fromkeys(d["Scenario"]))
    if order is None:
        print("[-] no availability CSVs found"); return
    labels = [SHORT.get(s, s) for s in order]
    n_s = len(order)
    y = np.arange(n_s)[::-1]
    h = 0.26
    offs = [+h, 0.0, -h]
    fig, ax = plt.subplots(figsize=(10, 8.5))
    for (name, agg, col), o in zip(series, offs):
        means = [agg.get(s, (0.0, 0.0))[0] for s in order]
        sds = [agg.get(s, (0.0, 0.0))[1] for s in order]
        xerr = sds if nmax > 1 else None
        ax.barh(y + o, means, height=h * 0.9, color=col, label=name,
                xerr=xerr, error_kw=ERRKW, zorder=3)
        for yi, m, d in zip(y + o, means, sds):
            ax.text(m + (d if nmax > 1 else 0) + 1.8, yi, f"{m:.0f}",
                    va="center", ha="left", fontsize=7.5, color=MUTED)
    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=10, color=INK)
    _style(ax, "Legitimate-client HTTP success rate DURING attack (%)",
           "Service availability under attack by defense mode: XDP vs iptables vs unprotected\n"
           + f"higher = more legitimate users served while attack + mitigation are active  ({_runs_note(nmax)})")
    _save(fig, out_path)
    print(f"[+] wrote {out_path} (+ .pdf)  — {n_s} scenarios x 3 modes, {_runs_note(nmax)}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "crossmode":
        chart_crossmode(sys.argv[2] if len(sys.argv) > 2 else "availability_crossmode.png")
    else:
        csv = sys.argv[1] if len(sys.argv) > 1 else "/tmp/availability_performance.csv"
        out = sys.argv[2] if len(sys.argv) > 2 else "availability_phases.png"
        chart_phases(csv, out)
