#!/usr/bin/env python3
"""Thesis figures from the distributed suite's service-availability CSVs.

Reads the availability_<mode>.csv files written by test_distributed_suite.py
(one row per scenario x period x profile) and renders publication figures of
legitimate-client service availability. Colours use the Okabe-Ito colour-blind-
safe qualitative palette. Requires matplotlib + pandas (see requirements.txt).

Usage:
    # before/during/after success rate per scenario (one mode's CSV):
    python plot_availability.py [availability_csv] [out_png]
        defaults: /tmp/availability_performance.csv  availability_phases.png

    # DURING-attack success rate per scenario, XDP vs iptables vs unprotected
    # (reads /tmp/availability_{performance,iptables,unprotected}.csv):
    python plot_availability.py crossmode [out_png]
        default out: availability_crossmode.png

Each call also writes a vector .pdf alongside the .png (LaTeX-ready).
"""
import sys
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

# Okabe-Ito colour-blind-safe palette (canonical CVD-safe qualitative set)
C = {"before": "#0072B2", "during": "#D55E00", "after": "#009E73"}  # blue / vermillion / green
INK, MUTED, GRID = "#222222", "#666666", "#DDDDDD"

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


def chart_phases(csv_path, out_path):
    df = pd.read_csv(csv_path)
    df = df[df["Profile"] == "ALL"]
    scenarios = list(dict.fromkeys(df["Scenario"]))          # suite order S1..S10
    labels = [SHORT.get(s, s) for s in scenarios]
    vals = {p: [] for p in PERIODS}
    reqs = {p: [] for p in PERIODS}
    for s in scenarios:
        for p in PERIODS:
            r = df[(df["Scenario"] == s) & (df["Period"] == p)]
            vals[p].append(float(r["Success_Rate_Pct"].iloc[0]) if len(r) else 0.0)
            reqs[p].append(int(r["Total_Reqs"].iloc[0]) if len(r) else 0)

    n = len(scenarios)
    y = np.arange(n)[::-1]            # draw S1 at top
    h = 0.26                         # thin bars
    off = {"before": +h, "during": 0.0, "after": -h}
    fig, ax = plt.subplots(figsize=(10, 8))
    for p in PERIODS:
        ax.barh(y + off[p], vals[p], height=h * 0.9, color=C[p],
                label=p.capitalize(), zorder=3)
        for yi, v, nq in zip(y + off[p], vals[p], reqs[p]):
            ax.text(v + 1.3, yi, f"{v:.0f}%", va="center", ha="left",
                    fontsize=7.5, color=MUTED)

    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=10, color=INK)
    ax.set_xlim(0, 112)
    ax.set_xticks(range(0, 101, 20))
    ax.set_xlabel("Legitimate-client HTTP success rate (%)", fontsize=10, color=INK)
    ax.set_title("Service availability for legitimate clients under attack (XDP-protected)\n"
                 + "continuous HTTP success rate — before / during / after each attack",
                 fontsize=12.5, color=INK, loc="left", pad=12)
    ax.xaxis.grid(True, color=GRID, linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)
    for sp in ("top", "right"):
        ax.spines[sp].set_visible(False)
    for sp in ("left", "bottom"):
        ax.spines[sp].set_color(MUTED)
    ax.tick_params(colors=MUTED)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.07), frameon=False,
              ncol=3, fontsize=10)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    fig.savefig(out_path.rsplit(".", 1)[0] + ".pdf", bbox_inches="tight")  # LaTeX-ready vector
    print(f"[+] wrote {out_path} (+ .pdf)  — {n} scenarios")


def chart_crossmode(out_path):
    """DURING-attack success rate per scenario across the three deployment modes."""
    modes = [("XDP (eBPF)", "/tmp/availability_performance.csv", "#0072B2"),
             ("iptables",    "/tmp/availability_iptables.csv",    "#E69F00"),
             ("Unprotected", "/tmp/availability_unprotected.csv", "#999999")]
    series, order = [], None
    for name, path, col in modes:
        try:
            d = pd.read_csv(path)
        except FileNotFoundError:
            series.append((name, {}, col)); continue
        d = d[(d["Period"] == "during") & (d["Profile"] == "ALL")]
        m = {r["Scenario"]: float(r["Success_Rate_Pct"]) for _, r in d.iterrows()}
        series.append((name, m, col))
        if order is None:
            order = list(dict.fromkeys(d["Scenario"]))
    labels = [SHORT.get(s, s) for s in order]
    n = len(order)
    y = np.arange(n)[::-1]
    h = 0.26
    offs = [+h, 0.0, -h]
    fig, ax = plt.subplots(figsize=(10, 8.5))
    for (name, m, col), o in zip(series, offs):
        vals = [m.get(s, 0.0) for s in order]
        ax.barh(y + o, vals, height=h * 0.9, color=col, label=name, zorder=3)
        for yi, v in zip(y + o, vals):
            ax.text(v + 1.3, yi, f"{v:.0f}", va="center", ha="left", fontsize=7.5, color=MUTED)
    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=10, color=INK)
    ax.set_xlim(0, 112)
    ax.set_xticks(range(0, 101, 20))
    ax.set_xlabel("Legitimate-client HTTP success rate DURING attack (%)", fontsize=10, color=INK)
    ax.set_title("Service availability under attack by defense mode: XDP vs iptables vs unprotected\n"
                 + "higher = more legitimate users served while the attack + mitigation are active",
                 fontsize=12.5, color=INK, loc="left", pad=12)
    ax.xaxis.grid(True, color=GRID, linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)
    for sp in ("top", "right"):
        ax.spines[sp].set_visible(False)
    for sp in ("left", "bottom"):
        ax.spines[sp].set_color(MUTED)
    ax.tick_params(colors=MUTED)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.07), frameon=False, ncol=3, fontsize=10)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    fig.savefig(out_path.rsplit(".", 1)[0] + ".pdf", bbox_inches="tight")
    print(f"[+] wrote {out_path} (+ .pdf)  — {n} scenarios x 3 modes")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "crossmode":
        chart_crossmode(sys.argv[2] if len(sys.argv) > 2 else "availability_crossmode.png")
    else:
        csv = sys.argv[1] if len(sys.argv) > 1 else "/tmp/availability_performance.csv"
        out = sys.argv[2] if len(sys.argv) > 2 else "availability_phases.png"
        chart_phases(csv, out)
