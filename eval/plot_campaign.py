#!/usr/bin/env python3
"""Figures for an evaluation campaign (PNG), in the style of the EXP-2a figure.

    venv/bin/python eval/plot_campaign.py <campaign_dir> [--out DIR]

Per scenario: availability_<scenario>.png — left, legit success during the attack per
mode (bars = pooled, dots = runs, whiskers = run-bootstrap 95 % CI); right, median
latency of served requests from 'perfect' clients over time since the attack start.
A campaign with load cells (run labels `mode@cell`, see eval/run_campaign.py --loads)
gets one such figure per cell, availability_<scenario>__<cell>.png (`wrk` for the
closed-loop default). Plus ttm.png: exact time-to-mitigate per bot (ban events). Output
defaults to <campaign_dir>/analysis/figures/.
"""
import argparse
import os
import re
import sys

import matplotlib
import matplotlib.pyplot as plt
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import campaign as C

matplotlib.use("Agg")                  # files only; no figure exists yet, so switching is safe

SURF, INK, INK2, MUTED, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#8a8984", "#e6e5e1"
STYLE = {"xdp": {"color": "#2a78d6"}, "iptables": {"color": "#eb6834"},
         "nginxlimits": {"color": INK2, "hatch": "///"}, "unprotected": {"color": "#1baf7a"}}
PNG_META = {"Software": None}          # keep the PNG bytes independent of the matplotlib build

plt.rcParams.update({
    "figure.facecolor": SURF, "axes.facecolor": SURF, "savefig.facecolor": SURF,
    "font.size": 10, "axes.edgecolor": MUTED, "axes.labelcolor": INK2, "xtick.color": INK2,
    "ytick.color": INK2, "axes.titlecolor": INK, "axes.titlesize": 11,
    "axes.titleweight": "bold", "legend.frameon": False})


def _style(ax):
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.yaxis.grid(True, color=GRID, lw=0.8)
    ax.set_axisbelow(True)


def _slug(name):
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def _mode_style(label):
    return STYLE.get(C.split_label(label)[0], {"color": MUTED})


def plot_availability(raw, avail, scenario, out_path, modes=None, title_suffix=""):
    modes = modes or C.ordered_modes(avail[avail.scenario == scenario]["mode"])
    rng = np.random.default_rng(C.BOOT_SEED)        # deterministic dot jitter
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5.2), gridspec_kw={"width_ratios": [1, 1.3]})
    d = avail[(avail.scenario == scenario) & (avail.period == "during")].set_index("mode")
    for i, mode in enumerate(modes):
        if mode not in d.index:
            continue
        r, st = d.loc[mode], _mode_style(mode)
        hatched = "hatch" in st
        ax1.bar(i, r.success_pct, width=0.62, color=SURF if hatched else st["color"],
                edgecolor=st["color"], hatch=st.get("hatch"), linewidth=1.3 if hatched else 0,
                yerr=[[max(0.0, r.success_pct - r.ci_lo)], [max(0.0, r.ci_hi - r.success_pct)]],
                error_kw={"ecolor": MUTED, "elinewidth": 1, "capsize": 3})
        for pct in (float(p) for p in str(r.per_run_pct).split("/") if p):
            ax1.plot(i + rng.uniform(-0.12, 0.12), pct, "o", ms=7, color=INK, mfc="white", mew=1.4,
                     zorder=5)
        ax1.text(i, 3, f"{r.success_pct:.0f}%", ha="center", fontsize=9,
                 color=INK if hatched else SURF, fontweight="bold")
    ax1.set_xticks(range(len(modes)))
    ax1.set_xticklabels([C.mode_name(m) for m in modes], rotation=18, ha="right", fontsize=8.5)
    ax1.set_ylim(0, 105)
    ax1.set_ylabel("legit success during the attack, %\n(bars pooled · dots runs · 95 % CI runs)")
    ax1.set_title("Availability during the attack", loc="left")
    _style(ax1)

    served = raw[(raw.Scenario == scenario) & (raw.OK == 1) & (raw.Profile == "perfect")]
    if "rel_s" in served:
        for mode in modes:
            g = served[served["mode"] == mode].dropna(subset=["rel_s"])
            if g.empty:
                continue
            b = (np.floor(g.rel_s / 2) * 2).astype(int)
            m = g.groupby(b).Latency_ms.agg(["median", "count"])
            m = m[m["count"] >= 2]
            st = _mode_style(mode)
            ax2.plot(m.index + 1, m["median"], color=st["color"], lw=2,
                     ls=(0, (4, 2)) if "hatch" in st else "-", marker="s" if "hatch" in st else "o",
                     ms=4, label=C.mode_name(mode))
        ax2.axvline(0, color=INK2, lw=1)
        ax2.legend(loc="upper right", fontsize=8.5)
    ax2.set_xlabel("request start, s since attack start (2-s bins)")
    ax2.set_ylabel("median latency, ms ('perfect' clients)")
    ax2.set_title("Latency of served legit requests", loc="left")
    _style(ax2)
    fig.suptitle(scenario + title_suffix, x=0.01, ha="left", fontsize=10.5, color=INK)
    fig.tight_layout(rect=(0, 0, 1, 0.95))
    fig.savefig(out_path, dpi=140, metadata=PNG_META)
    plt.close(fig)


def plot_ttm(scenarios, out_path):
    import json
    rows = []
    for r in scenarios.itertuples():
        if isinstance(r.TTM_Exact_By_Bot, str) and r.TTM_Exact_By_Bot.strip():
            rows += [(r.Data_Scenario, r.mode, float(t)) for t in json.loads(r.TTM_Exact_By_Bot).values()]
    if not rows:
        return False
    scen_order = list(dict.fromkeys(s for s, _, _ in rows))
    modes = C.ordered_modes({m for _, m, _ in rows})
    rng = np.random.default_rng(C.BOOT_SEED)
    fig, ax = plt.subplots(figsize=(max(6.0, 1.6 * len(scen_order) * len(modes) / 2), 4.6))
    width = 0.8 / max(1, len(modes))
    for j, mode in enumerate(modes):
        st = _mode_style(mode)
        for i, scen in enumerate(scen_order):
            ts = [t for s, m, t in rows if s == scen and m == mode]
            if ts:
                x = i - 0.4 + width * (j + 0.5)
                ax.plot(x + rng.uniform(-width / 4, width / 4, len(ts)), ts, "o", ms=4,
                        color=st["color"], alpha=0.8, label=C.display_name(mode) if i == 0 else None)
                ax.plot([x - width / 3, x + width / 3], [np.median(ts)] * 2, color=INK, lw=2)
    ax.set_xticks(range(len(scen_order)))
    ax.set_xticklabels(scen_order, rotation=15, ha="right", fontsize=8.5)
    ax.set_ylabel("time to mitigate per bot, s\n(first ban event − attack start; bar = median)")
    ax.set_title("Exact time-to-mitigate (ban events)", loc="left")
    ax.legend(fontsize=8.5)
    _style(ax)
    fig.tight_layout()
    fig.savefig(out_path, dpi=140, metadata=PNG_META)
    plt.close(fig)
    return True


def plot_all(campaign_dir, out_dir=None):
    """Write every figure of a campaign; returns the paths."""
    data = C.load(campaign_dir)
    out = out_dir or os.path.join(campaign_dir, "analysis", "figures")
    os.makedirs(out, exist_ok=True)
    avail = C.availability(data["raw"])
    written = []
    for scen in C._scenario_order(data["raw"]):
        labels = C.ordered_modes(avail[avail.scenario == scen]["mode"])
        if not C.has_cells(labels):
            path = os.path.join(out, f"availability_{_slug(scen)}.png")
            plot_availability(data["raw"], avail, scen, path)
            written.append(path)
            continue
        for cell in C.cells(labels):
            path = os.path.join(out, f"availability_{_slug(scen)}__{_slug(cell or 'wrk')}.png")
            plot_availability(data["raw"], avail, scen, path,
                              modes=[m for m in labels if C.split_label(m)[1] == cell],
                              title_suffix=f" — load cell {cell or 'wrk (closed loop)'}")
            written.append(path)
    if not data["scenarios"].empty and plot_ttm(data["scenarios"], os.path.join(out, "ttm.png")):
        written.append(os.path.join(out, "ttm.png"))
    return written


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("campaign")
    ap.add_argument("--out", help="output directory (default <campaign>/analysis/figures)")
    args = ap.parse_args()
    print("[+] " + "\n[+] ".join(plot_all(args.campaign, args.out)))


if __name__ == "__main__":
    main()
