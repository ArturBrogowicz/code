#!/usr/bin/env python3
"""Analyse an evaluation campaign: CSV tables and a Markdown summary.

    venv/bin/python eval/analyze_campaign.py <campaign_dir> [--window 10] [--reference unprotected]

Writes <campaign_dir>/analysis/{summary.md, availability.csv, delta_vs_reference.csv,
latency.csv, window.csv, detection.csv, server.csv}. Deterministic: running it again on
the same data reproduces the files byte for byte (see docs/EVALUATION.md).
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import campaign as C


def analyse(campaign_dir, out_dir=None, window_s=10.0, reference="unprotected"):
    data = C.load(campaign_dir)
    out_dir = out_dir or os.path.join(campaign_dir, "analysis")
    os.makedirs(out_dir, exist_ok=True)
    tables = {
        "availability": C.availability(data["raw"]),
        "delta_vs_reference": C.delta_vs_reference(data["raw"], data["runs"], reference),
        "latency": C.latency(data["raw"]),
        "window": C.window(data["raw"], window_s),
        "detection": C.detection(data["scenarios"]),
        "server": C.server(data["metrics"]),
    }
    for name, df in tables.items():
        df.to_csv(os.path.join(out_dir, f"{name}.csv"), index=False, float_format="%.3f",
                  lineterminator="\n")
    # Title from the campaign's own record, not its path: the output must not change when
    # a campaign is copied (published) elsewhere.
    title = None
    manifest = os.path.join(campaign_dir, "campaign.json")
    if os.path.isfile(manifest):
        with open(manifest, encoding="utf-8") as fh:
            title = json.load(fh).get("campaign_id")
    with open(os.path.join(out_dir, "summary.md"), "w", encoding="utf-8") as fh:
        fh.write(C.summary_markdown(title, data, tables, window_s, reference))
    return out_dir, data, tables


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("campaign", help="campaign directory (or a single run directory)")
    ap.add_argument("--window", type=float, default=10.0,
                    help="equal-exposure window after the attack start, seconds (default 10)")
    ap.add_argument("--reference", default="unprotected",
                    help="mode the others are compared with (default unprotected)")
    ap.add_argument("--out", help="output directory (default <campaign>/analysis)")
    args = ap.parse_args()
    out_dir, _, _ = analyse(args.campaign, args.out, args.window, args.reference)
    print(f"[+] analysis written to {out_dir}/ (summary.md + tables)")


if __name__ == "__main__":
    main()
