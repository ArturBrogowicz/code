#!/usr/bin/env python3
"""Aggregate P5 shadow-evaluation runs into one verdict (docs/L7_GRU_DESIGN.md §7.1).

Offline: reads each run's summary.json (written by ml/eval_l7.py) and applies the
PRE-REGISTERED verdict rule of §7.1 to the full-mix runs:

  marginal value shown  iff  the deterministic engines ban ~0 of the fast sub-threshold
  attackers, the GRU would-bans most of them, benign would-bans ~0, AND the H1b static
  threshold sweep has no threshold that catches as many attackers with 0 benign flagged.

    ./venv/bin/python ml/p5_report.py --run A=dirA --run B=dirB --run C=dirC --run D=dirD \
        [--out report.json] [--md report.md]
"""
import argparse
import json
import os
import sys

FAST_SUBTHRESHOLD = ("subthreshold_flood", "scraper")       # the GRU's niche (R1)
HELD_OUT = ("credstuff", "padded_flood", "slowread")
SLOW = ("slowloris", "slowpost", "slowread")


def load(path):
    with open(os.path.join(path, "summary.json"), encoding="utf-8") as fh:
        return json.load(fh)


def fam_counts(an, families):
    ips = det = would = 0
    for f in families:
        e = an["by_family"].get(f)
        if e:
            ips += e["ips"]
            det += e["det_banned"]
            would += e["would_banned"]
    return {"ips": ips, "det_banned": det, "would_banned": would}


def best_static(sweep):
    """The threshold with the most attacker IPs caught at 0 benign IPs flagged."""
    clean = [r for r in sweep["sweep"] if r["benign_ips_flagged"] == 0]
    return max(clean, key=lambda r: r["attacker_ips_caught"]) if clean else None


def verdict(summary):
    """Apply the §7.1 rule to one full-mix run. Returns (bool, reasons dict)."""
    an = summary["analysis"]
    fast = fam_counts(an, FAST_SUBTHRESHOLD)
    attackers_total = sum(e["ips"] for e in an["by_family"].values())
    gru_attackers = sum(e["would_banned"] for e in an["by_family"].values())
    static = best_static(summary["threshold_sweep"])
    reasons = {
        "fast_subthreshold": fast,
        "det_bans_fast_near_zero": fast["det_banned"] == 0,
        "gru_catches_most_fast": fast["ips"] > 0 and fast["would_banned"] > fast["ips"] / 2,
        "benign_would_bans": an["benign_would_ban_count"],
        "benign_near_zero": an["benign_would_ban_count"] == 0,
        "gru_attackers_caught_total": gru_attackers,
        "attackers_total": attackers_total,
        "best_static_threshold_at_0_benign": static,
        "static_matches_gru": (static is not None
                               and static["attacker_ips_caught"] >= gru_attackers),
    }
    ok = (reasons["det_bans_fast_near_zero"] and reasons["gru_catches_most_fast"]
          and reasons["benign_near_zero"] and not reasons["static_matches_gru"])
    return ok, reasons


def to_markdown(runs, verdicts):
    lines = [("| Run | Model | Soak | Benign would-bans | Fast sub-threshold: det-banned / "
              "GRU would-ban / IPs | Held-out GRU would-ban | Slow: det / GRU | "
              "Best static thr @ 0 benign | Verdict |"),
             "|---|---|---|---|---|---|---|---|---|"]
    for name, s in runs.items():
        an = s["analysis"]
        fast = fam_counts(an, FAST_SUBTHRESHOLD)
        ho = fam_counts(an, HELD_OUT)
        slow = fam_counts(an, SLOW)
        st = best_static(s["threshold_sweep"]) if not s.get("soak") else None
        v = verdicts.get(name)
        vtxt = "—" if v is None else ("PASS" if v[0] else "no marginal value")
        sttxt = (f"{st['rps_threshold']} rps → {st['attacker_ips_caught']} IPs"
                 if st else "—")
        lines.append(
            f"| {name} | {os.path.basename(os.path.dirname(s['model'].rstrip('/')))}/"
            f"{os.path.basename(s['model'].rstrip('/'))} | {s.get('soak')} | "
            f"{an['benign_would_ban_count']} / {an['benign_ips_total']} IPs | "
            f"{fast['det_banned']} / {fast['would_banned']} / {fast['ips']} | "
            f"{ho['would_banned']} / {ho['ips']} | {slow['det_banned']} / {slow['would_banned']} | "
            f"{sttxt} | {vtxt} |")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--run", action="append", required=True, help="NAME=dir")
    ap.add_argument("--out")
    ap.add_argument("--md")
    args = ap.parse_args()
    runs = {}
    for item in args.run:
        name, _, path = item.partition("=")
        runs[name] = load(path)
    verdicts = {n: verdict(s) for n, s in runs.items() if not s.get("soak")}
    report = {"runs": {n: {"model": s["model"], "seed": s["seed"], "soak": s.get("soak"),
                           "analysis": s["analysis"],
                           "threshold_sweep": s["threshold_sweep"]} for n, s in runs.items()},
              "verdicts": {n: {"marginal_value": v[0], "reasons": v[1]} for n, v in verdicts.items()}}
    md = to_markdown(runs, verdicts)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=1, default=str)
            fh.write("\n")
    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(md + "\n")
    print(md)
    for n, v in verdicts.items():
        print(f"{n}: marginal value {'SHOWN' if v[0] else 'NOT shown'} — {json.dumps(v[1], default=str)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
