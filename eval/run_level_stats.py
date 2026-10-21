#!/usr/bin/env python3
"""Run-level inference for a campaign (audit G-06).

Offline and read-only. The unit of analysis is the RUN, not the request: one success
percentage per (mode, run) for a scenario and a period, and inference over runs.
Campaigns recorded by eval/run_campaign.py give every mode the same PROFILE_SEEDs, so
runs sharing a seed form a block and a mode is compared with the reference mode inside
each block (paired). Per contrast the tool reports

  * the mean of the block differences (percentage points) and its 95 % t-interval;
  * the paired t-test p and the exact two-sided sign-flip p (Monte Carlo above
    EXACT_MAX_N blocks);
  * the share of blocks whose difference has the sign of the mean;
  * a decision from the rule below;
  * the number of blocks that would give 80 % power for the observed effect and SD.

It does NOT report pooled-request tests. eval/campaign.py's Fisher test treats the ~100
requests of a run as independent, and its 3-block bootstrap has 10 distinct resamples.
With n paired blocks the smallest attainable two-sided sign-flip p is 2 / 2^n (0.25 for
n = 3), so a handful of blocks cannot reach significance by that test whatever the effect.

Campaigns without shared seeds (the prototype EXP-2a import) are compared unpaired
(Welch interval, exact permutation p) and carry no decision.

DECISION RULE, fixed here before any EXP-A data exists (the commit that adds this file is
its timestamp). A paired contrast is "supported" iff
  (a) it has at least MIN_BLOCKS blocks,
  (b) the LEVEL t-interval of the mean block difference excludes 0, and
  (c) at least SAME_SIGN_SHARE of the blocks have the sign of the mean.
Otherwise it is "not shown" (or "too few blocks"). A contrast that is not supported is
reported as such; it is not evidence of no effect.

    ./venv/bin/python eval/run_level_stats.py CAMPAIGN [--reference unprotected]
        [--period during] [--scenario NAME ...] [--min-blocks N] [--md FILE] [--csv FILE]
"""
import argparse
import itertools
import math
import os
import sys

import numpy as np
import pandas as pd
from scipy import stats

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "eval"))
import campaign as C

LEVEL = 0.95
MIN_BLOCKS = 10
SAME_SIGN_SHARE = 0.8
EXACT_MAX_N = 20                 # sign-flip enumeration up to 2^20 patterns
MC_DRAWS = 200_000
MC_SEED = 20261020
POWER = 0.8
ALPHA = 0.05


def t_interval(d, level=LEVEL):
    """(mean, lo, hi) of the t-interval of the mean; lo, hi are NaN for fewer than 2 values."""
    d = np.asarray(d, dtype=float)
    mean = float(d.mean())
    if len(d) < 2:
        return mean, math.nan, math.nan
    half = stats.t.ppf(0.5 + level / 2, len(d) - 1) * d.std(ddof=1) / math.sqrt(len(d))
    return mean, mean - half, mean + half


def paired_t_p(d):
    """Two-sided p of the one-sample (paired) t-test of mean 0."""
    d = np.asarray(d, dtype=float)
    if len(d) < 2:
        return math.nan
    sd = d.std(ddof=1)
    if sd == 0:
        return 0.0 if d.mean() != 0 else 1.0
    return float(2 * stats.t.sf(abs(d.mean() / (sd / math.sqrt(len(d)))), len(d) - 1))


def signflip_p(d, seed=MC_SEED):
    """Two-sided sign-flip permutation p of mean 0: exact up to EXACT_MAX_N values, else
    Monte Carlo with a fixed seed. Never below 2 / 2^n."""
    d = np.asarray(d, dtype=float)
    n = len(d)
    if n == 0:
        return math.nan
    obs = abs(d.sum())
    tol = 1e-9 * max(1.0, float(np.abs(d).sum()))
    if n <= EXACT_MAX_N:
        total, count, chunk = 1 << n, 0, 1 << min(n, 16)
        bits = np.arange(n)
        for start in range(0, total, chunk):
            idx = np.arange(start, min(start + chunk, total))[:, None]
            signs = 1.0 - 2.0 * ((idx >> bits) & 1)
            count += int((np.abs(signs @ d) >= obs - tol).sum())
        return count / total
    rng = np.random.default_rng(seed)
    count, done = 0, 0
    while done < MC_DRAWS:
        m = min(20_000, MC_DRAWS - done)
        signs = rng.choice((-1.0, 1.0), size=(m, n))
        count += int((np.abs(signs @ d) >= obs - tol).sum())
        done += m
    return (count + 1) / (MC_DRAWS + 1)


def same_sign_share(d):
    d = np.asarray(d, dtype=float)
    mean = d.mean()
    return 0.0 if mean == 0 else float((np.sign(d) == np.sign(mean)).mean())


def decide(d, min_blocks=MIN_BLOCKS):
    """The pre-registered decision for the block differences `d` (see the module doc)."""
    if len(d) < min_blocks:
        return f"too few blocks ({len(d)} < {min_blocks})"
    mean, lo, hi = t_interval(d)
    if (lo > 0 or hi < 0) and same_sign_share(d) >= SAME_SIGN_SHARE:
        return "supported (+)" if mean > 0 else "supported (-)"
    return "not shown"


def blocks_for_power(delta, sd, power=POWER, alpha=ALPHA, max_n=500):
    """Smallest number of paired blocks with the given power for a true mean difference
    `delta` and block-difference SD `sd` (noncentral t). None if there is no such n <= max_n."""
    if not sd or sd <= 0 or not delta:
        return None
    for n in range(3, max_n + 1):
        df = n - 1
        nc = abs(delta) / (sd / math.sqrt(n))
        crit = stats.t.ppf(1 - alpha / 2, df)
        if 1 - stats.nct.cdf(crit, df, nc) + stats.nct.cdf(-crit, df, nc) >= power:
            return n
    return None


def welch(a, b, level=LEVEL):
    """(mean difference, lo, hi, p) of a Welch test of mean(a) - mean(b)."""
    a, b = np.asarray(a, dtype=float), np.asarray(b, dtype=float)
    diff = float(a.mean() - b.mean())
    if len(a) < 2 or len(b) < 2:
        return diff, math.nan, math.nan, math.nan
    va, vb = a.var(ddof=1) / len(a), b.var(ddof=1) / len(b)
    if va + vb == 0:
        return diff, diff, diff, 0.0 if diff != 0 else 1.0
    df = (va + vb) ** 2 / ((va ** 2 / (len(a) - 1) if va else 0)
                           + (vb ** 2 / (len(b) - 1) if vb else 0))
    half = stats.t.ppf(0.5 + level / 2, df) * math.sqrt(va + vb)
    return diff, diff - half, diff + half, float(2 * stats.t.sf(abs(diff) / math.sqrt(va + vb), df))


def exact_permutation_p(a, b):
    """Two-sided exact permutation p of the difference of means (all splits of the pooled
    values); NaN when there are more than 20 values."""
    pooled = np.concatenate([np.asarray(a, float), np.asarray(b, float)])
    n, k = len(pooled), len(a)
    if n > 20 or k == 0 or k == n:
        return math.nan
    obs = abs(np.mean(a) - np.mean(b))
    tol = 1e-9 * max(1.0, float(np.abs(pooled).sum()))
    count = total = 0
    for idx in itertools.combinations(range(n), k):
        mask = np.zeros(n, dtype=bool)
        mask[list(idx)] = True
        total += 1
        count += abs(pooled[mask].mean() - pooled[~mask].mean()) >= obs - tol
    return count / total


def _seed(x):
    return None if x is None or (isinstance(x, float) and math.isnan(x)) else int(x)


def run_percentages(raw, scenario, mode, period):
    """{run: success %} of a (scenario, mode, period); each run is one unit."""
    rows = raw[(raw.Scenario == scenario) & (raw["mode"] == mode) & (raw.Period == period)]
    if rows.empty:
        return {}
    counts = C._per_run_counts(rows)
    return {run: 100.0 * s / c for run, (s, c) in zip(counts.index, counts.to_numpy(), strict=True)
            if c > 0}


def contrasts(data, reference="unprotected", period="during", scenarios=None,
              min_blocks=MIN_BLOCKS):
    """One row per (scenario, mode) contrast against `reference`."""
    raw, runs = data["raw"], data["runs"]
    if raw.empty or reference not in set(raw["mode"]):
        return pd.DataFrame()
    seed_of = {(r.mode, r.run): _seed(r.profile_seed) for r in runs.itertuples()}
    rows = []
    for scen in scenarios or C._scenario_order(raw):
        ref = run_percentages(raw, scen, reference, period)
        if not ref:
            continue
        for mode in C.ordered_modes(raw["mode"]):
            if mode == reference:
                continue
            cur = run_percentages(raw, scen, mode, period)
            if not cur:
                continue
            seeds_c = {seed_of.get((mode, r)): v for r, v in cur.items()}
            seeds_r = {seed_of.get((reference, r)): v for r, v in ref.items()}
            paired = (None not in seeds_c and None not in seeds_r
                      and len(seeds_c) == len(cur) and len(seeds_r) == len(ref)
                      and bool(set(seeds_c) & set(seeds_r)))
            row = {"scenario": scen, "mode": mode, "reference": reference, "period": period}
            if paired:
                blocks = sorted(set(seeds_c) & set(seeds_r))
                d = np.array([seeds_c[k] - seeds_r[k] for k in blocks])
                mean, lo, hi = t_interval(d)
                row.update(design=f"paired by PROFILE_SEED ({len(d)} blocks)", blocks=len(d),
                           mean_diff_pp=mean, ci_lo=lo, ci_hi=hi, t_p=paired_t_p(d),
                           perm_p=signflip_p(d), same_sign=same_sign_share(d),
                           decision=decide(d, min_blocks),
                           blocks_for_80pct_power=blocks_for_power(mean, d.std(ddof=1)
                                                                   if len(d) > 1 else None))
            else:
                a, b = np.array(list(cur.values())), np.array(list(ref.values()))
                mean, lo, hi, p = welch(a, b)
                row.update(design=f"unpaired ({len(a)} vs {len(b)} runs)", blocks=min(len(a), len(b)),
                           mean_diff_pp=mean, ci_lo=lo, ci_hi=hi, t_p=p,
                           perm_p=exact_permutation_p(a, b), same_sign=math.nan,
                           decision="unpaired: descriptive only", blocks_for_80pct_power=None)
            rows.append(row)
    return pd.DataFrame(rows)


def _fmt(x, spec):
    if x is None or (isinstance(x, float) and math.isnan(x)):
        return "—"
    # A column that holds a missing value is float64, so whole numbers arrive as 12.0.
    return format(int(x), spec) if spec == "d" else format(x, spec)


def to_markdown(df, title="Run-level contrasts"):
    head = ("| Scenario | Mode vs reference | Design | Mean diff (pp) | 95 % t-interval | "
            "Paired t p | Sign-flip / permutation p | Same-sign blocks | Decision | "
            "Blocks for 80 % power |")
    lines = [f"**{title}**", "", head, "|---|---|---|---|---|---|---|---|---|---|"]
    for r in df.itertuples():
        lines.append(
            f"| {r.scenario} | {r.mode} vs {r.reference} ({r.period}) | {r.design} "
            f"| {_fmt(r.mean_diff_pp, '+.1f')} | [{_fmt(r.ci_lo, '+.1f')}, {_fmt(r.ci_hi, '+.1f')}] "
            f"| {_fmt(r.t_p, '.3f')} | {_fmt(r.perm_p, '.4f')} | {_fmt(r.same_sign, '.2f')} "
            f"| {r.decision} | {_fmt(r.blocks_for_80pct_power, 'd')} |")
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("campaign", help="campaign directory (or a single run)")
    ap.add_argument("--reference", default="unprotected")
    ap.add_argument("--period", default="during", choices=C.PERIOD_ORDER)
    ap.add_argument("--scenario", action="append", help="restrict to a scenario (repeatable)")
    ap.add_argument("--min-blocks", type=int, default=MIN_BLOCKS)
    ap.add_argument("--md", help="write the table as Markdown")
    ap.add_argument("--csv", help="write the table as CSV")
    args = ap.parse_args(argv)
    df = contrasts(C.load(args.campaign), args.reference, args.period, args.scenario,
                   args.min_blocks)
    if df.empty:
        raise SystemExit(f"no contrasts: no runs of the reference mode {args.reference!r} "
                         f"with availability data under {args.campaign}")
    text = to_markdown(df)
    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(text)
    if args.csv:
        df.to_csv(args.csv, index=False, float_format="%.4f")
    print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
