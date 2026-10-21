#!/bin/sh
# Regenerates every file of this directory (except README.md and SHA256SUMS) from the
# published campaigns. Offline, no root. From the repository root:
#
#     sh results/2026-10-20_audit-derived/regenerate.sh
#     (cd results/2026-10-20_audit-derived && sha256sum -c SHA256SUMS)
#
# The ban-event census names its campaigns explicitly (those published on 2026-10-20), so
# this directory stays what it was when it was published.
set -eu
cd "$(dirname "$0")/../.."
PY="${PYTHON:-./venv/bin/python}"
OUT=results/2026-10-20_audit-derived
P5C4=results/2026-10-16_l7-p5c4-eval
RUNS="$P5C4/runA1 $P5C4/runA2 $P5C4/runA3 $P5C4/runA4 $P5C4/runA5"
export MPLCONFIGDIR="${MPLCONFIGDIR:-/tmp/mplconfig-$$}"

# Does the L7 GRU use request order? (audit G-02)
$PY ml/order_ablation.py results/2026-10-16_l7-p5c3-train/model $RUNS $P5C4/runC \
    --out $OUT/order_ablation.json --md $OUT/order_ablation.md > /dev/null

# Do the labelled attackers harm anyone, who is flagged, at what rate? (audit G-01, G-05, G-08)
$PY ml/l7_run_audit.py harm  $RUNS --md $OUT/l7_harm_p5c4.md  --json $OUT/l7_harm_p5c4.json  > /dev/null
$PY ml/l7_run_audit.py roles $RUNS --md $OUT/l7_roles_p5c4.md --json $OUT/l7_roles_p5c4.json > /dev/null
$PY ml/l7_run_audit.py rates $RUNS --md $OUT/l7_rates_p5c4.md --json $OUT/l7_rates_p5c4.json > /dev/null

# Run-level inference on the knee campaigns (audit G-06); EXP-A is the one with ten blocks
for c in 2026-10-12_exp2a-knee_prototype 2026-10-13_exp2a-knee_reproduction \
         2026-10-13_exp2a-knee_equal-exposure-30s 2026-10-20_expa-knee-10-blocks; do
    $PY eval/run_level_stats.py results/$c --md $OUT/run_level_$c.md --csv $OUT/run_level_$c.csv > /dev/null
done

# The complete full-suite runs side by side: bans, engines, time to mitigate, bound per engine
S=results
$PY eval/suite_compare.py R2=$S/2026-10-13_regression-default-full-suite \
    replicate=$S/2026-10-13_regression-default-full-suite-replicate \
    baseline=$S/2026-10-19_baseline-before-audit-defaults \
    after=$S/2026-10-20_regression-after-audit-defaults \
    tolerant=$S/2026-10-20_expb-tolerant-profile-suite --md $OUT/suite_compare.md > /dev/null

# Ban events of every published campaign: who banned whom (audit G-16, G-11)
$PY eval/events_census.py \
    results/2026-10-11_superseded-dup-mac results/2026-10-12_exp2a-knee_prototype \
    results/2026-10-13_exp2a-knee_equal-exposure-30s results/2026-10-13_exp2a-knee_reproduction \
    results/2026-10-13_regression-default-full-suite \
    results/2026-10-13_regression-default-full-suite-replicate results/2026-10-14_l7-p1-smoke \
    results/2026-10-15_l7-p2-smoke results/2026-10-15_l7-p3-capture results/2026-10-15_l7-p4-train \
    results/2026-10-16_l7-p5-eval results/2026-10-16_l7-p5c-baseline \
    results/2026-10-16_l7-p5c2-tolerant-verify results/2026-10-16_l7-p5c3-capture \
    results/2026-10-16_l7-p5c3-train results/2026-10-16_l7-p5c4-eval \
    results/2026-10-19_baseline-before-audit-defaults results/2026-10-20_omitted-runs \
    --md $OUT/events_census.md --json $OUT/events_census.json > /dev/null
echo "regenerated $OUT"
