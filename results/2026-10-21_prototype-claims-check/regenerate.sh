#!/bin/sh
# Regenerates every file of this directory (except README.md and SHA256SUMS) from the
# published campaigns. Offline, no root. From the repository root:
#
#     sh results/2026-10-21_prototype-claims-check/regenerate.sh      # PYTHON=... if ./venv is elsewhere
#     (cd results/2026-10-21_prototype-claims-check && sha256sum -c SHA256SUMS)
set -eu
cd "$(dirname "$0")/../.."
PY="${PYTHON:-./venv/bin/python}"
OUT=results/2026-10-21_prototype-claims-check
export MPLCONFIGDIR="${MPLCONFIGDIR:-/tmp/mplconfig-$$}"

# Each number of docs/REPORT_ADDENDUM_EXP0_EXP1.md that rests on the prototype campaigns,
# recomputed from the published files: match / differs / cannot be checked
$PY eval/check_addendum.py --md $OUT/claims_check.md --csv $OUT/claims_check.csv > /dev/null

# Who banned whom in the ban events of the three converted prototype campaigns
$PY eval/events_census.py \
    results/2026-10-12_exp1-default-4modes_prototype \
    results/2026-10-12_exp2b-knee-nginxtuned_prototype \
    results/2026-10-12_f45-ack-stall-validation_prototype \
    --md $OUT/events_census_prototype.md --json $OUT/events_census_prototype.json > /dev/null
echo "regenerated $OUT"
