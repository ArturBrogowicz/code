#!/bin/bash
# EXP-1d calibration sweep (approved): find a server-capacity / attack-intensity operating point where the
# UNPROTECTED server drops below 100 % legit availability, so a cross-mode comparison becomes meaningful.
# Unprotected mode, HTTP flood only (ONLY_SCENARIOS=4), 1 run per config, suite copy d/. Repo untouched.
set -u
SUITE=/root/project_analysis/patches/work/d/test_distributed_suite.py
BASE=/root/project_analysis/campaigns/2026-10-12_calib; mkdir -p "$BASE"
cd /home/artur/DDoS-mitigation/code || exit 1
# label|env   (GW=gunicorn workers, GT=threads, CPUS=server taskset, WC=wrk conns, BOTS=bot count)
CONFIGS=(
  "w1t1_cpu0_c50_b5|GUNICORN_WORKERS=1 GUNICORN_THREADS=1 SERVER_CPUS=0 WRK_CONNS=50 BOTNET_COUNT=5"
  "w1t1_cpu0_c200_b5|GUNICORN_WORKERS=1 GUNICORN_THREADS=1 SERVER_CPUS=0 WRK_CONNS=200 BOTNET_COUNT=5"
  "w1t1_cpu0_c200_b10|GUNICORN_WORKERS=1 GUNICORN_THREADS=1 SERVER_CPUS=0 WRK_CONNS=200 BOTNET_COUNT=10"
  "w1t1_cpu0_c400_b10|GUNICORN_WORKERS=1 GUNICORN_THREADS=1 SERVER_CPUS=0 WRK_CONNS=400 BOTNET_COUNT=10"
  "w2t2_cpu01_c200_b10|GUNICORN_WORKERS=2 GUNICORN_THREADS=2 SERVER_CPUS=0-1 WRK_CONNS=200 BOTNET_COUNT=10"
)
echo "sweep start $(date -u +%FT%T)  HEAD $(git rev-parse --short HEAD)" > "$BASE/sweep.log"
printf "%-22s | %-8s | %s\n" "config" "result" "HTTP availability before/during/after" >> "$BASE/sweep.log"
for entry in "${CONFIGS[@]}"; do
  label="${entry%%|*}"; env_kv="${entry#*|}"; C="$BASE/$label"; mkdir -p "$C"
  rm -f /tmp/availability_unprotected.csv /tmp/availability_raw_unprotected.csv /tmp/metrics_unprotected.csv
  echo "===== CALIB $label ($env_kv) =====" > "$C/console.log"
  env MITIGATION_MODE=none ONLY_SCENARIOS=4 $env_kv python3 "$SUITE" >> "$C/console.log" 2>&1
  for f in availability_unprotected availability_raw_unprotected metrics_unprotected; do cp -p /tmp/$f.csv "$C/" 2>/dev/null; done
  line=$(sed -r 's/\x1B\[[0-9;]*[A-Za-z]//g' "$C/console.log" | grep -m1 "Availability:" | sed 's/.*Availability: *//')
  res=$(sed -r 's/\x1B\[[0-9;]*[A-Za-z]//g' "$C/console.log" | grep -m1 -oE '\[(PASS|FAIL)\]')
  printf "%-22s | %-8s | %s\n" "$label" "$res" "$line" >> "$BASE/sweep.log"
done
echo "sweep end $(date -u +%FT%T)  nginx=$(ps -C nginx --no-headers|wc -l) netns=$(ip netns list|wc -l)" >> "$BASE/sweep.log"
# restore the clean EXP-1b unprotected CSVs to /tmp (sweep rm'd them)
cp -p /root/project_analysis/campaigns/2026-10-12_macfix_unprotected/availability_unprotected.csv /tmp/ 2>/dev/null
cp -p /root/project_analysis/campaigns/2026-10-12_macfix_unprotected/availability_raw_unprotected.csv /tmp/ 2>/dev/null
cp -p /root/project_analysis/campaigns/2026-10-12_macfix_unprotected/metrics_unprotected.csv /tmp/ 2>/dev/null
cat "$BASE/sweep.log"
