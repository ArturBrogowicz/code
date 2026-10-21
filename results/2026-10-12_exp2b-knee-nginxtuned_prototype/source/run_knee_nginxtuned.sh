#!/bin/bash
# EXP-2b (approved): nginx-limits-only at the knee, but with the TUNED config (limit_req_status 429,
# limit_req_log_level warn, error_log error, access_log skips 429s). Isolates how much of EXP-2a's
# nginx-limits collapse (52%) was the 503 + logging amplification. 3 runs, HTTP flood. Suite copy d/.
set -u
SUITE=/root/project_analysis/patches/work/d/test_distributed_suite.py
C=/root/project_analysis/campaigns/2026-10-12_knee_nginxtuned; mkdir -p "$C"
TUNED=/root/project_analysis/configs/nginx_limits_tuned.conf
COMMON="GUNICORN_WORKERS=1 GUNICORN_THREADS=1 SERVER_CPUS=0 ATTACK_CPUS=1-7 WRK_CONNS=400 BOTNET_COUNT=10 ONLY_SCENARIOS=4"
cd /home/artur/DDoS-mitigation/code || exit 1
{ echo "start $(date -u +%FT%T)  HEAD $(git rev-parse --short HEAD)"; echo "COMMON: $COMMON"; echo "NGINX_CONF_OVERRIDE=$TUNED"
  sha256sum "$SUITE" "$TUNED"; } > "$C/provenance.txt"
rm -f /tmp/metrics_nginxlimits.csv /tmp/availability_nginxlimits.csv /tmp/availability_raw_nginxlimits.csv
for i in 1 2 3; do
  echo "===== KNEE nginxtuned run $i/3 ====="
  env $COMMON MITIGATION_MODE=none NGINX_PROTECTED=1 NGINX_CONF_OVERRIDE=$TUNED python3 "$SUITE"
done > "$C/console.log" 2>&1
cp -p /tmp/metrics_nginxlimits.csv /tmp/availability_nginxlimits.csv /tmp/availability_raw_nginxlimits.csv "$C/" 2>/dev/null
( cd "$C" && sha256sum *.csv > SHA256SUMS 2>/dev/null )
# restore clean EXP-1c nginxlimits CSVs to /tmp
cp -p /root/project_analysis/campaigns/2026-10-12_macfix_nginxlimits/metrics_nginxlimits.csv /root/project_analysis/campaigns/2026-10-12_macfix_nginxlimits/availability_nginxlimits.csv /root/project_analysis/campaigns/2026-10-12_macfix_nginxlimits/availability_raw_nginxlimits.csv /tmp/ 2>/dev/null
echo "end $(date -u +%FT%T)  nginx=$(ps -C nginx --no-headers|wc -l) netns=$(ip netns list|wc -l)" >> "$C/provenance.txt"
echo "=== nginxtuned HTTP 'during' availability (3 runs) ==="; sed -r 's/\x1B\[[0-9;]*[A-Za-z]//g' "$C/console.log" | grep "Availability:" | sed 's/.*Availability: */  /' | tee "$C/quicklook.txt"
