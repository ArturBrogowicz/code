#!/bin/bash
# EXP-1c (approved by the user on 2026-10-12): "nginx limits, no daemon" — copy c/ of the suite
# (= verified D1+D2 copy b/ + NGINX_PROTECTED switch, see patches/EXP1c_nginxlimits_mode.diff),
# MITIGATION_MODE=none + NGINX_PROTECTED=1 -> protected nginx.conf, no control_plane. 3 runs. Repo untouched.
set -u
SUITE=/root/project_analysis/patches/work/c/test_distributed_suite.py
C=/root/project_analysis/campaigns/2026-10-12_macfix_nginxlimits; mkdir -p "$C"
cd /home/artur/DDoS-mitigation/code || exit 1
{ echo "start $(date -u +%FT%T.%N)"; echo "env: MITIGATION_MODE=none NGINX_PROTECTED=1"; git rev-parse HEAD; git status --short; uname -a
  sha256sum "$SUITE" /root/project_analysis/patches/work/b/test_distributed_suite.py test_distributed_suite.py nginx.conf nginx_unprotected.conf
  journalctl -k -n 0 --show-cursor --no-pager | tail -1; } > "$C/provenance.txt" 2>&1
for i in 1 2 3; do
  echo "===== NGINXLIMITS-MACFIX run $i/3 ====="
  env MITIGATION_MODE=none NGINX_PROTECTED=1 python3 "$SUITE"
done > "$C/console.log" 2>&1
for f in /tmp/metrics_nginxlimits.csv /tmp/availability_nginxlimits.csv /tmp/availability_raw_nginxlimits.csv; do cp -p "$f" "$C/" 2>>"$C/provenance.txt"; done
( cd "$C" && sha256sum *.csv > SHA256SUMS )
{ echo "end $(date -u +%FT%T.%N)"; echo "nginx processes after final cleanup: $(ps -C nginx --no-headers | wc -l)"
  echo "netns after: $(ip netns list | wc -l)"; } >> "$C/provenance.txt"
