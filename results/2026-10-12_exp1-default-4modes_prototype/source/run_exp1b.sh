#!/bin/bash
# EXP-1b (approved by the user on 2026-10-12): the D1+D2-patched COPY of test_distributed_suite.py
# (unique veth MACs + nginx restart/orphan fix) in iptables mode (3 runs), then unprotected mode (3 runs).
# Repo working tree is not modified; CWD = repo so the daemon's relative paths resolve.
set -u
SUITE=/root/project_analysis/patches/work/b/test_distributed_suite.py
BASE=/root/project_analysis/campaigns
cd /home/artur/DDoS-mitigation/code || exit 1
run_mode () {   # $1 = tag (iptables|unprotected); $2.. = env assignments for the suite
  local tag=$1; shift
  local C=$BASE/2026-10-12_macfix_$tag; mkdir -p "$C"
  { echo "start $(date -u +%FT%T.%N)"; echo "env: $*"; git rev-parse HEAD; git status --short; uname -a
    sha256sum "$SUITE" test_distributed_suite.py control_plane.py xdp_ddos_filter.c nginx.conf nginx_unprotected.conf \
              training_results/gru_testbed_model.pth training_results/scaler_testbed.save training_results/feature_config_testbed.json
    journalctl -k -n 0 --show-cursor --no-pager | tail -1; } > "$C/provenance.txt" 2>&1
  tail -n +1 -F /tmp/mitigation_distributed_test.log 2>&1 | python3 -u -c 'import sys,time
for l in sys.stdin:
    sys.stdout.write("%.3f %s" % (time.time(), l)); sys.stdout.flush()' > "$C/daemon_log_timestamped.txt" &
  for i in 1 2 3; do
    echo "===== ${tag^^}-MACFIX run $i/3 ====="
    env "$@" python3 "$SUITE"
  done > "$C/console.log" 2>&1
  sleep 2
  pkill -f "tail -n \+1 -F /tmp/mitigation_distributed_test.log"
  for f in /tmp/metrics_$tag.csv /tmp/availability_$tag.csv /tmp/availability_raw_$tag.csv; do cp -p "$f" "$C/" 2>>"$C/provenance.txt"; done
  ( cd "$C" && sha256sum *.csv > SHA256SUMS )
  { echo "end $(date -u +%FT%T.%N)"; echo "nginx processes after final cleanup: $(ps -C nginx --no-headers | wc -l)"
    echo "netns after: $(ip netns list | wc -l)"; systemctl list-timers --all --no-pager | grep -E "fwupd|fstrim|sysstat-collect"; } >> "$C/provenance.txt"
}
run_mode iptables MITIGATION_BACKEND=iptables
run_mode unprotected MITIGATION_MODE=none
