#!/bin/bash
# EXP-1 (approved by the user on 2026-10-12): 3 XDP-mode runs of test_distributed_suite.py with the
# D1+D2 patch (unique veth MACs + nginx restart/orphan fix), executed from a patched COPY of the
# suite so the repository working tree is not modified. CWD = repo (daemon uses relative paths).
set -u
C=/root/project_analysis/campaigns/2026-10-12_macfix_xdp
SUITE=/root/project_analysis/patches/work/b/test_distributed_suite.py
cd /home/artur/DDoS-mitigation/code || exit 1
{ echo "start $(date -u +%FT%T.%N)"; git rev-parse HEAD; git status --short; uname -a
  sha256sum "$SUITE" test_distributed_suite.py control_plane.py xdp_ddos_filter.c nginx.conf nginx_unprotected.conf \
            training_results/gru_testbed_model.pth training_results/scaler_testbed.save training_results/feature_config_testbed.json
  echo "MITIGATION_BACKEND=${MITIGATION_BACKEND:-<unset>=xdp} MITIGATION_MODE=${MITIGATION_MODE:-<unset>=active}"; } > $C/provenance.txt 2>&1
# read-only observer: ms-timestamped copy of every daemon log line (the suite deletes/recreates the log per scenario)
tail -n +1 -F /tmp/mitigation_distributed_test.log 2>&1 | python3 -u -c 'import sys,time
for l in sys.stdin:
    sys.stdout.write("%.3f %s" % (time.time(), l)); sys.stdout.flush()' > $C/daemon_log_timestamped.txt &
for i in 1 2 3; do
  echo "===== XDP-MACFIX run $i/3 ====="
  python3 "$SUITE"
done > $C/console.log 2>&1
sleep 2
pkill -f "tail -n \+1 -F /tmp/mitigation_distributed_test.log"
for f in /tmp/mitigation_performance.csv /tmp/availability_performance.csv /tmp/availability_raw_performance.csv; do cp -p "$f" $C/ 2>>$C/provenance.txt; done
( cd $C && sha256sum *.csv > SHA256SUMS )
{ echo "end $(date -u +%FT%T.%N)"; echo "nginx processes after final cleanup: $(ps -C nginx --no-headers | wc -l)"; echo "netns after: $(ip netns list | wc -l)"; } >> $C/provenance.txt
