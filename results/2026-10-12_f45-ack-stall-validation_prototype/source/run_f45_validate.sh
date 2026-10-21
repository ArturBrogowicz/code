#!/bin/bash
# F-45 validation (approved): run the PATCHED daemon (cp_f45) through repeated ACK floods — the scenario
# that intermittently stalled ~10 s on HEAD (1/6 runs in EXP-1). XDP mode, ACK flood only, 6 runs.
# Check every bot-ban TTM stays < 2 s (no stall). Suite copy g/ (D1+D2 + CONTROL_PLANE override). Repo untouched.
set -u
SUITE=/root/project_analysis/patches/work/g/test_distributed_suite.py
CPATCH=/root/project_analysis/patches/work/cp_f45/control_plane.py
C=/root/project_analysis/campaigns/2026-10-12_f45; mkdir -p "$C"
cd /home/artur/DDoS-mitigation/code || exit 1
{ echo "start $(date -u +%FT%T)  HEAD $(git rev-parse --short HEAD)"; echo "patched daemon: $CPATCH"
  sha256sum "$SUITE" "$CPATCH" /home/artur/DDoS-mitigation/code/control_plane.py; } > "$C/provenance.txt"
rm -f /tmp/mitigation_performance.csv /tmp/availability_performance.csv /tmp/availability_raw_performance.csv
tail -n +1 -F /tmp/mitigation_distributed_test.log 2>&1 | python3 -u -c 'import sys,time
for l in sys.stdin:
    sys.stdout.write("%.3f %s"%(time.time(),l)); sys.stdout.flush()' > "$C/daemon_log_timestamped.txt" &
tpid=$!
for i in 1 2 3 4 5 6; do
  echo "===== F45 patched ACK run $i/6 ====="
  env CONTROL_PLANE_OVERRIDE=$CPATCH ONLY_SCENARIOS=5 python3 "$SUITE"
done > "$C/console.log" 2>&1
sleep 2; kill $tpid 2>/dev/null; pkill -f "tail -n \+1 -F /tmp/mitigation_distributed_test.log" 2>/dev/null
cp -p /tmp/mitigation_performance.csv /tmp/availability_performance.csv /tmp/availability_raw_performance.csv "$C/" 2>/dev/null
# restore clean EXP-1 xdp CSVs
cp -p /root/project_analysis/campaigns/2026-10-12_macfix_xdp/mitigation_performance.csv /root/project_analysis/campaigns/2026-10-12_macfix_xdp/availability_performance.csv /root/project_analysis/campaigns/2026-10-12_macfix_xdp/availability_raw_performance.csv /tmp/ 2>/dev/null
echo "end $(date -u +%FT%T)  nginx=$(ps -C nginx --no-headers|wc -l) netns=$(ip netns list|wc -l)" >> "$C/provenance.txt"
echo "=== per-run ACK result + Avg TTM (harness) ==="; sed -r 's/\x1B\[[0-9;]*[A-Za-z]//g' "$C/console.log" | grep -E "F45 patched|Botnet banned:|Avg TTM:|\[(PASS|FAIL)\]" | tee "$C/quicklook.txt"
echo "=== exact per-bot ACK ban TTM from daemon log (should all be < 2 s) ==="
/home/artur/DDoS-mitigation/code/venv/bin/python -I -c "
import re
ev=[(float(m.group(1)),m.group(2)) for l in open('$C/daemon_log_timestamped.txt',errors='replace') if (m:=re.match(r'^(\d+\.\d+) \[BAN\] (10\.0\.2\.\S+)',l.strip()))]
if ev:
    t0=ev[0][0]; import statistics as st
    # group bans into runs by >30s gaps
    runs=[]; cur=[ev[0]]
    for a,b in ev[1:]:
        if a-cur[-1][0]>30: runs.append(cur); cur=[]
        cur.append((a,b))
    runs.append(cur)
    for i,r in enumerate(runs,1):
        ts=[a for a,_ in r]; print(f'  run{i}: {len(r)} bans, span {max(ts)-min(ts):.2f}s (first-to-last)')
    print('  NOTE: TTM vs attack-start needs phase ts; use Avg TTM above as proxy. Max inter-ban span flags a stall.')
"
