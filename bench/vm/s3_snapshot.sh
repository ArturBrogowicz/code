#!/bin/bash
# Read-only snapshot of the host and the tree, for comparing before and after an S3 run. usage: s3_snapshot.sh DIR
# The tree is the checkout this script lies in (its bench/vm/). DIR is deleted first and written again.
set -u
WT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
B=$1
rm -rf "$B" && mkdir -p "$B"
cd "$WT" || exit 1
date -u +%FT%TZ > "$B/time.txt"
cat /proc/uptime /proc/loadavg > "$B/uptime_load.txt"
lsmod | sort > "$B/lsmod.txt"
ps -eo pid,ppid,user,args --sort=pid > "$B/ps.txt"
ip netns list > "$B/netns.txt" 2>&1
ip -br link show > "$B/links.txt"
ss -ltnH 2>/dev/null | sort > "$B/listeners.txt"
ls -la --time-style=full-iso /var/log/nginx > "$B/var_log_nginx.txt" 2>&1
ls -la --time-style=full-iso bench/__pycache__ > "$B/pycache.txt" 2>&1
stat -c '%U:%G %y %n' "$(git rev-parse --git-path index)" > "$B/index.txt" 2>&1
git rev-parse HEAD > "$B/head.txt"
git status --short > "$B/status.txt"
ls -la /run/nginx.pid > "$B/pid.txt" 2>&1
python3 -c "
import sys; sys.path.insert(0, 'bench')
import executor as X
print(X.leftovers(X.RealHost()))" > "$B/leftovers.txt" 2>&1
echo "snapshot $(cat "$B/time.txt"): uptime/load $(tr '\n' ' ' < "$B/uptime_load.txt"); HEAD $(cut -c1-7 "$B/head.txt") status [$(tr '\n' '|' < "$B/status.txt")]; netns [$(cat "$B/netns.txt")]; leftovers $(cat "$B/leftovers.txt"); modules $(wc -l < "$B/lsmod.txt"); listeners $(wc -l < "$B/listeners.txt")"
