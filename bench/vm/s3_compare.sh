#!/bin/bash
# Compares two snapshots of s3_snapshot.sh. usage: s3_compare.sh BEFORE AFTER
set -u
B=$1
A=$2
echo "before $(cat "$B/time.txt")  after $(cat "$A/time.txt")   uptime/load after: $(tr '\n' ' ' < "$A/uptime_load.txt")"
echo "HEAD/status: $(cut -c1-7 "$A/head.txt") / [$(tr '\n' '|' < "$A/status.txt")]   (before: $(cut -c1-7 "$B/head.txt") / [$(tr '\n' '|' < "$B/status.txt")])"
echo "netns now: [$(cat "$A/netns.txt")]   links: $(awk '{print $1}' "$A/links.txt" | tr '\n' ' ')   (before: $(awk '{print $1}' "$B/links.txt" | tr '\n' ' '))"
echo "executor.leftovers() now: $(cat "$A/leftovers.txt")"
echo "testbed processes now:"; awk 'NR>1 && ($3 == "nginx" || $3 == "gunicorn")' <(ps -eo pid,user,comm,args); echo "  (none above = none)"
echo "kernel modules, before -> after:"; diff "$B/lsmod.txt" "$A/lsmod.txt" | cut -c1-90 || true; diff -q "$B/lsmod.txt" "$A/lsmod.txt" > /dev/null && echo "  identical"
echo "listeners:"; diff "$B/listeners.txt" "$A/listeners.txt" && echo "  identical"
echo "pid file: $(cat "$A/pid.txt")"
echo "git index: $(cat "$A/index.txt")   (before: $(cat "$B/index.txt"))"
echo "bench/__pycache__ owners now:"; awk 'NR>3{print $3}' "$A/pycache.txt" | sort | uniq -c
diff <(awk 'NR>3{print $3, $9}' "$B/pycache.txt") <(awk 'NR>3{print $3, $9}' "$A/pycache.txt") > /dev/null && echo "  owners and names unchanged"
echo "/var/log/nginx:"; diff <(awk '{print $3,$5,$6,$7,$9}' "$B/var_log_nginx.txt") <(awk '{print $3,$5,$6,$7,$9}' "$A/var_log_nginx.txt") && echo "  unchanged"
