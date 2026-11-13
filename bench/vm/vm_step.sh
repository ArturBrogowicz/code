#!/bin/bash
# vm_step.sh [--print] NAME -- COMMAND [ARG...]
# Runs COMMAND from the worktree root with a read-only snapshot of the host before and after (s3_snapshot.sh, s3_compare.sh), `free -m` and
# `vmstat -n 5` beside it, its output teed to $S/NAME_output.txt; exits with COMMAND's exit code. Refuses a NAME used before.
# The worktree is the checkout this script lies in (its bench/vm/); S comes from the environment, default /var/tmp/hg1c_scratch.
# S4's s4_run.sh is this with its command written in. --print shows what would be done and runs nothing.
set -u
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
WT=$(cd "$HERE/../.." && pwd -P)
S=${S:-/var/tmp/hg1c_scratch}
PRINT=0
if [ "${1:-}" = "--print" ]; then PRINT=1; shift; fi
NAME=${1:-}
if [ -z "$NAME" ] || [ "${2:-}" != "--" ] || [ $# -lt 3 ]; then echo "usage: vm_step.sh [--print] NAME -- COMMAND [ARG...]"; exit 64; fi
shift 2
if [ $PRINT = 1 ]; then
    echo "cd $WT"
    echo "test ! -e $S/${NAME}_output.txt"
    echo "bash $HERE/s3_snapshot.sh $S/${NAME}_before; free -m > $S/${NAME}_free_before.txt"
    echo "vmstat -n 5 > $S/${NAME}_vmstat.txt &      (stopped at the end)"
    echo "$* 2>&1 | tee $S/${NAME}_output.txt"
    echo "free -m > $S/${NAME}_free_after.txt; bash $HERE/s3_snapshot.sh $S/${NAME}_after; bash $HERE/s3_compare.sh $S/${NAME}_before $S/${NAME}_after"
    exit 0
fi
cd "$WT" || exit 1
if [ -e "$S/${NAME}_output.txt" ]; then echo "$NAME was run already: $S/${NAME}_output.txt exists"; exit 9; fi
bash "$HERE/s3_snapshot.sh" "$S/${NAME}_before" | cut -c1-300
free -m > "$S/${NAME}_free_before.txt"
vmstat -n 5 > "$S/${NAME}_vmstat.txt" &
VM=$!
trap 'kill $VM 2>/dev/null' EXIT
date -u +"$NAME start %FT%TZ"
"$@" 2>&1 | tee "$S/${NAME}_output.txt"
code=${PIPESTATUS[0]}
date -u +"$NAME end   %FT%TZ, exit $code"
kill $VM 2>/dev/null
free -m > "$S/${NAME}_free_after.txt"
bash "$HERE/s3_snapshot.sh" "$S/${NAME}_after" | cut -c1-300
bash "$HERE/s3_compare.sh" "$S/${NAME}_before" "$S/${NAME}_after" | cut -c1-220
exit $code
