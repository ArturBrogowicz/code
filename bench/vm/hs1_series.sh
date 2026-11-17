#!/bin/bash
# HS1, the standalone host stability check: the series (docs/HS1_PREREG.md, section 4).
#
#   bench/vm/hs1_series.sh RUN_DIR            check the start conditions, then run detached (setsid nohup) and return
#   bench/vm/hs1_series.sh --collect RUN_DIR  write the extracts into RUN_DIR (the series does this when it stops;
#                                             after a host reset, run it once in the next boot before hs1_eval.py)
#   bench/vm/hs1_eval.py RUN_DIR              the verdict (verdict.json, medians.json)
#
# RUN_DIR must be a new or empty directory under /home/artur/agent_workspace/host/; nothing is written anywhere else.
# Every INTERVAL s (300) one probe (bench/vm/hs1_probe.py) on CPU 0, then 1, then 7, N times (HS1_SAMPLES, 36 = 3 h), each in
# the offline sandbox (HS1_SBX; empty = without it); beside it mpstat 5 s, pidstat 10 s, chrony every 30 s and the disk's
# latency (iostat -dx 30 s for sda and dm-0, reported only), all with TZ=UTC. HS1_STORAGE (user-reported: "internal SSD" or
# "USB HDD") is recorded and must match the pre-registration's expected storage, or the pre-check refuses.
# Stop: kill -TERM "$(cat RUN_DIR/run.pid)": monitors stop, identity_end.txt, END and the extracts are written; a probe in
# flight is killed (inside the sandbox it may still print its line within a few seconds). SIGINT does not work: bash starts
# the detached series with SIGINT ignored, and an ignored signal cannot be trapped.
# Every extract carries the collector's header (with its command's exit status) and end marker; hs1_eval.py counts an
# extract without them, or with a non-zero status, as a missing record.
# HS1_DRYRUN=1 (honoured only with HS1_SAMPLES < 36): the pre-check's refusals are recorded and ignored; the run is marked
# dry_run=1 and can never be an HS1 reading. Tier: T1 (offline; no network, no root state change; sudo only via the sandbox).
set -u
export TZ=UTC
HOST_BASE=/home/artur/agent_workspace/host
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
N=${HS1_SAMPLES:-36}
INTERVAL=${HS1_INTERVAL:-300}
REPEATS=${HS1_REPEATS:-21}
PY=${HS1_PY:-/home/artur/DDoS-mitigation/.venv/bin/python}
EPY=${HS1_EVAL_PY:-/home/artur/DDoS-mitigation/.venv/bin/python}
SBX=${HS1_SBX-/home/artur/agent_workspace/skills/sandboxed-offline-run/sbx.sh}
DRY=${HS1_DRYRUN:-0}
TIMERS="apt-daily.timer apt-daily-upgrade.timer fwupd-refresh.timer logrotate.timer man-db.timer"

usage() { sed -n '3,6p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; exit 2; }
mode=start
case "${1:-}" in --collect) mode=collect; shift;; --foreground) mode=foreground; shift;; -h|--help|"") usage;; esac
[ $# -eq 1 ] || usage
RUN=$(realpath -m -- "$1")
case "$RUN/" in "$HOST_BASE"/?*/) ;; *) echo "hs1: RUN_DIR must be under $HOST_BASE/ (got $RUN)" >&2; exit 2;; esac
if [ "$DRY" = 1 ] && ! [ "$N" -lt 36 ] 2>/dev/null; then
  echo "hs1: HS1_DRYRUN=1 is honoured only with HS1_SAMPLES < 36 (got $N)" >&2; exit 2
fi

ident() {   # key=value facts of the host and the code, for the start and end of the series
  local k; k=$(journalctl -b 0 -k -o cat -q --no-pager 2>/dev/null)
  {
    echo "utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "boot_id=$(cat /proc/sys/kernel/random/boot_id)"
    echo "uptime_s=$(cut -d' ' -f1 /proc/uptime)"
    echo "kernel=$(uname -r)"
    echo "cmdline=$(cat /proc/cmdline)"
    echo "memtotal_kb=$(awk '/^MemTotal:/{print $2}' /proc/meminfo)"
    echo "cpu_model=$(awk -F': ' '/^model name/{print $2; exit}' /proc/cpuinfo)"
    echo "tsc_mhz=$(sed -n 's/.*tsc: Detected \([0-9.]*\) MHz.*/\1/p' <<< "$k" | head -n 1)"
    echo "vbox_host_version=$(sed -n 's/.*vboxguest: host-version: \([^ ]*\).*/\1/p' <<< "$k" | head -n 1)"
    echo "timezone=$(timedatectl show -p Timezone --value 2>/dev/null)"
    echo "utc_offset=$(env -u TZ date +%z)"
    echo "chrony_tracking=$(chronyc -c tracking 2>/dev/null)"
    echo "chrony_sources=$(chronyc -c sources 2>/dev/null | paste -sd'|' -)"
    echo "masked=$(for t in $TIMERS; do printf '%s:%s,' "$t" "$(systemctl is-enabled "$t" 2>/dev/null)"; done)"
    echo "holds=$(apt-mark showhold 2>/dev/null | sort | paste -sd' ' -)"
    echo "dpkg_sha256=$(dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null | sha256sum | cut -c1-64)"
    echo "snap_sha256=$(snap list 2>/dev/null | sha256sum | cut -c1-64)"
    echo "busy_procs=$(pgrep -af -- '-m unittest|bench/executor\.py|bench/calibrate\.py|eval/run_campaign\.py' | cut -c1-80 | paste -sd'|' -)"
    for x in origin:bench/origin.py probe:bench/vm/hs1_probe.py series:bench/vm/hs1_series.sh eval:bench/vm/hs1_eval.py \
             record:bench/calibration/ddos-mitigation-2026-11-04.json; do
      echo "${x%%:*}_sha256=$(sha256sum "$ROOT/${x#*:}" | cut -c1-64)"
    done
    echo "git_head=$(git -C "$ROOT" rev-parse HEAD 2>/dev/null)"
    echo "git_dirty_n=$(git -C "$ROOT" status --porcelain 2>/dev/null | wc -l)"
    echo "storage=${HS1_STORAGE:-}"
    echo "dry_run=$DRY"
    echo "repeats=$REPEATS"; echo "n_samples=$N"; echo "interval_s=$INTERVAL"
  } > "$1" 2>/dev/null
}

extract() {  # extract NAME CMD...: CMD's output into RUN/NAME between the collector's header (CMD's exit status) and end marker
  local name=$1 rc out err
  shift
  out=$(mktemp "$RUN/.x.XXXXXX"); err=$(mktemp "$RUN/.x.XXXXXX")
  "$@" > "$out" 2> "$err"; rc=$?
  { echo "# hs1-collect v1 file=$name boot=$SB rc=$rc utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    cat "$out"; sed 's/^/# stderr: /' "$err"; echo "# hs1-collect end"; } > "$RUN/$name"
  rm -f "$out" "$err"
}

boot_tail() {  # the series boot against the collecting one, and the series boot's last 80 journal lines
  echo "series_boot_id=$SB"
  echo "current_boot_id=$(tr -d '-' < /proc/sys/kernel/random/boot_id)"
  echo "tail:"
  journalctl -b "$SB" --utc -o short-iso -q --no-pager -n 80
}

dpkg_window() { awk -v s="$1" '($1 " " $2) >= s' /var/log/dpkg.log; }

collect() {  # the series boot's extracts and the package records, into RUN
  local start
  SB=$(sed -n 's/^boot_id=//p' "$RUN/identity_start.txt" | tr -d '-')
  start=$(sed -n 's/^utc=//p' "$RUN/identity_start.txt")
  [ -n "$SB" ] && [ -n "$start" ] || { echo "hs1: no boot_id or utc in $RUN/identity_start.txt" >&2; return 1; }
  start=${start/T/ }; start=${start%Z}
  extract journal_kernel.txt journalctl -b "$SB" -k --utc -o short-iso -q --no-pager
  extract journal_chronyd.txt journalctl -b "$SB" -t chronyd --utc -o short-iso -q --no-pager
  extract boot_end.txt boot_tail
  extract dpkg_log_window.txt dpkg_window "$start"
  extract snap_changes.txt snap changes --abs-time
  return 0
}

if [ "$mode" = collect ]; then
  [ -f "$RUN/identity_start.txt" ] || { echo "hs1: $RUN has no identity_start.txt" >&2; exit 2; }
  collect; exit $?
fi

if [ "$mode" = start ]; then
  if [ -e "$RUN" ] && [ -n "$(ls -A "$RUN" 2>/dev/null)" ]; then echo "hs1: $RUN is not empty" >&2; exit 2; fi
  mkdir -p "$RUN" || exit 2
  ident "$RUN/identity_start.txt"
  if ! "$EPY" -I -B "$ROOT/bench/vm/hs1_eval.py" --precheck "$RUN" > "$RUN/precheck.txt" 2>&1; then
    cat "$RUN/precheck.txt" >&2
    if [ "$DRY" = 1 ]; then
      echo "hs1: DRY RUN: the pre-check's refusals above are recorded in precheck.txt and ignored" >&2
    else
      echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) precheck refused" > "$RUN/END"; exit 3
    fi
  fi
  setsid nohup bash "${BASH_SOURCE[0]}" --foreground "$RUN" > "$RUN/series.log" 2>&1 < /dev/null &
  echo "hs1: started pid $! ($N sample times every $INTERVAL s$([ "$DRY" = 1 ] && echo ', DRY RUN')); run dir $RUN"
  echo "hs1: stop with: kill -TERM \"\$(cat $RUN/run.pid)\""
  exit 0
fi

# --foreground: the series itself
echo $$ > "$RUN/run.pid"
P=; M1=; M2=; M3=; M4=
S_TIME_FORMAT=ISO LC_ALL=C TZ=UTC mpstat -P ALL 5 > "$RUN/mpstat.txt" 2>&1 & M1=$!
LC_ALL=C TZ=UTC pidstat -u -l -h -H 10 > "$RUN/pidstat.txt" 2>&1 & M2=$!
( while :; do
    u=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    echo "$u T $(chronyc -c tracking 2>/dev/null)"
    chronyc -c sources 2>/dev/null | sed "s/^/$u S /"
    sleep 30
  done ) > "$RUN/chrony.txt" 2>&1 & M3=$!
S_TIME_FORMAT=ISO LC_ALL=C TZ=UTC iostat -dxy -t 30 sda dm-0 > "$RUN/iostat.txt" 2>&1 & M4=$!

stop() {
  trap - INT TERM
  [ -n "$P" ] && kill "$P" 2>/dev/null
  kill "$M1" "$M2" "$M3" "$M4" 2>/dev/null
  wait 2>/dev/null
  ident "$RUN/identity_end.txt"
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $1" > "$RUN/END"
  collect
  exit 0
}
trap 'stop interrupted' INT TERM

for i in $(seq 1 "$N"); do
  t0=$(date +%s)
  for c in 0 1 7; do
    if [ -n "$SBX" ]; then
      "$SBX" "$RUN" taskset -c "$c" "$PY" -I -B "$ROOT/bench/vm/hs1_probe.py" "$i" "$REPEATS" >> "$RUN/probes.jsonl" 2>> "$RUN/probe_errors.txt" &
    else
      taskset -c "$c" "$PY" -I -B "$ROOT/bench/vm/hs1_probe.py" "$i" "$REPEATS" >> "$RUN/probes.jsonl" 2>> "$RUN/probe_errors.txt" &
    fi
    P=$!; wait "$P"; P=
  done
  if [ "$i" -lt "$N" ]; then
    s=$(( INTERVAL - ($(date +%s) - t0) ))
    if [ "$s" -gt 0 ]; then sleep "$s" & P=$!; wait "$P"; P=; fi
  fi
done
stop "complete $N"
