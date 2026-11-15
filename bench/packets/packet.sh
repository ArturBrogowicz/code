#!/bin/bash
# A packet of the harm benchmark's re-calibration (docs/RECALIBRATION_2026-11_DESIGN.md 5.2, 5.3 and 6.2; K7): the pre-checks, then the
# speed hold and the step(s) detached from the terminal (setsid nohup) with the packet's time budget, a tar and the sha256 of the
# outputs, and a one-line summary at the end of the packet's log. The step's own runner starts the monitors (K4) and judges every run.
#
#   sudo bench/packets/packet.sh PACKET --commit SHA [--session DIR] [--record FILE] [--campaign DIR] [--medians FILE]
#   bench/packets/packet.sh PACKET --print [...]          # what it would do; runs nothing, needs no root
#
# PACKET: R1 (speed hold against HS1's medians on this PC, K11: --medians FILE or HS1_MEDIANS=FILE; origin; capacity), R2a, R2b,
# R2c (one family's ladder each), R3 (the
# reference), R4 (the confirmation, a later window), P2-1 (the smoke runs of HG4 at twice the new knee), P2-2 (the MVP campaign; it
# takes two or three packets). Stop it with `kill -TERM` of the pid the terminal prints, the detached stage's (T-115 H-2): the stage
# passes the TERM to the step's process, waits for it to end (the step's own teardown takes the testbed down), starts no further step,
# and still writes the tar, its sha256 and the summary ("stopped by TERM"); the same command resumes. (The step runs as `cmd &` in a
# non-interactive bash, which starts it with SIGINT ignored; each Python main puts the default handler back, so an INT to the step's
# process stops it too, but TERM to the stage is the documented stop: T-105 F3.)
set -euo pipefail

SELF=$(realpath "$0")
PACKET=${1:-}
shift || true
SESSION=/var/tmp/ddos_campaigns/recal_2026-11
RECORD=""
CAMPAIGN=/var/tmp/ddos_campaigns/hg4_mvp_xdp_recal
COMMIT=""
MEDIANS=${HS1_MEDIANS:-}             # R1's speed reference: HS1's medians.json on this PC (K11)
PRINT=0
STAGE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --session) SESSION=$2; shift 2;;
    --record) RECORD=$2; shift 2;;
    --campaign) CAMPAIGN=$2; shift 2;;
    --commit) COMMIT=$2; shift 2;;
    --medians) MEDIANS=$2; shift 2;;
    --print) PRINT=1; shift;;
    --stage) STAGE=1; shift;;
    *) echo "packet.sh: unknown argument $1" >&2; exit 2;;
  esac
done

case "$SESSION" in /*) ;; *) echo "packet.sh: --session takes an absolute path (the stage runs from the repository's root), got '$SESSION'" >&2; exit 2;; esac
case "$CAMPAIGN" in /*) ;; *) echo "packet.sh: --campaign takes an absolute path (the stage runs from the repository's root), got '$CAMPAIGN'" >&2; exit 2;; esac

BUDGET_MIN=85                       # no run starts after 85 min, so the run in progress ends the packet within 90 (6.2)
PACKET_MIN=90
PY="./venv/bin/python -B"           # root writes no bytecode into the repository (T-105 F10); its children inherit this:
export PYTHONDONTWRITEBYTECODE=1
# R1's paired check of the two probe contexts (T-105 F8): HS1's probe is not in this tree, so the packet names it as a manual step
PAIRED="manual step, not run by this packet (T-105 F8): before R1's hold, one HS1 probe in HS1's own context (bench/vm/hs1_probe.py of feat/hs1-check, in sbx as uid 1000 with -I -B) and one hold probe (bench/calibrate.py origin-session as root) on the same CPU; record both contexts' costs"

HG4=bench/scenarios/cheap_static_flood_hg4.json

# the steps of each packet, one command a line; REMAINING is the packet's budget left when the line starts
steps() {
  # R1 against HS1's medians on this PC (K11; never the 2026-11-04 costs, which are another PC's); the probe takes the template's knobs
  local hold_hs1="$PY bench/hostcheck.py speed-hold --calibration bench/calibration/placeholder.json --medians ${MEDIANS:-HS1_MEDIANS} --session $SESSION --lo -0.10 --hi 0.10 --agree 0.05 --max-min 45"
  local hold_r1="$PY bench/hostcheck.py speed-hold --calibration bench/calibration/placeholder.json --reference $SESSION/origin/origin.json --lo -0.10 --hi 0.10 --max-min 30"
  local hold_rec="$PY bench/hostcheck.py speed-hold --calibration ${RECORD:-RECORD} --reference ${RECORD:-RECORD} --lo -0.10 --hi 0.10 --max-min 30"
  case "$1" in
    R1)  echo "$hold_hs1"
         echo "$PY bench/calibrate.py origin --out $SESSION"
         echo "$PY bench/calibrate.py capacity --out $SESSION --stop-after REMAINING";;
    R2a) echo "$hold_r1"; echo "$PY bench/calibrate.py ladder --family cheap_static_flood --out $SESSION --stop-after REMAINING";;
    R2b) echo "$hold_r1"; echo "$PY bench/calibrate.py ladder --family costly_export_flood --out $SESSION --stop-after REMAINING";;
    R2c) echo "$hold_r1"; echo "$PY bench/calibrate.py ladder --family costly_search_flood --out $SESSION --stop-after REMAINING";;
    R3)  echo "$hold_r1"; echo "$PY bench/calibrate.py reference --out $SESSION --stop-after REMAINING";;
    R4)  echo "$hold_rec"; echo "$PY bench/calibrate.py drift --calibration ${RECORD:-RECORD} --out $SESSION/confirmation --stop-after REMAINING";;
    P2-1) echo "$hold_rec"
          echo "$PY bench/executor.py run $HG4 --calibration ${RECORD:-RECORD} --kind M_xdp --seed 1 --out $CAMPAIGN.smoke/M_xdp"
          echo "$PY bench/executor.py run $HG4 --calibration ${RECORD:-RECORD} --kind M_limits --seed 1 --out $CAMPAIGN.smoke/M_limits";;
    P2-2) echo "$hold_rec"; echo "$PY bench/gate_campaign.py run $HG4 --calibration ${RECORD:-RECORD} --modes xdp --out $CAMPAIGN --stop-after REMAINING";;
    *) return 1;;
  esac
}

what() {
  case "$1" in
    R1) echo "speed hold against HS1's medians on this PC (K11); origin step; capacity (3 staged runs)";;
    R2a|R2b|R2c) echo "one family's ladder (18 runs: 14 attack runs at 7 levels, 4 controls)";;
    R3) echo "the reference: 5 rounds of the legit probe and one attack run per family";;
    R4) echo "the confirmation: 3 rounds, in a later window after a reboot (D4)";;
    P2-1) echo "AP-8 rebuilt: one M_xdp and one M_limits smoke run of cheap_static_flood_hg4";;
    P2-2) echo "AP-9 rebuilt: the MVP campaign, warm-up + 10 blocks of C, Cp, U, M_xdp, over two or three packets";;
  esac
}

outputs() {
  case "$1" in
    R4) echo "$SESSION/confirmation";;
    P2-1) echo "$CAMPAIGN.smoke";;
    P2-2) echo "$CAMPAIGN";;
    *) echo "$SESSION";;
  esac
}

if ! steps "$PACKET" >/dev/null 2>&1; then
  echo "packet.sh: PACKET is one of R1 R2a R2b R2c R3 R4 P2-1 P2-2, got '$PACKET'" >&2
  exit 2
fi
case "$PACKET" in R4|P2-1|P2-2) if [ -z "$RECORD" ] && [ "$PRINT" = 0 ]; then
  echo "packet.sh: $PACKET runs on the new frozen record: --record FILE" >&2; exit 2; fi;; esac
if [ -z "$COMMIT" ] && [ "$PRINT" = 0 ]; then
  echo "packet.sh: a packet runs at a pinned commit, which its pre-checks hold the tree and the frozen hashes to: --commit SHA" >&2; exit 2
fi
if [ "$PACKET" = R1 ] && [ -z "$MEDIANS" ] && [ "$PRINT" = 0 ]; then
  echo "packet.sh: R1 holds against HS1's medians on this PC (K11): --medians FILE or HS1_MEDIANS=FILE" >&2; exit 2
fi
[ -n "$MEDIANS" ] && [ -e "$MEDIANS" ] && MEDIANS=$(realpath "$MEDIANS")      # the stage runs from the repository's root

# the packet's log, tar and sha256: beside the campaign for P2-2 (a campaign directory holds nothing that is not the campaign's),
# in the step's output directory otherwise
case "$PACKET" in P2-2) LOGDIR=$CAMPAIGN.packets;; *) LOGDIR=$(outputs "$PACKET")/packets;; esac
PRECHECK="$PY bench/packets/prechecks.py --packet $PACKET --session $SESSION --minutes $PACKET_MIN --commit ${COMMIT:-COMMIT}${RECORD:+ --record $RECORD}"

if [ "$PRINT" = 1 ]; then
  echo "== packet $PACKET: $(what "$PACKET") =="
  echo "session     $SESSION"
  echo "budget      $BUDGET_MIN min: no run starts after it (--stop-after the minutes left), so the packet ends within $PACKET_MIN min"
  echo "pre-checks  $PRECHECK"
  echo "            (clean tree at the pinned commit, and its frozen hashes: bench/, eval/, the testbed's files and the record hash to"
  echo "            its blobs; kernel, MemTotal, CPU model and VirtualBox host version the session's, before its"
  echo "            first step the laptop's (D-096), all four reported; uptime 1800 s, chrony within H4, no apt, dpkg or daily timer due"
  echo "            within $PACKET_MIN + 10 min, no package job, no testbed left, no other process above 5 % of a CPU; each check fails"
  echo "            closed on a command that failed or printed nothing)"
  if [ "$PACKET" = R1 ]; then
    echo "reference   HS1's medians ${MEDIANS:-HS1_MEDIANS} on this PC: its sha256 printed by the hold and kept in $SESSION/speed_reference.json"
    echo "paired      $PAIRED"
  fi
  echo "detached    setsid nohup bash bench/packets/packet.sh $PACKET --stage ... > $LOGDIR/${PACKET}_<UTC>.log 2>&1 < /dev/null &"
  n=1
  while IFS= read -r line; do echo "step $n      $line"; n=$((n + 1)); done < <(steps "$PACKET")
  echo "after       tar -czf $LOGDIR/${PACKET}_<UTC>.tar.gz $(outputs "$PACKET"); sha256sum of it into ${PACKET}_<UTC>.sha256"
  echo "stop        kill -TERM <the stage's pid, printed at the start>: the TERM goes on to the step's process, the stage waits for"
  echo "            its teardown, starts no further step and still writes the tar, the sha256 and the summary; the same command resumes"
  echo "summary     one line at the end of the log: PACKET $PACKET <done|paused|host unfit|stopped|stopped by TERM> (exit N): runs made,"
  echo "            host-invalid"
  exit 0
fi

cd "$(dirname "$SELF")/../.."
if [ "$(id -u)" != 0 ]; then
  echo "packet.sh: the steps need root (namespaces): sudo bench/packets/packet.sh $PACKET ..." >&2
  exit 2
fi

# --- the stage's functions (tests/test_packets.py StageStopTest runs this block with stand-in steps) ------------------------------------

# the minutes of the packet's budget left at NOW for a packet that began at START (epoch seconds), to the hundredth, rounded down:
# never more than is left (T-105 F15); nothing (status 1) when less than a minute is
budget_left() {
  local left_s=$(( BUDGET_MIN * 60 - ( $2 - $1 ) ))
  [ "$left_s" -ge 60 ] || return 1
  printf '%d.%02d\n' $(( left_s / 60 )) $(( left_s % 60 * 100 / 60 ))
}

# kill -TERM of the stage stops the packet (T-115 H-2): the trap passes the TERM to the step's process, whose own handler takes the
# testbed down (the executor's teardown), and the stage waits for it to end, starts no further step, and still writes the tar, its
# sha256 and the summary. A TERM between two steps starts no further step. (INT is trapped too, but the stage starts with SIGINT
# ignored, as every `&` of a non-interactive bash does, and bash cannot trap a signal that was ignored at its entry: TERM is the stop.)
STOP="" STOP_STEP="" STEP_PID=""
on_stop() {
  STOP=${STOP:-$1}
  if [ -n "$STEP_PID" ]; then
    STOP_STEP=${STOP_STEP:-$STEP_PID}
    echo "$(date -u +%FT%TZ) $1: passing TERM to the step's process $STEP_PID and waiting for it to end"
    kill -TERM "$STEP_PID" 2>/dev/null || true
  else
    echo "$(date -u +%FT%TZ) $1: no step is running; no further step starts"
  fi
}

# the exit code of the step's process $1: a trapped signal ends `wait` early (status 128 + its number) while the step still runs, so
# the stage waits again until the step has ended, and then takes the status bash kept for it
step_wait() {
  local rc r
  wait "$1"; rc=$?
  while kill -0 "$1" 2>/dev/null; do
    wait "$1"; r=$?
    [ "$r" = 127 ] && break                                  # no longer this shell's child: it has ended
    rc=$r
  done
  wait "$1" 2>/dev/null; r=$?; [ "$r" = 127 ] || rc=$r     # the status bash kept, if the step ended inside an interrupted wait
  return "$rc"
}

# the detached stage: the steps in turn with the budget left, then the tar of the outputs, its sha256 and the one-line summary at the
# end of the log; its exit code is the last step's (128 + the signal's number for a stop that found no step running)
stage() {
  local start stamp mark code=0 line left cmd stopped out tar made invalid state
  trap 'on_stop TERM' TERM
  trap 'on_stop INT' INT
  start=$(date +%s)
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  mark=$(mktemp)
  echo "packet $PACKET stage, pid $$, $(date -u +%FT%TZ); kill -TERM $$ stops it"
  [ "$PACKET" = R1 ] && echo "paired check: $PAIRED"
  while IFS= read -r line; do
    if [ -n "$STOP" ]; then echo "$(date -u +%FT%TZ) stopped by $STOP: not started: $line"; break; fi
    left=$(budget_left "$start" "$(date +%s)") || { code=4; echo "the budget is used before: $line"; break; }
    cmd=${line//REMAINING/$left}
    echo "$(date -u +%FT%TZ) running: $cmd"
    set +e
    $cmd & STEP_PID=$!
    echo "the step's process: $STEP_PID (the packet stops with kill -TERM $$, the stage)"
    [ -z "$STOP" ] || on_stop "$STOP"                       # a TERM that came before the step's pid was known
    step_wait "$STEP_PID"; code=$?
    set -e
    STEP_PID=""
    echo "$(date -u +%FT%TZ) exit $code"
    [ -z "$STOP" ] || break
    [ "$code" = 0 ] || break
  done < <(steps "$PACKET")
  stopped=$STOP
  if [ -n "$stopped" ] && [ -z "$STOP_STEP" ]; then code=$(( 128 + $(kill -l "$stopped") )); fi
  out=$(outputs "$PACKET")
  tar="$LOGDIR/${PACKET}_${stamp}.tar.gz"
  tar --exclude=packets -czf "$tar" -C "$(dirname "$out")" "$(basename "$out")" 2>/dev/null || true
  sha256sum "$tar" > "${tar%.tar.gz}.sha256" || true
  made=$( { find "$out" -name DONE -newer "$mark" -not -path '*hostinvalid*' 2>/dev/null || true; } | wc -l)
  invalid=$( { find "$out" -maxdepth 6 -type d -name '*.hostinvalid*' -newer "$mark" 2>/dev/null || true; } | wc -l)
  if [ -n "$stopped" ]; then state="stopped by $stopped"
  else case "$code" in 0) state=done;; 4) state=paused;; 5) state="host unfit";; *) state=stopped;; esac; fi
  echo "PACKET $PACKET $state (exit $code): runs made $made, host-invalid $invalid; $(( ($(date +%s) - start) / 60 )) min; tar $tar, sha256 $(cut -c1-16 "${tar%.tar.gz}.sha256")"
  rm -f "$mark"
  return "$code"
}
# --- end of the stage's functions -------------------------------------------------------------------------------------------------------

if [ "$STAGE" = 0 ]; then
  $PRECHECK || { echo "packet.sh: a pre-check refused the packet; nothing was started" >&2; exit 3; }
  mkdir -p "$LOGDIR"
  STAMP=$(date -u +%Y%m%dT%H%M%SZ)
  LOG="$LOGDIR/${PACKET}_${STAMP}.log"
  setsid nohup bash "$SELF" "$PACKET" --stage --session "$SESSION" ${RECORD:+--record "$RECORD"} --campaign "$CAMPAIGN" \
    ${COMMIT:+--commit "$COMMIT"} ${MEDIANS:+--medians "$MEDIANS"} > "$LOG" 2>&1 < /dev/null &
  STAGE_PID=$!
  for _ in $(seq 50); do                # the pid the stage says it has, in its log's first line (else setsid's, which is the same here)
    said=$(sed -n '1s/^packet .* stage, pid \([0-9][0-9]*\),.*/\1/p' "$LOG" 2>/dev/null || true)
    if [ -n "$said" ]; then STAGE_PID=$said; break; fi
    sleep 0.1
  done
  echo "packet $PACKET started (pid $STAGE_PID), detached; its log: $LOG"
  echo "stop it with kill -TERM $STAGE_PID: the step's process gets the TERM and takes the testbed down, no further step starts, and"
  echo "the tar, its sha256 and the summary are still written; the same command resumes"
  exit 0
fi

# --- the detached stage ---------------------------------------------------------------------------------------------------------------
stage
