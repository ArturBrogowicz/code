#!/bin/bash
# A packet of the harm benchmark's re-calibration (docs/RECALIBRATION_2026-11_DESIGN.md 5.2, 5.3 and 6.2; K7): the pre-checks, then the
# speed hold and the step(s) detached from the terminal (setsid nohup) with the packet's time budget, a tar and the sha256 of the
# outputs, and a one-line summary at the end of the packet's log. The step's own runner starts the monitors (K4) and judges every run.
#
#   sudo bench/packets/packet.sh PACKET --commit SHA [--session DIR] [--record FILE] [--campaign DIR] [--medians FILE] [--paired DIR]
#   bench/packets/packet.sh PACKET --print [...]          # what it would do; runs nothing, needs no root
#
# PACKET: R1 (P-1's paired check went on, K20b: --paired DIR; speed hold against HS1's medians on this PC, K11: --medians FILE or
# HS1_MEDIANS=FILE; origin; capacity), R2a, R2b,
# R2c (one family's ladder each), R3 (the
# reference), R4 (the confirmation, a later window), P2-1 (the smoke runs of HG4 at twice the new knee), P2-2 (the MVP campaign; it
# takes two or three packets). Stop it with `sudo kill -TERM` of the pid the terminal prints, the detached stage's (T-115 H-2; the stage
# runs as root, so a kill without sudo is refused: T-117 N-1): the stage passes the TERM to the step's process, waits for it to end (the
# step's own teardown takes the testbed down), starts no further step, and still writes the tar, its sha256 and the summary ("stopped by
# TERM" when the step ended on it); the same command resumes. No run starts after 85 min; the packet can end about 3 h after its start
# at worst (PACKET_MIN below, T-117 N-2). (The step runs as `cmd &` in a
# non-interactive bash, which starts it with SIGINT ignored; each Python main puts the default handler back, so an INT to the step's
# process stops it too, but TERM to the stage is the documented stop: T-105 F3.)
set -euo pipefail

SELF=$(realpath "$0")
STARTED=$(date +%s)                 # the packet's start, which P-1's paired check must be at most 30 min before (K20b)
PACKET=${1:-}
shift || true
SESSION=/var/tmp/ddos_campaigns/recal_2026-11
RECORD=""
CAMPAIGN=/var/tmp/ddos_campaigns/hg4_mvp_xdp_recal
COMMIT=""
MEDIANS=${HS1_MEDIANS:-}             # R1's speed reference: HS1's medians.json on this PC (K11)
PAIRED_DIR=""                        # R1: the OUT_DIR of P-1's paired check (bench/vm/paired_check.py run OUT_DIR), K20b
PRINT=0
STAGE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --session) SESSION=$2; shift 2;;
    --record) RECORD=$2; shift 2;;
    --campaign) CAMPAIGN=$2; shift 2;;
    --commit) COMMIT=$2; shift 2;;
    --medians) MEDIANS=$2; shift 2;;
    --paired) PAIRED_DIR=$2; shift 2;;
    --print) PRINT=1; shift;;
    --stage) STAGE=1; shift;;
    *) echo "packet.sh: unknown argument $1" >&2; exit 2;;
  esac
done

case "$SESSION" in /*) ;; *) echo "packet.sh: --session takes an absolute path (the stage runs from the repository's root), got '$SESSION'" >&2; exit 2;; esac
case "$CAMPAIGN" in /*) ;; *) echo "packet.sh: --campaign takes an absolute path (the stage runs from the repository's root), got '$CAMPAIGN'" >&2; exit 2;; esac

BUDGET_MIN=85                       # no run starts after 85 min (--stop-after the minutes left, K6)
# How late the packet can end (T-117 N-2): a run that starts just before 85 min may be the first run of its step, which takes the full gate
# (uptime and load up to --wait-gate 30 min, then the timer gate up to 30 min more), then runs (2-5 min), and if it is host-invalid the
# hold after it takes up to 30 min before the budget is checked again: 85 + 30 + 30 + 5 + 30 = 180 min, about 3 h. The pre-checks look
# for timers due within it plus 10 min.
PACKET_MIN=180
PY="./venv/bin/python -B"           # root writes no bytecode into the repository (T-105 F10); its children inherit this:
export PYTHONDONTWRITEBYTECODE=1
# R1's paired check of the two probe contexts, P-1 (prereg 5.3; T-105 F8, T-115 M-1; K20b, a candidate until the user approves P-1): the
# user runs it right before R1, and the packet refuses R1 unless its paired.json says go on, from this boot, at most 30 min old
PAIRED="P-1 (prereg 5.3), run by the user right before R1: bench/vm/paired_check.py run OUT_DIR --medians FILE (HS1's context A in sbx as uid 1000, the hold's context B as root, CPU 0 then 1, A B B A; D = the mean of B/A - 1 over the CPUs and C3, C5). R1 starts only if OUT_DIR/paired.json has schema paired-check/1, exit 0 (|D| <= 5 %, every probe read), this boot's boot_id, a judged_utc at most 30 min before the packet starts and an uptime_s_at_start (written by run, not by a later judge) (--paired OUT_DIR); otherwise packet.sh refuses, exit 2, before the hold and the pre-checks, and the user decides"

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
if [ -n "$PAIRED_DIR" ] && [ "$PACKET" != R1 ]; then
  echo "packet.sh: --paired is R1's: P-1's paired check is checked before R1's hold only" >&2; exit 2
fi
if [ "$PACKET" = R1 ] && [ -z "$PAIRED_DIR" ] && [ "$PRINT" = 0 ]; then
  echo "packet.sh: R1 starts only after P-1's paired check went on (prereg 5.3, K20b): --paired OUT_DIR, the directory of" \
    "bench/vm/paired_check.py run OUT_DIR --medians FILE" >&2; exit 2
fi
[ -n "$MEDIANS" ] && [ -e "$MEDIANS" ] && MEDIANS=$(realpath "$MEDIANS")      # the stage runs from the repository's root
[ -n "$PAIRED_DIR" ] && [ -e "$PAIRED_DIR" ] && PAIRED_DIR=$(realpath "$PAIRED_DIR")

# the packet's log, tar and sha256: beside the campaign for P2-2 (a campaign directory holds nothing that is not the campaign's),
# in the step's output directory otherwise
case "$PACKET" in P2-2) LOGDIR=$CAMPAIGN.packets;; *) LOGDIR=$(outputs "$PACKET")/packets;; esac
PRECHECK="$PY bench/packets/prechecks.py --packet $PACKET --session $SESSION --minutes $PACKET_MIN --commit ${COMMIT:-COMMIT}${RECORD:+ --record $RECORD}"
PAIRED_GATE="$PY bench/packets/prechecks.py paired ${PAIRED_DIR:-PAIRED_DIR} --started"      # + the packet's start (K20b)

if [ "$PRINT" = 1 ]; then
  echo "== packet $PACKET: $(what "$PACKET") =="
  echo "session     $SESSION"
  echo "budget      $BUDGET_MIN min: no run starts after it (--stop-after the minutes left). The run in progress can end the packet up to"
  echo "            $PACKET_MIN min after its start at worst: the first run of a step takes the full gate (uptime and load up to 30 min, then"
  echo "            the timer up to 30 min more), the run 2-5 min, a host-invalid run's hold up to 30 min: 85 + 30 + 30 + 5 + 30 = $PACKET_MIN"
  echo "pre-checks  $PRECHECK"
  echo "            (clean tree at the pinned commit, and its frozen hashes: bench/, eval/, the testbed's files and the record hash to"
  echo "            its blobs; kernel, MemTotal, CPU model and VirtualBox host version the session's, before its"
  echo "            first step the laptop's (D-096), all four reported; uptime 1800 s, chrony within H4, no apt, dpkg or daily timer due"
  echo "            within $PACKET_MIN + 10 min, no package job, no testbed left, no other process above 5 % of a CPU; each check fails"
  echo "            closed on a command that failed or printed nothing)"
  if [ "$PACKET" = R1 ]; then
    echo "reference   HS1's medians ${MEDIANS:-HS1_MEDIANS} on this PC: its sha256 printed by the hold and kept in $SESSION/speed_reference.json"
    echo "paired      $PAIRED"
    echo "p-1 gate    $PAIRED_GATE <the packet's start, epoch s>   (exit 2: R1 refused, nothing started)"
  fi
  echo "detached    setsid nohup bash bench/packets/packet.sh $PACKET --stage ... > $LOGDIR/${PACKET}_<UTC>.log 2>&1 < /dev/null &"
  n=1
  while IFS= read -r line; do echo "step $n      $line"; n=$((n + 1)); done < <(steps "$PACKET")
  echo "after       tar -czf $LOGDIR/${PACKET}_<UTC>.tar.gz $(outputs "$PACKET"); sha256sum of it into ${PACKET}_<UTC>.sha256"
  echo "stop        sudo kill -TERM <the stage's pid, printed at the start>: the TERM goes on to the step's process, the stage waits for"
  echo "            its teardown, starts no further step and still writes the tar, the sha256 and the summary; the same command resumes"
  echo "summary     one line at the end of the log: PACKET $PACKET <done|paused|host unfit|not frozen|stopped|stopped by TERM> (exit N):"
  echo "            runs made, host-invalid. not frozen (exit 7) is a step's own rule (prereg 6); stopped (2) is a refusal of the host"
  echo "            or the environment, unsound twice or a defect: no reading, the log's last error line says which. stopped by TERM: the"
  echo "            step ended on the TERM (130 or 143); a TERM the step did not end on adds a note to the step's own state"
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
# end of the log; its exit code is the last step's (128 + the signal's number for a stop that found no step running). The states:
# done 0, paused 4 (the budget), host unfit 5, not frozen 7 (a step's own rule, calibrate.py's StepRuleStop: T-115 H-1), stopped
# otherwise (2: a refusal of the host or the environment, a run unsound twice or a defect; 1, 3, 130 and others)
stage() {
  local start stamp mark code=0 line left cmd stopped out tar made invalid state note="" i n
  local -a lines
  trap 'on_stop TERM' TERM
  trap 'on_stop INT' INT
  start=$(date +%s)
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  mark=$(mktemp)
  echo "packet $PACKET stage, pid $$, $(date -u +%FT%TZ); sudo kill -TERM $$ stops it"
  [ "$PACKET" = R1 ] && echo "paired check: $PAIRED"
  [ -n "${PAIRED_DIR:-}" ] && echo "paired check's record: $PAIRED_DIR/paired.json, sha256 $(sha256sum "$PAIRED_DIR/paired.json" 2>/dev/null | cut -c1-64)"
  mapfile -t lines < <(steps "$PACKET")
  n=${#lines[@]}
  for (( i = 0; i < n; i++ )); do
    line=${lines[i]}
    [ -z "$STOP" ] || break
    left=$(budget_left "$start" "$(date +%s)") || { code=4; echo "the budget is used before: $line"; break; }
    cmd=${line//REMAINING/$left}
    echo "$(date -u +%FT%TZ) running: $cmd"
    set +e
    $cmd & STEP_PID=$!
    echo "the step's process: $STEP_PID (the packet stops with sudo kill -TERM $$, the stage)"
    [ -z "$STOP" ] || on_stop "$STOP"                       # a TERM that came before the step's pid was known
    step_wait "$STEP_PID"; code=$?
    set -e
    STEP_PID=""
    echo "$(date -u +%FT%TZ) exit $code"
    [ -z "$STOP" ] || { i=$(( i + 1 )); break; }
    [ "$code" = 0 ] || break
  done
  stopped=$STOP
  if [ -n "$stopped" ]; then
    for (( ; i < n; i++ )); do echo "$(date -u +%FT%TZ) stopped by $stopped: not started: ${lines[i]}"; done
  fi
  if [ -n "$stopped" ] && [ -z "$STOP_STEP" ]; then code=$(( 128 + $(kill -l "$stopped") )); fi
  out=$(outputs "$PACKET")
  tar="$LOGDIR/${PACKET}_${stamp}.tar.gz"
  tar --exclude=packets -czf "$tar" -C "$(dirname "$out")" "$(basename "$out")" 2>/dev/null || true
  sha256sum "$tar" > "${tar%.tar.gz}.sha256" || true
  made=$( { find "$out" -name DONE -newer "$mark" -not -path '*hostinvalid*' 2>/dev/null || true; } | wc -l)
  invalid=$( { find "$out" -maxdepth 6 -type d -name '*.hostinvalid*' -newer "$mark" 2>/dev/null || true; } | wc -l)
  case "$code" in 0) state=done;; 4) state=paused;; 5) state="host unfit";; 7) state="not frozen";; *) state=stopped;; esac
  if [ -n "$stopped" ]; then              # "stopped by TERM" only when the step ended on it (T-117 L-1): a TERM that came in the
    case "$code" in                       # executor's shielded teardown is ignored there, and the step may end otherwise
      130|143) state="stopped by $stopped";;
      *) note=" (a $stopped was received and forwarded; the step was not interrupted: send it again)";;
    esac
  fi
  echo "PACKET $PACKET $state (exit $code)$note: runs made $made, host-invalid $invalid; $(( ($(date +%s) - start) / 60 )) min; tar $tar, sha256 $(cut -c1-16 "${tar%.tar.gz}.sha256")"
  rm -f "$mark"
  return "$code"
}
# --- end of the stage's functions -------------------------------------------------------------------------------------------------------

if [ "$STAGE" = 0 ]; then
  if [ "$PACKET" = R1 ]; then             # P-1 first: a refusal is the user's decision, and costs no pre-check's minute (K20b)
    $PAIRED_GATE "$STARTED" || { echo "packet.sh: P-1's paired check does not let R1 start (prereg 5.3); nothing was started" >&2; exit 2; }
  fi
  $PRECHECK || { echo "packet.sh: a pre-check refused the packet; nothing was started" >&2; exit 3; }
  mkdir -p "$LOGDIR"
  STAMP=$(date -u +%Y%m%dT%H%M%SZ)
  LOG="$LOGDIR/${PACKET}_${STAMP}.log"
  setsid nohup bash "$SELF" "$PACKET" --stage --session "$SESSION" ${RECORD:+--record "$RECORD"} --campaign "$CAMPAIGN" \
    ${COMMIT:+--commit "$COMMIT"} ${MEDIANS:+--medians "$MEDIANS"} ${PAIRED_DIR:+--paired "$PAIRED_DIR"} > "$LOG" 2>&1 < /dev/null &
  STAGE_PID=$!
  for _ in $(seq 50); do                # the pid the stage says it has, in its log's first line (else setsid's, which is the same here)
    said=$(sed -n '1s/^packet .* stage, pid \([0-9][0-9]*\),.*/\1/p' "$LOG" 2>/dev/null || true)
    if [ -n "$said" ]; then STAGE_PID=$said; break; fi
    sleep 0.1
  done
  echo "packet $PACKET started (pid $STAGE_PID), detached; its log: $LOG"
  echo "stop it with sudo kill -TERM $STAGE_PID: the step's process gets the TERM and takes the testbed down, no further step starts,"
  echo "and the tar, its sha256 and the summary are still written; the same command resumes"
  exit 0
fi

# --- the detached stage ---------------------------------------------------------------------------------------------------------------
stage
