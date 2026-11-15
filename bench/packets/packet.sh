#!/bin/bash
# A packet of the harm benchmark's re-calibration (docs/RECALIBRATION_2026-11_DESIGN.md 5.2, 5.3 and 6.2; K7): the pre-checks, then the
# speed hold and the step(s) detached from the terminal (setsid nohup) with the packet's time budget, a tar and the sha256 of the
# outputs, and a one-line summary at the end of the packet's log. The step's own runner starts the monitors (K4) and judges every run.
#
#   sudo bench/packets/packet.sh PACKET [--session DIR] [--record FILE] [--campaign DIR] [--commit SHA]
#   bench/packets/packet.sh PACKET --print [...]          # what it would do; runs nothing, needs no root
#
# PACKET: R1 (speed hold against the 2026-11-04 costs; origin; capacity), R2a, R2b, R2c (one family's ladder each), R3 (the
# reference), R4 (the confirmation, a later window), P2-1 (the smoke runs of HG4 at twice the new knee), P2-2 (the MVP campaign; it
# takes two or three packets). Stop it with `kill -INT` of the step's process (the log names it): the testbed is taken down and the
# same command resumes.
set -euo pipefail

SELF=$(realpath "$0")
PACKET=${1:-}
shift || true
SESSION=/var/tmp/ddos_campaigns/recal_2026-11
RECORD=""
CAMPAIGN=/var/tmp/ddos_campaigns/hg4_mvp_xdp_recal
COMMIT=""
PRINT=0
STAGE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --session) SESSION=$2; shift 2;;
    --record) RECORD=$2; shift 2;;
    --campaign) CAMPAIGN=$2; shift 2;;
    --commit) COMMIT=$2; shift 2;;
    --print) PRINT=1; shift;;
    --stage) STAGE=1; shift;;
    *) echo "packet.sh: unknown argument $1" >&2; exit 2;;
  esac
done

BUDGET_MIN=85                       # no run starts after 85 min, so the run in progress ends the packet within 90 (6.2)
PACKET_MIN=90
OLD_RECORD=bench/calibration/ddos-mitigation-2026-11-04.json
PY=./venv/bin/python
HG4=bench/scenarios/cheap_static_flood_hg4.json

# the steps of each packet, one command a line; REMAINING is the packet's budget left when the line starts
steps() {
  local hold_old="$PY bench/hostcheck.py speed-hold --calibration $OLD_RECORD --reference $OLD_RECORD --lo -0.05 --hi 0.12 --agree 0.05 --max-min 45"
  local hold_r1="$PY bench/hostcheck.py speed-hold --calibration bench/calibration/placeholder.json --reference $SESSION/origin/origin.json --lo -0.10 --hi 0.10 --max-min 30"
  local hold_rec="$PY bench/hostcheck.py speed-hold --calibration ${RECORD:-RECORD} --reference ${RECORD:-RECORD} --lo -0.10 --hi 0.10 --max-min 30"
  case "$1" in
    R1)  echo "$hold_old"
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
    R1) echo "speed hold against the 2026-11-04 costs; origin step; capacity (3 staged runs)";;
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

# the packet's log, tar and sha256: beside the campaign for P2-2 (a campaign directory holds nothing that is not the campaign's),
# in the step's output directory otherwise
case "$PACKET" in P2-2) LOGDIR=$CAMPAIGN.packets;; *) LOGDIR=$(outputs "$PACKET")/packets;; esac
PRECHECK="$PY bench/packets/prechecks.py --packet $PACKET --session $SESSION --minutes $PACKET_MIN${RECORD:+ --record $RECORD}${COMMIT:+ --commit $COMMIT}"

if [ "$PRINT" = 1 ]; then
  echo "== packet $PACKET: $(what "$PACKET") =="
  echo "session     $SESSION"
  echo "budget      $BUDGET_MIN min: no run starts after it (--stop-after the minutes left), so the packet ends within $PACKET_MIN min"
  echo "pre-checks  $PRECHECK"
  echo "            (clean tree at the pinned commit; kernel, MemTotal, CPU model and VirtualBox host version the session's, before its"
  echo "            first step the laptop's (D-096), all four reported; uptime 1800 s, chrony within H4, no apt, dpkg or daily timer due"
  echo "            within $PACKET_MIN + 10 min, no package job, no testbed left, no other process above 5 % of a CPU)"
  echo "detached    setsid nohup bash bench/packets/packet.sh $PACKET --stage ... > $LOGDIR/${PACKET}_<UTC>.log 2>&1 < /dev/null &"
  n=1
  while IFS= read -r line; do echo "step $n      $line"; n=$((n + 1)); done < <(steps "$PACKET")
  echo "after       tar -czf $LOGDIR/${PACKET}_<UTC>.tar.gz $(outputs "$PACKET"); sha256sum of it into ${PACKET}_<UTC>.sha256"
  echo "summary     one line at the end of the log: PACKET $PACKET <done|paused|host unfit|stopped> (exit N): runs made, host-invalid"
  exit 0
fi

cd "$(dirname "$SELF")/../.."
if [ "$(id -u)" != 0 ]; then
  echo "packet.sh: the steps need root (namespaces): sudo bench/packets/packet.sh $PACKET ..." >&2
  exit 2
fi

if [ "$STAGE" = 0 ]; then
  $PRECHECK || { echo "packet.sh: a pre-check refused the packet; nothing was started" >&2; exit 3; }
  mkdir -p "$LOGDIR"
  STAMP=$(date -u +%Y%m%dT%H%M%SZ)
  LOG="$LOGDIR/${PACKET}_${STAMP}.log"
  setsid nohup bash "$SELF" "$PACKET" --stage --session "$SESSION" ${RECORD:+--record "$RECORD"} --campaign "$CAMPAIGN" \
    ${COMMIT:+--commit "$COMMIT"} > "$LOG" 2>&1 < /dev/null &
  echo "packet $PACKET started (pid $!), detached; its log: $LOG"
  echo "stop it with kill -INT of the step's process named in the log; the same command resumes"
  exit 0
fi

# --- the detached stage ---------------------------------------------------------------------------------------------------------------
START=$(date +%s)
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
MARK=$(mktemp)
echo "packet $PACKET stage, pid $$, $(date -u +%FT%TZ)"
code=0
while IFS= read -r line; do
  left=$(( BUDGET_MIN - ( $(date +%s) - START ) / 60 ))
  [ "$left" -lt 1 ] && { code=4; echo "the budget is used before: $line"; break; }
  cmd=${line//REMAINING/$left}
  echo "$(date -u +%FT%TZ) running: $cmd"
  set +e; $cmd & pid=$!; echo "the step's process: $pid (kill -INT $pid stops it)"; wait $pid; code=$?; set -e
  echo "$(date -u +%FT%TZ) exit $code"
  [ "$code" = 0 ] || break
done < <(steps "$PACKET")
OUT=$(outputs "$PACKET")
TAR="$LOGDIR/${PACKET}_${STAMP}.tar.gz"
tar --exclude=packets -czf "$TAR" -C "$(dirname "$OUT")" "$(basename "$OUT")" 2>/dev/null || true
sha256sum "$TAR" > "${TAR%.tar.gz}.sha256" || true
made=$( { find "$OUT" -name DONE -newer "$MARK" -not -path '*hostinvalid*' 2>/dev/null || true; } | wc -l)
invalid=$( { find "$OUT" -maxdepth 6 -type d -name '*.hostinvalid*' -newer "$MARK" 2>/dev/null || true; } | wc -l)
case "$code" in 0) state=done;; 4) state=paused;; 5) state="host unfit";; *) state=stopped;; esac
echo "PACKET $PACKET $state (exit $code): runs made $made, host-invalid $invalid; $(( ($(date +%s) - START) / 60 )) min; tar $TAR, sha256 $(cut -c1-16 "${TAR%.tar.gz}.sha256")"
rm -f "$MARK"
exit "$code"
