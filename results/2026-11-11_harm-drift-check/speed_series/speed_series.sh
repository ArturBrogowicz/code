#!/bin/bash
# Offline speed series (T1, no root state, no network): every 300 s the origin's own self-measurement, alone, on CPU 0
# and on CPU 1, in the sandbox, against the frozen route costs (speed_probe.py). One line per probe.
# Writes only tasks/T-091/work/speed_series.txt. Ends by itself after 144 samples (12 h).
# Stop it before any VM step: pkill -f tasks/T-091/scripts/speed_series.sh
cd /home/artur/agent_workspace || exit 1
for i in $(seq 1 144); do
  for c in 0 1; do
    skills/sandboxed-offline-run/sbx.sh tasks/T-091 taskset -c "$c" /home/artur/DDoS-mitigation/.venv/bin/python -I -B \
      /home/artur/agent_workspace/tasks/T-091/scripts/speed_probe.py /home/artur/agent_workspace/worktrees/T-088-verify-main series 2>&1 | tail -n 1
  done >> tasks/T-091/work/speed_series.txt
  sleep 300
done
