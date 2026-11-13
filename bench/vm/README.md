# bench/vm: the VM step helpers

Three shell scripts that wrapped every root step of the harm benchmark on the testbed VM: the
calibration steps (`calibrate.py origin`, `capacity`, `ladder`, `reference`) and the drift checks.
They are VM tooling. No unit test and no module under `bench/` calls them.

| File | Lines | sha256 | What it does |
|---|---|---|---|
| `vm_step.sh` | 38 | `013aec6d7a5d8cb2ff38f528df56cf016f95ffba4eb8e2e9ff01e085eafae59a` | `vm_step.sh [--print] NAME -- COMMAND [ARG...]`: from the worktree root, takes a host snapshot (`s3_snapshot.sh`) and `free -m`, starts `vmstat -n 5`, runs COMMAND with its output teed to `$S/NAME_output.txt`, then takes `free -m`, a second snapshot and runs `s3_compare.sh`. Exits with COMMAND's exit code. Refuses a NAME whose output file exists (exit 9). `--print` prints the plan and runs nothing. |
| `s3_snapshot.sh` | 25 | `35155c4d01493c0202c871627681b2db5d21e0e53cbd5b0c7ec06234560d9cb2` | `s3_snapshot.sh DIR`: writes a record of the host and the tree into DIR: time, uptime and load, `lsmod`, `ps`, network namespaces, links, TCP listeners, `/var/log/nginx`, `bench/__pycache__`, the git index's owner, HEAD, `git status --short`, `/run/nginx.pid` and `bench/executor.py`'s `leftovers()`. |
| `s3_compare.sh` | 17 | `23d922832d0475b273381f1b9ded826416d66a65aab018a6483b7d666e0750ae` | `s3_compare.sh BEFORE AFTER`: prints what differs between two snapshots (HEAD and status, namespaces, links, leftovers, nginx and gunicorn processes, modules, listeners, pid file, index owner, `__pycache__` owners, `/var/log/nginx`). |

## Provenance

The three files are committed byte for byte as they lie in `/var/tmp/hg1c_scratch/` on the VM, so
their blobs have the hashes above. Those are the hashes that every approval packet of the thesis
orchestrator checked with `sha256sum -c` before it ran anything (for example lines 22-25 of
`tasks/T-081/ap5b.sh` in the orchestrator's workspace, `/home/artur/agent_workspace`).
`docs/HG1C_DESIGN.md` names `vm_step.sh` by that path in its planned steps.

## What the packets executed

No packet ran these bytes unchanged. Each packet checked the three hashes, wrote rewritten copies
into its own task directory `$H`, and ran the copies:

```
sed "s#^WT=.*#WT=$WT#" "$S/s3_snapshot.sh" > "$H/s3_snapshot_apN.sh"
sed -e "s#^WT=.*#WT=$WT#" -e "s#bash \"\$S/s3_snapshot.sh\"#bash \"$H/s3_snapshot_apN.sh\"#" "$S/vm_step.sh" > "$H/vm_step_apN.sh"
bash "$H/vm_step_apN.sh" NAME -- sudo -n env PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 ./venv/bin/python -B bench/calibrate.py ...
```

The executed copies differ from the files here in exactly these lines (checked with `diff` against
every copy the packets left behind):

- `vm_step.sh` line 7: `WT=` the packet's worktree;
- `vm_step.sh` lines 25 and 36: `bash "$S/s3_snapshot.sh"` became `bash "<absolute path of the copy>"`;
- `s3_snapshot.sh` line 4: `WT=` the packet's worktree;
- `s3_compare.sh`: not copied; it ran unchanged from `$S`.

Line 8 of `vm_step.sh` (`S=/var/tmp/hg1c_scratch`) was never rewritten, so every step wrote its
records there.

| Packet script | Worktree (`WT` in the copies) | Copies |
|---|---|---|
| `T-021/ap1.sh` | `worktrees/ap1-hg2b-origin4` | `T-021/ap1/` |
| `T-036/ap2.sh` | `worktrees/ap2-hg2b-capacity` | `T-036/ap2/` |
| `T-036/ap2b.sh` | `worktrees/ap2b-hg2b-capacity` | `T-036/ap2b/` |
| `T-049/ap3.sh`, `T-049/ap3b.sh` | `worktrees/ap2b-hg2b-capacity` | `T-049/ap3/`, `T-049/ap3b/` |
| `T-077/ap4.sh` | `worktrees/ap4-drift` | `T-077/ap4/` |
| `T-081/ap5.sh`, `T-081/ap5b.sh` | `worktrees/ap4-drift` | `T-081/ap5/`, `T-081/ap5b/` |
| `T-091/ap7.sh` | `worktrees/ap4-drift` | `T-091/ap7/` |

Paths are relative to the orchestrator's workspace. The process lists in
`results/2026-11-11_harm-drift-check/steps/*/ps.txt` show the copies running.

## Read before running

- `vm_step.sh` runs COMMAND exactly as given, as the user who calls it, from the worktree root. It
  adds no `sudo` itself. Every packet gave it a command that starts with `sudo -n`, so those steps
  ran as root and changed the host as the command does (namespaces, nginx, XDP; see
  `docs/EVALUATION.md` and `docs/HG1C_DESIGN.md`).
- `s3_snapshot.sh` line 6 runs `rm -rf "$B"` on the DIR it is given, then recreates it. Give it only
  a fresh path under `$S`.
- `WT` is hard-coded to the user's worktree
  `/home/artur/DDoS-mitigation/code/.claude/worktrees/audit-must-do-2-5` (`vm_step.sh` line 7,
  `s3_snapshot.sh` line 4) and `S` to `/var/tmp/hg1c_scratch` (`vm_step.sh` line 8).
- `/var/tmp` is cleaned by systemd-tmpfiles (`q /var/tmp 1777 root root 30d` in
  `/usr/lib/tmpfiles.d/tmp.conf`, `systemd-tmpfiles-clean.timer` active on the VM): records under
  `S` that nobody reads for 30 days are deleted. Copy what a result needs into `results/`.

## Helpers left out

Three more scripts lie beside these in `/var/tmp/hg1c_scratch/`. None is committed, because no
packet or step of the orchestrator's tasks ran them (a search of the workspace on 2026-11-13 finds
them only in reports and in a list of forbidden commands):

| File | sha256 | What it is |
|---|---|---|
| `s4_run.sh` | `64c38dd567f6f096a868d78ecfbc32b69c8db995edd47a791b3a73443b347c26` | `vm_step.sh` with S4's `gate_campaign.py run ... --dry-run` command written in (`vm_step.sh` line 5); S4 ran it on 2026-10-28, before the packets (`docs/HG1C_DESIGN.md`, "What S4 found") |
| `s1b.sh` | `3c12931ab8dace528b1d8a9367584cbd9a8f97545e9b0842038896307a837ea2` | S1b: three legit-only `executor.py clock-probe` runs with timer probes; needs a further helper, `leftovers.py` |
| `wait_quiet.sh` | `1884b2d9f260fe635e76167c8b5b42e916456ee9d5a2bfffd1b4a9e747417ca5` | waits until the 1-minute load average is below 0.3 in three readings 10 s apart |
