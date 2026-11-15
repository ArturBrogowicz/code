# bench/vm: the VM step helpers

Three shell scripts that wrapped every root step of the harm benchmark on the testbed VM: the
calibration steps (`calibrate.py origin`, `capacity`, `ladder`, `reference`) and the drift checks.
They are VM tooling. No module under `bench/` calls them; `tests/test_bench_vm_helpers.py` only
parses them and runs `vm_step.sh --print`.

| File | Lines | What it does |
|---|---|---|
| `vm_step.sh` | 40 | `vm_step.sh [--print] NAME -- COMMAND [ARG...]`: from the worktree root, takes a host snapshot (`s3_snapshot.sh`) and `free -m`, starts `vmstat -n 5`, runs COMMAND with its output teed to `$S/NAME_output.txt`, then takes `free -m`, a second snapshot and runs `s3_compare.sh`. Exits with COMMAND's exit code. Refuses a NAME whose output file exists (exit 9) and a malformed call (exit 64). `--print` prints the plan and runs nothing. |
| `s3_snapshot.sh` | 26 | `s3_snapshot.sh DIR`: writes a record of the host and the tree into DIR: time, uptime and load, `lsmod`, `ps`, network namespaces, links, TCP listeners, `/var/log/nginx`, `bench/__pycache__`, the git index's owner, HEAD, `git status --short`, `/run/nginx.pid` and `bench/executor.py`'s `leftovers()`. |
| `s3_compare.sh` | 17 | `s3_compare.sh BEFORE AFTER`: prints what differs between two snapshots (HEAD and status, namespaces, links, leftovers, nginx and gunicorn processes, modules, listeners, pid file, index owner, `__pycache__` owners, `/var/log/nginx`). |

## Use

    S=/var/tmp/<a directory for this step's records> bash <worktree>/bench/vm/vm_step.sh NAME -- COMMAND [ARG...]

- The worktree is the checkout the script lies in: `vm_step.sh` and `s3_snapshot.sh` take `WT` as
  the directory two levels above their own (`bench/vm/../..`), and `vm_step.sh` calls the
  snapshot and the comparison from its own directory. A packet runs the scripts of the worktree it
  measures, so no copy and no `sed` rewrite is needed. A worktree at a commit without `bench/vm/`
  cannot be measured this way.
- `S`, the directory for the step's records, comes from the environment. Its default is the old
  `/var/tmp/hg1c_scratch`.

## Hashes

| File | sha256 now | sha256 as first committed (450254f) and pinned by the packets |
|---|---|---|
| `vm_step.sh` | `e8f0f58b72d3f1a5e4d13d4518fc5516199fcc121f66d36ccdbc87981f0336c5` | `013aec6d7a5d8cb2ff38f528df56cf016f95ffba4eb8e2e9ff01e085eafae59a` |
| `s3_snapshot.sh` | `f7d0c49caaee4dd6d90cd7ab8b7146b77c679c3596c979f6d5725555b77056d6` | `35155c4d01493c0202c871627681b2db5d21e0e53cbd5b0c7ec06234560d9cb2` |
| `s3_compare.sh` | `23d922832d0475b273381f1b9ded826416d66a65aab018a6483b7d666e0750ae` (unchanged) | `23d922832d0475b273381f1b9ded826416d66a65aab018a6483b7d666e0750ae` |

A new packet pins the hashes of the first column. The second column is what every earlier packet
checked; `git show 450254f:bench/vm/<file>` gives those bytes.

## Provenance

Commit 450254f added the three files byte for byte as they lie in `/var/tmp/hg1c_scratch/` on
the VM, so its blobs have the hashes of the second column. Those are the hashes that every
approval packet of the thesis orchestrator checked with `sha256sum -c` before it ran anything (for
example lines 22-25 of `tasks/T-081/ap5b.sh` in the orchestrator's workspace,
`/home/artur/agent_workspace`). `docs/HG1C_DESIGN.md` names `vm_step.sh` by that path in its
planned steps. In those bytes `WT` was hard-coded to the user's worktree
`/home/artur/DDoS-mitigation/code/.claude/worktrees/audit-must-do-2-5` (`vm_step.sh` line 7,
`s3_snapshot.sh` line 4) and `S` to `/var/tmp/hg1c_scratch` (`vm_step.sh` line 8); the next
commit replaced both as described under "Use".

## What the packets executed

No packet ran the pinned bytes unchanged. Each packet checked the three hashes, wrote rewritten
copies into its own task directory `$H`, and ran the copies:

```
sed "s#^WT=.*#WT=$WT#" "$S/s3_snapshot.sh" > "$H/s3_snapshot_apN.sh"
sed -e "s#^WT=.*#WT=$WT#" -e "s#bash \"\$S/s3_snapshot.sh\"#bash \"$H/s3_snapshot_apN.sh\"#" "$S/vm_step.sh" > "$H/vm_step_apN.sh"
bash "$H/vm_step_apN.sh" NAME -- sudo -n env PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 ./venv/bin/python -B bench/calibrate.py ...
```

The executed copies differ from the pinned files (450254f) in exactly these lines (checked with
`diff` against every copy the packets left behind):

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
- `s3_snapshot.sh` runs `rm -rf "$B"` on the DIR it is given, then recreates it. Give it only a
  fresh path under `$S`.
- `/var/tmp` is cleaned by systemd-tmpfiles (`q /var/tmp 1777 root root 30d` in
  `/usr/lib/tmpfiles.d/tmp.conf`, `systemd-tmpfiles-clean.timer` active on the VM): records under
  the default `S` that nobody reads for 30 days are deleted. Copy what a result needs into
  `results/`.

## Helpers left out

Three more scripts lie beside these in `/var/tmp/hg1c_scratch/`. None is committed, because no
packet or step of the orchestrator's tasks ran them (a search of the workspace on 2026-11-13 finds
them only in reports and in a list of forbidden commands):

| File | sha256 | What it is |
|---|---|---|
| `s4_run.sh` | `64c38dd567f6f096a868d78ecfbc32b69c8db995edd47a791b3a73443b347c26` | `vm_step.sh` with S4's `gate_campaign.py run ... --dry-run` command written in (`vm_step.sh` line 5); S4 ran it on 2026-10-28, before the packets (`docs/HG1C_DESIGN.md`, "What S4 found") |
| `s1b.sh` | `3c12931ab8dace528b1d8a9367584cbd9a8f97545e9b0842038896307a837ea2` | S1b: three legit-only `executor.py clock-probe` runs with timer probes; needs a further helper, `leftovers.py` |
| `wait_quiet.sh` | `1884b2d9f260fe635e76167c8b5b42e916456ee9d5a2bfffd1b4a9e747417ca5` | waits until the 1-minute load average is below 0.3 in three readings 10 s apart |
