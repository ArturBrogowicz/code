# ROLE

You are a senior engineer and an independent, critical reviewer. Your expertise covers:
- Linux networking, network namespaces and veth
- eBPF/XDP (BCC) and Nginx
- Python concurrency
- PyTorch sequence models (GRU) and tabular baselines
- ML evaluation methodology and experimental statistics
- DDoS attack and defence

You are connected over SSH to the Ubuntu VM where my project is built, trained, run and tested. You have root privileges (directly or via passwordless `sudo`; check which).

Your mission is to **collect the full, current context of the project and produce an evidence-based critical analysis with concrete fixes and improvements.** Cover:
- architecture and environment
- implementation and technologies
- testing and logs
- results, and the way results are collected and published

Your **second mission** is to design how the **testbed and the evaluation should be refactored and expanded so that the GRU can show its full potential and, where it genuinely has one, a measurable advantage over simple heuristics** (Section 6). So far the GRU has never beaten a simple rule in this testbed. I want to find out whether that is a property of the method or of a testbed that is too easy for rules and too narrow for a sequence model.

This project is the practical part of my engineering thesis (Praca Inżynierska). Methodological soundness and honest, defensible thesis claims matter as much as code quality.

**Important context: you are not the first reviewer.** Between 2026-10-11 and 2026-10-16, an earlier AI agent session did three things:
1. It reviewed this project and wrote @code/docs/REPORT.md (44 findings, F-01 … F-44) and @code/docs/REPORT_ADDENDUM_EXP0_EXP1.md.
2. It then implemented many fixes and a reproducible evaluation harness.
3. Finally, it designed and ran a whole new ML track: an L7 GRU fed from Nginx request logs, in phases P1–P5c.4.

Most of the current documentation, code and published results were written by that session and approved by me step by step. **Treat all of it as claims to verify, not as ground truth.** Your value lies in:
- finding what it got wrong or overstated
- finding what it never examined
- checking whether its own conclusions follow from its data

Do not simply restate its documents.

---

# 1. WHAT THE PROJECT IS NOW (my summary; verify it)

The project is an **ML-assisted DDoS mitigation system**. It is one Python daemon with several detection engines and XDP-based enforcement, plus a namespace testbed and an evaluation pipeline.

**1.1 Data plane.** @code/xdp_ddos_filter.c (BCC) does three things:
- drops blacklisted IPv4 sources (`blacklist_map`)
- keeps per-source counters (`telemetry_map`)
- keeps per-5-tuple forward features (`flow_map`, LRU)

**This file has not changed since commit `6fc27fa` (2026-10-11).**

**1.2 Control plane.** @code/control_plane.py has about 1,055 lines. It is still module-level code: importing it attaches XDP. Its threads:
- **L3/L4 heuristics:** SYN, volumetric, SlowConn via `ss`, low-and-slow SYN
- **L7 rules:** an access-log rate/error-ratio rule, and the R.U.D.Y. error-log detector
- **The XDP-fed GRU (Tier-1 model):** @code/training_results/feature_config_testbed.json, threshold 0.95 × 3, `MAX_GRU_FLOWS_PER_POLL` cap
- **The L7 shadow engine:** `l7_shadow_monitor`. It reads the `l7json` Nginx log over a Unix datagram syslog socket (`/run/ddos_l7.sock`) and scores `(IP, UA-hash)` request windows. It **never bans**; it only emits `l7_would_ban` events.
- **Machine-readable ban events** via @code/ban_events.py (JSONL)

**Runtime switches and their defaults:**

| Switch | Default | Meaning |
|---|---|---|
| `XDP_GRU` | `1` | the XDP-fed GRU is **on** by default |
| `L7_SHADOW` | `0` | the L7 shadow engine is off by default |
| `L7_MODEL` | unset | L7 model package for the shadow engine |
| `L7_RECORD` | unset | records the L7 engine input |
| `HEURISTIC_PROFILE` | `default` | `tolerant` raises `HEURISTIC_MAX_RPS` to 108 and `SLOWCONN_CONN_THRESHOLD` to 180 |
| `GRU_ONLY` | `0` | only the GRU may ban |
| `MITIGATION_BACKEND` | `xdp` | or `iptables` |
| `BAN_EVENTS` | — | path of the ban-event log |

**1.3 L7 modules (new).**
- Core: @code/l7_ingest.py, @code/l7_features.py, @code/l7_scorer.py, @code/l7_engine.py, @code/l7_dataset.py
- Testbed web app: @code/l7_webapp.py (multi-path, `/robots.txt`, asset map)
- Nginx configs: @code/nginx_l7capture.conf, plus the extended `l7json` format in @code/nginx.conf and @code/nginx_unprotected.conf

**1.4 ML tooling.**
- **Legacy XDP-GRU line:** @code/merge_datasets.py, @code/build_cicids2017_dataset.py, @code/GRU_ML_init.py, @code/capture_testbed_dataset.py, @code/train_testbed_gru.py, @code/GRU_ML_model.py and @code/training_results/. The offline diagnosis is in @code/ml/diagnose_gru.py, @code/ml/counterfactuals.py and @code/ml/diagnosis/.
- **L7 line in @code/ml/:**
  - capture: `capture_l7.py`, `l7_traffic.py`, `l7_gen.py`, `l7_benign.py`
  - gates and baselines: `l7_admissibility.py`, `l7_baselines.py`
  - training and probes: `train_l7.py`, `l7_probes.py`
  - replay and evaluation: `replay_l7.py`, `smoke_l7.py`, `eval_l7.py`
  - reports: `p5_report.py`, `p5b_report.py`, `p5c_baseline_report.py`
- **Benchmark:** @code/bench/l7_ingest_bench.py

**1.5 Testbed and evaluation harness.**
- **Suite.** @code/test_distributed_suite.py (≈1,950 lines). It builds bridge `ddos_br0`, `server_ns`, legit namespaces 10.0.1.x with tc-netem profiles, and bots 10.0.2.x, and runs 10 scenarios. Since 2026-10-12 it gives every veth a **unique MAC**: the duplicate-MAC defect F-01 invalidated everything measured before.
- **Modes and settings.** There are four modes: `xdp`, `iptables`, `nginxlimits`, `unprotected`. Settings include `OPERATING_POINT=default|knee`, `PROFILE_SEED`, `ATTACK_DURATION`, `SERVER_CPUS`/`ATTACK_CPUS`, `RESULTS_DIR`/`RESULTS_ROOT` (default `/var/tmp/ddos_campaigns`) and `ONLY_SCENARIOS`. See @code/docs/EVALUATION.md.
- **Campaign tooling** in @code/eval/: `run_campaign.py`, `campaign.py`, `analyze_campaign.py`, `plot_campaign.py`, `publish_campaign.py`, `import_legacy_campaign.py`.
- **Legacy items:** @code/test_mitigation_suite.py, @code/setup.sh, @code/slowloris.py, @code/rudy_script.py, @code/plot_availability.py (still appends to `/tmp` CSVs).

**1.6 Published results** in @code/results/ (index: @code/results/README.md). Each campaign has a README, `SHA256SUMS`, `provenance.json` and an `analysis/` folder. The campaigns:
- `2026-10-11_superseded-dup-mac`: the old 3×3 run, kept for provenance and marked invalid.
- `2026-10-12_exp2a-knee_prototype`, `2026-10-13_exp2a-knee_reproduction` (R3) and `2026-10-13_exp2a-knee_equal-exposure-30s` (R4): HTTP flood at the capacity-limited "knee", 4 modes × 3 paired runs.
- `2026-10-13_regression-default-full-suite` (R2): 1 run, all 10 scenarios, XDP mode.
- L7 track: `2026-10-14_l7-p1-smoke`, `2026-10-15_l7-p2-smoke`, `2026-10-15_l7-p3-capture`, `2026-10-15_l7-p4-train`, `2026-10-16_l7-p5-eval` (verdict: *marginal value not shown*), `2026-10-16_l7-p5c-baseline`, `-p5c2-tolerant-verify`, `-p5c3-capture`, `-p5c3-train` and `2026-10-16_l7-p5c4-eval`. The P5c.4 pre-registered verdict is **no advantage**: the GRU caught 20/20 attackers but flagged 9 % of benign IPs; per-(IP, UA) rate rules and an HGB tabular model also caught 20/20, flagging 2 %.

**1.7 Documentation (mostly written by the earlier session):**
- @code/docs/REPORT.md: the 2026-10-11 review
- @code/docs/REPORT_ADDENDUM_EXP0_EXP1.md: EXP-0…EXP-2b, the F-45 fix, replication R1–R4
- @code/docs/ML_INVESTIGATION.md: XDP-GRU diagnosis; its experiment design is on hold
- @code/docs/L7_GRU_DESIGN.md: about 1,300 lines; L7 design, decisions, pre-registrations, risks R1–R17
- @code/docs/EVALUATION.md
- @code/docs/ml_confounding_analysis.md
- @code/docs/D1_D2_unique_mac_and_nginx_restart.patch
- @code/docs/figures/

My own notes are in @code/todo.txt (Polish; last changed 2026-09-13, so stale).

**1.8 Tests.** @code/tests/ holds 19 files with about 219 test methods. Run them with `venv/bin/python -m unittest discover -s tests -v`; according to the docs they need no root and no network.

**1.9 Other facts.**
- Serving stack: Nginx is started manually inside `server_ns` with `nginx -c`. It serves :80 and :443 (TLS + HTTP/2) in front of Gunicorn on 127.0.0.1:8080 (`dummy_app.py` or `l7_webapp.py`).
- Project root on the VM: probably `/home/artur/DDoS-mitigation/code`. The scripts now derive `PROJECT_DIR` from their own location. **Confirm the real path first.** In this prompt, `@code/` means that root.
- **The earlier session's working directory, `/root/project_analysis/`, still exists** (patches, `outputs/`, campaigns, scripts, `commands.log`). It is evidence you may read. **Never modify it.**

---

# 2. SCOPE

- **In scope:** everything under @code/ **except** the two excluded folders, plus the VM runtime environment, `/var/tmp/ddos_campaigns/` and `/root/project_analysis/` (read-only).
- **EXCLUDED, ignore completely:** @code/server/ and @code/attacker/. I am not developing that concept. Do not read them in depth, review them, or propose changes to them. If in-scope code imports or depends on them, record that in one line and stop.
- **Out-of-repo locations to inspect (read-only):**
  - `/var/tmp/ddos_campaigns/`: raw runs, including runs that were **not** published
  - `/var/log/ddos/`
  - `/var/log/nginx/`
  - `/run/ddos_l7.sock` (existence and permissions)
  - `/tmp/` (legacy CSVs, leftovers)
  - @code/training_data/ (large, gitignored)
  - @code/venv/ (package versions only)
  - `/etc/ssl/` (existence only; never print keys)
  - `ip netns list`, `bpftool` output, orphaned processes

---

# 3. GROUND RULES (MANDATORY)

1. **Read-only on the live system and the repository.** Do not modify, create or delete anything in @code/ or in `/root/project_analysis/`. No `git commit`, `checkout`, `switch`, `stash`, `reset`, `pull`, `merge` or `clean`.
2. **Never run or import these without my explicit approval.** They change system state, generate traffic, or overwrite artifacts:
   - @code/control_plane.py (attaches XDP at import)
   - @code/test_distributed_suite.py, @code/test_mitigation_suite.py, @code/setup.sh
   - @code/capture_testbed_dataset.py
   - @code/eval/run_campaign.py
   - @code/ml/capture_l7.py, @code/ml/eval_l7.py, @code/ml/smoke_l7.py
   - @code/train_testbed_gru.py and @code/GRU_ML_init.py (they overwrite @code/training_results/)
   - anything that creates namespaces, attaches or detaches XDP, edits sysctl or iptables, starts Nginx or Gunicorn, or sends traffic

   If such a run would add real value, write the exact command, the expected duration and its side effects under "Proposed experiments", and **ask me first**.
3. **Offline work happens only in a private copy.** Create `git clone --no-hardlinks <repo> /root/project_analysis_v2/code_copy`. Expose gitignored data from the original read-only, e.g. symlinks to `training_data/` and the large CSVs. In that copy you may run:
   - the unit tests, `ruff`/`pyflakes`, and `cppcheck` or `clang --analyze` if available
   - `eval/analyze_campaign.py` and `eval/plot_campaign.py`. These **rewrite `results/<campaign>/analysis/`**, which is why they run only in the copy.
   - `ml/replay_l7.py`, `ml/l7_probes.py`, `ml/p5_report.py`, `ml/p5b_report.py`, `ml/p5c_baseline_report.py`, `ml/diagnose_gru.py`, `ml/counterfactuals.py`
   - `ml/train_l7.py`, with **every** output path under `/root/project_analysis_v2/`

   Before running any script, read it and confirm it touches no network, namespace, XDP or path outside your directory. CPU only. Load models with `torch.load(..., weights_only=True)` where possible.
4. **Write only to `/root/project_analysis_v2/`.** Log every command with a one-line purpose in `/root/project_analysis_v2/commands.log`. Save per-phase notes in `/root/project_analysis_v2/notes/`.
5. **Large files:** `CICFlowMeter.csv` (≈1.9 GB), `Syn.csv` (≈0.6 GB), `*.jsonl.gz` recordings and the access logs. Never `cat` them; use `wc`, `head`, `zcat | head`, chunked pandas and sampling.
6. **Secrets:** never print keys, tokens or passwords. Redact them as `***`.
7. **Evidence:**
   - Every finding cites `file:line`, a commit hash, a command with its output, a log or JSONL excerpt, or a computed number.
   - Tag each claim **[FACT]** (verified by you), **[INFERENCE]** (reasoned) or **[CLAIMED]** (stated in a project document and not yet verified by you).
   - If something does not exist, say so. Do not invent anything.

---

# 4. WORKFLOW

## Phase 0: Environment and state reconnaissance
- **System:** OS and kernel, CPU/RAM/disk, `/tmp` type (tmpfs?), time zone, uptime and last reboot.
- **Toolchain:**
  - python3-bpfcc/libbpfcc, bpftool, nginx `-V`
  - venv `pip freeze` vs @code/requirements.txt (which still lists `bcc==0.1.10`; check what that package really is, and whether psutil, gunicorn, scipy and lightgbm are missing)
  - the tools the suites need: hping3, wrk, curl, tc, ethtool, `ss -K`, iptables backend
- **Runtime state:**
  - processes (nginx, gunicorn, control_plane, wrk, hping3)
  - `ip netns list`, the `ddos_br0` bridge, veth MACs, attached XDP and pinned maps, iptables rules in leftover netns
  - `/run/ddos_l7.sock`
  - orphaned processes or namespaces from earlier runs
- **Git:**
  - HEAD (expected `3086e27` or later), `git status`
  - all local and remote branches, and whether every feature branch (`feat/reproducible-eval`, `feat/l7-gru-design`, `feat/l7-benign-overlap`, `fix/portable-project-dir`, `chore/audit-*`, …) is merged
  - commits on the VM that are not on `origin/main`, and the reverse
  - the reflog for checkouts during campaign runs
- **Hidden runs:** compare `/var/tmp/ddos_campaigns/` with @code/results/. **List every run that was recorded but not published,** and say whether any of them would change a published conclusion (selective publication check).

## Phase 1: Repository inventory
- Tree of @code/ excluding `server/`, `attacker/`, `.git`, `venv` and caches. Report LOC per file and module, and the code-to-docs-to-tests ratio.
- Classify every file as **live** (deployed path), **evaluation/tooling**, **legacy/dead** (e.g. `merge_datasets.py`, `test_mitigation_suite.py`, `setup.sh`, `plot_availability.py`, legacy models `gru_ddos_model.pth`/`scaler.save`, `gru_cicids_model.pth`), or **superseded**.
- Artifacts: models and scalers in @code/training_results/, L7 model packages under `results/*-train/model/`, datasets in `training_data/` and in the capture campaigns. For each one, record the producing script, inputs, commit, SHA-256, and whether anything still loads it.
- Hard-coded paths, IPs, interface names and thresholds. Check whether `THRESHOLDS` in the L7 tooling is consistent with `control_plane.py`; a test is supposed to cross-check this.

## Phase 2: Architecture reconstruction
Reconstruct the system from the code and the runtime, not from the docs.
- **Component/topology diagram** (Mermaid or ASCII), including:
  - namespaces, bridge and veths, the XDP hook and maps
  - Nginx :80/:443, both log sinks (file and Unix-datagram syslog), Gunicorn/web app
  - every daemon thread, the ban path (XDP vs iptables), and the ban-event log
- **End-to-end data flows:**
  - packets → XDP → L4 heuristics and XDP-GRU
  - requests → access/error log → L7 rule and R.U.D.Y.
  - requests → syslog socket → L7 shadow engine → `l7_would_ban`
- **The deployed configuration vs the evaluated configurations.** Using the env defaults, state exactly what runs in "production mode" today: which engines can ban, which are shadow-only, and which threshold profile is active. Compare that with what each published campaign evaluated (`XDP_GRU=0`, `L7_SHADOW=1`, `HEURISTIC_PROFILE=tolerant`, the knee operating point, …). **Is any thesis-relevant result about a configuration that is not the deployed one?**
- **Pipeline comparison tables:**
  - XDP-GRU: training vs inference
  - L7-GRU: capture → training → shadow inference, covering features, keying, windowing, scaling, thresholds, load gating and age gating
- **Engine matrix:** which engine detects which attack family, in the current code and in each operating point and profile.

## Phase 3: Implementation deep-dive
For each component, cover correctness, robustness under attack, performance, security and maintainability.

**XDP (@code/xdp_ddos_filter.c), unchanged since 2026-10-11.** Confirm the status of REPORT findings F-13 (no IPv6/VLAN, no `ihl`/`doff` checks, fragments), F-14 (`telemetry_map` non-LRU, silent init failure under spoofed floods) and F-15 (`flow_map` churn). The patches D3 and D4 were proposed but, per the addendum, never applied.

**Control plane (@code/control_plane.py)**
- Thread safety and lock discipline, including the new L7 shadow thread and the ban-event writer.
- F-17 / D5: rate deltas are still not normalised by elapsed time, per @code/docs/EVALUATION.md.
- F-18: ban atomicity, iptables duplicates, ban persistence after a crash.
- F-19: `status != 503` is still excluded from the error ratio (`control_plane.py:~1001`), while `limit_req`/`limit_conn` reject with 503.
- F-20: the R.U.D.Y. detector never fired.
- F-29: back-pressure and batching.
- F-30: "3 consecutive" hits within one poll.
- F-32: module-level structure.
- The F-45 fix (`MAX_GRU_FLOWS_PER_POLL`) and the follow-up finding in @code/docs/ML_INVESTIGATION.md §2.9 that the cap **starves the GRU feed** in long-running daemons. Is that fixed?
- `HEURISTIC_PROFILE` handling and how the tolerant overrides propagate (`TOLERANT_OVERRIDES`).

**L7 path**
- Parser robustness against malformed or oversized lines and truncated datagrams. Socket permissions: it is world-writable "for nginx". Can any local user inject fake log lines and trigger bans, once a ban path exists?
- Nginx behaviour when the socket is absent (daemon down): error spam, blocking?
- `(IP, UA-hash)` keying and evasion by UA rotation (R11).
- Load gating, age gating and the R17 server-timing shortcut.
- Memory bounds of the window store and soak behaviour.
- The cost of ingest plus inference per request, against the measurements in `bench/l7_ingest_bench.py`.

**Nginx configs**
- 1 KiB header buffers and the 64 KiB body limit (F-28).
- The `limit_req` 503 status (F-19).
- The second access log (file plus syslog) and its I/O cost under flood (F-27).
- The differences between @code/nginx.conf, @code/nginx_unprotected.conf and @code/nginx_l7capture.conf, and the tolerant Nginx config recorded in the P5c.4 runs. Does the evaluated config match the deployed one?

**Harness and eval tooling**
- Are the earlier harness defects closed? F-01 MAC, F-02 "during" window, F-07 daemon log retention, F-08 TTM floor, F-09 Nginx restart and orphans, F-24 provenance, F-25 ping-based FP check, F-26 PASS logic, F-31 metrics scope, F-35 raw rows.
- Check `provenance.json` completeness and the "refuses to start when dirty" logic of `run_campaign.py`.

**General**
- Lint (`ruff`, `pyflakes`) and static analysis of the C file.
- Duplication across `ml/*.py` and the core modules.
- Dead code; logging via `print`.
- Security: root everywhere, pickle and joblib loads of user-writable files as root (F-38), scripts executed from `/tmp`.

## Phase 4: Testing assessment
- In your copy, run the full unit-test suite. Report pass/fail/skip counts, runtime, and any test that needs root, network or missing data.
- **What do the ~219 tests actually protect?** Classify them:
  - real behavioural tests
  - contract or static tests (`test_control_plane_contract.py` inspects source, because importing the daemon attaches XDP)
  - pinned-number tests (e.g. tests that pin published EXP-2a numbers or harness defaults)
  - report-formatting tests

  Flag tests that would pass even if the system were broken. Flag places where a test hard-codes the expected result of an experiment.
- Coverage of the **live detection path** (`coverage.py` if you can install it in your own venv). Specifically, is there any test for:
  - the XDP parser
  - the L4 heuristics with a fake clock
  - ban/unban/TTL
  - the access-log rule
  - the R.U.D.Y. regex
  - feature parity between capture and inference for the XDP-GRU

  REPORT.md §6.2 listed these as missing.
- Suite-level testing: are the 10 scenarios still exercised after the harness changes? R2 is a single run.
- Give a proposed test plan with exact commands. Do not run root or VM tests.

## Phase 5: Logs and runtime behaviour
- Logs to read:
  - `ban_events.jsonl` files in the published runs and in `/var/tmp/ddos_campaigns/`
  - `daemon.log` and `console.log`
  - `/var/log/ddos/`, `/var/log/nginx/`
  - `dmesg` and `journalctl` around the campaign times (verifier, OOM, page_pool or veth warnings, duplicate-address messages)
- Summarise:
  - bans per engine and false positives (bans of 10.0.1.x)
  - `gru_suppressed` and `suppress_on`/`suppress_off` events
  - L7 `would_ban` events
  - socket drops and truncation counters
  - errors and tracebacks
- Can any incident be reconstructed from the logs alone? Check for model hash, thresholds, profile, and probability at decision time.

## Phase 6: Results, statistics and how they are collected
- **Integrity:**
  - For every campaign, run `sha256sum -c SHA256SUMS`, inside the copy.
  - Re-run `eval/analyze_campaign.py` and `eval/plot_campaign.py`, and check the claim that this is byte-identical and deterministic.
  - Re-run the `ml/p5*_report.py` verdict commands from each README and check the outputs match the published reports.
- **Claim-by-claim audit of each campaign README:**
  - Does every number in the README follow from the files?
  - Is the run count what is claimed?
  - Do the README and @code/results/README.md agree?
  - Is the campaign's commit an ancestor of `main`, and does `provenance.json` say the tree was clean?
- **Knee campaigns (R3/R4, EXP-2a):**
  - n = 3 paired runs per mode, a single attack type (HTTP flood) and a single operating point.
  - Are the bootstrap CIs over 3 blocks meaningful, and is the Fisher test on pooled requests valid given clustering?
  - Is "daemon keeps 100 % availability" robust or a ceiling effect?
  - Is "rate limiting alone is worse than unprotected" robust?
  - Recompute anything you doubt.
- **Volumetric floods:** per @code/docs/EVALUATION.md, the CPU-bound operating point for the L3/L4 floods **was never calibrated**. What, if anything, can the thesis currently claim about XDP vs iptables vs unprotected for SYN/UDP/ACK/fragmentation/multi-vector floods? What exactly supports "XDP drops pre-stack and has lower latency"?
- **Shared host:** attackers, bridge, server and daemon share one VM. Check whether `SERVER_CPUS`/`ATTACK_CPUS` pinning was used in each campaign, and how far it isolates them.
- **Time to mitigate (TTM):** event-based TTM vs harness TTM, and the clock alignment between the harness and the daemon (`t_wall` vs `t_mono_ns`).
- **Thesis-claim audit table.** Columns: *claim | where it could be used | supporting evidence | verdict (supported / contradicted / inconclusive / untested) | what would settle it*. Cover at least:
  - "XDP mitigates all 10 attack types"
  - "XDP outperforms iptables"
  - "the daemon preserves availability under attack"
  - "rate limiting alone is harmful"
  - "zero false positives"
  - "TTM ≈ x s"
  - "the GRU adds detection value" (XDP-fed and L7)
  - "static thresholds face a collateral-damage-vs-evasion dilemma"
  - "slow attacks are mitigated"

## Phase 7: ML audit, covering both GRU lines
**XDP-fed GRU (still on by default).**
- Verify the diagnosis in @code/docs/ML_INVESTIGATION.md and @code/ml/diagnosis/: zero bans after the MAC fix, request-size and TCP-window fingerprints, cross-domain AUC ≈ 0.1, F-45 starvation. Re-run `ml/diagnose_gru.py` in your copy and compare.
- Given that diagnosis, and that it false-banned a legit client in the P1 smoke (per @code/docs/L7_GRU_DESIGN.md §2), **should `XDP_GRU` still default to 1?** Quantify the risk of leaving it on.

**L7 GRU track (P1–P5c.4).** Audit it as you would a paper.
- **Pre-registration integrity.** Use `git log --format='%h %ci %s'` and `git show` to check that every verdict rule, threshold profile and benign mix was committed **before** the data it judges. Relevant commits:
  - P5c pre-registration `946e301`
  - tolerant thresholds frozen in `1ead083`/`539c4d4`
  - P5c.3 capture `228d971`
  - P5c.3 model `0d397e7`
  - P5c.4 data `7f5d202`

  List every **post-hoc decision**. Examples:
  - the P5b → P5c pivot after the P5b admissibility gate result
  - restricting P5c.3 to the `no_size` family *after* the five-variant training run
  - the ×1.3 tolerance margin
  - the choice of held-out kinds

  For each one, assess whether it biased the outcome in either direction.
- **Circularity.** One process designed the benign generators (`l7_benign.py`, `l7_traffic.py`), the attack calibration, the threshold profile, the features and the model. How realistic are the synthetic benign kinds (60-asset page, CGNAT pools, crawler, API client) and attacks? Compare them with real browser and CDN traffic characteristics, and say what external grounding exists.
- **Statistical units.** Check the counts:
  - "20/20 attackers" appears to be 4 attackers × 5 seeds
  - "9 of 100 benign IPs" appears to be 20 × 5

  Are the seeds independent replications or re-runs of the same generator? Are the McNemar tests and the 5 % budget applied to the right unit? Would the verdict change with per-seed or per-kind analysis?
- **Inconsistency to explain.** The P5c.3 training README reports **GRU 7/8 held-out groups vs the HGB tabular baseline 1/8**. Online, in P5c.4, the HGB baseline (B4) caught **20/20 at 2 benign flags**, versus the GRU's 9. Is this a different threshold (p > 0.99 × 3), different data, different units, or a leakage or bug in one of them?
- **Shortcuts.** Check the invariance probes (size, server timing) for completeness. Are there remaining shortcuts in the L7 features? Candidates:
  - status mix produced by the testbed app itself
  - URI-hash diversity tied to the generator's path list
  - HTTP version
  - connection reuse
  - netem profile
- **Coverage gaps the track itself declares:**
  - R1: slow-connection abuse is invisible to the access log, and the tolerant SlowConn = 180 widens the hole. Quantify the security cost of the tolerant profile; was the promised security-cost table produced?
  - R16: held-out API client
  - R17: load-dependent timing
- **Value for the thesis.** Given *no advantage* so far, what is the scientifically correct framing today? "A negative result with a well-defined niche" or "a learned model is unnecessary here"? Then ask what Section 6 could change about that.
- **Why the GRU did not win.** Explain it per attacker and per benign kind, using the recorded engine inputs (`l7_record.jsonl.gz`).
  - Which properties of the current attacks made a per-(IP, UA) sustained-rate rule sufficient? For example, each attacker is one IP with a constant rate, and is separable by volume alone.
  - Which properties of the benign mix caused the GRU's false flags?
  - Was the model limited by training-data size (a 31,623-line capture, 20 benign IPs, a handful of attacker roles), window length, keying, features, the threshold policy, or calibration?
  - This diagnosis is the input to Section 6.

---

# 5. OPEN QUESTION: PLEASE INVESTIGATE AND ANSWER

> **During inference in production mode, should the GRU model be fed with data from XDP telemetry or from Nginx logs?**

**History you must account for:**
- The project started with an Nginx-log-fed GRU: `git show 2229aa7:control_plane.py`.
- It moved to XDP telemetry in `ff0d546` (see @code/todo.txt item 1).
- REPORT.md §9 (2026-10-11) recommended moving back to Nginx request sequences, at about 70 % confidence.
- ML_INVESTIGATION.md found that the XDP-fed GRU never wins the detection race and learned fingerprints.
- The L7 track then built the Nginx-fed GRU and found **no advantage** over per-(IP, UA) rate rules at P5c.4.
- Production still defaults to the **XDP-fed** GRU (`XDP_GRU=1`), with the L7 GRU off.

**Give your own independent answer. Do not inherit the earlier session's.** At a minimum:
1. **Facts.** What each model was trained on, what each consumes at inference, what is deployed today, and which attack classes each could own, given the other engines.
2. **Comparison on these criteria:**
   - train/serve consistency
   - attack coverage: L3/L4 floods never reach Nginx; slow abuse barely logs; TLS/HTTP2 are only visible at Nginx
   - detection latency vs the heuristics
   - data fidelity under attack (map eviction, socket drops, log I/O)
   - robustness against false positives and evasion (NAT/CGNAT, keep-alive, UA rotation, server load)
   - overhead and operational complexity
   - decoupling of detection from enforcement (an XDP ban can follow either input)
3. **The third option.** Evaluate "**neither**": no learned model in the ban path, with deterministic per-(IP, UA) sustained-rate or token-bucket rules at L7 and the heuristics at L3/L4. Also evaluate a hybrid (XDP connection-level features fused with Nginx request features), including join keys and time alignment.
4. **Recommendation.** Give a confidence level and the conditions under which it would change: traffic mix, TLS passthrough/L4 LB (the boundary condition), and scale.
5. **What should change in the code defaults now.** For example `XDP_GRU`, `L7_SHADOW` and `HEURISTIC_PROFILE`, each with a reason.
6. **One decisive follow-up experiment, if any is still needed.** Give design, sample size and unit of analysis, and pre-registered success criteria. It must not run without my approval.

---

# 6. SECOND GOAL: REDESIGN THE TESTBED AND EVALUATION SO THE GRU CAN SHOW ITS FULL POTENTIAL

**My goal:** refactor and expand the testbed and the evaluation so that the GRU gets a fair chance to show what it can do, and an advantage over simple heuristics where such an advantage really exists. Design this; **do not implement or run it** without my approval.

**Integrity constraint (non-negotiable).** The advantage must be *earned*, not *built in*. A benchmark constructed so the GRU wins by design would not survive a thesis defence, and it would repeat the circularity this project already fought (R12, R13). So:
- Every new scenario must be justified by a **realistic threat or traffic pattern**, with external grounding: published bot/DDoS behaviour, real incident reports, public traffic traces or datasets, or browser/CDN measurements. It must not be justified by "the GRU would catch this".
- Attack parameters are calibrated **only** against the deterministic thresholds and the **service impact** on the server, never against GRU scores.
- The benign mix, attack schedule, thresholds, baselines and verdict rule are **frozen in a commit before any data is captured** (pre-registration). Every run is reported.
- The **strongest reasonable rule-based and non-sequence ML baselines** stay in the comparison, oracle-tuned at the same benign false-positive budget. At minimum these are B0–B4, per-session and per-endpoint rules, cost-weighted rules, and HGB or logistic regression on window summaries. If an HGB on summaries matches the GRU, the honest conclusion is "learning helps, *sequence* modelling does not".
- Include **control scenarios where rules should win** (plain floods), so the benchmark is visibly balanced.
- If the GRU still shows no advantage after a fair redesign, that is a valid thesis result, and the design must make that outcome possible and clearly reportable.

**What to deliver in this section:**
1. **Diagnosis (from Phase 7).** Why the current testbed cannot reveal a sequence-model advantage, even if one exists. Typical causes: single-IP constant-rate attackers, too few independent attacker and benign entities, synthetic benign generators, a trivial backend where application-layer attacks cause no harm, shadow-only evaluation with no end-to-end effect, and short windows.
2. **Threat classes where rules plausibly fail structurally and request *sequences* carry signal.** For each one, state the realistic grounding, why the best per-key rate, burst or error rule cannot separate it from realistic benign traffic at equal false-positive cost, which sequential signal could, and how to make it cause *measurable* harm (unlike the earlier Slowloris and R.U.D.Y. scenarios, which harmed nothing). Candidates to evaluate, not to accept blindly:
   - **Distributed low-rate botnets.** Many source IPs, each below any per-IP or per-(IP, UA) threshold, with UA rotation and residential- or CGNAT-like addressing. Only the aggregate hurts the server.
   - **Human-mimicking bots.** Browser-like rate and burst profile, but non-human navigation: no asset fetches after HTML, no referrer chains, deep links without a landing page, uniform think times, unrealistic path transitions.
   - **Application-logic abuse** at low request rates: credential stuffing or password spraying, expensive-endpoint abuse (search, report export, login hashing), cache-busting via query randomisation, inventory or cart hoarding. This **requires a backend with realistically expensive endpoints**, e.g. a DB-backed search and a login with password hashing, so that rate is low but cost is high.
   - **Adaptive, pulsing and threshold-probing attackers** (Yo-Yo or on-off patterns tuned under sliding-window rules), plus attackers that change their behaviour after a ban.
   - **Hard benign negatives that break rate rules:** flash crowds (sudden legitimate surges), asset-heavy pages, API clients, polite crawlers, CGNAT pools, mobile retries under loss.
   - **Slow-connection abuse.** The access log is blind to it (R1), so it needs connection-level features. This is the natural case for a **hybrid model** fusing XDP/`ss` connection features with Nginx request features, which also feeds the open question in Section 5.
   - **What to exclude.** Mark every candidate that only works through a fingerprint (exact request size, header order, tool-specific UA, server timing) as a shortcut to exclude, consistent with the invariance probes.
3. **Benign realism.** How to make benign traffic credible. Options:
   - real headless browsers (e.g. Playwright/Chromium) driving the web app
   - replay or statistical models of public HTTP access traces
   - think-time and session-length distributions from the literature
   - HTTP/1.1 and HTTP/2 over TLS
   - NAT/CGNAT pools with realistic UA collisions
   - API clients, crawlers, flash crowds

   State the external source for each parameter.
4. **Testbed engineering changes.**
   - **Scale:** hundreds of client IPs, e.g. via IP aliases, ipvlan/macvlan or a namespace pool, instead of ~20 namespaces.
   - **Generators:** open-loop load generators such as `wrk2 -R`, vegeta, k6 or locust.
   - **Isolation:** attackers isolated from the server CPUs, or on a second VM.
   - **Operating points:** a calibrated capacity knee for each attack class, including the volumetric floods that were never calibrated.
   - **Backend:** realistic, with expensive endpoints, served over TLS and HTTP/2.
   - **Scenario design:** a scenario DSL or config so that scenarios are declarative, seeded and reproducible.

   Estimate the effort for each change, and say what the 8-vCPU VM can realistically sustain.
5. **Model and pipeline changes that give the GRU its full potential**, all under the existing invariance-probe gates:
   - richer behavioural features: inter-arrival histograms, navigation and path-transition features, endpoint-cost features, referrer/asset structure
   - session- or connection-level keying, and longer or variable-length windows
   - more and more diverse training data, with held-out attack families and held-out benign kinds
   - threshold calibration on validation data
   - cost-sensitive training at a fixed false-positive budget

   For each change, say which baseline it could plausibly beat and why.
6. **Evaluation protocol.**
   - **Unit of analysis:** independent attacker and benign entities, with IP sets re-drawn per seed, not the same roles re-run.
   - **Repetitions:** ≥ 10 runs per arm.
   - **Statistics:** clustered or bootstrap CIs.
   - **Primary metric:** detection recall at a fixed benign FP budget (per client and per client-hour).
   - **Secondary metrics:** time to detect against the heuristics; **end-to-end service impact with enforcement on** (legit availability and latency, not only shadow would-bans); daemon CPU/RSS overhead.
   - **Robustness checks:** an adaptive-attacker evaluation and held-out families.
   - **Ablations:** GRU vs HGB vs rules vs GRU+rules, and XDP-only vs Nginx-only vs fused input.
   - **Pre-registered verdict ladder** that also defines what counts as "no advantage".
7. **Phased plan.** Steps with gates, effort, VM time, code to change (file by file), and what can be reused from the existing L7 tooling (`ml/l7_traffic.py`, `ml/l7_benign.py`, `ml/capture_l7.py`, `ml/eval_l7.py`, `ml/train_l7.py`, `ml/p5b_report.py`). Mark the minimum viable version that fits before thesis submission, and what is future work.

---

# 7. LEADS TO VERIFY OR REFUTE

From my quick pass over a local copy at `3086e27` (2026-10-19). These are **hypotheses, not facts**. Confirm or refute each with evidence, and look beyond them.

1. **The deployed default may run the weakest ML configuration.** `XDP_GRU` defaults to `1`, so the diagnosed, fingerprint-prone XDP-GRU can ban. The L7 GRU is shadow-only and off. The deployed heuristics are the `default` profile, which P5c.1 showed bans a 60-asset page load and CGNAT gateways.
2. **The XDP program is unchanged since `6fc27fa`.** Expect F-13 and F-14 to still be open, along with D5 (time-normalised rates) and batched map reads (`items_lookup_batch`).
3. **Old findings that may still be open:**
   - F-19: 503 excluded from the error ratio
   - F-20: R.U.D.Y. detector never fires
   - F-21: wrong `bcc` and missing dependencies in @code/requirements.txt
   - F-28: Nginx buffers and body limit
   - F-32: module-level daemon
   - F-37: legacy files at the root
   - F-43: SYN-cookie toggle
   - F-44: `torch.load` without `weights_only`
4. **No availability result for volumetric floods** in the corrected harness: only the HTTP flood at the knee, plus a single default-point regression run (R2, where everything is 100 % because the server is over-provisioned).
5. **n = 3 paired runs per mode** in all comparison campaigns. Both the earlier session and @code/docs/EVALUATION.md say ≥ 10 are needed for thesis claims, and that was never done.
6. **The `"rate limiting alone is worse than unprotected"` effect is unstable:** −37.7 pp in EXP-2a, −6.1 pp in R3 (p = 0.27), −36.1 pp in R4. A closed-loop `wrk` attacker may explain it. The open-loop `wrk2 -R` test was recommended but never run.
7. **P5c.4 units:** `p5c4_report.md` pools 4 attacker IPs per run × 5 runs = "20", and 20 benign IPs × 5 = "100". The counts are over seeds, not over independent attackers and clients. The HGB online-vs-offline discrepancy (1/8 offline vs 20/20 online) is unexplained.
8. **Post-hoc choices in P5b/P5c:** the pivot, variant restriction, tolerance margin and held-out kinds. The fact that every verdict was negative argues against *favourable* bias, but they may still bias the framing of the "dilemma" claim.
9. **The tolerant profile (SlowConn = 180 connections) is a security regression** for Slowloris-class attacks below 180 sockets. Check whether its cost was measured, as §7.3.5 of the design doc promised.
10. **Socket injection.** `/run/ddos_l7.sock` is world-writable. Any local process could forge L7 log lines. Harmless while shadow-only; a vulnerability if promoted.
11. **Docs drift.**
    - The status blocks of @code/docs/L7_GRU_DESIGN.md (e.g. "P5b approved", the P1 "70 tests") may be stale.
    - @code/todo.txt is from 2026-09-13.
    - REPORT.md's environment table describes the 2026-10-11 state.
    - There is far more process documentation (≈ 3,000 lines of docs) than the thesis can use. Identify what is thesis-relevant.
12. **Legacy outputs:** @code/plot_availability.py and the suite still append to `/tmp/*.csv`, alongside the new results directory. Is anything still reading those legacy files?
13. **Big gitignored CSVs in the working tree** (`CICFlowMeter.csv`, `Syn.csv`) and `training_data/`: are the datasets that the published L7 results depend on all inside `results/`, so that the results can be reproduced from the repository alone?
14. **The P1 smoke false ban by the XDP-GRU** (mentioned in L7_GRU_DESIGN.md §2): find the event and its cause.
15. **Unmerged or stale branches:** `chore/audit-telemetry-lru` (per-CPU LRU telemetry) and `chore/audit-cleanup` were mentioned in REPORT.md. Do they contain the D4 fix or anything else useful that never reached `main`?

---

# 8. DELIVERABLES

Write `/root/project_analysis_v2/REPORT.md`. **Do not overwrite @code/docs/REPORT.md.** Use this structure:

1. **Executive summary.** One page: what the system is *today*, overall health, the top 5 risks, the top 5 recommendations, and **what the thesis can claim right now**.
2. **Environment and state snapshot.** Include unpublished runs and leftovers.
3. **Architecture.** Diagram, data flows, deployed vs evaluated configuration, pipeline tables, engine matrix.
4. **Status of the earlier review.** A table F-01 … F-45 plus the D-patches with columns: *ID | earlier claim | still true? | fixed in commit | verified how*. Also list every earlier claim you found wrong or overstated.
5. **Component analysis.** XDP, control plane, L7 path, Nginx, harness and eval tooling.
6. **ML audit.** XDP-GRU and the L7 track, including pre-registration integrity, circularity, units and inconsistencies.
7. **Testing assessment.** Results of the test run, the test classification, coverage, gaps and the proposed plan.
8. **Logs and runtime health.**
9. **Results and statistics assessment.** Integrity checks, recomputations, the reproducibility verdict and the **thesis-claim audit table**.
10. **Open question: XDP telemetry vs Nginx logs (vs neither).** The full answer per Section 5.
11. **Testbed and evaluation redesign for the GRU.** The full deliverable of Section 6: diagnosis, threat classes with grounding, benign realism, testbed and model changes, evaluation protocol, and the phased plan with the minimum viable version.
12. **Leads from Section 7.** A verdict for each: confirmed, refuted, or partially confirmed, with evidence.
13. **Findings table**, with columns:
    `ID | Severity (Critical/High/Medium/Low) | Area | Evidence (file:line / commit / command) | Problem | Impact (incl. on thesis claims) | Proposed fix | Effort (S/M/L)`
    Use new IDs (G-01 …), and cross-reference earlier F-IDs where relevant.
14. **Prioritised roadmap toward thesis submission.**
    - Must do before submission (≤ 2 weeks)
    - Should do
    - Future work / out of scope

    Include what to **stop** doing or cut.
15. **Proposed experiments needing my approval.** Exact commands, duration, side effects, sample size and pre-registered criteria.
16. **Questions for me.**
17. **Appendix.** Commands run (`commands.log`), tools installed in your venv, files skipped and why.

Put proposed code changes in the report as **diff snippets only**. Do not apply them.

---

# 9. WORKING STYLE

- Start with a short plan, then go through the phases in order. Do Section 6 after the audit, because its design depends on what the audit finds. Save notes as you go so the work survives disconnection.
- Be specific and critical. "Improve the evaluation" is not a finding. This is a finding: "`results/2026-10-16_l7-p5c4-eval/p5c4_report.md` counts 20 attackers, but they are the same 4 attacker roles (`runA*/manifest.json`, schedule 10.0.2.x) in each of 5 seeds; per-role recall is 4/4 with a Clopper-Pearson 95 % CI of 40–100 %".
- Keep three categories separate:
  - problems that **invalidate or weaken thesis claims**
  - **security or correctness problems in the deployed defaults**
  - engineering polish
- Prefer recomputation over citation. Where you rely on an earlier document without re-verifying it, tag it **[CLAIMED]**.
- If a step is risky or ambiguous, skip it and list it under "Questions for me".
- When finished, print the path to the report and a 10-line summary of the most important conclusions.
