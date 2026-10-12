# Addendum to the review — approved follow-up experiments (EXP-0 … EXP-2b) + F-45 fix (2026-10-12)

**Scope:** a chronological log of the follow-up experiments you approved on 2026-10-12 — EXP-0 (dup-MAC reproduction), EXP-1/1b/1c (unique-MAC re-runs in XDP / iptables / unprotected / nginx-limits-only), EXP-1d (calibration sweep, §J), EXP-2a (cross-mode comparison at a capacity-limited server), EXP-2b (nginx log/status tuning), EXP-5 (BCC map-iteration benchmark) — plus the **F-45** GRU-feed-stall fix. Sections A–I were written as each experiment finished; **§J–§M were added afterwards** (knee comparison, nginx tuning, F-45 validation, campaign summary). **The D1+D2 (unique veth MAC + nginx restart/orphan cleanup) and F-45 (GRU-feed stall) fixes are now committed and merged to `main` — commit `51cc21c`.** The "needs your approval" lists in §G / §H.6 / §I.6 are historical: each item was subsequently approved and carried out in the section that follows it.
**Context:**
* The VM had rebooted at about 08:06 UTC on 2026-10-12, which wiped `/tmp` (the 2026-10-11 CSVs and orphan Nginx workers). The baseline used below is my sha256-verified snapshot `outputs/tmp_snapshot/` (hashes unchanged).
* `REPORT.md` and the patch had been moved by you into the repo's `docs/` (untracked). I left them untouched, so this addendum is a separate file.
**Evidence tags** as in the main report: [FACT] / [INFERENCE].

## A. How the experiments were run
* **EXP-0** (08:10 UTC, ≈10 s, no traffic, no XDP): 3 transient netns + veth pairs, then deleted (0 left behind).
* **EXP-1** (08:11:02 → 08:41:31 UTC):
  * `campaigns/2026-10-12_macfix_xdp/run_exp1.sh` ran 3 × `python3 <patched copy of test_distributed_suite.py>` in XDP mode, with CWD = repo.
  * The patched copy is `patches/work/b/test_distributed_suite.py`, verified as the HEAD file plus the D1+D2 patch (byte-identical to your `docs/` copy). Running a copy instead of branching/patching the repo kept the working tree exactly as you left it [FACT: `git status` before and after shows only your two untracked `docs/` files].
  * A read-only observer (`tail -F` → ms timestamps) saved every daemon log line to `daemon_log_timestamped.txt`, because the suite deletes the daemon log per scenario.
  * Results: `console.log`, the 3 CSVs + `SHA256SUMS`, `provenance.txt` (HEAD 6fc27fa, sha256 of every input), and the journal cursor.
* **Side effects (as approved):** the suite's usual pkills, netns/bridge rebuilds, XDP attach/detach, Nginx log truncation, a `dummy_app.py` rewrite (identical content), and new `/tmp/{mitigation_performance,availability_performance,availability_raw_performance}.csv`. These now hold *only* the EXP-1 runs; move them before your next campaign, because the suite appends.
* **End state** [FACT]: 0 Nginx processes and 0 netns after the final cleanup (yesterday: 72 orphan workers / 9 zombie netns), no XDP attached, no attack or backend processes.

## B. EXP-0 — duplicate MAC reproduced [FACT]
```
plain   : veth_in@if5  12:af:eb:2d:8a:f2 | veth_in@if7  12:af:eb:2d:8a:f2 | veth_in@if9  12:af:eb:2d:8a:f2
patched : veth_in@if11 02:00:0a:00:01:01 | veth_in@if13 02:00:0a:00:01:02 | veth_in@if15 02:00:0a:00:01:03  (numrxqueues 8 honoured)
```
Three different namespaces received the identical name-derived MAC. With an explicitly assigned address (the patch's exact `peer … address …` syntax), udev leaves it alone. **F-01 is now directly reproduced, not only inferred.**

## C. EXP-1 — same XDP code, unique MACs (+ Nginx restart fix)

| Measure (pooled over 3 runs) | Baseline 2026-10-11 (duplicate MAC) | EXP-1 2026-10-12 (unique MAC) |
|---|---|---|
| Kernel duplicate-address messages | 21–24 per run | **0** |
| "during" success — SYN / LowSlowSYN / UDP / HTTP / ACK | 34.0 / 91.6 / 35.3 / 89.0 / 34.1 % | **100.0 % in every scenario** |
| "during" success — Frag / Slowloris / R.U.D.Y. / Yo-Yo / Multi | 34.1 / 95.0 / 94.5 / 90.0 / 31.7 % | **100.0 %** (n = 70–463 per scenario) |
| Flood still running **after all bots banned** (UDP / ACK / Frag / Multi) | 35.9 / 31.9 / 33.0 / 32.7 % | **100 / 100 / 100 / 100 %** (n = 325–385 each) |
| First second of floods (SYN/UDP/ACK/Frag/Multi), before any ban | 10–20 % | **100 %** |
| First second, HTTP / Yo-Yo | 85.0 / 82.4 % | **100 / 100 %** |
| "before" / "after" | 95.9 % / 100 % | **100 % / 100 %** |
| Failed requests (all periods) | 439 (all curl `000`) | **0** |
| Per-run mean flood "during" success | 26.2 / 21.4 / 49.2 (SD 14.8) | **100 / 100 / 100 (SD 0)** |
| Flood rate reaching `veth_server` (PPS, Phase 2A/3) | UDP 1.10 M, ACK 1.01 M, Frag 1.09 M | **UDP 1.55 M, ACK 1.64 M, Frag 1.61 M** |
| `PreStack_Dropped` ≈ PPS, `IP_InReceives` | yes; 41–48 pps | yes; 147–169 pps |
| CPU_Total / hot core during floods | 64–66 % / 100 % | 55–59 % / 98–100 % |

Charts: `charts/exp1_timeseries.png`, `charts/exp1_segments.png`. Tables: `outputs/exp1/exp1_summary.txt`, `raw_both.csv`, `phases_both.csv`.

**Interpretation**
* [FACT] Fixing the MAC collision alone takes legit availability from ≈ 32–36 % to **100 %** under every flood, *including the first second before any ban*, with 1.5–1.6 M pps hitting `veth_server`, attackers still sharing the CPUs, and the hot core still at ~100 %. **The availability losses reported for 2026-10-11 (and every earlier run) were an artefact of the testbed's L2 defect, not of attack load or of the defence.** Shared-CPU contention, which I had listed as a possible co-cause, does not cause failures at these intensities [FACT for this setup].
* [INFERENCE] The attack rate the testbed delivers rose by ≈ 50 % (1.0–1.1 M → 1.55–1.64 M pps). With one MAC on 25 bridge ports, the FDB entry moved on almost every frame (each move also emits a netlink notification), which throttled bridge forwarding.
* **Consequence for the thesis** [INFERENCE, needs EXP-1b]:
  * With correct L2, these attacks do not degrade legit service at all in XDP mode, even before bans.
  * Unless iptables and unprotected modes *do* degrade under the same corrected conditions, the availability metric cannot show any benefit of mitigation at these intensities. The demonstrable benefits would then be detection itself and stack offload (`PreStack_Dropped`), or would require stronger attacks or a resource-constrained server.
  * EXP-1 contains no iptables or unprotected runs, so no cross-mode statement can be made yet.
* **Caveat:** the patch also makes Nginx restart between scenarios (D2). That plausibly affects per-scenario state, but it cannot explain a jump from ~33 % to 100 % *during a flood* while the failures were network-level timeouts. The duplicate-address count fell from 21–24 to 0 per run in lockstep [INFERENCE: D1 is the operative change].

## D. Exact detection data (first time available: timestamped daemon log)
* **TTM** (ban time − attack start), per bot, 3 runs [FACT]:

| Scenario | exact TTM median (min–max) | harness-reported TTM (3 runs) |
|---|---|---|
| SYN | 1.54 s (0.64–1.83) | 2.16 / 1.17 / 1.77 |
| Low&Slow SYN | 3.74 s (3.57–3.98) | 3.62 / 4.18 / 4.14 |
| UDP | 0.62 s (0.41–0.92) | 1.19 / 1.27 / 1.14 |
| HTTP | 0.78 s (0.11–1.00) | 1.10 / 1.70 / 1.61 |
| ACK | 1.35 s (0.12–**10.32**) | 1.12 / **N/A (0/5)** / 1.42 |
| Frag | 0.55 s (0.42–1.20) | 1.20 / 1.26 / 1.45 |
| Slowloris | 3.94 s (3.26–4.17) | 4.21 / 3.45 / 4.35 |
| R.U.D.Y. | 3.77 s (3.56–4.04) | 4.05 / 3.81 / 4.31 |
| Yo-Yo | 0.54 s (0.15–0.81) | 1.58 / 1.71 / 1.71 |
| Multi | 1.26 s (0.05–3.69) | 1.73 / 1.95 / 1.63 |

  The harness overestimates TTM by **0.52 s on average (0.65 s for floods, up to 1.26 s)**, confirming F-08 quantitatively (`outputs/exp1/ttm_harness_vs_exact.csv`).
* **Engine attribution per bot (first ban), 150 bot-scenarios** [FACT]: L4 Volumetric 54, L4 SlowConn 30, L7 Heuristic 33, L4 SYN 18, L4 Low-SYN 15, **GRU 0**. No bot was banned twice. In Multi-vector the HTTP bot is now banned by L7 (yesterday by SlowConn in 2 runs, because its connections stalled under the L2 defect).
* **The GRU banned nothing in EXP-1** (yesterday: co-engine in 7/30 XDP scenario-runs). [INFERENCE] With correct L2 the L7 rule bans wrk bots in 0.1–1.0 s, before the GRU accumulates 15 snapshots and 3 hits. Yesterday's GRU co-detections were enabled by the L2 defect slowing the heuristics. This further weakens any "GRU adds detection" claim (Lead 11, F-06).
* **No legit IP was banned in any EXP-1 scenario** [FACT: no `[BAN] 10.0.1.x` line in the daemon log]. Run 3's ACK scenario still reported "FP: 10.0.1.9 (mobile_bad)" → **the ping-based collateral check produced a false FP**, confirming the Lead-17 inference and F-25.

## E. New finding F-45 (High) — the GRU feed can stall L4 detection by ~10 s under a TCP flood
* **Evidence** [FACT], run 2 ACK flood:
  * The daemon printed nothing from −5.3 s to **+10.32 s**, then banned all 5 bots in the same millisecond, logging "Rate: 1,350,230 … 1,471,750 pkts/s". These are un-normalised deltas over the stalled loop (F-17).
  * During the stall `CPU_Daemon_Pct` = **182–226 %** and the daemon RSS grew 460 → 526 → 611 MB.
  * At Phase 2, `PreStack_Dropped = 0` and `IP_InReceives = 582 k pps`: the flood was unmitigated.
  * The harness timed out at 10 s and reported 0/5 FAIL.
  * Runs 1 and 3 banned the same bots in 0.12 s and 1.35 s.
* **Mechanism** [INFERENCE, strongly supported]:
  1. hping3 `-A` increments the source port, so every ACK-flood packet is a new **TCP** flow in `flow_map`.
  2. If the flood starts after a poll's per-IP rules have run but before its GRU-feed pass (no suppression yet, bots not yet banned), the pass computes features, appends to the bots' deques, and runs `scaler.transform` + an inference enqueue (`control_plane.py:725-753`) for each of tens of thousands of new flows.
  3. The GIL-bound thread, plus the inference worker, then spends ~10 s before the next poll can run the volumetric rule.
  4. UDP floods are skipped by the TCP filter. SYN floods are banned within 1–2 s at 5,000 pps. So the ACK (and any TCP) flood at line rate is the worst case.
* **Impact:** a ~10 s blind spot at flood onset (observed 1 of 3 ACK runs), with no legit impact here only because the L2 fix made the server robust at this load.
* **Fix:**
  * Run the L4 per-IP rules and the GRU feed in separate threads or processes, so the GRU can never delay L4.
  * Skip GRU feeding for any IP whose per-poll rate exceeds a fraction of the L4 thresholds, and for IPs with more than N new flows per poll.
  * Bound per-poll work (max flows) and batch scaler + inference.
  * Normalise rates by elapsed time (D5).

## F. Effect on the main report's verdicts

| Item | Before (main report) | After EXP-0/EXP-1 |
|---|---|---|
| F-01 duplicate MAC | Critical, mechanism proven, effect inferred (ρ = −0.84) | **Critical, effect measured: 32–36 % → 100 %** |
| Lead 13 (bottleneck upstream of XDP) | Confirmed; L2 defect dominant, CPU co-factor | **L2 defect is the cause; CPU contention alone causes no failures at these intensities** |
| Lead 16 (baseline < 100 %) | Onset bleed | **Confirmed: "before" = 100 % once responses are no longer misdelivered** |
| Lead 17 (FP 10.0.1.3) | Most likely a ping artefact | **Confirmed mechanism: an identical ping-FP (10.0.1.9) occurred with zero bans in the daemon log** |
| Lead 11 / F-06 (GRU value) | Co-engine 13/60, never sole | **0 GRU bans in 150 bot-scenarios once L2 is fixed** |
| F-08 (TTM floor) | Harness floor ≈ 1.1 s | **Measured over-estimate 0.52 s mean (0.65 s floods)** |
| §8.5 claim "XDP better than iptables under floods" | Contradicted/unsupported | **Still unsupported, and moot at these intensities: XDP mode already serves 100 % from the first second. Needs EXP-1b** |
| F-09 harness orphans / no restart | defect | **D2 verified: 0 Nginx processes and 0 netns after cleanup** |
| New | — | **F-45 (High): GRU-feed stall delays L4 bans by ~10 s** |
| Tier-1 training data | captured on defective L2 (inference) | Still true. Re-capture after D1 is required |

## G. Recommended next steps (each needs your approval)
1. **EXP-1b — DONE (approved and run 2026-10-12, see §H).** ~~The same patched copy in iptables and unprotected modes, 3 runs each.~~ Command: as `run_exp1.sh`, with `MITIGATION_BACKEND=iptables` (and then `MITIGATION_MODE=none`), writing to `campaigns/2026-10-12_macfix_{iptables,unprotected}/`.
2. If unprotected also stays ≈ 100 %, scale attacks up (more bots, `--flood` for SYN, larger HTTP floods, effective slow attacks per EXP-6) and/or pin the server to fewer CPUs until legit service degrades unprotected. Only then compare modes (EXP-2 protocol).
3. Fix F-45 before any further benchmark: the ACK-flood blind spot will otherwise add random 10-s outliers to TTM and PASS/FAIL.
4. Re-capture the Tier-1 dataset with D1 applied. The training capture shares the L2 defect, so its "lossy/stalled benign" rows are partly artefacts.

---

## H. EXP-1b — iptables and unprotected modes with unique MACs (approved "proceed", run 2026-10-12 08:57–10:05 UTC)

**Run:**
* `campaigns/run_exp1b.sh`: the same patched suite copy, 3 runs with `MITIGATION_BACKEND=iptables`, then 3 runs with `MITIGATION_MODE=none`, plus the same timestamped daemon-log observer.
* Data: `campaigns/2026-10-12_macfix_{iptables,unprotected}/` (console, CSVs + `SHA256SUMS`, provenance with input hashes).
* End state after each mode: 0 Nginx processes, 0 netns, no XDP attached, no duplicate-address kernel messages. The repo's tracked files are unchanged; you added `docs/REPORT_ADDENDUM_EXP0_EXP1.md` meanwhile, which predates this section.
* Analysis: `scripts/exp1b_compare.py` → `outputs/exp1b/exp1b_summary.txt`, `latency_by_mode.txt`.
* Charts: `charts/exp1b_crossmode_macfix.png`, `exp1b_timeseries_macfix.png`, `exp1b_latency_macfix.png`.

### H.1 Availability — 100 % in every mode, including unprotected [FACT]

| Scenario | XDP | iptables | Unprotected (no daemon, no Nginx limits) |
|---|---|---|---|
| SYN / LowSlowSYN | 100 % (n 80) / 100 % (147) | 100 % (98) / 100 % (134) | 100 % (260) / 100 % (713) |
| UDP / ACK / Frag | 100 % (388) / 100 % (463) / 100 % (393) | 100 % (406) / 100 % (406) / 100 % (403) | **99.8 % (555; 1 timeout)** / 100 % (536) / 100 % (530) |
| HTTP / Yo-Yo | 100 % (70) / 100 % (73) | 100 % (74) / 100 % (72) | **100 % (347) / 100 % (563)** |
| Slowloris / R.U.D.Y. / Multi | 100 % / 100 % / 100 % | 100 % / 100 % / 100 % | 100 % (903) / 100 % (913) / 100 % (787) |

* Every run is 100 %; equal-exposure windows (requests started 0–1, 0–3, 3–10 s after attack start) are 100 % in all modes.
* Protected vs unprotected Fisher exact p = 1 for every scenario.
* While the flood keeps running after Phase 2, success is 100 / 100 / 99.8–100 %.

**Interpretation:**
* At the suite's attack intensities, **no attack degrades legit availability even with no protection at all**. That holds for floods of 1.0–1.44 M pps reaching the IP stack, wrk floods hitting an unlimited Nginx, and the Slowloris / R.U.D.Y. variants.
* Every availability difference ever reported between modes was an artefact of the L2 defect. That includes yesterday's unprotected HTTP 58 % and Yo-Yo 77 %; the wrk traffic also flapped the FDB.
* **The success-rate availability metric cannot demonstrate any mitigation benefit in this testbed as configured.**

### H.2 What does discriminate between modes

**1. Latency under L7 floods** [FACT]. `perfect` clients (no netem) in the equal-exposure window [0, 2.5) s after attack start, p50 / p95 in ms:

| Scenario | XDP | iptables | Unprotected |
|---|---|---|---|
| HTTP | 2 / 115 | 3 / 280 | **338 / 677** |
| Yo-Yo | 2 / 276 | 2 / 265 | **319 / 577** |
| Multi | 2 / 7 | 3 / 6 | 40 / 225 |
| UDP | 3 / 10 | 3 / 135 | 4 / 10 |

* Over the whole unprotected flood, HTTP latency stays at 230–410 ms until the harness stops it. Yo-Yo spikes every 8 s with the wrk bursts.
* Network floods (UDP/ACK/Frag/SYN) leave latency unchanged in every mode.
* *Attribution:* the gap is already present in the first second, before any ban (exact bans at 0.1–1.8 s). So it is largely Nginx `limit_req`/`limit_conn`, which the unprotected config removes (F-11). The daemon's share can only be isolated with a "Nginx limits, no daemon" mode.

**2. Server CPU under L7 floods** [FACT] (mean of P2 / P2A / P3):

| Scenario | Nginx CPU XDP / iptables / unprotected | CPU_Total XDP / iptables / unprotected |
|---|---|---|
| HTTP | 52 % / 55 % / **112 %** of a core | 25 / 35 / **88 %** |
| Yo-Yo | 24 / 52 / **110 %** | 16 / 24 / **87 %** |

**3. Stack offload** [FACT]:
* XDP drops 1.24–1.36 M pps pre-stack under UDP/ACK/Frag. Its `IP_InReceives` mean is 108–199 k pps, including the pre-ban part of Phase 2.
* iptables and unprotected pass 1.07–1.44 M pps into the IP layer.
* CPU_Total is similar across modes (41–58 %): the attack generators dominate it.

**4. Daemon cost in iptables mode** [FACT]: 105 % of a core during the SYN flood (XDP 37 %), plus HTTP 62 % and Yo-Yo 46 %. In iptables mode banned flood packets are not dropped in XDP, so they keep inserting into `flow_map`, which the daemon iterates every poll (F-15).

### H.3 Detection — exact TTM from daemon timestamps [FACT]
* Medians, XDP vs iptables:

| Scenario | XDP | iptables |
|---|---|---|
| SYN | 1.54 | 1.70 |
| LowSlowSYN | 3.74 | 3.78 |
| UDP | 0.62 | 0.73 |
| HTTP | 0.78 | 0.97 |
| ACK | 1.35 | 0.95 |
| Frag | 0.55 | 0.45 |
| Slowloris | 3.94 | 3.70 |
| R.U.D.Y. | 3.77 | 3.60 |
| Yo-Yo | 0.54 | 0.86 |
| Multi | 1.26 | 0.52 |

* First-ban engines are identical in both modes. **GRU bans: 0. Legit IPs banned: 0** (300 bot-scenarios across XDP + iptables).
* The F-45 stall did not recur in the three iptables ACK runs (max 1.09 s). It has occurred in 1 of 6 protected ACK runs so far.

### H.4 SYN-RECV (Lead 18, refined) [FACT]
* With unique MACs, unprotected SYN-RECV during the fragmentation flood is ≈ 2 (was 512); protected modes show ≈ 340.
* The constant 512 seen in all modes on 2026-10-11 was a product of the L2 defect: misdelivered SYN-ACKs never drew RSTs from the bots, so request sockets piled up to the backlog cap (511 + 1).
* With correct L2, bots RST the cookies immediately in unprotected mode, while in protected modes the bans drop those RSTs.

### H.5 Updated thesis-claim audit (replaces the corresponding rows of the main report §8.5)

| Claim | Verdict after EXP-1/1b |
|---|---|
| "XDP preserves availability better than iptables / unprotected under floods" | **Refuted at these intensities.** All modes serve 100 %. |
| "Protection restores availability under HTTP flood / Yo-Yo" | **Refuted for success rate** (unprotected also 100 %). **Supported for latency and server CPU** (≈ 100× lower p50; Nginx CPU ½), attributable mainly to Nginx limits until separated. |
| "XDP drops attack traffic before the kernel stack" | **Supported** (unchanged) |
| "All 10 attack types are detected and banned within seconds" | **Supported in both protected modes**, with exact TTMs (H.3). Caveat: F-45 ~10-s stall (1/6 ACK runs) and F-25 (ping-based FP check). |
| "Mitigation preserves service under attack" | **Cannot be shown with the current attacks.** Unprotected service is not degraded. |
| "The GRU contributes detections" | **Not supported:** 0 GRU bans in 300 bot-scenarios with correct L2 |

### H.6 Recommended next steps (each needs your approval)
1. **"Nginx limits, no daemon" mode, 3 runs (≈ 35 min).** Run the patched copy with `MITIGATION_MODE=none` but the *protected* `nginx.conf`. This needs a one-line copy-level change; the suite currently couples mode=none to the unprotected config. It separates Nginx's share of the L7 latency/CPU benefit from the daemon's.
2. **Calibrate attack intensity** until the *unprotected* server degrades: more bots, `hping3 --flood` for SYN, larger wrk floods, effective slow attacks (EXP-6), and/or confine Nginx+Gunicorn (+softirq) to 1–2 CPUs with a cgroup cpuset. Only then compare modes with ≥10 interleaved runs (EXP-2).
3. **Report latency (p50/p95 per profile) and server CPU** as primary QoS metrics alongside success rate; success rate saturates.
4. Fix F-45 and D5 before further benchmarking; re-capture the Tier-1 dataset with D1.

---

## I. EXP-1c — "Nginx limits, no daemon" (approved "proceed", run 2026-10-12 10:15–10:53 UTC)

**Run:**
* `campaigns/run_exp1c.sh`, 3 runs with `MITIGATION_MODE=none NGINX_PROTECTED=1`, using suite copy `patches/work/c/` = the verified D1+D2 copy plus a 5-site switch (`patches/EXP1c_nginxlimits_mode.diff`) that keeps the protected `nginx.conf` without the daemon and writes `*_nginxlimits.csv`.
* Verified during the run [FACT]: `nginx: master process nginx -c …/code/nginx.conf`, no `control_plane.py` process, 25 unique MACs per run, 0 duplicate-address messages.
* End state: 0 Nginx processes, 0 netns, repo tracked files unchanged.
* Data: `campaigns/2026-10-12_macfix_nginxlimits/`. Analysis: `outputs/exp1c/exp1c_summary.txt`. Charts: `charts/exp1c_latency_4modes.png`, `charts/exp1c_nginx_cpu_4modes.png`.

### I.1 Availability — 100 % in all four modes [FACT]
Every scenario in Nginx-limits-only mode is 100 % (n = 299–992 per scenario). Across XDP / iptables / Nginx-limits-only / unprotected, the only failure in 12 runs is one unprotected UDP-flood request.

### I.2 Latency under L7 floods — where the benefit comes from [FACT]
`perfect` clients (no netem), successful requests, p50 / p95 in ms:

| Window | Scenario | XDP + daemon | iptables + daemon | **Nginx limits only** | Unprotected |
|---|---|---|---|---|---|
| [0, 2.5) s, all modes under attack | HTTP | 2 / 115 | 3 / 280 | **40 / 359** | 338 / 677 |
| | Yo-Yo | 2 / 276 | 2 / 265 | **14 / 287** | 319 / 577 |
| | Multi | 2 / 7 | 3 / 6 | **3 / 22** | 40 / 225 |
| [2.5, 16.5) s, sustained flood, no bans in either mode | HTTP | (attack stopped) | (attack stopped) | **25 / 199** | 266 / 547 |
| [2.5, 26.2) s | Yo-Yo | — | — | **2 / 81** | 2 / 354 |
| [2.5, 35.2) s | Multi | — | — | **3 / 45** | 41 / 173 |

* Nginx `limit_req`/`limit_conn` alone gives ≈ 10× lower median latency than no protection under a sustained HTTP flood.
* The daemon's bans (0.1–1.8 s) remove the remaining ≈ 10–20× within the first seconds.
* Network floods (UDP/ACK/Frag/SYN) leave `perfect`-client latency unchanged in every mode (p50 2–6 ms).

### I.3 Server cost — rate limiting alone is *more* expensive than no protection [FACT]

| HTTP flood (mean P2 + P3) | XDP + daemon | iptables + daemon | **Nginx limits only** | Unprotected |
|---|---|---|---|---|
| Nginx worker CPU, % of one core | 52 | 55 | **434** | 112 |
| CPU_Total | 25 % | 35 % | **94 %** | 88 % |
| Packets/s reaching the server | 5.0 k | 7.0 k | **48.7 k** | 1.2 k |
| `IP_InReceives` | 7.2 k | 10.2 k | **59.5 k** | 20.8 k |

Yo-Yo shows the same pattern: Nginx CPU 24 / 52 / **374** / 110 %.

[INFERENCE, consistent with the PPS numbers] The mechanism:
* wrk is a closed-loop generator.
* Without limits, each request waits for Gunicorn, so the flood throttles itself (1.2 k pps).
* With `limit_req`, the bots get an immediate, cheap 503 and fire the next request at once, so ≈ 40× more packets arrive.
* Every rejection also writes an access-log line *and* an `[error] limiting requests` line (default `limit_req_log_level error`). This is the same mechanism behind the 1.1 GB + 1.1 GB of logs in the 10-09 capture.
* The daemon's network-layer bans (XDP or iptables, plus `ss -K`) are what bring Nginx back to ≈ ½ core.

An open-loop attacker at a fixed rate would not amplify like this, so the effect is specific to throughput-maximising bots.

### I.4 Attribution — what each layer contributes in this testbed (unique MACs, current intensities)

| Benefit | Nginx limits alone | + daemon bans (XDP or iptables) |
|---|---|---|
| Legit success rate | none measurable (100 % everywhere) | none measurable |
| L7-flood latency | ≈ 10× better than unprotected (sustained) | a further ≈ 10–20× in the first seconds; flood stopped |
| Server CPU under L7 floods | **worse** (Nginx ≈ 4× unprotected) | Nginx ≈ ½ core (≈ 8× less than limits alone) |
| L3/L4 floods | irrelevant | XDP only: drop before the IP stack (1.24–1.36 M pps) |

### I.5 Claim audit additions
* "The daemon reduces server load under L7 floods compared with Nginx rate limiting alone": **supported** (Nginx CPU 52–55 % vs 374–434 %; 3 runs each, large effect).
* "Nginx rate limiting alone protects legit latency": **supported** (≈ 10× vs unprotected), but it multiplies server CPU and log volume against closed-loop floods.
* "Protection improves availability": **refuted at these intensities** in all four modes.
* XDP vs iptables: no difference in availability or latency. XDP keeps flood traffic out of the IP stack; iptables does not.

### I.6 Next steps (each needs your approval)
1. **Calibrate attack strength** (the only way to make availability claims): more bots, `hping3 --flood` SYN, open-loop and closed-loop HTTP floods at several rates, effective slow attacks (EXP-6), and/or confine the server to 1–2 CPUs. Increase until the *unprotected* server degrades, then run the 4 modes × ≥10 interleaved runs (EXP-2).
2. Configuration fixes for the Nginx-limits mode: `limit_req_log_level warn`, conditional access logging for rejected requests, `limit_req_status 429` + `$limit_req_status` in the log. Then re-measure Nginx CPU.
3. Fix F-45 (GRU-feed stall) and D5 before any further benchmark; re-capture the Tier-1 dataset with D1.

---

## J. EXP-2a — cross-mode comparison at a capacity-limited operating point (approved "proceed", 2026-10-12 13:02–13:17 UTC)

**Why:** EXP-1b/1c showed that with the suite's default over-provisioned server (8 cores, trivial static backend), no attack degrades availability in any mode, so the comparison was uninformative. EXP-1d (calibration sweep) found the knee: the unprotected server only degrades once its backend is capacity-limited. EXP-2a runs the 4-mode comparison at that knee.

**Setup** (`campaigns/run_knee_4modes.sh`, suite copy `d/`): server (nginx + gunicorn) pinned to **cpu0** with a **single gunicorn worker/thread**; attack generators pinned to **cpus 1–7** (so degradation comes from attacker *requests* saturating the one backend worker, not from generator CPU contention); HTTP flood `wrk -c400` from **10 bots**; `ONLY_SCENARIOS=4` (HTTP flood), 3 runs per mode; timestamped daemon-log observer for the protected modes. Verified live: server affinity = cpu0, 10 bots, 30 unique MACs. End state: 0 nginx, 0 netns; /tmp clean copies restored; repo untouched.

### J.1 Result — availability DURING the HTTP flood [FACT]

| Mode | 'during' success (pooled, 3 runs) | per-run | perfect-client latency p50 / p95 | Fisher vs unprotected |
|---|---|---|---|---|
| **XDP + daemon** | **100 %** (n=68) | 100/100/100 | **1 / 147 ms** | p = 0.003 |
| **iptables + daemon** | **100 %** (n=72) | 100/100/100 | **2 / 418 ms** | p = 0.003 |
| nginx limits only (no daemon) | **52 %** (n=113) | 53/53/51 | 3837 / 4613 ms | p = 1.2e-13 |
| unprotected | **90 %** (n=208) | 89/87/93 | 1102 / 6395 ms | — |

* **The daemon (XDP or iptables) restores availability to 100 %** with sub-millisecond median latency, versus 90 % unprotected. This is the first clean, significant demonstration in this project that mitigation preserves legitimate service under attack. [FACT]
* **Rate-limiting alone (no daemon) is *worse* than no protection here: 52 % vs 90 %** (p = 1.2e-13). [FACT] Mechanism, from the server metrics (mean of Phase 2 + 3):

| Mode | nginx CPU (% of cpu0) | PPS reaching server | CPU_Total | daemon CPU |
|---|---|---|---|---|
| XDP | 11 | 10.6 k (3.7 k dropped pre-stack) | 7 % | 3 |
| iptables | 17 | 12.5 k | 10 % | 8 |
| **nginx limits only** | **98** | **34.2 k** | 21 % | 0 |
| unprotected | 34 | 3.7 k | 16 % | 0 |

  The closed-loop `wrk` bots get instant 503s from `limit_req`, so they re-fire immediately → **~9× more requests (34 k vs 3.7 k pps)**, each generating a 503 **plus an access-log line and an `[error] limiting requests` line**. On the single shared cpu0 this saturates nginx (98 %) and starves legit request handling. Unprotected has no such amplification (bots block on the real response), so cpu0 is less contended and legit service is actually better. **Shedding the attacker at L7 without dropping it at the network is counterproductive on a constrained server.**

### J.2 Detection [FACT]
* The **L7 rate heuristic** bans the HTTP-flood bots in **0.19 s (XDP) / 0.34 s (iptables)** median (0.07–0.47 s); a few bots are co-banned by L4 SYN (wrk's connection churn). **GRU: 0 bans. No legit IP banned.** Consistent with EXP-1/1b (the heuristics act long before the GRU accumulates 15 snapshots).
* XDP drops banned-bot packets before the stack (`PreStack_Dropped` 3.7 k; `IP_InReceives` 7.4 k vs iptables 17.3 k). XDP's perfect-client p95 latency is lower than iptables (147 vs 418 ms) — a marginal XDP edge.

### J.3 What this establishes for the thesis
* **Supported now:** at a capacity-limited server, the daemon (XDP or iptables) restores legitimate-client availability from 90 % to 100 % and latency from ~1 s to ~1 ms under an HTTP flood; XDP additionally keeps the flood out of the IP stack and has slightly lower latency than iptables.
* **New, defensible finding:** nginx `limit_req`/`limit_conn` *without* dropping the attacker can reduce availability below the unprotected baseline against a closed-loop flood on a constrained server, because the 503 + logging amplification costs more CPU than it saves. This argues for network-level bans (the daemon) over config-only rate limiting, and motivates the logging fix (§K).

### J.4 Caveats
* One operating point, one scenario (HTTP flood), 3 runs — but per-run variance is tiny (e.g. nginx-limits 53/53/51). Fisher tests pool requests and ignore run/client clustering (negligible here given the spread).
* The capacity limit (1 worker on 1 CPU) is deliberately severe to create a meaningful load; absolute numbers depend on it. The *ordering* (daemon > unprotected > limits-only) is the result, not the exact percentages.
* nginx-limits ran with default `limit_req_log_level error`; §K quantifies how much of its collapse is log I/O.

---

## K. EXP-2b — does nginx logging/status tuning rescue rate-limiting-only? (approved "proceed", 2026-10-12 13:21–13:25 UTC)

**Why:** §J showed nginx-limits-only (52%) was worse than unprotected (90%) at the knee, with the 503s + per-rejection logging as a suspected cause. §K re-runs nginx-limits-only at the same knee with a **tuned config** (`configs/nginx_limits_tuned.conf`, `nginx -t` OK): `limit_req_status 429` / `limit_conn_status 429`, `limit_req_log_level warn` + `error_log … error` (suppress per-rejection error lines), and `access_log … if=$loggable` (skip logging 429s). 3 runs, HTTP flood. Data: `campaigns/2026-10-12_knee_nginxtuned/`.

**Result [FACT]:**

| config | 'during' availability (3 runs) | nginx CPU (% of cpu0) | PPS reaching server |
|---|---|---|---|
| nginx-limits untuned (503, error-log) | 52 % (53/53/51) | 98 | 34.2 k |
| **nginx-limits tuned (429, no rejection log)** | **~62 % (59/78/49)** | **96** | **50.3 k** |
| unprotected | 90 % | 34 | 3.7 k |
| XDP / iptables + daemon | 100 % | 11 / 17 | 10.6 k / 12.5 k |

**Interpretation:** tuning gives only a marginal, noisy improvement (52 % → ~49–78 %) and does **not** approach even the unprotected baseline. nginx CPU stays pegged at ~96 % of the shared core, and PPS actually *rises* (34 k → 50 k) because cheaper 429s + suppressed logging let the closed-loop bots be rejected and re-fire faster. **The bottleneck is the CPU cost of processing/rejecting the amplified request stream on the constrained core, not log I/O.** Logging/status tuning is good hygiene (lower log volume, correct 429 semantics) but cannot fix the availability problem — only dropping the attacker at the network layer (the daemon, XDP or iptables → 100 %) does.

**Thesis takeaway (combining §J + §K):** on a capacity-limited server under a closed-loop L7 flood, the ordering is **daemon (100 %) ≫ unprotected (90 %) > rate-limiting-only (~50–60 %)**. Application-layer rate limiting without a network-level ban is not just insufficient, it is counterproductive here; the control plane's actual contribution is to *drop* the attacker so the server never spends CPU on its requests. This is the clearest argument in the project for the mitigation daemon over config-only defences.

**Caveat:** `limit_req`/`limit_conn` would still help against an *open-loop* attacker (fixed send rate, no re-fire amplification) and against connection exhaustion; this result is specific to closed-loop request floods on a CPU-constrained server. A proper evaluation should include an open-loop generator (e.g. `wrk2 -R<rate>`).

---

## L. F-45 fix — flow_map / GRU-feed stall: implemented and validated (approved "proceed", 2026-10-12)

**Bug (from EXP-1):** on HEAD, 1 of 6 ACK-flood runs stalled the telemetry loop ~10.3 s (daemon at 180–226 % CPU, RSS 460→611 MB), delaying the L4 volumetric bans and producing a 0/5 FAIL. Cause: when a TCP flood (ACK with incrementing source ports) begins mid-poll, the GRU-feed loop iterates the whole 262k-entry LRU `flow_map` and scales every flow before the next poll can ban.

**Magnitude (EXP-5, deterministic — `outputs/exp5_bcc_iter_bench.txt`):** one BCC `flow_map.items()` pass costs **1.04 s at 262k entries** (10k→0.03 s, 50k→0.20 s); `items_lookup_batch()` is ~7× faster (0.15 s). At ~0.13 ms scaler.transform per flow, featurising a full map adds tens of seconds — matching the observed stall.

**Fix (`patches/F45_gru_feed_stall.diff`, verified):**
1. Arm volumetric suppression from the **current** poll's aggregate deltas *before* the feed (not only the previous poll's), so a flood that begins mid-poll skips the feed immediately.
2. Hard-cap the per-poll feed at `MAX_GRU_FLOWS_PER_POLL = 2000` entries visited (legit traffic has only tens of active flows/poll, so it is never affected). This bounds worst-case feed work to ~8 ms iteration + ~0.25 s scaling instead of 1 s + tens of seconds.

**Validation (`campaigns/2026-10-12_f45/`): patched daemon (suite copy g/ → cp_f45), 6 ACK-flood runs, XDP mode** [FACT]:

| run | bots banned | harness Avg TTM | exact last-ban TTM |
|---|---|---|---|
| 1–6 | **5/5 every run** | 1.11 / 1.16 / 1.13 / 1.16 / 1.74 / 1.28 s | ≤ 0.97 s |

**Max TTM across all 6 patched runs = 0.97 s**, with no run approaching the ~10.3 s stall. vs the HEAD baseline (1/6 stalled at 10.32 s, 0/5 FAIL). The patched daemon loaded and ran correctly from the non-repo path (XDP compiled, model/scaler loaded, all threads started). **F-45 fix confirmed.** Recommend also switching the periodic map reads to `items_lookup_batch()` (7× faster) and implementing D5 (time-normalised rates) — both carried as verified/snippet patches, not applied.

---

## M. Summary of the 2026-10-12 experiment campaign (EXP-0 … F-45)

All runs used copies of the suite/daemon under `/root/project_analysis/patches/work/`; the repository's tracked files were never modified. Data in `campaigns/2026-10-12_*`, analysis in `outputs/`, charts in `charts/`, verified patches in `patches/`.

| Finding | Evidence |
|---|---|
| Testbed duplicate-MAC defect is real and dominates flood results | EXP-0 (reproduced), EXP-1 (32–36 %→100 % with unique MACs) |
| With correct L2 + default over-provisioned server, no attack degrades availability in any mode | EXP-1b/1c (100 % incl. unprotected) |
| The availability metric only discriminates once the server is capacity-limited | EXP-1d sweep (knee at 1 worker/1 CPU, wrk-c400, 10 bots) |
| **At the knee, the daemon (XDP/iptables) restores availability 90 %→100 % and latency ~1 s→~1 ms** | EXP-2a (Fisher p=0.003) |
| **Rate-limiting alone is worse than no protection (52 % vs 90 %) against a closed-loop flood on a constrained server** | EXP-2a + EXP-2b (CPU-bound, not logging) |
| XDP ≈ iptables on availability; XDP drops pre-stack and has lower latency | EXP-1b, EXP-2a |
| GRU bans nothing once the heuristics act (<0.5 s); no legit bans | EXP-1/1b/2a (0 GRU bans in 450+ bot-scenarios) |
| F-45 GRU-feed stall is fixed and validated | EXP-5 + §L (6/6 ACK runs, max 0.97 s TTM) |
| The ping-based FP check yields false FPs | EXP-1/1b (FP reported with 0 bans in daemon log) |

**Applied since this campaign:** D1+D2 (unique veth MAC + nginx restart/orphan cleanup) and F-45 (GRU-feed stall cap) are committed and merged to `main` (commit `51cc21c`); both files compile and the XDP program passes the BPF verifier.

**Still open / recommended (not yet done):** ≥10 interleaved runs per mode at the knee (§J) for publication-grade confidence intervals; an open-loop attacker (`wrk2 -R`) to test rate-limiting in its intended regime; a realistic benign mix (keep-alive / HTTPS / HTTP2 / NAT) and held-out attack families for the ML re-capture; the remaining engineering patches carried as verified diffs but **not** applied (D5 time-normalised rates, `items_lookup_batch()` map reads); and re-capturing the Tier-1 dataset on the fixed (unique-MAC) testbed.
