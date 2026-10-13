# ML investigation: the GRU engine (2026-10-13)

**Status:** diagnosis complete. It was done offline, with no traffic and no change to the
system. The experimental design (§5) awaits approval before any VM workload.

**Evidence:**
* `ml/diagnosis/report.md`: `ml/diagnose_gru.py` scores the deployed model read-only
  (≈ 15 s).
* `ml/diagnosis/counterfactuals.md`: `ml/counterfactuals.py` retrains models in memory
  with a replica of `train_testbed_gru.py`, whose seed-42 run reproduces the deployed
  weights bit for bit (≈ 7 min on CPU; nothing is saved).
* The published runs in `results/`.

Both scripts are deterministic. **Tags:** [FACT] verified by code, data or a reproducible
computation; [INFERENCE] reasoned.

## 1. Answers in brief

1. **Zero GRU bans.** The GRU never reaches a decision before a heuristic bans the same
   IP, and banned IPs are no longer scored. Its decision rule makes it the slowest engine
   for every attack in the suite. Floods pause it. It cannot see hping3 flows, and it is
   not fed UDP at all. On its own training distribution the model works.
2. **Marginal value.** Not measured yet, and the current suite cannot measure it: every
   attack trips a heuristic first. The only niche left is L7 abuse below the heuristic
   thresholds, and EXP-3 (§5) is designed to measure it.
3. **Generalization.**
   * *R.U.D.Y.:* the model separates classes by request size, a tool fingerprint, not by
     behavior. With only the request size changed, held-out R.U.D.Y. goes from 19–29 % to
     100 % detected. Without the request-size features the model generalizes on this data
     (94–97 %).
   * *CIC-IDS2017:* the out-of-range TCP window pushes every score towards zero. The
     ≈ 0.1 AUC reproduces, but it depends on how benign hosts are sampled (0.115 per host,
     0.52 per flow). With the window moved into range, 95 % of typical benign hosts score
     as attacks: the learned rules point the wrong way there.
4. **Pipeline.** D12 is fixed. The capture and the trainer have further gaps (§4). A
   reproducible capture → train → promote pipeline is proposed (§5).

   **New finding:** the F-45 cap starves the GRU feed in any daemon that runs longer than
   a few minutes (§2.9). It must be fixed before long tests.

## 2. Why the GRU has banned nothing since the MAC fix

**2.1 Census [FACT, report §1].** The published runs cover 28 scenario-runs with the
daemon: 18 knee HTTP-flood runs with 10 bots each, and one full 10-scenario suite (R2).
They hold 232 bans, none by the GRU.
* 13 of the 19 runs have the daemon's complete event log; the other 6 were imported from
  console bans. In those 13, no GRU detection was suppressed either. **The GRU never
  reached a decision**, rather than being overruled.
* The addendum's EXP-1 records agree: 0 GRU bans in 150 bot-scenarios
  (`REPORT_ADDENDUM_EXP0_EXP1.md:105`).

**2.2 How it decides [FACT, `control_plane.py`].**
* The telemetry thread polls every 1 s (`:607`). For each TCP flow that advanced since
  the last poll, it appends one 8-feature snapshot to the source IP's 15-step sequence.
  Once 15 exist, every new snapshot queues a window for inference (`:767-798`).
* Results are drained at the start of the **next** poll (`:612`). A ban needs 3
  consecutive windows with p > 0.95 (`:539-542`).
* Guards on the feed:
  * banned IPs are skipped (`:774`);
  * only TCP is fed (`:771`);
  * at most 2000 flow-table entries are visited per poll (`:769`);
  * during flood suppression nothing is fed (`:755-762`) and no GRU ban is issued
    (`:555-558`).

**2.3 Cause A: it loses every race [FACT, report §2–3].** Replaying this rule with the
deployed model on the Tier-1 capture gives each attacker's earliest possible GRU ban.
Times run from the attacker's launch and include the drain at the next poll. (REPORT.md
§5.2 counted from the first captured row, without the drain, so its times are 2 s
shorter.)

| Attack (capture bot) | Earliest GRU ban | Heuristic ban, same tool in the suite (R2, median) |
|---|---|---|
| HTTP flood, `wrk -c50` | 2 s | 0.55 s (L7 rate) |
| Slowloris, N = 8 | 16 s | 3.72 s (SlowConn) |
| R.U.D.Y., N = 10 | 8 s | 3.57 s (SlowConn) |

Once a heuristic has banned the IP, the GRU stops scoring it, so it can never catch up.

**2.4 Cause B: floods pause it [FACT].**
* A per-IP SYN or volumetric ban re-arms flood suppression at once (`:661`, `:671`).
  Suppression clears the GRU's sequences and stops its feed for a 15-s cooldown
  (`:747-762`).
* In all five flood scenarios of R2, suppression switched on with the first L4 ban
  (+0.48 to +0.97 s after the attack started), and every bot was banned by then.
* Suppression then lasted 15.2–15.6 s (`ban_events.jsonl`).

**2.5 Cause C: blind to hping3 flows [FACT, report §4].**
* All SYN, ACK and fragment floods in the suite use hping3. So does the Low & Slow SYN
  scenario, the one the suite labels "GRU ML Target" (`test_distributed_suite.py:1436`).
* hping3 sends bare packets with a TCP window of 64 and no options. A window of such
  flows scores **p = 0.0003**; the same flow with window 65535 scores 0.9997.
* Every attack row in the training data has window 64240, so 64 lies far outside the
  range the model learned.
* In Low & Slow, each bot opens 10 new flows/s (`test_distributed_suite.py:1442`). Its
  sequence is therefore full after about 1.5 s, roughly 2.5 s before the low-SYN ban at
  3.98 s [INFERENCE from the rate]. Suppression never switched on, yet the GRU logged no
  event [FACT].
* *Refuted hypothesis:* the training data's only low windows are two benign one-packet
  snapshots without payload (window 63, from 10.0.1.7 and 10.0.1.20) [INFERENCE: flow
  entries created by a mid-flow packet, whose window field is scaled]. They do **not**
  cause the blind spot. With every window that contains them removed from training, the
  hping3 probe stays benign over 3 seeds (p ≤ 0.05), as in a control that removes as many
  random benign windows (CF1).

**2.6 Cause D [FACT].** UDP floods are never fed to the GRU (`:771`).

**2.7 What it is not [FACT, report §3].** On its own distribution the model works. In the
replay, 97–100 % of each attacker's windows exceed the threshold, and none of the 24
benign clients (1042 windows) would be banned. Before the MAC fix it was a co-engine in
13 of 60 scenario-runs and never the sole engine (`REPORT.md:498`). The addendum
attributes this to the L2 defect slowing the heuristics (`REPORT_ADDENDUM_EXP0_EXP1.md:75`)
[INFERENCE].

**2.8 The false-positive mechanism [FACT, report §4].** A legit handshake stalled by a
flood (two SYNs 1 s apart, no payload) scores p = 0.9996, as does a Linux client's bare
SYN. This is why load-aware suppression is load-bearing, and why a GRU-only deployment
would ban legit clients during floods.

**2.9 New latent defect: the F-45 cap starves the feed.**
* *Mechanism [FACT]:*
  * The cap counts every *visited* flow-table entry, stale ones included
    (`control_plane.py:767-770`).
  * The daemon never deletes `flow_map` entries (`control_plane.py:343-344`).
  * The kernel evicts an entry only when a new flow needs room in the full LRU table of
    262,144 entries (`xdp_ddos_filter.c:47`).
* *Consequence [INFERENCE]:* once the table holds more than 2000 entries, the feed sees
  only the first 2000 in hash order. A new flow is then scored with probability
  ≈ 2000 / (entries in the table), down to 0.8 % when the table is full.
* *How soon:* legit clients open about 5 new connections/s in the capture's traffic
  (868 benign flows in 170 s) [FACT]. Legit traffic alone therefore crosses 2000 entries
  in about 6.5 minutes, and a port-incrementing flood does so at once [INFERENCE].
* *The read is not bounded either [FACT]:* BCC's `items()` builds the full list of
  entries before the loop starts (`bcc/table.py`). The cap bounds the per-flow feature
  work, not the read itself, which costs 1.04 s at 262 k entries (EXP-5).
* *Why the suite never showed it [FACT]:* the suite starts a fresh daemon, with fresh
  maps, for every scenario (one `start` event per scenario in R2). Any long-running
  deployment would hit it, and so would the soak test proposed in §5.

## 3. Why it generalizes poorly

REPORT.md §5.3 already showed the shortcut: one feature, the maximum request size,
reproduces the GRU's F1 on its own (0.994), and leaving R.U.D.Y. out drops F1 to 0.484.
The counterfactuals below show the mechanism and a remedy.

**3.1 R.U.D.Y. left out [FACT, CF2].** Trained without R.U.D.Y., the model detects
19–29 % of R.U.D.Y. windows (3 seeds). The experiment then changes only the request size
of those windows: the maximum forward payload, with total bytes scaled to match.

| R.U.D.Y. request size | Windows detected (p > 0.95) |
|---|---|
| 51 B, as captured | 19–29 % |
| 36 B (Slowloris-like) | 100 % |
| 34 B (wrk-like) | 100 % |
| 72 B (curl-like) | 2–6 % |

The decision follows request size. R.U.D.Y.'s slow-connection timing, which it shares
with Slowloris, is not enough on its own.

**3.2 Feature hygiene [FACT, CF3].** Same hold-out, 3 seeds, threshold 0.95:

| Feature set | Held-out R.U.D.Y. detected | Benign FP | hping3 probe p | Stalled-handshake p |
|---|---|---|---|---|
| all 8, as deployed | 19–29 % | 0 % | 0.001–0.009 | 0.999 |
| without TCP window | 12–18 % | 0 % | 0.997–0.999 | 0.997–0.999 |
| **without the two request-size features** | **94–97 %** | 0 % | 0.0006–0.0008 | **0.001** |
| without both | 87–98 % | 0 % | 0.0006–0.22 | 0.001–0.016 |

* Dropping the request-size features restores generalization and removes the
  stalled-handshake false positive.
* Dropping only the window makes every SYN-only flow look like an attack.

**Caveat [INFERENCE]:** the only benign traffic in the data is one-shot curl. Without
request size, the model must separate the classes by timing and connection pattern, and
keep-alive browser sessions may then resemble wrk floods. The result must be re-checked
on a diverse benign mix (§5, W4).

**3.3 The slow families reflect nginx, not the tools [FACT].** In the capture, Slowloris
and R.U.D.Y. flows both last about 5 s (median flow lifetime 5.00 s and 5.06 s, report
§5). nginx closes both at that point (`nginx.conf:29-34`):
* Slowloris hits `client_header_timeout 5s`.
* R.U.D.Y. announces `Content-Length: 1000000` (`capture_testbed_dataset.py:96`), above
  `client_max_body_size 64k`. nginx answers 413 and closes about 5 s later.

The "slow attack behavior" the model learned is nginx's timeout behavior.

**3.4 CIC-IDS2017: why the AUC is ≈ 0.1 [FACT, report §6].**
* *The TCP window is out of range.* CIC's median TCP window per traffic type is 118 to
  29,200. The testbed's is 64,240 in all but 2 of 12,729 snapshots. Every CIC window
  therefore scores near zero: 0 % of attack windows and 0.2 % of benign windows exceed
  0.95.
* *The AUC depends on the benign sample.* It only ranks scores that are all near zero.
  * Sampling benign windows per host (400 hosts, ≤ 60 windows each, as in the audit
    behind REPORT.md §4.4)
    gives **0.115**, reproducing the REPORT's figure.
  * Sampling them per flow gives **0.52**. Five internal hosts carry 43 % of those benign
    flows.

  The "≈ 0.1" is therefore not a stable property of the model.
* *With the window in range, the learned rules point the wrong way.* With every window
  set to 64240:
  * 95 % of per-host benign windows score above 0.95;
  * only 31 % of attack windows do (DDoS 81 %, Slowhttptest 39 %, Hulk 29 %, slowloris
    7 %, GoldenEye 0.2 %);
  * the per-host AUC falls to 0.06.
* *Why:*
  * Three of the eight features reverse direction between the datasets (IAT mean,
    packets/s, total length). In CIC, ordinary clients send faster and more than the
    attack flows do.
  * The request-size cue carries no signal in CIC (AUC 0.47). Large requests (GoldenEye
    370 B, Hulk 325 B) look even more benign to the model than curl [INFERENCE].
  * CIC's features describe completed bidirectional flows (CICFlowMeter), not live
    forward snapshots, so the same names do not mean the same measurements [INFERENCE].

## 4. Dataset and pipeline gaps (static analysis)

**Capture (`capture_testbed_dataset.py`)**

| # | Gap | Where |
|---|---|---|
| C1 | **Fixed (D12).** The attack scripts were written to another session's tmpfs scratchpad, so the capture crashed after any reboot. They now go to a private temporary directory that is removed at exit, and a static test guards this (`tests/test_capture_static.py`). | `:49-53` |
| C2 | Generic (SKB) XDP mode, while the daemon uses native mode. | `:158`, `:206` |
| C3 | One 170-s capture with one IP per family and intensity (6 bots), unseeded sampling of 80 attack rows per poll, and no manifest. The output overwrites `training_data/testbed_flows.csv`. | `:45-48`, `:165-172`, `:199-200`, `:214` |
| C4 | Benign traffic is one-shot curl only: 72-B requests, one OS, one TCP window. | `:162`; REPORT.md §5.1 |
| C5 | Attacks run unmitigated for 150 s, so the model learns steady-state flows, while deployment decides at onset. | `:166-171` |
| C6 | nginx rejects R.U.D.Y. (413), so there is no real slow-body attack. | `:96`; `nginx.conf:34` |
| C7 | Two benign snapshots carry a mid-flow window of 63 [INFERENCE: entry re-created mid-flow]. | §2.5 |
| C8 | Recorded on the duplicate-MAC L2. New captures inherit D1, because the capture builds the suite's topology. | `:31` |

**Trainer (`train_testbed_gru.py`)**

| # | Gap | Where |
|---|---|---|
| T1 | IP-to-split assignment is hard-coded: the test split has 2 attacker IPs and validation has 1 (95 % CI on IP-level recall: 16–100 %). | `:46-53` |
| T2 | Evaluation uses p ≥ 0.5; deployment uses p > 0.95 three times in a row. | `:100` |
| T3 | The model is selected by `f1 >= best` on a single validation attacker. | `:109` |
| T4 | Windows overlap (stride 1, thinned evenly to 800 per IP), so the window count overstates the independent evidence. The unit of evidence is the IP. | `:67-74` |
| T5 | It overwrites the deployed model, scaler and config. | `:23-24`, `:124` |
| T6 | There is no leave-one-family-out evaluation, no probe battery and no IP-level confidence interval. | n/a |
| T7 | The docstring claims the TCP window is constant. | `:9` |

## 5. Proposed experimental design (for approval)

### Phase A: code, no VM workload
* **A1. `HEURISTICS_ONLY=1`.** The mirror of `GRU_ONLY` (`control_plane.py:61`): the GRU
  still scores and logs but never bans.
* **A2. GRU telemetry.** One `gru_poll` event per poll recording entries visited,
  snapshots fed, windows scored, windows above the threshold, and the top IPs by maximum
  p with their hit streak. This makes the GRU observable even when it does not ban, and
  measures §2.9 directly.
* **A3. Arms in the campaign runner.** New modes `xdp-gru-only` and
  `xdp-heuristics-only` in `eval/run_campaign.py`, with the switches recorded in the
  provenance. The three arms then interleave in one campaign, paired by `PROFILE_SEED`,
  and `ONLY_SCENARIOS` (which already exists) selects the scenarios.
* **A4. New scenarios** (60-s exposure each):
  * **S11:** HTTP flood *below* the L7 threshold, about 20 rps per bot over 4 keep-alive
    connections (`wrk` with a Lua `delay()`; no new tools).
  * **S12:** Slowloris with 6 sockets, below SlowConn's 8.
  * **S13:** a real slow-body R.U.D.Y. (`Content-Length` 60000, 1 B every 4 s, 6
    sockets) that nginx does not reject.
  * **S14:** S11 with padded requests of about 450 B, to test fingerprint evasion.
  * **S15:** benign soak: no attack for 10 min, with a 30-s SYN flood midway.
* **A5. Capture v2 (`ml/capture.py`):**
  * a CLI with seeds, native XDP, a provenance manifest and an attack-schedule log
    (ground-truth start and stop per bot);
  * at least 5 IPs per family;
  * a benign mix of one-shot curl, keep-alive sessions, varied request sizes and headers,
    and varied TCP windows per namespace;
  * attack families at several rates, including below the thresholds, a real slow-body
    R.U.D.Y., and held-out families kept for evaluation only;
  * output to a new dataset directory, never over the existing file.
* **A6. Trainer v2 (`ml/train.py`):**
  * reads dataset manifests and writes a model package with a model card; it never
    touches `training_results/`;
  * splits grouped by IP and capture, plus leave-one-family-out;
  * metrics at the deployed policy: per-IP detection with Clopper-Pearson CIs, time to
    detect, false positives per benign client-hour;
  * the probes of §2.5 and §2.8 as regression tests, loss-based model selection, and
    feature-set variants.
* **A7. `ml/promote.py`.** A manual, approval-gated step that installs a vetted model into
  `training_results/` with hashes and metrics.
* **A8. Feed fix (§2.9; a prerequisite for W2).**
  * Read the table in one batch (`items_lookup_batch()`, 0.15 s at 262 k, EXP-5).
  * Count only flows that advanced towards the cap.
  * Age out dead entries, so that the feed tracks active flows rather than the table's
    history.

### Phase B: VM workloads (each needs your go-ahead)

| ID | Workload | Duration | Answers |
|---|---|---|---|
| W0 | Regression: full suite, defaults, after A1, A2 and A8 | ≈ 12 min | Are the heuristics' results unchanged vs R2? |
| W1 | EXP-3 pilot: 3 arms × 3 paired runs × {S2, S4, S7, S8, S9, S11–S14}, current model | ≈ 2 h | Marginal value, GRU-only time to detect, online fingerprint dependence |
| W2 | Benign soak S15, GRU-only and hybrid, 3 runs each | ≈ 40 min | False positives per client-hour; does suppression prevent the stalled-handshake FP? |
| W3 | Capture v2 smoke test (one 3-min capture) | ≈ 15 min | Do the benign-diversity knobs work, and are the manifest and schedule complete? |
| W4 | Re-capture: 5 seeded captures × ~10 min | ≈ 1 h | The retraining dataset; training then runs offline, CPU only |
| W5 | EXP-3 with a retrained candidate (not promoted) | ≈ 2 h | Does the candidate generalize online without new false positives? |

### Pre-registered hypotheses and decisions
* **H1, the niche.** In S11–S13, heuristics-only bans 0 of 5 bots, while GRU-only and
  hybrid ban at least 4 of 5 within the 60-s exposure.
  * If H1 holds, the GRU has measurable marginal value below the thresholds. The thesis
    should then also ask whether lower heuristic thresholds would do the same.
  * If it fails, the thesis presents the GRU as an experimental, non-contributing
    component.
* **H2, fingerprint dependence online.** The current model detects markedly fewer bots in
  S14 (padded requests) than in S11.
* **H3, false positives.** GRU-only produces 0 false positives in the benign soak, and
  the hybrid stays at 0 through the SYN flood, thanks to suppression.
* **H4, retraining.** A candidate without the request-size features:
  * detects held-out families at ≥ 80 % (IP level);
  * has false positives at most equal to the current model's on the diverse benign mix;
  * passes the probe battery.

  Only then is promotion (A7) proposed.

### Guards (as in the previous milestones)
* Work stays on the feature branch, and no detection thresholds change.
* Results go to `/var/tmp`; only published campaigns enter `results/`.
* Captured datasets get manifests and SHA-256 hashes.
* The deployed model changes only through A7, with your approval.
* Every VM workload above runs only after explicit approval.
