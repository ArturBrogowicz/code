# EXP-C protocol, written down before the blocks run

**Status (2026-10-23): proposed with the run command, committed before the first block.** The experiment is
`docs/BENCHMARK_HARM_DESIGN.md` 8.5 (on `design/benchmark-harm`): EXP-A's design on EXP-A's server with only the
attacker's load model changed. This file fixes what that section leaves open: the three open-loop rates, how they
sit against the per-IP rules, how each hypothesis is read, and what is reported whatever the outcome. The tools are
`docs/EXPC_ATTACKER_SETTING_DESIGN.md` (the setting, the probe, amendment A) and `eval/` (`docs/EVALUATION.md`).
Tags: **[FACT]** from the code or a published file; **[ARITHMETIC]** computed from them; **[RULE]** fixed here.

## 1. Design

* **Server and attack:** the knee operating point (one gunicorn worker with one thread on CPU 0; 10 bots on CPUs
  1-7), scenario 4 (HTTP flood), 30 s in every mode (`--attack-duration 30`), as `results/2026-10-20_expa-knee-10-blocks/`.
* **Modes (3):** `unprotected`, `nginxlimits` (Nginx `limit_req` and `limit_conn` only), `xdp` (daemon + XDP).
* **Load models, the cells (4):** `wrk` (closed loop, `-c400` per bot, EXP-A's) and the in-repo open-loop engine
  `bench/loadgen.py` (verified, constant schedule) at **125, 250 and 500 requests/s per bot**, i.e. 1,250, 2,500 and
  5,000 in total. The rates are the user's decision of 2026-10-23: amendment A's default, 0.5, 1 and 2 x R50, with R50 =
  2,501 requests/s in total (`results/2026-10-23_expc-r50-refinement/`).
* **Blocks (10):** `PROFILE_SEED` 101-110, the legit clients of EXP-A's blocks 1-10; every block runs the 12
  (mode, cell) pairs once in a random order (`--order-seed 0`). 120 runs.
* **The `wrk` cell replicates EXP-A** with the same seeds and settings (the `wrk` command is pinned by a test; the
  suite code has changed since, `docs/EXPC_ATTACKER_SETTING_DESIGN.md`).

## 2. The rates against the per-IP rules (design 8.5: written down before the blocks run)

Nginx: `limit_req` 30 r/s with `burst=100 nodelay` and `limit_conn` 50 per source address. Daemon: the L7 rate rule
bans a source above `HEURISTIC_MAX_RPS` = 50 requests/s over a 10 s window. **[FACT]**

| Per bot | x `limit_req` rate | x L7 rule | Burst used up after | Rejected by `limit_req` afterwards |
|---|---|---|---|---|
| 125 | 4.2 | 2.5 | 1.05 s | 76 % |
| 250 | 8.3 | 5.0 | 0.45 s | 88 % |
| 500 | 16.7 | 10.0 | 0.21 s | 94 % |

**[ARITHMETIC]** (burst / (rate - 30); (rate - 30) / rate). All three cells are above both rules, so EXP-C answers the
**amplification** question (does a closed-loop attacker speeding up when rejected explain limits-only's -22.5 pp in
EXP-A) and not the sub-threshold question, which needs more sources (design 9). The file access log has no `lreq`
field; a 503 is a `limit_req` or `limit_conn` rejection and is counted as such.

## 3. How each result is read **[RULE]**

* **The decision rule is `eval/run_level_stats.py`'s, unchanged** (fixed 2026-10-20, before EXP-A): a paired contrast is
  *supported* iff it has at least 10 blocks, the 95 % t-interval of the mean block difference excludes 0 and at least 80 %
  of the blocks have the sign of the mean; otherwise it is *not shown*, which is not evidence of no effect.
* **The outcome** is the legit success in the suite's "during" period, as in EXP-A (correct for open-loop floods since
  `78122bc`); the first 10 s after the attack start (`analysis/window.csv`) is reported next to it.
* **Contrasts** are drawn inside a cell, against that cell's unprotected arm: `xdp - unprotected` and
  `nginxlimits - unprotected` in each of the 4 cells, 8 in all, paired by `PROFILE_SEED`. None is adjusted for the
  number of contrasts; all 8 are reported.
* **A cell is harmed** iff its unprotected arm averages below 90 % over the 10 blocks (`run_level_stats.HARM_BELOW_PCT`;
  ten blocks certify a harm of about 10 pp, design 11). In a cell that is not harmed the contrasts are still reported:
  a positive one cannot show a benefit there, a negative one is collateral damage.
* **HYP-5** (design 6.4: at the same open-loop rate limits-only is no worse than unprotected). In a harmed open-loop
  cell it is **contradicted** iff `nginxlimits - unprotected` is "supported (-)"; otherwise it is consistent with the
  data, which for "not shown" means only that no difference was detected, and the interval says how large one could be.
* **HYP-6** (the daemon's advantage persists where the per-bot rate exceeds 50 rps, here every open-loop cell). In a
  harmed open-loop cell it **holds** iff `xdp - unprotected` is "supported (+)"; it fails if "not shown" or "supported (-)".
* **The closed-loop cell** is reported next to EXP-A's intervals (xdp +33.2 pp [+26.1, +40.2], limits only -22.5 pp
  [-32.0, -13.1]); there is no rule for "replicates".
* **Reported whatever happens:** the 8 contrasts, the harm status of every cell, the offered load at the server
  (`offered.csv`), Nginx CPU and `PPS_Rx` (`server.csv`), latency of the served requests (`latency.csv`), the 503 and 499
  counts, the daemon's time to mitigate (`detection.csv`), and every run that failed.

## 4. Validity and what is not known

* **[FACT]** The generators are killed before they write a summary, so what they sent is not recorded. The server's log
  holds 97-99 % of the nominal count up to 190 per bot and 82, 63, 49 and 20 % at 230, 270, 320 and 640 per bot
  (`results/2026-10-23_expc-r50-refinement/`). For the 250 and 500 cells the nominal rate is the schedule, unverified at
  the sender, and `offered.csv` is a floor. The design's server-side check (8.3: the log within 5 % of the requests
  sent) can only be made against the nominal count, and only below the limit.
* The engine's request carries about 35 bytes more than `wrk`'s; one VM, whose idle vCPUs wake late; one legit
  profile per block; R50 came from one run per rate. A longer flood would move R50 down.
* The runner records each run's exit code and goes on; only a testbed left behind stops it. While it runs, every run is
  watched, and a non-zero exit code, a leftover, or a flood that did not start (the launch check) stops the campaign
  and is reported to the user. A stopped campaign resumes from `campaign.json`: a run without `DONE` is removed and
  repeated, which the report then says.

## 5. Cost **[ARITHMETIC from the probe and the refinement runs]**

Healthy runs take 88-99 s, collapsed ones at 230-270 per bot 99-113 s, one at 640 per bot 395 s (its post-attack check
waited for the server to drain). 120 runs at 95-100 s are 3.2-3.3 h; the unprotected and limits-only runs at 500 per
bot may take longer. Estimate **3.5-5 h**; `--attack-duration 30` fixes the exposure, not the clean-up.

## 6. After the run

    venv/bin/python eval/analyze_campaign.py /var/tmp/ddos_campaigns/<id> --window 10
    venv/bin/python eval/run_level_stats.py /var/tmp/ddos_campaigns/<id> --md contrasts.md --csv contrasts.csv
    venv/bin/python eval/publish_campaign.py /var/tmp/ddos_campaigns/<id> --name <yyyy-mm-dd_expc-...>

`run_level_stats.py` and `analyze_campaign.py` compare inside each cell; `publish_campaign.py` copies
`server_requests.csv` and regenerates the analysis and one figure per cell from the published files.
