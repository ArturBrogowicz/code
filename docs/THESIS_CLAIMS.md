# What the thesis can claim

**Status (2026-10-20).** Written after the second independent review (2026-10-19). The review
re-ran every published analysis, verdict report and model and reproduced them bit for bit, so
no published number is retracted. This page fixes the *wording*. For each claim it gives the
strongest sentence the evidence supports, the evidence, what the evidence does not show, and
what would settle the rest. It is a recommendation for the thesis text; the framing is the
author's call.

**Updated after the three VM runs of 2026-10-20** (the full suite on the new defaults, EXP-B and
EXP-A; `results/2026-10-20_*`). M4 moved from inconclusive to supported with scope; M2, M3, M6, M7
and L4 gained evidence; M1 now rests on four complete runs.

**Updated 2026-10-21** with the prototype campaigns of 2026-10-12, now published
(`results/2026-10-12_*_prototype`, `results/2026-10-12_exp1d-calibration-sweep_raw`) and compared
number by number with the addendum (`results/2026-10-21_prototype-claims-check/`: 139 comparisons,
129 match, 4 differ, 6 cannot be checked). M1 and M2 lose their [CLAIMED] items and gain evidence;
Q1 loses its first limit. No verdict changes; M2's enforcement-latency half is scoped to the HTTP flood.
The ban-event census of the audit-derived directory includes the prototype campaigns since the same
day: 52 distinct logs and 710 bans, still one GRU ban (L1, M5).

**Updated 2026-10-23** with EXP-C, the open-loop attacker (`results/2026-10-23_expc-open-vs-closed-loop/`,
120 runs). M4 is now scoped to the closed-loop attacker: against an open-loop one, at the rates tried, the
evidence points the other way. M3's advantage of the daemon holds against both attackers. No other verdict changes.

**Tags.** **[FACT]** recomputed from files in this repository (paths given). **[INFERENCE]**
reasoned from code or design, not measured. **[CLAIMED]** stated in an earlier document with no
data in `results/`. **[NOT RUN]** needs a VM workload and explicit approval.

**Verdicts.** *Supported*: holds as worded. *Supported with scope*: holds only in the stated
setting. *Partly supported*: one half holds. *Inconclusive*: the data cannot decide.
*Not supported*: no evidence for it. *Contradicted*: the evidence points the other way.

| # | Claim | Verdict |
|---|---|---|
| M1 | The rules ban all 10 testbed attack types, and XDP enforces the bans | Supported with scope |
| M2 | XDP outperforms iptables | Partly supported |
| M3 | The daemon preserves availability under an HTTP flood | Supported with scope |
| M4 | Rate limiting alone is harmful | Supported with scope (closed-loop attacker only) |
| M5 | Zero false positives | Contradicted as a general claim |
| M6 | Time to mitigate is X seconds | Supported as bounds per rule |
| M7 | Slow attacks are mitigated | Not supported |
| L1 | The XDP-fed GRU adds detection value | Contradicted |
| L2 | The Nginx-log GRU adds detection value | Not supported |
| L3 | A sequence model is needed | Not supported |
| L4 | Static thresholds face a collateral-damage-versus-evasion dilemma | Partly supported; scope it |
| Q1 | The results are reproducible | Supported for what is published |
| Q2 | The L7 track was pre-registered | Supported with scope |

Numbers below come from `results/`; "the audit-derived directory" is
`results/2026-10-20_audit-derived/`. The four complete suite runs at the default profile are
`2026-10-13_regression-default-full-suite` (R2),
`2026-10-13_regression-default-full-suite-replicate`,
`2026-10-19_baseline-before-audit-defaults` and `2026-10-20_regression-after-audit-defaults`
(the first run on the change set of 2026-10-19). `2026-10-20_expb-tolerant-profile-suite` holds
three more complete runs under the tolerant profile, and `2026-10-20_expa-knee-10-blocks` is EXP-A.

## Mitigation claims

### M1. The rules ban all 10 testbed attack types, and XDP enforces the bans

**Verdict: supported with scope.**

**Wording.** "At the suite's default operating point, with 5 bots per scenario, the daemon's
rules banned all 5 bots in each of 10 attack scenarios, in each of four complete runs (the last
on the change set of 2026-10-19), and no legitimate client was banned. The bans are enforced in
XDP; the detection is done by the L4 and L7 rules."

**Evidence [FACT].** In the four `scenario_results.csv`, `Banned_Events` equals `Bots` (5) in
all 40 scenario-runs, `Result` is PASS, `FP_IPs` is empty, and the HTTP check from 15 sampled
legitimate clients after each scenario (3 attempts each) passed (15/15). By engine, over all
four runs, the 200 bans are `l4_volumetric` 72, `l7_rate` 44, `l4_slowconn` 40, `l4_syn` 24,
`l4_lowsyn` 20. The post-change run (`2026-10-20_regression-after-audit-defaults`) has
`xdp_gru: false` and the new XDP program in its `start` events and the same engine in every
scenario as the three runs before it. Under the tolerant profile 8 of the 10 scenarios stay at
5/5 (M7).

The three XDP runs of `2026-10-12_exp1-default-4modes_prototype` (an older code state with the
XDP-fed GRU on, recorded with the prototype harness) agree: ban events show all 5 bots banned in each
of the 30 scenario-runs, with the same engines, no legitimate client banned and no GRU ban among 150
first bans. One ACK flood was banned only 10.32 s after its start (finding F-45, since fixed): the
harness reported 0/5 and FAIL.

**It does not show.**
* Detection by anything other than the rules: no GRU ban occurs in these runs.
* Harm without mitigation. At the default point every mode, unprotected included, served 100 % of
  the legitimate requests started during the attacks (17,363 requests, one failed: an unprotected
  UDP-flood request) [FACT, `results/2026-10-12_exp1-default-4modes_prototype`; addendum §H.1 and
  §I.1, reproduced]. There is no harm to prevent at that point: "mitigates" here means "bans".
  Service is protected only at the knee (M3).
* Attacks away from the calibration points (other rates, socket counts, ports), or more than
  four runs.

**Would settle it.** More runs; variants away from the calibration points; harm measured at a
calibrated operating point per scenario.

### M2. XDP outperforms iptables

**Verdict: partly supported.** Enforcement latency for the HTTP flood (ten blocks, post hoc) and
packet drop before the IP stack: yes. Availability: no difference. Enforcement latency in the other
scenarios of the full suite: no consistent difference.

**Wording.** "At the HTTP-flood knee, XDP and iptables both kept legitimate success at 100 % in
every run (19 runs each). XDP banned the flood's bots sooner: 0.075 s on average per block in the
ten blocks of EXP-A [+0.030, +0.120], 0.09-0.17 s in the three earlier campaigns. The latency of
answered requests did not differ consistently. In volumetric floods XDP drops the packets before
the IP stack."

**Evidence [FACT].**
* Median time to mitigate, XDP against iptables, in the three knee campaigns
  (`analysis/detection.csv`): 0.217 against 0.311 s (`2026-10-12_exp2a-knee_prototype`),
  0.198 against 0.336 s (`2026-10-13_exp2a-knee_reproduction`), 0.188 against 0.357 s
  (`2026-10-13_exp2a-knee_equal-exposure-30s`). All 30 bots were banned in both modes every time.
* EXP-A (`2026-10-20_expa-knee-10-blocks`): median time to mitigate per block, XDP 0.215 s and
  iptables 0.290 s on average over 10 blocks, XDP faster in 8 of them, mean difference +0.075 s
  [+0.030, +0.120]; all 200 bots banned. Post hoc and descriptive: the pre-registered rule covers
  availability only.
* p95 latency of answered requests during the attack (`analysis/latency.csv`, all profiles): 358,
  344, 464 and 602 ms for XDP against 447, 489, 446 and 612 ms for iptables (the three earlier
  campaigns, then EXP-A): lower for XDP in three of four, higher in R4, 2 % apart in EXP-A.
* Pre-stack drop (`2026-10-13_regression-default-full-suite/metrics.csv`, post-ban and sustained
  phases): the UDP, ACK, IP-fragmentation and multi-vector scenarios put 0.84-1.66 M packets/s
  on the server interface while `IP_InReceives` stayed at or below 227 packets/s and
  `PreStack_Dropped` was within 0.02 % of `PPS_Rx`.
* The same full suite with iptables as the backend, recorded with the prototype harness
  (`2026-10-12_exp1-default-4modes_prototype`, three runs per mode, an older code state): in the UDP,
  ACK and fragmentation floods iptables and unprotected passed 1.07-1.44 M packets/s into the IP
  layer, against 108-199 k/s for XDP (mean of Phases 2, 2A (2/3) and 3) and 147-169 packets/s in its
  sustained phases, with 1.24-1.36 M/s dropped before the stack (`2026-10-21_prototype-claims-check`,
  rows H-14 to H-16 and C-20).
* Outside the HTTP flood, neither backend is consistently faster to ban in that suite. The median
  time to mitigate is lower with XDP in 5 of the 10 scenarios (SYN flood, Low & Slow SYN, UDP flood,
  HTTP flood, Yo-Yo) and lower with iptables in the other 5 (ACK flood, fragmentation, Slowloris,
  R.U.D.Y., multi-vector), by 0.04-0.74 s, from three unpaired runs per mode. Legitimate success is
  100 % in both modes in all ten scenarios.

**It does not show.**
* The cause of the 0.08-0.17 s difference. Plausibly the serial `iptables` calls against a map
  update [INFERENCE]. Nor that the advantage holds beyond the HTTP flood (see the last evidence
  bullet).
* The pre-stack comparison on the current code and harness: it comes from the prototype harness
  (three runs per mode, 2026-10-12), not from `eval/run_campaign.py`.
* The effect on a physical NIC. The testbed uses veth pairs.

### M3. The daemon preserves availability under an HTTP flood

**Verdict: supported with scope** (one scenario, one operating point; a closed-loop and an open-loop attacker).

**Wording.** "At the HTTP-flood knee, legitimate success during the attack was 100 % with the
daemon (XDP or iptables) in all 19 runs of four campaigns, and between 50 % and 93 % unprotected.
In EXP-A, ten paired blocks, the daemon served 33.2 pp more than no protection [+26.1, +40.2], with
the same sign in 10 of 10 blocks."

**Evidence [FACT]** (`analysis/availability.csv`, success during the attack, per run):

| Campaign | xdp | iptables | Nginx limits only | unprotected |
|---|---|---|---|---|
| EXP-2a prototype (10-12) | 100/100/100 | 100/100/100 | 53/53/51 | 89/87/93 |
| R3 reproduction (10-13) | 100/100/100 | 100/100/100 | 73/78/67 | 67/88/82 |
| R4 equal exposure, 30 s (10-13) | 100/100/100 | 100/100/100 | 33/34/44 | 60/92/64 |
| EXP-A, 10 blocks (10-20) | 100 in all 10 | 100 in all 10 | 32/56/38/34/33/50/38/48/67/48 | 50/63/72/65/78/67/75/57/81/60 |

Run-level contrasts, daemon minus unprotected (audit-derived directory, `run_level_*.md`): R3
+21.0 pp [-5.5, +47.4], R4 +28.0 pp [-15.3, +71.3] (paired by `PROFILE_SEED`, 3 blocks each);
EXP-2a +10.2 pp [+2.7, +17.6] (unpaired, 3 against 3); **EXP-A +33.2 pp [+26.1, +40.2], 10
paired blocks, same sign in 10 of 10, exact sign-flip p = 0.002, decision "supported (+)"** under the
rule of `eval/run_level_stats.py`, which was committed (8d26335) six hours before the first run.

**Size and scope.** The size is estimated by EXP-A: +33.2 pp at this operating point, for this
scenario and this attacker. The three-block campaigns are consistent with it and do not decide.
Nine of the earlier runs are not nine independent blocks (R3 and R4 reuse the same three
`PROFILE_SEED`s, EXP-2a was unseeded), so the review draft's sign test over them ("p = 0.002")
stays withdrawn; the ten blocks of EXP-A are independent.

**EXP-C [FACT]** (`2026-10-23_expc-open-vs-closed-loop`, same server, same ten `PROFILE_SEED`s, 10 paired
blocks): against an open-loop attacker at 250 and 500 requests/s per bot, where the unprotected server served
42.1 % and 11.4 %, the daemon served 100 % in every block, +57.9 pp [+52.6, +63.2] and +88.6 pp [+84.7, +92.5]
("supported (+)", 10 of 10 blocks each); at 125 per bot the unprotected server was not harmed (100 %), so
there was nothing to show. In the closed-loop cell of that campaign the daemon was +22.5 pp [+16.0, +29.0].
Nothing here covers other scenarios, other operating points, an adaptive attacker, or rates below the
per-source rules (EXP-C's lowest rate is 2.5 times the daemon's 50 rps rule).

**Would settle the rest.** Other attack scenarios at their own calibrated knees (the knee is
calibrated for the HTTP flood only), rates below the per-source thresholds from more sources, and an
adaptive attacker.

### M4. Rate limiting alone is harmful

**Verdict: supported with scope (a closed-loop attacker only); contradicted for an open-loop attacker at the
rates tried.** It was inconclusive until EXP-A, and EXP-C (2026-10-23) showed where the harm comes from.

**Wording.** "Against a closed-loop attacker (`wrk`, 400 connections per bot), Nginx `limit_req` and `limit_conn`
alone left legitimate success during the knee flood 22.5 pp below no protection at all in EXP-A (44.4 % against
66.8 % on average; 95 % interval [-32.0, -13.1], the same sign in 10 of 10 blocks) and 34.3 pp below in EXP-C
[-45.4, -23.2]. Against an open-loop attacker at 125, 250 and 500 requests/s per bot the same limits served 100 % in
every block, 57.9 pp (250) and 88.6 pp (500) more than no protection where the unprotected server was harmed. The
penalty belongs to the closed-loop attacker, which sent 29.6 k requests/s into `limit_req`, almost all rejected with
503, against 1.6 k/s without it."

**Evidence [FACT].** The table in M3; `analysis/summary.md` and `run_level_*.md` of
`2026-10-20_expa-knee-10-blocks`: limits only against unprotected -22.5 pp [-32.0, -13.1],
"supported (-)"; daemon against limits only +55.7 pp [+47.5, +63.9]. The three-run campaigns before
it (-37.6 pp unpaired, -6.4 [-33.8, +21.0] in R3, -34.9 [-85.4, +15.7] in R4) disagreed on the
size and did not decide; ten blocks put it at about -22 pp. The report's estimate of 26 blocks
came from R3's small effect; at -22.5 pp the power calculation gives 5. The requests it answered in
EXP-A were far slower (all-client median 6.6 s against 1.0 s) and its Nginx CPU was 96 % against 33 %.

EXP-C (`2026-10-23_expc-open-vs-closed-loop`, same server and legit profiles, 10 paired blocks), limits only
against unprotected: closed loop (`wrk`) -34.3 pp [-45.4, -23.2], "supported (-)", unprotected arm 77.5 % (EXP-A:
66.8 %); open loop 125 per bot 0.0 pp, "not shown" (nothing to harm: unprotected 100 %); 250 per bot +57.9 pp
[+52.6, +63.2] and 500 per bot +88.6 pp [+84.7, +92.5], "supported (+)", 10 of 10 blocks each. At the server, request
lines per second logged by Nginx (by arrival): limits only under `wrk` 29,638 (29,585 of them 503) with `PPS_Rx`
34,688, unprotected 1,605 and 4,540 (EXP-A: `PPS_Rx` 33,440 against 3,303); under the open-loop attacker 1,214, 2,446
and 4,859, 97 % of the nominal rates, with `PPS_Rx` 1,441, 2,951 and 6,263. `limit_req` admits about 330 requests/s
from ten sources (30 r/s each plus a burst of 100); Nginx answered 283-325 per second with 200 and rejected the rest.
The rejections are not free: Nginx CPU 82 % at 500 per bot and a median of 642 ms for the perfect clients, against
0 % and 1 ms under the daemon.

**It does not show** that limits alone are safe in general. The open-loop attacker does not adapt, and all three
rates are 4.2 to 16.7 times the `limit_req` rate, so rates below 30 r/s per source, many more sources, and a botnet
that speeds up when rejected are not covered. Whether `wrk` or a constant-rate generator is the better model of a real
botnet is a choice for the thesis, not something measured here. Nor does it show that limits and the daemon are
equal: both served 100 % in every open-loop block (a ceiling), and they differ in latency and Nginx load. Other
operating points are untested.

**Would settle the rest.** Sub-threshold rates from many more sources (`docs/BENCHMARK_HARM_DESIGN.md` section 9),
other operating points, and an adaptive attacker.

### M5. Zero false positives

**Verdict: contradicted as a general claim.** True for the suite's benign mix only.

**Wording.** "No legitimate client was banned in the suite's 70 scenario-runs (seven complete runs,
default and tolerant profile), whose benign traffic is one-shot `curl` requests. With realistic
clients the default deterministic rules banned three of them, and the only ban the XDP-fed GRU
made in the recorded ban-event logs hit a legitimate client."

**Evidence [FACT].** `events_census.md` in the audit-derived directory lists 4 bans of legitimate
clients in 52 distinct ban-event logs (710 bans): in `2026-10-16_l7-p5c-baseline` a browser with a 60-asset
page (10.0.1.16, `l7_rate` at 7.0 s) and two carrier-grade NAT gateways (10.0.1.17 and 10.0.1.18,
`l4_slowconn`); in `2026-10-20_omitted-runs/p1_smoke_20261014T152428Z` client 10.0.1.6 by the GRU
(p = 0.999013, 127 s after the daemon started, 56 s after the burst's bans).

**It does not show** a false-positive rate: the logs do not record how much benign exposure each
run had.

### M6. Time to mitigate

**Verdict: supported as bounds per rule, not as one number.**

**Wording.** "Per bot, the L7 rate rule banned in 0.06-1.13 s, the L4 volumetric rule in
0.41-1.25 s, the L4 SYN rule in 0.50-3.82 s (0.50-1.97 s but for one bot), and the SlowConn and
low-SYN rules in 3.5-4.7 s. The slow-rule times are set by the number of consecutive one-second
polls the rule requires (3 and 4), plus where in the poll the attack began."

**Evidence [FACT]** (`TTM_Exact_By_Bot` and `Engine_By_Bot` in the `scenario_results.csv` of the
seven complete suite runs, four at the default profile and three tolerant; the table is the last one
of `2026-10-20_audit-derived/suite_compare.md`):

| Engine | Bots | Time to mitigate (s) |
|---|---|---|
| `l7_rate` | 77 | 0.06-1.13 |
| `l4_volumetric` | 126 | 0.41-1.25 |
| `l4_syn` | 42 | 0.50-3.82 |
| `l4_slowconn` | 40 | 3.52-4.66 |
| `l4_lowsyn` | 35 | 3.46-3.99 |

SlowConn banned nothing under the tolerant profile, so its row is the four default runs. The median
of the same flood scenario differs between runs by up to a factor 3.1 (SYN flood: 0.50 to 1.56 s;
IP fragmentation 2.6, UDP 2.4). The slow scenarios differ by at most 1.3 (R.U.D.Y.: 3.57 to 4.64 s).
The 3.82 s of the SYN rule is one bot of the multi-vector scenario in one tolerant run (the other
four bots of that run: 0.13-0.41 s) [INFERENCE: it competes with a 0.85 M pps flood for the
server's CPUs; not examined].

**Would settle a single number.** A distribution over at least 10 default-profile runs [NOT RUN];
seven complete runs bound it.

### M7. Slow attacks are mitigated

**Verdict: not supported.**

**Wording.** "The SlowConn rule bans the suite's Slowloris (8 sockets per bot) and R.U.D.Y.
(10 sockets per bot) in 3.5-4.7 s at its default threshold of 8, and bans neither under the tolerant
threshold of 180: 0 of 15 bots each in three runs (EXP-B). Slowloris opens exactly the rule's
threshold of 8 concurrent connections, so the default-profile scenario shows detection at the
threshold."

**Evidence [FACT].** `test_distributed_suite.py:1560` (`N = 8`) and `:1603` (`N = 10`);
`control_plane.py:95-97` (at least 8 established connections, under 250 bytes per interval, 3
consecutive polls); the bans in M6; `2026-10-20_expb-tolerant-profile-suite` (the other eight
scenarios stay at 5/5, so the loss is exactly the two slow attacks, as predicted before the run).

**It does not show** protection against a slow attack. A client with 7 sockets passes the rule.
`docs/REPORT.md` F-10 reports that Nginx's own timeouts and body limit neutralise both scenarios
even unprotected [CLAIMED]; EXP-B is consistent with it: during the two unbanned attacks the
legitimate clients were not hurt (1019 and 1000 requests, all served). The tolerant profile raises
the SlowConn threshold to 180 (`control_plane.py:143`) and bans neither scenario [FACT, EXP-B]. The
L7 track's 6-socket slow families were caught by no engine (`docs/L7_GRU_DESIGN.md`, audit note 8).

**Would settle it.** Slow attacks around and below the threshold, at default Nginx timeouts.

## Machine-learning claims

### L1. The XDP-fed GRU adds detection value

**Verdict: contradicted.**

**Wording.** "The GRU fed with XDP flow telemetry banned no attacker in any recorded run: in the 37
distinct ban-event logs recorded with it on (52 logs and 710 bans in all) it made no true ban and
one false ban. A heuristic bans the same IP
first in every scenario, and the model's inputs let it learn tool and TCP-stack fingerprints
(request size) rather than behaviour. It is off by default since 2026-10-19."

**Evidence [FACT].** `events_census.md` (audit-derived directory; the converted prototype
campaigns of 2026-10-12 folded in on 2026-10-21): `gru` 1 of 710 bans, a legitimate client. Of the 52
distinct logs, 37 come from daemons with the XDP-fed GRU on (36 recorded before the `xdp_gru` field
existed, when it was the default, and the pre-change baseline), 14 are L7-track logs with it off and 1
is empty; the 12 logs and 330 bans added by the prototype campaigns hold no GRU ban. `docs/ML_INVESTIGATION.md` §1: the GRU never decides before a heuristic bans
the same IP; with only the request size changed, held-out R.U.D.Y. detection goes from 19-29 % to
100 %; the CIC-IDS2017 AUC of about 0.1 depends on how benign hosts are sampled (0.115 per host,
0.52 per flow). `control_plane.py:84`: `XDP_GRU` defaults to off.

### L2. The Nginx-log GRU adds detection value

**Verdict: not supported.** The pre-registered verdict is *no advantage*.

**Wording.** "In the pre-registered evaluation P5c.4 (five seeds and a soak; 20 attacker IPs, 100
benign IPs) the log-fed GRU caught 20 of 20 attackers and flagged 9 benign IPs. Per-(IP, UA)
sustained-rate rules and the tabular HGB baseline, tuned on the same runs, caught 20 of 20 and
flagged 2. The GRU also missed the usability criteria (9 % of benign IPs flagged against a 5 %
budget; 1.8 against 1.0 false positives per client-hour in the soak)."

**Evidence [FACT].** `results/2026-10-16_l7-p5c4-eval/p5c4_report.md`; `l7_roles_p5c4.md`
(audit-derived): B4 at the deployed 0.95 x 3 flags 3 of 100.

**Scope of the negative result.**
* The baselines are tuned on the evaluation runs (oracle), which favours them; B4 at the deployed
  setting still flags fewer benign IPs than the GRU (3 against 9).
* The attackers do not harm anyone: benign success is 1.0 and the median server time 2.0 ms with
  and without a fast attacker active, in all five runs (`l7_harm_p5c4.md`). The result shows that
  a model can classify labelled clients, not that it mitigates anything.
* Units: 20 "attackers" are 4 roles in 5 seeds and the 100 "benign IPs" are 20 roles in 5 seeds.
  Attackers have no netem profile in any run, benign clients are spread over four. The GRU
  flagged a 60-asset browser exactly when its profile was `perfect` (4 of 4 such browser-runs,
  0 of the other 6).
* The hard negative `api_bulk`, specified at 15-20 rps, ran at 2.5-4.4 rps in four of five runs
  (`l7_rates_p5c4.md`).

**Suggested framing.** A negative result with a precise scope: in a controlled testbed, neither an
XDP-flow-fed nor an Nginx-log-fed GRU added detection value over deterministic rules. A learned
model was unnecessary for the threat classes this testbed contains. Not "a niche was found":
every pre-registered niche test is negative.

### L3. A sequence model is needed

**Verdict: not supported.**

**Wording.** "Shuffling the order of the requests in every scored window changed 60 of 29 171
window decisions (0.21 %) and no IP-level decision. Reversing the order caught the same 20
attackers and dropped 2 of the 11 benign flags. On this data the trained model's decisions hardly
depend on order."

**Evidence [FACT].** `order_ablation.md` and `.json` (audit-derived directory; tool
`ml/order_ablation.py`). Single windows can still move by up to 0.98 in probability (mean 0.003),
so the effect is negligible, not zero. This tests the trained model on this data; it does not
show that no model could use order. The P4 sentence "sequence modelling earns its place" is not
supported (the GRU's lead over the HGB at P5c.3 is one credstuff client, six (IP, UA) groups;
`docs/L7_GRU_DESIGN.md`, audit note 3).

### L4. Static thresholds face a collateral-damage-versus-evasion dilemma

**Verdict: partly supported; scope it to per-IP peak and connection-count rules.**

**Evidence [FACT].** The benign side is measured for per-IP peak and connection-count rules (M5:
the 60-asset browser under the rate rule, NAT gateways under SlowConn). The evasion side is true by
construction: the attacks were calibrated at most 45 rps against a tolerant rule of 108 rps. Rules
keyed on (IP, UA) with a sustained rate escape the dilemma: B2 caught 20 of 20 at 2 benign flags.
For the connection-count rule both sides are now measured: raising SlowConn from 8 to 180, which
stops the false bans of CGNAT gateways, loses the suite's Slowloris and R.U.D.Y. in 3 of 3 runs
(EXP-B).

**Would settle it.** A threat class where per-key sustained-rate rules also fail, with measurable
harm (`docs/L7_GRU_DESIGN.md` §7 admission rule).

## Method claims

### Q1. The results are reproducible

**Verdict: supported for what is published.**

**Evidence [FACT].** Every published campaign except `2026-10-11_superseded-dup-mac` has a
`SHA256SUMS` that verifies. Analyses regenerate byte for byte. The second review also re-ran the
verdict reports and retrained the P5c.3 model (seed 0, 25 epochs, about 80 s on CPU) and got
identical files. The audit-derived directory regenerates from `results/` alone.

**Limits.**
* The prototype campaigns of 2026-10-12 behind the addendum's cross-mode claims have been published
  since 2026-10-21, and 129 of the 139 comparisons with the addendum's numbers that rest on them match
  (`results/2026-10-21_prototype-claims-check/`). They were converted from prototype-harness files
  with documented approximations (attack start, event times, unseeded client profiles). Not in the
  repository: the kernel log of the EXP-1 runs, EXP-0, and the EXP-5 benchmark output.
* L7 runs published before 2026-10-20 record the commit but no dirty flag; since 9202f61 the L7
  runners record commit, branch and dirty state and refuse a dirty tree.
* The deployed XDP-GRU cannot be rebuilt from the repository alone: its training flows and the
  CIC data are not in `results/`.

### Q2. The L7 track was pre-registered

**Verdict: supported with scope.** The verdict rule and its code (`ml/p5b_report.py`, 241e927)
were committed before the runs they judge and never modified afterwards. The track was iterated
after a negative verdict (P5, then P5b, then P5c), each step changing the test; the iterations and
their direction of bias are listed in the review report §6.2.1. Say "pre-registered per
iteration, with the post-hoc iterations listed". Most of those iterations favoured the GRU, so
the negative verdict is not an artefact of bias against it.

## Corrections to the review report (2026-10-19)

The report is checksummed and lives outside the repository; its corrections are recorded in an
addendum next to it. They matter here because three sentences were stronger than the data:
1. "71 ban-event logs, 529 bans" counted a published log and its raw copy twice. By content there
   were 39 distinct logs at review time and 52 now (66 files, 14 byte-identical copies, 710 bans,
   the prototype campaigns of 2026-10-12 included since 2026-10-21).
2. "Daemon above unprotected in 9 of 9 runs, sign test p = 0.002" is withdrawn as inference (M3).
3. "The GRU does not use order" is refined to "order has a negligible effect" (L3).

## Check it offline

```bash
sh results/2026-10-20_audit-derived/regenerate.sh      # PYTHON=... if ./venv is elsewhere
(cd results/2026-10-20_audit-derived && sha256sum -c SHA256SUMS)
sh results/2026-10-21_prototype-claims-check/regenerate.sh
(cd results/2026-10-21_prototype-claims-check && sha256sum -c SHA256SUMS)
for c in results/20*/; do                              # prints only failures
  if [ -f "$c/SHA256SUMS" ]; then
    (cd "$c" && sha256sum --quiet -c SHA256SUMS) || echo "FAILED: $c"
  fi
done
./venv/bin/python -m unittest discover -s tests
```

## What was run on 2026-10-20 and what remains

Run with your approval (root; Nginx, XDP, namespaces and traffic; `docs/EVALUATION.md`, "Side
effects of a suite run"), one after another, from the audit worktree at commit 618b2fc:

| Run | Command (from the repository root) | Time | Result |
|---|---|---|---|
| Full suite on the 2026-10-19 defaults | `sudo python3 eval/run_campaign.py --modes xdp --runs 1 --seed-base=-1` | 11 min | `2026-10-20_regression-after-audit-defaults`: 10/10 PASS (M1, M6) |
| EXP-B, tolerant profile | `sudo env HEURISTIC_PROFILE=tolerant python3 eval/run_campaign.py --modes xdp --runs 3 --seed-base 200 --out /var/tmp/ddos_campaigns/20261020_tolerant-suite` | 33 min | `2026-10-20_expb-tolerant-profile-suite`: prediction held (M7, L4) |
| EXP-A, knee with 10 paired blocks | `sudo python3 eval/run_campaign.py --operating-point knee --scenarios 4 --runs 10 --attack-duration 30 --seed-base 100` | 62 min | `2026-10-20_expa-knee-10-blocks`: three contrasts supported (M2, M3, M4) |

Still open [NOT RUN], each needing a VM workload and your approval, or offline work:
* A distribution of the time to mitigate over at least 10 default-profile runs (M6).
* Slow attacks around and below the SlowConn threshold (M7).
* A live `hping3 --rand-source` flood with the daemon polling, and the remaining G-17 checks
  (`docs/EVALUATION.md`, verification record).

Done offline on 2026-10-21, no VM workload: the prototype campaigns of 2026-10-12 are published
(M1, M2, Q1) and compared with the addendum (`results/2026-10-21_prototype-claims-check/`).

Run on 2026-10-22 and 23 with your approval: the open-loop probe and its refinement
(`2026-10-22_expc-r50-probe`, `2026-10-23_expc-r50-refinement`) and EXP-C, 120 runs in 3.85 h:
`sudo timeout -s INT 28800 python3 eval/run_campaign.py --operating-point knee --scenarios 4 --attack-duration 30
--modes unprotected,nginxlimits,xdp --runs 10 --seed-base 100 --loads wrk,loadgen:125,loadgen:250,loadgen:500`,
published as `2026-10-23_expc-open-vs-closed-loop` (M3, M4; protocol `docs/EXPC_PROTOCOL.md`).
