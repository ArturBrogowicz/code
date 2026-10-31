# L7 track v2: a costed, enforcing L7 harness for P1, shared with P3 and P4 (design note, written before the code)

**Status (2026-10-30): a design for approval. Nothing in it is built or run.** It is on `design/priority-p1-p4`, branched
from `feat/hg1c` at e413a34, and changes no code. It carries out harness architecture B of the priority plan (P1, P3 and P4 on
"L7 track v2", P2 on the harm benchmark), which you approved on 2026-10-30 (ledger D-015), for the 2-4 week deadline (D-014). Two
companion notes reuse the harness defined here: `docs/P4_SLOW_DESIGN.md` (slow attacks) and `docs/P3_DATASET_DESIGN.md` (the
capture pipeline and the learning curves). The form follows `docs/HG1C_DESIGN.md`.

**Tags.**
- **[FACT]**: read now. The source is one of:
  - a file at e413a34 (`path:line`; every line reference in this note is at e413a34);
  - an accepted S1 artifact, `S1:T-00x/<file>`, under `/home/artur/agent_workspace/tasks/T-00x/artifacts/`;
  - a row of the verification ledger (`VR:Vn`, `/home/artur/agent_workspace/ledger/VERIFY_RECONCILIATION.md`), whose numbers
    replace the producers' where the two differ;
  - a T-012 quote id such as `[G1-01-Q2]`, re-found in the source by script (`S1:T-012/quotes.tsv`).
- **[CLAIMED]**: a project document or memory says it; not re-verified here.
- **[INFERENCE]**: reasoned; the premises are named.
- **[ESTIMATE]**: arithmetic on claimed inputs.
- **[PROPOSAL]**: a value or rule set here. It is frozen by a commit before the data it judges (section 13).
- **[ASSUMPTION]**: a model value that no source supports. It is declared, not measured.
- **[NOT RUN]**: needs a VM workload.

## 1. Decisions for the user, and what I found

**What I found while reading the code** (each finding changes the design; details in the sections named):
- **F-V1: the costed backend is not a drop-in** (section 4).
  - l7_webapp's URL space does not match the origin's route patterns. Pages are `/page/<any>`, and assets are
    `/static/site<level>/...` (`l7_webapp.py:16-26`, `:55-70`). The origin expects `/static/<digits>`, `/page/<digits>` and
    `/api/item/<digits>` (`bench/origin.py:60-62`), and it answers GET and HEAD only (`bench/origin.py:232-234`).
  - L7 v2 therefore calls the origin's work by route class. It does not route through the origin's WSGI face.
  - Today's "expensive" `/search` is a 40 ms sleep (`l7_webapp.py:38`, `:124-126`). A sleep costs no CPU, which is exactly
    what the origin was built to avoid (`bench/origin.py:22-27`).
- **F-V2: the intensity unit.** T-006's harm arithmetic uses S ≈ (C_sat − C_slo) × mean cost ≈ 1.30 CPU-s/s
  (`S1:T-006/threat_classes.md`, header). The code defines the spare capacity as S = (C_slo − ρ) × mean cost with ρ = 0.5 C_slo
  (`bench/calibration.py:55`, `:268-279`), which gives 0.313 CPU-s/s on the draft record (`S1:T-004/p2_capacity.md` §1)
  [FACT].
  - The classes survive this: the plan's "≤ 0.74 req/s per source" is T-004's ladder at L = 8 (0.71 req/s per source over 100
    sources) [FACT: `S1:T-004/p2_capacity.md` §2].
  - L7 v2 states every intensity as a level of the code's S, fixed by a harm ladder (section 5.3). T-006's arithmetic is not
    used.
- **F-V3: the benign browser sends no Referer and no cookie, and the server sets none.** `grep -i 'referer|cookie'` over
  `ml/l7_gen.py`, `ml/l7_benign.py`, `l7_webapp.py` and `l7_ingest.py` is empty [FACT].
  - Referrer consistency and cookie keying therefore need a benign-model change, not only a feature (section 8).
- **F-V4: no realistic benign kind uses a costly route.** [FACT]
  - The realistic (P5b) kinds load pages and assets, or call `/api/...` (`ml/l7_benign.py:156-188`).
  - Only `curl_oneshot` and the attacks draw "mixed" paths: one choice in five is `/search` (`ml/l7_gen.py:53-55`;
    `ml/l7_traffic.py:95-96`, `:130-131`).
  - No `/export` route exists.
  - Without benign search and export users, any costly request is an attack request, and a cost rule wins by construction.
    L7 v2 adds them (section 7.2).
- **F-V5: today's benign navigation has no order structure.** Each page view draws its page i.i.d. from a Zipf law
  (`ml/l7_benign.py:106-108`, `:129`) [FACT]. Against a structureless benign model, any structured bot is separable "by order"
  only because the benign side is structureless. That would be a benchmark the generator wins. L7 v2 grounds benign navigation
  in a published multi-step model, and keeps i.i.d. Zipf as a held-out kind (section 12).
- **F-V6: njs is not available; `auth_request`, `map` and `geo` are.** [FACT: static check, 2026-10-30]
  - nginx is 1.28.3-2ubuntu1.12. No `libnginx-mod-*` package is installed, `/usr/share/nginx/modules` points to a missing
    directory, and `/etc/nginx/modules-enabled` is empty (`dpkg-query`, `ls`).
  - The binary has no `ngx_http_js_module` string. Its configure string contains `--with-http_auth_request_module`.
    `http_map_module` and `http_geo_module` occur in it (`grep -a -c` on `/usr/sbin/nginx`).
  - The modules built `=dynamic` are geoip, image_filter, perl, xslt, mail and stream.
  - `nginx -V` was not run; that auth_request is static is [INFERENCE] from the strings.
- **F-V7: a config-injection path.** Writing a logged User-Agent into an nginx `map` file lets a client write nginx
  configuration (section 9.4) [INFERENCE]. The design constrains what may be written.
- **F-V8: the probe gate blocks navigation features as written.** The hard `uri_bijection` probe (`ml/l7_probes.py:44`, `:97`)
  renames URIs at random [FACT]. Every model that reads a route class from the path would fail it by construction
  [INFERENCE]. It must become class-preserving (section 8.5).
- **F-V9: the P1 VM budget in the plan is too small.** The plan's ~5 VM h for F5 (`final/PRIORITY_PLAN.md` §8) does not cover
  10 blocks of the live arms. My arithmetic gives 11-14 VM h for the three core classes, and ~8 h in a minimum cut
  (section 14) [ESTIMATE].

**Decisions requested.**

| # | Decision | Recommendation | Why, and what the alternative costs |
|---|---|---|---|
| D-V1 | Costed backend: l7_webapp keeps its URL space. Each route is mapped to an origin work class (C0, C1, C2, C3, C5) and calls `Origin.handle` (`bench/origin.py:223-225`) with the knobs and costs of the HG2 frozen record. Until that record exists it runs on the placeholder: answers are labelled, and no verdict is given (section 4) | accept | It reuses the measured work functions, the 25 % self-check and the freeze/refuse discipline. The alternative, origin URLs in the generators, rewrites the asset waves and the admissibility gate |
| D-V2 | Client-side harm metric: request-level Q and p95 against the calibration's SLOs, on the judged links only, with the harm gate's floors. Views that fell due but never started count as failures. Each block holds C, C' and U plus the live M arms. A class enters only if it passes harm admission (section 5) | accept | It is the harm gate's rule (`eval/harm_gate.py:9-31`) applied to closed-loop clients. Lighter validity gates are offset by a server-side cross-check |
| D-V3 | Per-seed IP pools drawn from one shared client space (10.0.16.0/20) for both roles, with the role map only in the manifest (section 6) | accept | Today one 29-IP map serves every run [FACT, VR:V10], and roles sit in fixed /24s (`ml/l7_traffic.py:294`, `:302`) |
| D-V4 | Classes: core C2, C3a, C3b; optional C4 and C1, run only if the core campaign leaves VM time (section 7) | core first | The deadline allows the full plan (D-014), but C4 and C1 add ~3.5 VM h each [ESTIMATE] and are expected to give V-B or V-C |
| D-V5 | Model: a two-level model, a GRU over view tokens (the last 32 page views), with the per-request seq_len-64 GRU as an offline ablation. Navigation features, (IP, UA, sid) keying, three new log fields, and a class-preserving probe gate (section 8) | two-level | 20 requests are shorter than one cold page view [FACT, `S1:T-005/p1_baseline_facts.md` §4]. Navigation lives at the view level |
| D-V6 | Benign navigation grounded in a published multi-step model: the TPC-W customer-behaviour graph mixes, two trained and one held out. This is a W-LIT retrieval task before the generators are frozen (section 12) | accept | See F-V5. Without it, a GRU win would be uninterpretable |
| D-V7 | Enforcing arm, graduated (section 9): (1) deny the (IP, UA, sid) key at nginx through a daemon-written `map` and a rate-limited graceful reload; (2) an XDP ban only for single-key IPs. Safeguards and a kill switch. `auth_request` is the fallback if reloads misbehave in the pilot | accept | njs is absent (F-V6). An XDP ban hits a whole IP, so CGNAT pools must never get one |
| D-V8 | Arms: every arm is tuned on validation seeds to the same benign budget (≤ 1 % of benign users flagged). Only the strongest of each family runs live; the rest are scored by replay (section 10) | accept | Running every arm live would take ~2× the VM time (section 14) |
| D-V9 | Verdict ladder V-A..V-D with an equivalence margin and a fixed testing order; "inconclusive" is reported as such (section 11) | accept | Without an equivalence margin, V-C ("rules suffice") could be claimed from lack of power |
| D-V10 | VM budget: about 11-14 h for P1 (pilot and ladder ~3 h, campaign 8-10 h); minimum cut ~8 h (C3b and C2 only) (section 14) | accept the 11-14 h | This is above the plan's ~5 h (F-V9). The cut drops the C3a control and the live HGB arm for the controls |

## 2. Scope

| In | Out (named, not forgotten) |
|---|---|
| The costed backend; the client-side harm metric and its block design; per-seed pools; the P1 classes; the model, feature and log changes; the enforcing arm; the arms and their tuning; outcomes and verdicts; the circularity guard; pre-registration; the VM budget | L3/L4 floods and the XDP-fed GRU, which stays off (`control_plane.py:84`); P2 (the harm benchmark); a fused XDP+Nginx input (future work, `S1:T-005/o2_draft.md` §4); an attacker that reacts to bans, for which no source was found (`S1:T-012/grounding_update.csv` row 20); real browsers, since the testbed has no browser engine and C3b is a request-level emulation (section 7); client-side signals such as mouse data `[G1-04-Q1]`; HTTP/3 |

## 3. What exists (facts)

| Need | L7 track today (`ml/`, `l7_*`) | Harm benchmark (`bench/`, `eval/`) |
|---|---|---|
| Backend cost | none: deterministic bodies; `/search` sleeps 40 ms (`l7_webapp.py:38`, `:124-126`) | measured work per class C0-C5 with a frozen-record self-check (`bench/origin.py:51-52`, `:263-305`) |
| Realistic benign | browser devices with asset waves, cache, TPC-W think time, UA table, CGNAT pools (`ml/l7_benign.py:35-41`, `:68-86`, `:115-142`) | Poisson streams per identity; one UA; GET only (`S1:T-006/threat_classes.md` 1(f), 2(f)) |
| Attacks | sub-threshold rate families, slow families, credstuff (`ml/l7_traffic.py:129-147`) | open-loop cost floods (`S1:T-004/p2_capacity.md` §2) |
| Harm metric | none (P5c.4 attacks were harmless: benign success 1.0 [CLAIMED, `S1:T-005/p1_baseline_facts.md` §3]) | Q and p95 per block of C, C', U; floors 10 pp or log2 p95 ≥ 1; ≥ 10 blocks; control Q ≥ 99 % (`eval/harm_gate.py:9-31`; `bench/calibration/placeholder.json` `gate`) |
| Enforcement | shadow only: the engine "never bans" (`l7_engine.py:3-5`; `control_plane.py:521-531`) | unprotected stack only (14 gaps, `S1:T-004/hg4_gaps.md`) |
| Detectors | GRU on the last 20 requests per (IP, ua_hash) (`l7_ingest.py:38`, `:133-135`); B0-B4 offline (`ml/l7_baselines.py:39-44`) | none |
| Data hygiene | one 29-IP role map for every run; seed 1 in training and evaluation; selection on test sets [FACT, VR:V10; `ml/train_l7.py:403-416`] | seeded populations and run contracts |

The evidence to beat, as reconciled [FACT, VR:V7-V9]:
- **Detection at equal benign cost.** The GRU, tuned on the evaluation runs like the baselines, catches 0/20 attackers at ≤ 2
  benign flags and 10/20 at 3. It needs 5 flags (the held-out api_bulk) for 20/20. B2, B3 and B4 reach 20/20 at 2 flags.
- **The rules' win is a knife edge.** 1 of 54 B2 settings and 1 of 48 B3 settings reach it, in a threshold window 1.4 rps wide.
- **Speed.** Median time to decision from the first request: GRU 3.61 s, HGB 3.19 s, token bucket 11.20 s, sustained rate
  31.65 s. At one more benign flag the sustained-rate rule decides in 7.83 s.

## 4. The costed backend

### 4.1 Route-to-class map [PROPOSAL]

| l7_webapp route (kept) | Work class | Work called | Body |
|---|---|---|---|
| `GET /static/...` (assets, incl. `/static/site<level>/...`) | C0 | `Origin._c0` | l7_webapp's deterministic size (`l7_webapp.py:50-52`), so the asset waves and the size features stay as they are |
| `GET /`, `GET /page/<n>` | C1 | `Origin._c1`, ident = crc32(n) | the origin's rendered page |
| `GET /api/<name>` | C2 | `Origin._c2`, ident = crc32(name) | the origin's JSON |
| `GET /search?q=<term>` | C3 | `Origin._c3` with the term; the 40 ms sleep is removed | the origin's JSON |
| `GET /export[?r=<n>]` (new) | C5 | `Origin._c5` | the origin's CSV |
| `GET /download/large`, `POST /upload`, `POST /login`, `/robots.txt`, 404 | uncosted, as today | none | unchanged (`l7_webapp.py:131-155`) |

- **Work factor.** It is drawn from a hash of the URL (`bench/origin.py:96-102`), so a replayed URL costs the same.
  `spread_sigma` 0.25 stays an [ASSUMPTION], as the origin declares it (`bench/origin.py:85`).
- **Headers.** Every costed answer carries `X-Route-Class` and `X-Work`. Every answer carries `X-Origin-Calibration`
  (`bench/origin.py:252-258`). The runner records the latter per run.
- **C4 and C6** (POST login and upload) stay uncosted. No P1 class needs them; P4 uses `/upload` for worker-slot harm, not CPU
  (`docs/P4_SLOW_DESIGN.md`).

### 4.2 The calibration record: frozen or placeholder
- The backend reads `ORIGIN_CALIBRATION` exactly as `app_from_env` does (`bench/origin.py:308-321`):
  - **knobs** from the record;
  - **frozen route costs**, which arm the start-up self-check: a route more than 25 % off its frozen cost stops the start
    (`bench/origin.py:282-305`);
  - **the tag** `frozen:<sha8>`.
- **The HG2 frozen record does not exist yet.** HG2 is blocked, and its fix is being built (`final/PRIORITY_PLAN.md` §3).
- **Until it exists, the backend runs on the placeholder:**
  - `bench/calibration/placeholder.json`: `status: placeholder`, costs C0 0.05 / C1 3.0 / C2 2.0 / C3 30 / C5 150 ms,
    `c_slo_rps` 180, illustrative [FACT];
  - or, for development only, the HG2a diagnostics: C0 0.006, C1 3.96, C2 2.15, C3 35.5, C5 191.8 ms [CLAIMED,
    `S1:T-006/threat_classes.md` header]; C_slo 84.5 and C_sat 241.3 req/s [FACT, recomputed in `S1:T-004/capacity_replay.md`;
    VR:V5].
- **Rule [PROPOSAL]:** every L7 v2 report prints `PLACEHOLDER` in its title on such a record. The verdict code refuses it, as
  `calibration.require_frozen` does (`bench/calibration.py:259-262`). Only pilots, smoke runs and ladders may use it.
- **A second record.** The frozen record is measured on the harm benchmark's stack, so the P1 runs adopt that stack (4.3). If
  the stacks differ, L7 v2 measures its own capacity record with the same calibrator, and that record is frozen separately.

### 4.3 Server stack for P1 [PROPOSAL]
- **Gunicorn:** 2 workers × 8 threads, bound to 127.0.0.1:8080, on CPUs 0-1. This is the harm benchmark's D22 stack
  [CLAIMED, `docs/HG1C_DESIGN.md` §1 D22]. Today's L7 runner starts 4 × 4 on 0.0.0.0 (`ml/capture_l7.py:298`;
  `ml/eval_l7.py:91`).
- **Why the loopback bind matters.** The 0.0.0.0 bind lets clients bypass nginx [FACT, `S1:T-007/security.md` S11]. Nginx
  already proxies to 127.0.0.1 (`nginx_l7capture.conf:79`).
- **Nginx:**
  - `nginx_unprotected.conf` for C, C' and U;
  - `nginx.conf` with the L7 sink for the M arms, rendered as today (`ml/capture_l7.py:84-141`);
  - the protected arms also include the deny map (section 9.2).
- **P4 uses its own realistic profile** (`docs/P4_SLOW_DESIGN.md` §2).

## 5. The client-side harm metric

### 5.1 What each benign client records [PROPOSAL]
- **One row per request**, with the harm gate's columns `t_intended, t_sent, t_done, status, err` (`eval/harm_gate.py:62`). Each
  row also carries `route_class`, `netem`, `entity`, `view` and `wave`.
- **Closed-loop clients have no independent schedule within a view.** Each view has a nominal start in the plan
  (`ml/l7_benign.py:115-142`), and network time stretches the timeline (`ml/l7_gen.py:199-202`). So:
  - a sent request has `t_intended = t_sent`;
  - **the coordinated-omission guard:** a view whose nominal start falls in the attack window, but which has not started 10 s
    after its nominal start, counts every request it planned as failed (`err = "never_sent"`), with `t_intended` = the nominal
    start.
- **Files.** The rows go to one gzip CSV per client, in the run contract's form (`eval/harm_gate.py:113-163`). The executor's
  `run.json` and `block.json` keys are reused (`eval/harm_gate.py:60-62`).

### 5.2 Q, p95 and the floors
All of these are the harm gate's rules, unchanged [FACT: `eval/harm_gate.py:191-257`, `:300-312`, `:397-408`;
`bench/calibration/placeholder.json` `gate`]:
- **Q** is the share of judged requests in the attack window that returned 2xx within their route class's SLO. The SLOs are the
  record's `slo_ms`: C0 100, C1 300, C2 300, C3 1000, C5 3000 ms. **p95** is taken over the successful requests.
- **Judged links** are `perfect` and `broadband` (D19/A1). The mobile profiles are reported per profile and do not vote.
- **Per block:** dQ = Q(C) − Q(U), dL = log2(p95(U) / p95(C)), and the same against the placebo C'.
- **PASS** (harmful): over ≥ 10 valid blocks, the mean dQ ≥ 10 pp or the mean dL ≥ 1. Its 95 % t-interval excludes 0, and
  ≥ 80 % of the blocks have the sign of the mean. The placebo must not pass.
- **Healthy control:** Q(C) ≥ 99 %, and every route class has ≥ 95 % of its requests within the SLO. A failed block is re-run
  once with the same seed, at most 2 times per campaign.

**Time-resolved outcomes** reuse the gate's 1-s bins: degraded below 95 %, recovered at ≥ 99 % for 5 bins
(`eval/harm_gate.py:64`).

### 5.3 Blocks, intensity and harm admission [PROPOSAL]
- **A block** is one evaluation seed. The seed draws the IP pool, the role map, the per-entity parameters, the netem
  profiles and the schedule. Every run of a block uses them unchanged: C, C', then for each class k U_k and its live M arms.
  The runs are in a seeded random order.
  - C and C' are shared by the classes of a block. The class analyses are therefore correlated, and each class's verdict is
    reported separately.
- **Intensity per class** is a level of the code's S (F-V2), or, for C3b, a number of bots (section 7). It is fixed before the
  campaign by a ladder on **pilot seeds** (9001-9008, disjoint from every other seed):
  - levels {1, 2, 4, 8}, 2 repeats of (C, U) per level;
  - the knee is the lowest level whose harm reaches the floor in both repeats (`bench/calibration.py:288` `knee`);
  - the campaign runs at the knee.
- **Harm admission.** A class enters the P1 verdicts only if U_k passes 5.2 against C in the evaluation campaign itself.
  Otherwise its verdict is V-D "no harm" (section 11). Nothing is retuned after admission.

### 5.4 Validity (lighter than the harm benchmark's, so a cross-check is added) [PROPOSAL]
- **Gate checks that apply as they are:** the healthy control, the placebo, and the re-run rule.
- **Runner checks:**
  - every planned client started;
  - in M runs, the daemon was alive from before the attack to the end and XDP was attached (HG4 G11, `S1:T-004/hg4_gaps.md`);
  - the file-sink log has no gaps.
- **Server-side cross-check.** Q is recomputed from nginx's `$request_time` for the same benign requests.
  - A block is **invalid as a client-side artefact** when the client-side dQ ≥ 10 pp but the server-side Q(U) ≥ 99 %.
  - Why it is needed: the VM has host-level stalls of up to 847 ms, which closed-loop clients would book as latency [FACT,
    `S1:T-004/p2_capacity.md` §6].
  - This check fits CPU harm (P1). P4's connection harm is not visible to `$request_time`, so P4 uses a connection-level
    variant.

## 6. Populations: per-seed IP pools and role maps [PROPOSAL]
- **The pool.** For each seed, the runner draws a pool from **10.0.16.0/20** (4,094 addresses).
  - That range is inside the testbed's /16 (`test_distributed_suite.py:42`, `:51`; `bench/executor.py:58-59`) and outside the
    legacy role nets: 10.0.1.x and 10.0.2.x in the suite (`test_distributed_suite.py:47-49`), and `BENIGN_NETS` and
    `ATTACK_NETS` (`bench/population.py:38-39`). The address does not reveal the role.
  - The l7_gen scope lock (10.0.0.0/16) still holds (`ml/l7_gen.py:33`).
- **Roles** are a seeded permutation of the pool. A CGNAT pool is one address with many users by definition
  (`ml/l7_benign.py:164-171`).
- **Namespaces.** Entities are grouped onto client namespaces as address aliases, as the harm executor does
  (`bench/executor.py:334-336`). The netem profile belongs to a namespace, so entities are grouped by their drawn profile.
- **Netem is drawn for attackers too, from the benign distribution.** Today attackers have none
  (`ml/capture_l7.py:65-74`; `S1:T-005/p3_inventory.csv`, the "no netem = attacker" confound).
- **The manifest** carries the full role map: entity → address, namespace, kind or family, per-entity parameters, netem.
  Benign-blocked counts (HG4 G8) are attributed from the manifest, never from a subnet.
- **Scale:** ≤ 300 aliases have been verified on this testbed [CLAIMED, `final/PRIORITY_PLAN.md` §3 "Scale", S2 of HG1c].
  P1 needs about 250-320 identities per run (section 7.3).

## 7. The P1 classes

### 7.1 Class definitions (taxonomy and evaluation parameters for this testbed's in-repo generators)

| Class | Threat and grounding | Harm route and intensity | Sources and per-source pacing | UA, cookies, assets | Expected separator | Role |
|---|---|---|---|---|---|---|
| **C2** request-cost abuse | Few expensive requests exhaust back-end CPU and are "difficult to detect by state-of-the-art detection systems" `[G5-03-Q1]` `[G5-03-Q2]`; mimics target expensive resources `[G5-01-Q1]`; OWASP API4 (`S1:T-006/threat_classes.md` 2(a)) | C3 `/search` (and C5 `/export` as a variant); level of S from the ladder. On the draft record, L = 4 is 35.3 req/s of C3 in total [FACT, `S1:T-004/p2_capacity.md` §2] | 100 sources; Poisson at level × S / (cost × 100), e.g. 0.35 req/s each at L = 4; search terms drawn like the benign search users' | one browser UA per source from `UA_TABLE` (`ml/l7_benign.py:68-86`); cookies kept; no assets | per-key cost budget; per-request CPU time is the best discriminant for CPU attacks `[G4-03-Q1]` | **control** (rules or cost should win) |
| **C3a** browser-claiming HTTP-library bots | 86.2 % of bots claim Firefox or Chrome but are HTTP libraries `[G1-01-Q2]`; 0.63 % of bot sessions run JavaScript `[G1-01-Q3]`; crawlers forge UAs, cookies and referrers `[G1-03-Q2]` | pages (C1) plus one costly request per page; level of S from the ladder | 50-100 sources; one page every U[2, 8] s [ASSUMPTION] | browser UA; cookies kept; **no assets, no JS** | asset/page ratio per session, a summary feature [INFERENCE from `[G1-01-Q3]`] | **control** (features and rules should win) |
| **C3b** headless-browser bots, non-human navigation | Bots that use real browsers become hard to distinguish from users `[G1-02-Q1]`; a traversal-graph model separates them on real traffic, with about the same AUROC as a feature model (0.9892 vs 0.9886) `[G1-02-Q3]`; they differ from users "in intent but not in content" `[G5-01-Q2]` | the views load like a browser's; each view issues one costly request (C3; C5 as a variant). Intensity = the number of bots, from the ladder {50, 100, 200, 300} | ~200 bots [ESTIMATE: 200 bots × one C3 request per 7 s ≈ 28.6 req/s ≈ 1.0 CPU-s/s, inside the 0.75-1.06 CPU-s/s range where T-004 expects harm, `S1:T-004/p2_capacity.md` §3] | browser UA from `UA_TABLE`; cookies and Referer like the benign browser (section 8.4); **asset waves and cache like a browser device** (`ml/l7_gen.py:199-216`) | navigation: entry, dwell, revisits and transitions (mimicry levels below) | **the GRU's fair chance** |
| C4 pulsing (optional) | Pulse period tuned to the defender's timescale with a low mean `[G2-01-Q2]` `[G2-02-Q5]`; parameters (R, L, T) `[G2-02-Q1]`; autocorrelation detects it `[G2-02-Q4]` | C2's route and level delivered in on/off pulses: T ∈ {10, 15} s against the 10 s rule window (`control_plane.py:132`); duty 0.2 | 100 sources, each with a per-key mean below the tuned B2/B3 thresholds | as C2 | multi-scale rate | secondary |
| C1 distributed low rate with UA rotation (optional) | The UA is attacker-chosen `[G1-01-Q2]`; volume statistics miss low-rate attacks (P3-02 in `docs/sota_broad_review.md:287`, via `S1:T-006/threat_classes.md` 1(a)) | C1 or C2 at 3-6 req/s per source [CLAIMED, `S1:T-006/threat_classes.md` 1(c)]; level from the ladder | 100 sources | a new UA per session from `UA_TABLE` | population level only (new keys per IP) | negative control for per-key models |

**C3b mimicry levels** [PROPOSAL; the values are [ASSUMPTION], frozen before any model sees data]. They sit on the
navigation model of section 12:
- **M2 (primary)** follows the plan's definition: "deep links, uniform dwell, no revisits" (`final/PRIORITY_PLAN.md` §6.1).
  - Entry and every next page are uniform over the page universe. The bot ignores the benign transition model.
  - Dwell is uniform on [2, 12] s, mean 7 s, the benign mean (`ml/l7_benign.py:37`).
  - Pages are drawn without replacement, so there are no revisits.
- **M1 (secondary, a sanity level):** like M2, with a constant dwell of 3 s. Every learned arm should catch it.
- **M3 (held out, evaluation only):** it follows the benign transition model, with uniform dwell and no back-navigation. It
  measures how detection degrades near the benign envelope.

Each level's parameters are fixed in the generator commit (section 13). They are **never** adjusted after a model has been
scored. The harm ladder may change only the number of bots.

**Honesty notes:**
- **C3b is an emulation.** The testbed has no browser engine. "Headless browser" means the request pattern of one: HTML, then
  CSS/JS, then fonts and images, a persistent cache and 6 keep-alive connections (`ml/l7_benign.py:41`). No script runs.
- **The separators are not equally visible.** Most of M2's differences (page popularity, dwell variance, revisit share) are
  visible to a window summary [INFERENCE]. That is why V-B is the most likely C3b outcome (section 11).

### 7.2 Benign mix changes (frozen with the generators) [PROPOSAL]
- **Kept:** the P5 and P5b kinds (`ml/l7_traffic.py:94-121`) as the base, including the hard negatives: browser_page at
  level 60, CGNAT-12 and CGNAT-24, and api_bulk.
  - Rename "flash crowd / 60-asset page" to "median page load". A median desktop page loads 71 requests `[G3-01-Q1]`, so it is
    not a flash crowd [FACT, `S1:T-012/review.md`].
- **New `search_user`:** browser sessions that issue searches.
- **New `exporter`:** occasional `/export` downloads.
- Both new kinds have rates [ASSUMPTION]: no measured source exists (T-012 G3 gap statement). They must pass the admissibility
  gate (`ml/l7_admissibility.py:207-249`) under the profile in use.
- **New `flash_crowd` (held out):** many new browser clients arrive within 60 s, at per-client rates no higher than usual. In a
  flash crowd, per-client rates drop `[G3-06-Q1]`.
- **Referer and a session cookie** on every browser-like kind (section 8.4).

### 7.3 Population per run [PROPOSAL]
- **Benign:** 120-160 users, comprising:
  - ≥ 40 browser devices (levels 30 and 60, half on 443);
  - CGNAT-12 and CGNAT-24 (36 users on 2 addresses);
  - ≥ 20 search users and ≥ 5 exporters;
  - the P5 kinds;
  - api_bulk and a polite crawler;
  - a flash crowd of 30 users (held out).
- **Attack:** 100 sources for C2, C4 and C1; 50-100 for C3a; up to 300 for C3b.
- **Total:** at most ~320 addresses, which fits the verified 300-alias range only at the top of the C3b ladder. If 300 bots
  cannot be carried, the ladder stops at 200 and the knee is searched below that.

## 8. Model and feature changes

### 8.1 Horizon: a two-level model [PROPOSAL, D-V5]
- **View tokens.** Ingest groups each key's requests into views. A page request (route class C1, or `/`) opens a view. The
  key's following non-page requests (assets, API calls, searches, exports) belong to it until the next page request.
- **Features per view token:**
  - log dwell (to the next page request);
  - the number of requests and the asset share;
  - the share of assets this key had already fetched (a browser does not re-fetch within max-age, `ml/l7_benign.py:21-23`);
  - the number of costly requests (C3, C5);
  - page revisit (a hash-set membership, never the id);
  - referrer present, and referrer known (the referrer equals a page this key requested before);
  - the status and method mix;
  - the new-connection share.
- **The GRU** reads the last V = 32 tokens and scores once a key has ≥ 4 views.
- **Ablation.** The per-request GRU with seq_len 64 is scored offline as an ablation.
- **Today's horizon.** Seq_len is 20 (`ml/train_l7.py:52`; `l7_ingest.py:38`), against 61 requests in one cold level-60 view
  [FACT, `S1:T-005/p1_baseline_facts.md` §4].
- **Scorer package.** Its format gains `"level": "view" | "request"`. The scorer refuses a mismatch, as `validate_columns`
  does for columns (`l7_scorer.py:43-52`).

### 8.2 Navigation features per request (computed at ingest; never the raw URI) [PROPOSAL]
- **The features:** `is_page`, `is_asset`, `is_costly`, `asset_refetch`, `page_revisit`, `ref_present`, `ref_known`, and
  `log_page_gap`, the time since the key's previous page request.
- **Anti-fingerprint discipline.** The route class comes from a site map, which is l7_webapp's route table. The discipline
  (`l7_features.py:14-21`) is extended: class-level semantics may enter, identities may not.
- **The HGB and the LR get the same tokens summarized** (mean, std and max per column, plus counts), as `window_summary`
  does today (`l7_features.py:146-162`). A GRU win then has to come from order, not from features the baselines lacked.
- **Default groups drop `server_timing`.** With a costed backend, server timing encodes load and harm, which is R17
  (`l7_features.py:33`; variants in `ml/train_l7.py:333`). The protocol group stays off (`l7_features.py:43-44`).

### 8.3 Keying [PROPOSAL]
- **The key** is (IP, ua_h, sid_h) when a server-issued session cookie is present, and (IP, ua_h) otherwise.
  - Today it is (IP, ua_h) (`l7_ingest.py:133-135`).
  - The sid separates CGNAT users whose UAs collide, which `UA_TABLE` makes realistic (`ml/l7_benign.py:25-26`).
  - The sid is a key component only, never a feature.
- **A population-level detector** runs as a separate baseline (replay only): new keys per IP per minute, and the cookie-less
  share. It is C1's natural detector.

### 8.4 Log format and benign-model additions [PROPOSAL]
- **Log fields.** `nginx_l7capture.conf:25-47` and the deployed sink gain `"ref":"$http_referer"` and
  `"sid":"$cookie_sid"`. Ingest hashes both with `stable_hash32`, as it does `ua` and `uri` (`l7_ingest.py:114-122`).
- **The server.** l7_webapp sets `sid` (random, HttpOnly) on an HTML answer to a request that carries no valid sid.
- **Benign browser devices.** They send `Referer` = the previous page for page requests, and = their page for that page's
  assets. They keep cookies: a `requests.Session` keeps them [INFERENCE: the devices use one Session each,
  `ml/l7_gen.py:187-196`].
- **Grounding.** The Referer behaviour is a browser convention [CLAIMED: RFC 9110 §10.1.3; not in the T-012 corpus]. PUBCRAWL's
  crawlers manage cookies and referrers `[G1-03-Q2]`, so the bots do too: presence is not a separator; consistency may be.

### 8.5 Probe gates (hard, applied to every variant before selection) [PROPOSAL]
- **Today's gate:** `ua_swap`, `uri_bijection`, `time_offset` and `server_load` (`ml/l7_probes.py:91-97`), applied as a hard
  gate in the trainer (`ml/train_l7.py:19-22`).
- **L7 v2 changes:**
  - `uri_bijection` becomes **class-preserving**: it renames paths within each route class and keeps the site graph and the
    revisit structure (F-V8);
  - a new exact probe, `sid_swap`, renames session cookies.
- **Exact tolerance:** |Δp| ≤ 1e-5 (`ml/l7_probes.py:35`).
- **Unchanged:** `server_load` (R17) stays, and so does the robustness tolerance of a 5 % decision-flip rate
  (`ml/l7_probes.py:36`).
- **As built (T-025b, 2026-10-30): a change to a hard gate, approved with this design (D-V5).**
  - The L7 v2 gate is `ml/l7_probes.py` `GATE_PROBES_V2`: `ua_swap`, `uri_bijection_class`, `sid_swap`, `time_offset`,
    `server_load`, frozen in `ml/l7v2_model_prereg.json` ("probes") before any capture.
  - `uri_bijection_class` renames every URI identity to a fresh one while each request keeps its route class (`rc`, set
    at ingest from the site map), and renames the Referers with the same map.
  - The P5c probe `uri_bijection` and the P5c gate `GATE_PROBES` are unchanged and remain the defaults of `run_probes`
    and `gate_pass`, so the published P5c runs reproduce. L7 v2 reports still list `uri_bijection`, ungated: a model
    that reads `ref_known` fails it by construction (F-V8).
- **What the v2 gate is, re-registered 2026-10-31 under D-034 (review T-038, T038-02; labelled post hoc, before any
  data): a pipeline-invariance check, not a test of what a view arm learned.**
  - `server_load` holds every request's start fixed and scales its rt and urt. View tokens are built from start times
    (dwell, counts, shares, the status and method mix, creq), so every view arm passes it exactly, whatever it learned.
  - `ua_swap`, `uri_bijection_class`, `sid_swap` and `time_offset` pass by construction too, because no identity and no
    absolute time is a feature. The P5c gate behaved the same way for its published variant (T-038,
    `p5c_window_hash.txt`).
  - What the gate does catch: a pipeline that lets an identity, an absolute time or a server timing into the inputs.
  - What it cannot catch: load that reaches the features through the closed loop. A loaded server delays every next view
    of a closed-loop client, so load enters `log_dwell`, `log_span` and `log_rate`, and attack windows exist only under
    attack load (R17).
  - **So a descriptive load split is reported for every arm on validation** (`ml/l7v2_model_prereg.json` `load_split`;
    `train_l7v2.load_split`, in `selection.json` beside each arm's operating point): the benign flag rate inside versus
    outside the attack phases, and attack-entity recall per load level (the phase intensity the plan records). It is
    descriptive and never a gate. A closed-loop load probe stays optional (D-034).

## 9. The enforcing arm (today the L7 engine is shadow-only)

### 9.1 Decision policy [PROPOSAL]
- **Rule:** p > θ in k consecutive scored windows of a key. θ and k are fixed on validation seeds (section 10). This is
  today's shadow policy (`l7_engine.py:144-166`), with the event now acted on.
- **Gates kept:**
  - flood suppression and the age gate (`l7_engine.py:7-18`, `:86-131`);
  - min_events, applied as min views (8.1).
- **Gates added:**
  - a **key-age gate**: no action on a key younger than 20 s;
  - an **allowlist**: the server's own addresses and the monitoring identities.
- **Prerequisite.** The daemon-robustness fix (D-ROB) must be on the branch before any M run. One non-UTF-8 logged byte stops
  the daemon and detaches XDP (NEW-1) [FACT static chain, `S1:T-007/security.md` S1; `tasks/T-007/review.md`].

### 9.2 Graduated responses [PROPOSAL, D-V7]
1. **Level 1, key deny at nginx.**
   - The daemon writes `deny.map` (atomic write and rename) under a root-owned run directory. The protected nginx config
     includes it in a `map "$remote_addr|$http_user_agent|$cookie_sid" $l7_deny { default 0; include ...; }`.
   - A denied key gets 429.
   - A graceful reload (`nginx -s reload`) is issued **at most once per 10 s**, with batched updates.
   - The same file carries TTL bookkeeping (300 s, like `BAN_TTL_SECONDS`, `control_plane.py:112`).
2. **Level 2, XDP ban of the IP** (today's `ban_ip`, `control_plane.py:286-312`). Only if:
   - the key keeps sending ≥ 30 s after its level-1 deny;
   - **and** the IP is single-key: fewer than 3 distinct UA hashes and fewer than 3 distinct sids in the last 10 min.
   - An IP with ≥ 3 keys is **never** XDP-banned by the L7 engine. This is the CGNAT guard: IP blacklisting hits every
     subscriber behind a shared address `[G3-04-Q1]`, and CGNs are in > 90 % of cellular ASes `[G3-05-Q1]`.
3. **Fallback if the pilot shows reload trouble** (old workers lingering under many open connections [INFERENCE]):
   `auth_request` to a local deny service. It is compiled in (F-V6). It costs one subrequest per request, which is measured in
   the pilot. The choice is made before the campaign.

### 9.3 Safeguards and kill switch [PROPOSAL]
- **The enforcing path is off by default.** `L7_ENFORCE=0` is the default, as every L7 switch is today (`control_plane.py:31`).
- **Runtime kill switch:** the existence of `/run/l7v2/kill`, checked every poll. It stops new actions, empties the deny map
  (one reload) and lifts the L7 engine's XDP bans. L3/L4 bans stay.
- **Rate caps:**
  - ≤ 20 level-2 bans per minute;
  - ≤ 2,000 active denies;
  - beyond either cap the event is logged as "capped" and not enforced.
- **Logging.** Every action is a ban event with the arm, θ, k, p and the level (`ban_events.py` engines plus a new id, as
  `S1:T-007/p4_hooks.md` §1 describes).

### 9.4 What may be written into nginx's configuration [PROPOSAL; F-V7]
- **What is written:** only keys whose decoded UA is printable ASCII (0x20-0x7E), at most 256 bytes, without `"`, `\`, `;`,
  `{`, `}` or `$`, and whose sid matches the server's own format. They are written as one double-quoted string.
- **Any other key** can only reach level 2 (if single-key), or it is logged as "unenforceable" and counted as a miss.
- **Map size:** bounded by the 2,000 cap.
- **Tests** feed hostile UAs (quotes, braces, newline escapes, bytes ≥ 0x80) and assert that the file stays one
  `key value;` line per entry.

### 9.5 One enforcement path for every arm [PROPOSAL]
- **One interface.** The engine loads a detector package of any kind (GRU, HGB, LR or rule) with the same
  `score(batch) → p` interface. Rules give p ∈ {0, 1}.
- **Same policy for all.** Each package has its own θ and k. Every arm goes through 9.1-9.4, so speed and accuracy compare
  fairly (`final/PRIORITY_PLAN.md` §6.4).

## 10. Arms and their tuning

**Budget and selection [PROPOSAL]:**
- **The budget**, the same for every arm: ≤ 1 % of benign users flagged, pooled over the validation seeds.
- **The objective:** maximise attack-entity recall over the core classes' validation runs. Ties go to fewer benign flags, then
  to the lower median time to decision, then to grid order.
- **Validation seeds only.** P5c.4 tuned on the evaluation runs (`S1:T-005/p1_baseline_facts.md` §1); here the validation
  seeds come from P3 (`docs/P3_DATASET_DESIGN.md`).
- **Threshold grids** are written as multiples of the benign validation maximum of each statistic: τ ∈ {0.8, 1.0, 1.2, 1.5,
  2.0}. The rule is frozen now; the numbers come from validation.

| Arm | Live in the campaign? | Tuned on validation |
|---|---|---|
| unprotected (U) | yes | – |
| nginx limits only | replay, plus the existing EXP-A/EXP-C evidence | – |
| default rules (daemon, default profile) | **yes** for C3b (the status quo) | – (`control_plane.py:132-135`) |
| tolerant rules | replay | – (`control_plane.py:142-148`) |
| per-(IP, UA) sustained rate on windows {10, 30, 60} s, and a token bucket (rates {5..30}, bursts {10, 25, 50, 100}) | replay; the best of the rule arms runs live | grids of `ml/l7_baselines.py:39-43` |
| per-endpoint cost budget (new): per key, the sum of the frozen class costs over windows {10, 60, 300} s | replay; may be the live rule | τ grid |
| multi-scale rate (new): rates over {1, 10, 60, 300} s, each with its own threshold | replay; may be the live rule | τ grid per window, jointly at the budget |
| LR on token summaries | replay | θ ∈ {0.5, …, 0.999}, k ∈ {1, 2, 3, 5, 8} |
| HGB on token summaries | **yes** for C3b; replay for the controls | as LR |
| GRU (view level) | **yes** | as LR; architecture choices only on validation |
| GRU per request (seq 64) | replay (ablation) | as LR |
| shuffled-GRU (tokens shuffled within the window at scoring) | replay (ablation) | same θ, k as the GRU |
| GRU + best rule (OR, joint budget) | optional live 7th run | joint |
| population-level detector | replay | τ grid |

**Live set per block [PROPOSAL]:**
- C and C' (shared);
- C3b: U, default rules, best rule (R*), HGB, GRU;
- C2: U, R*, GRU;
- C3a: U, R*, GRU.

That makes 13 runs per block. R* is the rule arm with the best validation recall at the budget.

## 11. Outcomes, the verdict ladder, units and statistics

**Primary outcomes.**
- Q in the attack window, on judged links (5.2).
- Benign users wrongly acted on, at level 1 or level 2, per run, attributed from the manifest.

**Secondary outcomes.**
- p95 and dL.
- Time to mitigate: from the attack start to the first 5 consecutive 1-s bins with Q ≥ 99 %.
- Time to decision per attack entity.
- Attacker requests served.
- Server CPU.

**Detection metrics** come from replaying each U run's recording through every arm. The U run is unmitigated, so every arm
sees the same traffic, as in P5c.4. They are entity recall at the frozen operating point, benign FP per benign kind (held-out
kinds included), and time to decision.

**Units and statistics.**
- The unit is the **block**, one evaluation seed.
- ≥ 10 evaluation seeds (3001-3010), each with its own IP pool.
- Harm contrasts are paired by block with `eval/run_level_stats.py`: the 95 % t-interval, the exact sign-flip p, and the
  decision rule of ≥ 10 blocks, an interval excluding 0 and ≥ 80 % same sign (`eval/run_level_stats.py:58-66`, `:123`).
- Detection contrasts use a cluster bootstrap over (seed, entity), B = 2000, percentile 95 %.
- Power is reported for every contrast that is not shown (`eval/run_level_stats.py:133` `blocks_for_power`).

**Effect sizes [PROPOSAL]:**
- "**Beats**" on harm: the paired contrast is supported and its mean is ≥ 5 pp of Q.
- "**≈**" on harm (equivalence): the 95 % interval of the contrast lies inside ±5 pp.
- On detection, "beats" needs ≥ 10 pp with the bootstrap CI excluding 0, and "≈" needs the CI inside ±10 pp.

**The fixed testing order (gatekeeping)** controls the family-wise error at 0.05 [INFERENCE: fixed-sequence procedure]:
1. harm admission;
2. budget;
3. best learned arm vs R*;
4. GRU vs HGB;
5. GRU vs shuffled-GRU.

| Verdict | Condition (per class, after harm admission) |
|---|---|
| **V-A: the GRU beats all** | The GRU meets the budget, **beats** every live baseline arm on harm, **and** beats the HGB and the shuffled-GRU on detection by ≥ 10 pp |
| **V-B: learning helps, sequence does not** | The best learned arm **beats** R* on harm, but the GRU is not V-A: it is ≈ the HGB or ≈ the shuffled-GRU, or loses to them |
| **V-C: rules suffice** | The best learned arm ≈ R* on harm (equivalence) |
| **V-D: no advantage, or no harm** | U fails harm admission; or no enforcing arm meets the budget on the evaluation seeds; or no arm mitigates (Q(M) − Q(U) not supported for any M) |
| inconclusive | none of the above: reported with the power calculation; no verdict is claimed |

**Each verdict is reachable** [INFERENCE]: each needs a data pattern the rules permit.
- **V-A:** a C3b level where the multi-step structure (section 12) is visible only in order.
- **V-B:** C3b at M2, where the summaries see most differences.
- **V-C:** C2, where a cost budget matches the learned arms.
- **V-D:** a class whose U is harmless.

The verdict code is unit-tested on synthetic fixtures for all five outcomes before any evaluation data exist (section 13), as
P5b's verdict was (`docs/L7_GRU_DESIGN.md` §7.2).

**Priors, stated plainly.**
- For C3b: about 30 / 20 / 10 / 40 % for V-A / V-B / V-C / V-D (`final/PRIORITY_PLAN.md` §6.1) [CLAIMED prior].
- For C2 and C3a, V-B or V-C is expected, in line with the literature: feature models match sequence models wherever the two
  were compared (`[G1-02-Q3]`, `[G2-03-Q3]`, `[G6-01-Q1]`; `S1:T-012/lit_gap_fill.md` §6).

## 12. The circularity guard and held-out kinds [PROPOSAL, D-V6]

**The risk:** a benchmark the generator wins by construction (`S1:T-005/p1_baseline_facts.md` §4). The guard has six parts:
1. **Benign navigation from an externally grounded model.**
   - Kept: think time with mean 7 s and maximum 70 s `[G3-07-Q1]`; Zipf-like page popularity `[G3-06-Q4]` (α = 0.75 stays an
     [ASSUMPTION]: no α was found); page weight `[G3-01-Q1]`; connections per page `[G3-09-Q1]`.
   - Added: a **published multi-step transition model**, the TPC-W customer-behaviour mixes (browsing, shopping, ordering)
     mapped onto the testbed's page types: home → `/`, search → `/search`, product → `/page/<n>`, order → `/export`.
   - The TPC-W specification clause with the transition matrices was not retrieved: tpc.org returned HTML for the spec URLs
     (`S1:T-012/lit_gap_fill.md` G3-07). Retrieving it, or the customer-behaviour-model-graph literature it comes from, is a
     W-LIT task before the generators are frozen.
   - Until then the i.i.d. Zipf model stays. Any C3b result is then labelled "against a structureless benign model" and
     cannot support V-A.
2. **Bot navigation is specified separately**, in its own module, from the class definitions of section 7.1. It is not the
   benign planner with a flag flipped: `ml/l7_benign.py` gets no `if bot` branch. A test asserts that the bot module imports
   nothing from the benign planner except the site map and the asset waves.
3. **Held-out benign kinds** are never trained on or tuned on: the third TPC-W mix, `flash_crowd`, and api_bulk, as in P5b
   (`ml/l7_traffic.py:119`). Their FP is reported per kind.
4. **Held-out bot variants:** C3b at M3, and C3b with exponential dwell (evaluation only).
5. **No outcome-driven changes.** C3b's parameters are frozen before any model is trained. The harm ladder may change only the
   number of bots.
6. **An order audit**, descriptive and pre-registered. On validation data only, the gap between the HGB on token summaries and
   the shuffled-GRU is reported per mimicry level. It is used for nothing.

## 13. Pre-registration: what is frozen, by which commit, before which data [PROPOSAL]

| # | Frozen content | Before |
|---|---|---|
| 1 | this note, as approved (with your edits) | any L7 v2 code |
| 2 | the costed backend's route map, and the calibration record's sha256 (frozen HG2, or L7 v2's own) | any run that judges harm |
| 3 | generators, benign mix, class parameters, mimicry levels, seed lists (pilot 9001-9008, P3's training and validation seeds, evaluation 3001-3010) | the first P3 capture |
| 4 | the verdict code with fixtures for V-A, V-B, V-C, V-D and inconclusive; effect sizes; the testing order; the live set | the first evaluation block |
| 5 | every arm's operating point (θ, k, τ), chosen on validation seeds | the first evaluation block |
| 6 | the run index: every attempt, valid or not, with the reasons | reported with the results |

A departure is labelled post hoc in this note's "As built" section, as `docs/HG1C_DESIGN.md` §14 does.

## 14. VM budget, phasing and out of scope

**Offline build (T2, after approval)** [ESTIMATE]: 5-7 working days. It covers the costed backend; the harm records in the
runner; the pools and the manifest; the new benign kinds and the bot module; the log fields; the view tokens; engine v2 with
enforcement and safeguards; and the verdict code. Every piece gets fake-based tests in the style of `tests/test_daemon_rules.py`.

**VM time** [ESTIMATE]. One run is 180 s of traffic (30 s baseline, 120 s attack, 30 s recovery) plus ~45 s of set-up, about
3.75 min.

| Step | Runs | VM h |
|---|---|---|
| smoke: one run per mode | ~8 | 0.5 |
| harm ladder, 3 classes × 4 levels × 2 repeats × (C, U) | 48 | 3.0 |
| evaluation: 10 blocks × 13 runs | 130 | 8.1 |
| re-runs (≤ 2 blocks) | 26 | 1.6 |
| **total** | | **~13 h** (11.6 without re-runs) |

**Notes on the budget:**
- **Minimum cut:** C3b and C2 only. The block is C, C', C3b (U, R*, HGB, GRU) and C2 (U, R*, GRU): 9 runs, so the
  campaign takes 5.6 h. With a 3-level ladder (1.5 h) and the smoke (0.5 h) that is ~7.6 h, or ~8.7 h with re-runs.
- **The optional classes:** C4 and C1 add ~3.5 h each, including their ladders.
- **P3's captures are budgeted in the P3 note.** They supply training and validation data, not evaluation blocks.
- **Prerequisites:** D-ROB (daemon robustness), and the HG2 frozen record before any verdict run.

**Out of scope:** see section 2. In addition, no claim about real headless-browser bots goes beyond "a request-level
emulation of their observable pattern".

## 15. Risks

| Risk | Mitigation |
|---|---|
| The HG2 record stays a placeholder | The verdict code refuses it; pilots only |
| VM timer stalls inflate client-side latency (`S1:T-004/p2_capacity.md` §6) | The server-side cross-check (5.4); placebo C'; the re-run rule |
| The GRU loses (the most likely single outcome) | Plan the thesis so that V-B and V-C are full results (`final/PRIORITY_PLAN.md` §6.5) |
| Log-socket loss under load: 2.19 % steady, 40.1 % in flood bursts (`S1:T-005/o2_draft.md` §2) | The P1 classes are not floods; the analysis reads the lossless file sink; the live loss is reported per run |
| Reload storms, or config injection through the deny map | 9.2 rate cap; 9.4 write rules; the auth_request fallback |
| The C3b emulation is too easy or too hard | Mimicry levels fixed before the data; held-out variants; per-level reporting |
| Multiple comparisons | The fixed testing order (section 11) |

## As built (feat/l7v2-traffic; recorded 2026-10-31)

Every departure from the text above is labelled here, as section 13 requires. The approved text is left as it was.

**Accepted as built by the user (2026-10-31).**
- **The intensity application in the P3 captures** (`ml/l7_pools.py`):
  - C2's per-entity rate is m x L_knee x S / (n x cost);
  - C3a's page gaps are divided by m;
  - for C3b, m is recorded and not applied. C3b's frozen parameters may change only through the number of bots, and P3
    fixes that number.

**Re-registered by the user on 2026-10-31, before any capture** (review T-030):
- **The never-sent guard (L7V2-01, L7V2-02).** Each view, and each paced request, is judged against the device's own
  closed-loop schedule: the previous view's or request's completion plus its pause or gap. One stall then fails only the
  views that were slow, and a paced kind's own latency books no failure. (`ml/l7v2_prereg.json` harm;
  `eval/l7v2_harm.py`.)
- **Arrivals (L7V2-03).**
  - Benign entities arrive across the whole timeline in every role, and attack entities arrive across their slot.
  - Held-out benign kinds arrive like the trained ones. The flash crowd's minute starts at least 60 s from every slot start.
  - A plan is refused unless the first-seen times of the two roles are matched: KS ≤ 0.3, AUC within 0.5 ± 0.15, and the
    held-out kinds' KS ≤ 0.45. (`ml/l7v2_prereg.json` arrivals; `ml/l7_pools.age_check`.)
  - **This replaces section 5's reading** that the held-out benign kinds share the evaluation tail with C3b at M3. The
    tail slot holds C3b at M3. The held-out kinds arrive over the whole capture.
- **C3b's costly request (L7V2-04).** After each navigation view, the bot loads the costly route's form page, and a dwell
  later issues one costly request in-page from it. Its Referer and its timing are those of a benign search or export.
  C2 and C3a, the controls, keep their tells.
- **C3b's costly route is export (C5), search (C3) the variant** (the user's "Keep, aim at export", 2026-10-31). Its form
  page is the account page that benign exporters load. The page-then-dwell placement above is confirmed: its earlier
  "by the user" label was a forward reference. [ESTIMATE, arithmetic: AP-1's measured C5 cost of 159.7 ms, a costly
  request every three dwells (21 s at M2 or M3), the placeholder S = 0.552 CPU-s/s]
  - Each bot costs about 7.6 ms of CPU per second.
  - 300 bots give about 2.3 CPU-s/s, about 4 S, which is above the 0.75-1.06 CPU-s/s where T-004 expects harm.
  - About 100-140 bots reach that range; with C3, 300 bots gave only about 0.43.
  - `tasks/T-025a/artifacts/c3b_export_arithmetic.json`.
- **P3's benign target is 120 users per capture seed**, not 200 (`ml/p3_prereg.json`). 200 users do not fit the 300
  verified aliases next to the L7 v2 classes.

**Other departures, labelled post hoc:**
- **Navigation mapping (section 12.1).** The T-018 review's rules replace "search -> /search, order -> /export":
  - Home -> `/`; Product Detail -> `/page/<n>`;
  - Search Request -> the form page `/page/search`; Search Results -> `/search`, in-page from it;
  - New Products and Best Sellers -> `/page/new` and `/page/best`;
  - Order Inquiry -> the form page `/page/account`; Order Display -> `/export`, in-page;
  - the order flow and the admin pages are unmapped (the chain is watched on the mapped states).
- **Held-out and unused mixes.** Browsing is trained and Shopping is held out. Ordering is unused: 49.5 % of it has no
  route. The i.i.d. Zipf model is a held-out kind (`zipf_browser`), no longer the trained default.
- **Think time.** The think mean is drawn per device, uniform on [7, 8] s, within TPC-W v1.8's 7-8 s. The
  pre-registration's 7.0 s is the module default and M2exp's mean.
- **Log fields (section 8.4).** The third field is `sid_set` (`$upstream_cookie_sid`). `nginx_unprotected.conf` keeps
  its format because the harm benchmark pins its sha256, so a P1 runner renders the fields into its own copy (ledger D-028).
- **Schema 3** (sections 6 and 7.3):
  - two entities share an address in time (M3 on the C2 phase's addresses);
  - a CGNAT pool lists its users as entities, which the benign budget counts (`l7_dataset.user_units`).

## 16. As built: the model side (T-025b, 2026-10-30, branch `feat/l7v2-model`)

Built offline; nothing ran on the VM. Departures and readings are labelled; everything else is as sections 8 and 10 say.

**Frozen first.** `ml/l7v2_model_prereg.json` (commit d18b0ad, before any capture and before the code that reads it): the
key and its sid rule, the ingest hashing, the site map, the request-level `nav` group, the view tokens and their
summaries, the hyperparameters of every arm, the v2 probe gate, the 1 % budget in user units with the tie rules, and the
engine's constants. Each module's constants are tested against it.

**Readings of the design (not departures):**
- **Key (8.3).** sid_h is the hash of `sid_set` when the answer set a session, else of the `sid` cookie; with neither,
  the key is (IP, ua_h, −1), which is today's (IP, ua_h). `sid_set` wins because it names the session of a cookie-less
  first request (T-025a F7).
- **Referer (8.4).** Ingest hashes the Referer's path and query, so `ref_known` compares it with the uri hashes of the
  pages in the window. A foreign host's Referer maps to its path too; every testbed client refers to the one origin.
- **Route class at ingest (8.2).** `l7_ingest.route_class` restates `l7_webapp.route_class`, so ingest never imports the
  app; a test keeps the two equal.
- **History within the window (8.1, 8.2).** Refetch, revisit and `ref_known` look back over the window only, as
  `uri_repeat` does. The engine then needs only the last 33 tokens of a key, and training and serving compute the same
  numbers.
- **Order by start time.** Tokens are built in request start order (ties in arrival order), so a 10× slower server
  (`server_load`) leaves every token unchanged and the exact gate holds.
- **Complete tokens only.** A token's dwell is the gap to the next token's start. A window is scored once per completed
  token; the open token never enters.
- **Two-level model (D-V5).** The view encoder is one linear layer and a ReLU (32 units) on the design's token
  features. Its output is masked with `valid`; a GRU (64 units, 2 layers) runs over the encoded tokens. The token list
  gains `page_view` (see the next bullet).

**Additions the design does not cover (labelled post hoc, before any data):**
- **Pageless tokens.** A request while the key has no open page view is a token of its own. Without this, keys that
  never load a page (C2 by its definition in 7.1, API clients) would never be scored, so the view GRU's C2 recall would
  be 0 by construction. `page_view` tells such tokens from page views.
- **Sessions.** v2 keys idle for 300 s are evicted, and the trainer splits keys at the same start-time gap. The P5
  engine's 60 s would cut a benign key at the 70 s think-time cap.
- **The budget's unit cost.**
  - **The user's decision (2026-10-31):** "budget counted per key (a CGNAT user = one key)".
  - **The rule:** a flagged key costs one unit of its entity, at most the entity's `user_units` (`train_l7.unit_cost`).
  - **One rule, two consumers:** `train_l7v2.assess` (the arms) and `train_l7.operating_point` (the P3 curves and the
    trainer's validation rule) both use it.
  - **It supersedes** commit 9662960 of `feat/l7v2-traffic` ("the benign budget counts a pool by its users"). That
    commit charged a flagged pool all its users, in `train_l7.operating_point` and its test
    `test_the_budget_refuses_a_flagged_24_user_pool`. The denominator still counts a pool by its users.
  - **At the request level** the key is (entity, UA), so pool users who share a UA count as one key.
- **Recall's denominator** is every attack entity with a labelled request, the same for every arm. An arm cannot gain
  by scoring fewer entities.

**Arms (10), as built in `ml/train_l7v2.py`:**
- The view GRU, the HGB and LR on the same windows' token summaries, the per-request GRU (seq 64, `V2_REQUEST_GROUPS`),
  and the shuffled-GRU at the view GRU's (θ, k).
- The P3 curves (`ml/learning_curve.py`) score the shuffled-GRU at its GRU's (θ, k) too, at both levels. This is the
  user's decision of 2026-10-31. Before it, the P3 tool chose the shuffled-GRU's own validation point.
- **Not built here:**
  - the rule arms (per-endpoint cost budget, multi-scale rate, population-level detector);
  - the enforcing arm (9, T-025c);
  - the verdict code (11).
  The selection code takes any arm's per-window scores, rules included (p ∈ {0, 1}).

**Engine.** `l7_engine.L7ViewEngine` is observe-only.
- It scores at most 4 new windows per key per poll; older ones are skipped and counted.
- Records that started before a key's pruned history are dropped on arrival.
- `build_engine` picks it for a view package.
- A test checks that it scores exactly the trainer's windows.

**Published results.** The P5c paths are unchanged:
- `key_of`, the default feature groups, `TRANSFORMS`, `GATE_PROBES`, package format 1 and `train_l7`.
- On the P5c.3 capture, the base 30cb4d8 and this branch give byte-identical window matrices for all five variants,
  probe transforms and 2-epoch GRU weights (`S3:T-025b/test_logs/p5c_regen_*.json`).

## 17. As built: the D-034 fix round (T-041, 2026-10-31, branch `feat/l7v2-fix2`)

Review T-038 found that key age still coded the role (T038-01), that the v2 probe gate cannot fail a view arm on server
load (T038-02), that the seq-64 request ablation reads sizes (T038-03), and conformance gaps (T038-04..08). The user
approved the three recommended changes on 2026-10-31 at 12:10:57Z ("Approve all three", D-034). Built offline; nothing
ran on the VM and no capture exists. **Every item below is labelled post hoc, before any data.** Each frozen value was
committed in 7b40c86, sha256-pinned by tests, before the code that implements or judges it; T038-03's groups were
re-registered with their mirror constant in one commit.

**Key lifetimes (T038-01; `ml/l7v2_prereg.json` `arrivals.lifetimes`).**
- **One law for every key unit, whatever its role:** uniform on [60, 420] s [ASSUMPTION: no measured session-length
  source in the T-012 corpus]. Its floor is `min_active_s`; its ceiling is above the 240 s slot, so a share of the keys
  of either role outlives one slot.
- **Benign keys are sessions.** An L7 v2 browser-like kind (TPC-W browsing and shopping, the i.i.d. Zipf browser,
  search users, exporters, the flash crowd, and each CGNAT user) runs, from its first view, sessions of a drawn lifetime
  with a gap U[10, 120] s between two, while at least 60 s of its run remain. Each session starts with a fresh browser
  state: no cookies, so a new sid and a new key, and an empty cache. A returning user is a new key. The entity, its
  address, its UA and its budget units are unchanged, so the 120 benign users (D-031) and the per-key budget rule hold.
- **Machine clients** (the polite crawler, api_bulk and the P5 kinds, whose generators have no sessions) run one
  lifetime from their arrival.
- **Attack entities** run one lifetime from their arrival, which is unchanged. So an attack key may stay active past its
  slot, into the next slot or the tail: 70-80 % of the attack entities at seeds 1001, 2001 and 3201 run past their
  slot's end, 52-64 % by more than 60 s, and 40-51 % live longer than a slot. The class parameters are unchanged.
- **Evaluation and pilot captures** end with the same 120 s benign tail after the M3 slot that every capture has after
  its last slot: 1,140 s instead of 1,020 s (`ml/p3_prereg.json` `eval_capture_s`, re-registered). Without it the M3
  bots' lifetimes, and so their window ages, are cut short (window-age AUC 0.31 at seed 3201). **VM cost:** +120 s per
  evaluation and pilot capture.
- **M3's addresses.** An M3 bot takes the address of a trained attack entity that has stopped before it starts and that
  no other M3 bot holds, C2 entities first. With lifetimes past the slots, C2's addresses alone do not always suffice.

**The extended age check (`arrivals.age_check`, `rule_v2`; `ml/l7_pools.age_check`).** The first-seen check is unchanged.
A plan is also refused unless:
- the lifetimes of the trained benign and attack key units have KS <= 0.3 and an AUC within 0.5 ± 0.15;
- window age has an AUC within 0.5 ± 0.15, pooled and for every attack family with >= 20 key units, held-out families
  included, each against the trained benign windows;
- the held-out benign kinds' lifetimes have KS <= 0.45 against the trained kinds'.

Window age is replayed at nominal times, as T-038's probe does.

**The re-run of T-038's probe (the acceptance test)** [FACT, `S3:T-041/artifacts/probe_age_tokens_*.txt`]:

| Seed | AUC(window age), pooled | C3b@M2 | Held-out C3b@M3 |
|---|---|---|---|
| 1001 train, before -> after | 0.886 -> 0.496 | 0.860 -> 0.516 | – |
| 2001 val, before -> after | 0.877 -> 0.520 | 0.861 -> 0.544 | – |
| 3201 eval, before -> after | 0.877 -> 0.545 | 0.847 -> 0.486 | 0.849 -> 0.533 |

- **The check on every pre-registered seed** (train, validation, P3 and P1 evaluation, pilots; 36 plans) and on the
  extension seeds 3211-3220 passes. Window-age AUC is 0.449-0.537; C3b@M2 0.456-0.587; C3b@M3 0.438-0.517.
  Lifetime KS is <= 0.267 and its AUC 0.515-0.642; attack keys live a little longer, because benign sessions are cut by
  the capture's end more often. The benign gate drops no entity.
- **What stays.** The probe's token-count AUCs (entry flag 0.12-0.23, n_valid) now separate in the other direction:
  C2's high rate gives its keys many full windows. That is rate, a class behaviour, not age. C3b@M2 still holds its
  entry token in 97-100 % of its windows, against 84-87 % of benign windows (T-038: 100 % vs 46 %), because it makes
  about two tokens per three dwells.
- **The probe's in-phase restriction** drops the windows outside every attack slot. It now also drops the oldest windows
  of the bots that outlive the last slot. So C3b@M2's in-phase AUC is 0.638 and 0.664 at seeds 1001 and 2001, where
  C3b's slot is the last one, against 0.516 and 0.544 on all windows. That is inside the band, and the pre-registered
  check uses all windows.

**The age-only baseline (T038-01; `ml/l7v2_model_prereg.json` `baselines.age_only`; `train_l7v2.age_scores`).**
- **The score:** the key-level time since the key session's first view. p is the share of the training benign windows
  that are older, so the θ grid reads quantiles of the benign training ages.
- **Selection:** it takes its operating point by the same rules as every arm, sits in `selection.json` and `eval.json`
  under `baselines`, and is never selected or run live.
- **Pre-registered reading:** its validation AUC must lie within 0.5 ± 0.15. Outside the band, every view-level result on
  those captures is age-confounded and supports neither V-A nor "sequence helps".
- **On synthetic validation** replayed from the plans at nominal times (train 1001, validation 2001;
  `S3:T-041/artifacts/age_only_synthetic_*.json`): AUC 0.874, "age-confounded", with T-038's lifetimes; AUC 0.520, "near
  chance", with D-034's.
- **What it still catches.** At its operating point (θ 0.99, k 5) it catches 48 of 160 attack entities, all C2 at load
  level 0.5. The earliest windows of a fast key are younger than any benign window, because time since the first view
  at token j is about j divided by the token rate. That is rate, read through age, at the extreme tail. It is reported,
  not gated.

**T038-03, the request ablation's groups (`request_level.groups`, `l7_features.V2_REQUEST_GROUPS`).** Re-registered
post hoc, before any capture: the size group (log_rlen, log_bsent, size_ratio) is dropped, as P5c's published
`no_size_no_server_timing` drops it. A request-versus-view comparison then no longer mixes the horizon with sizes.
`DEFAULT_GROUPS` and the P5c paths are unchanged.

**T038-02, the probe gate and the load split.** See section 8.5. The gate is a pipeline-invariance check. The
descriptive load split is reported per arm on validation.

**Conformance (LOW).**
- **T038-04, one tuning rule.**
  - Every learned arm runs fixed epochs or iterations, and the last epoch is kept. The GRUs no longer keep their best
    epoch by validation loss, and the HGB no longer early-stops on 10 % of its training windows.
  - One class weighting, balanced: the GRUs' pos_weight = negatives / positives, the LR's and the HGB's 'balanced'. The
    P3 view-level curves use the same HGB.
  - Not changed: the P3 request-level curves still call `train_l7.train_gru`, which keeps its best validation epoch.
    Changing it would touch the P5c code path. Their GRU is the ablation, not an L7 v2 arm.
- **T038-05, the shuffled-GRU.** Its benign units are reported beside every gap, in `selection.json` and in
  `eval.json`. A second variant keeps each window's first valid token in place (`pin_first`). Both use the view GRU's
  (θ, k).
- **T038-06, engine-trainer parity.** At the view level the evaluator counts k consecutive windows over the windows the
  live engine would score: per key and 1-s poll, the newest 4 (`train_l7v2.engine_scored`). A parity test drives
  `l7_engine.L7ViewEngine` (unchanged) with a key that completes 8 windows a second. The request level, an offline
  ablation, scores every window.
- **T038-07, the selection freeze.** `select` refuses a directory that already holds a selection. `score` takes the
  training and validation captures from split.json: from the frozen selection's `split_dirs` when they are omitted.
  Given or not, their capture ids and manifest hashes must be exactly split.json's.
- **T038-08, limitation.** Exporters have a median of 3 view tokens per key, and with sessions 1-2. A view window needs
  5 token starts, so no view arm scores the exporters, while the request ablation can. C3 and C5 merge into one costly
  count at the token level, so the search users remain C3b's matched negatives. Exporter FP is reported per kind.

**Files touched in this round:**
- `ml/l7v2_prereg.json`, `ml/l7v2_prereg.py`, `ml/l7v2_model_prereg.json`, `ml/p3_prereg.json`;
- `ml/l7_benign.py` (the session path, opt-in; the L7 v2 kinds only), `ml/l7_pools.py`, `ml/train_l7v2.py`,
  `ml/learning_curve.py` (one line: the view HGB), `l7_features.py` (`V2_REQUEST_GROUPS`);
- tests, and this note and the P3 note.

`control_plane.py`, `l7_engine.py`, `bench/`, `server/`, the nginx confs and `l7_backend.py` are untouched.

## 18. As built: the verdict constants, the rule arms, the verdict code and the replay scorer (T-025d, 2026-10-31, branch `feat/l7v2-arms`)

Built offline; nothing ran on the VM and no capture exists. Every item below is labelled post hoc, before any data.

**Frozen first (section 13 item 4).** `ml/l7v2_verdict_prereg.json` (commit 2b8b949), sha256-pinned by its test before
the verdict code existed: the ladder, the effect sizes, the testing order, the live set, R*'s definition and
candidates, the units and statistics, and the blocks on V-A. `ml/l7v2_rules_prereg.json` (commit d663785) freezes the
rule arms' grids and readings with the code that tunes them, before any capture.

**Open judging choices, written down and not picked** (`open_choices`, resolution null; for the user):
- OC-1, the "best learned arm" of V-B and V-C for C3b: the live learned arm with the higher evaluation mean Q, the one
  with the higher validation recall, or the GRU.
- OC-2, the measure of "meets the budget on the evaluation seeds": the replay of the U runs, or the live M runs.
- OC-3, whether U is one of V-A's "live baseline arms".
- OC-4, the verdict when R* beats the best learned arm on harm (no rung names it): inconclusive, or V-C.
- `ml/l7v2_verdict.judge` computes the verdict under every combination of the open options and claims one only when
  all agree; otherwise it names the choices that decide it. A resolution is a new file version.

**Readings of section 11 (R-1..R-8 in the file):** harm contrasts are `eval/run_level_stats` unchanged; detection
contrasts compare the replays of the same U runs, with a two-stage bootstrap (blocks, then entities within a block);
V-A's other harm contrasts join step 3 as an intersection-union test; V-B's "equivalent to or loses to" is the detection
contrast (the shuffled-GRU never runs live); a V-A that a block stops (age-confounded validation, structureless benign
model) is inconclusive with the block named; the shuffled-GRU of the ladder is the plain variant. Under the fixed
testing order, steps 4 and 5 are reached only when step 3 (the best learned arm beats R*) passes, so V-A needs it too.

**The rule arms (`ml/l7v2_rules.py`), readings for strong baselines:**
- **Decision points.** A rule decides where the view arms decide: the same (IP, UA, sid) keys and view windows, the
  windows the live engine would score, the same k-consecutive policy, budget, objective and ties. Rules give p in
  {0, 1}, so theta is fixed at 0.5 and k comes from the common k grid.
- **The statistic of a window** is the maximum of its per-request value over the requests of its state key since the
  key's previous scored window (looking back at most 300 s), so no burst between two decision points is lost.
- **Key.** Each per-key arm takes (IP, UA), as section 10 writes, or the L7 v2 key (IP, UA, sid), chosen on validation.
- **Grids.** The cost budget takes one window per grid point (section 10 says "tau grid", not "jointly"); the
  multi-scale rate and the population detector take their tau per statistic jointly. Grid order is k first, then the
  arm's own grid as listed.
- **R*'s candidates** are the four arms whose section-10 row says "the best of the rule arms runs live" or "may be the
  live rule". The population detector (replay only) and the fixed replays (default and tolerant rules, nginx limits)
  are reported and never R*.
- **The fixed replays** run on the log's completion time, not on the daemon's receive clock. nginx's `limit_conn` is
  not replayable from an access log and is left out.

**Finding: on synthetic validation, three of the four R* candidates are starved by their grids** [synthetic plans
2001 and 2002 replayed at nominal times, placeholder record; `S3:T-025d/artifacts/rules_synthetic_val_2001_2002.json`].
- The sustained-rate thresholds (2-50 req/s) and the token-bucket rates (5-30 r/s) of `ml/l7_baselines.py` were sized
  for P5's floods. A C2 source sends m x L x S / (n x cost) req/s, under 1 req/s at L = 4 on the placeholder, and a
  C3a or C3b bot a page every 2-12 s. Each arm catches 2 of 320 attack entities at its point.
- The tau grid starts at 0.8 x the benign validation maximum. Benign page loads are the burstiest keys, so every
  attack family's per-key rate stays below that floor on every window, and the multi-scale rate catches 0 of 320.
- The cost budget reaches its point at the grid's lowest tau (0.8 over 60 s per L7 v2 key, 1 of 2 allowed benign units)
  and catches 270 of 320 (C2 and C3b all, C3a half). It is R* here, at the edge of its grid.
- The grids are left as approved. Extending them downward, or replacing the multiples with benign quantiles, is the
  user's call, before any capture.

**The replay scorer (`ml/l7v2_replay.py`).** A recording (records and poll ticks) runs through each view arm's own
`l7_engine.L7ViewEngine` at its frozen (theta, k), and through `TapEngine` for the rule arms and the age-only arm: the
same engine, which also hands the windows it is about to score to the arm. A key is decided at the poll of its first
`l7_would_ban`; time to decision runs from the entity's first request start to that poll, at most one poll later than
the evaluator's deciding window. Tests check that the rule arms, the age-only arm and a view arm decide in the replay
exactly the keys `train_l7v2` decides on the same records.

**L7V2-08.** Knees carry `record_sha256`, the digest of the calibration record they were measured on.
`l7_pools.build_plan` refuses knees whose record is not the one in use (any role), and a training, validation or
evaluation plan on a record that is not frozen or with knees that name no record. T-041's age check of the 36
pre-registered plans ran on the placeholder; a frozen record with the placeholder's numbers gives the same plans
(`tests/test_l7v2_population.py`).

**Files touched in this round:** `ml/l7v2_verdict_prereg.{json,py}`, `ml/l7v2_rules_prereg.json`, `ml/l7v2_rules.py`,
`ml/l7v2_verdict.py`, `ml/l7v2_replay.py`, `ml/l7_pools.py` (`_knees`), `ml/capture_l7.py` (one help line), tests and
this note. `control_plane.py`, `l7_engine.py`, `bench/`, `server/`, the nginx confs and the generators are untouched.

## References (T-012 ids; full IEEE entries in `S1:T-012/bib_ieee.txt`)
- G1-01 Li et al., S&P 2021.
- G1-02 Kadel et al., BOTracle, ESORICS Workshops 2024.
- G1-03 Jacob et al., PUBCRAWL, USENIX Security 2012.
- G1-04 Iliou et al., DTRAP 2021.
- G2-01 Kuzmanovic & Knightly, SIGCOMM 2003.
- G2-02 Zhijun et al., IEEE Access 2020.
- G2-03 Ben David & Bremler-Barr, CLOSER 2021.
- G3-01 / G3-09 HTTP Archive Web Almanac 2024.
- G3-04 RFC 6269.
- G3-05 Richter et al., IMC 2016.
- G3-06 Jung et al., WWW 2002.
- G3-07 TPC-W white paper.
- G4-03 Demoulin et al., FineLame, ATC 2019.
- G5-01 Kandula et al., NSDI 2005.
- G5-03 Meng et al., Rampart, USENIX Security 2018.
- G6-01 Grinsztajn et al., 2022.
