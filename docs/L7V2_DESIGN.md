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

**Re-registered 2026-11-02, before any capture (D-051, D-053, D-054; `ml/l7v2_verdict_prereg_v3.json`).** The testing order, the budget step, what carries V-B and V-C, the latency-alone rule and the harm window below are superseded as section "As built: the P1 runner" says.

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

**VM time** [ESTIMATE, re-computed 2026-11-02 under D-053]. One run is 270 s of traffic (30 s baseline, 210 s attack, 30 s recovery) plus
~45 s of set-up, about 5.25 min. The ladder's runs are what its levels can reach (section "As built: the P1 runner").

| Step | Runs | VM h |
|---|---|---|
| smoke: part A on two seeds, the alias read, part B | 10-11 | 0.9-1.0 |
| the halving rule (D-049): 2 runs per step, 1-3 steps | 2-6 | 0.2-0.5 |
| harm ladder, the reachable levels × 2 repeats × (C, U) | 28-32 | 2.5-2.8 |
| evaluation: 10 blocks × 13 runs | 130 | 11.4 |
| re-runs (≤ 2 blocks) | 26 | 2.3 |
| **total** | | **~18 h** (about 15.5 without re-runs) |

**Notes on the budget:**
- **Minimum cut:** C3b and C2 only. The block is C, C', C3b (U, R*, HGB, GRU) and C2 (U, R*, GRU): 9 runs, so the
  campaign takes 7.9 h. With the same smoke, rule and ladder that is ~12 h, or ~13.7 h with 18 re-run runs.
- **The optional classes:** C4 and C1 add ~3.5 h each, including their ladders.
- **P3's captures are budgeted in the P3 note.** They supply training and validation data, not evaluation blocks. D-052's two more validation
  seeds add 0.6 VM h there.
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
  its last slot: 1,140 s instead of 1,020 s (`ml/p3_prereg.json` `eval_capture_s`, re-registered). D-034's text does not
  cover the capture's length: the user confirmed it at 14:46:37Z ("Confirm 1140 s", D-036), after 7b40c86 had committed
  it (T-042 F05). Without it the M3 bots' lifetimes, and so their window ages, are cut short (window-age AUC 0.31 at
  seed 3201). **VM cost:** +120 s per evaluation and pilot capture.
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
  extension seeds 3211-3220 passes. Window-age AUC, age as a score for the attack role, is 0.449-0.537; C3b@M2
  0.456-0.587; C3b@M3 0.438-0.517. C3b@M1 has 10 key units, so the per-family check exempts it: over the 34 P3 and P1
  plans it reads 0.336-0.575, outside the band at pilot 9008 (section 18).
  Lifetime KS is <= 0.267 and its AUC 0.515-0.642; attack keys live a little longer, because benign sessions are cut by
  the capture's end more often. The benign gate drops no entity.
- **What stays.** The probe's token-count AUCs (entry flag 0.12-0.23, n_valid) now separate in the other direction:
  C2's high rate gives its keys many full windows. That is rate, a class behaviour, not age. C3b@M2 still holds its
  entry token in 97-100 % of its windows, against 84-87 % of benign windows (T-038: 100 % vs 46 %), because it makes
  about two tokens per three dwells.
- **The probe's in-phase restriction** drops the windows outside every attack slot. It now also drops the oldest windows
  of the bots that outlive the last slot. So C3b@M2's in-phase AUC is 0.638 and 0.664 at seeds 1001 and 2001, where
  C3b's slot is the last one, against 0.516 and 0.544 on all windows. **Corrected 2026-11-01 (T-042 F02):** this bullet
  first called both values inside the band, but 0.664 is outside 0.5 ± 0.15. The pre-registered check uses all windows,
  so it does not see this. Section 18 gives the in-phase view of every family, held-out C3b@M3 included.

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

## 19. As built: the rule arms at their own level, and the user's decisions D-043 and D-044 (T-025d, 2026-11-01, branch `feat/l7v2-arms`)

Built offline; nothing ran on the VM and no capture exists. Every item below is labelled post hoc, before any data. Each
frozen file was committed and sha256-pinned before the code that reads it. Where this section and section 18 differ,
this one holds.

**T042-E08, the rules' level (format 2, commit cabe284; format 3 keeps it).** Review T-042 found that
deciding the rules on the view windows of (IP, UA, sid) keys starves them: a C2 key's 32-token window spans seconds, and
sid rotation splits an (IP, UA) key.
- **Level.** A per-key rule is keyed (IP, UA) over wall-clock windows of the key's whole history. The population
  detector and the daemon heuristic act on the address and reach a key through its own requests. nginx's `limit_req`
  acts on the key that sent the rejected request. The key is no longer a grid dimension.
- **Decision points.** One row per (IP, UA) key and engine poll in which the key has a request: each statistic's
  maximum over those requests. The section-9 policy runs over the rows: p > 0.5 in k consecutive rows of the key.
- **Age.** An (IP, UA) key age-only arm sits beside the rule arms on validation, with the address age's AUC (T042-F01).
  It is a diagnostic, never R* and never live.
- **What R* needs live.** Its own (IP, UA) path beside the view engine: every log record feeds its statistics, every
  poll gives its rows, and section 9 applies unchanged, with a level-1 deny that covers every session of the (IP, UA)
  key (the map of 9.2 is keyed IP|UA|sid today) and a level-2 ban only for a single-key address.
  `ml/l7v2_replay.RulePath` is that path in the replay.

**D-043 (the user: "Benign quantiles"; "M2; charge users behind"; `ml/l7v2_rules_prereg_v3.json`).**
- **Thresholds.** A level is a multiple of section 10 {0.8, 1.0, 1.2, 1.5, 2.0} x the benign validation maximum, or a
  quantile {0.5, 0.75, 0.9, 0.95, 0.98, 0.99, 0.995} of the statistic's per-key maximum over the benign keys. The
  quantiles read the share of benign keys flagged at k = 1, which is why they are taken over keys and not rows.
- **Absolute grids.** Sustained-rate thresholds extend down to 0.05 req/s and bucket rates down to 0.1 r/s.
- **Cost of a flag.** A flagged (IP, UA) key costs every benign user behind it: the devices of its entity's plan that
  carry that UA, at most the entity's units. D-031's one unit per key stays for the learned arms' view-level keys.
- **Detection entities (`ml/l7v2_verdict_prereg_v2.json`).** C3b's primary contrast reads C3b@M2. M1, M3 and M2exp get
  their own descriptive contrasts and judge nothing.

**D-044 (the user: "Settle as recommended"; `ml/l7v2_verdict_prereg_v2.json`).** The verdict code now claims one verdict.
- OC-1: the best learned arm has the higher validation recall at the budget, frozen in the selection (ties: the GRU).
- OC-2: the budget on evaluation is benign users wrongly acted on in the arm's own M runs, pooled over blocks. The
  replay's reading is reported beside it and judges nothing.
- OC-3: V-A's live baselines include U.
- OC-4: when R* beats the best learned arm on harm the verdict is V-C, read as "rules suffice or win".

**Re-measured on synthetic validation** [synthetic plans 2001 and 2002 at nominal times, a frozen fixture record with the
placeholder's numbers; a plan user's sid starts at its first page, as the origin issues it; 320 attack entities, 252
benign users, 2 allowed; `S3:T-025d/artifacts/rules_level_synthetic_val_2001_2002.json`]:

| Arm | Point | Caught | Benign users | C2, C3a, C3b@M1, C3b@M2 |
|---|---|---|---|---|
| cost budget (R*) | 60 s, q 0.995, k 3 | 255 of 320 | 0 | 100/100, 41/100, 20/20, 94/100 |
| sustained rate | no point catches | 0 | 0 | none |
| token bucket | no point catches | 0 | 0 | none |
| multi-scale rate | no point catches | 0 | 0 | none |
| population (no candidate) | new keys tau 1.0, cookie-less tau 0.8, k 2 | 100 | 0 | 100/100, 0, 0, 0 |
| default rules (fixed) | - | 58 | 97, over budget | 0, 0, 14/20, 44/100 |
| tolerant rules, nginx limits (fixed) | - | 0 | 0 | none |
| (IP, UA) age-only (diagnostic) | theta 0.999, k 2; AUC 0.750, address 0.787 | 0 | 0 | none |

**Three R* candidates still catch nothing, and the grids are no longer the reason.** On every rate window the attack
families' per-key maxima lie inside the benign distribution: over 10 s at most 10.4 req/s against a benign q 0.99 of 12.4,
over 60 s at most 3.7 against 4.5, because a benign browser's page load is the burstier client. No threshold does better: 200 log-spaced thresholds on each rate and
bucket statistic alone, at every k, catch 0 attack entities within the budget (`any_threshold` in the file), and an OR
of statistics that each catch none within the budget catches none. A rate rule cannot separate these low-rate classes
within the budget. The cost budget can, because it reads what a request costs and not how many arrive, and its grid
reaches the best any threshold reaches (255 over 60 s), so it is not starved. These numbers are synthetic and on placeholder costs; the
real validation captures decide.

**Correction (T-048, T048-03 and T048-04, 2026-11-02).** "255 of 320 at 0 benign users" holds on the validation plans only, and it is no reading of P1's harm.
[FACT, synthetic, T-048's own replay.] At that point, on evaluation plans of seeds 3001-3010, R* charges 69 of 1778 benign users against a budget of 17, nearly all of them
behind CGNAT pools (59) and api_bulk (10), a held-out kind; other stream labels draw other points, and all those measured stay over the budget. On P1's blocks at the former 120-s attack it decided late, and
83 % of C3b's cost, 91 % of C3a's and 38 % of C2's stayed served by the worst case of the enforcing path. "The best any threshold reaches" holds for the v1 label
only. D-051, D-052 and D-053 answer this; section "As built: the P1 runner" has them, and the figures at 210 s.

**The (IP, UA) age-only arm reads "age-confounded"** (AUC 0.750, address 0.787), as T042-F01 found, yet catches nothing
at the budget. No rule arm reads a key's age, so R*'s recall does not come from it; a model keyed (IP, UA) would be
exposed to it.

**Files touched in this round:** `ml/l7v2_rules_prereg_v3.json` and `ml/l7v2_verdict_prereg_v2.json` (each replacing its
earlier format), `ml/l7v2_verdict_prereg.py`, `ml/l7v2_verdict.py`, `ml/l7v2_rules.py`, `ml/l7v2_replay.py`, tests and this
note. `control_plane.py`, `l7_engine.py`, `bench/`, `server/`, the nginx confs and the generators are untouched.

## As built: the enforcing arm (T-025c, 2026-10-31, branch `feat/l7v2-enforce`)

Built offline; nothing ran on the VM. Section 9 as written, with these readings and additions (labelled post hoc,
before any data). Usage and events: `docs/EVALUATION.md`, "L7 v2: the enforcing arm".

**Readings of the design (not departures):**
- **Key-age gate (9.1).** A decision on a key younger than 20 s waits and is acted on when the key is 20 s old. The
  engine fires once per streak, so dropping it would let a fast key escape for good.
- **"Keeps sending >= 30 s after its deny" (9.2).** A request of the key that started at least 30 s after the reload
  that published its deny (nginx answers it 429 and logs it). For an unenforceable key, whose level 1 is a miss, the
  reference is the decision.
- **Single-key (9.2).** Distinct UA hashes, and distinct sids of requests that carry one, seen from the address in
  the last 10 min. An address the arm has not seen counts as shared.
- **TTL (9.2).** A deny ends 300 s after it was added (not after it took effect).
- **One path (9.5).** The enforcing arm takes its detector and operating point from the frozen selection
  (`L7_SELECTION`, its sha256, `L7_ARM`), never from `L7_MODEL` (the shadow's), so a placeholder point cannot reach it.

**Additions the design does not cover:**
- nginx matches map strings ignoring case and refuses a map that lists one key twice, so keys that differ only in
  case share one line (`ngx_http_map_module.c`, `ngx_hash.c` of nginx 1.28.3).
- nginx refuses a map whose longest key does not fit a hash bucket; the run's conf sets the bucket and max sizes.
- No deny outlives its daemon: the map is emptied at the daemon's start and stop. The kill switch also drops the
  decisions waiting for the key-age gate.
- The level-2 ban reaches `ban_ip` through the arm's injected callable, engine `l7v2`, kept out of
  `ban_events.ENGINES` (which `tests/test_control_plane_contract.py` pins to the direct calls).

**Fix round after review T-042 (2026-10-31), each its own commit:**
- **E01, canonical addresses only.** No decision, at level 1 or level 2, on an address that is not a canonical
  dotted-quad IPv4 address (skip reason `ip_format`); the allowlist fails closed on one, and the CGNAT guard counts
  canonical addresses only. The XDP ban path parses with `inet_aton`, which reads `10.0.4617`, `012.0.18.9`,
  `0xa.0.18.9` or `10.0.18.9 ` as 10.0.18.9: a forged datagram could have bypassed the guard and the allowlist of
  the real address.
- **E02, a key without a session (orchestrator's decision D-040, under the CGNAT guard).** Its line `ip|ua|` matches
  every cookie-less request from the address with that UA, any case, a new user's first request included. It is
  written only while the address is single-key in the guard's window; on a shared address the key is a miss
  (`sid_less_shared`), and a line already written is withdrawn once the address turns shared. Level 2 is unchanged.
- **E03, the stop.** `Arm.stop` and the arm's own steps hold one lock and no step runs after the stop: a step in flight
  could add entries after the stop's clear or replace its empty map (65 of 300 trials in the review's probe).
- **E04, the kill switch's reload is paced** like every other (at most one per 10 s), so it may come up to 10 s after
  the file appears; only the daemon's stop reloads at once. A file toggled every second gave 30 reloads a minute.
- **E05, claims-valid selections only.** A selection marked `valid_for_claims` false (a `--smoke` run or a legacy
  capture) is refused for enforcement; the daemon logs why (`daemon_error`, `where` `l7_enforce`) and does not start.
- **E06, the L7 socket.** With the arm on, a datagram on the sink can drive a ban, so the socket is bound 0660 with
  nginx's group (`L7_SOCKET_GROUP`, default `nogroup`: the installed nginx's compiled worker group, as no `user` is
  set) instead of 0666; without `L7_ENFORCE=1` it is 0666 as before. An unknown group stops the daemon at start.
- **E07, hostile field types.** `l7_ingest.normalise` drops a record whose text field holds another JSON type than a
  string (only a forged datagram can); it used to raise, or make the engine's keys unsortable, and so restart the
  shadow thread with a fresh engine. Records nginx writes normalise as before; the engine is unchanged.

**A conflict for the user, resolved by D-038 (below).** 9.4 excludes `;` from a writable UA. Every UA of
`ml/l7_benign.UA_TABLE` contains one (17 of 17, weight 0.99 of 0.99; 3 of the 6 `ml/l7_gen.UAS`), so as written no
testbed browser key can be denied at level 1: P1's arm would act only by misses and level-2 bans of single-key
addresses. Inside nginx's double quotes only `"` and `\` are special (`ngx_conf_read_token`,
`src/core/ngx_conf_file.c` of 1.28.3); `;`, `{`, `}` and `$` are ordinary. Without `;` in the rule, all 23 UAs pass.

**Amendment D-038 (2026-10-31; the user's decision "Allow ';'", before any data).** 9.4's write rules now allow `;` in
a UA written into the deny map. `"`, `\`, `$`, `{`, `}`, bytes outside 0x20-0x7E and UAs over 256 bytes stay
excluded (`l7_denymap.FORBIDDEN_UA_CHARS`). All 17 UAs of `ml/l7_benign.UA_TABLE` and all 6 of `ml/l7_gen.UAS` pass;
the tests write UAs with `;` alone, repeated, next to quotes and backslashes, and at either end, and read the file
back with a port of nginx's tokenizer: one `"key" 1;` line per entry.

## 20. As built: the T-042 fix round (T-041, 2026-11-01, branch `feat/l7v2-fix2`, D-040)

Review T-042 rated the D-034 round READY-WITH-NITS; the orchestrator ordered these follow-ups under D-040 (2026-10-31,
15:48:50Z). Built offline; no capture exists, and **the generators are unchanged in this round**. Everything here is
labelled post hoc, before any data. The new baseline and readings were registered in 07c086d before their code.

**The figures are recomputed** [FACT, `S3:T-041/artifacts/round2/age_views_34plans.*`, my own script; T-038's probe re-run
unchanged at 07c086d, `probe_age_tokens_34plans_07c086d.txt`]. They cover 34 plans at nominal times: P3 training and
validation, P3 and P1 evaluation, P1 pilots (28 of them hold C3b@M3).
- **Direction.** Unlike rule_v2's window-age AUC (age as a score for the attack role), the table below is AUC(-age):
  P(an attack window is younger than a trained benign window). It is 1 minus rule_v2's reading, and T-038's and T-042's
  direction.
- **Agreement with T-042.** My figures match T-042's to rounding, except C2 at the pilots, where I built the plans with
  the placeholder knee, as a pilot plan is built. For example, pooled at 9004 reads 0.471 in T-042's run with a frozen
  knee.

| View: range over the plans (plans outside 0.5 ± 0.15) | Trained, pooled | C2 | C3a | C3b@M1 | C3b@M2 | Held-out C3b@M3 |
|---|---|---|---|---|---|---|
| A. Key (IP, UA, sid), all windows | 0.463-0.551 (0) | 0.461-0.576 (0) | 0.402-0.533 (0) | 0.425-0.664 (1) | 0.413-0.544 (0) | 0.483-0.562 (0) |
| B. As A, inside attack phases | 0.450-0.630 (0) | 0.444-0.721 (3) | 0.393-0.527 (0) | 0.410-0.789 (2) | 0.399-0.664 (1) | 0.599-0.685 (11 of 28) |
| C. As A, time-matched in 30-s bins | 0.418-0.595 (0) | 0.384-0.642 (0) | 0.343-0.534 (1) | 0.341-0.693 (3) | 0.341-0.623 (1) | 0.507-0.607 (0) |
| D. From the (IP, UA) key's first request | 0.750-0.837 (34) | 0.748-0.837 (34) | 0.713-0.838 (34) | 0.735-0.873 (34) | 0.719-0.823 (34) | 0.809-0.851 (28 of 28) |
| E. From the address's first request | 0.792-0.859 (34) | 0.790-0.860 (34) | 0.764-0.859 (34) | 0.781-0.903 (34) | 0.769-0.844 (34) | 0.154-0.537 (12 of 28) |

Plans outside the band in views A-C:
- **A:** C3b@M1 at 9008 (0.664).
- **B:** C2 at 1003, 1004 and 2002 (0.672, 0.721, 0.686); C3b@M1 at 1001 and 2001 (0.789, 0.697); C3b@M2 at 2001 (0.664);
  C3b@M3 in 11 of 28 plans (up to 0.685 at 3201).
- **C:** C3a at 1002 (0.343); C3b@M1 at 1001, 2001 and 3209 (0.693, 0.686, 0.341); C3b@M2 at 3209 (0.341).

**F01: the role-coded age moved from the key to the address.**
- **What remains.** D-034 made benign keys finite, but a benign device keeps its address and UA for the whole capture,
  while an attack entity holds its address for one lifetime. So views D and E read 0.71-0.90 for every trained family in
  all 34 plans: attack windows are the younger ones. The generators are not changed in this round, so this stays.
- **Who can read it.** The consumers keyed by (IP, UA) or by address: the P3 request-level curves, the P5 request engine,
  the planned per-(IP, UA) rule arms and the population detector. The view arms key by (IP, UA, sid), and no view feature
  reads address history [INFERENCE from T-042 and the token list of 8.1].
- **M3 on a reused address.** View E counts from the donor's first request, so M3's address is older than its key: it
  reads 0.154-0.537, the other direction in 12 of 28 plans. Its new UA makes a new (IP, UA) key, so view D reads
  0.809-0.851.
- **The request-level baseline and its label** (`ml/p3_prereg.json` `learning_curve.age_only_ip_ua`,
  `learning_curve.age_only_ip_ua()`).
  - Each request-level window carries its (IP, UA)-key age. The baseline scores it as the view level's does, and reports
    its validation AUC, its reading and its evaluation recall beside the curves.
  - Unless its validation AUC reads near chance (0.5 ± 0.15), `selection.json` and `curve.json` carry the label
    **age-assisted**, and the verdict starts with AGE-ASSISTED. A missing AUC cannot read near chance, so it labels too.
  - **Expect the label.** On records replayed from plans 1001 and 2001 it reads AUC 0.724, "age-assisted" (C2 0.670, C3a
    0.684, C3b@M1 0.755, C3b@M2 0.774; `round2/round2_synthetic_1001_2001.txt`). Those records are synthetic, so this is
    [FACT] for the replay and [INFERENCE] for the captures.
  - At its operating point on that replay it catches nothing: the budget allows 0 of the replay's 80 benign units.
- **The plan's report** (`ml/l7v2_prereg.json` `arrivals.age_check.report_v3`, `l7_pools.age_report_v3`). Views D and E per
  family sit in `plan["age_check"]["report_v3"]`, in the check's direction. They are report-only and refuse no plan.
- **Not done:** D-040 also puts this baseline beside the rule arms. They are not on this branch (feat/l7v2-arms carries
  the arms' work), so that consumer still has to read it.

**F02: the in-phase view.** Views B and C are reported, not gated: rule_v2 still judges all windows.
- **Held-out C3b@M3 is outside the band in phase in 11 of 28 plans** (0.599-0.685). Its slot is the last one, so the
  restriction drops the windows its bots make in the tail, their oldest [INFERENCE from the arrival rule; the same effect
  moves C3b@M2 where its slot is last].
- **Time-matched, M3 stays inside** (0.507-0.607), but it leans the same way in every plan: M3 windows are the younger.
- **So** an M3 recall can owe a little to age. Read it beside these values and the view-level age-only baseline on the
  evaluation captures. Nothing in this round removes that.

**F03: C3b@M1.** The per-family check still exempts it, at 10 key units (`family_min_units` is unchanged). It is now reported:
- on its own, in rule_v2's direction, 0.336-0.575 over the 34 plans, outside the band at pilot 9008 (0.336);
- pooled with C3b@M2, 0.437-0.570, inside the band in all 34 plans (`report_v3.small_families`).

**F05.** `eval_tail_label` now cites D-036 and calls its earlier D-034 wording a forward reference. The value is unchanged.

**F06: the rest of T038-06, on the evaluator side.** `l7_engine.py` is not edited.
- **The report.** `train_l7v2.engine_replay` drives the real observe-only engine with a capture's records in completion
  order. `engine_parity` compares its windows with the evaluator's per capture, at poll phases 0.0 (the evaluator's
  convention) and 0.5 (the live phase is arbitrary), in `selection.json` and `eval.json`. It counts:
  - windows the same and windows built differently (a request that completed after the window's poll is absent);
  - evaluator-only windows (the cap, a late opener) and engine-only windows;
  - disagreements between the `engine_scored` rule and the engine;
  - records dropped as older than the pruned history, and truncated records.
- **Fixtures** (`tests/test_l7v2_engine.py`): a friendly key, slow assets (the count matches an independent
  reconstruction), a key over the cap, and a request older than the pruned history.
- **On records replayed from plan 2001** (`round2/round2_synthetic_1001_2001.txt`; 73,106 records, about 12 s per capture):

| Completion times | Phase | Same | Built differently | Evaluator-only | Rule vs engine |
|---|---|---|---|---|---|
| rt 20 ms | 0.0 | 16,623 | 0 | 16 | 0 and 0 |
| rt 20 ms | 0.5 | 16,630 | 0 | 9 | 9 and 16 |
| rt 1 s, every request | 0.0 | 16,625 | 0 | 14 | 0 and 0 |
| rt 10 s non-pages, 20 ms pages | 0.0 | 11,360 | 5,265 | 15 | 1 and 0 |

- **What this means.**
  - A uniform slowdown moves no completion past another's.
  - The last row is an illustration, not a measured load: slow non-page requests change about a third of the windows.
  - The operating points stay on the evaluator's windows, so **on a loaded capture live decisions can differ from
    offline ones**. The report sizes the window difference per run; how many decisions it changes is not computed.
    How large the difference is under real load is [NOT RUN].

**Not addressed:** T-042's INFO items F04 (a token-count tell for C3b, behaviour rather than age) and F07 (the age-only
baseline's held-out FP per kind).

## As built: R*'s live path (T-025e, 2026-11-01, branch `feat/l7v2-rstar`)

Built offline; nothing ran on the VM. Sections 9.5, 10 and 19 as written, with these readings and additions, labelled
post hoc, before any data. Usage and events: `docs/EVALUATION.md`, "L7 v2: the enforcing arm".

**The path.** `l7_rule_engine.L7RuleEngine` is the rule arm behind the view engine's interface, so the shadow thread and the
arm take it unchanged: every record into `ml/l7v2_rules.RuleStats`, one row per (IP, UA) key with a request at each poll, p >
theta in k consecutive rows a decision, a suppressing poll clearing every run. The statistics and the scorer are the
replay's own objects, imported from `ml/`, not a copy. `ml/l7v2_replay.RulePath` is the reference and is not touched:
`tests/test_l7_rstar.py` holds the two to the same keys at the same polls, at four rules on generated streams and on a
recording the daemon's own shadow thread wrote.

**Readings (not departures):**
- **Which arm.** `L7_ARM=R*` with the frozen rule selection in `L7_SELECTION`; R* is `r_star` of that file. Every other rule
  arm and the fixed replays are refused: section 10 runs only the best rule live.
- **Key-age gate.** It counts from the first request of the (IP, UA) key, of any session.
- **"Keeps sending" and single-key.** Any session of the key counts as the key sending. The CGNAT guard is unchanged, so a
  key with three sessions in 10 min on its address is never XDP-banned, however few users are behind it.
- **A decision is made when a run reaches k**, as in the view engine; a key whose run breaks and reaches k again is decided
  again. `RulePath` keeps the first decision only, so the parity is on first decisions.

**Additions the design does not cover:**
- **The second map.** `deny_key.map`, one `"ip|ua" 1;` line per key, mapped from `"$remote_addr|$http_user_agent"` in the
  run's own copy (`l7_conf.protected(text, run_dir, key_map=True)`; no tracked conf changes), with the same write rules,
  case folding, cap, TTL, reload pacing and kill switch. Its keys are shorter than the session map's, so the hash sizes hold.
- **D-040 and D-043.** D-040 keeps a sid-less line off a shared address because such a line hits users the session-level
  decision did not mean to. A line of R*'s means to: D-043 charges a flagged (IP, UA) key every user behind it. So D-040's
  guard does not apply to this map, and R* can deny a whole UA on a shared address; level 2 keeps the guard.
- **`users_seen`** on R*'s events, for the budget's live reading (D-044 OC-2): the distinct session ids seen under the key
  so far, a request without a session counting as one, which is `ml/l7v2_rules.key_costs`'s fallback. One user can hold
  several sessions, so it reads high; the run's manifest gives the devices.
- **Bounds.** The replay's statistics do not evict. Live, at most 65,536 keys and 65,536 addresses are kept, the least
  recently seen going first and counted as `evicted`; the parity holds while `evicted` is 0.
- **Validity.** Beyond the learned arms' refusals: the calibration record must be frozen and the package's, since the
  thresholds are in its costs, and the rule spec must be this tree's.
- **Removed.** The view-window hook for rule arms (`l7_arms.RULES`, `"kind": "rule"`), empty since T-025c and against
  section 19, with its tests.

**D-047, a pre-data change (2026-11-02; the orchestrator's decision on T-025e's F5, labelled before any data).** A decision
fires when a run reaches k, and a denied key's 429s keep its run, so a deny whose 300 s TTL ended was not decided again, and
a long attack on a shared address was served again. In P1's 180-s runs the TTL never ends, so no run is affected. For every
arm alike (view arms and R*):
- **A deny whose key keeps sending is renewed** when its TTL ends: `RENEW_RECENT_S`, a request that started within the last
  120 s (longer than a closed-loop client's longest think time, 70 s; a value set here). A key under an XDP ban counts as
  sending, as the ban hides its requests. A key that stopped sending lets its deny expire as before.
- **It needs no new would-ban event and adds no line:** the entry's TTL starts again in place, so nothing reaches nginx, no
  reload is due, and the pacing and the 2,000 cap hold. The kill switch ends every deny, and nothing renews one afterwards.
  Each renewal is an `l7_deny_renew` event with the arm and the level. A sid-less line on an address that turned shared is
  still withdrawn (D-040).
- **Level 2:** when an XDP ban has ended, level 2 applies again as it did the first time (30 s of sending, the CGNAT guard,
  the 20-per-minute cap), and its `ban` carries `renewal`. A level-1 miss is tracked through its ban the same way, as it has
  no line to fall back on.
- **Tested** on fakes for both arm kinds and through the daemon's real ban path (`tests/test_l7_deny_renewal.py`). [NOT RUN]
  on the testbed.

## As built: the P1 runner (T-025f, 2026-11-02, branch `feat/l7v2-runner`)

Built offline and tested on a fake host (`tests/p1_fake_host.py`); nothing ran on the VM. `eval/p1_runner.py` is a T3 script,
`ml/p1_traffic.py` a block's population, `eval/p1_records.py` a run's records and `eval/p1_analysis.py` a campaign's verdicts. Every
item below is a reading or an addition, labelled post hoc, before any data. D-049 (2026-11-02, the user: "Approve as recommended",
dated record `ml/p1_prereg.json`) accepted the readings, kept the two assumptions as assumptions, and settled the age check and the halving rule. D-051, D-052 and D-053 (the
user) and D-054 (the orchestrator), all 2026-11-02 after T-048's review, before any capture, re-registered the verdict (`ml/l7v2_verdict_prereg_v3.json`), the validation seeds and
the timeline (`ml/p1_prereg_2.json`).

**The population (sections 5.3, 6, 7).**
- **Timeline (D-053).** 30 s + 210 s + 30 s, 120 s of attack until T-048 found that most of the slow classes' cost was served before a decision. Attack sources stop at the attack's end, so the
  recovery is attack-free.
- **Benign.** `l7_pools`'s frozen mix, held-out kinds included: 138 addresses, about 176-179 users, unless the halving rule fires.
- **C3b's side bots** [ASSUMPTION, kept as one by D-049]. Besides the level's bots at M2, every C3b run of a block carries 10 bots each at M1, M3 and
  M2exp, so that D-043's separate reports have entities. They run in U and in every M arm, are constant across the ladder, and
  judge nothing. M2exp is in the frozen class table (`ml/l7v2_prereg.json` mimicry), so it has its entity labels here; `l7_pools`'s P3
  population stays without it. An M3 bot needs no reused address here, since one class runs at a time.
- **Arrivals on one slot.** `arrivals`, unchanged, with the attack window as the only slot: benign over [0, 180] s, attack over
  [30, 180] s, at least 60 s of life, capped at the attack's end.
- **What the longer slot does to the attack [FACT, plans at nominal times, 10 blocks, `S3:T-025f/artifacts/p1_plan_at_210s_hg2.json`].** About 80 % of the bots reach the cap (78-89 % by family), the median bot
  is active about 120 s, the longest 210 s. Since arrivals stretch with the slot, the share of a family's sources active is 59 % at 120 s, when the level window opens, 77 % at 150 s, 93 % at 180 s and 87 % at 210 s: the
  level window does not sit on a plateau, and its load is about 80 % of the level's nominal one [INFERENCE from those shares].

**The age check on one slot.** One of the two rules that did not fit 120 s.
- `arrivals.age_check` stays enforced on P3's training, validation and held-out captures. On P1's runs it is recorded per run (`run.json`
  `age_check`: `applied` false, the plan's report for the run's class, none for a control) and not applied: it refuses nothing and
  invalidates nothing (D-049). At 120 s it failed on all 30 pairs of block and class, first-seen KS 0.27-0.46. At 210 s [FACT, plans, 10 blocks]: passes on 17 of 30 (C2 3, C3a 8, C3b 6), first-seen KS
  0.13-0.31 (limit 0.30), AUC 0.51-0.67, lifetime KS 0.13-0.35, window-age AUC 0.32-0.46 (attack windows younger; band 0.35-0.65).
  The learned arms are trained on P3's age-matched captures and the rules read no age, so this is a shift at scoring, not a
  leak in training [INFERENCE]. So the analysis puts the age-only reading on the U replays beside every view-level contrast
  (`age_only_on_U`: the window-age AUC per block, per family and pooled, in the age-only arm's sense, AUC above 0.5 meaning younger attack
  windows; the age-only arm's recall at its frozen point; each U run's recorded check. `view_level_contrasts`: every contrast of the
  judge's output naming the GRU, the HGB or the shuffled GRU, with that reading beside it). It is descriptive: `judge`'s inputs do not read it,
  and a test shows the verdict's output unchanged without it.
- `flash_gap_s`, which 120 s could not keep, now holds: the flash crowd's minute starts at a uniform time in [90, 120] s, at least 60 s from the attack's start, so part of it falls in the level window.

**The address limit bounds C3b's ladder.** A run over `ml/p3_prereg.json` `pool.address_limit` (300) is refused. With the benign
138 and 30 side bots, C3b reaches 132 bots: the ladder's 50 and 100 are reachable, 200 and 300 are not. C3b's addresses per level and halvings:

| Halvings | 100 bots | 200 bots | 300 bots |
|---|---|---|---|
| 0 | 268 | 368 | 468 |
| 1 | 204 | 304 | 404 |
| 2 | 171 | 271 | 371 |

Only a smoke may read above the limit (`--address-limit`, E-2), and nothing else moves it. A ladder or a campaign above 300 addresses needs a new
dated decision after that read.

**C3a's ladder on HG2's numbers [FACT, arithmetic, `S3:T-025f/artifacts/p1_plan_at_210s_hg2.json`].** With C_slo 84.5 req/s, rho 42.25 and S 0.263 CPU-s/s, C3a needs 40 sources at level 1, 79 at level 2 and 158 at level 4,
against its bound of 50-100: only level 2 is reachable, where the placeholder reached only level 1. If level 2 does not reach the floor, C3a has no knee. C2 reaches all four levels; C3b 50 and 100 bots, and 200 at 2 halvings.

**The halving rule (D-049, `ml/p1_prereg.json` `halving`, modelled on `ml/p4_traffic.py`'s).**
- **Where.** Before the harm ladder, on pilot seed 9001. Phase `health` runs C and C' at `--halvings`; `eval/p1_analysis.py --health` reads
  both through `eval/harm_gate.control_health` (Q(C) >= 99 %, each route class >= 95 %).
- **Steps.** Either control unhealthy: one more halving, both controls again. The first step counting up from 0 with both healthy
  gives the factor, and no step runs after it. A control whose run checks failed gives no reading and fires nothing; it is re-run at most twice.
- **What is halved.** Every benign spec of count > 1 keeps its first `count >> halvings` entities, at least 1. A spec of count 1 stays: both CGNAT
  pools, the NAT gateway, each single-entity kind. The draws run over the full mix, so an entity keeps its index, sub-seed, address, parameters
  and netem profile whatever the halvings, and the attack's addresses do not move.
- **The floor, my choice: 2 halvings.** 138, 74 and 41 addresses. At 2 the pools hold 36 of about 81 users and the flash crowd has 7 devices;
  at 3 they would hold 36 of about 65, a majority, and the crowd 3. A halving raises the share of users behind the pools (20 %, 32 %, 44 %), so
  a flagged pool costs a larger share of the budget's users (D-043): the factor is recorded with every run and must be reported with every result.
- **Frozen.** The factor is in a health file bound to the record's digest. A ladder and a campaign take it from there (`--health`), a campaign's
  knees must name the same factor, and each block, run and manifest records it. A ladder at two factors is refused.
- **At the floor.** Still unhealthy at 2 halvings: no factor, and the ladder and the campaign refuse and say why. Going on is a new decision.

**The benign rate against C_slo and rho.** [FACT, arithmetic on plans at nominal times, without the seven kinds that have no plan (about 10 req/s by their parameters [INFERENCE]); HG2's measured capacity and route costs of
2026-11-03 and 2026-10-30 in a frozen fixture; `S3:T-025f/artifacts/p1_plan_at_210s_hg2.json`; NOT RUN.] C_slo 84.5 req/s, first unhealthy 109.9, C_sat 241.3; rho 42.25; seeds 3001-3005 at 30 + 210 + 30 s:

| Halvings | Addresses, users | Attack window req/s (x C_slo) | Level window req/s (x C_slo) | Peak over 20 s req/s (x C_slo) | CPU-s/s at class costs (x C_slo's 0.525) |
|---|---|---|---|---|---|
| 0 | 138, 175-179 | 120-135 (1.42-1.59) | 141-147 (1.67-1.74) | 180-198 (2.13-2.34) | 0.127-0.149 (0.24-0.28) |
| 1 | 74, 111-115 | 73-86 (0.86-1.02) | 85-94 (1.00-1.11) | 119-130 (1.40-1.54) | 0.087-0.102 (0.17-0.19) |
| 2 | 41, 78-82 | 52-61 (0.61-0.72) | 56-70 (0.66-0.83) | 85-93 (1.01-1.10) | 0.063-0.080 (0.12-0.15) |

The two units disagree, and the rule, not this table, decides. In requests the full mix is above C_slo in every window; in the capacity's own CPU terms it is about a quarter, since its mean cost at class costs is about 1 ms per request against the record's
6.2 ms: about 80 % of its requests are static assets and under 2 % search, where the record's mix has 33 % and 11 %. HG2's stack cost adds about 2.2 ms per request [FACT: origin 7.7-8.0 ms against 6.2 ms at class costs, nginx 0.5 ms], which puts the
full mix at about 0.5 CPU-s/s over the level window and 0.6 at its peak, against 0.71 at C_slo [INFERENCE]. So a server-side limit alone need not fire the rule at 0 halvings; CPU 7 and the 20-s peak are the likelier causes, which is what the smoke reads.
Rho only sizes the attack, through S, and the mix does not read the record: S's assumption of 0.263 CPU-s/s of benign work is about twice what this mix costs at class costs, which the ladder's knee absorbs [INFERENCE]. `--plan` prints these figures on the record in use, and `block.json` keeps them.

**The verdict (D-051, `ml/l7v2_verdict_prereg_v3.json`; T048-01, -02, -13).**
- **Order.** After admission: the budget step, which counts R*, the HGB and the GRU only; mitigation; then V-A's conditions jointly. Only when they do not hold does OC-1's best learned arm enter, for V-B and V-C.
- **Reported.** Every GRU contrast of an admitted class, whatever the verdict: harm against every live arm, detection against the HGB, the shuffled GRU, R* and the age-only arm.
- **Carriers.** An arm over the budget cannot carry a verdict: V-B's carrier is the best learned arm, V-C's is R*, and the class is then inconclusive with the arm named.
- **Latency alone.** A class admitted on the p95 criterion alone gets V-D unless some live arm's mean gain in Q reaches 5 pp.
- **Disclosed [INFERENCE, R-9].** The family-wise bound stays 0.05 where the best learned arm is the GRU. Where the HGB leads validation (C3b only), V-A rests on GRU vs R* and V-B on HGB vs R*, so with both nulls true a false claim of either is at most 0.10 by the union bound.
- **Keyed (D-054, T048-12).** Harm is `{arm: {block: Q}}`, and different key sets are refused.

**The harm window (D-053).** The verdict's contrasts read Q from the attack's start + 90 s to its end, with the never-sent guard on that window (`eval/l7v2_harm.py window_figures`). The whole window's Q is reported beside it; admission, the placebo and the ladder's knees read the whole
attack window, as registered. Each class's `reported` also holds, descriptively, time to decision per arm and family and the attack cost left: by the replay's worst case (a request is removed from max(decision, first + 20 s) + 10 s), and, for an arm with M runs, measured as its attack 2xx cost over U's.
T-048's probe re-run at 210 s, same point and levels, placeholder costs [FACT, synthetic, `S3:T-025f/artifacts/t048_p4_probe_at_210s.out`]: C2 27.5 % of the cost left (was 38 %), C3a 75 % (91 %), C3b 64 % (83 %); C3b@M2 caught 751 of 1000 (586), at a mean of 74 s. Longer attacks help R* too, as they do every arm.

**The validation seeds and the frozen points (D-052; T048-03).**
- `p3_val` is 2001-2004 for every arm's selection. Seeds 2003 and 2004 pass the plan's own checks on stream 2026-11-v1 with the frozen age limits [FACT, a frozen fixture, `S3:T-025f/artifacts/p3_val_plans_2001_2004.json`]. Capture time: +0.6 VM h.
- **The pilot's check, before the campaign.** `eval/p1_analysis.py --points` replays one valid control per pilot seed at the frozen factor through each arm at its frozen point: benign units flagged, pooled over all eight seeds, against the budget. The ladder's pairs must cycle through the eight seeds for that.
- **Its stop.** R*, the HGB or the GRU over the budget there stops the campaign until a dated decision is named (`--points-decision`), recorded with every block. A seed without a valid control leaves the check incomplete, and a campaign refuses it. The file is bound to the record, both selections and the factor. Nothing is re-tuned.
- **What four seeds do to R*, and what the check is likely to read [FACT, synthetic: plans at nominal times, placeholder costs; `S3:T-025f/artifacts/rstar_val4_synthetic.out`, `S3:T-025f/artifacts/rstar_pilot_check_synthetic.out`].** Tuned on 2001-2004 the cost rule moves to tau 1.0, above 621 ms over 60 s, k 1: 395 of 640 at 0 benign users (on two seeds, 254 of 320). On evaluation plans it charges 37 of 1778 users against a budget of 17 (two seeds: 69), and catches C3b@M2 269 of 500 (460) and C3a 250 of 500 (335). On P1's control plans of the eight pilot seeds it charges 38 units at every halving, against budgets of 14, 9 and 6: the pools and api_bulk are never removed, so a halving shrinks the budget and not this charge. If real traffic reads alike, the check stops the campaign for R*, and a dated decision is needed first [INFERENCE].

**An M run's shadow (D-054, T048-14).** `run.json` and the run's record hold the largest `evicted` and `late` of its `l7_shadow` reports and every `daemon_error`. `evicted` above 0 on R*'s path, or the shadow thread's error in the attack window, makes the run invalid; `late` and other threads' errors are recorded only. `bans_by_engine` is
reported per run, so a branch like T048-07's is visible.

**The arms (one table, `ARM_TABLE`, on T-025e's env per arm).**
- **Heuristics [reading, accepted by D-049].** HGB, GRU and R* run the tolerant profile and its nginx limits, the default rules arm the default
  profile and limits. Section 10 names the default rules as the status quo; with the default profile underneath them, every arm
  would inherit the benign flags that P5c.2 was made to remove.
- **One conf for every M arm** (T-025e's F8): `l7_conf.protected(..., key_map=True)`, both maps empty until the arm writes.
- **Pins.** The harm benchmark's daemon plan in every run (`bench/population.PIN_PLAN_DAEMON`), so U and M differ only by the table.
- **Validity (5.4).** Also the daemon's start and arm events against the table, and a limit of 10 s [ASSUMPTION, kept as one by D-049] on
  the file sink's silence.

**The analysis (sections 11, 13).**
- **The U run's recording.** A U run has no daemon. Its engine input is the file sink, lossless where the socket is not (section
  15), with poll ticks at whole seconds of the log clock, the cadence `train_l7v2.engine_scored` assumes.
- **The live budget (D-044).** An XDP ban of any engine, `L7V2_ENGINE` included (D-037), costs everyone behind the address; a
  view-level deny one user (D-031); an (IP, UA) deny the plan's devices with that UA (D-043). At most the entity's units.
- **A campaign the admission finds INVALID gets no verdict**, with its reasons: too few valid blocks are not V-D "no harm".
- **Blocks a class judges** are the final attempts where the class is valid and every live run is sound; the others are listed.

**VM time as built** [ESTIMATE, section 14's 45 s of set-up, D-053's timeline]: 5.25 min per run, 68.25 min per block, 11.4 h for 10 blocks (7.9 h for the minimum cut). The ladder, on HG2's numbers, has 14 reachable pairs of runs (C2 at 4 levels, C3b at 2, C3a at 1, 2 repeats each), 2.45 h, or 16 pairs
and 2.8 h at 2 halvings, where C3b reaches 200 bots. Re-runs add up to 2.3 h. The halving rule adds 10.5 min per step, 31.5 min at most without re-runs. The smoke's own runs are 10-11, 1 h. In all about 18 h at most, plus P3's +0.6 h, plus whatever the timer gate waits: its probe takes seconds, and a refused one is made again every 30 s for up to 30 min per run.

**Files touched in this round:** `ml/p1_traffic.py`, `eval/p1_runner.py`, `eval/p1_records.py`, `eval/p1_analysis.py`, `eval/p4_runner.py`
(two additive parameters), `eval/l7v2_harm.py` (`window_figures`), `ml/l7v2_replay.py` (`with_poll_ticks`, `age_windows`, `age_auc`, `attack_requests`, `cost_left`), `ml/l7v2_verdict.py`, `ml/l7v2_verdict_prereg.py` and its `_v3.json`, `ml/p1_prereg.json`, `ml/p1_prereg_2.json`, `ml/p3_prereg.json`, tests and this note. `control_plane.py`, `l7_engine.py`, `l7_enforce.py`,
`bench/`, `server/` and the tracked nginx confs are untouched.

**After review T-048 (the orchestrator's decision D-054; pre-data changes, every arm alike), each its own commit:**
- **T048-07, the arm's 429s and the access-log rule.** The daemon's `l7_rate` rule has an error branch: more than 80 % errors
  at more than 10 requests/s bans the address, with no CGNAT guard, no 30-s wait, no rate cap and no kill-switch lift. It
  counted the arm's own 429s as errors, so a level-1 deny could end in such a ban (the review's port: 2.2 % of denied (IP, UA)
  keys on CGNAT addresses, a whole pool). With `L7_ENFORCE=1` it no longer counts status 429. Without it nothing changes. The
  rate branch still counts every request: a key above the rule's rate is banned, denied or not, as it was before its deny.
  The arm's `l7_enforce_poll` reports `bans_by_engine`, with a last one at the stop, and `ban_events.bans_by_engine` reads
  the same from any run's event log.
- **T048-09, hostile numbers.** `l7_ingest.normalise` drops a record with a non-finite numeric field (`1e999`, `10**400`,
  `"nan"`, which only a forged datagram can carry); they raised there or in the rules' statistics, and restarted the shadow
  thread with a fresh engine. Records nginx writes normalise as before; `l7_engine.py` is unchanged.
- **T048-10, the seen table.** `RuleStats`' per-address table of keys holds at most `SEEN_MAX` = 4,096 keys, the least recently
  seen going first, in O(1); it was rebuilt on every request above that while all were inside the lookback, so a client
  rotating its cookie made each request O(n). A key evicted from it and back within 300 s counts as new again, which only the
  population detector reads, and only for an address above 4,096 keys in 300 s. Replay and live share the code.
- **T048-08 and T048-11, documented, not changed** (`docs/EVALUATION.md`, Known limits): no recovery while any user behind R*'s
  key sends, and a sid-less line hides the evidence that would withdraw it. Neither is reachable in P1's runs.

### The fix round on review T-050, and D-058 (T-051, 2026-11-03, branch `feat/p1-fix`, records `ml/p1_prereg_3.json`, `ml/p1_prereg_4.json`, `ml/l7v2_verdict_prereg_v4.json`)

T-050 found that a campaign from integ/s4 could not give a fair verdict. Built offline, on the fake host and on real generators over loopback; nothing ran on the VM. **Re-review is due before the VM, since these are live-path changes.**

**The two that made a campaign rigged or impossible.**
- **T050-01.** `execute_run` passed the plan's daemon dict to `render_conf`, which reads `L7_SHADOW` from the arm's row. So no real M run's nginx fed the socket: GRU, HGB and R* decided nothing and passed every check, and the verdict was V-C or V-D by construction. The tests now read the conf `execute_run` wrote.
- **T050-02.** Merging P4's `--stats` made every P1 attack generator exit 1. P1 now makes `attack_stats/`, and the fake exits 1 as the real one does.

**The generator's deadline (T050-03, -04, -16; `ml/l7_gen.py`, shared with P3 and P4).** Every think time and pause is cut at a generator's end, so no draw moves. No new view starts after it. A view in flight may finish within 5 s, so a healthy client's last view keeps its rows; no request starts or waits past that, and a hung one gets its row with its error. At the end + 7 s the process exits, code 0, whatever it is doing; the run's grace stays 10 s. Before this the downloader's last think time invalidated about a third of healthy runs, and a banned generator's overshoot made an arm's success invalidate its own run. A test runs every kind and family as a real process on three loopback sinks: one answering, one silent after accept, one with a full accept queue, which drops a SYN as an XDP ban does.

**What makes a run invalid, added (T050-07, -08, -11; numbers [ASSUMPTION], mine, `ml/p1_prereg_3.json`).**
- **An enforcing arm:** `parsed` above 0 and at least 0.5 of the file sink's lines; a reload that took effect within 30 s of the first deny, and a last reload that did not fail; no `daemon_error` at `l7_enforce` in the attack window. The socket loss is reported per run (section 15). It is an upper bound: the daemon reports `parsed` every 5 s and not at its stop, so the sink's lines of up to the last 5 s count as lost, about 2 % of a 270-s run [INFERENCE from the timeline; NOT RUN on the VM] (T057-10).
- **An attack:** at least 0.9 of its addresses in the file sink by its end.
- **The file sink:** the 10-s silence now reads the benign addresses from the attack's start to the run's end, so attack lines cannot hide a stalled benign CPU. At nominal times that silence is at most 3.8 s on the 18 seeds at any halvings [FACT]; before the attack it reaches 17.4 s at 2 halvings, so that part judges nothing.
- **The backend (D-063, as P4's, by its own functions):** a gunicorn that exits during a run makes it invalid, with its time and code, naming a calibration refusal or a boot failure from `gunicorn.log`; before the traffic the run stops at once, with no daemon and no 30-s wait. An nginx whose quit fails at the run's end makes it invalid too; that a dead master gives that exit code is [CLAIMED], NOT RUN. A dead backend's 502s would otherwise read as harm.
- **The timer gate:** the harm benchmark's before each run, at the record's `validity.timer_p99_ms`, with its wait. Its probes go into `run.json`, and a run it refuses starts nothing.

**One setting (T050-12, -17).** A campaign block with another record, knees, factor, selection, point check or code is refused, and so is an analysis given another record or selection than the blocks ran. A campaign's order reads no free label; a run is in the index before it begins and when it ends; the runner keeps to the executor's CPU.

**The ladder (T050-13).** Per (class, level, repeat) the last attempt with both runs sound counts, and a re-run needs an invalid run before it. `--ladder` writes the file `--knees` takes. A class without a knee is null and named there, and a campaign that needs it refuses; what that means for the verdict is not decided (`--cut` drops C3a).

**D-058 (the user: "Approve as recommended").**
- **Too few blocks (T050-05).** A class admitted with fewer than 10 judged blocks gets no verdict: `invalid (k of 10)`, with the excluded blocks' reasons. It used to read V-D.
- **Re-runs (T050-06).** A block-level reason, `valid_all`: a run invalid or missing, a class invalid, or an unhealthy C. One per block and two per campaign, checked by the runner before a block starts. A re-run for one run no longer makes the other classes INVALID.
- **Over all attempts.** An arm's bans and the benign users it wrongly acted on count over all attempts of all blocks, so an arm's worst run cannot vanish from the budget. Q and the contrasts read the judged blocks' final attempts.
- **The halving rule's stop (T050-09).** A control unhealthy with a server-side Q of at least 99 % does not fire the rule. The rule stops for a dated decision, which fires or repeats that step (`--health-decision`). The file records each control's server-side Q, CPU shares and largest view slip.
- **P1's control health (T050-10).** The class floor applies from 20 judged requests; a smaller class is reported. `eval/harm_gate.py control_health` is unchanged.
- **V-C (T050-14).** When the GRU beats R* on harm and the verdict would be V-C through an HGB-led best learned arm, the class is inconclusive, with every contrast reported.

**Reported, judging nothing (T050-09, -11, -15).** Server-side Q per run beside Q; the late window's Q over [210, 240) s, where arrivals have ended and no source is younger than 30 s, so that a speed effect can be told from a removal effect; per run the largest view slip, with its entity and time, where a stall in mid-life shows and no validity rule looks; the runner's largest launch lag and loop gap.

**p95 (C-084).** `p95_s` counts only the requests that met their SLO, so it is no plain latency: it is capped by each class's SLO, and it can fall as an attack pushes requests out of the SLO, which Q then counts. P1 reads it as dL in harm admission, the placebo and the knees, either-or with dQ, and `admitted_on` "latency" names that reading. The verdict's contrasts read Q only. Any report of it says "p95 of the requests within their SLO".

**On the frozen record (HG2, 2026-11-04; read only, nothing registered moved)** [FACT, arithmetic on plans at nominal times, `S3:T-051/artifacts/p1_on_frozen_record.json`; NOT RUN]. S is 0.263 CPU-s/s and rho 42.25 req/s, against the placeholder's 0.552 and 90. Costs and capacity are the figures above. A level's nominal cost over the whole attack window, in S, the window admission and the knees read: C2 0.61, 1.14, 2.26 and 4.50 at levels 1, 2, 4 and 8; C3a 1.22 at level 2, its one reachable level (79 sources; its bound of 100 is level 2.5); C3b@M2 0.85 at 50 bots and 1.73 at 100. The record's knees for its own floods: search 4, export 4, cheap 2. So [INFERENCE, the ladder decides, and P1's mix is not the benchmark's]: C2's knee is likely at 8; C3a likely has no knee; and C3b, at under half the costly floods' knee at 100 bots, may have none either, unless it reaches 200 bots at 2 halvings or a dated lift of the address limit. A campaign that needs a class without a knee refuses, and what that means for the verdict is undecided.

## As built: the ladder extension, the no-knee rule and P3's per-family sizing (T-073, 2026-11-07, branch `feat/p1-ladder-ext`)

Built offline from T-070's design (`S3:T-070/artifacts/design.md`) as the user approved it on 2026-11-07 (D-073 to D-076). Nothing ran on
the VM. The records `ml/p1_prereg_5.json` (D-073, D-074, D-075) and `ml/p3_sizing_prereg.json` (D-076) were each pinned before the code
that reads them. Where this section and the ones above differ, this one holds.

- **Levels (D-073).**
  - The classes: C2 1, 2, 4, 8, 16; C3a 2, 4, 6, 8; C3b 50, 100, 150, 200, 300 bots.
  - Ascending, stopping after the first level that passes in both repeats. C2 16 runs only after 8 failed; C3a 6 and C3b 150 only when
    8 or 200 is not reachable.
  - The two repeats sit on the seed map 9001 + ((2 i + r - 1) mod 8). The runner refuses a ladder block off it.
  - C3a takes up to 320 sources. Its sources 101-320 sit in an index range after the last family, so no entity of a lower level moves
    (a test pins seed 9001's rows as planned before).
- **The address limit and memory (D-075).**
  - P1 keeps one generator process per client. P1's address limit is its own: the dated decision on the smoke's read at the heaviest
    planned run, in `ml/p1_address_limit.json`, at most 468; the verified 300 until it exists.
  - The read accepts on MemAvailable >= 1024 MB at every sample [ASSUMPTION, fixed before the read], no OOM kill, every alias added,
    and the run's own checks.
  - The runner samples MemAvailable into `cpu.jsonl`, and `run.json`'s runner report gives its least value.
- **Statuses and the no-knee rule (D-074).**
  - A level is run, with its repeats that had no sound attempt, not reachable or not run.
  - A registered ladder block that the plan refuses as not reachable (the source bounds, the address limit) goes into
    `ROOT/ladder_unreachable.jsonl`.
  - `--ladder`'s knees file gives every level's status, `top_tested` and a line per class: its knee, or "no harm reached up to X on
    this testbed". "Not reachable" never reads as no harm.
  - The campaign runs the classes of its live set, or of its cut, that have a knee, C2 alone if it is the only one. With none, there is
    no campaign. Blocks record `live_classes`, and the analysis judges those and names the rest.
- **The premise check.** `eval/p1_premise.py` wrote `ml/p1_premise.json` (pinned) on the frozen record of 2026-11-04, on the pilot plans at
  nominal times [FACT, plan arithmetic; NOT RUN on the VM]. Every registered level evades. A level marked "crosses" never becomes a knee.

  | Per (address, UA) key, req/s | 1 s | 10 s | 30 s | 60 s | 300 s |
  |---|---|---|---|---|---|
  | benign q 0.99 | 82 | 14.7 | 8.8 | 6.9 | 3.8 |
  | C2 at 16, highest maximum | 12 | 3.3 | 2.4 | 2.0 | 1.0 |
  | C3b at any bot count, highest maximum | 61 | 10.4 | 4.3 | 2.9 | 1.1 |
  | C3a at any level, highest maximum | 2 | 1.0 | 0.67 | 0.63 | 0.31 |

- **P3 (D-076):** see `docs/P3_DATASET_DESIGN.md`, section on the capture's timeline.
- **Not measured:** T-070's memory figures (20 MB private per generator at import, 7.6 GB available, no swap) are what the smoke's read
  checks. No ladder level, address count or memory reading has been run.

### Dated note, 2026-11-08: D-079 and D-080, on review T-078 (T-079, branch `feat/p1-review-fixes-4`), before any P1 data

The orchestrator's decisions, pre-data; the user may overrule them. The section above stands where this note does not narrow it, and so
does `ml/p1_prereg_5.json`, which carries the same note.

- **Class statuses (D-079, T078-01).**
  - Each class in the knees file is knee, no_knee, incomplete, not_tested or no_sound_level, read over the levels its conditions call
    for.
  - no_knee, D-074's "no harm" result, holds only when no level passed in 2 of 2, every called level ran with every repeat sound or is
    recorded not reachable, and X exists.
  - A knee or an X read over a called level that is "not run", a level with a repeat that had no sound attempt where no knee is read,
    or a conditional level run outside its condition, is incomplete. The reasons are named under `incomplete`.
  - `no_knee` lists only no_knee classes.
- **Who takes what (D-079).** The campaign and P3's family_knee take a class only at knee or no_knee and refuse every other status by
  name. A class left out of the campaign carries the knees file's own line, in its blocks and in the analysis.
- **Conditional levels (D-079, T078-02).** The runner refuses C2 16, C3a 6 and C3b 150 outside their conditions, read from the index
  and `ladder_unreachable.jsonl`, before the block runs. The ascending stop stays a procedure.
- **Harm in the file (T078-03, T078-04).**
  - Each run level gives each repeat's harm, dQ in pp and dlog2 p95, and `--ladder` prints them.
  - The no-knee line reads "no level harmed in 2 of 2 up to X on this testbed".
  - passed comes from the raw harms. A level marked "crosses" is never X and is named.
- **The factor file (D-080, T078-08).** `--health` records the root and the sha256 of its health index lines, and `load_factor` refuses
  a file of another root or of changed steps.

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
