# P4: slow-connection attacks that harm a realistic server, mitigated per connection without CGNAT collateral (design note, written before the code)

**Status (2026-10-30): a design for approval. Nothing in it is built or run.** It is on `design/priority-p1-p4`, branched from
`feat/hg1c` at e413a34, and changes no code. It details priority P4 of the approved direction
(`/home/artur/agent_workspace/final/PRIORITY_PLAN.md` §4). It uses the L7 v2 runner as its harm vehicle
(`docs/L7V2_DESIGN.md` §5, §6). The tags and the citation forms are those of `docs/L7V2_DESIGN.md` (header):
- `path:line` refers to e413a34;
- `S1:T-00x/<file>` is an accepted S1 artifact;
- `VR:Vn` is a verification row;
- `[Gx-yy-Qz]` is a T-012 quote id.

**Re-registrations, dated, all before any P4 data** (review T-039 V-07, T-029 P4-04). The approved text below is left as it
was; each place a re-registration changes carries a marker "[re-registered: ...]" that points here. The pinned code is
`slow_pc.py` (frozen block and docstring), `eval/p4_outcome.py` (module docstring and constants) and `docs/EVALUATION.md`.

| Decision | Date (UTC) | What changed | Where the note said otherwise |
|---|---|---|---|
| D-025 | 2026-10-30T14:33Z | T_mit 30 s → **90 s**, the user's choice: the frozen dribble leg needs 2 data segments after the first poll, so at the frozen pacing the closes take a median of ~52-55 s (Slowloris) and ~36-39 s (slow POST). The share within 30 s stays reported as a secondary figure | D-S6; §6.4 objective; §10 (a) |
| D-030 | 2026-10-31T09:23Z | P4 attacks last **210 s** (was 120 s): a run is 30 s of baseline, 210 s of attack and 30 s of recovery (270 s), so that the level window of (b), from attack start + T_mit (90 s) to the attack's end, is 120 s long. §11's VM estimate becomes ~11.8 h (10.4 h without re-runs) | §10 units; §11 |
| D-031 | 2026-10-31T09:23Z | The recovery reading of §10 (a), accepted as recommended: the 5 consecutive bins at ≥ 0.99 × Q(C) are counted from the first harmed second after the attack starts (a run that never dips has recovered at once), and must end within T_mit. (b)'s window is [attack start + T_mit, attack end] = [120 s, 240 s] of the run (`LEVEL_WINDOW_S`) | §10 (a), (b) |
| D-035 (V-04) | 2026-10-31T12:44Z | The validation runs (§6.4) run M_pc's daemon mode without enforcement: tolerant profile, SLOW_PC=1, SLOW_PC_ENFORCE=0, SLOW_PC_RECORD; each manifest records it, and the scorer refuses another mode, an enforcing poll and a poll whose banned set holds a non-attack address (`eval/p4_validation.py`) | §6.4 "the detector runs in shadow mode" (no daemon profile named) |
| D-035 (V-08) | 2026-10-31T12:44Z | An M_pc run is valid only if the rule logged slow_pc_poll at least every 10 s from the traffic's start to the run's end (`eval/p4_runner.py` SLOW_PC_POLL_GAP_S; the daemon logs one every 5 s); the runner applies it to the validation runs too | §5.4 of `docs/L7V2_DESIGN.md` names only "the daemon was alive" |
| D-035 (V-01) | 2026-10-31T12:44Z | The harmed second of (a) is the first of 5 consecutive 1-s bins below 0.99 × Q(C) inside the attack window; the recovery is the end of the first 5 consecutive bins at or above it after that second; 0 without such harm; the recovery is reported with its onset. Noisy fixtures pin it: onset at +30 s, a true recovery at +95 s fails (a), one at +60 s passes (`eval/p4_outcome.py` recovery) | §10 (a) |
| D-035 (V-02) | 2026-10-31T12:44Z | Fewer than 10 valid blocks give "invalid (k of 10 valid)" for the family, never "not harmful" or "harmful but not mitigated", and for M7 unless another family qualifies, in which case M7 names the invalid family next to its claim (`eval/p4_outcome.py`) | §10 "≥ 10 valid blocks" (what fewer meant was unsaid) |
| D-035 (V-03) | 2026-10-31T12:44Z | The outcome takes every attempt of the run index: the harm, (a) and (b) on the last valid attempt of each (block, arm); (c), the benign closes and the bans per arm over ALL attempts, invalid ones included (`eval/p4_outcome.py`, `eval/p4_runner.py --summarize`) | §10 (c) "in all M_pc runs" (which attempts was unsaid) |

Two further forms appear here:
- `T0:` facts were read on this VM on 2026-10-30, without running anything: package metadata, the ss manual page, the kernel
  header and strings in binaries;
- `ss.8:N` is line N of the uncompressed manual page of iproute2 6.19.0 (`/usr/share/man/man8/ss.8.gz`).

## 1. Decisions for the user, and what I found

**What I found** (each finding shapes the design):
- **F-S1: the attacks are harmless for two reasons: the configuration and the scale.**
  - All three nginx configurations keep `worker_connections 16384`, 5 s header and body timeouts and a 64 KiB body cap. The
    "unprotected" one is no exception (`nginx_unprotected.conf:4`, `:61-62`, `:66`) [FACT, `S1:T-006/p4_inventory.md` §2;
    re-checked in `tasks/T-006/review.md`].
  - The suite's slow attacks hold about 80-100 sockets in total [FACT, VR:V12].
  - The R.U.D.Y. bots declare a 1 MB body, so they get a 413 before the body is read; that is [INFERENCE, NOT RUN] (VR:V12).
    The R.U.D.Y. engine fired 0 times in 1,487 ban events; those bots were banned by SlowConn at 8 connections [FACT,
    `tasks/T-007/review.md`].
- **F-S2: the distribution's default is 768, not 16384.** This VM's `/etc/nginx/nginx.conf:9` sets `worker_connections 768`
  and `:2` sets `worker_processes auto`, as shipped with nginx-common 1.28.3-2ubuntu1.12 [FACT, T0].
  - That file sets no client timeout and no body cap, so nginx's built-in defaults apply there [CLAIMED, nginx documentation;
    not fetched in this task].
- **F-S3: the per-connection fields exist, under these exact names.** [FACT, T0]
  - The manual page of iproute2 6.19.0 documents, under `-i`:
    - `bytes_acked` (ss.8:237) and `bytes_received` (:241);
    - `segs_out` (:245) and `segs_in` (:249);
    - `lastsnd` (:257), `lastrcv` (:261) and `lastack` (:265), "the unit is millisecond";
    - `rcv_space` (:273);
    - and `-K, --kill` (:312).
  - `/usr/bin/ss` also carries the format strings `bytes_sent:`, `notsent:` and `data_segs_in:`, which the manual page does not
    list.
  - The kernel structure has `tcpi_last_data_sent` (`/usr/include/linux/tcp.h:269`), `tcpi_last_data_recv` (:271),
    `tcpi_last_ack_recv` (:272), `tcpi_rcv_space` (:285), `tcpi_bytes_acked` (:291), `tcpi_bytes_received` (:292),
    `tcpi_segs_out` and `tcpi_segs_in` (:293-294), `tcpi_notsent_bytes` (:296), `tcpi_data_segs_in` (:298) and
    `tcpi_bytes_sent` (:310).
  - What the undocumented tokens mean, and whether ss omits a counter that is zero, is [CLAIMED]. The parser treats a missing
    token as 0, and a fixture recorded in the pilot settles it (section 9).
- **F-S4: TLS breaks "the server sent nothing".** On :443 the server sends its handshake before any HTTP answer. So
  "never answered" needs a handshake allowance there, or the set of connections that completed a request in nginx's log
  [INFERENCE].
- **F-S5: backlog connections look unanswered.** When nginx's connections are exhausted, new client connections can complete
  the TCP handshake into the listen backlog. They then show as established before any nginx worker owns them [INFERENCE]. A
  naive "old and unanswered" rule would close benign clients that are only waiting. The detector therefore considers only
  sockets owned by nginx.
- **F-S6: a waiting request looks like a slow one.** While the upstream is slow, a benign request waits with zero response
  bytes and a falling byte rate [INFERENCE]. What separates a dribble from a wait is data arriving *after* the request was
  sent. The detector asks for ≥ 2 data segments received after the connection was first seen, using `data_segs_in` (section
  6.2).
- **F-S7: the VM budget is about 3× the plan's.** The plan has P4 at ~0.5 h of pilot and ~2 h of campaign
  (`final/PRIORITY_PLAN.md` §0). Ten blocks of C, C', two U runs and four M runs need ~7.5-8.6 VM h (section 11)
  [ESTIMATE].
- **F-S8: benign keep-alive eats the realistic profile's slots.**
  - A browser device holds 6 connections (`ml/l7_benign.py:41`). The default `keepalive_timeout` of 75 s keeps idle ones
    open 5× longer than today's 15 s (`nginx_l7capture.conf:54`) [CLAIMED default].
  - The benign population must be sized so that the control stays healthy (section 4.2).

**Decisions requested.**

| # | Decision | Recommendation | Why, and what the alternative costs |
|---|---|---|---|
| D-S1 | A realistic profile **R** becomes a named, evaluated configuration of the system under test (section 4.1). Every P4 arm runs on it; the thesis states that "unprotected" means R in P4 and the hardened baseline elsewhere | accept | Without it no slow attack can harm (F-S1). R uses distribution and nginx defaults, not invented weaknesses |
| D-S2 | Gunicorn on R: sync workers × 5 (2 × CPUs + 1), bound to 127.0.0.1:8080 | accept | Sync workers hold one connection each, which makes worker slots the slow-POST harm resource. The "2 × cores + 1" rule is [CLAIMED] (gunicorn documentation, not fetched). Keeping 2 × 8 threads would need ≥ 16 slow bodies and is less default-like |
| D-S3 | Attack scale: Slowloris from 100-300 sources × 6 connections (up to ~1,800 held); slow POST from 5-40 sources × 1-2 connections on `/upload`; the ladder picks the knee. Slow read and HTTP/2 variants are secondary: recorded and replayed, not in the verdict (section 5) | accept | 6 connections per address is the benign device's own footprint, so no single address stands out. Slow read needs a different predicate |
| D-S4 | The per-connection detector: five legs and a 3-poll persistence, with thresholds chosen on validation seeds by a rule frozen now (section 6) | accept | It keys on the connection, not the address (`S1:T-006/p4_design_sketch.md` §2). F-S4 to F-S6 add the guards |
| D-S5 | Enforcement: close the connection with `ss -K` on its 5-tuple after 3 suspect polls. Ban the address only if ≥ K of its connections were closed within 60 s **and** it carried < 3 UA keys in the L7 log in the last 10 min. TTL 300 s, rate caps and a kill switch (section 7) | accept | `CONFIG_INET_DIAG_DESTROY=y` [FACT, `tasks/T-006/review.md`]. The address ban stops reconnects, and the key guard spares shared addresses |
| D-S6 | T_mit = 30 s, as in the plan, with the age threshold T restricted to {5, 10, 15, 20} s [re-registered: T_mit = 90 s, D-025; T's grid unchanged] | 30 s | A larger T cannot meet 30 s. The alternative, T_mit = 60 s with T ≤ 30 s, is more lenient towards slow legitimate clients but weaker as a claim |
| D-S7 | The new arm runs the daemon's **tolerant** profile (SlowConn at 180) plus the per-connection rule, so the old per-address rule cannot ban the CGNAT pools inside the new arm. The default profile is a separate arm | accept | Otherwise a CGNAT ban by the old rule would be booked against the new one |
| D-S8 | Port 80 is primary. Port 443 is secondary, with the log-derived answered set (section 6.3) | accept | F-S4 |
| D-S9 | VM budget ~8.6 h with both families; a cut to Slowloris only, ~5 h (section 11) | full | F-S7 |

## 2. Scope

| In | Out |
|---|---|
| Profile R; Slowloris and slow POST at realistic scale; the per-connection detector and its enforcement; the comparison with SlowConn default (8) and tolerant (180); a co-resident CGNAT pool; the harm outcome on the L7 v2 runner; tests with fakes; an admissibility replica; the pre-registered outcome | Slow read in the verdict (recorded for replay only); HTTP/2 slow attacks (L7-01, `docs/targeted_literature_selection.md:286-313` via `S1:T-006/threat_classes.md` 5(a)); in-flight event-sequence models (`S1:T-006/p4_design_sketch.md` §2: a scalar tuple, not an order); XDP per-flow drops (`S1:T-007/p4_hooks.md` §4); tightening nginx timeouts as an arm (that is the hardened baseline, already shown harmless: `results/2026-10-20_expb-tolerant-profile-suite/README.md` per `S1:T-006/p4_inventory.md` §5) |

## 3. What exists (facts)
- **Generators.**
  - The L7 track has three slow families, with 6 connections and a 3 s interval each: slowloris (`header_every_s`), slowpost
    (`byte_every_s`, body 60,000 B) and slowread (`read_every_s`), all on port 80 (`ml/l7_traffic.py:133-136`, `:145-146`).
  - The suite runs 8 connections per bot with a 5 s sleep (S7), and 10 per bot with a 7 s sleep and Content-Length 1,000,000
    (S8) (`S1:T-006/p4_inventory.md` §1).
- **Deployed slow rules.** Both key on the source address:
  - **SlowConn** bans at ≥ 8 established connections **and** < 250 B per interval, for 3 intervals (`control_plane.py:95-97`,
    `:794-807`). Its count comes from `ss -tan state established` (`control_plane.py:397-422`); its idle leg is the address's
    XDP ingress-byte delta (`S1:T-007/p4_hooks.md` §2).
  - **R.U.D.Y.** bans at ≥ 3 body-read timeouts in 60 s, from the error log (`control_plane.py:88-89`).
  - After a SlowConn ban the daemon closes **all** of that address's sockets with `ss -K dst <ip>` (`control_plane.py:387-394`,
    `:800-803`).
- **The CGNAT false positive.** P5c.1 banned the `cgnat_browsers` kinds for 12 and 24 users by SlowConn, at counts of 12 and
  54 with 0 bytes [FACT, `S1:T-006/p4_inventory.md` §4].
  - Raising the threshold to 180 (tolerant) removes the false ban and all detection: 0/5 slow bots banned in each of three runs
    (EXP-B) [FACT, `S1:T-006/p4_inventory.md` §5].
  - Under the per-IP threshold of 8, a desktop page load at the 25th percentile already opens 8 HTTP/1.1 connections (all
    origins) `[G3-09-Q1]`.
- **The literature.**
  - Connection idle time is the best discriminant for slow attacks `[G4-03-Q1]`.
  - "Simple detection methods which use x number of such connections in y time can be easily evaded" (L7-02, via
    `S1:T-006/p4_design_sketch.md` §0).
  - About 1,900 connections exhausted an unhardened nginx in L7-03 (`S1:T-006/threat_classes.md` 5(a), 5(c)).
  - No scholarly measurement of the mitigations' collateral on legitimate slow clients was found
    (`S1:T-012/grounding_update.csv` row 25).

## 4. The realistic "unprotected" profile R (P4.1)

### 4.1 Values, justification, and what each changes in the system under test [PROPOSAL, D-S1, D-S2]

| Knob | Hardened baseline (all configurations today) | Profile R | Justification | What it changes |
|---|---|---|---|---|
| `worker_processes` | `auto` (`nginx_l7capture.conf:14`) | 2 | the server's CPU set is CPUs 0-1 (`S1:T-004/p2_capacity.md` §5); `auto` counts the online CPUs [CLAIMED, nginx documentation] | 2 workers |
| `worker_connections` | 16384 (`nginx_unprotected.conf:4`) | **768** | the distribution's default [FACT, T0 `/etc/nginx/nginx.conf:9`]. 16384 is a hardening value | 2 × 768 = **1,536** slots. A proxied request uses two, one to the client and one upstream [CLAIMED, nginx documentation] |
| `client_header_timeout`, `client_body_timeout` | 5 s (`nginx_unprotected.conf:61-62`) | 60 s | nginx default [CLAIMED] | a dribble with gaps under 60 s keeps its connection |
| `keepalive_timeout` | 15 s (`nginx_l7capture.conf:54`) | 75 s | nginx default [CLAIMED]; the distribution file leaves it unset [FACT, T0: no match] | idle benign connections live 5× longer (F-S8) |
| `send_timeout` | 10 s (`nginx_l7capture.conf:55`) | 60 s | nginx default [CLAIMED] | matters only to slow read (secondary) |
| `client_max_body_size` | 64k (`nginx_unprotected.conf:66`) | 1m globally; **10m on `/upload`** | real upload endpoints take MB-scale bodies; 64k gives a 413 before the body is read (F-S1) | slow bodies are read, and the R.U.D.Y. regex can match a real body timeout |
| `proxy_request_buffering` | on (nginx default) | **off on `/upload` only** | streaming uploads are the reason to switch it off (`S1:T-006/p4_design_sketch.md` §4.3) | a slow body occupies an upstream worker for its whole duration |
| `large_client_header_buffers` | 2 1k (`nginx_unprotected.conf:67`) | 4 8k | nginx default [CLAIMED] | long headers no longer end in 400 at 2 KB |
| upstream | gunicorn 2 × 8 threads (harm benchmark) or 4 × 4 on 0.0.0.0 (`ml/capture_l7.py:298`) | **sync × 5, 127.0.0.1:8080** | D-S2; the loopback bind fixes S11 (`S1:T-007/security.md`) | 5 upstream slots |
| backend | l7_webapp | the L7 v2 costed backend (`docs/L7V2_DESIGN.md` §4) | one harness | the benign load needs workers |
| `limit_req`, `limit_conn` | 30 r/s burst 100; 50 per address (`ml/l7_traffic.py:39-40`, `:50`) | none in C, C' and U; as deployed in the M arms | protected = R plus the deployed limits plus the daemon | 6 connections per address never reach 50 |

**Naming.** The rendered configuration is committed as its own file, and its sha256 goes in every run's provenance. Results
on R are not transferable to the hardened profile, and the reverse holds too. The thesis must say so (`final/PRIORITY_PLAN.md`
§4 P4.1).

### 4.2 Sizing the benign population so that the control is healthy [PROPOSAL]
- **The benign mix of the L7 v2 runner on R:**
  - 40 browser devices;
  - CGNAT-12 and CGNAT-24 (the co-resident pool, `ml/l7_traffic.py:117-118`);
  - 10 search users;
  - api_bulk and a polite crawler;
  - 4 `uploader` clients, with bodies up to 2 MB on `/upload`;
  - 2 `slow_uploader` clients: a 16 kbit/s netem rate cap. They are the hard negative for the byte-rate leg; the rate is an
    [ASSUMPTION].
- **Footprint** [ESTIMATE]: 76 devices × 6 connections ≈ 456 slots, plus about 15 for the paced clients. That is ~31 % of
  1,536 before any attack.
- **Rule, frozen before the pilot.** If either of two pilot controls is unhealthy (Q(C) < 99 % or a class below 95 %,
  `eval/harm_gate.py:300-312`), the browser devices are halved and the pilot is repeated. CGNAT-12 and CGNAT-24 are never
  removed.

### 4.3 The arms on R [PROPOSAL, D-S7]

| Arm | nginx | Daemon | Per-connection rule |
|---|---|---|---|
| C, C' (no attack) | R | none | – |
| U | R | none | – |
| M_def | R plus the deployed limits | default profile (SlowConn 8, R.U.D.Y., L7 rate 50) with XDP | off |
| M_pc | R plus the deployed limits | tolerant profile (SlowConn 180, L7 rate 108; `control_plane.py:142-148`) with XDP | **on, enforcing** |
| M_tol | R plus the deployed limits | tolerant profile | off: replay only (section 8) |

**The prerequisite of every daemon arm is the daemon-robustness fix (D-ROB).** One non-UTF-8 logged byte currently stops the
daemon and lifts every XDP ban (NEW-1), and the telemetry thread has no guard (NEW-2) [FACT, `S1:T-007/security.md` S1;
`S1:T-007/p4_hooks.md` §1].

## 5. Attack scale (scenario parameters for the in-repo generators) [PROPOSAL, D-S3]

| | Slowloris (family 1, primary) | Slow POST, R.U.D.Y.-like (family 2, primary) | Slow read (secondary) |
|---|---|---|---|
| Generator | `ml/l7_gen.py` slowloris (`:325`) | slowpost (`:345`) | slowread (`:375`) |
| Sources (ladder) | {100, 175, 250, 300} from the per-seed pool (`docs/L7V2_DESIGN.md` §6) | {5, 10, 20, 40} | 50 |
| Connections per source | 6, the benign device's footprint; < SlowConn's 8 and < `limit_conn` 50 | 1-2 | 6 |
| Held connections at the top level | ~1,800 (L7-03 needed ~1,900 against an unhardened nginx) | ≤ 80 | ~300 |
| Pacing | a header line every U[10, 40] s per connection, ≤ 32 B; it must stay under R's 60 s header timeout (L7-02: a gap longer than the timeout keeps the attack alive only part of the time, via `S1:T-006/p4_design_sketch.md` §4.5) | Content-Length U[100 KB, 1 MB] (≤ 10m); a chunk of ≤ 16 B every U[5, 30] s | reads ≤ 64 B every U[5, 30] s from `/download/large` |
| Port | 80 (443 secondary, D-S8) | 80, `/upload` | 80 |
| Re-opening | a closed connection is re-opened, as the in-repo generators do (`S1:T-006/p4_inventory.md` §1) | same | same |
| Harm mechanism | nginx's 1,536 slots: new benign connections fail to be accepted | the 5 sync workers: benign requests queue | send buffers and slots |

**Notes:**
- **Intensity.** It is set by the ladder on pilot seeds; the knee is the lowest level that harms in 2 of 2 repeats
  (`bench/calibration.py:288`). Only the number of sources moves; the pacing is frozen.
- **The UA does not matter here.** Slowloris requests never complete, so they never reach the access log
  (`S1:T-006/p4_design_sketch.md` §1).

## 6. The per-connection detector (P4.2)

### 6.1 Signals (exact names; F-S3)

| Needed | ss `-tinp` token | Kernel field (`/usr/include/linux/tcp.h`) | Status |
|---|---|---|---|
| age | none; the daemon's own first-seen table, keyed by the 5-tuple, at poll resolution | – | [PROPOSAL]. The XDP `first_seen_ns` exists (`xdp_ddos_filter.c:34`) but is read only with `XDP_GRU=1` (`S1:T-007/p4_hooks.md` §3) |
| server bytes acknowledged by the client | `bytes_acked:` (ss.8:237) | `tcpi_bytes_acked` (:291) | [FACT, documented] |
| server bytes sent | `bytes_sent:` (string in `/usr/bin/ss`) | `tcpi_bytes_sent` (:310) | name [FACT]; semantics [CLAIMED]; used only as a cross-check |
| client bytes received | `bytes_received:` (ss.8:241) | `tcpi_bytes_received` (:292) | [FACT, documented] |
| client data segments | `data_segs_in:` (string in `/usr/bin/ss`) | `tcpi_data_segs_in` (:298) | name [FACT]; semantics [CLAIMED] from the header's comment "RFC4898 tcpEStatsDataSegsIn" |
| time since the last receive, send or ack (ms) | `lastrcv:`, `lastsnd:`, `lastack:` (ss.8:257-265) | `tcpi_last_data_recv`, `tcpi_last_data_sent`, `tcpi_last_ack_recv` (:269-272) | [FACT, documented]; recorded, not judged |
| unsent backlog | `notsent:` (string) | `tcpi_notsent_bytes` (:296) | recorded for slow read |
| owner | `users:(("nginx",pid=…,fd=…))` with `-p` | – | [CLAIMED] semantics; root is needed for other users' sockets, and the daemon runs as root in server_ns |

- **The reader runs once per poll, in server_ns:** `ss -tinpH state established '( sport = :80 or sport = :443 )'`.
- **Every poll's raw output is recorded** (gzip) in shadow and in enforcing runs, so that every rule can be replayed offline.

### 6.2 The predicate [PROPOSAL, D-S4]
For an established socket s at poll t, **suspect(s, t)** holds iff all five legs hold:
1. **owned:** an nginx worker owns s (F-S5). A backlog socket is never a candidate;
2. **old:** age(s, t) > T;
3. **unanswered:** `bytes_acked(s)` ≤ A(port), with A(80) = 64 B (this allows an interim `100 Continue`, which is 25 bytes);
4. **slow:** `bytes_received(s)` / age(s, t) < F;
5. **dribbling:** `data_segs_in(s, t)` − `data_segs_in(s, first seen)` ≥ 2 (F-S6). A benign request that is waiting, whose
   bytes arrived before the first poll, fails this leg.

**Persistence.** The connection is closed after **3 consecutive suspect polls**, the same 3 as SlowConn's
`SLOWCONN_CONSECUTIVE` (`control_plane.py:97`).

**Why each benign kind is spared** [INFERENCE from the legs]:
- an idle keep-alive connection, including every CGNAT browser's, already received responses (leg 3);
- a slow but legitimate uploader exceeds F (leg 4);
- a request waiting on a slow upstream does not dribble (leg 5);
- a connection still in the backlog is not owned (leg 1).

The fakes test each of these (section 9).

### 6.3 Guards [PROPOSAL]
- **:443 (D-S8).** The connection counts as unanswered iff (ip, port) has completed no request in the L7 log (the `ip`, `port`
  and `creq` fields, `nginx_l7capture.conf:28-31`) during the connection's lifetime.
  - Log loss can only make a connection look *unanswered*, never answered. That risks closing a benign connection, not banning
    an address, because the ban needs K closes and the multi-key guard (section 7).
  - The loss rates: 2.19 % steady, 40.1 % in flood bursts [FACT, `S1:T-005/o2_draft.md` §2].
- **A missing token counts as 0** (F-S3). A line that cannot be parsed skips that socket for the poll and is counted.
- **A failed `ss` call** (timeout, error) skips the poll. It never resets streaks to "clean": unlike `get_established_conns_by_ip`,
  which returns an empty dict on error (`control_plane.py:407-410`).
- **The reader runs inside a guarded loop** with a supervisor, in line with D-ROB.
- **HTTP/2** connections with any answered stream are answered. Slowloris over h2 is out of scope (section 2).

### 6.4 Thresholds: the rule, frozen now; the values, chosen on validation seeds [PROPOSAL]
- **Grid:** T ∈ {5, 10, 15, 20} s (D-S6); F ∈ {16, 64, 256, 1024} B/s; K ∈ {2, 3, 4, 6}. A(80) = 64 B, persistence 3 polls
  and the 60 s ban window are fixed.
- **Data:** 2 validation seeds (4001-4002), each with C (attack-free), U_loris and U_post on R. The detector runs in shadow mode
  and records the `ss` snapshots. It is replayed offline.
- **Objective:** maximise the share of attacking addresses banned within 30 s of their first connection.
  [re-registered: within T_mit = 90 s, D-025; the 30 s share is reported as a secondary figure]
- **Constraints, all of which must hold:** 0 benign addresses banned (CGNAT included); ≤ 0.1 % of benign connections closed;
  0 slow_uploader connections closed.
- **Ties** go to the larger T, then the smaller F, then the larger K: the more conservative choice.
- **If no grid point meets the constraints**, the detector fails its budget. That is reported, and section 10's "mitigated"
  outcome is not supported. The grid is not widened after seeing data.

### 6.5 Where it plugs in (`S1:T-007/p4_hooks.md` §1)
- **The reader** sits next to `get_established_conns_by_ip()`, which is read once per poll (`control_plane.py:732`).
- **The decision** is a separate pass after the per-address loop and before the GRU feed (`control_plane.py:839-843`). It is
  keyed by the 5-tuple, with its own streak dictionary pruned in `evict_idle_clients` (`control_plane.py:347-384`).
- **Bans** go through `ban_ip` (`control_plane.py:286-312`), with a new engine id, `l4_slowconn_pc`, in `ban_events.ENGINES`,
  and its thresholds in the start event.

## 7. Enforcement (P4.3) [PROPOSAL, D-S5]
1. **Close.** `ss -K` with the socket's full filter (client address and port, server port) from server_ns as root. Today's
   per-address form is `ss -K dst <ip>` (`control_plane.py:389`).
   - `ss -K` "silently skips sockets that the kernel does not support closing" (ss.8 `-K`, around :312). The next poll
     therefore checks that the socket is gone, and failures are counted.
   - `CONFIG_INET_DIAG_DESTROY=y` [FACT, `tasks/T-006/review.md`].
2. **Ban the address** through XDP, only when both hold:
   - ≥ K of its connections were closed as suspect within 60 s;
   - the address carried fewer than 3 distinct UA keys in the L7 log in the last 10 min. A shared address keeps its other
     users: blacklisting hits every subscriber behind it `[G3-04-Q1]`.
   - An attacker that also completes requests under ≥ 3 UAs keeps its address, but its connections are still closed one at a
     time [INFERENCE].
3. **TTL** 300 s, as `BAN_TTL_SECONDS` (`control_plane.py:112`).
4. **Caps:** ≤ 500 closes per poll and ≤ 20 address bans per minute. Above them the event is logged as "capped".
5. **Kill switch:** `SLOW_PC_ENFORCE=0` by default. The L7 v2 kill file `/run/l7v2/kill` also stops it, and the rule then
   runs in shadow (`docs/L7V2_DESIGN.md` §9.3).

## 8. The comparison, the co-resident CGNAT pool and the harm vehicle
- **SlowConn default (8).**
  - With 6 connections per address the attack never reaches 8, so M_def is expected to miss it. The CGNAT pools hold
    72-144 connections, mostly idle, so M_def is expected to ban them, as in P5c.1 [INFERENCE from `control_plane.py:795`
    and `S1:T-006/p4_inventory.md` §4].
  - M_def runs live because it is the deployed system.
- **SlowConn tolerant (180).** Its count leg can never be met at 6 per address. Its outcome is therefore decided without
  running it, and it is confirmed by replaying the recorded snapshots (M_tol). EXP-B already measured its cost: 0/15 slow
  bots banned [FACT, `S1:T-006/p4_inventory.md` §5].
- **The co-resident CGNAT pool.** CGNAT-12 and CGNAT-24 are present in every run (section 4.2). CGNs are in > 90 % of cellular
  ASes `[G3-05-Q1]`; the pool sizes match AS12978's allocation of 4K ports per subscriber `[G3-05-Q2]` (≤ 16 subscribers per
  address; [INFERENCE] in `S1:T-012/lit_gap_fill.md` G3-05).
- **The harm vehicle** is the L7 v2 runner: client-side Q and p95 on judged links, with blocks of C, C', U and M
  (`docs/L7V2_DESIGN.md` §5).
  - A connect or accept failure counts as a failed request with `err = "connect"`.
  - **Server-side cross-check (the P4 variant):** nginx `stub_status` is compiled in (`--with-http_stub_status_module`) [FACT,
    T0]. It is sampled every second in every run and recorded, not judged: active, reading, writing and waiting connections.
    It shows whether slot exhaustion coincides with the client-side harm. `$request_time` cannot show connections that were
    never accepted.

## 9. Test plan (offline first, in the style of `tests/test_daemon_rules.py`)

**Fakes** (T2, offline). The fake `ss` of `tests/daemon_harness.py` (`S1:T-007/p4_hooks.md` §1) is extended with `-i` and `-p`
fields. Assertions per case:
1. a CGNAT pool: 72 answered, idle sockets from one address → 0 suspect, 0 bans;
2. Slowloris: 6 unanswered, dribbling sockets per address from 250 addresses → closes after T + 3 polls; address bans after K;
3. a slow but legitimate uploader at more than F → 0;
4. slow POST: unanswered, dribbling, below F → closed;
5. a waiting benign GET, with its bytes before the first poll and age > T → **not** suspect (leg 5);
6. a backlog socket with no `users:` → never a candidate;
7. :443 with a handshake answered by bytes but no request completed in the log → suspect, if the other legs hold;
8. tokens missing or garbled, a failing `ss` → no crash, no reset to clean;
9. hostile input: a peer address that will not parse is skipped and logged;
10. the multi-key guard: an address with 3 UA keys → closes only, no ban;
11. the caps and the kill switch.

**A parser fixture.** The text of one real `ss -tinpH` output, recorded in server_ns during the pilot (T3), becomes a test
fixture. It confirms the token layout of F-S3 [NOT RUN].

**The admissibility replica** (pure, like `ml/l7_admissibility.py:166` `slowconn_scan`):
- each simulated connection gains `answered` and `dribbled` fields;
- the benign gate is re-run at the **default** count;
- the expected result: the CGNAT pools fail the old per-address rule, as in P5c.1, and pass the per-connection rule, with no
  need for 180.

## 10. The pre-registered outcome (P4.5) [PROPOSAL]
- **Units.** A block is one evaluation seed (3101-3110, disjoint from every other seed in the three notes). Each block has
  8 runs in a seeded random order: C, C', U_loris, U_post, M_def_loris, M_pc_loris, M_def_post and M_pc_post. One run is
  30 s of baseline, 120 s of attack and 30 s of recovery. [re-registered: 210 s of attack, a run of 270 s, D-030]
- **"Harmful", per family.** Both must hold:
  - the harm gate PASSes U against C: a mean dQ ≥ 10 pp or a mean dL ≥ 1, the 95 % t-interval excluding 0, ≥ 80 % of blocks
    with the sign of the mean, ≥ 10 valid blocks, and the placebo not passing (`eval/harm_gate.py:9-31`);
  - **and** ≥ 9 of 10 blocks are individually at dQ ≥ 10 pp or dL ≥ 1, the plan's stricter count.
- **"Mitigated", per family, for M_pc.** All three must hold:
  - (a) recovery: Q(M_pc) in 1-s bins reaches ≥ 0.99 × Q(C) for 5 consecutive bins within T_mit = 30 s of the attack start, in
    ≥ 9 of 10 blocks; [re-registered: T_mit = 90 s, D-025; the bins counted from the first harmed second, D-031; the harmed second is the first of 5 consecutive harmed bins, D-035]
  - (b) level: Q(M_pc) over [attack start + 30 s, attack end] is ≥ 0.99 × Q(C) as a mean over blocks, and in ≥ 9 of 10 blocks;
    [re-registered: over [attack start + T_mit, attack end] = [120 s, 240 s] of the run, D-025, D-030, D-031]
  - (c) collateral: **0 benign addresses banned in all M_pc runs**, the CGNAT pools and browser devices included. Benign
    connections closed are reported against the ≤ 0.1 % validation budget.
- **Comparison.** Q(M_pc) − Q(M_def), paired, with `eval/run_level_stats.py` (≥ 10 blocks, an interval excluding 0, ≥ 80 % same
  sign). CGNAT bans are reported per arm.
- **The claim.** If both families are harmful **and** mitigated, M7 moves from "not supported" to "supported with scope":
  profile R, these two families at this scale, this testbed.
  - If only one family qualifies, the claim names that family.
  - Every other result is reported as it is: not harmful, harmful but not mitigated, or mitigated with collateral.
- **Fixtures.** The outcome code is unit-tested on synthetic fixtures for each of these outcomes before any evaluation data
  exist.

## 11. VM budget and phasing [ESTIMATE, D-S9]
One run is ~4 min: 180 s of traffic plus ~60 s to set up ~300 aliased addresses and 1,500 connections. [re-registered: 270 s
of traffic, ~5.5 min a run, ~11.8 h in all (10.4 h without re-runs), D-030]

| Step | Runs | VM h |
|---|---|---|
| smoke of R, with the `ss` and `stub_status` recording and the parser fixture | 3 | 0.2 |
| harm ladder: 2 families × 3 levels (the 4th only if no knee is found) × 2 repeats × (C, U) | 24 | 1.6 |
| validation for the threshold rule: 2 seeds × (C, U_loris, U_post) | 6 | 0.4 |
| campaign: 10 blocks × 8 runs | 80 | 5.3 |
| re-runs (≤ 2 blocks) | 16 | 1.1 |
| **total** | | **~8.6 h (7.5 h without re-runs)** |

**The cut**, Slowloris only (C, C', U, M_def, M_pc): ~5 h with re-runs.

**Phasing** (`final/PRIORITY_PLAN.md` §8):
- **offline, F2:** profile R files, the reader and parser, the detector, enforcement, fakes and the replica;
- **then F3 on the VM:** smoke → ladder → validation → freeze of the thresholds → campaign.

**Prerequisites:** D-ROB on the branch; the L7 v2 runner's harm records (`docs/L7V2_DESIGN.md` §5). The HG2 record is not
needed: P4's harm is about slots, not CPU, and is judged against its own controls.

## 12. Risks

| Risk | Mitigation |
|---|---|
| The control on R is unhealthy (benign keep-alive, F-S8) | Section 4.2's sizing rule, frozen before the pilot |
| The undocumented `ss` tokens behave differently (F-S3) | The pilot fixture; a missing token = 0; legs 3-5 are tested on fakes |
| The cost of polling ~2,000 sockets every second, and the closes | The daemon's CPU is recorded per run; caps of 500 closes per poll |
| VM timer stalls inflate client-side latency (`S1:T-004/p2_capacity.md` §6) | `stub_status` cross-check; placebo; re-run rule |
| The R.U.D.Y. regex stays silent on R: with pacing under 60 s, no body timeout occurs [INFERENCE] | Reported as it is; the per-connection rule is the detector under test |
| The scale needs more than 300 addresses | The ladder's top level is 300; ≤ 300 aliases are verified [CLAIMED, `final/PRIORITY_PLAN.md` §3] |
| The content level | Parameters for the in-repo generators only; no new tool; nothing outside the namespaces (ledger D-006) |

## 13. Pre-registration: what is frozen, and before what [PROPOSAL]

| # | Frozen | Before |
|---|---|---|
| 1 | this note, as approved | any P4 code |
| 2 | the files of profile R (sha256), the benign sizing rule, the attack parameters and ladders, the seed lists (pilot 9101-9106, validation 4001-4002, evaluation 3101-3110) | the smoke run |
| 3 | the detector code, the grid, the objective and the constraints of section 6.4 | the validation runs |
| 4 | the chosen T, F and K | the first evaluation block |
| 5 | the outcome code with its fixtures | the first evaluation block |
| 6 | the run index: every attempt, valid or not | reported with the results |
