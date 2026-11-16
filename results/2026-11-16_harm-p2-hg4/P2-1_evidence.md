# P2-1 (AP-16): the evidence, read offline by the orchestrator, 2026-11-16

**Label:** two smoke runs, **not host-checked** (D-112). Not a result: no control or unprotected run beside them.

**Source:** backup/p2_2026-11/packets/P2-1_20261116T141738Z.tar.gz (sha256 934bed2f..., equal to the packet's own), extracted
to a scratch directory. harm_gate.mitigation and read_run are from integ/s6 688594a. The live leftover check was made on the VM at
14:30:43Z.

**Packet:** all pre-checks OK. Speed hold -0.3 % / +1.5 % (337 s). M_xdp 14:23:15-14:25:52Z, M_limits 14:25:52-14:29:17Z. Both
runs are at commit 688594a (clean), with spec aa43c844 and record 7005a2ed. `PACKET P2-1 done (exit 0)`, 11 min. "Runs made 0" is
the summary's count of host-checked runs; these two are not host-checked.

## M_xdp (seed 1)
| item | check | value | holds |
|---|---|---|---|
| E1 | the run is sound | executor.ok true, reasons [], setup_retries 0; role mitigated, mode xdp, level 8.0, overrides {} | yes |
| E2 | the daemon started | ready after 4.07 s; start_event backend xdp, xdp_gru false, gru_only false, l7_shadow false, heuristic default, interface veth_server, xdp_sha256 1f9e8606...; daemon.log "Listening for Nginx logs" | yes |
| E3 | XDP attached | xdp_prog_at_ready 86 = xdp_prog_at_end 86; alive_at_end true | yes |
| E4 | it banned the attack | 5 of 5 attack identities (10.0.2.65, .180, .181, .219, .227), engine l7_rate, value 51 > threshold 50, backend xdp, enforced; first bans 30.55-31.40 s on the run's axis; time to mitigate median 0.818 s (min 0.758, max 1.606) | yes |
| E5 | no legit identity banned | benign_blocked [] (5 ban events, all attack) | yes |
| E6 | stopped and detached | stop {INT, exit 0, killed false, xdp_off true, 1.12 s}; daemon.log ends "XDP program detached from veth_server. Finished."; "teardown complete"; live at 14:30:43Z: no namespace, no XDP program, no blacklist/telemetry/flow map, `bpftool net show` lists no xdp entry, no daemon/Nginx/gunicorn/engine process | yes |
| E7 | the H-01 fix is in | h01 {fix_commit 8db9827a..., fix_is_ancestor true, has_fix true, tailers_replace_undecodable 2} | yes |
| E8 | provenance | nginx_source nginx.conf 2eca9903...; engine_is_pinned true; CPUs: daemon 2, Nginx 0-1, origin 0-1; mem 7422 MiB; kernel 7.0.0-42-generic; gate met (load1 0.21, waited 20 s); timer_executor present | yes |
| E9 | the feed held | inodes 793308 (ddos_ml_access.log) and 793309 (error.log), the same at ready and end | yes |
| E10 | recorded only | judged links (perfect, broadband), 30-75 s: Q 96.04 % of 1491 requests, p95 117 ms, slip p99 13 ms; daemon CPU mean 1.0 %, max 3.0 %. Nginx saw 525 attack requests (230 200s, 245 499s, 50 503s) | – |

## M_limits (seed 1)
| item | check | value | holds |
|---|---|---|---|
| L1 | the run is sound | executor.ok true, reasons [], setup_retries 0; mode limits, daemon null, level 8.0, overrides {}; no ban_events, daemon.log or feed_before | yes |
| L2 | the limits loaded | nginx_source nginx.conf 2eca9903...; the rendered sha256 equals the run's nginx.conf and the plan's; `limit_req zone=mylimit burst=100 nodelay;` and `limit_conn connlimit 50;` | yes |
| L3 | the limits acted | attack 19,624 of 26,747 requests answered 503 (73.4 %; the plan said about 75 %); nginx_error.log 19,483 "limiting requests" and 141 "limiting connections" lines; legit 4,455 requests, all 200 (0 503 or 429) | yes |
| L4 | the testbed is free | "teardown complete" in executor.log; live check as E6 | yes |
| – | recorded only | judged links, 30-75 s: Q 89.81 % of 1492 requests, p95 186 ms, slip p99 13 ms | – |

**Stop-and-ask criteria (AP-16):** none triggered. The daemon was ready in 4.1 s; XDP id 86 was reported; nothing was left over;
there were 5 bans, not 0; no legit identity was banned; killed false; both runs had executor.ok true; median time to mitigate
0.82 s (under 3 s).

**Reading:** P2-1 passes its evidence list. It is the first real start, ban, stop and detach of the daemon under the executor on
kernel 7.0.0-42 at this pin. It is not a measurement of harm or protection, and its Q and p95 are descriptive only and not host-checked.
