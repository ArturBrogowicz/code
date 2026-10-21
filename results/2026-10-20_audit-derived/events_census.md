**Ban-event census**

* Files found: 66; distinct logs (by content): 52 (14 byte-identical copies removed); logs without events: 1.
* Events: ban 710, l7_gru_poll 960, l7_shadow 1072, l7_would_ban 208, start 133, suppress_off 27, suppress_on 27, unban 1
* Bans: 710 (l7_rate 300, l4_volumetric 197, l4_slowconn 92, l4_syn 75, l4_lowsyn 45, gru 1)
* Daemon configurations seen in `start` events: xdp_gru=False l7_shadow=True profile=None x7; xdp_gru=False l7_shadow=True profile=tolerant x7; xdp_gru=None l7_shadow=None profile=None x109; xdp_gru=True l7_shadow=False profile=default x10
* **GRU bans: 1, of which 1 of legitimate clients.**
  * `results/2026-10-20_omitted-runs/p1_smoke_20261014T152428Z/ban_events.jsonl`: 10.0.1.6, p = 0.999013, hits = 3

Bans of legitimate clients (4):

* `results/2026-10-16_l7-p5c-baseline/ban_events.jsonl`: 10.0.1.16 by l7_rate (value 51.0)
* `results/2026-10-16_l7-p5c-baseline/ban_events.jsonl`: 10.0.1.17 by l4_slowconn (value 12)
* `results/2026-10-16_l7-p5c-baseline/ban_events.jsonl`: 10.0.1.18 by l4_slowconn (value 54)
* `results/2026-10-20_omitted-runs/p1_smoke_20261014T152428Z/ban_events.jsonl`: 10.0.1.6 by gru (value 0.999013)
