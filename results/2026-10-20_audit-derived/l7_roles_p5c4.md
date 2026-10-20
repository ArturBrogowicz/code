**Attackers caught / benign flagged, per run and detector**

| Run | Seed | Deterministic engines | GRU | B2 | B3 | B4 | B4@0.95 |
|---|---|---|---|---|---|---|---|
| runA1 | 1 | 0/4 | 4/4 · 2 benign | 4/4 · 0 benign | 4/4 · 0 benign | 4/4 · 0 benign | 4/4 · 1 benign |
| runA2 | 2 | 0/4 | 4/4 · 2 benign | 4/4 · 1 benign | 4/4 · 1 benign | 4/4 · 0 benign | 4/4 · 0 benign |
| runA3 | 3 | 0/4 | 4/4 · 2 benign | 4/4 · 0 benign | 4/4 · 0 benign | 4/4 · 0 benign | 4/4 · 0 benign |
| runA4 | 4 | 0/4 | 4/4 · 1 benign | 4/4 · 1 benign | 4/4 · 1 benign | 4/4 · 1 benign | 4/4 · 1 benign |
| runA5 | 5 | 0/4 | 4/4 · 2 benign | 4/4 · 0 benign | 4/4 · 0 benign | 4/4 · 1 benign | 4/4 · 1 benign |

Pooled: GRU 20/20 attackers, 9/100 benign; B2 20/20 attackers, 2/100 benign; B3 20/20 attackers, 2/100 benign; B4 20/20 attackers, 2/100 benign; B4@0.95 20/20 attackers, 3/100 benign

Benign flags by role (IP, kind/netem), number of runs:

* GRU: 10.0.1.15 browser_page/perfect x1; 10.0.1.16 browser_page/perfect x3; 10.0.1.19 api_bulk/broadband x1; 10.0.1.19 api_bulk/mobile_3g x2; 10.0.1.19 api_bulk/mobile_bad x2
* B2: 10.0.1.18 cgnat_browsers/mobile_bad x1; 10.0.1.19 api_bulk/broadband x1
* B3: 10.0.1.18 cgnat_browsers/mobile_bad x1; 10.0.1.19 api_bulk/broadband x1
* B4: 10.0.1.16 browser_page/perfect x1; 10.0.1.19 api_bulk/broadband x1
* B4@0.95: 10.0.1.16 browser_page/perfect x2; 10.0.1.19 api_bulk/broadband x1
