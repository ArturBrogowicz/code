# P5c.3 capture — full realistic mix under the tolerant profile (2026-10-16)

The training dataset for P5c.3 (`docs/L7_GRU_DESIGN.md` §7.3.4).
`ml/capture_l7.py --duration 600 --benign 12 --seed 1 --mix overlap --heuristics tolerant`,
branch `feat/l7-benign-overlap` at `f5148e2`. No daemon, no XDP (as in P3): traffic is
recorded unmitigated; nginx runs the tolerant limits (`nginx_l7capture.conf`: 82 r/s,
burst 133, `limit_conn` 50).

* 20 benign IPs: the 12 P5 clients + all 8 realistic kinds (60-asset pages, both CGNAT
  gateways, polite crawler, and `api_bulk`, marked held out in the manifest).
* 8 calibrated sub-threshold attack families (5 trained, 3 held out) and the 8 s mid-run
  SYN flood, as in P3.

## Gate [FACT, from `manifest.json` + `access.log.gz`]

* 31,623 request lines; manifest valid; every benign kind and attack family present;
  1 unlabelled line (the readiness probe).
* nginx rejected 0 requests.
* The slow families log 6 lines each (one per held connection): the access log barely sees
  them, as P3 found (R1).

| Class | Kind / family | Lines |
|---|---|---|
| benign | cgnat_browsers (12 + 24 users) | 12,171 |
| benign | nat_gateway, api_bulk, crawler_polite, browser_page, http2 | 2,094–2,494 each |
| benign | keepalive, curl_oneshot, api_poll, uploader, downloader | 54–1,090 each |
| attack | subthreshold_flood (2 IPs), padded_flood, scraper, credstuff | 915–2,272 each |
| attack | slowloris, slowpost, slowread | 6 each |

## Use

The trainer reads `access.log`; unpack it first:

    gunzip -k results/2026-10-16_l7-p5c3-capture/access.log.gz
    ./venv/bin/python ml/train_l7.py results/2026-10-16_l7-p5c3-capture --out <pkg_dir>

## Files

`manifest.json`, `access.log.gz`, `nginx_l7capture.conf` (the conf nginx ran),
`console.log`.
