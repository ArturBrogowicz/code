# 2026-11-11_harm-drift-check: run-contract directories, judged again from the published runs

Record: `bench/calibration/ddos-mitigation-2026-11-04.json` (sha256 field `cff6e515acf6f1969435e8843ea79c0c5338be13170a3dc052049928bf1aa0bf`).

| directory | verdict | judged again | agree | legit Q / p95 | cheap_static_flood | costly_export_flood | costly_search_flood |
|---|---|---|---|---|---|---|---|
| drift_20261108 | recorded ok=False | ok=False | True | 99.67 / 0.085 s (n 3035) | 94.70 / 0.223 s (n 1095) | 55.25 / 0.245 s (n 1314) | 65.12 / 0.426 s (n 1359) |
| drift_20261108.second | recorded ok=False | ok=False | True | 100.00 / 0.072 s (n 3037) | 78.54 / 0.287 s (n 1095) | 78.88 / 0.247 s (n 1307) | 54.22 / 0.441 s (n 1361) |
| drift_20261108_q1 | recorded ok=False | ok=False | True | 100.00 / 0.077 s (n 3039) | 95.25 / 0.198 s (n 1094) | 85.39 / 0.274 s (n 1314) | 61.95 / 0.412 s (n 1356) |
| drift_20261108_q1.second | no verdict (the step was cut: no drift.json) | none | – | – | – | – | – |
| drift_20261110b_q1 | no verdict (the step was cut: no drift.json) | none | – | 100.00 / 0.079 s (n 3037) | 82.53 / 0.256 s (n 1093) | 76.24 / 0.328 s (n 1313) | – |
| drift_20261111c_q1 | recorded ok=False | ok=False | True | 97.00 / 0.097 s (n 3035) | 10.71 / 0.610 s (n 1092) | 68.67 / 0.277 s (n 1312) | 74.96 / 0.298 s (n 1362) |
| drift_20261111c_q1.second | recorded ok=False | ok=False | True | 100.00 / 0.074 s (n 3038) | 95.89 / 0.208 s (n 1096) | 86.06 / 0.226 s (n 1313) | 57.55 / 0.494 s (n 1364) |
| drift_20261111c_q2 | no verdict (the step was cut: no drift.json) | none | – | 100.00 / 0.076 s (n 3034) | 72.12 / 0.201 s (n 1094) | 25.13 / 0.583 s (n 1313) | – |

Q in %, p95 in s. A row without a verdict lists its complete runs as descriptive only. Not compared: created_utc, waits, smoke.

- drift_20261108: reasons judged again: costly_export_flood: Q 55.2511 against 75.3211 frozen (more than the gate's floor_pp, 10 pp)
- drift_20261108.second: reasons judged again: cheap_static_flood: Q 78.5388 against 95.8089 frozen (more than the gate's floor_pp, 10 pp)
- drift_20261108_q1: reasons judged again: costly_export_flood: Q 85.3881 against 75.3211 frozen (more than the gate's floor_pp, 10 pp)
- drift_20261108_q1.second: legit: no complete run (run.json and DONE)
- drift_20261110b_q1: costly_search_flood: no complete run (run.json and DONE)
- drift_20261111c_q1: reasons judged again: legit probe: Q 97.0016 against 100 frozen (more than 2 pp); cheap_static_flood: Q 10.7143 against 95.8089 frozen (more than the gate's floor_pp, 10 pp); cheap_static_flood: p95 0.610173 against 0.205702 frozen (more than the gate's floor_log2_p95, a factor of 2); costly_search_flood: Q 74.9633 against 63.37 frozen (more than the gate's floor_pp, 10 pp); costly_search_flood: p95 0.298051 against 0.630813 frozen (more than the gate's floor_log2_p95, a factor of 2)
- drift_20261111c_q1.second: reasons judged again: costly_export_flood: Q 86.0625 against 75.3211 frozen (more than the gate's floor_pp, 10 pp)
- drift_20261111c_q2: costly_search_flood: no complete run (run.json and DONE)

| run | state | executor ok | commit | dirty | kernel | mem_mib |
|---|---|---|---|---|---|---|
| drift_20261108/drift/attack_cheap_static_flood/U | complete | True | 1cdda9b | False | 7.0.0-42-generic | 9426 |
| drift_20261108/drift/attack_cheap_static_flood/U.failed1 | ended without DONE | False | 1cdda9b | False | 7.0.0-42-generic | 9426 |
| drift_20261108/drift/attack_costly_export_flood/U | complete | True | 1cdda9b | False | 7.0.0-42-generic | 9426 |
| drift_20261108/drift/attack_costly_search_flood/U | complete | True | 1cdda9b | False | 7.0.0-42-generic | 9426 |
| drift_20261108/drift/legit/C | complete | True | 1cdda9b | False | 7.0.0-42-generic | 9426 |
| drift_20261108.second/drift/attack_cheap_static_flood/U | complete | True | 1cdda9b | False | 7.0.0-42-generic | 9426 |
| drift_20261108.second/drift/attack_costly_export_flood/U | complete | True | 1cdda9b | False | 7.0.0-42-generic | 9426 |
| drift_20261108.second/drift/attack_costly_search_flood/U | complete | True | 1cdda9b | False | 7.0.0-42-generic | 9426 |
| drift_20261108.second/drift/legit/C | complete | True | 1cdda9b | False | 7.0.0-42-generic | 9426 |
| drift_20261108_q1/drift/attack_cheap_static_flood/U | complete | True | 1cdda9b | False | 7.0.0-42-generic | 7422 |
| drift_20261108_q1/drift/attack_costly_export_flood/U | complete | True | 1cdda9b | False | 7.0.0-42-generic | 7422 |
| drift_20261108_q1/drift/attack_costly_search_flood/U | complete | True | 1cdda9b | False | 7.0.0-42-generic | 7422 |
| drift_20261108_q1/drift/legit/C | complete | True | 1cdda9b | False | 7.0.0-42-generic | 7422 |
| drift_20261108_q1.second/drift/legit/C | cut before run.json | None | 1cdda9b | False | 7.0.0-42-generic | 7422 |
| drift_20261110b_q1/drift/attack_cheap_static_flood/U | complete | True | 1cdda9b | False | 7.0.0-42-generic | 7422 |
| drift_20261110b_q1/drift/attack_costly_export_flood/U | complete | True | 1cdda9b | False | 7.0.0-42-generic | 7422 |
| drift_20261110b_q1/drift/attack_costly_export_flood/U.failed1 | ended without DONE | False | 1cdda9b | False | 7.0.0-42-generic | 7422 |
| drift_20261110b_q1/drift/attack_costly_search_flood/U | cut before run.json | None | 1cdda9b | False | 7.0.0-42-generic | 7422 |
| drift_20261110b_q1/drift/legit/C | complete | True | 1cdda9b | False | 7.0.0-42-generic | 7422 |
| drift_20261111c_q1/drift/attack_cheap_static_flood/U | complete | True | 1cdda9b | False | 7.0.0-42-generic | 7422 |
| drift_20261111c_q1/drift/attack_costly_export_flood/U | complete | True | 1cdda9b | False | 7.0.0-42-generic | 7422 |
| drift_20261111c_q1/drift/attack_costly_search_flood/U | complete | True | 1cdda9b | False | 7.0.0-42-generic | 7422 |
| drift_20261111c_q1/drift/legit/C | complete | True | 1cdda9b | False | 7.0.0-42-generic | 7422 |
| drift_20261111c_q1.second/drift/attack_cheap_static_flood/U | complete | True | 1cdda9b | False | 7.0.0-42-generic | 7422 |
| drift_20261111c_q1.second/drift/attack_costly_export_flood/U | complete | True | 1cdda9b | False | 7.0.0-42-generic | 7422 |
| drift_20261111c_q1.second/drift/attack_costly_search_flood/U | complete | True | 1cdda9b | False | 7.0.0-42-generic | 7422 |
| drift_20261111c_q1.second/drift/attack_costly_search_flood/U.failed1 | ended without DONE | False | 1cdda9b | False | 7.0.0-42-generic | 7422 |
| drift_20261111c_q1.second/drift/legit/C | complete | True | 1cdda9b | False | 7.0.0-42-generic | 7422 |
| drift_20261111c_q2/drift/attack_cheap_static_flood/U | complete | True | 1cdda9b | False | 7.0.0-42-generic | 7422 |
| drift_20261111c_q2/drift/attack_costly_export_flood/U | complete | True | 1cdda9b | False | 7.0.0-42-generic | 7422 |
| drift_20261111c_q2/drift/attack_costly_search_flood/U | failed before run.json | None | 1cdda9b | False | 7.0.0-42-generic | 7422 |
| drift_20261111c_q2/drift/attack_costly_search_flood/U.failed1 | ended without DONE | False | 1cdda9b | False | 7.0.0-42-generic | 7422 |
| drift_20261111c_q2/drift/legit/C | complete | True | 1cdda9b | False | 7.0.0-42-generic | 7422 |
