"""Complete calibration records for the tests.

A frozen record must carry its host and the reference of its drift check (docs/HG1C_DESIGN.md 4.2, F2), which only
a measurement can supply; the tests use these shapes. They are not results.
"""
import copy
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "bench"))
import calibration as C

SAMPLE_HOST = {
    "uname": "Linux testbed 7.0.0-38-generic x86_64", "cpus": 8, "mem_mib": 9426, "origin_seed": 1,
    "origin_sha256": "a" * 64, "loadgen_sha256": "b" * 64,
    "pins": {"server": "0-1", "daemon": "2", "legit": "6", "attack": "3-5,7"},
    "gunicorn": {"version": "26.2.0", "workers": 2, "threads": 8, "nofile": 524288},
    "nginx": {"version": "1.28.3", "conf_sha256": "c" * 64},
}
SAMPLE_DRIFT = {"rho_rps": 90.0, "q_pct": 100.0, "p95_s": 0.053,
                "attack": {"costly_search_flood": {"level": 2.0, "q_pct": 71.0, "p95_s": 0.060}}}


def placeholder():
    return C.load(C.PLACEHOLDER)


def frozen(cal=None, created="2026-10-24T08:00:00Z", host=None, drift_reference=None):
    """`cal` (default the placeholder) as a frozen record with a sample host and drift reference, unless it brings
    its own."""
    cal = copy.deepcopy(cal if cal is not None else placeholder())
    if host is None and not isinstance(cal.get("host", {}).get("uname"), str):
        host = SAMPLE_HOST
    if drift_reference is None and cal.get("drift_reference") is None:
        drift_reference = SAMPLE_DRIFT
    return C.freeze(cal, created, host=host, drift_reference=drift_reference)
