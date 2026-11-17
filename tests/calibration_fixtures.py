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
    "pins": {"server": "0-1", "daemon": "2", "legit": "7", "attack": "3-6"},
    "gunicorn": {"version": "26.2.0", "workers": 2, "threads": 8, "nofile": 524288},
    "nginx": {"version": "1.28.3", "conf_sha256": "c" * 64},
}
# a host of schema 2 names its PC (K10): the desktop of the record of 2026-11-04, which the simulated host reports by default (SIM_PC)
SAMPLE_PC = {"cpu_model": "Intel(R) Core(TM) i7-10700F CPU @ 2.90GHz", "vbox_host_version": "7.2.4r170995"}
SAMPLE_HOST_V2 = {**SAMPLE_HOST, **SAMPLE_PC}
SAMPLE_DRIFT = {"rho_rps": 90.0, "q_pct": 100.0, "p95_s": 0.053,
                "attack": {"costly_search_flood": {"level": 2.0, "q_pct": 71.0, "p95_s": 0.060}}}


def placeholder():
    return C.load(C.PLACEHOLDER)


# The placeholder with knees, for the tests and the golden plans of the attack specs, which run at the calibration's knee (D-066) and
# refuse a record that has none. These are the levels the specs named before D-066, not measurements: a test that wants the real ones
# reads the frozen record. The status stays placeholder, and the placeholder itself still has no knee.
PLACEHOLDER_WITH_KNEES = os.path.join(REPO, "tests", "golden", "placeholder_with_knees.json")


def placeholder_with_knees():
    return C.load(PLACEHOLDER_WITH_KNEES)


def frozen(cal=None, created="2026-10-24T08:00:00Z", host=None, drift_reference=None):
    """`cal` (default the placeholder) as a frozen record with a sample host and drift reference, unless it brings
    its own."""
    cal = copy.deepcopy(cal if cal is not None else placeholder())
    if host is None and not isinstance(cal.get("host", {}).get("uname"), str):
        host = SAMPLE_HOST
    if drift_reference is None and cal.get("drift_reference") is None:
        drift_reference = SAMPLE_DRIFT
    return C.freeze(cal, created, host=host, drift_reference=drift_reference)


# five rounds of the reference of schema 2 (docs/RECALIBRATION_2026-11_DESIGN.md 4, K1): made-up runs, not results
SAMPLE_ROUNDS_LEGIT = [{"Q": q, "p95_s": p} for q, p in ((100.0, 0.05), (99.5, 0.06), (100.0, 0.055), (99.8, 0.05), (100.0, 0.065))]
SAMPLE_ROUNDS_ATTACK = {"costly_search_flood": {"level": 2.0, "runs": [{"Q": q, "p95_s": 0.2 * 2 ** (i / 10)}
                                                                       for i, q in enumerate((60.0, 62.0, 64.0, 66.0, 68.0))]}}


def drift_reference_v2(cal=None, rho_rps=90.0, legit=None, attacks=None):
    """A drift reference of schema 2 for `cal`'s gate (default the placeholder's)."""
    gate = (cal if cal is not None else placeholder())["gate"]
    return C.drift_reference_of(rho_rps, legit or SAMPLE_ROUNDS_LEGIT, attacks or SAMPLE_ROUNDS_ATTACK, gate)


def frozen_v2(cal=None, created="2026-11-20T08:00:00Z", host=None, drift_reference=None):
    """`cal` (default the placeholder) as a frozen record of schema 2 with a sample host that names its PC and a reference of five
    rounds."""
    cal = copy.deepcopy(cal if cal is not None else placeholder())
    cal["schema"] = 2
    cal.pop("sha256", None)
    return C.freeze(cal, created, host=host or SAMPLE_HOST_V2, drift_reference=drift_reference or drift_reference_v2(cal))
