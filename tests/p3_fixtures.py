"""Schema-2 (P3) fixture captures for the tests: entity rows, a gzipped synthetic access log, a manifest
with every hash filled in, and a dataset-version directory with its SHA256SUMS. Not a test module itself.
Everything is written under the directory the caller passes (a temporary directory in every test)."""
import gzip
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p in (REPO, os.path.join(REPO, "ml")):
    if p not in sys.path:
        sys.path.insert(0, p)
import l7_testutil as U

import l7_dataset as D

COMMIT = "0123456789abcdef0123456789abcdef01234567"
PROFILES = ("perfect", "broadband", "mobile_3g", "mobile_bad")


def entities(version, seed, n_benign=6, n_attack=4, *, base=None, families=("f_a", "f_b"),
             held_out_family=None, kinds=("browse", "api")):
    """Entity rows: benign kinds alternate over `kinds`, attack families over `families` (plus one
    entity of `held_out_family`, held out, when given). Addresses are 10.0.<base>.<i>, `base`
    defaulting to 16 + seed % 15 so that different seeds get different addresses."""
    base = 16 + seed % 15 if base is None else base
    rows = []
    specs = [("benign", kinds[i % len(kinds)], False) for i in range(n_benign)]
    specs += [("attack", families[j % len(families)], False) for j in range(n_attack)]
    if held_out_family:
        specs.append(("attack", held_out_family, True))
    for i, (role, kof, held) in enumerate(specs):
        e = {"entity_id": f"{version}:{seed}:{i}", "index": i, "subseed": 1000 * seed + i,
             "role": role, "kind_or_family": kof, "mechanism": "rate" if role == "attack" else None,
             "held_out": held, "address": f"10.0.{base}.{i + 1}", "namespace": f"l7n{i % 4}_{PROFILES[i % 4]}",
             "netem": PROFILES[i % 4], "port": 80, "params": {"rps": 20} if role == "attack" else {},
             "client_seed": 7 * seed + i,
             "schedule": {"start_s": 0.0 if role == "benign" else 5.0,
                          "stop_s": 60.0 if role == "benign" else 50.0,
                          "phase": None if role == "benign" else "p1"}}
        e["plan_sha256"] = D.entity_plan_sha256(e)
        rows.append(e)
    return rows


def log_lines(ents, per=40, t0=1000.0):
    """Synthetic l7json lines: benign GET a mix of pages slowly; attackers POST one path fast."""
    out = []
    for e in ents:
        for j in range(per):
            if e["role"] == "benign":
                o = U.obj(ip=e["address"], ua="browser", method="GET", uri=f"/page/{j % 7}",
                          msec=t0 + j * 0.8, status=200, bsent=500 + 50 * (j % 7))
            else:
                o = U.obj(ip=e["address"], ua="bot", method="POST", uri="/login",
                          msec=t0 + j * 0.05, status=401, bsent=120)
            out.append(json.dumps(o, sort_keys=True) + "\n")
    return "".join(out)


def write_gz(path, text):
    with open(path, "wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as fh:
        fh.write(text.encode())


def capture(version_dir, version, seed, seed_role, ents, *, started="2026-11-02T10:00:00Z",
            ended="2026-11-02T10:15:00Z", per=40, commit=COMMIT, capture_id=None):
    """Write one capture directory (manifest.json, access.log.gz, error.log.gz) under version_dir and
    return (capture_dir, manifest)."""
    capture_id = capture_id or f"s{seed}"
    d = os.path.join(version_dir, capture_id)
    os.makedirs(d, exist_ok=True)
    write_gz(os.path.join(d, D.ACCESS_LOG_GZ), log_lines(ents, per))
    write_gz(os.path.join(d, D.ERROR_LOG_GZ), "")
    files = [D.file_record(os.path.join(d, n), n) for n in (D.ACCESS_LOG_GZ, D.ERROR_LOG_GZ)]
    m = D.make_manifest_v2(
        dataset_version=version, capture_id=capture_id, seed=seed, seed_role=seed_role,
        started_utc=started, ended_utc=ended, duration_s=60.0,
        code={"commit": commit, "branch": "feat/p3-dataset-pipeline", "dirty": False, "dirty_files": [],
              "inputs_sha256": {"ml/l7_gen.py": "0" * 64}},
        server={"config_id": "A" if seed % 2 else "B"}, host={"uname": "test"},
        pool={"range": "10.0.16.0/20", "permutation_seed": seed, "role_map": {e["address"]: e["role"] for e in ents}},
        timeline={"lead_in_s": 0.0, "phases": [], "tail_s": 0.0}, entities=ents, files=files)
    D.write_dataset_manifest(os.path.join(d, D.MANIFEST_FILE), m)
    return d, m


def resign(manifest):
    """Recompute a mutated manifest's hashes, as a careful forger would (the checks must still catch it)."""
    manifest["plan_set_sha256"] = D.plan_set_sha256(manifest["entities"])
    manifest["manifest_sha256"] = D.manifest_sha256(manifest)
    return manifest
