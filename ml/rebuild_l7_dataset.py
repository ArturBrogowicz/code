#!/usr/bin/env python3
"""Rebuild a P3 dataset version from its manifests (docs/P3_DATASET_DESIGN.md §4.6). Offline, read only on the
store; it writes only into --out.

    ./venv/bin/python ml/rebuild_l7_dataset.py /home/artur/datasets/l7/2026-11-v1 --out <dir>

1. verifies the version's SHA256SUMS and every manifest (schema 2, its own manifest_sha256, its files' sizes and
   hashes) and stops on the first kind of mismatch, before anything is derived;
2. re-derives the labels from the manifests alone (labels.json: capture -> address -> entity, role, kind or
   family, held_out, netem);
3. re-derives the request windows with this checkout's code (ml/train_l7.group_windows over every feature
   column) and records per capture and key the window count and the sha256 of the window tensor (windows.json;
   the view tokens of docs/L7V2_DESIGN.md §8 join when L7 v2 defines them);
4. writes the split file (entity -> split, by each capture's seed role; split.json) and its sha256
   (split.sha256).
Every output is canonical JSON without timestamps, so two rebuilds of the same inputs with the same code are
byte-identical; rebuild.json names the code (commit and the sha256 of the files that derive the windows).
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)
sys.path.insert(0, HERE)
import l7_store
import train_l7 as T

import l7_dataset as D
import l7_features as F

CODE_FILES = ("ml/train_l7.py", "l7_features.py", "l7_ingest.py", "l7_dataset.py", "ml/rebuild_l7_dataset.py")
FORMAT = "p3-rebuild/1"


class RebuildError(RuntimeError):
    """An input does not match its recorded hash or its manifest is not acceptable: nothing is derived."""


def captures(vdir):
    """The capture directories of a version (those holding a manifest), sorted by name."""
    return sorted(os.path.join(vdir, d) for d in os.listdir(vdir)
                  if not d.startswith(".") and os.path.isfile(os.path.join(vdir, d, D.MANIFEST_FILE)))


def verify(vdir):
    """Raise RebuildError on any mismatch; return [(capture_dir, manifest)]."""
    probs = l7_store.sha256sums_problems(vdir)
    if probs:
        raise RebuildError("SHA256SUMS: " + "; ".join(probs))
    out = []
    for d in captures(vdir):
        try:
            with open(os.path.join(d, D.MANIFEST_FILE), encoding="utf-8") as fh:
                m = json.load(fh)
        except (OSError, ValueError) as exc:
            raise RebuildError(f"{d}: {exc}") from exc
        probs = D.manifest_problems(m)
        for f in m.get("files", []) if not probs else []:
            path = os.path.join(d, f["path"])
            if not os.path.isfile(path) or os.path.getsize(path) != f["size"] \
                    or l7_store.sha256_file(path) != f["sha256"]:
                probs.append(f"{f['path']} does not match its manifest")
        if probs:
            raise RebuildError(f"{d}: " + "; ".join(probs))
        out.append((d, m))
    if not out:
        raise RebuildError(f"{vdir}: no capture manifests")
    return out


def labels(caps):
    """capture -> address -> its entity; a schema-3 address reused in time -> its entities in time order, each with
    its schedule."""
    out = {}
    for _, m in caps:
        rows = {}
        for e in m["entities"]:
            rows.setdefault(e["address"], []).append(
                {"entity_id": e["entity_id"], "role": e["role"], "kind_or_family": e["kind_or_family"],
                 "held_out": e["held_out"], "netem": e["netem"],
                 "start_s": e["schedule"]["start_s"], "stop_s": e["schedule"]["stop_s"]})
        out[m["capture_id"]] = {a: ({k: v for k, v in r[0].items() if k not in ("start_s", "stop_s")}
                                    if len(r) == 1 else sorted(r, key=lambda x: (x["start_s"], x["entity_id"])))
                                for a, r in rows.items()}
    return out


def windows(caps, seq, stride, min_events):
    cols = F.columns()
    out = {}
    for d, m in caps:
        _, recs = T.load_records(d)
        per_key = {}
        for w in T.group_windows(recs, seq, cols, stride, min_events):
            per_key.setdefault(f"{w['ip']}|{w['ua_h']}", []).append(w["X"])
        out[m["capture_id"]] = {k: {"windows": len(xs), "sha256": hashlib.sha256(
            b"".join(x.astype("<f4").tobytes() for x in xs)).hexdigest()} for k, xs in sorted(per_key.items())}
    return out, cols


def split(caps):
    return {"format": "p3-split/1",
            "entities": {e["entity_id"]: m["seed_role"] for _, m in caps for e in m["entities"]},
            "captures": {m["capture_id"]: {"split": m["seed_role"], "seed": m["seed"],
                                           "manifest_sha256": m["manifest_sha256"]} for _, m in caps}}


def code_record():
    try:
        r = subprocess.run(["git", "-C", REPO, "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10,
                           check=False)
        commit = r.stdout.strip() if r.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        commit = None
    return {"commit": commit, "files_sha256": {f: l7_store.sha256_file(os.path.join(REPO, f)) for f in CODE_FILES}}


def _write(path, obj):
    data = D.canonical_json(obj) + b"\n"
    with open(path, "wb") as fh:
        fh.write(data)
    return hashlib.sha256(data).hexdigest()


def rebuild(vdir, out, *, seq=T.DEFAULT_SEQ, stride=T.DEFAULT_STRIDE, min_events=T.DEFAULT_MIN_EVENTS):
    """Verify, then derive into `out`. Returns {output name: sha256}."""
    vdir, out = os.path.abspath(vdir), os.path.abspath(out)
    if out == vdir or out.startswith(vdir + os.sep):
        raise RebuildError("--out must be outside the version directory (SHA256SUMS covers it)")
    caps = verify(vdir)
    os.makedirs(out, exist_ok=True)
    wins, cols = windows(caps, seq, stride, min_events)
    shas = {"labels.json": _write(os.path.join(out, "labels.json"), labels(caps)),
            "windows.json": _write(os.path.join(out, "windows.json"),
                                   {"seq": seq, "stride": stride, "min_events": min_events, "columns": cols,
                                    "captures": wins}),
            "split.json": _write(os.path.join(out, "split.json"), split(caps))}
    with open(os.path.join(out, "split.sha256"), "w", encoding="utf-8") as fh:
        fh.write(f"{shas['split.json']}  split.json\n")
    shas["rebuild.json"] = _write(os.path.join(out, "rebuild.json"), {
        "format": FORMAT, "version_dir": os.path.basename(vdir), "code": code_record(),
        "sha256sums": l7_store.sha256_file(os.path.join(vdir, l7_store.SUMS)),
        "manifests": {m["capture_id"]: m["manifest_sha256"] for _, m in caps}, "outputs": dict(shas)})
    return shas


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("version_dir")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    try:
        shas = rebuild(args.version_dir, args.out)
    except RebuildError as exc:
        print(f"[-] rebuild stopped: {exc}", file=sys.stderr)
        return 1
    for name, sha in sorted(shas.items()):
        print(f"{sha}  {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
