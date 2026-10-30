#!/usr/bin/env python3
"""Disjointness checks that fail closed (docs/P3_DATASET_DESIGN.md §4.7, T-005's protocol §1).

One checker, two uses: the unit tests run it on fixture manifests, and `--check` (this script, the trainer and
the learning-curve tool) runs it before every fit; they refuse to fit unless it passes. Unknown means fail: a
manifest that is not a valid schema-2 manifest, or a file that cannot be read, is a failure, never a skip.

Each failure starts with its rule number:
   1  a manifest is missing, unreadable, or not a valid schema-2 manifest (a required field is missing, a hash
      does not match, the tree was dirty, ...)
   2  entity ids intersect across train, validation and evaluation
   3  a seed is used by two splits (an evaluation seed in a training or validation manifest included)
   4  an evaluation capture's plan_set_sha256 equals a training or validation capture's (a replayed plan)
   5  one plan_sha256 is shared across splits
   6  an evaluation capture started before the last training capture ended
   7  the generator commit differs within a dataset version
   8  a file's size or sha256 does not match its manifest
   9  a held-out kind or family occurs in a training or validation capture
  10  the split file's sha256 differs from the one the selection file records
  11  a capture's seed_role is not the split it is used as, or its seed is not pre-registered for that role
  12  the training or the validation split is empty

    ./venv/bin/python ml/l7_disjoint.py --check --train D1 D2 --val D3 [--eval D4 ...] [--split F --selection F]

Exit 0 and "PASS" when nothing fails, else exit 1 and one line per failure.
"""
import argparse
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
import p3_prereg

import l7_dataset as D

SPLITS = ("train", "val", "eval")
SPLIT_FORMAT = "p3-split/1"


class DisjointnessError(RuntimeError):
    """The datasets of a fit are not disjoint, or cannot be shown to be."""


def _sha_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_manifest(dataset_dir):
    """(manifest or None, problem or None): read only, never validated here (validation is rule 1)."""
    try:
        with open(os.path.join(dataset_dir, D.MANIFEST_FILE), encoding="utf-8") as fh:
            return json.load(fh), None
    except (OSError, ValueError) as exc:
        return None, f"{dataset_dir}: {exc}"


def check(splits, *, prereg=None, split_file=None, selection_file=None, verify_files=True):
    """Every failure of the rules above for `splits` = {"train": [dirs], "val": [dirs], "eval": [dirs]}.
    Returns a list of strings, empty when the datasets pass."""
    pre = prereg or p3_prereg.load()
    fails = []
    loaded = {s: [] for s in SPLITS}
    for split in SPLITS:
        for d in splits.get(split, []):
            m, err = load_manifest(d)
            if m is None:
                fails.append(f"1 {split} {err}")
                continue
            probs = D.manifest_problems(m)
            if probs:
                fails.append(f"1 {split} {d}: " + "; ".join(probs))
                continue
            loaded[split].append((d, m))
    for split in ("train", "val"):
        if not splits.get(split):
            fails.append(f"12 the {split} split is empty")
    if any(f.startswith("1 ") for f in fails):
        return fails                      # the remaining rules need valid manifests: fail closed now

    ids = {s: {e["entity_id"] for _, m in loaded[s] for e in m["entities"]} for s in SPLITS}
    seeds = {s: [m["seed"] for _, m in loaded[s]] for s in SPLITS}
    plans = {s: {e["plan_sha256"] for _, m in loaded[s] for e in m["entities"]} for s in SPLITS}
    for i, a in enumerate(SPLITS):
        for b in SPLITS[i + 1:]:
            both = ids[a] & ids[b]
            if both:
                fails.append(f"2 entity ids in both {a} and {b}: {sorted(both)[:5]}")
            reused = sorted(set(seeds[a]) & set(seeds[b]))
            if reused:
                fails.append(f"3 seeds in both {a} and {b}: {reused}")
            shared = plans[a] & plans[b]
            if shared:
                fails.append(f"5 {len(shared)} plan_sha256 in both {a} and {b}")
    for split in SPLITS:
        dup = sorted({s for s in seeds[split] if seeds[split].count(s) > 1})
        if dup:
            fails.append(f"3 seeds used twice within {split}: {dup}")
    sets_tv = {m["plan_set_sha256"]: d for s in ("train", "val") for d, m in loaded[s]}
    for d, m in loaded["eval"]:
        if m["plan_set_sha256"] in sets_tv:
            fails.append(f"4 {d}: plan_set_sha256 equals that of {sets_tv[m['plan_set_sha256']]}")
    if loaded["train"] and loaded["eval"]:
        last_end = max(m["ended_utc"] for _, m in loaded["train"])
        for d, m in loaded["eval"]:
            if m["started_utc"] < last_end:
                fails.append(f"6 {d}: started {m['started_utc']} before the last training capture ended {last_end}")
    by_version = {}
    for s in SPLITS:
        for d, m in loaded[s]:
            by_version.setdefault(m["dataset_version"], set()).add(m["code"]["commit"])
    for version, commits in sorted(by_version.items()):
        if len(commits) > 1:
            fails.append(f"7 version {version} has {len(commits)} generator commits: {sorted(commits)}")
    if verify_files:
        for s in SPLITS:
            for d, m in loaded[s]:
                for f in m["files"]:
                    path = os.path.join(d, f["path"])
                    try:
                        ok = os.path.getsize(path) == f["size"] and _sha_file(path) == f["sha256"]
                    except OSError:
                        ok = False
                    if not ok:
                        fails.append(f"8 {d}: {f['path']} does not match its manifest")
    for s in ("train", "val"):
        for d, m in loaded[s]:
            held = sorted({e["kind_or_family"] for e in m["entities"] if e["held_out"]})
            if held:
                fails.append(f"9 {d} ({s}) holds held-out kinds or families: {held}")
    for s in SPLITS:
        for d, m in loaded[s]:
            if m["seed_role"] != s:
                fails.append(f"11 {d}: seed_role {m['seed_role']!r} used as {s}")
            elif p3_prereg.seed_role(m["seed"], pre) != s:
                fails.append(f"11 {d}: seed {m['seed']} is not pre-registered for {s}")
    if selection_file is not None or split_file is not None:
        try:
            with open(selection_file, encoding="utf-8") as fh:
                recorded = json.load(fh).get("split_sha256")
            actual = _sha_file(split_file)
        except (OSError, ValueError, TypeError) as exc:
            fails.append(f"10 split or selection file unreadable: {exc}")
        else:
            if recorded != actual:
                fails.append(f"10 the split file's sha256 {actual} differs from the selection's {recorded}")
    return fails


def require(splits, **kw):
    """check(), raising DisjointnessError when anything fails: what a fit calls first."""
    fails = check(splits, **kw)
    if fails:
        raise DisjointnessError("refusing to fit: the datasets are not shown disjoint:\n  " + "\n  ".join(fails))
    return True


def split_record(splits):
    """The split file's content: capture ids and entity -> split, from the manifests (no fitting state)."""
    out = {"format": SPLIT_FORMAT, "captures": {}, "entities": {}}
    for s in SPLITS:
        for d in splits.get(s, []):
            m, err = load_manifest(d)
            if m is None:
                raise DisjointnessError(err)
            out["captures"][m["capture_id"]] = {"split": s, "seed": m["seed"],
                                                "manifest_sha256": m["manifest_sha256"]}
            for e in m["entities"]:
                out["entities"][e["entity_id"]] = s
    return out


def write_split(path, splits):
    """Write the split file (canonical JSON) and return its sha256."""
    data = D.canonical_json(split_record(splits)) + b"\n"
    with open(path, "wb") as fh:
        fh.write(data)
    return hashlib.sha256(data).hexdigest()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="run the checks (the default action)")
    for s in SPLITS:
        ap.add_argument(f"--{s}", nargs="*", default=[], metavar="DATASET_DIR")
    ap.add_argument("--split", help="the split file a selection was made on")
    ap.add_argument("--selection", help="the frozen selection file (records split_sha256)")
    args = ap.parse_args(argv)
    fails = check({s: getattr(args, s) for s in SPLITS}, split_file=args.split, selection_file=args.selection)
    for f in fails:
        print(f"FAIL {f}")
    print("PASS" if not fails else f"{len(fails)} failure(s): refusing")
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
