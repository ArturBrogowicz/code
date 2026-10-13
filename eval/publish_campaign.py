#!/usr/bin/env python3
"""Copy a campaign into the repository (results/<id>/) so it can be committed.

    venv/bin/python eval/publish_campaign.py <campaign_dir> [--name ID] [--force]

Copies campaign.json (if any) and, per run, provenance.json, scenario_results.csv,
availability.csv, availability_raw.csv, metrics.csv, ban_events.jsonl, daemon.log,
console.log (ANSI colour codes stripped) and DONE; then regenerates analysis/ in the
copy with eval/analyze_campaign.py and eval/plot_campaign.py and writes SHA256SUMS.
If the source already had an analysis/, the regenerated one must match it byte for
byte (proof that the published numbers come from the published data). Nothing outside
results/<id>/ is touched; committing is left to you.
"""
import argparse
import hashlib
import os
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import campaign as C
from analyze_campaign import analyse
from plot_campaign import plot_all

REPO = os.path.dirname(HERE)
RUN_FILES = ["provenance.json", "scenario_results.csv", "availability.csv",
             "availability_raw.csv", "metrics.csv", "ban_events.jsonl", "daemon.log",
             "console.log", "DONE"]
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
WARN_BYTES, MAX_BYTES = 20 << 20, 100 << 20


def tree_hashes(root):
    out = {}
    for d, _, files in os.walk(root):
        for f in files:
            p = os.path.join(d, f)
            rel = os.path.relpath(p, root)
            if rel != "SHA256SUMS":
                with open(p, "rb") as fh:
                    out[rel] = hashlib.sha256(fh.read()).hexdigest()
    return dict(sorted(out.items()))


def regenerate(campaign_dir, out_dir):
    analyse(campaign_dir, out_dir)
    plot_all(campaign_dir, os.path.join(out_dir, "figures"))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("campaign")
    ap.add_argument("--name", help="results/<name> (default: the campaign directory name)")
    ap.add_argument("--force", action="store_true", help="replace an existing results/<name>, "
                    "or publish more than 100 MB")
    args = ap.parse_args()
    src = os.path.abspath(args.campaign)
    name = args.name or os.path.basename(src)
    dst = os.path.join(REPO, "results", name)
    if os.path.exists(dst):
        if not args.force:
            sys.exit(f"{dst} exists (use --force to replace it)")
        shutil.rmtree(dst)
    runs = C.find_runs(src)
    if not runs:
        sys.exit(f"no runs (provenance.json) under {src}")
    single = len(runs) == 1 and os.path.isfile(os.path.join(src, "provenance.json"))
    os.makedirs(dst)
    for extra in ("campaign.json", "README.md"):
        if os.path.isfile(os.path.join(src, extra)):
            shutil.copy2(os.path.join(src, extra), dst)
    for _, run, rdir in runs:
        target = dst if single else os.path.join(dst, os.path.relpath(rdir, src))
        os.makedirs(target, exist_ok=True)
        for f in RUN_FILES:
            p = os.path.join(rdir, f)
            if not os.path.isfile(p):
                continue
            if f == "console.log":
                with open(p, encoding="utf-8", errors="replace") as fh:
                    text = ANSI.sub("", fh.read())
                with open(os.path.join(target, f), "w", encoding="utf-8") as fh:
                    fh.write(text)
            else:
                shutil.copy2(p, target)
    regenerate(dst, os.path.join(dst, "analysis"))
    src_analysis = os.path.join(src, "analysis")
    if os.path.isdir(src_analysis):
        a, b = tree_hashes(src_analysis), tree_hashes(os.path.join(dst, "analysis"))
        differ = sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))
        if differ:
            print("[!] analysis/ of the source differs from the one regenerated from the "
                  "published data (stale source analysis?):\n    " + "\n    ".join(differ))
        else:
            print(f"[+] analysis/ reproduces byte for byte from the published data ({len(a)} files)")
    hashes = tree_hashes(dst)
    with open(os.path.join(dst, "SHA256SUMS"), "w", encoding="utf-8") as fh:
        fh.writelines(f"{h}  {rel}\n" for rel, h in hashes.items())
    size = sum(os.path.getsize(os.path.join(dst, rel)) for rel in hashes)
    if size > MAX_BYTES and not args.force:
        shutil.rmtree(dst)
        sys.exit(f"{size / 2**20:.1f} MB is too large to commit (use --force to keep it)")
    if size > WARN_BYTES:
        print(f"[!] {size / 2**20:.1f} MB — consider Git LFS or publishing a subset")
    rel = os.path.relpath(dst, REPO)
    print(f"[+] published {len(hashes)} files ({size / 2**20:.2f} MB) to {rel}/\n"
          f"    review, then: git add {rel} && git commit")


if __name__ == "__main__":
    main()
