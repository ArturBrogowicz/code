"""L7 capture dataset: manifest schema and labels (docs/L7_GRU_DESIGN.md §6; Phase P3).

A *dataset* is a directory with
    manifest.json   this schema: provenance, seeds, the IP->label map, and the attack
                    schedule (ground-truth start/stop per bot) — everything the trainer
                    needs that the access log alone does not carry
    access.log      the extended l7json access log (one JSON object per request)
    capture.log     the human-readable run log (optional)

The capture (`ml/capture_l7.py`, P3) writes it; the trainer (`ml/train_l7.py`, P4)
reads it. This module is the shared contract, so the writer and reader cannot drift.
Standard library only, no import-time side effects.

Labels come from the namespace plan, never from the model: a request is `attack` iff
its source IP is an attacker IP in the plan, `benign` iff a benign IP, else `other`
(dropped from training). Each attacker IP carries its family and whether it is a
held-out (evaluation-only) family.
"""
import json
import time

DATASET_FORMAT = "l7-dataset/1"
MANIFEST_FILE = "manifest.json"
ACCESS_LOG = "access.log"

BENIGN = "benign"
ATTACK = "attack"
OTHER = "other"


def label_for(ip, ip_map):
    """Return (class, family, held_out) for a source IP given manifest['ip_map'].
    An unknown IP is ('other', None, False) and must be dropped from training."""
    entry = ip_map.get(ip)
    if entry is None:
        return (OTHER, None, False)
    return (entry.get("class", OTHER), entry.get("family"), bool(entry.get("held_out")))


def build_ip_map(benign_clients, attackers):
    """Build the IP->label map.

    benign_clients: iterable of {ip, profile, kind, ...}
    attackers:      iterable of {ip, family, held_out, params, ...}
    """
    ip_map = {}
    for c in benign_clients:
        ip_map[c["ip"]] = {"class": BENIGN, "family": None, "held_out": False,
                           "profile": c.get("profile"), "kind": c.get("kind")}
    for a in attackers:
        ip_map[a["ip"]] = {"class": ATTACK, "family": a["family"],
                           "held_out": bool(a.get("held_out")), "params": a.get("params", {})}
    return ip_map


def make_manifest(*, seed, duration_s, ip_map, schedule, provenance, notes=""):
    """Assemble a manifest dict. `schedule` is the list of attack-window records
    (see ml/l7_traffic.AttackSpec.as_schedule_entry): each has ip, family, held_out,
    start_s, stop_s, params. Times are seconds from capture start (t0 in provenance)."""
    return {
        "format": DATASET_FORMAT,
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "seed": int(seed),
        "duration_s": float(duration_s),
        "access_log": ACCESS_LOG,
        "ip_map": ip_map,
        "schedule": list(schedule),
        "provenance": provenance,
        "notes": notes,
    }


def validate_manifest(m):
    """Raise ValueError if the manifest is malformed. Returns m on success."""
    if m.get("format") != DATASET_FORMAT:
        raise ValueError(f"unsupported dataset format: {m.get('format')}")
    for key in ("seed", "duration_s", "ip_map", "schedule", "provenance"):
        if key not in m:
            raise ValueError(f"manifest missing '{key}'")
    if not isinstance(m["ip_map"], dict) or not m["ip_map"]:
        raise ValueError("ip_map must be a non-empty object")
    classes = {e.get("class") for e in m["ip_map"].values()}
    if not ({BENIGN, ATTACK} & classes):
        raise ValueError("ip_map has neither benign nor attack IPs")
    sched_ips = {s.get("ip") for s in m["schedule"]}
    attack_ips = {ip for ip, e in m["ip_map"].items() if e.get("class") == ATTACK}
    unknown = sched_ips - set(m["ip_map"])
    if unknown:
        raise ValueError(f"schedule references IPs not in ip_map: {sorted(unknown)}")
    for s in m["schedule"]:
        if not (0.0 <= s["start_s"] <= s["stop_s"] <= m["duration_s"] + 1e-6):
            raise ValueError(f"schedule entry out of range: {s}")
    scheduled_attackers = {s["ip"] for s in m["schedule"]}
    if attack_ips and not (attack_ips & scheduled_attackers):
        raise ValueError("no attacker IP appears in the schedule")
    return m


def write_dataset_manifest(path, manifest):
    validate_manifest(manifest)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1)
        fh.write("\n")


def read_dataset(dataset_dir):
    """Load and validate a dataset's manifest. Returns (manifest, access_log_path)."""
    import os
    with open(os.path.join(dataset_dir, MANIFEST_FILE), encoding="utf-8") as fh:
        manifest = json.load(fh)
    validate_manifest(manifest)
    return manifest, os.path.join(dataset_dir, manifest.get("access_log", ACCESS_LOG))


def families(manifest, held_out=None):
    """The attack families in a manifest. held_out=True/False filters; None = all."""
    out = set()
    for e in manifest["ip_map"].values():
        if e.get("class") == ATTACK and (held_out is None or bool(e.get("held_out")) == held_out):
            out.add(e.get("family"))
    return sorted(out)
