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

Schema 2 (docs/P3_DATASET_DESIGN.md §4.4; the P3 captures) adds one row per entity (id,
role, kind or family, address, namespace, netem, drawn params, sub-seed, schedule and
plan_sha256), the pool and its role map, the code, server and host blocks, the files with
their hashes, plan_set_sha256 and manifest_sha256 (over the canonical JSON without that
field). Its ip_map and schedule are derived from the entities, and validation recomputes
every hash, so nothing can drift. Schema 1 manifests read exactly as before.

Schema 3 (docs/L7V2_DESIGN.md §6; the P3 note §5, "the M3 phase reuses the C2 phase's addresses")
is schema 2 plus address reuse in time: two entities may share an address when they have the same
role and their schedules [start_s, stop_s) do not overlap. `address_map` (derived and checked) gives
each address its entities in time order; labeler() labels a request by (address, time since t0,
the capture's timeline.t0_wall), and a request outside every interval of a reused address is
`other`. For an address with one entity the ip_map entry is schema 2's; a reused address's entry
says so ("time_indexed") and carries no entity, so no reader can take one entity's label for
another's. A schema-2 manifest reads as before (schema 3 readers accept it).
"""
import gzip
import hashlib
import itertools
import json
import os
import re
import time

DATASET_FORMAT = "l7-dataset/1"
DATASET_FORMAT_V2 = "l7-dataset/2"
DATASET_FORMAT_V3 = "l7-dataset/3"
FORMATS_P3 = {DATASET_FORMAT_V2: 2, DATASET_FORMAT_V3: 3}
MANIFEST_FILE = "manifest.json"
ACCESS_LOG = "access.log"
ACCESS_LOG_GZ = "access.log.gz"
ERROR_LOG_GZ = "error.log.gz"
SEED_ROLES = ("train", "val", "eval", "pilot")
ROLES = ("benign", "attack")
# What plan_sha256 covers: everything the entity will do, but not its id, index, sub-seed or
# namespace name (positional), so a replayed plan has the same hash under another seed.
PLAN_KEYS = ("role", "kind_or_family", "mechanism", "held_out", "address", "netem", "port",
             "params", "client_seed", "schedule")
ENTITY_KEYS = ("entity_id", "index", "subseed", "namespace", "plan_sha256") + PLAN_KEYS
TOP_KEYS_V2 = ("format", "schema", "dataset_version", "capture_id", "seed", "seed_role",
               "started_utc", "ended_utc", "duration_s", "code", "server", "host", "pool",
               "timeline", "entities", "files", "ip_map", "schedule", "access_log", "notes",
               "plan_set_sha256", "manifest_sha256")
TOP_KEYS_V3 = TOP_KEYS_V2 + ("address_map",)
VERSION_RE = re.compile(r"^\d{4}-\d{2}-[a-z0-9][a-z0-9.-]{0,40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
# Schema 2 maps one address to one entity for the whole capture. Two entities on one address (a CGNAT pool's users,
# the M3 phase reusing C2's addresses) need schema 3's time-indexed entity-address map (feat/l7v2-traffic).
NEEDS_SCHEMA_3 = "address reuse needs schema 3 (a time-indexed entity-address map; feat/l7v2-traffic)"


class ManifestError(ValueError):
    """A schema-2 manifest is incomplete, inconsistent or does not match its hashes."""

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

    benign_clients: iterable of {ip, profile, kind, held_out?, ...} (a held-out benign
                    kind, P5b, is never trained on; the trainer reports it separately)
    attackers:      iterable of {ip, family, held_out, params, ...}
    """
    ip_map = {}
    for c in benign_clients:
        ip_map[c["ip"]] = {"class": BENIGN, "family": None, "held_out": bool(c.get("held_out")),
                           "profile": c.get("profile"), "kind": c.get("kind"),
                           "gate_admissible": c.get("gate_admissible", True)}
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
    """Raise ValueError if the manifest is malformed. Returns m on success. A schema-2
    manifest goes through validate_manifest_v2()."""
    if m.get("format") in FORMATS_P3:
        return validate_manifest_v2(m)
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
    """Load and validate a dataset's manifest. Returns (manifest, access_log_path). A
    schema-1 dataset whose access.log is absent but whose access.log.gz is present (the
    published form) gets the .gz path; open_log() reads either."""
    with open(os.path.join(dataset_dir, MANIFEST_FILE), encoding="utf-8") as fh:
        manifest = json.load(fh)
    validate_manifest(manifest)
    path = os.path.join(dataset_dir, manifest.get("access_log", ACCESS_LOG))
    if not os.path.exists(path) and os.path.exists(path + ".gz"):
        path += ".gz"
    return manifest, path


def open_log(path):
    """A text handle on an access log, gzipped or not (undecodable bytes replaced)."""
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, encoding="utf-8", errors="replace")


# ───────────────────────────── schema 2 (P3) ─────────────────────────────

def canonical_json(obj):
    """The bytes every schema-2 hash is taken over: sorted keys, no spaces, ASCII."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def entity_plan_sha256(entity):
    """The hash of an entity's exact plan (PLAN_KEYS)."""
    return sha256_hex(canonical_json({k: entity.get(k) for k in PLAN_KEYS}))


def plan_set_sha256(entities):
    """The hash of the sorted plan_sha256 values: what the disjointness check compares."""
    return sha256_hex("\n".join(sorted(e["plan_sha256"] for e in entities)).encode())


def ip_map_from_entities(entities):
    """The schema-1 ip_map (address -> label) derived from the entity rows. An address that serves several
    entities in time (schema 3) gets {"class", "time_indexed": True, "entity_ids"} and no entity of its own."""
    out = {}
    by_addr = {}
    for e in entities:
        by_addr.setdefault(e["address"], []).append(e)
    for e in entities:
        if len(by_addr[e["address"]]) > 1:
            out[e["address"]] = {"class": ATTACK if e["role"] == "attack" else BENIGN, "time_indexed": True,
                                 "entity_ids": sorted(x["entity_id"] for x in by_addr[e["address"]])}
            continue
        attack = e["role"] == "attack"
        out[e["address"]] = {"class": ATTACK if attack else BENIGN,
                             "family": e["kind_or_family"] if attack else None,
                             "kind": None if attack else e["kind_or_family"],
                             "held_out": bool(e["held_out"]), "profile": e["netem"],
                             "entity_id": e["entity_id"]}
    return out


def schedule_from_entities(entities):
    """The schema-1 attack schedule derived from the attack entities' rows."""
    rows = [{"ip": e["address"], "family": e["kind_or_family"], "held_out": bool(e["held_out"]),
             "mechanism": e.get("mechanism"), "start_s": e["schedule"]["start_s"],
             "stop_s": e["schedule"]["stop_s"], "params": dict(e["params"])}
            for e in entities if e["role"] == "attack"]
    return sorted(rows, key=lambda r: (r["start_s"], r["ip"]))


def address_map_from_entities(entities):
    """Schema 3: address -> its entities in time order, [{entity_id, role, kind_or_family, held_out, start_s,
    stop_s}]."""
    out = {}
    for e in entities:
        out.setdefault(e["address"], []).append(
            {"entity_id": e["entity_id"], "role": e["role"], "kind_or_family": e["kind_or_family"],
             "held_out": bool(e["held_out"]), "start_s": e["schedule"]["start_s"], "stop_s": e["schedule"]["stop_s"]})
    for rows in out.values():
        rows.sort(key=lambda r: (r["start_s"], r["entity_id"]))
    return dict(sorted(out.items()))


def reuse_problems(entities):
    """Schema 3: an address shared by entities of two roles, or by two entities whose schedules overlap."""
    probs = []
    for addr, rows in address_map_from_entities(entities).items():
        if len({r["role"] for r in rows}) > 1:
            probs.append(f"address {addr} serves two roles: {[r['entity_id'] for r in rows]}")
        for a, b in itertools.pairwise(rows):
            if b["start_s"] < a["stop_s"]:
                probs.append(f"address {addr}: {a['entity_id']} [{a['start_s']}, {a['stop_s']}) overlaps "
                             f"{b['entity_id']} [{b['start_s']}, {b['stop_s']})")
    return probs


def pool_users(entity):
    """Schema 3: the user entities of a pool (params.users > 1: a CGNAT pool, a NAT gateway), each its own unit with the
    pool's entity as their cluster (docs/P3_DATASET_DESIGN.md 4.4): ["<entity_id>/u0", ...]; [] for one user."""
    users = entity["params"].get("users", 1) if isinstance(entity.get("params"), dict) else 1
    return [f"{entity['entity_id']}/u{k}" for k in range(users)] if isinstance(users, int) and users > 1 else []


def users_problems(entities):
    """Schema 3: an entity whose `users` list is not exactly its pool's user entities."""
    return [f"entity {e['entity_id']}: users {e.get('users')!r} are not its pool's {len(pool_users(e))} user entities"
            for e in entities if e.get("users", []) != pool_users(e)]


def user_units(m):
    """The benign-budget units of a capture as (unit, cluster entity, role): every entity, and in schema 3 a pool counted
    by its users, so a flagged 24-user pool costs 24 units, not one."""
    out = []
    for e in m["entities"]:
        users = e.get("users") if m.get("format") == DATASET_FORMAT_V3 else None
        out += [(u, e["entity_id"], e["role"]) for u in (users or [e["entity_id"]])]
    return out


def time_origin(m):
    """The wall-clock time (s) the schedule's seconds count from, or None (schema 1, or no t0 recorded)."""
    t0 = (m.get("timeline") or {}).get("t0_wall") if isinstance(m.get("timeline"), dict) else None
    return float(t0) if isinstance(t0, (int, float)) and not isinstance(t0, bool) else None


def labeler(m):
    """label(ip, t_rel) -> (class, family, held_out, entity_id) for a request from `ip` at `t_rel` seconds after the
    capture's time origin. Schema 1 and 2 ignore the time (one entity per address: the ip_map label, the entity id
    when the manifest has one); schema 3 picks the entity whose schedule holds t_rel on a reused address, and a
    request outside every interval of a reused address, or with no time, is `other`."""
    ip_map = m["ip_map"]
    amap = m.get("address_map") if m.get("format") == DATASET_FORMAT_V3 else None

    def label(ip, t_rel=None):
        entry = ip_map.get(ip)
        if entry is None:
            return (OTHER, None, False, None)
        if not entry.get("time_indexed"):
            cls, family, held = label_for(ip, ip_map)
            return (cls, family, held, entry.get("entity_id", ip))
        if t_rel is None or amap is None:
            return (OTHER, None, False, None)
        for r in amap[ip]:
            if r["start_s"] <= t_rel < r["stop_s"]:
                attack = r["role"] == "attack"
                return (ATTACK if attack else BENIGN, r["kind_or_family"] if attack else None, r["held_out"],
                        r["entity_id"])
        return (OTHER, None, False, None)
    return label


def kind_or_family(m):
    """entity_id (or address, schema 1) -> kind or family, for tagging windows."""
    if m.get("format") in FORMATS_P3:
        return {e["entity_id"]: e["kind_or_family"] for e in m["entities"]}
    return {ip: e.get("family") or e.get("kind") for ip, e in m["ip_map"].items()}


def manifest_sha256(m):
    """The hash of the canonical JSON of the manifest without its manifest_sha256 field."""
    return sha256_hex(canonical_json({k: v for k, v in m.items() if k != "manifest_sha256"}))


def make_manifest_v2(*, dataset_version, capture_id, seed, seed_role, started_utc, ended_utc,
                     duration_s, code, server, host, pool, timeline, entities, files, notes="", schema=2):
    """Assemble a schema-2 manifest (schema=3: with the time-indexed address_map); the derived fields and both hashes
    are filled in."""
    m = {"format": DATASET_FORMAT_V3 if schema == 3 else DATASET_FORMAT_V2, "schema": schema,
         "dataset_version": dataset_version,
         "capture_id": capture_id, "seed": int(seed), "seed_role": seed_role,
         "started_utc": started_utc, "ended_utc": ended_utc, "duration_s": float(duration_s),
         "code": code, "server": server, "host": host, "pool": pool, "timeline": timeline,
         "entities": list(entities), "files": list(files),
         "ip_map": ip_map_from_entities(entities), "schedule": schedule_from_entities(entities),
         "access_log": ACCESS_LOG_GZ, "notes": notes,
         "plan_set_sha256": plan_set_sha256(entities)}
    if schema == 3:
        m["address_map"] = address_map_from_entities(entities)
    m["manifest_sha256"] = manifest_sha256(m)
    return m


def manifest_problems(m):
    """Every reason a schema-2 or schema-3 manifest is not acceptable (empty when it is). Unknown or
    missing means a problem: the checks fail closed."""
    if not isinstance(m, dict):
        return ["manifest is not an object"]
    v3 = m.get("format") == DATASET_FORMAT_V3
    probs = [f"missing field {k!r}" for k in (TOP_KEYS_V3 if v3 else TOP_KEYS_V2) if k not in m]
    if probs:
        return probs
    if FORMATS_P3.get(m["format"]) != m["schema"]:
        probs.append(f"format {m['format']!r} schema {m['schema']!r}")
    if not isinstance(m["dataset_version"], str) or not VERSION_RE.match(m["dataset_version"]):
        probs.append(f"dataset_version {m['dataset_version']!r} is not <yyyy-mm>-<tag>")
    if not isinstance(m["seed"], int) or isinstance(m["seed"], bool):
        probs.append("seed is not an int")
    if m["seed_role"] not in SEED_ROLES:
        probs.append(f"seed_role {m['seed_role']!r} not in {SEED_ROLES}")
    stamps = {}
    for k in ("started_utc", "ended_utc"):
        try:
            stamps[k] = time.strptime(m[k], "%Y-%m-%dT%H:%M:%SZ") if UTC_RE.match(str(m[k])) else None
        except ValueError:
            stamps[k] = None
        if stamps[k] is None:
            probs.append(f"{k} {m[k]!r} is not %Y-%m-%dT%H:%M:%SZ")
    if None not in stamps.values() and stamps["ended_utc"] < stamps["started_utc"]:
        probs.append("ended_utc is before started_utc")
    code = m["code"] if isinstance(m["code"], dict) else {}
    if not HEX40_RE.match(str(code.get("commit"))):
        probs.append("code.commit is not a git commit")
    if code.get("dirty") is not False:
        probs.append(f"code.dirty is {code.get('dirty')!r}: a P3 capture must run on a clean tree")
    if not isinstance(code.get("inputs_sha256"), dict) or not code.get("inputs_sha256"):
        probs.append("code.inputs_sha256 missing")
    if not isinstance(m["server"], dict) or "config_id" not in m["server"]:
        probs.append("server.config_id missing")
    ents = m["entities"]
    if not isinstance(ents, list) or not ents:
        return probs + ["entities missing or empty"]
    ids, addrs = set(), set()
    for i, e in enumerate(ents):
        miss = [k for k in ENTITY_KEYS if k not in e]
        if miss:
            probs.append(f"entity {i}: missing {miss}")
            continue
        if e["entity_id"] != f"{m['dataset_version']}:{m['seed']}:{e['index']}":
            probs.append(f"entity {i}: id {e['entity_id']!r} is not <version>:<seed>:<index>")
        if e["entity_id"] in ids:
            probs.append(f"entity {i}: duplicate id {e['entity_id']}")
        if e["address"] in addrs and not v3:
            probs.append(f"entity {i}: address {e['address']} belongs to another entity too: {NEEDS_SCHEMA_3}")
        ids.add(e["entity_id"])
        addrs.add(e["address"])
        if e["role"] not in ROLES:
            probs.append(f"entity {i}: role {e['role']!r}")
        if e["plan_sha256"] != entity_plan_sha256(e):
            probs.append(f"entity {e['entity_id']}: plan_sha256 does not match its plan")
        sch = e["schedule"] if isinstance(e["schedule"], dict) else {}
        try:
            ok = 0.0 <= sch["start_s"] <= sch["stop_s"] <= m["duration_s"] + 1e-6
        except (KeyError, TypeError):
            ok = False
        if not ok:
            probs.append(f"entity {e['entity_id']}: schedule out of range: {sch}")
    if probs:
        return probs
    if v3:
        probs += reuse_problems(ents) + users_problems(ents)
        if m["address_map"] != address_map_from_entities(ents):
            probs.append("address_map does not match the entities")
        if time_origin(m) is None and any(len(r) > 1 for r in address_map_from_entities(ents).values()):
            probs.append("timeline.t0_wall missing: a reused address cannot be labelled in time")
    pool = m["pool"] if isinstance(m["pool"], dict) else {}
    if pool.get("role_map") != {e["address"]: e["role"] for e in ents}:
        probs.append("pool.role_map does not match the entities")
    if m["ip_map"] != ip_map_from_entities(ents):
        probs.append("ip_map does not match the entities")
    if m["schedule"] != schedule_from_entities(ents):
        probs.append("schedule does not match the entities")
    if not ({"benign", "attack"} >= {e["role"] for e in ents}):
        probs.append("unknown roles")
    names = [f.get("path") for f in m["files"] if isinstance(f, dict)]
    if m["access_log"] not in names:
        probs.append(f"files do not list the access log {m['access_log']!r}")
    for f in m["files"]:
        if not (isinstance(f, dict) and HEX64_RE.match(str(f.get("sha256")))
                and isinstance(f.get("size"), int)):
            probs.append(f"file record incomplete: {f}")
        elif not (isinstance(f.get("path"), str) and f["path"] == os.path.basename(f["path"])
                  and f["path"] not in ("", ".", "..")):
            probs.append(f"file path {f.get('path')!r} is not a plain name inside the capture directory")
    if m["plan_set_sha256"] != plan_set_sha256(ents):
        probs.append("plan_set_sha256 does not match the entities")
    if m["manifest_sha256"] != manifest_sha256(m):
        probs.append("manifest_sha256 does not match the manifest")
    return probs


def validate_manifest_v2(m):
    """Raise ManifestError listing every problem of a schema-2 manifest. Returns m."""
    probs = manifest_problems(m)
    if probs:
        raise ManifestError("; ".join(probs))
    return m


def file_record(path, rel):
    """{path, size, sha256, lines, content_sha256} of a stored file; for a .gz file the line
    count and content_sha256 are of the decompressed bytes."""
    h, size = hashlib.sha256(), 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
            size += len(chunk)
    rec = {"path": rel, "size": size, "sha256": h.hexdigest()}
    opener = gzip.open if path.endswith(".gz") else open
    c, lines = hashlib.sha256(), 0
    with opener(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            c.update(chunk)
            lines += chunk.count(b"\n")
    rec["content_sha256"], rec["lines"] = c.hexdigest(), lines
    return rec


def families(manifest, held_out=None):
    """The attack families in a manifest. held_out=True/False filters; None = all."""
    out = set()
    for e in manifest["ip_map"].values():
        if e.get("class") == ATTACK and (held_out is None or bool(e.get("held_out")) == held_out):
            out.add(e.get("family"))
    return sorted(out)
