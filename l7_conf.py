"""The P1 runner's nginx configurations for L7 v2 (ledger D-028; review T-030 L7V2-09; docs/L7V2_DESIGN.md 8.4, 9.2).

Pure functions over the text of the tracked confs: a run renders its own copies and never edits the tracked files.
nginx_unprotected.conf is pinned by the harm benchmark (its sha256 is in the executor's golden plans and in a frozen
calibration record's host block), so it stays as it is, and so does nginx.conf.
  * unprotected(text): nginx_unprotected.conf for the C, C' and U runs, with the three L7 v2 log fields nginx.conf's
    l7json already has (ref, sid, sid_set) added after ua, in the same lines, so every arm of a block logs the same
    schema (L7V2-09: without them the U runs would key (IP, UA) and miss the referrer features).
  * protected(text, run_dir): nginx.conf for the M arms, with the enforcing arm's level 1 (9.2): in the http block,
    `map "$remote_addr|$http_user_agent|$cookie_sid" $l7_deny { default 0; include <run_dir>/deny.map; }` and the map
    hash sizes the deny map's keys need; in the server block, `if ($l7_deny) { return 429; }`. A server-level `if`
    with `return` runs in the server rewrite phase, before any location and before limit_req, and the 429 is still
    logged, which is how the arm sees that a denied key keeps sending (l7_enforce, level 2).
Every insertion point must occur exactly once, or the text is refused (ConfError), as capture_l7.render_l7_sink and
bench/executor.render_nginx_conf refuse. The `# L7-SYSLOG-SINK` marker is left in place: the runner adds the
daemon's socket sink with capture_l7.render_l7_sink and the run's log paths with executor.render_nginx_conf, in any
order. The run directory must exist, with an empty deny.map, before nginx starts (l7_denymap.prepare_run_dir):
nginx refuses an include of a missing file.

Map hash sizes. nginx refuses a map whose longest key does not fit a bucket ("could not build map_hash, you should
increase map_hash_bucket_size"; an element needs 8 + align(len + 2, 8) + 8 bytes, src/core/ngx_hash.c:248-288 of
nginx 1.28.3), and the default bucket is one cache line (64 bytes here): a testbed browser's key (about 150 bytes)
would already not fit. MAP_HASH_BUCKET_SIZE covers the longest key the writer allows (305 bytes, l7_denymap), and
MAP_HASH_MAX_SIZE lets nginx find a hash for 2,000 such keys; a port of nginx's size search over 2,000 realistic and
2,000 worst-case keys finds sizes 671 and 4,378 (tasks/T-025c/artifacts/hash_sim). [NOT RUN: `nginx -t` of a rendered
copy with a full map is in the smoke packet.]
"""
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
UNPROTECTED_CONF = os.path.join(HERE, "nginx_unprotected.conf")
PROTECTED_CONF = os.path.join(HERE, "nginx.conf")
DENY_FILE = "deny.map"                               # l7_denymap.DENY_FILE
DENY_VAR = "$l7_deny"
DENY_STATUS = 429
MAP_SOURCE = '"$remote_addr|$http_user_agent|$cookie_sid"'
MAP_HASH_BUCKET_SIZE = 1024
MAP_HASH_MAX_SIZE = 8192
V2_FIELDS = (("ref", "$http_referer"), ("sid", "$cookie_sid"), ("sid_set", "$upstream_cookie_sid"))
RUN_DIR_RE = re.compile(r"/[A-Za-z0-9_./-]+")
L7JSON = re.compile(r"log_format l7json escape=json\n(.*?)'}';", re.DOTALL)
UA_LAST = re.compile(r"^([ \t]*)'\"ua\":\"\$http_user_agent\"'[ \t]*$", re.MULTILINE)
SERVER_OPEN = re.compile(r"^([ \t]*)server[ \t]*\{[ \t]*$", re.MULTILINE)
SERVER_NAME = re.compile(r"^([ \t]*)server_name[ \t][^;\n]*;[ \t]*$", re.MULTILINE)


class ConfError(ValueError):
    """The conf text is not the one this renderer knows, or the run directory is not usable."""


def _one(pattern, text, what):
    found = list(pattern.finditer(text))
    if len(found) != 1:
        raise ConfError(f"nginx configuration: expected exactly one {what}, found {len(found)}")
    return found[0]


def unprotected(text):
    """nginx_unprotected.conf's text with ref, sid and sid_set logged in its l7json, after ua (D-028)."""
    block = _one(L7JSON, text, "l7json log_format")
    if "$http_referer" in block.group(1) or "$cookie_sid" in block.group(1):
        raise ConfError("nginx configuration: the l7json format already logs the L7 v2 fields")
    ua = _one(UA_LAST, block.group(1), "last l7json field ua")
    indent = ua.group(1)
    lines = [f"{indent}'\"ua\":\"$http_user_agent\",'"]
    lines += [f"{indent}'\"{name}\":\"{var}\"{',' if i < len(V2_FIELDS) - 1 else ''}'"
              for i, (name, var) in enumerate(V2_FIELDS)]
    start = block.start(1) + ua.start()
    return text[:start] + "\n".join(lines) + text[block.start(1) + ua.end():]


def deny_map_path(run_dir):
    """The deny map nginx includes for a run directory (an absolute path of letters, digits and _ . / -)."""
    if not isinstance(run_dir, str) or not RUN_DIR_RE.fullmatch(run_dir) or "/../" in run_dir + "/":
        raise ConfError(f"unusable run directory {run_dir!r}")
    return f"{run_dir.rstrip('/')}/{DENY_FILE}"


def protected(text, run_dir):
    """nginx.conf's text with the enforcing arm's deny map (http block) and its 429 (server block)."""
    path = deny_map_path(run_dir)
    if DENY_VAR in text:
        raise ConfError(f"nginx configuration: {DENY_VAR} is already defined")
    server = _one(SERVER_OPEN, text, "server block")
    name = _one(SERVER_NAME, text, "server_name line")
    ind = server.group(1)
    block = (f"{ind}# L7 v2 enforcing arm, level 1 (docs/L7V2_DESIGN.md 9.2): the daemon writes {path}, one\n"
             f"{ind}# \"ip|ua|sid\" 1; line per denied key (l7_denymap.py); a request whose key is listed gets "
             f"{DENY_STATUS}.\n"
             f"{ind}map_hash_bucket_size {MAP_HASH_BUCKET_SIZE};\n"
             f"{ind}map_hash_max_size {MAP_HASH_MAX_SIZE};\n"
             f"{ind}map {MAP_SOURCE} {DENY_VAR} {{\n"
             f"{ind}    default 0;\n"
             f"{ind}    include {path};\n"
             f"{ind}}}\n\n")
    inner = name.group(1)
    deny = (f"\n\n{inner}# L7 v2 level 1: a denied (IP, UA, sid) key, before any location and limit\n"
            f"{inner}if ({DENY_VAR}) {{\n{inner}    return {DENY_STATUS};\n{inner}}}")
    out = text[:name.end()] + deny + text[name.end():]
    return out[:server.start()] + block + out[server.start():]


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def run_confs(run_dir):
    """{"unprotected": text, "protected": text}: the run's copies of the two tracked confs (read, never written)."""
    return {"unprotected": unprotected(read(UNPROTECTED_CONF)), "protected": protected(read(PROTECTED_CONF), run_dir)}
