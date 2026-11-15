"""The pre-checks of a packet of the re-calibration (docs/RECALIBRATION_2026-11_DESIGN.md 5.2, K7): each a function of the text a
command printed, so that it can be tried on fixtures, and a command line that runs the commands on this host and prints one line a
check. Nothing here starts, stops or changes anything; bpftool and the journal need root to see everything.

    python3 bench/packets/prechecks.py --packet R2a --session DIR --minutes 180 --commit SHA [--record FILE]

Every check fails closed (T-105 F5): a command that failed or printed nothing where it always prints something is a problem, never a
clean reading.
"""
import argparse
import datetime
import json
import os
import re
import signal
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.dirname(HERE)
REPO = os.path.dirname(BENCH)
sys.path.insert(0, BENCH)
import calibration as C
import hostcheck as HC

UPTIME_MIN_S = 1800                          # the environment gate's uptime (loadtool_validate.GATE)
DUE_MARGIN_S = 600                           # no apt, dpkg or daily timer due within the packet's length plus 10 min
DUE_UNITS = re.compile(r"apt|dpkg|daily|man-db|logrotate|unattended|fwupd")
JOB_PROGRAMS = re.compile(r"(^|/)(apt|apt-get|aptitude|dpkg|unattended-upgr\S*|unattended-upgrade)(\s|$)")
TESTBED_LEFT = re.compile(r"(^|/)(nginx|gunicorn)(:|\s|$)|loadgen\.py|control_plane\.py")
QUIET_PCT = 5.0                              # no process that is not the testbed's above 5 % of a CPU over a 60-s sample
# the host the programme holds fixed (D2): kernel 7.0.0-42, 8 GiB of guest memory (MemTotal 7,422 MiB), and the PC that runs every
# measurement until 2026-12-03, the laptop (D-096, K10: the CPU model and VirtualBox host version its guest saw at the boot of
# 2026-11-14 11:41Z); R1 is checked against it, every later packet against the session's first step (host.json, K5, K10)
PROGRAMME_HOST = {"uname": "Linux ddos-mitigation 7.0.0-42-generic x86_64", "mem_mib": 7422,
                  "cpu_model": "AMD Ryzen 7 7730U with Radeon Graphics", "vbox_host_version": "7.2.10r174163"}
PACKETS = ("R1", "R2a", "R2b", "R2c", "R3", "R4", "P2-1", "P2-2")
# 5.2's frozen hashes: what the steps run from, by content against the pinned commit (with the frozen record, wherever in the tree)
FROZEN = ("bench", "eval", "nginx.conf", "nginx_unprotected.conf", "control_plane.py", "xdp_ddos_filter.c", "test_distributed_suite.py")
COMMIT_ID = re.compile(r"[0-9a-f]{7,40}")


def check_tree(porcelain, head, commit):
    """The tree is clean (git status --porcelain --untracked-files=no printed nothing, and succeeded: None is a failed command) and
    HEAD is the pinned commit, which a packet must have (--commit). A HEAD that cannot be read is a problem, never a pass (T-105 F5)."""
    if porcelain is None:
        out = ["git status failed: whether the tree is clean cannot be read"]
    else:
        out = [f"uncommitted change: {line.strip()}" for line in porcelain.splitlines() if line.strip()]
    if not commit or not COMMIT_ID.fullmatch(commit):
        out.append(f"no pinned commit ({commit!r}): a packet runs at one (--commit SHA, 7 to 40 hex digits)")
    elif not re.fullmatch(r"[0-9a-f]{40}", head or ""):
        out.append(f"HEAD cannot be read (git printed {(head or '')[:40]!r})")
    elif not head.startswith(commit):
        out.append(f"HEAD is {head[:12]}, the packet is pinned to {commit[:12]}")
    return out


def parse_ls_tree(text):
    """{path: blob id} of `git ls-tree -r COMMIT -- PATH...`; None for a failed command."""
    if text is None:
        return None
    out = {}
    for line in text.splitlines():
        meta, _, path = line.partition("\t")
        fields = meta.split()
        if len(fields) == 3 and fields[1] == "blob" and path:
            out[path] = fields[2]
    return out


def check_frozen(at_commit, here, record=None):
    """5.2's frozen hashes match: every file the pinned commit has under FROZEN (and the frozen record, which must be one of the
    commit's files) hashes here to the commit's blob (`at_commit` from git ls-tree, `here` path -> git hash-object, None where the
    file is missing). Fails closed: a listing that failed or is empty is a problem."""
    if not at_commit:
        return ["git ls-tree of the pinned commit listed nothing: the frozen hashes cannot be read"]
    out = []
    if record is not None and record not in at_commit:
        out.append(f"the record {record} is not a file of the pinned commit: a frozen record is committed before it is used")
    for path, blob in sorted(at_commit.items()):
        got = (here or {}).get(path)
        if got != blob:
            out.append(f"{path} is {'missing' if got is None else got[:12]} here, {blob[:12]} at the pinned commit")
    return out


def check_host(facts, first):
    """The kernel release, MemTotal and the PC (CPU model, VirtualBox host version) are the session's (or, before its first step, the
    programme's): calibration.host_problems."""
    return C.host_problems(first, facts, "the session" if "first_step" in first else "the programme's host (D2, D-096)")


def describe_host(facts):
    """What the host check reports of this host, whether it passes or not: its kernel, MemTotal and PC (K10)."""
    return (f"kernel {C.kernel_release(facts.get('uname'))}, MemTotal {facts.get('mem_mib')} MiB, "
            f"CPU {facts.get('cpu_model') or 'not read'}, VirtualBox host {facts.get('vbox_host_version') or 'not read'}")


def check_uptime(uptime_s):
    return [] if uptime_s >= UPTIME_MIN_S else [f"up {uptime_s:.0f} s, the packet waits for {UPTIME_MIN_S} s"]


def check_chrony(tracking, sources):
    """chrony synchronised within H4's bounds now: `chronyc -n -c tracking` and `chronyc -n -c sources` (hostcheck.rule_clock)."""
    sample = HC.parse_chrony("2000-01-01T00:00:00Z\n" + (tracking or "") + "\n" + (sources or ""))
    if not sample or sample[0]["tracking"] is None:
        return ["chronyc gave no tracking record"]
    t = sample[0]["t"]
    return [r.replace("H4: at 2000-01-01T00:00:00+00:00 ", "") for r in HC.rule_clock(sample, [], t, t)["reasons"]]


def _json_list(text, what):
    """A JSON list a command printed, or (None, the problem): nothing printed, or not a JSON list, is a problem (T-105 F5)."""
    if not (text or "").strip():
        return None, f"{what} printed nothing: it cannot be read"
    try:
        got = json.loads(text)
    except ValueError:
        return None, f"{what} did not print JSON: {text.strip()[:80]!r}"
    return (got, None) if isinstance(got, list) else (None, f"{what} did not print a JSON list")


def check_timers(timers_json, now_s, minutes):
    """No apt, dpkg or daily timer (systemctl list-timers --all --output=json) due within the packet's length plus 10 min."""
    horizon = now_s + 60.0 * minutes + DUE_MARGIN_S
    timers, problem = _json_list(timers_json, "systemctl list-timers")
    if problem:
        return [problem]
    out = []
    for t in timers:
        unit = f"{t.get('unit', '')} {t.get('activates', '')}"
        nxt = t.get("next")
        if DUE_UNITS.search(unit) and nxt and nxt / 1e6 <= horizon:
            when = datetime.datetime.fromtimestamp(nxt / 1e6, datetime.UTC).isoformat(timespec="seconds")
            out.append(f"{t.get('unit')} is due at {when}, within the packet and 10 min")
    return out


def check_jobs(ps_args):
    """No apt or dpkg job runs (ps -eo args=, which always lists itself: nothing printed is a problem)."""
    if not (ps_args or "").strip():
        return ["ps printed nothing: the running jobs cannot be read"]
    return [f"a package job runs: {line.strip()[:120]}" for line in ps_args.splitlines() if JOB_PROGRAMS.search(line.strip())]


def check_testbed_free(netns, ps_args, xdp_progs_json):
    """No namespace, no Nginx, gunicorn, engine or daemon, no XDP program left (ip netns list, ps -eo args=, bpftool -j prog show).
    `ip netns list` prints nothing when there is none (None: it failed); ps and bpftool always print something (bpftool `[]`)."""
    out = ["ip netns list failed: the namespaces cannot be read"] if netns is None else \
        [f"a namespace is left: {line.split()[0]}" for line in netns.splitlines() if line.strip()]
    if not (ps_args or "").strip():
        out.append("ps printed nothing: the processes cannot be read")
    else:
        out += [f"a testbed process is left: {line.strip()[:120]}" for line in ps_args.splitlines() if TESTBED_LEFT.search(line)]
    progs, problem = _json_list(xdp_progs_json, "bpftool -j prog show")
    if problem:
        return [*out, problem]
    out += [f"an XDP program is loaded: id {p.get('id')} {p.get('name')}" for p in progs if isinstance(p, dict) and p.get("type") == "xdp"]
    return out


def check_quiet(pidstat_text):
    """No process that is not the testbed's above 5 % of a CPU over a 60-s sample (pidstat -u -l 60 1; hostcheck.is_testbed). Output
    with no sample in it is a problem (T-105 F5)."""
    samples = HC.parse_pidstat(pidstat_text, interval=60.0)
    if not samples:
        return ["pidstat gave no sample: whether the host is quiet cannot be read"]
    out = []
    for sample in samples:
        for r in sample["rows"]:
            if not HC.is_testbed(r["command"], r["uid"]) and r["cpu_pct"] > QUIET_PCT:
                out.append(f"{r['command'][:80]} (uid {r['uid']}) used {r['cpu_pct']:.1f} % of a CPU")
    return out


# --- on this host ---------------------------------------------------------------------------------------------------------------------

def _sh(argv, timeout=90, stdin=None):
    """What a command printed, or None when it failed (it could not start, timed out or exited non-zero): a failed command is never
    read as empty output (T-105 F5)."""
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False, input=stdin)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout if r.returncode == 0 else None


def frozen_here(git, at_commit):
    """path -> git hash-object of the file here, for the paths of `at_commit` (None where it is missing)."""
    paths = sorted(p for p in (at_commit or {}) if os.path.isfile(os.path.join(REPO, p)))
    got = _sh([*git, "hash-object", "--stdin-paths"], stdin="\n".join(paths) + "\n") if paths else ""
    ids = (got or "").split()
    return dict(zip(paths, ids, strict=True)) if len(ids) == len(paths) else {}


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _facts():
    """This host as executor.RealHost.facts gives it: uname, MemTotal and the PC (the CPU model from /proc/cpuinfo; VirtualBox's host
    version from the boot's kernel log, the journal's, else dmesg's)."""
    uname = " ".join(os.uname())
    mem = next(int(line.split()[1]) // 1024 for line in _read("/proc/meminfo").splitlines() if line.startswith("MemTotal:"))
    vbox = (C.vbox_host_version(_sh(["journalctl", "-k", "-b", "0", "-o", "cat", "--no-pager"]) or "")
            or C.vbox_host_version(_sh(["dmesg"]) or ""))
    return {"uname": uname, "mem_mib": mem, "cpu_model": C.cpu_model(_read("/proc/cpuinfo")), "vbox_host_version": vbox}


def run_all(packet, session, minutes, record=None, commit=None):
    """Every check on this host: (name, reasons) in order."""
    first_path = os.path.join(session, "host.json")
    first = PROGRAMME_HOST
    if os.path.exists(first_path):
        with open(first_path, encoding="utf-8") as fh:
            first = json.load(fh)
    uptime = float(_read("/proc/uptime").split()[0])
    git = ["git", "-c", f"safe.directory={REPO}", "-C", REPO]
    facts = _facts()
    pinned = commit if commit and COMMIT_ID.fullmatch(commit) else None
    at_commit = parse_ls_tree(_sh([*git, "ls-tree", "-r", pinned, "--", *FROZEN])) if pinned else None
    rel = None
    if record:                                  # the record by its path in the repository (outside it: not a file of the commit)
        rel = os.path.relpath(os.path.realpath(record), os.path.realpath(REPO))
        if rel.startswith(".."):
            rel = os.path.abspath(record)
        elif at_commit and rel not in at_commit:
            at_commit.update(parse_ls_tree(_sh([*git, "ls-tree", "-r", pinned, "--", rel])) or {})
    checks = [("tree", check_tree(_sh([*git, "status", "--porcelain", "--untracked-files=no"]),
                                  (_sh([*git, "rev-parse", "HEAD"]) or "").strip(), commit)),
              ("frozen hashes", check_frozen(at_commit, frozen_here(git, at_commit), rel)),
              (f"host ({describe_host(facts)})", check_host(facts, first)),
              ("uptime", check_uptime(uptime)),
              ("chrony", check_chrony(_sh(["chronyc", "-n", "-c", "tracking"]), _sh(["chronyc", "-n", "-c", "sources"]))),
              ("timers", check_timers(_sh(["systemctl", "list-timers", "--all", "--output=json"]),
                                      datetime.datetime.now(datetime.UTC).timestamp(), minutes)),
              ("jobs", check_jobs(_sh(["ps", "-eo", "args="]))),
              ("testbed", check_testbed_free(_sh(["ip", "netns", "list"]), _sh(["ps", "-eo", "args="]),
                                             _sh(["bpftool", "-j", "prog", "show"]))),
              ("quiet", check_quiet(_sh(["pidstat", "-u", "-l", "60", "1"], timeout=120)))]
    if record:
        try:
            C.require_host(C.load(record), facts)
            checks.append(("record", []))
        except (C.RecordError, OSError, ValueError) as exc:
            checks.append(("record", [str(exc)]))
    return checks


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--packet", required=True, choices=PACKETS)
    ap.add_argument("--session", required=True)
    ap.add_argument("--minutes", type=float, default=180.0, help="how late the packet can end: packet.sh's PACKET_MIN (T-117 N-2)")
    ap.add_argument("--record", default=None, help="the frozen record a packet after the freeze uses")
    ap.add_argument("--commit", required=True, help="the pinned commit (a packet runs at one: T-105 F5)")
    args = ap.parse_args(argv)
    bad = 0
    for name, reasons in run_all(args.packet, args.session, args.minutes, args.record, args.commit):
        print(f"{'OK' if not reasons else 'NO'}  {name}" + ("" if not reasons else ": " + "; ".join(reasons)))
        bad += bool(reasons)
    return 0 if not bad else 3


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.default_int_handler)  # a step started by packet.sh (`cmd &`) inherits SIGINT ignored (T-105 F3)
    sys.exit(main())
