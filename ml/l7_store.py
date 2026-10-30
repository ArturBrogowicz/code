"""The P3 dataset store (docs/P3_DATASET_DESIGN.md §4.5, D-D1): raw captures live outside git and outside the
purged /var/tmp, by default under /home/artur/datasets/l7/<version>/<capture_id>/, with one SHA256SUMS per
version that covers every file.

Rules this module keeps:
  * it creates directories and files, and never deletes anything except the staging directory it created
    itself with tempfile.mkdtemp, and only after every staged log was copied and its hash verified;
  * a capture directory is never reused (os.makedirs without exist_ok);
  * the gzip output is deterministic (no name, mtime 0), so the same log always gives the same bytes;
  * the capture runs as root, so hand_back() returns the files to the owner of the store directory, which
    the user creates beforehand.
Standard library only.
"""
import gzip
import hashlib
import os
import re
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import l7_dataset

DEFAULT_STORE = "/home/artur/datasets/l7"
SUMS = "SHA256SUMS"
STAGING_PREFIX = ".staging-"
SUMS_LINE = re.compile(r"^([0-9a-f]{64})  (\S.*)$")


class StoreError(ValueError):
    """A store path is refused, or a stored file does not match its recorded hash."""


def refused_roots(repo):
    """Where raw data must never go: the purged temporary trees and the git checkout."""
    return ("/var/tmp", "/tmp", "/dev/shm", repo)


def _under(path, root):
    path, root = os.path.realpath(path), os.path.realpath(root)
    return path == root or path.startswith(root.rstrip("/") + "/")


def version_dir(store, version, refused):
    """The absolute <store>/<version> directory, refused under any of `refused`."""
    if not l7_dataset.VERSION_RE.match(str(version)):
        raise StoreError(f"dataset version {version!r} is not <yyyy-mm>-<tag>")
    path = os.path.join(os.path.abspath(store), version)
    for root in refused:
        if root and _under(path, root):
            raise StoreError(f"refused: {path} is under {root} (purged or in git); use the dataset store")
    return path


def capture_id(seed, started_struct):
    return f"s{int(seed)}-{started_struct.tm_year:04d}{started_struct.tm_mon:02d}{started_struct.tm_mday:02d}T" \
           f"{started_struct.tm_hour:02d}{started_struct.tm_min:02d}{started_struct.tm_sec:02d}Z"


def make_capture_dir(vdir, cid):
    """Create <vdir>/<cid> (refusing an existing one) and a staging directory inside it. Returns both."""
    os.makedirs(vdir, exist_ok=True)
    path = os.path.join(vdir, cid)
    os.makedirs(path)
    return path, tempfile.mkdtemp(prefix=STAGING_PREFIX, dir=path)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def gzip_file(src, dst):
    """Deterministic gzip of src into dst (no file name, mtime 0, level 9)."""
    with open(src, "rb") as fin, open(dst, "xb") as raw, \
            gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as out:
        shutil.copyfileobj(fin, out, 1 << 20)


def finalize_logs(staging, capture_dir, names=("access.log", "error.log")):
    """Gzip each staged log into the capture directory, check that the copy decompresses to the staged
    bytes, and only then remove the staging directory. An absent log is recorded as an empty one.
    Returns the l7_dataset.file_record of each .gz. On a mismatch it raises and keeps the staging copy."""
    if not (os.path.basename(staging).startswith(STAGING_PREFIX)
            and os.path.dirname(os.path.abspath(staging)) == os.path.abspath(capture_dir)):
        raise StoreError(f"{staging} is not a staging directory of {capture_dir}")
    recs = []
    for name in names:
        raw = os.path.join(staging, name)
        if not os.path.exists(raw):
            open(raw, "wb").close()
        dst = os.path.join(capture_dir, name + ".gz")
        gzip_file(raw, dst)
        rec = l7_dataset.file_record(dst, name + ".gz")
        if rec["content_sha256"] != sha256_file(raw):
            raise StoreError(f"{dst} does not decompress to the staged {raw}; staging kept")
        recs.append(rec)
    shutil.rmtree(staging)                      # this run's own mkdtemp, every copy verified above
    return recs


def _walk(vdir):
    for dirpath, dirnames, filenames in os.walk(vdir):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
        for f in sorted(filenames):
            if f.startswith(".") or (os.path.abspath(dirpath) == os.path.abspath(vdir) and f == SUMS):
                continue
            yield os.path.relpath(os.path.join(dirpath, f), vdir)


def write_sha256sums(vdir):
    """(Re)write <vdir>/SHA256SUMS over every file below it (hidden entries and itself excluded), sorted
    by path; written beside it first and then renamed over it. Returns its path."""
    rows = sorted((rel, sha256_file(os.path.join(vdir, rel))) for rel in _walk(vdir))
    tmp = os.path.join(vdir, "." + SUMS + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.writelines(f"{sha}  {rel}\n" for rel, sha in rows)
    os.replace(tmp, os.path.join(vdir, SUMS))
    return os.path.join(vdir, SUMS)


def read_sha256sums(vdir):
    out = {}
    with open(os.path.join(vdir, SUMS), encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            m = SUMS_LINE.match(line.rstrip("\n"))
            if not m:
                raise StoreError(f"{SUMS}:{n}: not '<sha256>  <path>'")
            out[m.group(2)] = m.group(1)
    return out


def sha256sums_problems(vdir):
    """Every mismatch between <vdir>/SHA256SUMS and the files: a missing SHA256SUMS, a listed file that is
    missing or differs, and a file that is not listed. Empty when everything matches."""
    if not os.path.isfile(os.path.join(vdir, SUMS)):
        return [f"{SUMS} missing in {vdir}"]
    try:
        listed = read_sha256sums(vdir)
    except StoreError as exc:
        return [str(exc)]
    probs = []
    for rel, sha in sorted(listed.items()):
        path = os.path.join(vdir, rel)
        if not os.path.isfile(path):
            probs.append(f"{rel}: listed but missing")
        elif sha256_file(path) != sha:
            probs.append(f"{rel}: sha256 differs from {SUMS}")
    probs += [f"{rel}: not listed in {SUMS}" for rel in _walk(vdir) if rel not in listed]
    return probs


def store_owner(store):
    """(uid, gid) of the existing store directory; the capture refuses a store the user did not create."""
    if not os.path.isdir(store):
        raise StoreError(f"{store} does not exist: create it as the user first (mkdir -p {store})")
    st = os.stat(store)
    return st.st_uid, st.st_gid


def hand_back(path, uid, gid):
    """chown every directory and file below `path` (and path) to uid:gid when running as root.
    Returns how many entries were changed (0 when not root)."""
    if os.geteuid() != 0:
        return 0
    n = 0
    for dirpath, _dirnames, filenames in os.walk(path):
        for p in [dirpath] + [os.path.join(dirpath, f) for f in filenames]:
            os.chown(p, uid, gid)
            n += 1
    return n
