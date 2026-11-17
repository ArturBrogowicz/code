"""T-132: two calibration records (JSON) compared field by field: every leaf path whose value differs, with both values; numbers
compared exactly. Also the record hash of the first with created_utc set to the second's (calibration.digest, the code under REPO).
usage: python -I -B compare_records.py REPO A.json B.json"""
import json
import os
import sys

REPO, A, B = sys.argv[1:4]
sys.path.insert(0, os.path.join(REPO, "bench"))
import calibration as C  # noqa: E402


def leaves(x, path=""):
    if isinstance(x, dict):
        for k in sorted(x):
            yield from leaves(x[k], f"{path}.{k}" if path else k)
    elif isinstance(x, list):
        for i, v in enumerate(x):
            yield from leaves(v, f"{path}[{i}]")
    else:
        yield path, x


a = json.load(open(A, encoding="utf-8"))
b = json.load(open(B, encoding="utf-8"))
la, lb = dict(leaves(a)), dict(leaves(b))
diff = sorted(k for k in set(la) | set(lb) if la.get(k, "<absent>") != lb.get(k, "<absent>"))
print(f"A {A}\nB {B}\nleaves: A {len(la)}, B {len(lb)}; differing: {len(diff)}")
for k in diff:
    print(f"  {k}: A {la.get(k, '<absent>')!r}  B {lb.get(k, '<absent>')!r}")
c = dict(a)
c["created_utc"] = b["created_utc"]
c.pop("sha256", None)
print(f"A's digest with created_utc set to B's ({b['created_utc']}): {C.digest(c)}; B's sha256 field: {b.get('sha256')}; "
      f"equal: {C.digest(c) == b.get('sha256')}")
