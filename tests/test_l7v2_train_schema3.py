"""train_l7 on L7 v2 (schema-3) captures: the default selection rule (T-030 L7V2-06). Offline: fixture captures are
written under temporary directories."""
import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "ml"), os.path.join(REPO, "tests")):
    sys.path.insert(0, _p)
import test_l7_manifest_v3 as V3
import train_l7 as T


class DefaultSelectionTest(unittest.TestCase):
    def test_a_schema_three_capture_gets_validation_only_selection(self):
        with tempfile.TemporaryDirectory() as root:
            d, m = V3.capture_v3(root, V3.reuse_entities()[0])
            self.assertEqual(m["schema"], 3)
            self.assertEqual(T.default_selection([d]), "val")


if __name__ == "__main__":
    unittest.main()
