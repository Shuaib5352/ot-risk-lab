import json
from pathlib import Path
import tempfile
import unittest

from ot_risk_lab.manifest import build_experiment_manifest, verify_experiment_manifest


class ManifestTests(unittest.TestCase):
    def test_manifest_detects_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = root / "data.csv"
            data.write_text("x\n1\n", encoding="utf-8")
            manifest = build_experiment_manifest([data], base_dir=root, parameters={"split": "site"})
            path = root / "manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            self.assertTrue(verify_experiment_manifest(path, base_dir=root)["passed"])
            data.write_text("x\n2\n", encoding="utf-8")
            self.assertFalse(verify_experiment_manifest(path, base_dir=root)["passed"])


if __name__ == "__main__":
    unittest.main()
