import tempfile
import unittest
from pathlib import Path

from ot_risk_lab.bundle import build_supplement_bundle, verify_supplement_bundle


class BundleTests(unittest.TestCase):
    def test_bundle_is_deterministic_and_verifiable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder = root / "study"
            folder.mkdir()
            (folder / "a.txt").write_text("alpha\n", encoding="utf-8")
            (folder / "b.txt").write_text("beta\n", encoding="utf-8")
            first = root / "one.zip"
            second = root / "two.zip"
            build_supplement_bundle([folder], first, label="test")
            build_supplement_bundle([folder], second, label="test")
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertTrue(verify_supplement_bundle(first)["passed"])

    def test_bundle_excludes_development_residue(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder = root / "study"
            folder.mkdir()
            (folder / "keep.txt").write_text("ok", encoding="utf-8")
            cache = folder / "__pycache__"
            cache.mkdir()
            (cache / "bad.pyc").write_bytes(b"x")
            out = root / "bundle.zip"
            result = build_supplement_bundle([folder], out)
            self.assertEqual(result["files"], 1)

    def test_bundle_rejects_reserved_metadata_filename(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reserved = root / "MANIFEST.json"
            reserved.write_text("{}", encoding="utf-8")
            with self.assertRaises(ValueError):
                build_supplement_bundle([reserved], root / "bundle.zip")


if __name__ == "__main__":
    unittest.main()
