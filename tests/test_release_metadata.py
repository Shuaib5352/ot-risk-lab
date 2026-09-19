import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class ReleaseMetadataTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parents[1]

    def test_release_consistency_script(self):
        result = subprocess.run(
            [sys.executable, str(self.root / "scripts/release_check.py")],
            cwd=self.root,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS", result.stdout)

    def test_codemeta_and_sbom_version(self):
        codemeta = json.loads((self.root / "codemeta.json").read_text(encoding="utf-8"))
        self.assertEqual(codemeta["version"], "0.7.0")
        self.assertEqual(codemeta["@context"], "https://w3id.org/codemeta/3.1")

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "sbom.json"
            result = subprocess.run(
                [sys.executable, str(self.root / "scripts/generate_sbom.py"), str(output)],
                cwd=self.root,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            sbom = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(sbom["bomFormat"], "CycloneDX")
            self.assertEqual(sbom["metadata"]["component"]["version"], "0.7.0")


if __name__ == "__main__":
    unittest.main()
