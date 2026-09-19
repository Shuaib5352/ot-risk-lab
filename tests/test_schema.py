import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from ot_risk_lab.cli import main
from ot_risk_lab.schema import analysis_config_schema


class SchemaTests(unittest.TestCase):
    def test_bundled_schema_matches_repository_schema(self):
        bundled = analysis_config_schema()
        root = Path(__file__).resolve().parents[1]
        repository = json.loads((root / "schemas/analysis-config.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(bundled, repository)
        self.assertEqual(bundled["type"], "object")

    def test_schema_cli_prints_and_writes_json(self):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            self.assertEqual(main(["schema"]), 0)
        self.assertEqual(json.loads(stream.getvalue())["type"], "object")

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "schema.json"
            self.assertEqual(main(["schema", "-o", str(output)]), 0)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["type"], "object")


if __name__ == "__main__":
    unittest.main()
