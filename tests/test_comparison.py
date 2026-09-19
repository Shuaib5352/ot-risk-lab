import json
import tempfile
from pathlib import Path
import unittest

from ot_risk_lab.cli import main
from ot_risk_lab.comparison import compare_configs
from ot_risk_lab.models import AnalysisConfig


BASE = {
    "asset": {
        "name": "PLC",
        "criticality": 0.9,
        "safety_impact": 0.8,
        "availability_impact": 0.9,
        "internet_exposure": 0.3,
        "legacy_factor": 0.6,
    },
    "threat": {"name": "Scenario", "cvss": 8.8, "likelihood": 0.6, "impact": 0.9},
    "simulation": {"iterations": 200, "uncertainty": 0.05, "seed": 7},
}


class ComparisonTests(unittest.TestCase):
    def test_candidate_control_reduces_risk(self):
        candidate = json.loads(json.dumps(BASE))
        candidate["mitigation"] = {
            "controls": [{"name": "Segmentation", "effectiveness": 0.6, "coverage": 0.9, "confidence": 0.9}]
        }
        result = compare_configs(AnalysisConfig.from_mapping(BASE), AnalysisConfig.from_mapping(candidate))
        metric = result["metrics"]["residual_risk"]
        self.assertLess(metric["after"], metric["before"])
        self.assertGreater(metric["relative_reduction_percent"], 0)

    def test_cli_compare_and_template(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline = root / "before.json"
            candidate = root / "after.json"
            template = root / "template.json"
            report = root / "compare.md"
            baseline.write_text(json.dumps(BASE), encoding="utf-8")
            changed = json.loads(json.dumps(BASE))
            changed["mitigation"] = {"manual_effectiveness": 0.5}
            candidate.write_text(json.dumps(changed), encoding="utf-8")
            self.assertEqual(main(["compare", str(baseline), str(candidate), "--format", "markdown", "-o", str(report)]), 0)
            self.assertIn("# OT-RiskLab Scenario Comparison", report.read_text(encoding="utf-8"))
            self.assertEqual(main(["template", "-o", str(template)]), 0)
            self.assertIn("asset", json.loads(template.read_text(encoding="utf-8")))
