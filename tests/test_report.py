import unittest

from ot_risk_lab.models import AnalysisConfig
from ot_risk_lab.report import analyze, config_fingerprint, render_html, render_markdown


RAW = {
    "metadata": {"assessment_id": "R-1", "scope": "unit test"},
    "asset": {"name": "PLC", "asset_type": "PLC", "zone": "Z1", "criticality": 0.9, "safety_impact": 0.8, "availability_impact": 0.9, "internet_exposure": 0.2, "legacy_factor": 0.4},
    "threat": {"name": "Scenario", "cvss": 8.0, "likelihood": 0.4, "impact": 0.8, "techniques": ["T0886"]},
    "mitigation": {"controls": [{"name": "Segmentation", "effectiveness": 0.5, "coverage": 0.9, "confidence": 0.8, "implementation": 1.0, "evidence": "reviewed"}]},
    "simulation": {"iterations": 150, "uncertainty": 0.05, "seed": 4},
    "decision": {"risk_tolerance": 10.0, "tolerance_label": "test"},
}


class ReportTests(unittest.TestCase):
    def test_report_contains_decision_and_evidence(self):
        result = analyze(AnalysisConfig.from_mapping(RAW))
        self.assertEqual(result["schema_version"], "4.0")
        self.assertIn("decision_support", result)
        self.assertIn("vulnerability_evidence", result)

    def test_fingerprint_is_stable(self):
        config = AnalysisConfig.from_mapping(RAW)
        self.assertEqual(config_fingerprint(config), config_fingerprint(config))
        self.assertEqual(len(config_fingerprint(config)), 64)

    def test_markdown_and_html_escape_user_content(self):
        raw = {**RAW, "asset": {**RAW["asset"], "name": "PLC <unsafe>"}}
        result = analyze(AnalysisConfig.from_mapping(raw))
        self.assertIn("PLC <unsafe>", render_markdown(result))
        html = render_html(result)
        self.assertIn("PLC &lt;unsafe&gt;", html)
        self.assertNotIn("PLC <unsafe>", html)


if __name__ == "__main__":
    unittest.main()
