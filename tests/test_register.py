import unittest

from ot_risk_lab.models import AnalysisConfig
from ot_risk_lab.register import build_risk_register, render_risk_register_csv, render_risk_register_markdown


def cfg(name: str, likelihood: float) -> AnalysisConfig:
    return AnalysisConfig.from_mapping(
        {
            "metadata": {"assessment_id": f"ID-{name}"},
            "asset": {"name": name, "criticality": 0.8, "safety_impact": 0.7, "availability_impact": 0.8, "internet_exposure": 0.2, "legacy_factor": 0.3},
            "threat": {"name": "Scenario", "cvss": 8.0, "likelihood": likelihood, "impact": 0.8},
            "simulation": {"iterations": 100, "uncertainty": 0.0},
            "decision": {"risk_tolerance": 15.0},
        }
    )


class RegisterTests(unittest.TestCase):
    def test_register_sorted_by_residual_risk(self):
        result = build_risk_register([("low", cfg("low", 0.2)), ("high", cfg("high", 0.8))])
        self.assertEqual(result["risks"][0]["asset"], "high")
        self.assertEqual(result["summary"]["risk_count"], 2)

    def test_register_renderers(self):
        result = build_risk_register([("one", cfg("asset", 0.4))])
        self.assertIn("risk_id", render_risk_register_csv(result))
        self.assertIn("# OT-RiskLab Risk Register", render_risk_register_markdown(result))

    def test_empty_register_rejected(self):
        with self.assertRaises(ValueError):
            build_risk_register([])


if __name__ == "__main__":
    unittest.main()
