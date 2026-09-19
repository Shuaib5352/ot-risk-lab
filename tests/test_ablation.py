import unittest

from ot_risk_lab.ablation import run_ablation
from ot_risk_lab.models import AnalysisConfig

RAW = {
    "asset": {"name": "PLC", "criticality": 0.8, "safety_impact": 0.9, "availability_impact": 0.9, "internet_exposure": 0.4, "legacy_factor": 0.5},
    "threat": {"name": "Remote compromise", "cvss": 9.0, "likelihood": 0.5, "impact": 0.8},
    "mitigation": {"controls": [
        {"name": "Segmentation", "effectiveness": 0.6, "coverage": 0.8, "confidence": 0.9, "implementation": 1.0},
        {"name": "Monitoring", "effectiveness": 0.3, "coverage": 0.7, "confidence": 0.8, "implementation": 0.9, "csf_function": "DETECT"}
    ]},
    "simulation": {"iterations": 100, "uncertainty": 0.0}
}


class AblationTests(unittest.TestCase):
    def test_removing_controls_increases_residual_risk(self):
        result = run_ablation(AnalysisConfig.from_mapping(RAW))
        self.assertGreater(result["risk_without_any_mitigation"], result["residual_risk"])
        self.assertEqual(len(result["controls"]), 2)
        self.assertTrue(all(row["absolute_risk_increase_if_removed"] > 0 for row in result["controls"]))

    def test_factor_ablation_is_nonnegative(self):
        result = run_ablation(AnalysisConfig.from_mapping(RAW))
        self.assertTrue(all(row["absolute_inherent_reduction"] >= 0 for row in result["factors"]))
        self.assertEqual(result["factors"][0]["factor"], "threat_likelihood")


if __name__ == "__main__":
    unittest.main()
