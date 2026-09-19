import unittest

from ot_risk_lab.models import AnalysisConfig
from ot_risk_lab.posture import control_posture, model_quality_warnings

BASE = {
    "asset": {"name": "PLC", "criticality": 0.8, "safety_impact": 0.5, "availability_impact": 0.7, "internet_exposure": 0.2, "legacy_factor": 0.4},
    "threat": {"name": "Scenario", "cvss": 8.0, "likelihood": 0.5, "impact": 0.8},
    "simulation": {"iterations": 100, "uncertainty": 0.1},
}


class PostureTests(unittest.TestCase):
    def test_control_posture_tracks_functions(self):
        raw = {**BASE, "mitigation": {"controls": [{"name": "Segmentation", "effectiveness": 0.5, "csf_function": "PROTECT"}, {"name": "Monitoring", "effectiveness": 0.4, "csf_function": "DETECT"}]}}
        posture = control_posture(AnalysisConfig.from_mapping(raw))
        self.assertIn("PROTECT", posture["represented_functions"])
        self.assertIn("GOVERN", posture["missing_functions"])
        self.assertEqual(posture["represented_count"], 2)

    def test_quality_warning_for_low_confidence(self):
        raw = {**BASE, "mitigation": {"controls": [{"name": "Uncertain control", "effectiveness": 0.5, "confidence": 0.3}]}}
        codes = {x["code"] for x in model_quality_warnings(AnalysisConfig.from_mapping(raw))}
        self.assertIn("LOW_CONTROL_CONFIDENCE", codes)

    def test_partial_implementation_and_missing_evidence_warnings(self):
        raw = {**BASE, "mitigation": {"controls": [{"name": "Control", "effectiveness": 0.9, "coverage": 1.0, "confidence": 1.0, "implementation": 0.4}]}}
        codes = {x["code"] for x in model_quality_warnings(AnalysisConfig.from_mapping(raw))}
        self.assertIn("PARTIAL_HIGH_EFFECT_CONTROL", codes)
        self.assertIn("CONTROL_EVIDENCE_MISSING", codes)

    def test_kev_and_tolerance_warnings(self):
        raw = {**BASE, "threat": {**BASE["threat"], "cisa_kev": True}, "decision": {"risk_tolerance": 1.0}}
        codes = {x["code"] for x in model_quality_warnings(AnalysisConfig.from_mapping(raw))}
        self.assertIn("CISA_KEV_CONFIRMED_EXPLOITATION", codes)
        self.assertIn("DETERMINISTIC_RISK_ABOVE_TOLERANCE", codes)


if __name__ == "__main__":
    unittest.main()
