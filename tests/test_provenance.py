import unittest

from ot_risk_lab.models import AnalysisConfig
from ot_risk_lab.provenance import deterministic_provenance, model_signature

RAW = {
    "asset": {"name": "PLC", "criticality": 0.8, "safety_impact": 0.8, "availability_impact": 0.8, "internet_exposure": 0.2, "legacy_factor": 0.4},
    "threat": {"name": "Scenario", "cvss": 8.0, "likelihood": 0.4, "impact": 0.8},
    "simulation": {"iterations": 100, "uncertainty": 0.0}
}


class ProvenanceTests(unittest.TestCase):
    def test_signature_is_deterministic(self):
        config = AnalysisConfig.from_mapping(RAW)
        self.assertEqual(model_signature(config), model_signature(config))
        payload = deterministic_provenance(config)
        self.assertEqual(payload["software"]["version"], "0.7.0")
        self.assertEqual(len(payload["model_signature_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
