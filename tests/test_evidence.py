import unittest

from ot_risk_lab.evidence import vulnerability_evidence
from ot_risk_lab.models import AnalysisConfig

RAW = {
    "asset": {"name": "PLC", "criticality": 0.8, "safety_impact": 0.8, "availability_impact": 0.8, "internet_exposure": 0.2, "legacy_factor": 0.4},
    "threat": {"name": "Scenario", "cvss": 8.2, "likelihood": 0.15, "impact": 0.8, "cve_ids": ["CVE-2024-12345"], "epss_probability": 0.15, "epss_percentile": 0.92, "cisa_kev": True, "evidence_date": "2026-09-19", "likelihood_basis": "epss-30d"},
    "simulation": {"iterations": 100, "uncertainty": 0.0},
}


class EvidenceTests(unittest.TestCase):
    def test_evidence_preserves_distinct_signals(self):
        evidence = vulnerability_evidence(AnalysisConfig.from_mapping(RAW))
        self.assertTrue(evidence["cisa_kev"])
        self.assertEqual(evidence["epss_probability_30d"], 0.15)
        self.assertIn("confirmed-exploitation-cisa-kev", evidence["workflow_flags"])
        self.assertIn("epss-30d-forecast-available", evidence["workflow_flags"])


if __name__ == "__main__":
    unittest.main()
