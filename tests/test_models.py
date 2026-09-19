import unittest

from ot_risk_lab.models import AnalysisConfig, ControlContext, MitigationContext, RiskModelConfig, ThreatContext


class ModelTests(unittest.TestCase):
    def test_control_combination(self):
        mitigation = MitigationContext(
            controls=(
                ControlContext("A", effectiveness=0.5, coverage=1.0, confidence=1.0, implementation=1.0),
                ControlContext("B", effectiveness=0.5, coverage=1.0, confidence=1.0, implementation=1.0),
            )
        )
        self.assertAlmostEqual(mitigation.effectiveness, 0.75)

    def test_control_implementation_reduces_credit(self):
        full = ControlContext("A", effectiveness=0.8, implementation=1.0)
        partial = ControlContext("A", effectiveness=0.8, implementation=0.25)
        self.assertAlmostEqual(full.effective_strength, 0.8)
        self.assertAlmostEqual(partial.effective_strength, 0.2)

    def test_duplicate_control_ids_rejected(self):
        with self.assertRaises(ValueError):
            MitigationContext(controls=(ControlContext("A", 0.2, control_id="X"), ControlContext("B", 0.3, control_id="X")))

    def test_risk_weights_must_sum_to_one(self):
        with self.assertRaises(ValueError):
            RiskModelConfig(cvss_weight=0.9)

    def test_v01_config_is_migrated(self):
        config = AnalysisConfig.from_mapping(
            {
                "asset": {"name": "PLC", "criticality": 0.8, "internet_exposure": 0.2, "legacy_factor": 0.4},
                "threat": {"cvss": 8.0, "likelihood": 0.5, "impact": 0.7},
                "mitigation": {"effectiveness": 0.2},
            }
        )
        self.assertEqual(config.asset.safety_impact, 0.8)
        self.assertEqual(config.asset.availability_impact, 0.8)
        self.assertEqual(config.threat.name, "Unspecified threat scenario")
        self.assertAlmostEqual(config.mitigation.effectiveness, 0.2)

    def test_epss_can_supply_likelihood(self):
        config = AnalysisConfig.from_mapping(
            {
                "asset": {"name": "PLC", "criticality": 0.8, "safety_impact": 0.8, "availability_impact": 0.8, "internet_exposure": 0.2, "legacy_factor": 0.4},
                "threat": {"name": "CVE scenario", "cvss": 8.0, "impact": 0.7, "epss_probability": 0.22, "likelihood_basis": "epss-30d", "cve_ids": ["CVE-2024-12345"]},
            }
        )
        self.assertAlmostEqual(config.threat.likelihood, 0.22)

    def test_epss_basis_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            ThreatContext(name="x", cvss=8, likelihood=0.2, impact=0.5, epss_probability=0.3, likelihood_basis="epss-30d")

    def test_invalid_cve_rejected(self):
        with self.assertRaises(ValueError):
            ThreatContext(name="x", cvss=8, likelihood=0.2, impact=0.5, cve_ids=("not-a-cve",))

    def test_invalid_attack_technique_rejected(self):
        with self.assertRaises(ValueError):
            ThreatContext(name="x", cvss=8, likelihood=0.2, impact=0.5, techniques=("BAD",))

    def test_invalid_evidence_date_rejected(self):
        with self.assertRaises(ValueError):
            ThreatContext(name="x", cvss=8, likelihood=0.2, impact=0.5, evidence_date="19-09-2026")


if __name__ == "__main__":
    unittest.main()
