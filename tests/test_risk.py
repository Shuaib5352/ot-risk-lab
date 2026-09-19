import unittest

from ot_risk_lab.models import AssetContext, MitigationContext, RiskModelConfig, ThreatContext
from ot_risk_lab.risk import baseline_risk, consequence_component, residual_risk, vulnerability_component


class RiskTests(unittest.TestCase):
    def setUp(self):
        self.asset = AssetContext(
            name="PLC-1",
            asset_type="PLC",
            zone="Level 1",
            criticality=0.9,
            safety_impact=0.8,
            availability_impact=0.95,
            internet_exposure=0.2,
            legacy_factor=0.6,
        )
        self.threat = ThreatContext(name="Remote service compromise", cvss=8.8, likelihood=0.6, impact=0.9)
        self.model = RiskModelConfig()

    def test_components_are_bounded(self):
        self.assertTrue(0 <= vulnerability_component(self.asset, self.threat, self.model) <= 1)
        self.assertTrue(0 <= consequence_component(self.asset, self.threat, self.model) <= 1)

    def test_risk_is_bounded(self):
        self.assertTrue(0 <= baseline_risk(self.asset, self.threat, self.model) <= 100)

    def test_mitigation_is_monotone(self):
        inherent = baseline_risk(self.asset, self.threat, self.model)
        residual = residual_risk(self.asset, self.threat, MitigationContext(manual_effectiveness=0.4), self.model)
        self.assertLess(residual, inherent)
        self.assertAlmostEqual(residual, inherent * 0.6)


if __name__ == "__main__":
    unittest.main()
