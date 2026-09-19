import unittest

import ot_risk_lab


class PublicApiTests(unittest.TestCase):
    def test_legacy_top_level_exports_remain_available(self):
        expected = [
            "AnalysisConfig",
            "AssetContext",
            "ThreatContext",
            "baseline_risk",
            "residual_risk",
            "run_monte_carlo",
            "simulate_attack_progression",
        ]
        for name in expected:
            self.assertTrue(hasattr(ot_risk_lab, name), name)
        self.assertEqual(ot_risk_lab.__version__, "0.7.0")


if __name__ == "__main__":
    unittest.main()
