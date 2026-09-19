import unittest

from ot_risk_lab.models import AnalysisConfig
from ot_risk_lab.monte_carlo import run_monte_carlo

RAW = {
    "asset": {"name": "PLC", "criticality": 0.9, "safety_impact": 0.8, "availability_impact": 0.9, "internet_exposure": 0.2, "legacy_factor": 0.6},
    "threat": {"name": "Scenario", "cvss": 8.8, "likelihood": 0.6, "impact": 0.9},
    "mitigation": {"manual_effectiveness": 0.2},
    "simulation": {"iterations": 600, "uncertainty": 0.08, "seed": 7},
}


class MonteCarloTests(unittest.TestCase):
    def test_reproducible(self):
        config = AnalysisConfig.from_mapping(RAW)
        self.assertEqual(run_monte_carlo(config).as_dict(), run_monte_carlo(config).as_dict())

    def test_quantiles_are_ordered(self):
        result = run_monte_carlo(AnalysisConfig.from_mapping(RAW))
        self.assertLessEqual(result.minimum, result.p05)
        self.assertLessEqual(result.p05, result.p50)
        self.assertLessEqual(result.p50, result.p95)
        self.assertLessEqual(result.p95, result.maximum)

    def test_sensitivity_is_bounded_and_sorted(self):
        result = run_monte_carlo(AnalysisConfig.from_mapping(RAW))
        influence = [abs(x.spearman_rho) for x in result.sensitivity]
        self.assertEqual(influence, sorted(influence, reverse=True))
        self.assertTrue(all(-1.0 <= x.spearman_rho <= 1.0 for x in result.sensitivity))

    def test_triangular_distribution(self):
        raw = {**RAW, "simulation": {"iterations": 300, "uncertainty": 0.1, "seed": 1, "distribution": "triangular"}}
        result = run_monte_carlo(AnalysisConfig.from_mapping(raw))
        self.assertEqual(result.distribution, "triangular")

    def test_tolerance_exceedance(self):
        raw = {**RAW, "decision": {"risk_tolerance": 5.0}}
        result = run_monte_carlo(AnalysisConfig.from_mapping(raw))
        self.assertIsNotNone(result.probability_above_tolerance)
        self.assertGreaterEqual(result.probability_above_tolerance, 0.0)
        self.assertLessEqual(result.probability_above_tolerance, 1.0)
        self.assertGreaterEqual(result.mean_excess_above_tolerance, 0.0)

    def test_no_tolerance_leaves_exceedance_unset(self):
        result = run_monte_carlo(AnalysisConfig.from_mapping(RAW))
        self.assertIsNone(result.probability_above_tolerance)


if __name__ == "__main__":
    unittest.main()
