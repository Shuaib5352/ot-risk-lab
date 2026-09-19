import unittest

from ot_risk_lab.markov import simulate_attack_progression, transition_matrix


class MarkovTests(unittest.TestCase):
    def test_rows_sum_to_one(self):
        matrix = transition_matrix(0.5)
        for row in matrix:
            self.assertAlmostEqual(sum(row), 1.0)

    def test_probability_is_conserved(self):
        result = simulate_attack_progression(0.5, 12)
        for row in result.history:
            self.assertAlmostEqual(sum(row), 1.0)

    def test_more_risk_means_more_compromise(self):
        low = simulate_attack_progression(0.1, 24).compromise_probability
        high = simulate_attack_progression(0.9, 24).compromise_probability
        self.assertGreater(high, low)

    def test_expected_compromise_step_is_in_horizon(self):
        result = simulate_attack_progression(0.5, 24)
        self.assertIsNotNone(result.expected_compromise_step_within_horizon)
        self.assertGreaterEqual(result.expected_compromise_step_within_horizon, 1)
        self.assertLessEqual(result.expected_compromise_step_within_horizon, 24)


if __name__ == "__main__":
    unittest.main()
