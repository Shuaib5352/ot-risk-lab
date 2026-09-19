import tempfile
import unittest
from pathlib import Path

from ot_risk_lab.calibration import calibration_diagnostics, load_calibration_csv


class CalibrationTests(unittest.TestCase):
    def test_perfect_predictions_have_zero_brier(self):
        result = calibration_diagnostics([(0.0, 0), (1.0, 1), (0.0, 0), (1.0, 1)], bins=4)
        self.assertEqual(result["brier_score"], 0.0)
        self.assertEqual(result["expected_calibration_error"], 0.0)

    def test_worse_predictions_have_positive_loss(self):
        result = calibration_diagnostics([(0.9, 0), (0.1, 1)], bins=2)
        self.assertGreater(result["brier_score"], 0.5)
        self.assertGreater(result["log_loss"], 1.0)

    def test_load_csv_probabilities(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "obs.csv"
            path.write_text("predicted_probability,observed\n0.2,0\n0.8,1\n", encoding="utf-8")
            self.assertEqual(load_calibration_csv(path), [(0.2, 0), (0.8, 1)])


if __name__ == "__main__":
    unittest.main()
