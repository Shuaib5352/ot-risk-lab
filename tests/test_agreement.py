from pathlib import Path
import tempfile
import unittest

from ot_risk_lab.agreement import RatingRecord, agreement_diagnostics, load_ratings_csv


class AgreementTests(unittest.TestCase):
    def test_perfect_agreement_is_one(self):
        rows = [
            RatingRecord("1", "A", "High"), RatingRecord("1", "B", "High"),
            RatingRecord("2", "A", "Low"), RatingRecord("2", "B", "Low"),
        ]
        result = agreement_diagnostics(rows, bootstrap=100, seed=1)
        self.assertAlmostEqual(result["krippendorff_alpha_nominal"], 1.0)
        self.assertAlmostEqual(result["pairwise_agreement"], 1.0)

    def test_disagreement_reduces_alpha(self):
        rows = [
            RatingRecord("1", "A", "High"), RatingRecord("1", "B", "Low"),
            RatingRecord("2", "A", "Low"), RatingRecord("2", "B", "High"),
        ]
        result = agreement_diagnostics(rows, bootstrap=100, seed=2)
        self.assertLess(result["krippendorff_alpha_nominal"], 0.0)
        self.assertEqual(result["pairwise_agreement"], 0.0)

    def test_load_csv_rejects_duplicate_analyst_item(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ratings.csv"
            path.write_text("item_id,analyst,rating\n1,A,High\n1,A,Low\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_ratings_csv(path)


if __name__ == "__main__":
    unittest.main()
