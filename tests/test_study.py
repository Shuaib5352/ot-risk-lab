from pathlib import Path
import tempfile
import unittest

from ot_risk_lab.study import (
    StudyRecord,
    bootstrap_metric_intervals,
    evaluate_study,
    load_study_csv,
    site_disjoint_split,
    temporal_split,
)


class StudyTests(unittest.TestCase):
    def setUp(self):
        self.records = [
            StudyRecord("a1", 0.1, 0, "A", "2026-01-01T00:00:00Z", "PLC"),
            StudyRecord("a2", 0.3, 0, "A", "2026-02-01T00:00:00Z", "HMI"),
            StudyRecord("b1", 0.6, 1, "B", "2026-03-01T00:00:00Z", "PLC"),
            StudyRecord("b2", 0.8, 1, "B", "2026-04-01T00:00:00Z", "HMI"),
        ]

    def test_bootstrap_is_reproducible(self):
        one = bootstrap_metric_intervals(self.records, repetitions=100, seed=9, bins=2)
        two = bootstrap_metric_intervals(self.records, repetitions=100, seed=9, bins=2)
        self.assertEqual(one, two)
        self.assertLessEqual(one["brier_score"]["lower"], one["brier_score"]["estimate"])
        self.assertGreaterEqual(one["brier_score"]["upper"], one["brier_score"]["estimate"])

    def test_site_bootstrap_is_reproducible(self):
        one = bootstrap_metric_intervals(self.records, repetitions=100, seed=3, bins=2, unit="site")
        two = bootstrap_metric_intervals(self.records, repetitions=100, seed=3, bins=2, unit="site")
        self.assertEqual(one, two)

    def test_temporal_split(self):
        dev, test, details = temporal_split(self.records, "2026-03-01T00:00:00Z")
        self.assertEqual(len(dev), 2)
        self.assertEqual(len(test), 2)
        self.assertTrue(details["temporal_order_valid"])

    def test_site_disjoint_split(self):
        dev, test, details = site_disjoint_split(self.records, ["B"])
        self.assertEqual({r.site for r in dev}, {"A"})
        self.assertEqual({r.site for r in test}, {"B"})
        self.assertTrue(details["site_disjoint_valid"])
        self.assertEqual(details["site_overlap"], [])

    def test_evaluate_study_has_held_out_metrics(self):
        result = evaluate_study(
            self.records,
            bins=2,
            bootstrap=100,
            split_mode="site-disjoint",
            evaluation_sites=["B"],
            group_by="site",
        )
        self.assertIn("evaluation", result)
        self.assertEqual(result["evaluation"]["n"], 2)
        self.assertEqual(len(result["subgroups"]["groups"]), 2)

    def test_site_bootstrap_reports_unavailable_for_single_site_partition(self):
        result = evaluate_study(
            self.records,
            bins=2,
            bootstrap=100,
            split_mode="site-disjoint",
            evaluation_sites=["B"],
            group_by="none",
            bootstrap_unit="site",
        )
        self.assertIsNone(result["evaluation"]["bootstrap_intervals"])
        self.assertIn("fewer than two sites", result["evaluation"]["bootstrap_note"])

    def test_load_study_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "study.csv"
            path.write_text(
                "record_id,site,timestamp,subgroup,predicted_probability,observed\n"
                "r1,A,2026-01-01T00:00:00Z,PLC,0.2,0\n"
                "r2,B,2026-02-01T00:00:00Z,HMI,0.8,1\n",
                encoding="utf-8",
            )
            records = load_study_csv(path)
            self.assertEqual(len(records), 2)
            self.assertEqual(records[1].site, "B")


if __name__ == "__main__":
    unittest.main()
