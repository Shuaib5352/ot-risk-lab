import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from ot_risk_lab.cli import main

CONFIG = {
    "metadata": {"assessment_id": "TEST-001"},
    "asset": {
        "name": "Demo PLC",
        "asset_type": "PLC",
        "zone": "Process",
        "criticality": 0.9,
        "safety_impact": 0.85,
        "availability_impact": 0.95,
        "internet_exposure": 0.15,
        "legacy_factor": 0.5,
    },
    "threat": {
        "name": "Remote compromise",
        "cvss": 8.8,
        "likelihood": 0.6,
        "impact": 0.9,
        "techniques": ["T0886"],
    },
    "mitigation": {
        "controls": [
            {
                "name": "Segmentation",
                "control_id": "C-1",
                "effectiveness": 0.5,
                "coverage": 0.9,
                "confidence": 0.8,
                "implementation": 1.0,
                "csf_function": "PROTECT",
                "evidence": "Test evidence",
            }
        ]
    },
    "simulation": {"iterations": 200, "uncertainty": 0.05, "seed": 42, "markov_steps": 12},
    "decision": {"risk_tolerance": 20.0},
}


class CliTests(unittest.TestCase):
    def test_analyze_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.json"
            output_path = Path(tmp) / "report.json"
            config_path.write_text(json.dumps(CONFIG), encoding="utf-8")
            code = main(["analyze", str(config_path), "--output", str(output_path)])
            self.assertEqual(code, 0)
            report = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(report["software"]["version"], "0.7.0")
            self.assertIn("decision_support", report)

    def test_markdown_and_html_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.json"
            markdown = Path(tmp) / "report.md"
            html = Path(tmp) / "report.html"
            config_path.write_text(json.dumps(CONFIG), encoding="utf-8")
            self.assertEqual(main(["analyze", str(config_path), "--format", "markdown", "-o", str(markdown)]), 0)
            self.assertIn("# OT-RiskLab Analysis Report", markdown.read_text(encoding="utf-8"))
            self.assertEqual(main(["analyze", str(config_path), "--format", "html", "-o", str(html)]), 0)
            self.assertIn("<!doctype html>", html.read_text(encoding="utf-8").lower())

    def test_validate_text_and_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.json"
            config_path.write_text(json.dumps(CONFIG), encoding="utf-8")
            self.assertEqual(main(["validate", str(config_path)]), 0)
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                self.assertEqual(main(["validate", str(config_path), "--format", "json"]), 0)
            payload = json.loads(stream.getvalue())
            self.assertTrue(payload["valid"])

    def test_strict_validate_returns_three_on_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.json"
            data = json.loads(json.dumps(CONFIG))
            data["threat"]["cisa_kev"] = True
            config_path.write_text(json.dumps(data), encoding="utf-8")
            self.assertEqual(main(["validate", str(config_path), "--strict"]), 3)

    def test_batch_csv_and_html(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            (folder / "a.json").write_text(json.dumps(CONFIG), encoding="utf-8")
            second = json.loads(json.dumps(CONFIG))
            second["asset"]["name"] = "Demo HMI"
            (folder / "b.json").write_text(json.dumps(second), encoding="utf-8")
            csv_path = folder / "portfolio.csv"
            html_path = folder / "portfolio.html"
            self.assertEqual(main(["batch", str(folder), "--format", "csv", "-o", str(csv_path)]), 0)
            self.assertIn("tolerance_status", csv_path.read_text(encoding="utf-8"))
            self.assertEqual(main(["batch", str(folder), "--format", "html", "-o", str(html_path)]), 0)
            self.assertIn("OT-RiskLab Portfolio", html_path.read_text(encoding="utf-8"))

    def test_register_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            (folder / "a.json").write_text(json.dumps(CONFIG), encoding="utf-8")
            output = folder / "register.csv"
            self.assertEqual(main(["register", str(folder), "--format", "csv", "-o", str(output)]), 0)
            self.assertIn("risk_id", output.read_text(encoding="utf-8"))

    def test_template(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "template.json"
            self.assertEqual(main(["template", "-o", str(output)]), 0)
            data = json.loads(output.read_text(encoding="utf-8"))
            self.assertIn("decision", data)
            self.assertIn("implementation", data["mitigation"]["controls"][0])

    def test_ablate_calibrate_benchmark_and_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = root / "config.json"
            config_path.write_text(json.dumps(CONFIG), encoding="utf-8")

            ablation = root / "ablation.json"
            self.assertEqual(main(["ablate", str(config_path), "-o", str(ablation)]), 0)
            self.assertIn("controls", json.loads(ablation.read_text(encoding="utf-8")))

            observations = root / "observations.csv"
            observations.write_text("predicted_probability,observed\n0.1,0\n0.8,1\n", encoding="utf-8")
            calibration = root / "calibration.json"
            self.assertEqual(main(["calibrate", str(observations), "--bins", "2", "-o", str(calibration)]), 0)
            self.assertIn("brier_score", json.loads(calibration.read_text(encoding="utf-8")))

            expected = json.loads((root / "ablation.json").read_text(encoding="utf-8"))["residual_risk"]
            manifest = root / "bench.json"
            manifest.write_text(json.dumps({
                "cases": [{
                    "name": "cli",
                    "config": "config.json",
                    "expected": {"deterministic.residual_risk": expected}
                }]
            }), encoding="utf-8")
            benchmark = root / "benchmark.json"
            self.assertEqual(main(["benchmark", str(manifest), "-o", str(benchmark)]), 0)
            self.assertTrue(json.loads(benchmark.read_text(encoding="utf-8"))["passed"])

            provenance = root / "provenance.json"
            self.assertEqual(main(["provenance", str(config_path), "-o", str(provenance)]), 0)
            self.assertIn("model_signature_sha256", json.loads(provenance.read_text(encoding="utf-8")))

    def test_study_agreement_manifest_and_bundle_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            study = root / "study.csv"
            study.write_text(
                "record_id,site,timestamp,subgroup,predicted_probability,observed\n"
                "a,A,2026-01-01T00:00:00Z,PLC,0.1,0\n"
                "b,A,2026-02-01T00:00:00Z,HMI,0.3,0\n"
                "c,B,2026-03-01T00:00:00Z,PLC,0.7,1\n"
                "d,B,2026-04-01T00:00:00Z,HMI,0.9,1\n",
                encoding="utf-8",
            )
            study_out = root / "study.json"
            self.assertEqual(
                main([
                    "study", str(study), "--bootstrap", "100", "--bins", "2",
                    "--split-mode", "site-disjoint", "--evaluation-sites", "B", "-o", str(study_out),
                ]),
                0,
            )
            self.assertTrue(json.loads(study_out.read_text(encoding="utf-8"))["split"]["site_disjoint_valid"])

            ratings = root / "ratings.csv"
            ratings.write_text(
                "item_id,analyst,rating\n1,A,High\n1,B,High\n2,A,Low\n2,B,Low\n",
                encoding="utf-8",
            )
            agreement = root / "agreement.json"
            self.assertEqual(main(["agreement", str(ratings), "--bootstrap", "100", "-o", str(agreement)]), 0)
            self.assertAlmostEqual(json.loads(agreement.read_text(encoding="utf-8"))["krippendorff_alpha_nominal"], 1.0)

            manifest = root / "manifest.json"
            self.assertEqual(
                main(["manifest", str(study), "--base-dir", str(root), "--parameter", "split=site", "-o", str(manifest)]),
                0,
            )
            verify = root / "verify.json"
            self.assertEqual(main(["verify-manifest", str(manifest), "--base-dir", str(root), "-o", str(verify)]), 0)
            self.assertTrue(json.loads(verify.read_text(encoding="utf-8"))["passed"])

            bundle = root / "supplement.zip"
            self.assertEqual(main(["supplement", str(study), str(ratings), "-o", str(bundle)]), 0)
            bundle_verify = root / "bundle-verify.json"
            self.assertEqual(main(["verify-bundle", str(bundle), "-o", str(bundle_verify)]), 0)
            self.assertTrue(json.loads(bundle_verify.read_text(encoding="utf-8"))["passed"])


if __name__ == "__main__":
    unittest.main()
