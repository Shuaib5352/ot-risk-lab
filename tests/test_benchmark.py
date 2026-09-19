import json
from pathlib import Path
import tempfile
import unittest

from ot_risk_lab.benchmark import run_benchmark_manifest


CONFIG = {
    "asset": {"name": "PLC", "criticality": 0.8, "safety_impact": 0.8, "availability_impact": 0.8, "internet_exposure": 0.2, "legacy_factor": 0.4},
    "threat": {"name": "Scenario", "cvss": 8.0, "likelihood": 0.4, "impact": 0.8},
    "simulation": {"iterations": 100, "uncertainty": 0.0, "markov_steps": 4}
}


class BenchmarkTests(unittest.TestCase):
    def test_manifest_pass_and_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config.json").write_text(json.dumps(CONFIG), encoding="utf-8")
            manifest = {
                "suite": "unit",
                "absolute_tolerance": 1e-9,
                "cases": [{"name": "case", "config": "config.json", "expected": {"deterministic.residual_risk": 17.28}}],
            }
            path = root / "benchmark.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            result = run_benchmark_manifest(path)
            self.assertTrue(result["passed"])
            manifest["cases"][0]["expected"]["deterministic.residual_risk"] = 99.0
            path.write_text(json.dumps(manifest), encoding="utf-8")
            self.assertFalse(run_benchmark_manifest(path)["passed"])


if __name__ == "__main__":
    unittest.main()
