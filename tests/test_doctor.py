import contextlib
import io
import json
import unittest

from ot_risk_lab.cli import main
from ot_risk_lab.doctor import runtime_diagnostics


class DoctorTests(unittest.TestCase):
    def test_offline_diagnostics_pass(self):
        result = runtime_diagnostics()
        self.assertTrue(result["passed"])
        self.assertFalse(result["network_checks_performed"])
        self.assertGreaterEqual(len(result["checks"]), 4)

    def test_doctor_cli_json(self):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            self.assertEqual(main(["doctor", "--format", "json"]), 0)
        result = json.loads(stream.getvalue())
        self.assertTrue(result["passed"])
        self.assertEqual(result["software_version"], "0.7.0")


if __name__ == "__main__":
    unittest.main()
