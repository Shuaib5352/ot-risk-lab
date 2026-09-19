import unittest
from unittest.mock import patch

from ot_risk_lab.evidence_sources import (
    EvidenceSourceError,
    collect_vulnerability_evidence,
    parse_epss_payload,
    parse_kev_payload,
    parse_nvd_payload,
)


class EvidenceSourceTests(unittest.TestCase):
    def test_parse_epss(self):
        result = parse_epss_payload({"data": [{"cve": "CVE-2024-12345", "epss": "0.42", "percentile": "0.91", "date": "2026-09-19"}]})
        self.assertEqual(result["CVE-2024-12345"]["epss_probability"], 0.42)

    def test_parse_kev(self):
        payload = {"vulnerabilities": [{"cveID": "CVE-2024-12345", "dateAdded": "2026-01-01", "requiredAction": "Patch"}]}
        result = parse_kev_payload(payload, {"CVE-2024-12345"})
        self.assertTrue(result["CVE-2024-12345"]["cisa_kev"])

    def test_parse_nvd_prefers_cvss31(self):
        payload = {"vulnerabilities": [{"cve": {"id": "CVE-2024-12345", "vulnStatus": "Analyzed", "descriptions": [{"lang": "en", "value": "demo"}], "metrics": {"cvssMetricV31": [{"type": "Primary", "source": "nvd@nist.gov", "cvssData": {"version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/..."}}]}}}]}
        result = parse_nvd_payload(payload)
        self.assertEqual(result["cvss_base_score"], 9.8)
        self.assertEqual(result["cvss_version"], "3.1")


class EvidenceResilienceTests(unittest.TestCase):
    def test_parse_missing_nvd_is_empty(self):
        self.assertEqual(parse_nvd_payload({"vulnerabilities": []}), {})

    def test_collect_merges_sources_without_scoring(self):
        epss = {"data": [{"cve": "CVE-2024-12345", "epss": "0.42", "percentile": "0.91", "date": "2026-09-19"}]}
        kev = {"vulnerabilities": [{"cveID": "CVE-2024-12345", "dateAdded": "2026-01-01"}]}
        nvd = {"vulnerabilities": [{"cve": {"id": "CVE-2024-12345", "metrics": {"cvssMetricV31": [{"type": "Primary", "source": "nvd@nist.gov", "cvssData": {"version": "3.1", "baseScore": 9.8}}]}}}]}

        def fake_request(url, timeout, headers=None):
            if "api.first.org" in url:
                return epss
            if "cisa.gov" in url:
                return kev
            return nvd

        with patch("ot_risk_lab.evidence_sources._request_json", side_effect=fake_request):
            result = collect_vulnerability_evidence(["CVE-2024-12345"])
        row = result["records"][0]
        self.assertTrue(result["complete"])
        self.assertEqual(row["epss_probability"], 0.42)
        self.assertTrue(row["cisa_kev"])
        self.assertEqual(row["cvss_base_score"], 9.8)

    def test_collect_reports_partial_source_failure(self):
        def fake_request(url, timeout, headers=None):
            if "cisa.gov" in url:
                raise EvidenceSourceError("blocked")
            if "api.first.org" in url:
                return {"data": []}
            return {"vulnerabilities": []}

        with patch("ot_risk_lab.evidence_sources._request_json", side_effect=fake_request):
            result = collect_vulnerability_evidence(["CVE-2024-12345"])
        self.assertFalse(result["complete"])
        status = {row["source"]: row["status"] for row in result["sources"]}
        self.assertEqual(status["CISA KEV"], "error")
        self.assertEqual(status["FIRST EPSS"], "ok")

    def test_strict_sources_raises(self):
        with patch("ot_risk_lab.evidence_sources._request_json", side_effect=EvidenceSourceError("offline")):
            with self.assertRaises(EvidenceSourceError):
                collect_vulnerability_evidence(["CVE-2024-12345"], strict_sources=True)


if __name__ == "__main__":
    unittest.main()
