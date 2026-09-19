from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .version import SOFTWARE_VERSION

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class EvidenceSourceError(RuntimeError):
    pass


def _normalize_cves(cve_ids: list[str] | tuple[str, ...]) -> list[str]:
    normalized: list[str] = []
    for value in cve_ids:
        cve = str(value).upper().strip()
        if not _CVE_RE.fullmatch(cve):
            raise ValueError(f"invalid CVE identifier: {value}")
        if cve not in normalized:
            normalized.append(cve)
    if not normalized:
        raise ValueError("at least one CVE identifier is required")
    if len(normalized) > 50:
        raise ValueError("a maximum of 50 CVE identifiers may be enriched in one request")
    return normalized


def _request_json(url: str, timeout: float, headers: dict[str, str] | None = None) -> dict[str, Any]:
    request_headers = {
        "Accept": "application/json",
        "User-Agent": f"OT-RiskLab/{SOFTWARE_VERSION} (+https://github.com/Shuaib5352/ot-risk-lab)",
    }
    if headers:
        request_headers.update(headers)
    request = Request(url, headers=request_headers)
    try:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed HTTPS sources
            payload = json.load(response)
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise EvidenceSourceError(f"failed to retrieve {url}: {exc}") from exc
    if not isinstance(payload, dict):
        raise EvidenceSourceError(f"unexpected non-object JSON payload from {url}")
    return payload


def parse_epss_payload(payload: dict[str, Any]) -> dict[str, dict[str, object]]:
    output: dict[str, dict[str, object]] = {}
    for row in payload.get("data", []):
        if not isinstance(row, dict) or not row.get("cve"):
            continue
        cve = str(row["cve"]).upper()
        output[cve] = {
            "epss_probability": float(row["epss"]),
            "epss_percentile": float(row["percentile"]),
            "epss_date": row.get("date") or row.get("created"),
        }
    return output


def parse_kev_payload(payload: dict[str, Any], wanted: set[str] | None = None) -> dict[str, dict[str, object]]:
    output: dict[str, dict[str, object]] = {}
    for row in payload.get("vulnerabilities", []):
        if not isinstance(row, dict) or not row.get("cveID"):
            continue
        cve = str(row["cveID"]).upper()
        if wanted is not None and cve not in wanted:
            continue
        output[cve] = {
            "cisa_kev": True,
            "kev_date_added": row.get("dateAdded"),
            "kev_due_date": row.get("dueDate"),
            "kev_vendor_project": row.get("vendorProject"),
            "kev_product": row.get("product"),
            "kev_required_action": row.get("requiredAction"),
            "kev_known_ransomware_campaign_use": row.get("knownRansomwareCampaignUse"),
        }
    return output


def _preferred_cvss(metrics: dict[str, Any]) -> dict[str, object] | None:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key) or []
        if not rows:
            continue
        primary = next((row for row in rows if row.get("type") == "Primary"), rows[0])
        data = primary.get("cvssData") or {}
        if "baseScore" in data:
            return {
                "cvss_version": data.get("version"),
                "cvss_base_score": float(data["baseScore"]),
                "cvss_vector": data.get("vectorString"),
                "cvss_severity": data.get("baseSeverity") or primary.get("baseSeverity"),
                "cvss_source": primary.get("source"),
            }
    return None


def parse_nvd_payload(payload: dict[str, Any]) -> dict[str, object]:
    vulnerabilities = payload.get("vulnerabilities") or []
    if not vulnerabilities:
        return {}
    cve = vulnerabilities[0].get("cve") or {}
    descriptions = cve.get("descriptions") or []
    english = next((item.get("value") for item in descriptions if item.get("lang") == "en"), None)
    output: dict[str, object] = {
        "cve": cve.get("id"),
        "nvd_status": cve.get("vulnStatus"),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "description": english,
    }
    cvss = _preferred_cvss(cve.get("metrics") or {})
    if cvss:
        output.update(cvss)
    if cve.get("cisaExploitAdd"):
        output.update(
            {
                "nvd_cisa_kev": True,
                "nvd_cisa_exploit_add": cve.get("cisaExploitAdd"),
                "nvd_cisa_action_due": cve.get("cisaActionDue"),
                "nvd_cisa_required_action": cve.get("cisaRequiredAction"),
            }
        )
    return output


def collect_vulnerability_evidence(
    cve_ids: list[str] | tuple[str, ...],
    *,
    include_epss: bool = True,
    include_kev: bool = True,
    include_nvd: bool = True,
    timeout: float = 15.0,
    nvd_api_key: str | None = None,
    strict_sources: bool = False,
) -> dict[str, object]:
    """Retrieve public vulnerability evidence from authoritative sources.

    Network enrichment is intentionally separate from deterministic risk
    analysis. Source failures are reported per source by default so temporary
    API/network problems are not mistaken for negative evidence. Set
    ``strict_sources=True`` to fail on the first unavailable source.
    """
    cves = _normalize_cves(cve_ids)
    if not any((include_epss, include_kev, include_nvd)):
        raise ValueError("at least one evidence source must be enabled")
    records = {cve: {"cve": cve, "cisa_kev": False} for cve in cves}
    source_status: list[dict[str, object]] = []

    def source_error(source: str, url: str, exc: EvidenceSourceError) -> None:
        if strict_sources:
            raise exc
        source_status.append({"source": source, "url": url, "status": "error", "error": str(exc)})

    if include_epss:
        try:
            query = urlencode({"cve": ",".join(cves)})
            payload = _request_json(f"{EPSS_URL}?{query}", timeout)
            parsed = parse_epss_payload(payload)
            for cve, values in parsed.items():
                if cve in records:
                    records[cve].update(values)
            source_status.append({"source": "FIRST EPSS", "url": EPSS_URL, "status": "ok"})
        except EvidenceSourceError as exc:
            source_error("FIRST EPSS", EPSS_URL, exc)

    if include_kev:
        try:
            payload = _request_json(CISA_KEV_URL, timeout)
            parsed = parse_kev_payload(payload, set(cves))
            for cve, values in parsed.items():
                records[cve].update(values)
            source_status.append({"source": "CISA KEV", "url": CISA_KEV_URL, "status": "ok"})
        except EvidenceSourceError as exc:
            source_error("CISA KEV", CISA_KEV_URL, exc)

    if include_nvd:
        api_key = nvd_api_key or os.getenv("NVD_API_KEY")
        headers = {"apiKey": api_key} if api_key else None
        nvd_errors: list[str] = []
        successful = 0
        for cve in cves:
            try:
                query = urlencode({"cveId": cve})
                payload = _request_json(f"{NVD_URL}?{query}", timeout, headers=headers)
                records[cve].update(parse_nvd_payload(payload))
                successful += 1
            except EvidenceSourceError as exc:
                if strict_sources:
                    raise
                nvd_errors.append(f"{cve}: {exc}")
        status = "ok" if not nvd_errors else "partial" if successful else "error"
        source_row: dict[str, object] = {
            "source": "NVD CVE API 2.0",
            "url": NVD_URL,
            "status": status,
            "api_key_used": bool(api_key),
            "successful_records": successful,
        }
        if nvd_errors:
            source_row["errors"] = nvd_errors
        source_status.append(source_row)

    complete = all(source["status"] == "ok" for source in source_status)
    return {
        "retrieved_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "complete": complete,
        "records": [records[cve] for cve in cves],
        "sources": source_status,
        "note": (
            "External evidence is returned separately from risk scoring. Review applicability and freshness before "
            "using it in an assessment; CVSS, EPSS, and KEV express different concepts and are not interchangeable. "
            "A source error means evidence was unavailable, not that the vulnerability lacks that signal."
        ),
    }


def render_evidence_markdown(result: dict[str, object]) -> str:
    lines = [
        "# OT-RiskLab Vulnerability Evidence",
        "",
        f"Retrieved: **{result['retrieved_at_utc']}**",
        "",
        "| CVE | CVSS | EPSS | EPSS pct. | KEV | Published |",
        "|---|---:|---:|---:|---|---|",
    ]
    for row in result["records"]:
        lines.append(
            f"| {row['cve']} | {row.get('cvss_base_score', 'n/a')} | {row.get('epss_probability', 'n/a')} | "
            f"{row.get('epss_percentile', 'n/a')} | {'yes' if row.get('cisa_kev') or row.get('nvd_cisa_kev') else 'no'} | "
            f"{row.get('published', 'n/a')} |"
        )
    lines.extend(["", str(result["note"]), "", "## Sources", ""])
    for source in result["sources"]:
        lines.append(f"- {source['source']}: {source['url']} ({source['status']})")
    lines.append("")
    return "\n".join(lines)
