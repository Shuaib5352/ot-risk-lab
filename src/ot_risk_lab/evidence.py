from __future__ import annotations

from .models import AnalysisConfig


def vulnerability_evidence(config: AnalysisConfig) -> dict[str, object]:
    """Return vulnerability evidence without converting it into an opaque score.

    EPSS is retained as a 30-day exploitation probability and CISA KEV as a
    confirmed-exploitation indicator. Neither is multiplied by CVSS.
    """
    threat = config.threat
    flags: list[str] = []
    if threat.cisa_kev:
        flags.append("confirmed-exploitation-cisa-kev")
    if threat.epss_probability is not None:
        flags.append("epss-30d-forecast-available")
    if threat.cve_ids:
        flags.append("cve-linked")

    return {
        "cve_ids": list(threat.cve_ids),
        "cvss_base_score": threat.cvss,
        "epss_probability_30d": threat.epss_probability,
        "epss_percentile": threat.epss_percentile,
        "cisa_kev": threat.cisa_kev,
        "evidence_date": threat.evidence_date,
        "likelihood_basis": threat.likelihood_basis,
        "workflow_flags": flags,
        "interpretation": (
            "EPSS is treated as a forward-looking exploitation probability, while CISA KEV is a confirmed-"
            "exploitation signal. These are preserved as separate evidence fields rather than multiplied by CVSS."
        ),
    }
