from __future__ import annotations

import csv
import io

from .models import AnalysisConfig
from .report import SOFTWARE_VERSION, analyze


def build_risk_register(named_configs: list[tuple[str, AnalysisConfig]]) -> dict[str, object]:
    if not named_configs:
        raise ValueError("risk register requires at least one scenario")
    items: list[dict[str, object]] = []
    for source, config in named_configs:
        result = analyze(config)
        det = result["deterministic"]
        mc = result["monte_carlo"]
        decision = result["decision_support"]
        evidence = result["vulnerability_evidence"]
        decomposition = det["decomposition"]
        posture = result["control_posture"]
        fingerprint = str(result["config_fingerprint_sha256"])
        items.append(
            {
                "risk_id": config.metadata.assessment_id or fingerprint[:12],
                "source": source,
                "asset": config.asset.name,
                "asset_type": config.asset.asset_type,
                "zone": config.asset.zone,
                "threat": config.threat.name,
                "cve_ids": ";".join(evidence["cve_ids"]),
                "cisa_kev": evidence["cisa_kev"],
                "epss_probability": evidence["epss_probability_30d"],
                "likelihood_basis": evidence["likelihood_basis"],
                "inherent_risk": det["inherent_risk"],
                "residual_risk": det["residual_risk"],
                "p95": mc["p95"],
                "risk_tolerance": decision["risk_tolerance"],
                "tolerance_status": decision["deterministic_status"],
                "probability_above_tolerance": decision["probability_above_tolerance"],
                "top_vulnerability_driver": decomposition["top_vulnerability_driver"],
                "top_consequence_driver": decomposition["top_consequence_driver"],
                "missing_csf_functions": ";".join(posture["missing_functions"]),
                "warning_count": len(result["quality_warnings"]),
                "fingerprint": fingerprint,
            }
        )
    items.sort(key=lambda x: (-float(x["residual_risk"]), str(x["asset"])))
    return {
        "schema_version": "1.0",
        "software": {"name": "OT-RiskLab", "version": SOFTWARE_VERSION},
        "summary": {
            "risk_count": len(items),
            "above_tolerance_count": sum(x["tolerance_status"] == "above-tolerance" for x in items),
            "kev_linked_count": sum(bool(x["cisa_kev"]) for x in items),
        },
        "risks": items,
    }


def render_risk_register_csv(result: dict[str, object]) -> str:
    fields = [
        "risk_id", "source", "asset", "asset_type", "zone", "threat", "cve_ids", "cisa_kev",
        "epss_probability", "likelihood_basis", "inherent_risk", "residual_risk", "p95", "risk_tolerance",
        "tolerance_status", "probability_above_tolerance", "top_vulnerability_driver", "top_consequence_driver",
        "missing_csf_functions", "warning_count", "fingerprint",
    ]
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for item in result["risks"]:
        writer.writerow({field: item[field] for field in fields})
    return output.getvalue()


def render_risk_register_markdown(result: dict[str, object]) -> str:
    lines = [
        "# OT-RiskLab Risk Register",
        "",
        f"Risks: **{result['summary']['risk_count']}** · Above tolerance: **{result['summary']['above_tolerance_count']}** · KEV-linked: **{result['summary']['kev_linked_count']}**",
        "",
        "| ID | Asset | Threat | Residual | P95 | Tolerance | KEV | CVEs |",
        "|---|---|---|---:|---:|---|---|---|",
    ]
    for x in result["risks"]:
        lines.append(
            f"| {x['risk_id']} | {x['asset']} | {x['threat']} | {x['residual_risk']:.3f} | {x['p95']:.3f} | "
            f"{x['tolerance_status']} | {'yes' if x['cisa_kev'] else 'no'} | {x['cve_ids'] or '—'} |"
        )
    return "\n".join(lines) + "\n"
