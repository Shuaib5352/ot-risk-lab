from __future__ import annotations

import csv
import io
from html import escape
from statistics import fmean

from .models import AnalysisConfig
from .report import SOFTWARE_VERSION, analyze


def analyze_portfolio(named_configs: list[tuple[str, AnalysisConfig]]) -> dict[str, object]:
    if not named_configs:
        raise ValueError("portfolio requires at least one scenario")
    scenarios: list[dict[str, object]] = []
    residual_scores: list[float] = []
    p95_scores: list[float] = []
    compromise_scores: list[float] = []
    above_tolerance = 0
    kev_count = 0
    for source, config in named_configs:
        result = analyze(config)
        deterministic = result["deterministic"]
        mc = result["monte_carlo"]
        attack = result["attack_progression"]
        evidence = result["vulnerability_evidence"]
        decision = result["decision_support"]
        residual = float(deterministic["residual_risk"])
        p95 = float(mc["p95"])
        compromise = float(attack["compromise_probability"])
        residual_scores.append(residual)
        p95_scores.append(p95)
        compromise_scores.append(compromise)
        if decision["deterministic_status"] == "above-tolerance":
            above_tolerance += 1
        if evidence["cisa_kev"]:
            kev_count += 1
        scenarios.append(
            {
                "source": source,
                "asset": config.asset.name,
                "asset_type": config.asset.asset_type,
                "zone": config.asset.zone,
                "threat": config.threat.name,
                "cve_ids": ";".join(config.threat.cve_ids),
                "epss_probability": config.threat.epss_probability,
                "cisa_kev": config.threat.cisa_kev,
                "inherent_risk": deterministic["inherent_risk"],
                "residual_risk": residual,
                "residual_band": deterministic["residual_band"],
                "monte_carlo_p95": p95,
                "compromise_probability": compromise,
                "mitigation_effectiveness": deterministic["mitigation_effectiveness"],
                "risk_tolerance": decision["risk_tolerance"],
                "tolerance_status": decision["deterministic_status"],
                "probability_above_tolerance": decision["probability_above_tolerance"],
                "warning_count": len(result["quality_warnings"]),
                "config_fingerprint_sha256": result["config_fingerprint_sha256"],
            }
        )
    scenarios.sort(key=lambda item: (-float(item["residual_risk"]), str(item["asset"])))
    return {
        "schema_version": "2.0",
        "software": {"name": "OT-RiskLab", "version": SOFTWARE_VERSION},
        "summary": {
            "scenario_count": len(scenarios),
            "mean_residual_risk": fmean(residual_scores),
            "mean_p95": fmean(p95_scores),
            "mean_compromise_probability": fmean(compromise_scores),
            "maximum_residual_risk": max(residual_scores),
            "minimum_residual_risk": min(residual_scores),
            "highest_risk_asset": scenarios[0]["asset"],
            "highest_risk_threat": scenarios[0]["threat"],
            "above_tolerance_count": above_tolerance,
            "cisa_kev_scenario_count": kev_count,
        },
        "scenarios": scenarios,
    }


def render_portfolio_markdown(result: dict[str, object]) -> str:
    summary = result["summary"]
    scenarios = result["scenarios"]
    lines = [
        "# OT-RiskLab Portfolio Report",
        "",
        f"Scenarios analyzed: **{summary['scenario_count']}**",
        "",
        "| Asset | Threat | Residual | Band | P95 | Compromise | Tolerance | KEV |",
        "|---|---|---:|---|---:|---:|---|---|",
    ]
    for item in scenarios:
        lines.append(
            f"| {item['asset']} | {item['threat']} | {item['residual_risk']:.3f} | {item['residual_band']} | "
            f"{item['monte_carlo_p95']:.3f} | {item['compromise_probability']:.3f} | {item['tolerance_status']} | "
            f"{'yes' if item['cisa_kev'] else 'no'} |"
        )
    lines.extend(
        [
            "",
            f"Mean residual risk: **{summary['mean_residual_risk']:.3f}**  ",
            f"Mean P95: **{summary['mean_p95']:.3f}**  ",
            f"Mean compromise probability: **{summary['mean_compromise_probability']:.3f}**  ",
            f"Above-tolerance scenarios: **{summary['above_tolerance_count']}**  ",
            f"CISA KEV-linked scenarios: **{summary['cisa_kev_scenario_count']}**  ",
            f"Range: **{summary['minimum_residual_risk']:.3f}–{summary['maximum_residual_risk']:.3f}**  ",
            f"Highest modeled residual-risk scenario: **{summary['highest_risk_asset']} / {summary['highest_risk_threat']}**",
            "",
        ]
    )
    return "\n".join(lines)


def render_portfolio_csv(result: dict[str, object]) -> str:
    output = io.StringIO(newline="")
    fields = [
        "source", "asset", "asset_type", "zone", "threat", "cve_ids", "epss_probability", "cisa_kev",
        "inherent_risk", "residual_risk", "residual_band", "monte_carlo_p95", "compromise_probability",
        "mitigation_effectiveness", "risk_tolerance", "tolerance_status", "probability_above_tolerance",
        "warning_count", "config_fingerprint_sha256",
    ]
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for item in result["scenarios"]:
        writer.writerow({field: item[field] for field in fields})
    return output.getvalue()


def render_portfolio_html(result: dict[str, object]) -> str:
    summary = result["summary"]
    rows = "".join(
        "<tr>"
        f"<td>{escape(str(x['asset']))}</td><td>{escape(str(x['threat']))}</td><td>{x['residual_risk']:.3f}</td>"
        f"<td>{x['monte_carlo_p95']:.3f}</td><td>{x['compromise_probability']:.3f}</td>"
        f"<td>{escape(str(x['tolerance_status']))}</td><td>{'yes' if x['cisa_kev'] else 'no'}</td></tr>"
        for x in result["scenarios"]
    )
    return f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>OT-RiskLab Portfolio</title><style>body{{font-family:system-ui,sans-serif;max-width:1100px;margin:auto;padding:30px;color:#17202a}}table{{border-collapse:collapse;width:100%}}th,td{{padding:9px;border-bottom:1px solid #d7dde3;text-align:left}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}}.card{{border:1px solid #d7dde3;border-radius:9px;padding:14px}}</style></head><body>
<h1>OT-RiskLab Portfolio Report</h1><div class='grid'><div class='card'><strong>Scenarios</strong><br>{summary['scenario_count']}</div><div class='card'><strong>Mean residual risk</strong><br>{summary['mean_residual_risk']:.3f}</div><div class='card'><strong>Above tolerance</strong><br>{summary['above_tolerance_count']}</div><div class='card'><strong>KEV-linked</strong><br>{summary['cisa_kev_scenario_count']}</div></div>
<h2>Scenarios</h2><table><thead><tr><th>Asset</th><th>Threat</th><th>Residual</th><th>P95</th><th>Compromise</th><th>Tolerance</th><th>KEV</th></tr></thead><tbody>{rows}</tbody></table></body></html>"""
