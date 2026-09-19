from __future__ import annotations

from html import escape

from .evidence import vulnerability_evidence
from .markov import simulate_attack_progression
from .models import AnalysisConfig
from .monte_carlo import run_monte_carlo
from .posture import control_posture, model_quality_warnings
from .risk import baseline_risk, qualitative_band, residual_risk, risk_decomposition
from .provenance import config_fingerprint, deterministic_provenance
from .version import OUTPUT_SCHEMA_VERSION, SOFTWARE_VERSION


def _decision_support(config: AnalysisConfig, residual: float, mc: dict[str, object]) -> dict[str, object]:
    tolerance = config.decision.risk_tolerance
    if tolerance is None:
        status = "unconfigured"
    elif residual > tolerance:
        status = "above-tolerance"
    else:
        status = "within-tolerance"
    return {
        "risk_tolerance": tolerance,
        "tolerance_label": config.decision.tolerance_label,
        "deterministic_status": status,
        "probability_above_tolerance": mc.get("probability_above_tolerance"),
        "mean_excess_above_tolerance": mc.get("mean_excess_above_tolerance"),
        "note": "Tolerance is organization-defined and is not a NIST/IEC threshold.",
    }


def analyze(config: AnalysisConfig) -> dict[str, object]:
    inherent = baseline_risk(config.asset, config.threat, config.risk_model)
    residual = residual_risk(config.asset, config.threat, config.mitigation, config.risk_model)
    mc_result = run_monte_carlo(config)
    mc = mc_result.as_dict()
    markov = simulate_attack_progression(residual / 100.0, config.simulation.markov_steps, config.markov)
    return {
        "schema_version": OUTPUT_SCHEMA_VERSION,
        "software": {"name": "OT-RiskLab", "version": SOFTWARE_VERSION},
        "config_fingerprint_sha256": config_fingerprint(config),
        "provenance": deterministic_provenance(config),
        "metadata": {
            "assessment_id": config.metadata.assessment_id,
            "analyst": config.metadata.analyst,
            "organization": config.metadata.organization,
            "scope": config.metadata.scope,
            "notes": list(config.metadata.notes),
        },
        "scenario": {
            "asset": config.asset.name,
            "asset_type": config.asset.asset_type,
            "zone": config.asset.zone,
            "threat": config.threat.name,
            "attack_techniques": list(config.threat.techniques),
        },
        "vulnerability_evidence": vulnerability_evidence(config),
        "deterministic": {
            "inherent_risk": inherent,
            "inherent_band": qualitative_band(inherent),
            "residual_risk": residual,
            "residual_band": qualitative_band(residual),
            "mitigation_effectiveness": config.mitigation.effectiveness,
            "decomposition": risk_decomposition(config.asset, config.threat, config.risk_model),
        },
        "decision_support": _decision_support(config, residual, mc),
        "control_posture": control_posture(config),
        "quality_warnings": model_quality_warnings(config),
        "controls": [
            {
                "name": c.name,
                "control_id": c.control_id,
                "csf_function": c.csf_function,
                "effectiveness": c.effectiveness,
                "coverage": c.coverage,
                "confidence": c.confidence,
                "implementation": c.implementation,
                "effective_strength": c.effective_strength,
                "evidence": c.evidence,
                "reference": c.reference,
            }
            for c in config.mitigation.controls
        ],
        "monte_carlo": mc,
        "attack_progression": markov.as_dict(),
        "interpretation": {
            "risk_scale": "0-100 project reference scale",
            "risk_band_note": "Bands are OT-RiskLab reporting conventions, not NIST or IEC thresholds.",
            "sensitivity_note": "Spearman correlations describe association under the chosen uncertainty model, not causality.",
            "markov_note": "Default transition coefficients are transparent reference parameters, not empirically calibrated incident rates.",
            "epss_note": "EPSS is retained as a 30-day exploitation probability and is not multiplied by CVSS.",
            "kev_note": "CISA KEV is treated as confirmed-exploitation evidence, not as a numeric probability.",
        },
        "standards_context": [
            "NIST Cybersecurity Framework 2.0",
            "NIST SP 800-82 Rev. 3 Guide to Operational Technology (OT) Security",
            "MITRE ATT&CK for ICS",
            "FIRST Exploit Prediction Scoring System (EPSS)",
            "CISA Known Exploited Vulnerabilities (KEV) Catalog",
        ],
    }


def _fmt(value: float | None, digits: int = 3) -> str:
    return "n/a" if value is None else f"{value:.{digits}f}"


def render_markdown(result: dict[str, object]) -> str:
    scenario = result["scenario"]
    deterministic = result["deterministic"]
    mc = result["monte_carlo"]
    attack = result["attack_progression"]
    controls = result["controls"]
    evidence = result["vulnerability_evidence"]
    decision = result["decision_support"]
    metadata = result["metadata"]

    lines = [
        "# OT-RiskLab Analysis Report",
        "",
        f"- **Assessment ID:** {metadata['assessment_id'] or 'not supplied'}",
        f"- **Asset:** {scenario['asset']}",
        f"- **Asset type / zone:** {scenario['asset_type']} / {scenario['zone']}",
        f"- **Threat scenario:** {scenario['threat']}",
        f"- **Config fingerprint:** `{result['config_fingerprint_sha256']}`",
        f"- **Model signature:** `{result['provenance']['model_signature_sha256']}`",
        "",
        "## Risk summary",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Inherent risk | {_fmt(deterministic['inherent_risk'])} ({deterministic['inherent_band']}) |",
        f"| Residual risk | {_fmt(deterministic['residual_risk'])} ({deterministic['residual_band']}) |",
        f"| Combined mitigation effectiveness | {_fmt(deterministic['mitigation_effectiveness'])} |",
        f"| Monte Carlo mean | {_fmt(mc['mean'])} |",
        f"| Monte Carlo P05 / P50 / P95 | {_fmt(mc['p05'])} / {_fmt(mc['p50'])} / {_fmt(mc['p95'])} |",
        f"| Final compromise probability | {_fmt(attack['compromise_probability'])} |",
        f"| Expected compromise step within horizon | {_fmt(attack['expected_compromise_step_within_horizon'])} |",
    ]
    if decision["risk_tolerance"] is not None:
        lines.extend(
            [
                f"| Risk tolerance ({decision['tolerance_label']}) | {_fmt(decision['risk_tolerance'])} |",
                f"| Deterministic tolerance status | {decision['deterministic_status']} |",
                f"| P(simulated risk > tolerance) | {_fmt(decision['probability_above_tolerance'])} |",
            ]
        )

    lines.extend(["", "## Vulnerability evidence", ""])
    lines.append(f"- CVE IDs: {', '.join(f'`{x}`' for x in evidence['cve_ids']) if evidence['cve_ids'] else 'none supplied'}")
    lines.append(f"- CVSS base score: **{_fmt(evidence['cvss_base_score'], 1)}**")
    lines.append(f"- EPSS 30-day probability: **{_fmt(evidence['epss_probability_30d'])}**")
    lines.append(f"- EPSS percentile: **{_fmt(evidence['epss_percentile'])}**")
    lines.append(f"- CISA KEV: **{'yes' if evidence['cisa_kev'] else 'no'}**")
    lines.append(f"- Likelihood basis: **{evidence['likelihood_basis']}**")
    lines.append("")
    lines.append(evidence["interpretation"])

    lines.extend(["", "## Sensitivity", "", "| Factor | Spearman ρ | Direction |", "|---|---:|---|"])
    for entry in mc["sensitivity"]:
        lines.append(f"| {entry['factor']} | {entry['spearman_rho']:.3f} | {entry['direction']} |")

    decomposition = deterministic["decomposition"]
    lines.extend(
        [
            "",
            "## Main deterministic drivers",
            "",
            f"- Top vulnerability driver: **{decomposition['top_vulnerability_driver']}**",
            f"- Top consequence driver: **{decomposition['top_consequence_driver']}**",
        ]
    )

    lines.extend(["", "## Controls", ""])
    if controls:
        lines.extend(["| Control | CSF | Impl. | Confidence | Effective strength | Evidence |", "|---|---|---:|---:|---:|---|"])
        for control in controls:
            evidence_text = control["evidence"] or "—"
            lines.append(
                f"| {control['name']} | {control['csf_function']} | {control['implementation']:.3f} | "
                f"{control['confidence']:.3f} | {control['effective_strength']:.3f} | {evidence_text} |"
            )
    else:
        lines.append("No explicit controls were modeled.")

    posture = result["control_posture"]
    lines.extend(["", "## CSF Function coverage of modeled controls", "", "| Function | Controls | Combined modeled strength |", "|---|---:|---:|"])
    for item in posture["functions"]:
        lines.append(f"| {item['function']} | {item['control_count']} | {item['combined_strength']:.3f} |")
    lines.extend(["", posture["note"], ""])

    warnings = result["quality_warnings"]
    lines.extend(["## Model-quality warnings", ""])
    if warnings:
        for warning in warnings:
            lines.append(f"- **{warning['severity']}** `{warning['code']}` — {warning['message']}")
    else:
        lines.append("No non-blocking model-quality warnings were generated.")

    techniques = scenario["attack_techniques"]
    lines.extend(["", "## Threat-informed context", ""])
    if techniques:
        lines.append("ATT&CK technique identifiers supplied by the analyst: " + ", ".join(f"`{x}`" for x in techniques))
    else:
        lines.append("No ATT&CK technique identifiers were supplied for this scenario.")

    lines.extend(
        [
            "",
            "## Interpretation limits",
            "",
            "This output is a transparent decision-support model. It is not a certified safety assessment, a substitute for site-specific engineering analysis, or an empirically calibrated probability forecast unless the user supplies validated parameters.",
            "",
        ]
    )
    return "\n".join(lines)


def render_html(result: dict[str, object]) -> str:
    """Render a dependency-free, self-contained HTML report."""
    s = result["scenario"]
    d = result["deterministic"]
    mc = result["monte_carlo"]
    dec = result["decision_support"]
    ev = result["vulnerability_evidence"]
    warnings = result["quality_warnings"]
    controls = result["controls"]

    warning_rows = "".join(
        f"<li><strong>{escape(str(w['severity']))}</strong> <code>{escape(str(w['code']))}</code> — {escape(str(w['message']))}</li>"
        for w in warnings
    ) or "<li>None</li>"
    control_rows = "".join(
        "<tr>"
        f"<td>{escape(str(c['name']))}</td><td>{escape(str(c['csf_function']))}</td>"
        f"<td>{c['implementation']:.3f}</td><td>{c['confidence']:.3f}</td><td>{c['effective_strength']:.3f}</td>"
        f"<td>{escape(str(c['evidence'] or '—'))}</td></tr>"
        for c in controls
    ) or "<tr><td colspan='6'>No explicit controls modeled.</td></tr>"
    sensitivity_rows = "".join(
        f"<tr><td>{escape(str(x['factor']))}</td><td>{x['spearman_rho']:.3f}</td><td>{escape(str(x['direction']))}</td></tr>"
        for x in mc["sensitivity"]
    )
    tolerance_row = ""
    if dec["risk_tolerance"] is not None:
        tolerance_row = (
            f"<tr><th>Risk tolerance</th><td>{dec['risk_tolerance']:.3f} ({escape(str(dec['deterministic_status']))})</td></tr>"
            f"<tr><th>P(risk &gt; tolerance)</th><td>{_fmt(dec['probability_above_tolerance'])}</td></tr>"
        )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OT-RiskLab Report — {escape(str(s['asset']))}</title>
<style>
body{{font-family:system-ui,-apple-system,Segoe UI,sans-serif;max-width:1050px;margin:0 auto;padding:32px;line-height:1.55;color:#17202a;background:#fff}}
h1,h2{{line-height:1.2}} .muted{{color:#59636e}} .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}}
.card{{border:1px solid #d7dde3;border-radius:10px;padding:16px}} table{{border-collapse:collapse;width:100%;margin:10px 0 24px}}
th,td{{border-bottom:1px solid #d7dde3;padding:9px;text-align:left;vertical-align:top}} code{{background:#f3f5f7;padding:2px 4px;border-radius:4px}}
.badge{{display:inline-block;border:1px solid #aab4be;border-radius:999px;padding:2px 8px;font-size:.9rem}} @media print{{body{{max-width:none;padding:12px}}}}
</style></head><body>
<h1>OT-RiskLab Analysis Report</h1>
<p class="muted">Software v{SOFTWARE_VERSION} · config <code>{escape(str(result['config_fingerprint_sha256']))}</code> · model <code>{escape(str(result['provenance']['model_signature_sha256']))}</code></p>
<div class="grid"><div class="card"><strong>Asset</strong><br>{escape(str(s['asset']))}<br><span class="muted">{escape(str(s['asset_type']))} · {escape(str(s['zone']))}</span></div>
<div class="card"><strong>Threat</strong><br>{escape(str(s['threat']))}</div>
<div class="card"><strong>Residual risk</strong><br><span style="font-size:1.8rem">{d['residual_risk']:.2f}</span><br><span class="badge">{escape(str(d['residual_band']))}</span></div>
<div class="card"><strong>Monte Carlo P95</strong><br><span style="font-size:1.8rem">{mc['p95']:.2f}</span></div></div>
<h2>Decision summary</h2><table><tr><th>Inherent risk</th><td>{d['inherent_risk']:.3f}</td></tr><tr><th>Residual risk</th><td>{d['residual_risk']:.3f}</td></tr><tr><th>Mitigation effectiveness</th><td>{d['mitigation_effectiveness']:.3f}</td></tr><tr><th>Final compromise probability</th><td>{result['attack_progression']['compromise_probability']:.3f}</td></tr>{tolerance_row}</table>
<h2>Vulnerability evidence</h2><table><tr><th>CVE IDs</th><td>{escape(', '.join(ev['cve_ids']) or 'none supplied')}</td></tr><tr><th>CVSS</th><td>{ev['cvss_base_score']:.1f}</td></tr><tr><th>EPSS 30-day probability</th><td>{_fmt(ev['epss_probability_30d'])}</td></tr><tr><th>EPSS percentile</th><td>{_fmt(ev['epss_percentile'])}</td></tr><tr><th>CISA KEV</th><td>{'yes' if ev['cisa_kev'] else 'no'}</td></tr><tr><th>Likelihood basis</th><td>{escape(str(ev['likelihood_basis']))}</td></tr></table>
<h2>Controls</h2><table><thead><tr><th>Control</th><th>CSF</th><th>Implementation</th><th>Confidence</th><th>Modeled strength</th><th>Evidence</th></tr></thead><tbody>{control_rows}</tbody></table>
<h2>Sensitivity</h2><table><thead><tr><th>Factor</th><th>Spearman ρ</th><th>Direction</th></tr></thead><tbody>{sensitivity_rows}</tbody></table>
<h2>Model-quality warnings</h2><ul>{warning_rows}</ul>
<h2>Interpretation limits</h2><p>This report is decision-support output, not a certified safety assessment or a substitute for site-specific engineering validation. Default coefficients are reference parameters unless externally calibrated.</p>
</body></html>"""
