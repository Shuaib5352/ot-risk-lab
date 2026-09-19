from __future__ import annotations

from html import escape

from .models import AnalysisConfig
from .report import analyze


def _pct_reduction(before: float, after: float) -> float | None:
    if before == 0.0:
        return None
    return (before - after) / before * 100.0


def compare_configs(baseline: AnalysisConfig, candidate: AnalysisConfig) -> dict[str, object]:
    before = analyze(baseline)
    after = analyze(candidate)

    b_det, a_det = before["deterministic"], after["deterministic"]
    b_mc, a_mc = before["monte_carlo"], after["monte_carlo"]
    b_attack, a_attack = before["attack_progression"], after["attack_progression"]

    metrics = {
        "residual_risk": {"before": b_det["residual_risk"], "after": a_det["residual_risk"]},
        "monte_carlo_p95": {"before": b_mc["p95"], "after": a_mc["p95"]},
        "compromise_probability": {"before": b_attack["compromise_probability"], "after": a_attack["compromise_probability"]},
        "mitigation_effectiveness": {"before": b_det["mitigation_effectiveness"], "after": a_det["mitigation_effectiveness"]},
    }
    for values in metrics.values():
        before_value = float(values["before"])
        after_value = float(values["after"])
        values["absolute_change"] = after_value - before_value
        values["relative_reduction_percent"] = _pct_reduction(before_value, after_value)

    return {
        "schema_version": "1.1",
        "software": after["software"],
        "baseline": {"asset": before["scenario"]["asset"], "threat": before["scenario"]["threat"], "fingerprint": before["config_fingerprint_sha256"]},
        "candidate": {"asset": after["scenario"]["asset"], "threat": after["scenario"]["threat"], "fingerprint": after["config_fingerprint_sha256"]},
        "metrics": metrics,
        "candidate_decision_support": after["decision_support"],
        "candidate_quality_warnings": after.get("quality_warnings", []),
        "interpretation": "Differences are model-output changes under the supplied configurations, not empirical realized-incident reductions unless externally calibrated.",
    }


def _fmt(value: float | None, digits: int = 3) -> str:
    return "n/a" if value is None else f"{value:.{digits}f}"


def render_comparison_markdown(result: dict[str, object]) -> str:
    metrics = result["metrics"]
    lines = [
        "# OT-RiskLab Scenario Comparison", "",
        f"- **Baseline:** {result['baseline']['asset']} / {result['baseline']['threat']}",
        f"- **Candidate:** {result['candidate']['asset']} / {result['candidate']['threat']}", "",
        "| Metric | Before | After | Absolute change | Relative reduction |",
        "|---|---:|---:|---:|---:|",
    ]
    labels = {"residual_risk": "Residual risk", "monte_carlo_p95": "Monte Carlo P95", "compromise_probability": "Compromise probability", "mitigation_effectiveness": "Mitigation effectiveness"}
    for key, label in labels.items():
        item = metrics[key]
        rr = item["relative_reduction_percent"]
        lines.append(f"| {label} | {_fmt(item['before'])} | {_fmt(item['after'])} | {_fmt(item['absolute_change'])} | {'n/a' if rr is None else f'{rr:.2f}%'} |")
    decision = result["candidate_decision_support"]
    lines.extend(["", "## Candidate decision support", "", f"Tolerance status: **{decision['deterministic_status']}**"])
    if decision["risk_tolerance"] is not None:
        lines.append(f"Probability above tolerance: **{_fmt(decision['probability_above_tolerance'])}**")
    warnings = result.get("candidate_quality_warnings", [])
    lines.extend(["", "## Candidate model warnings", ""])
    if warnings:
        for warning in warnings:
            lines.append(f"- **{warning['severity']}** `{warning['code']}` — {warning['message']}")
    else:
        lines.append("No non-blocking model-quality warnings were generated.")
    lines.extend(["", "## Interpretation", "", result["interpretation"], ""])
    return "\n".join(lines)


def render_comparison_html(result: dict[str, object]) -> str:
    labels = {"residual_risk": "Residual risk", "monte_carlo_p95": "Monte Carlo P95", "compromise_probability": "Compromise probability", "mitigation_effectiveness": "Mitigation effectiveness"}
    rows = "".join(
        f"<tr><td>{escape(label)}</td><td>{result['metrics'][key]['before']:.3f}</td><td>{result['metrics'][key]['after']:.3f}</td><td>{result['metrics'][key]['absolute_change']:.3f}</td></tr>"
        for key, label in labels.items()
    )
    return f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>OT-RiskLab Comparison</title><style>body{{font-family:system-ui,sans-serif;max-width:900px;margin:auto;padding:30px}}table{{border-collapse:collapse;width:100%}}th,td{{padding:9px;border-bottom:1px solid #ddd;text-align:left}}</style></head><body><h1>OT-RiskLab Scenario Comparison</h1><p><strong>Baseline:</strong> {escape(str(result['baseline']['asset']))} / {escape(str(result['baseline']['threat']))}<br><strong>Candidate:</strong> {escape(str(result['candidate']['asset']))} / {escape(str(result['candidate']['threat']))}</p><table><thead><tr><th>Metric</th><th>Before</th><th>After</th><th>Change</th></tr></thead><tbody>{rows}</tbody></table><p>{escape(str(result['interpretation']))}</p></body></html>"""
