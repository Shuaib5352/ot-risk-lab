from __future__ import annotations

from dataclasses import replace

from .models import AnalysisConfig, MitigationContext
from .risk import baseline_risk, residual_risk, risk_decomposition


def run_ablation(config: AnalysisConfig) -> dict[str, object]:
    """Run transparent one-at-a-time counterfactual ablations.

    Control ablations remove exactly one named control while preserving all
    other inputs. Factor ablations report the deterministic change that would
    occur if one normalized driver were set to zero, holding all other terms
    fixed. These are local counterfactuals, not causal effect estimates.
    """
    inherent = baseline_risk(config.asset, config.threat, config.risk_model)
    full_residual = residual_risk(config.asset, config.threat, config.mitigation, config.risk_model)

    no_controls = MitigationContext(manual_effectiveness=0.0, controls=())
    no_mitigation_risk = residual_risk(config.asset, config.threat, no_controls, config.risk_model)

    control_rows: list[dict[str, object]] = []
    controls = config.mitigation.controls
    for index, control in enumerate(controls):
        reduced_controls = controls[:index] + controls[index + 1 :]
        reduced = replace(config.mitigation, controls=reduced_controls)
        without = residual_risk(config.asset, config.threat, reduced, config.risk_model)
        delta = without - full_residual
        control_rows.append(
            {
                "control": control.name,
                "control_id": control.control_id,
                "effective_strength": control.effective_strength,
                "residual_without_control": without,
                "absolute_risk_increase_if_removed": delta,
                "relative_risk_increase_if_removed": (delta / full_residual if full_residual > 0 else None),
            }
        )
    control_rows.sort(key=lambda item: float(item["absolute_risk_increase_if_removed"]), reverse=True)

    decomposition = risk_decomposition(config.asset, config.threat, config.risk_model)
    likelihood = float(decomposition["likelihood"])
    vulnerability = float(decomposition["vulnerability"])
    consequence = float(decomposition["consequence"])

    factor_rows: list[dict[str, object]] = []
    for factor, term in dict(decomposition["vulnerability_terms"]).items():
        ablated_inherent = 100.0 * likelihood * max(0.0, vulnerability - float(term)) * consequence
        factor_rows.append(
            {
                "factor": factor,
                "component": "vulnerability",
                "inherent_risk_if_zero": ablated_inherent,
                "absolute_inherent_reduction": inherent - ablated_inherent,
            }
        )
    for factor, term in dict(decomposition["consequence_terms"]).items():
        ablated_inherent = 100.0 * likelihood * vulnerability * max(0.0, consequence - float(term))
        factor_rows.append(
            {
                "factor": factor,
                "component": "consequence",
                "inherent_risk_if_zero": ablated_inherent,
                "absolute_inherent_reduction": inherent - ablated_inherent,
            }
        )
    factor_rows.append(
        {
            "factor": "threat_likelihood",
            "component": "likelihood",
            "inherent_risk_if_zero": 0.0,
            "absolute_inherent_reduction": inherent,
        }
    )
    factor_rows.sort(key=lambda item: float(item["absolute_inherent_reduction"]), reverse=True)

    return {
        "analysis_type": "one-at-a-time-counterfactual-ablation",
        "inherent_risk": inherent,
        "residual_risk": full_residual,
        "risk_without_any_mitigation": no_mitigation_risk,
        "controls": control_rows,
        "factors": factor_rows,
        "interpretation": (
            "Removing one control or zeroing one factor is a local counterfactual sensitivity check. "
            "It does not identify causal effects and does not model dependencies between controls."
        ),
    }


def render_ablation_markdown(result: dict[str, object]) -> str:
    lines = [
        "# OT-RiskLab Ablation Report",
        "",
        f"- Inherent risk: **{float(result['inherent_risk']):.3f}**",
        f"- Residual risk: **{float(result['residual_risk']):.3f}**",
        f"- Risk without any mitigation: **{float(result['risk_without_any_mitigation']):.3f}**",
        "",
        "## Control removal counterfactuals",
        "",
        "| Control | Effective strength | Residual if removed | Risk increase |",
        "|---|---:|---:|---:|",
    ]
    controls = list(result["controls"])
    if controls:
        for row in controls:
            lines.append(
                f"| {row['control']} | {float(row['effective_strength']):.3f} | "
                f"{float(row['residual_without_control']):.3f} | "
                f"{float(row['absolute_risk_increase_if_removed']):.3f} |"
            )
    else:
        lines.append("| No explicit controls modeled | 0.000 | — | — |")

    lines.extend(
        [
            "",
            "## Deterministic factor ablations",
            "",
            "| Factor | Component | Inherent risk if zero | Reduction |",
            "|---|---|---:|---:|",
        ]
    )
    for row in result["factors"]:
        lines.append(
            f"| {row['factor']} | {row['component']} | {float(row['inherent_risk_if_zero']):.3f} | "
            f"{float(row['absolute_inherent_reduction']):.3f} |"
        )
    lines.extend(["", str(result["interpretation"]), ""])
    return "\n".join(lines)
