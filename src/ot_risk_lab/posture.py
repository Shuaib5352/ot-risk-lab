from __future__ import annotations

from collections import defaultdict
from statistics import fmean

from .models import AnalysisConfig, CSF_FUNCTIONS
from .risk import residual_risk


def control_posture(config: AnalysisConfig) -> dict[str, object]:
    """Summarize modeled control coverage by CSF Function.

    This is a decision-support view of explicitly entered controls, not a NIST
    CSF conformance or maturity assessment.
    """
    strengths: dict[str, list[float]] = defaultdict(list)
    for control in config.mitigation.controls:
        strengths[control.csf_function].append(control.effective_strength)

    functions: list[dict[str, object]] = []
    represented: list[str] = []
    missing: list[str] = []
    for function in CSF_FUNCTIONS:
        values = strengths.get(function, [])
        if values:
            represented.append(function)
            residual = 1.0
            for value in values:
                residual *= 1.0 - value
            combined = 1.0 - residual
            functions.append(
                {
                    "function": function,
                    "control_count": len(values),
                    "combined_strength": combined,
                    "mean_strength": fmean(values),
                }
            )
        else:
            missing.append(function)
            functions.append(
                {
                    "function": function,
                    "control_count": 0,
                    "combined_strength": 0.0,
                    "mean_strength": 0.0,
                }
            )

    return {
        "represented_functions": represented,
        "missing_functions": missing,
        "represented_count": len(represented),
        "functions": functions,
        "note": (
            "Function coverage reflects only the controls modeled in this scenario; "
            "it is not a NIST CSF compliance, maturity, or completeness assessment."
        ),
    }


def model_quality_warnings(config: AnalysisConfig) -> list[dict[str, str]]:
    warnings: list[dict[str, str]] = []

    if not config.mitigation.controls and config.mitigation.manual_effectiveness == 0.0:
        warnings.append({"code": "NO_MITIGATION_MODELED", "severity": "info", "message": "No mitigation controls or manual mitigation effectiveness are modeled."})

    if config.mitigation.manual_effectiveness > 0.0 and not config.mitigation.controls:
        warnings.append({"code": "MANUAL_MITIGATION_ONLY", "severity": "info", "message": "Mitigation is represented as one aggregate manual estimate without named controls."})

    low_confidence = [c.name for c in config.mitigation.controls if c.confidence < 0.5]
    if low_confidence:
        warnings.append({"code": "LOW_CONTROL_CONFIDENCE", "severity": "warning", "message": "One or more controls have confidence below 0.50: " + ", ".join(low_confidence)})

    partial_controls = [c.name for c in config.mitigation.controls if c.implementation < 0.5 and c.effectiveness >= 0.5]
    if partial_controls:
        warnings.append({"code": "PARTIAL_HIGH_EFFECT_CONTROL", "severity": "warning", "message": "High nominal effectiveness is paired with implementation below 0.50: " + ", ".join(partial_controls)})

    evidence_missing = [c.name for c in config.mitigation.controls if c.effective_strength >= 0.35 and not c.evidence]
    if evidence_missing:
        warnings.append({"code": "CONTROL_EVIDENCE_MISSING", "severity": "info", "message": "Material modeled controls have no supporting evidence note: " + ", ".join(evidence_missing)})

    if not config.threat.techniques:
        warnings.append({"code": "NO_ATTACK_TECHNIQUES", "severity": "info", "message": "No ATT&CK for ICS technique identifiers were supplied for the threat scenario."})

    if config.threat.cisa_kev:
        warnings.append({"code": "CISA_KEV_CONFIRMED_EXPLOITATION", "severity": "warning", "message": "At least one mapped vulnerability is marked as CISA KEV; treat confirmed exploitation as a remediation-priority signal independent of the model score."})

    if config.threat.epss_probability is not None and not config.threat.cve_ids:
        warnings.append({"code": "EPSS_WITHOUT_CVE", "severity": "warning", "message": "EPSS evidence is present but no CVE identifier is recorded for traceability."})

    if config.simulation.uncertainty == 0.0 and not any(config.simulation.factor_uncertainty.values()):
        warnings.append({"code": "NO_UNCERTAINTY", "severity": "info", "message": "Uncertainty is zero, so Monte Carlo output is effectively deterministic."})
    elif config.simulation.uncertainty >= 0.30:
        warnings.append({"code": "HIGH_GLOBAL_UNCERTAINTY", "severity": "info", "message": "Global uncertainty is at least 0.30; interpret wide output intervals with care."})

    if config.asset.internet_exposure >= 0.75 and config.mitigation.effectiveness < 0.25:
        warnings.append({"code": "HIGH_EXPOSURE_LOW_MITIGATION", "severity": "warning", "message": "High modeled internet exposure is paired with low combined mitigation effectiveness."})

    if config.asset.safety_impact >= 0.8 and config.asset.availability_impact >= 0.8:
        warnings.append({"code": "HIGH_OT_CONSEQUENCE", "severity": "info", "message": "Both safety and availability consequence inputs are high; site-specific engineering review is important."})

    if config.decision.risk_tolerance is not None:
        residual = residual_risk(config.asset, config.threat, config.mitigation, config.risk_model)
        if residual > config.decision.risk_tolerance:
            warnings.append({"code": "DETERMINISTIC_RISK_ABOVE_TOLERANCE", "severity": "warning", "message": "Modeled residual risk exceeds the organization-defined tolerance."})

    return warnings
