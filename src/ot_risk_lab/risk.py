from __future__ import annotations

from .models import AssetContext, MitigationContext, RiskModelConfig, ThreatContext


def _clip100(value: float) -> float:
    return max(0.0, min(100.0, float(value)))


def vulnerability_component(
    asset: AssetContext,
    threat: ThreatContext,
    model: RiskModelConfig | None = None,
) -> float:
    """Return normalized susceptibility/vulnerability component in [0, 1]."""
    model = model or RiskModelConfig()
    return (
        model.cvss_weight * (threat.cvss / 10.0)
        + model.exposure_weight * asset.internet_exposure
        + model.legacy_weight * asset.legacy_factor
    )


def consequence_component(
    asset: AssetContext,
    threat: ThreatContext,
    model: RiskModelConfig | None = None,
) -> float:
    """Return normalized consequence component in [0, 1]."""
    model = model or RiskModelConfig()
    return (
        model.threat_impact_weight * threat.impact
        + model.criticality_weight * asset.criticality
        + model.safety_weight * asset.safety_impact
        + model.availability_weight * asset.availability_impact
    )


def baseline_risk(
    asset: AssetContext,
    threat: ThreatContext,
    model: RiskModelConfig | None = None,
) -> float:
    """Compute inherent risk on a 0–100 reference scale.

    R = 100 × L × V × C
    where L is scenario likelihood, V is contextual susceptibility, and C is
    contextual consequence. The equation is transparent and parameterized; it is
    not presented as a universally calibrated OT risk standard.
    """
    model = model or RiskModelConfig()
    score = 100.0 * threat.likelihood * vulnerability_component(asset, threat, model) * consequence_component(
        asset, threat, model
    )
    return _clip100(score)


def residual_risk(
    asset: AssetContext,
    threat: ThreatContext,
    mitigation: MitigationContext,
    model: RiskModelConfig | None = None,
) -> float:
    """Apply the explicitly modeled mitigation effectiveness to inherent risk."""
    return _clip100(baseline_risk(asset, threat, model) * (1.0 - mitigation.effectiveness))


def qualitative_band(score: float) -> str:
    """Human-readable reporting band.

    These thresholds are a project reporting convention, not NIST/IEC thresholds.
    """
    value = _clip100(score)
    if value < 20.0:
        return "very-low"
    if value < 40.0:
        return "low"
    if value < 60.0:
        return "moderate"
    if value < 80.0:
        return "high"
    return "very-high"


def risk_decomposition(
    asset: AssetContext,
    threat: ThreatContext,
    model: RiskModelConfig | None = None,
) -> dict[str, object]:
    model = model or RiskModelConfig()
    vulnerability_terms = {
        "cvss": model.cvss_weight * (threat.cvss / 10.0),
        "internet_exposure": model.exposure_weight * asset.internet_exposure,
        "legacy_factor": model.legacy_weight * asset.legacy_factor,
    }
    consequence_terms = {
        "threat_impact": model.threat_impact_weight * threat.impact,
        "asset_criticality": model.criticality_weight * asset.criticality,
        "safety_impact": model.safety_weight * asset.safety_impact,
        "availability_impact": model.availability_weight * asset.availability_impact,
    }
    vulnerability = sum(vulnerability_terms.values())
    consequence = sum(consequence_terms.values())
    vulnerability_shares = {
        key: (value / vulnerability if vulnerability else 0.0)
        for key, value in vulnerability_terms.items()
    }
    consequence_shares = {
        key: (value / consequence if consequence else 0.0)
        for key, value in consequence_terms.items()
    }
    top_vulnerability_driver = max(vulnerability_terms, key=vulnerability_terms.get)
    top_consequence_driver = max(consequence_terms, key=consequence_terms.get)
    return {
        "likelihood": threat.likelihood,
        "vulnerability": vulnerability,
        "consequence": consequence,
        "vulnerability_terms": vulnerability_terms,
        "consequence_terms": consequence_terms,
        "vulnerability_shares": vulnerability_shares,
        "consequence_shares": consequence_shares,
        "top_vulnerability_driver": top_vulnerability_driver,
        "top_consequence_driver": top_consequence_driver,
        "formula": "100 * likelihood * vulnerability * consequence",
    }
