from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date
from typing import Any

CSF_FUNCTIONS = ("GOVERN", "IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER")
UNCERTAINTY_DISTRIBUTIONS = ("fixed", "truncated_normal", "triangular")
LIKELIHOOD_BASES = ("analyst", "expert-elicitation", "historical", "epss-30d", "other")

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_ATTACK_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)


def _unit(value: float, field_name: str) -> float:
    value = float(value)
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{field_name} must be in [0, 1], got {value}")
    return value


def _bounded_100(value: float, field_name: str) -> float:
    value = float(value)
    if not 0.0 <= value <= 100.0:
        raise ValueError(f"{field_name} must be in [0, 100], got {value}")
    return value


def _nonnegative(value: float, field_name: str) -> float:
    value = float(value)
    if value < 0.0:
        raise ValueError(f"{field_name} must be >= 0, got {value}")
    return value


def _require_weight_sum(values: tuple[float, ...], group_name: str) -> None:
    total = sum(values)
    if abs(total - 1.0) > 1e-9:
        raise ValueError(f"{group_name} weights must sum to 1.0, got {total}")


def _optional_iso_date(value: str | None, field_name: str) -> str | None:
    if value is None or not str(value).strip():
        return None
    normalized = str(value).strip()
    try:
        date.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an ISO date (YYYY-MM-DD), got {normalized}") from exc
    return normalized


@dataclass(frozen=True)
class AssessmentMetadata:
    assessment_id: str = ""
    analyst: str = ""
    organization: str = ""
    scope: str = ""
    notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "assessment_id", str(self.assessment_id).strip())
        object.__setattr__(self, "analyst", str(self.analyst).strip())
        object.__setattr__(self, "organization", str(self.organization).strip())
        object.__setattr__(self, "scope", str(self.scope).strip())
        object.__setattr__(self, "notes", tuple(str(x).strip() for x in self.notes if str(x).strip()))


@dataclass(frozen=True)
class AssetContext:
    name: str
    criticality: float
    safety_impact: float
    availability_impact: float
    internet_exposure: float
    legacy_factor: float
    asset_type: str = "unspecified"
    zone: str = "unspecified"

    def __post_init__(self) -> None:
        if not str(self.name).strip():
            raise ValueError("asset.name must not be empty")
        object.__setattr__(self, "name", str(self.name).strip())
        for field_name in (
            "criticality",
            "safety_impact",
            "availability_impact",
            "internet_exposure",
            "legacy_factor",
        ):
            object.__setattr__(self, field_name, _unit(getattr(self, field_name), f"asset.{field_name}"))
        object.__setattr__(self, "asset_type", str(self.asset_type).strip() or "unspecified")
        object.__setattr__(self, "zone", str(self.zone).strip() or "unspecified")


@dataclass(frozen=True)
class ThreatContext:
    name: str
    cvss: float
    likelihood: float
    impact: float
    techniques: tuple[str, ...] = ()
    cve_ids: tuple[str, ...] = ()
    epss_probability: float | None = None
    epss_percentile: float | None = None
    cisa_kev: bool = False
    evidence_date: str | None = None
    likelihood_basis: str = "analyst"

    def __post_init__(self) -> None:
        if not str(self.name).strip():
            raise ValueError("threat.name must not be empty")
        object.__setattr__(self, "name", str(self.name).strip())
        cvss = float(self.cvss)
        if not 0.0 <= cvss <= 10.0:
            raise ValueError(f"threat.cvss must be in [0, 10], got {cvss}")
        object.__setattr__(self, "cvss", cvss)
        object.__setattr__(self, "likelihood", _unit(self.likelihood, "threat.likelihood"))
        object.__setattr__(self, "impact", _unit(self.impact, "threat.impact"))

        techniques = tuple(str(x).upper().strip() for x in self.techniques if str(x).strip())
        invalid_techniques = [x for x in techniques if not _ATTACK_RE.fullmatch(x)]
        if invalid_techniques:
            raise ValueError("threat.techniques contains invalid ATT&CK identifier(s): " + ", ".join(invalid_techniques))
        object.__setattr__(self, "techniques", tuple(dict.fromkeys(techniques)))

        cve_ids = tuple(str(x).upper().strip() for x in self.cve_ids if str(x).strip())
        invalid_cves = [x for x in cve_ids if not _CVE_RE.fullmatch(x)]
        if invalid_cves:
            raise ValueError("threat.cve_ids contains invalid CVE identifier(s): " + ", ".join(invalid_cves))
        object.__setattr__(self, "cve_ids", tuple(dict.fromkeys(cve_ids)))

        if self.epss_probability is not None:
            object.__setattr__(self, "epss_probability", _unit(self.epss_probability, "threat.epss_probability"))
        if self.epss_percentile is not None:
            object.__setattr__(self, "epss_percentile", _unit(self.epss_percentile, "threat.epss_percentile"))
        object.__setattr__(self, "cisa_kev", bool(self.cisa_kev))
        object.__setattr__(self, "evidence_date", _optional_iso_date(self.evidence_date, "threat.evidence_date"))

        basis = str(self.likelihood_basis).lower().strip()
        if basis not in LIKELIHOOD_BASES:
            raise ValueError(f"threat.likelihood_basis must be one of {LIKELIHOOD_BASES}, got {basis}")
        if basis == "epss-30d":
            if self.epss_probability is None:
                raise ValueError("threat.epss_probability is required when likelihood_basis is 'epss-30d'")
            if abs(self.likelihood - self.epss_probability) > 1e-9:
                raise ValueError(
                    "threat.likelihood must equal threat.epss_probability when likelihood_basis is 'epss-30d'"
                )
        object.__setattr__(self, "likelihood_basis", basis)


@dataclass(frozen=True)
class ControlContext:
    name: str
    effectiveness: float
    coverage: float = 1.0
    confidence: float = 1.0
    implementation: float = 1.0
    csf_function: str = "PROTECT"
    control_id: str = ""
    evidence: str = ""
    reference: str = ""

    def __post_init__(self) -> None:
        if not str(self.name).strip():
            raise ValueError("control.name must not be empty")
        object.__setattr__(self, "name", str(self.name).strip())
        object.__setattr__(self, "effectiveness", _unit(self.effectiveness, "control.effectiveness"))
        object.__setattr__(self, "coverage", _unit(self.coverage, "control.coverage"))
        object.__setattr__(self, "confidence", _unit(self.confidence, "control.confidence"))
        object.__setattr__(self, "implementation", _unit(self.implementation, "control.implementation"))
        fn = str(self.csf_function).upper().strip()
        if fn not in CSF_FUNCTIONS:
            raise ValueError(f"control.csf_function must be one of {CSF_FUNCTIONS}, got {fn}")
        object.__setattr__(self, "csf_function", fn)
        object.__setattr__(self, "control_id", str(self.control_id).strip())
        object.__setattr__(self, "evidence", str(self.evidence).strip())
        object.__setattr__(self, "reference", str(self.reference).strip())

    @property
    def effective_strength(self) -> float:
        """Transparent modeled control strength.

        effectiveness × coverage × confidence × implementation keeps the four
        analyst inputs visible. It is not an empirical claim of control efficacy.
        """
        return self.effectiveness * self.coverage * self.confidence * self.implementation


@dataclass(frozen=True)
class MitigationContext:
    manual_effectiveness: float = 0.0
    controls: tuple[ControlContext, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "manual_effectiveness",
            _unit(self.manual_effectiveness, "mitigation.manual_effectiveness"),
        )
        controls = tuple(self.controls)
        ids = [c.control_id for c in controls if c.control_id]
        if len(ids) != len(set(ids)):
            raise ValueError("mitigation.controls contains duplicate non-empty control_id values")
        object.__setattr__(self, "controls", controls)

    @property
    def effectiveness(self) -> float:
        """Combine independent residual-control factors.

        M = 1 - (1-M_manual) Π_i (1-s_i), where s_i is a control's modeled
        effective strength. The independence assumption is documented and should
        be replaced when calibrated dependency evidence exists.
        """
        residual_fraction = 1.0 - self.manual_effectiveness
        for control in self.controls:
            residual_fraction *= 1.0 - control.effective_strength
        return 1.0 - residual_fraction


@dataclass(frozen=True)
class RiskModelConfig:
    cvss_weight: float = 0.50
    exposure_weight: float = 0.30
    legacy_weight: float = 0.20

    threat_impact_weight: float = 0.25
    criticality_weight: float = 0.25
    safety_weight: float = 0.25
    availability_weight: float = 0.25

    def __post_init__(self) -> None:
        vuln = tuple(
            _nonnegative(getattr(self, f), f"risk_model.{f}")
            for f in ("cvss_weight", "exposure_weight", "legacy_weight")
        )
        cons = tuple(
            _nonnegative(getattr(self, f), f"risk_model.{f}")
            for f in (
                "threat_impact_weight",
                "criticality_weight",
                "safety_weight",
                "availability_weight",
            )
        )
        _require_weight_sum(vuln, "vulnerability")
        _require_weight_sum(cons, "consequence")


@dataclass(frozen=True)
class MarkovConfig:
    secure_to_recon_base: float = 0.02
    secure_to_recon_scale: float = 0.18
    recon_to_exploit_base: float = 0.03
    recon_to_exploit_scale: float = 0.25
    exploit_to_compromise_base: float = 0.01
    exploit_to_compromise_scale: float = 0.30

    def __post_init__(self) -> None:
        pairs = (
            ("secure_to_recon", self.secure_to_recon_base, self.secure_to_recon_scale),
            ("recon_to_exploit", self.recon_to_exploit_base, self.recon_to_exploit_scale),
            ("exploit_to_compromise", self.exploit_to_compromise_base, self.exploit_to_compromise_scale),
        )
        for name, base, scale in pairs:
            base = _unit(base, f"markov.{name}_base")
            scale = _nonnegative(scale, f"markov.{name}_scale")
            if base + scale > 1.0:
                raise ValueError(f"markov {name}: base + scale must be <= 1.0")


@dataclass(frozen=True)
class SimulationConfig:
    iterations: int = 10_000
    uncertainty: float = 0.10
    seed: int = 42
    markov_steps: int = 24
    distribution: str = "truncated_normal"
    factor_uncertainty: Mapping[str, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        iterations = int(self.iterations)
        markov_steps = int(self.markov_steps)
        if iterations < 100:
            raise ValueError("simulation.iterations must be >= 100")
        if markov_steps < 1:
            raise ValueError("simulation.markov_steps must be >= 1")
        distribution = str(self.distribution).strip().lower()
        if distribution not in UNCERTAINTY_DISTRIBUTIONS:
            raise ValueError(
                f"simulation.distribution must be one of {UNCERTAINTY_DISTRIBUTIONS}, got {distribution}"
            )
        factor_uncertainty = {
            str(k): _unit(v, f"simulation.factor_uncertainty.{k}")
            for k, v in dict(self.factor_uncertainty).items()
        }
        object.__setattr__(self, "iterations", iterations)
        object.__setattr__(self, "markov_steps", markov_steps)
        object.__setattr__(self, "uncertainty", _unit(self.uncertainty, "simulation.uncertainty"))
        object.__setattr__(self, "seed", int(self.seed))
        object.__setattr__(self, "distribution", distribution)
        object.__setattr__(self, "factor_uncertainty", factor_uncertainty)

    def uncertainty_for(self, factor: str) -> float:
        return float(self.factor_uncertainty.get(factor, self.uncertainty))


@dataclass(frozen=True)
class DecisionContext:
    risk_tolerance: float | None = None
    tolerance_label: str = "organization-defined"

    def __post_init__(self) -> None:
        if self.risk_tolerance is not None:
            object.__setattr__(self, "risk_tolerance", _bounded_100(self.risk_tolerance, "decision.risk_tolerance"))
        object.__setattr__(self, "tolerance_label", str(self.tolerance_label).strip() or "organization-defined")


@dataclass(frozen=True)
class AnalysisConfig:
    asset: AssetContext
    threat: ThreatContext
    mitigation: MitigationContext = field(default_factory=MitigationContext)
    simulation: SimulationConfig = field(default_factory=SimulationConfig)
    risk_model: RiskModelConfig = field(default_factory=RiskModelConfig)
    markov: MarkovConfig = field(default_factory=MarkovConfig)
    decision: DecisionContext = field(default_factory=DecisionContext)
    metadata: AssessmentMetadata = field(default_factory=AssessmentMetadata)

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> AnalysisConfig:
        asset_raw = dict(raw["asset"])
        asset_raw.setdefault("safety_impact", asset_raw.get("criticality", 0.0))
        asset_raw.setdefault("availability_impact", asset_raw.get("criticality", 0.0))

        threat_raw = dict(raw["threat"])
        threat_raw.setdefault("name", "Unspecified threat scenario")
        threat_raw["techniques"] = tuple(threat_raw.get("techniques", ()))
        threat_raw["cve_ids"] = tuple(threat_raw.get("cve_ids", ()))
        threat_raw.setdefault("likelihood_basis", "analyst")
        if "likelihood" not in threat_raw and threat_raw.get("likelihood_basis") == "epss-30d":
            if threat_raw.get("epss_probability") is None:
                raise ValueError("threat.likelihood or threat.epss_probability is required")
            threat_raw["likelihood"] = threat_raw["epss_probability"]

        mitigation_raw = dict(raw.get("mitigation", {}))
        manual = mitigation_raw.get("manual_effectiveness", mitigation_raw.get("effectiveness", 0.0))
        controls = tuple(ControlContext(**item) for item in mitigation_raw.get("controls", ()))

        metadata_raw = dict(raw.get("metadata", {}))
        metadata_raw["notes"] = tuple(metadata_raw.get("notes", ()))

        return cls(
            asset=AssetContext(**asset_raw),
            threat=ThreatContext(**threat_raw),
            mitigation=MitigationContext(manual_effectiveness=manual, controls=controls),
            simulation=SimulationConfig(**raw.get("simulation", {})),
            risk_model=RiskModelConfig(**raw.get("risk_model", {})),
            markov=MarkovConfig(**raw.get("markov", {})),
            decision=DecisionContext(**raw.get("decision", {})),
            metadata=AssessmentMetadata(**metadata_raw),
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "metadata": {
                "assessment_id": self.metadata.assessment_id,
                "analyst": self.metadata.analyst,
                "organization": self.metadata.organization,
                "scope": self.metadata.scope,
                "notes": list(self.metadata.notes),
            },
            "asset": {
                "name": self.asset.name,
                "asset_type": self.asset.asset_type,
                "zone": self.asset.zone,
                "criticality": self.asset.criticality,
                "safety_impact": self.asset.safety_impact,
                "availability_impact": self.asset.availability_impact,
                "internet_exposure": self.asset.internet_exposure,
                "legacy_factor": self.asset.legacy_factor,
            },
            "threat": {
                "name": self.threat.name,
                "cvss": self.threat.cvss,
                "likelihood": self.threat.likelihood,
                "impact": self.threat.impact,
                "techniques": list(self.threat.techniques),
                "cve_ids": list(self.threat.cve_ids),
                "epss_probability": self.threat.epss_probability,
                "epss_percentile": self.threat.epss_percentile,
                "cisa_kev": self.threat.cisa_kev,
                "evidence_date": self.threat.evidence_date,
                "likelihood_basis": self.threat.likelihood_basis,
            },
            "mitigation": {
                "manual_effectiveness": self.mitigation.manual_effectiveness,
                "controls": [
                    {
                        "name": c.name,
                        "control_id": c.control_id,
                        "effectiveness": c.effectiveness,
                        "coverage": c.coverage,
                        "confidence": c.confidence,
                        "implementation": c.implementation,
                        "csf_function": c.csf_function,
                        "evidence": c.evidence,
                        "reference": c.reference,
                    }
                    for c in self.mitigation.controls
                ],
            },
            "simulation": {
                "iterations": self.simulation.iterations,
                "uncertainty": self.simulation.uncertainty,
                "seed": self.simulation.seed,
                "markov_steps": self.simulation.markov_steps,
                "distribution": self.simulation.distribution,
                "factor_uncertainty": dict(self.simulation.factor_uncertainty),
            },
            "risk_model": {
                "cvss_weight": self.risk_model.cvss_weight,
                "exposure_weight": self.risk_model.exposure_weight,
                "legacy_weight": self.risk_model.legacy_weight,
                "threat_impact_weight": self.risk_model.threat_impact_weight,
                "criticality_weight": self.risk_model.criticality_weight,
                "safety_weight": self.risk_model.safety_weight,
                "availability_weight": self.risk_model.availability_weight,
            },
            "markov": {
                "secure_to_recon_base": self.markov.secure_to_recon_base,
                "secure_to_recon_scale": self.markov.secure_to_recon_scale,
                "recon_to_exploit_base": self.markov.recon_to_exploit_base,
                "recon_to_exploit_scale": self.markov.recon_to_exploit_scale,
                "exploit_to_compromise_base": self.markov.exploit_to_compromise_base,
                "exploit_to_compromise_scale": self.markov.exploit_to_compromise_scale,
            },
            "decision": {
                "risk_tolerance": self.decision.risk_tolerance,
                "tolerance_label": self.decision.tolerance_label,
            },
        }
