from __future__ import annotations

from dataclasses import dataclass
import math
import random
from statistics import fmean, pstdev

from .models import AnalysisConfig, AssetContext, ThreatContext
from .risk import baseline_risk


def _clip(value: float, lower: float, upper: float) -> float:
    return max(lower, min(upper, value))


def _sample_unit(rng: random.Random, mean: float, width: float, distribution: str) -> float:
    mean = _clip(mean, 0.0, 1.0)
    width = _clip(width, 0.0, 1.0)
    if distribution == "fixed" or width == 0.0:
        return mean
    if distribution == "truncated_normal":
        return _clip(rng.gauss(mean, width), 0.0, 1.0)
    if distribution == "triangular":
        low = max(0.0, mean - width)
        high = min(1.0, mean + width)
        return rng.triangular(low, high, mean)
    raise ValueError(f"unsupported distribution: {distribution}")


def _percentile(sorted_values: list[float], q: float) -> float:
    if not sorted_values:
        raise ValueError("percentile requires at least one value")
    if not 0.0 <= q <= 1.0:
        raise ValueError("q must be in [0, 1]")
    position = (len(sorted_values) - 1) * q
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return sorted_values[lower]
    fraction = position - lower
    return sorted_values[lower] * (1.0 - fraction) + sorted_values[upper] * fraction


def _average_ranks(values: list[float]) -> list[float]:
    order = sorted(range(len(values)), key=values.__getitem__)
    ranks = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i + 1
        while j < len(order) and values[order[j]] == values[order[i]]:
            j += 1
        average_rank = (i + 1 + j) / 2.0
        for k in range(i, j):
            ranks[order[k]] = average_rank
        i = j
    return ranks


def _pearson(x: list[float], y: list[float]) -> float:
    if len(x) != len(y) or not x:
        raise ValueError("correlation inputs must have equal non-zero length")
    mx, my = fmean(x), fmean(y)
    dx = [v - mx for v in x]
    dy = [v - my for v in y]
    sx = math.sqrt(sum(v * v for v in dx))
    sy = math.sqrt(sum(v * v for v in dy))
    if sx == 0.0 or sy == 0.0:
        return 0.0
    return sum(a * b for a, b in zip(dx, dy)) / (sx * sy)


def _spearman(x: list[float], y: list[float]) -> float:
    return _pearson(_average_ranks(x), _average_ranks(y))


@dataclass(frozen=True)
class SensitivityEntry:
    factor: str
    spearman_rho: float

    def as_dict(self) -> dict[str, float | str]:
        return {
            "factor": self.factor,
            "spearman_rho": self.spearman_rho,
            "absolute_influence": abs(self.spearman_rho),
            "direction": "increases-risk" if self.spearman_rho > 0 else "decreases-risk" if self.spearman_rho < 0 else "neutral",
        }


@dataclass(frozen=True)
class MonteCarloResult:
    mean: float
    std: float
    p05: float
    p50: float
    p95: float
    minimum: float
    maximum: float
    iterations: int
    seed: int
    distribution: str
    sensitivity: tuple[SensitivityEntry, ...]
    risk_tolerance: float | None = None
    probability_above_tolerance: float | None = None
    mean_excess_above_tolerance: float | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "mean": self.mean,
            "std": self.std,
            "p05": self.p05,
            "p50": self.p50,
            "p95": self.p95,
            "minimum": self.minimum,
            "maximum": self.maximum,
            "iterations": self.iterations,
            "seed": self.seed,
            "distribution": self.distribution,
            "risk_tolerance": self.risk_tolerance,
            "probability_above_tolerance": self.probability_above_tolerance,
            "mean_excess_above_tolerance": self.mean_excess_above_tolerance,
            "sensitivity": [entry.as_dict() for entry in self.sensitivity],
        }


def run_monte_carlo(config: AnalysisConfig) -> MonteCarloResult:
    """Propagate bounded input uncertainty into residual risk.

    Sensitivity is Spearman rank correlation between each sampled factor and
    residual risk. If an organization-defined risk tolerance is supplied, the
    simulation also reports the fraction of runs that exceed it.
    """
    sim = config.simulation
    rng = random.Random(sim.seed)
    values: list[float] = []
    factors: dict[str, list[float]] = {
        "threat_likelihood": [],
        "threat_cvss": [],
        "threat_impact": [],
        "asset_criticality": [],
        "asset_safety_impact": [],
        "asset_availability_impact": [],
        "asset_internet_exposure": [],
        "asset_legacy_factor": [],
        "mitigation_effectiveness": [],
    }

    def sample(name: str, mean: float) -> float:
        return _sample_unit(rng, mean, sim.uncertainty_for(name), sim.distribution)

    for _ in range(sim.iterations):
        sampled = {
            "threat_likelihood": sample("threat_likelihood", config.threat.likelihood),
            "threat_cvss": sample("threat_cvss", config.threat.cvss / 10.0),
            "threat_impact": sample("threat_impact", config.threat.impact),
            "asset_criticality": sample("asset_criticality", config.asset.criticality),
            "asset_safety_impact": sample("asset_safety_impact", config.asset.safety_impact),
            "asset_availability_impact": sample("asset_availability_impact", config.asset.availability_impact),
            "asset_internet_exposure": sample("asset_internet_exposure", config.asset.internet_exposure),
            "asset_legacy_factor": sample("asset_legacy_factor", config.asset.legacy_factor),
            "mitigation_effectiveness": sample("mitigation_effectiveness", config.mitigation.effectiveness),
        }
        asset = AssetContext(
            name=config.asset.name,
            asset_type=config.asset.asset_type,
            zone=config.asset.zone,
            criticality=sampled["asset_criticality"],
            safety_impact=sampled["asset_safety_impact"],
            availability_impact=sampled["asset_availability_impact"],
            internet_exposure=sampled["asset_internet_exposure"],
            legacy_factor=sampled["asset_legacy_factor"],
        )
        threat = ThreatContext(
            name=config.threat.name,
            cvss=10.0 * sampled["threat_cvss"],
            likelihood=sampled["threat_likelihood"],
            impact=sampled["threat_impact"],
            techniques=config.threat.techniques,
            cve_ids=config.threat.cve_ids,
            epss_probability=config.threat.epss_probability,
            epss_percentile=config.threat.epss_percentile,
            cisa_kev=config.threat.cisa_kev,
            evidence_date=config.threat.evidence_date,
            likelihood_basis="analyst" if config.threat.likelihood_basis == "epss-30d" else config.threat.likelihood_basis,
        )
        inherent = baseline_risk(asset, threat, config.risk_model)
        residual = inherent * (1.0 - sampled["mitigation_effectiveness"])
        values.append(residual)
        for factor, value in sampled.items():
            factors[factor].append(value)

    sorted_values = sorted(values)
    sensitivity = [
        SensitivityEntry(factor=name, spearman_rho=_spearman(samples, values))
        for name, samples in factors.items()
    ]
    sensitivity.sort(key=lambda entry: (-abs(entry.spearman_rho), entry.factor))

    tolerance = config.decision.risk_tolerance
    probability_above: float | None = None
    mean_excess: float | None = None
    if tolerance is not None:
        exceedances = [value - tolerance for value in values if value > tolerance]
        probability_above = len(exceedances) / len(values)
        mean_excess = fmean(exceedances) if exceedances else 0.0

    return MonteCarloResult(
        mean=fmean(values),
        std=pstdev(values),
        p05=_percentile(sorted_values, 0.05),
        p50=_percentile(sorted_values, 0.50),
        p95=_percentile(sorted_values, 0.95),
        minimum=sorted_values[0],
        maximum=sorted_values[-1],
        iterations=sim.iterations,
        seed=sim.seed,
        distribution=sim.distribution,
        sensitivity=tuple(sensitivity),
        risk_tolerance=tolerance,
        probability_above_tolerance=probability_above,
        mean_excess_above_tolerance=mean_excess,
    )
