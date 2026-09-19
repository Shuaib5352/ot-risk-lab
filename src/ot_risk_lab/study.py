from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime, timezone
import math
from pathlib import Path
import random
from typing import Iterable

from .calibration import calibration_diagnostics

_EPSILON = 1e-15


@dataclass(frozen=True)
class StudyRecord:
    record_id: str
    predicted_probability: float
    observed: int
    site: str = ""
    timestamp: str = ""
    subgroup: str = ""

    def __post_init__(self) -> None:
        record_id = str(self.record_id).strip()
        if not record_id:
            raise ValueError("study record_id must not be empty")
        probability = float(self.predicted_probability)
        if not 0.0 <= probability <= 1.0:
            raise ValueError(f"predicted_probability must be in [0, 1], got {probability}")
        observed = int(self.observed)
        if float(self.observed) != observed or observed not in (0, 1):
            raise ValueError(f"observed must be binary (0/1), got {self.observed!r}")
        timestamp = str(self.timestamp).strip()
        if timestamp:
            _parse_timestamp(timestamp)
        object.__setattr__(self, "record_id", record_id)
        object.__setattr__(self, "predicted_probability", probability)
        object.__setattr__(self, "observed", observed)
        object.__setattr__(self, "site", str(self.site).strip())
        object.__setattr__(self, "timestamp", timestamp)
        object.__setattr__(self, "subgroup", str(self.subgroup).strip())


def _parse_timestamp(value: str) -> datetime:
    text = str(value).strip()
    if not text:
        raise ValueError("timestamp must not be empty")
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"invalid ISO-8601 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def load_study_csv(path: Path) -> list[StudyRecord]:
    records: list[StudyRecord] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = set(reader.fieldnames or ())
        required = {"predicted_probability", "observed"}
        missing = sorted(required - fields)
        if missing:
            raise ValueError("study CSV missing required column(s): " + ", ".join(missing))
        for line_number, row in enumerate(reader, start=2):
            rid = (row.get("record_id") or f"row-{line_number}").strip()
            observed_raw = (row.get("observed") or "").strip().lower()
            if observed_raw in {"1", "true", "yes", "y"}:
                observed = 1
            elif observed_raw in {"0", "false", "no", "n"}:
                observed = 0
            else:
                raise ValueError(f"line {line_number}: observed must be binary (0/1)")
            try:
                probability = float((row.get("predicted_probability") or "").strip())
            except ValueError as exc:
                raise ValueError(f"line {line_number}: invalid predicted_probability") from exc
            records.append(
                StudyRecord(
                    record_id=rid,
                    predicted_probability=probability,
                    observed=observed,
                    site=row.get("site") or "",
                    timestamp=row.get("timestamp") or "",
                    subgroup=row.get("subgroup") or "",
                )
            )
    if not records:
        raise ValueError("study CSV contains no observations")
    ids = [record.record_id for record in records]
    if len(ids) != len(set(ids)):
        raise ValueError("study CSV contains duplicate record_id values")
    return records


def _metric_values(records: list[StudyRecord], bins: int) -> dict[str, float]:
    diagnostics = calibration_diagnostics(
        [(record.predicted_probability, record.observed) for record in records],
        bins=bins,
    )
    return {
        "observed_rate": float(diagnostics["observed_rate"]),
        "predicted_mean": float(diagnostics["predicted_mean"]),
        "brier_score": float(diagnostics["brier_score"]),
        "log_loss": float(diagnostics["log_loss"]),
        "expected_calibration_error": float(diagnostics["expected_calibration_error"]),
        "maximum_calibration_error": float(diagnostics["maximum_calibration_error"]),
    }


def _percentile(sorted_values: list[float], q: float) -> float:
    if not sorted_values:
        raise ValueError("percentile requires at least one value")
    if q <= 0.0:
        return sorted_values[0]
    if q >= 1.0:
        return sorted_values[-1]
    position = (len(sorted_values) - 1) * q
    lower = int(math.floor(position))
    upper = int(math.ceil(position))
    if lower == upper:
        return sorted_values[lower]
    fraction = position - lower
    return sorted_values[lower] * (1.0 - fraction) + sorted_values[upper] * fraction


def bootstrap_metric_intervals(
    records: list[StudyRecord],
    *,
    repetitions: int = 1000,
    confidence: float = 0.95,
    seed: int = 42,
    bins: int = 10,
    unit: str = "record",
) -> dict[str, dict[str, float]]:
    """Non-parametric percentile bootstrap intervals.

    ``unit="record"`` resamples individual observations. ``unit="site"``
    performs a cluster bootstrap by resampling complete sites, preserving
    within-site dependence in each replicate.
    """
    if not records:
        raise ValueError("bootstrap requires at least one study record")
    if repetitions < 100:
        raise ValueError("bootstrap repetitions must be >= 100")
    if not 0.5 < confidence < 1.0:
        raise ValueError("confidence must be between 0.5 and 1.0")
    if bins < 2 or bins > 100:
        raise ValueError("bins must be between 2 and 100")
    if unit not in {"record", "site"}:
        raise ValueError("bootstrap unit must be 'record' or 'site'")

    point = _metric_values(records, bins)
    rng = random.Random(seed)
    names = tuple(point)
    samples: dict[str, list[float]] = {name: [] for name in names}
    n = len(records)
    site_groups: list[list[StudyRecord]] = []
    if unit == "site":
        if any(not record.site for record in records):
            raise ValueError("site-level bootstrap requires site for every record")
        grouped: dict[str, list[StudyRecord]] = {}
        for record in records:
            grouped.setdefault(record.site, []).append(record)
        if len(grouped) < 2:
            raise ValueError("site-level bootstrap requires at least two sites")
        site_groups = list(grouped.values())
    for _ in range(repetitions):
        if unit == "record":
            replicate = [records[rng.randrange(n)] for _ in range(n)]
        else:
            replicate = []
            for _site_index in range(len(site_groups)):
                replicate.extend(site_groups[rng.randrange(len(site_groups))])
        values = _metric_values(replicate, bins)
        for name in names:
            samples[name].append(values[name])

    alpha = (1.0 - confidence) / 2.0
    result: dict[str, dict[str, float]] = {}
    for name in names:
        values = sorted(samples[name])
        result[name] = {
            "estimate": point[name],
            "lower": _percentile(values, alpha),
            "upper": _percentile(values, 1.0 - alpha),
            "confidence": confidence,
        }
    return result


def _summary(
    records: list[StudyRecord],
    *,
    bins: int,
    bootstrap: int,
    confidence: float,
    seed: int,
    bootstrap_unit: str,
) -> dict[str, object]:
    diagnostics = calibration_diagnostics(
        [(record.predicted_probability, record.observed) for record in records],
        bins=bins,
    )
    bootstrap_note = ""
    try:
        intervals = bootstrap_metric_intervals(
            records,
            repetitions=bootstrap,
            confidence=confidence,
            seed=seed,
            bins=bins,
            unit=bootstrap_unit,
        )
    except ValueError as exc:
        if bootstrap_unit != "site" or "at least two sites" not in str(exc):
            raise
        intervals = None
        bootstrap_note = "Site-level bootstrap interval unavailable because this partition contains fewer than two sites."
    return {
        "n": len(records),
        "diagnostics": diagnostics,
        "bootstrap_intervals": intervals,
        "bootstrap_note": bootstrap_note,
    }


def temporal_split(records: list[StudyRecord], cutoff: str) -> tuple[list[StudyRecord], list[StudyRecord], dict[str, object]]:
    cutoff_dt = _parse_timestamp(cutoff)
    if any(not record.timestamp for record in records):
        raise ValueError("temporal split requires timestamp for every record")
    development = [record for record in records if _parse_timestamp(record.timestamp) < cutoff_dt]
    evaluation = [record for record in records if _parse_timestamp(record.timestamp) >= cutoff_dt]
    if not development or not evaluation:
        raise ValueError("temporal split must produce non-empty development and evaluation sets")
    dev_max = max(_parse_timestamp(record.timestamp) for record in development)
    eval_min = min(_parse_timestamp(record.timestamp) for record in evaluation)
    return development, evaluation, {
        "mode": "temporal",
        "cutoff": cutoff_dt.isoformat(),
        "development_n": len(development),
        "evaluation_n": len(evaluation),
        "development_max_timestamp": dev_max.isoformat(),
        "evaluation_min_timestamp": eval_min.isoformat(),
        "temporal_order_valid": dev_max < eval_min,
        "note": "Evaluation records occur at or after the frozen cutoff; development records occur before it.",
    }


def site_disjoint_split(
    records: list[StudyRecord], evaluation_sites: Iterable[str]
) -> tuple[list[StudyRecord], list[StudyRecord], dict[str, object]]:
    requested = {str(site).strip() for site in evaluation_sites if str(site).strip()}
    if not requested:
        raise ValueError("site-disjoint split requires at least one evaluation site")
    if any(not record.site for record in records):
        raise ValueError("site-disjoint split requires site for every record")
    known = {record.site for record in records}
    unknown = sorted(requested - known)
    if unknown:
        raise ValueError("evaluation site(s) not present in study CSV: " + ", ".join(unknown))
    development = [record for record in records if record.site not in requested]
    evaluation = [record for record in records if record.site in requested]
    if not development or not evaluation:
        raise ValueError("site-disjoint split must produce non-empty development and evaluation sets")
    dev_sites = sorted({record.site for record in development})
    eval_sites = sorted({record.site for record in evaluation})
    overlap = sorted(set(dev_sites) & set(eval_sites))
    return development, evaluation, {
        "mode": "site-disjoint",
        "development_n": len(development),
        "evaluation_n": len(evaluation),
        "development_sites": dev_sites,
        "evaluation_sites": eval_sites,
        "site_overlap": overlap,
        "site_disjoint_valid": not overlap,
        "note": "No site appears in both development and evaluation partitions.",
    }


def subgroup_diagnostics(records: list[StudyRecord], field: str, bins: int = 10) -> list[dict[str, object]]:
    if field not in {"site", "subgroup"}:
        raise ValueError("subgroup field must be 'site' or 'subgroup'")
    groups: dict[str, list[StudyRecord]] = {}
    for record in records:
        value = getattr(record, field) or "(missing)"
        groups.setdefault(value, []).append(record)
    results: list[dict[str, object]] = []
    for value in sorted(groups):
        group = groups[value]
        effective_bins = max(2, min(bins, len(group))) if len(group) >= 2 else 2
        diagnostics = calibration_diagnostics(
            [(record.predicted_probability, record.observed) for record in group],
            bins=effective_bins,
        )
        results.append({"group": value, "n": len(group), "diagnostics": diagnostics})
    return results


def evaluate_study(
    records: list[StudyRecord],
    *,
    bins: int = 10,
    bootstrap: int = 1000,
    confidence: float = 0.95,
    seed: int = 42,
    split_mode: str = "none",
    cutoff: str | None = None,
    evaluation_sites: Iterable[str] = (),
    group_by: str = "site",
    bootstrap_unit: str = "record",
) -> dict[str, object]:
    if split_mode not in {"none", "temporal", "site-disjoint"}:
        raise ValueError("split_mode must be one of: none, temporal, site-disjoint")
    if group_by not in {"none", "site", "subgroup"}:
        raise ValueError("group_by must be one of: none, site, subgroup")

    result: dict[str, object] = {
        "study_schema_version": "1.0",
        "n": len(records),
        "bootstrap": {"repetitions": bootstrap, "confidence": confidence, "seed": seed, "unit": bootstrap_unit},
        "full_sample": _summary(
            records,
            bins=bins,
            bootstrap=bootstrap,
            confidence=confidence,
            seed=seed,
            bootstrap_unit=bootstrap_unit,
        ),
        "interpretation": (
            "Bootstrap intervals quantify sampling uncertainty under the selected resampling unit. "
            "Use site-level resampling when facilities are the independent sampling units."
        ),
    }
    if group_by != "none":
        result["subgroups"] = {"field": group_by, "groups": subgroup_diagnostics(records, group_by, bins=bins)}

    if split_mode == "temporal":
        if cutoff is None:
            raise ValueError("temporal split requires --cutoff")
        development, evaluation, split = temporal_split(records, cutoff)
    elif split_mode == "site-disjoint":
        development, evaluation, split = site_disjoint_split(records, evaluation_sites)
    else:
        development = evaluation = []
        split = {"mode": "none", "note": "No frozen development/evaluation partition requested."}

    result["split"] = split
    if split_mode != "none":
        result["development"] = _summary(
            development,
            bins=min(bins, max(2, len(development))),
            bootstrap=bootstrap,
            confidence=confidence,
            seed=seed,
            bootstrap_unit=bootstrap_unit,
        )
        result["evaluation"] = _summary(
            evaluation,
            bins=min(bins, max(2, len(evaluation))),
            bootstrap=bootstrap,
            confidence=confidence,
            seed=seed + 1,
            bootstrap_unit=bootstrap_unit,
        )
    return result


def render_study_markdown(result: dict[str, object]) -> str:
    full = result["full_sample"]
    diagnostics = full["diagnostics"]
    intervals = full["bootstrap_intervals"]
    lines = [
        "# OT-RiskLab Empirical Study Diagnostics",
        "",
        f"- Observations: **{result['n']}**",
        f"- Brier score: **{float(diagnostics['brier_score']):.4f}**",
        f"- Log loss: **{float(diagnostics['log_loss']):.4f}**",
        f"- Observed event rate: **{float(diagnostics['observed_rate']):.4f}**",
        f"- Mean predicted probability: **{float(diagnostics['predicted_mean']):.4f}**",
        "",
        "## Bootstrap confidence intervals",
        "",
        "| Metric | Estimate | Lower | Upper | Confidence |",
        "|---|---:|---:|---:|---:|",
    ]
    if intervals is None:
        lines.append("| unavailable | n/a | n/a | n/a | n/a |")
        if full.get("bootstrap_note"):
            lines.extend(["", str(full["bootstrap_note"])])
    else:
        for name, row in intervals.items():
            lines.append(
                f"| {name} | {float(row['estimate']):.4f} | {float(row['lower']):.4f} | "
                f"{float(row['upper']):.4f} | {float(row['confidence']):.3f} |"
            )

    split = result["split"]
    lines.extend(["", "## Validation partition", "", f"- Mode: **{split['mode']}**"])
    for key in (
        "cutoff",
        "development_n",
        "evaluation_n",
        "development_max_timestamp",
        "evaluation_min_timestamp",
        "temporal_order_valid",
        "development_sites",
        "evaluation_sites",
        "site_overlap",
        "site_disjoint_valid",
    ):
        if key in split:
            lines.append(f"- {key}: **{split[key]}**")
    if result.get("evaluation"):
        eval_diag = result["evaluation"]["diagnostics"]
        lines.extend(
            [
                "",
                "## Held-out evaluation diagnostics",
                "",
                f"- N: **{result['evaluation']['n']}**",
                f"- Brier score: **{float(eval_diag['brier_score']):.4f}**",
                f"- Log loss: **{float(eval_diag['log_loss']):.4f}**",
                f"- ECE: **{float(eval_diag['expected_calibration_error']):.4f}**",
            ]
        )

    subgroup_block = result.get("subgroups")
    if subgroup_block:
        lines.extend(
            [
                "",
                f"## Subgroup diagnostics by `{subgroup_block['field']}`",
                "",
                "| Group | N | Brier | Observed | Predicted |",
                "|---|---:|---:|---:|---:|",
            ]
        )
        for row in subgroup_block["groups"]:
            diag = row["diagnostics"]
            lines.append(
                f"| {row['group']} | {row['n']} | {float(diag['brier_score']):.4f} | "
                f"{float(diag['observed_rate']):.4f} | {float(diag['predicted_mean']):.4f} |"
            )
    lines.extend(["", str(result["interpretation"]), ""])
    return "\n".join(lines)
