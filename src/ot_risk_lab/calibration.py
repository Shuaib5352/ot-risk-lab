from __future__ import annotations

import csv
import json
import math
from pathlib import Path

from .models import AnalysisConfig
from .report import analyze

_EPSILON = 1e-15


def _unit_probability(value: float, field: str) -> float:
    value = float(value)
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{field} must be in [0, 1], got {value}")
    return value


def _binary(value: int | float | str, field: str = "observed") -> int:
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "y"}:
            return 1
        if normalized in {"0", "false", "no", "n"}:
            return 0
        raise ValueError(f"{field} must be binary (0/1), got {value!r}")
    integer = int(value)
    if float(value) != integer or integer not in (0, 1):
        raise ValueError(f"{field} must be binary (0/1), got {value!r}")
    return integer


def _wilson_interval(successes: int, n: int, z: float = 1.959963984540054) -> tuple[float, float]:
    if n <= 0:
        return (0.0, 1.0)
    p = successes / n
    z2 = z * z
    denominator = 1.0 + z2 / n
    center = (p + z2 / (2.0 * n)) / denominator
    half = z * math.sqrt((p * (1.0 - p) / n) + (z2 / (4.0 * n * n))) / denominator
    return (max(0.0, center - half), min(1.0, center + half))


def calibration_diagnostics(
    rows: list[tuple[float, int]],
    bins: int = 10,
) -> dict[str, object]:
    """Evaluate probabilistic predictions against binary observations.

    Intended for empirical validation of compromise probabilities. The function
    does not calibrate or refit the model; it only reports diagnostic metrics.
    """
    if bins < 2 or bins > 100:
        raise ValueError("bins must be between 2 and 100")
    if not rows:
        raise ValueError("calibration requires at least one observation")

    clean = [(_unit_probability(p, "predicted_probability"), _binary(y)) for p, y in rows]
    n = len(clean)
    predicted_mean = sum(p for p, _ in clean) / n
    successes = sum(y for _, y in clean)
    observed_rate = successes / n
    observed_ci = _wilson_interval(successes, n)
    brier = sum((p - y) ** 2 for p, y in clean) / n
    log_loss = -sum(
        y * math.log(max(_EPSILON, min(1.0 - _EPSILON, p)))
        + (1 - y) * math.log(max(_EPSILON, min(1.0 - _EPSILON, 1.0 - p)))
        for p, y in clean
    ) / n
    reference_brier = observed_rate * (1.0 - observed_rate)
    skill = None if reference_brier == 0.0 else 1.0 - (brier / reference_brier)

    grouped: list[list[tuple[float, int]]] = [[] for _ in range(bins)]
    for p, y in clean:
        index = min(int(p * bins), bins - 1)
        grouped[index].append((p, y))

    calibration_bins: list[dict[str, object]] = []
    weighted_gap = 0.0
    maximum_gap = 0.0
    for index, group in enumerate(grouped):
        if not group:
            continue
        count = len(group)
        mean_p = sum(p for p, _ in group) / count
        group_successes = sum(y for _, y in group)
        rate = group_successes / count
        gap = abs(mean_p - rate)
        low, high = _wilson_interval(group_successes, count)
        weighted_gap += (count / n) * gap
        maximum_gap = max(maximum_gap, gap)
        calibration_bins.append(
            {
                "bin": index + 1,
                "lower": index / bins,
                "upper": (index + 1) / bins,
                "count": count,
                "mean_predicted": mean_p,
                "observed_rate": rate,
                "observed_rate_wilson_95": [low, high],
                "absolute_gap": gap,
            }
        )

    return {
        "n": n,
        "predicted_mean": predicted_mean,
        "observed_rate": observed_rate,
        "observed_rate_wilson_95": list(observed_ci),
        "brier_score": brier,
        "log_loss": log_loss,
        "brier_skill_score_vs_base_rate": skill,
        "expected_calibration_error": weighted_gap,
        "maximum_calibration_error": maximum_gap,
        "bins": calibration_bins,
        "interpretation": (
            "Lower Brier score, log loss, ECE, and MCE indicate better probabilistic agreement. "
            "Calibration results are meaningful only for representative, independently observed outcomes."
        ),
    }


def load_calibration_csv(path: Path) -> list[tuple[float, int]]:
    """Load calibration observations.

    CSV accepts either `predicted_probability,observed` or `config,observed`.
    In the latter form, `config` is resolved relative to the CSV file and the
    predicted probability is generated from OT-RiskLab attack progression.
    """
    rows: list[tuple[float, int]] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = set(reader.fieldnames or ())
        if "observed" not in fields:
            raise ValueError("calibration CSV requires an 'observed' column")
        if "predicted_probability" not in fields and "config" not in fields:
            raise ValueError("calibration CSV requires 'predicted_probability' or 'config'")
        for line_number, row in enumerate(reader, start=2):
            observed = _binary(row.get("observed", ""), f"observed at line {line_number}")
            predicted_raw = (row.get("predicted_probability") or "").strip()
            if predicted_raw:
                predicted = _unit_probability(float(predicted_raw), f"predicted_probability at line {line_number}")
            else:
                config_name = (row.get("config") or "").strip()
                if not config_name:
                    raise ValueError(f"line {line_number}: missing predicted_probability and config")
                config_path = (path.parent / config_name).resolve()
                with config_path.open("r", encoding="utf-8") as config_handle:
                    raw = json.load(config_handle)
                config = AnalysisConfig.from_mapping(raw)
                predicted = float(analyze(config)["attack_progression"]["compromise_probability"])
            rows.append((predicted, observed))
    return rows


def render_calibration_markdown(result: dict[str, object]) -> str:
    skill = result["brier_skill_score_vs_base_rate"]
    skill_text = "n/a" if skill is None else f"{float(skill):.4f}"
    ci = result["observed_rate_wilson_95"]
    lines = [
        "# OT-RiskLab Calibration Diagnostics",
        "",
        f"- Observations: **{result['n']}**",
        f"- Mean predicted probability: **{float(result['predicted_mean']):.4f}**",
        f"- Observed event rate: **{float(result['observed_rate']):.4f}** (Wilson 95% CI {float(ci[0]):.4f}–{float(ci[1]):.4f})",
        f"- Brier score: **{float(result['brier_score']):.4f}**",
        f"- Log loss: **{float(result['log_loss']):.4f}**",
        f"- Brier skill score vs base rate: **{skill_text}**",
        f"- Expected calibration error: **{float(result['expected_calibration_error']):.4f}**",
        f"- Maximum calibration error: **{float(result['maximum_calibration_error']):.4f}**",
        "",
        "| Bin | Range | N | Mean predicted | Observed | Wilson 95% CI | Gap |",
        "|---:|---|---:|---:|---:|---|---:|",
    ]
    for row in result["bins"]:
        bin_ci = row["observed_rate_wilson_95"]
        lines.append(
            f"| {row['bin']} | {float(row['lower']):.2f}–{float(row['upper']):.2f} | {row['count']} | "
            f"{float(row['mean_predicted']):.4f} | {float(row['observed_rate']):.4f} | "
            f"{float(bin_ci[0]):.4f}–{float(bin_ci[1]):.4f} | {float(row['absolute_gap']):.4f} |"
        )
    lines.extend(["", str(result["interpretation"]), ""])
    return "\n".join(lines)
