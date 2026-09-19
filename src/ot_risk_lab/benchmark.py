from __future__ import annotations

import json
from pathlib import Path

from .models import AnalysisConfig
from .report import analyze


def _lookup(data: object, dotted_path: str) -> object:
    current = data
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            raise KeyError(f"benchmark metric path not found: {dotted_path}")
        current = current[part]
    return current


def run_benchmark_manifest(path: Path) -> dict[str, object]:
    """Run regression benchmarks defined by a JSON manifest."""
    with path.open("r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    if not isinstance(manifest, dict):
        raise ValueError("benchmark manifest must be a JSON object")
    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("benchmark manifest requires a non-empty 'cases' list")
    default_tolerance = float(manifest.get("absolute_tolerance", 1e-6))
    if default_tolerance < 0:
        raise ValueError("absolute_tolerance must be non-negative")

    case_results: list[dict[str, object]] = []
    all_passed = True
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("each benchmark case must be an object")
        name = str(case.get("name") or case.get("config") or "unnamed")
        config_name = str(case.get("config") or "").strip()
        expected = case.get("expected")
        if not config_name or not isinstance(expected, dict) or not expected:
            raise ValueError(f"benchmark case {name!r} requires config and expected metrics")
        tolerance = float(case.get("absolute_tolerance", default_tolerance))
        config_path = (path.parent / config_name).resolve()
        with config_path.open("r", encoding="utf-8") as handle:
            config_raw = json.load(handle)
        result = analyze(AnalysisConfig.from_mapping(config_raw))
        metrics: list[dict[str, object]] = []
        case_passed = True
        for metric_path, expected_value in expected.items():
            actual_value = _lookup(result, str(metric_path))
            if isinstance(expected_value, bool) or not isinstance(expected_value, (int, float)):
                passed = actual_value == expected_value
                absolute_error = None
            else:
                actual_numeric = float(actual_value)
                expected_numeric = float(expected_value)
                absolute_error = abs(actual_numeric - expected_numeric)
                passed = absolute_error <= tolerance
            metrics.append(
                {
                    "metric": metric_path,
                    "expected": expected_value,
                    "actual": actual_value,
                    "absolute_error": absolute_error,
                    "tolerance": tolerance,
                    "passed": passed,
                }
            )
            case_passed = case_passed and passed
        case_results.append(
            {
                "name": name,
                "config": str(config_path),
                "passed": case_passed,
                "metrics": metrics,
            }
        )
        all_passed = all_passed and case_passed

    return {
        "suite": str(manifest.get("suite", path.stem)),
        "passed": all_passed,
        "case_count": len(case_results),
        "cases": case_results,
        "note": "Regression benchmarks detect computational drift; they do not establish empirical validity.",
    }


def render_benchmark_markdown(result: dict[str, object]) -> str:
    lines = [
        "# OT-RiskLab Benchmark Report",
        "",
        f"- Suite: **{result['suite']}**",
        f"- Overall: **{'PASS' if result['passed'] else 'FAIL'}**",
        f"- Cases: **{result['case_count']}**",
        "",
    ]
    for case in result["cases"]:
        lines.extend(
            [
                f"## {case['name']} — {'PASS' if case['passed'] else 'FAIL'}",
                "",
                "| Metric | Expected | Actual | Abs. error | Tol. | Status |",
                "|---|---:|---:|---:|---:|---|",
            ]
        )
        for row in case["metrics"]:
            error = "—" if row["absolute_error"] is None else f"{float(row['absolute_error']):.8g}"
            lines.append(
                f"| {row['metric']} | {row['expected']} | {row['actual']} | {error} | "
                f"{float(row['tolerance']):.8g} | {'PASS' if row['passed'] else 'FAIL'} |"
            )
        lines.append("")
    lines.extend([str(result["note"]), ""])
    return "\n".join(lines)
