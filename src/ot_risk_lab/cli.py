from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .ablation import render_ablation_markdown, run_ablation
from .agreement import agreement_diagnostics, load_ratings_csv, render_agreement_markdown
from .benchmark import render_benchmark_markdown, run_benchmark_manifest
from .bundle import build_supplement_bundle, verify_supplement_bundle
from .calibration import calibration_diagnostics, load_calibration_csv, render_calibration_markdown
from .comparison import compare_configs, render_comparison_html, render_comparison_markdown
from .doctor import render_diagnostics_text, runtime_diagnostics
from .evidence_sources import EvidenceSourceError, collect_vulnerability_evidence, render_evidence_markdown
from .manifest import build_experiment_manifest, verify_experiment_manifest
from .models import AnalysisConfig
from .portfolio import analyze_portfolio, render_portfolio_csv, render_portfolio_html, render_portfolio_markdown
from .posture import model_quality_warnings
from .provenance import config_fingerprint, environment_provenance
from .register import build_risk_register, render_risk_register_csv, render_risk_register_markdown
from .report import analyze, render_html, render_markdown
from .schema import analysis_config_schema_text
from .study import evaluate_study, load_study_csv, render_study_markdown
from .templates import starter_config
from .version import SOFTWARE_VERSION


def _load_config(path: Path) -> AnalysisConfig:
    with path.open("r", encoding="utf-8") as handle:
        raw = json.load(handle)
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: top-level JSON value must be an object")
    return AnalysisConfig.from_mapping(raw)


def _write_or_print(rendered: str, output: Path | None) -> None:
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")


def _expand_inputs(paths: list[Path]) -> list[Path]:
    expanded: list[Path] = []
    for path in paths:
        if path.is_dir():
            expanded.extend(sorted(path.glob("*.json")))
        else:
            expanded.append(path)
    unique: list[Path] = []
    seen: set[Path] = set()
    for path in expanded:
        resolved = path.resolve()
        if resolved not in seen:
            seen.add(resolved)
            unique.append(path)
    return unique


def _json(data: object) -> str:
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _render_analysis(data: dict[str, object], fmt: str) -> str:
    if fmt == "json":
        return _json(data)
    if fmt == "markdown":
        return render_markdown(data) + "\n"
    if fmt == "html":
        return render_html(data) + "\n"
    raise ValueError(f"unsupported output format: {fmt}")


def _render_portfolio(data: dict[str, object], fmt: str) -> str:
    if fmt == "json":
        return _json(data)
    if fmt == "markdown":
        return render_portfolio_markdown(data) + "\n"
    if fmt == "csv":
        return render_portfolio_csv(data)
    if fmt == "html":
        return render_portfolio_html(data) + "\n"
    raise ValueError(f"unsupported output format: {fmt}")


def _render_comparison(data: dict[str, object], fmt: str) -> str:
    if fmt == "json":
        return _json(data)
    if fmt == "markdown":
        return render_comparison_markdown(data) + "\n"
    if fmt == "html":
        return render_comparison_html(data) + "\n"
    raise ValueError(f"unsupported output format: {fmt}")


def _render_register(data: dict[str, object], fmt: str) -> str:
    if fmt == "json":
        return _json(data)
    if fmt == "markdown":
        return render_risk_register_markdown(data)
    if fmt == "csv":
        return render_risk_register_csv(data)
    raise ValueError(f"unsupported output format: {fmt}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ot-risk-lab",
        description="Transparent, reproducible ICS/OT cyber-risk analysis.",
    )
    parser.add_argument("--version", action="version", version=f"OT-RiskLab {SOFTWARE_VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze_cmd = sub.add_parser("analyze", help="Analyze one JSON scenario")
    analyze_cmd.add_argument("config", type=Path)
    analyze_cmd.add_argument("--format", choices=("json", "markdown", "html"), default="json")
    analyze_cmd.add_argument("--output", "-o", type=Path)

    validate_cmd = sub.add_parser("validate", help="Validate one JSON scenario and exit")
    validate_cmd.add_argument("config", type=Path)
    validate_cmd.add_argument("--strict", action="store_true", help="Return exit code 3 when warning-severity quality issues exist")
    validate_cmd.add_argument("--format", choices=("text", "json"), default="text")

    batch_cmd = sub.add_parser("batch", help="Analyze multiple JSON files or directories")
    batch_cmd.add_argument("inputs", nargs="+", type=Path)
    batch_cmd.add_argument("--format", choices=("json", "markdown", "csv", "html"), default="json")
    batch_cmd.add_argument("--output", "-o", type=Path)

    compare_cmd = sub.add_parser("compare", help="Compare baseline and candidate JSON scenarios")
    compare_cmd.add_argument("baseline", type=Path)
    compare_cmd.add_argument("candidate", type=Path)
    compare_cmd.add_argument("--format", choices=("json", "markdown", "html"), default="json")
    compare_cmd.add_argument("--output", "-o", type=Path)

    register_cmd = sub.add_parser("register", help="Build a risk register from JSON scenarios")
    register_cmd.add_argument("inputs", nargs="+", type=Path)
    register_cmd.add_argument("--format", choices=("json", "markdown", "csv"), default="csv")
    register_cmd.add_argument("--output", "-o", type=Path)

    ablate_cmd = sub.add_parser("ablate", help="Run control and factor counterfactual ablations")
    ablate_cmd.add_argument("config", type=Path)
    ablate_cmd.add_argument("--format", choices=("json", "markdown"), default="json")
    ablate_cmd.add_argument("--output", "-o", type=Path)

    benchmark_cmd = sub.add_parser("benchmark", help="Run a regression benchmark manifest")
    benchmark_cmd.add_argument("manifest", type=Path)
    benchmark_cmd.add_argument("--format", choices=("json", "markdown"), default="json")
    benchmark_cmd.add_argument("--output", "-o", type=Path)

    calibrate_cmd = sub.add_parser("calibrate", help="Evaluate probability calibration against observed outcomes")
    calibrate_cmd.add_argument("observations", type=Path, help="CSV with observed plus predicted_probability or config")
    calibrate_cmd.add_argument("--bins", type=int, default=10)
    calibrate_cmd.add_argument("--format", choices=("json", "markdown"), default="json")
    calibrate_cmd.add_argument("--output", "-o", type=Path)

    evidence_cmd = sub.add_parser("evidence", help="Retrieve public CVE evidence from FIRST, CISA, and NVD")
    evidence_cmd.add_argument("cves", nargs="+", help="CVE identifiers")
    evidence_cmd.add_argument("--no-epss", action="store_true")
    evidence_cmd.add_argument("--no-kev", action="store_true")
    evidence_cmd.add_argument("--no-nvd", action="store_true")
    evidence_cmd.add_argument("--timeout", type=float, default=15.0)
    evidence_cmd.add_argument("--strict-sources", action="store_true", help="Fail if any selected evidence source is unavailable")
    evidence_cmd.add_argument("--format", choices=("json", "markdown"), default="json")
    evidence_cmd.add_argument("--output", "-o", type=Path)

    provenance_cmd = sub.add_parser("provenance", help="Emit environment and model provenance for a scenario")
    provenance_cmd.add_argument("config", type=Path)
    provenance_cmd.add_argument("--output", "-o", type=Path)

    study_cmd = sub.add_parser("study", help="Evaluate empirical probability observations with bootstrap and leakage-aware splits")
    study_cmd.add_argument("observations", type=Path, help="CSV with predicted_probability, observed, and optional site/timestamp/subgroup")
    study_cmd.add_argument("--bins", type=int, default=10)
    study_cmd.add_argument("--bootstrap", type=int, default=1000)
    study_cmd.add_argument("--confidence", type=float, default=0.95)
    study_cmd.add_argument("--seed", type=int, default=42)
    study_cmd.add_argument("--bootstrap-unit", choices=("record", "site"), default="record")
    study_cmd.add_argument("--split-mode", choices=("none", "temporal", "site-disjoint"), default="none")
    study_cmd.add_argument("--cutoff", help="ISO-8601 cutoff for temporal split")
    study_cmd.add_argument("--evaluation-sites", nargs="*", default=[])
    study_cmd.add_argument("--group-by", choices=("none", "site", "subgroup"), default="site")
    study_cmd.add_argument("--format", choices=("json", "markdown"), default="json")
    study_cmd.add_argument("--output", "-o", type=Path)

    agreement_cmd = sub.add_parser("agreement", help="Measure inter-rater consistency for subjective analyst ratings")
    agreement_cmd.add_argument("ratings", type=Path, help="CSV with item_id, analyst, rating")
    agreement_cmd.add_argument("--bootstrap", type=int, default=1000)
    agreement_cmd.add_argument("--confidence", type=float, default=0.95)
    agreement_cmd.add_argument("--seed", type=int, default=42)
    agreement_cmd.add_argument("--format", choices=("json", "markdown"), default="json")
    agreement_cmd.add_argument("--output", "-o", type=Path)

    manifest_cmd = sub.add_parser("manifest", help="Freeze file hashes and experiment parameters into a reproducibility manifest")
    manifest_cmd.add_argument("inputs", nargs="+", type=Path)
    manifest_cmd.add_argument("--label", default="")
    manifest_cmd.add_argument("--parameter", action="append", default=[], help="Experiment parameter as key=value; repeatable")
    manifest_cmd.add_argument("--base-dir", type=Path)
    manifest_cmd.add_argument("--output", "-o", type=Path, required=True)

    verify_manifest_cmd = sub.add_parser("verify-manifest", help="Verify an experiment manifest against current files")
    verify_manifest_cmd.add_argument("manifest", type=Path)
    verify_manifest_cmd.add_argument("--base-dir", type=Path)
    verify_manifest_cmd.add_argument("--output", "-o", type=Path)

    supplement_cmd = sub.add_parser("supplement", help="Create a deterministic, checksummed supplementary ZIP")
    supplement_cmd.add_argument("inputs", nargs="+", type=Path)
    supplement_cmd.add_argument("--label", default="")
    supplement_cmd.add_argument("--output", "-o", type=Path, required=True)

    verify_bundle_cmd = sub.add_parser("verify-bundle", help="Verify checksums and archive safety for a supplementary ZIP")
    verify_bundle_cmd.add_argument("bundle", type=Path)
    verify_bundle_cmd.add_argument("--output", "-o", type=Path)

    schema_cmd = sub.add_parser("schema", help="Print or write the bundled analysis JSON Schema")
    schema_cmd.add_argument("--output", "-o", type=Path)

    doctor_cmd = sub.add_parser("doctor", help="Run offline installation and environment diagnostics")
    doctor_cmd.add_argument("--format", choices=("text", "json"), default="text")
    doctor_cmd.add_argument("--output", "-o", type=Path)

    template_cmd = sub.add_parser("template", help="Write a starter JSON configuration")
    template_cmd.add_argument("--output", "-o", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "validate":
            config = _load_config(args.config)
            warnings = [x for x in model_quality_warnings(config) if x["severity"] == "warning"]
            payload = {
                "valid": True,
                "asset": config.asset.name,
                "threat": config.threat.name,
                "warning_count": len(warnings),
                "warnings": warnings,
                "fingerprint": config_fingerprint(config),
            }
            if args.format == "json":
                print(json.dumps(payload, indent=2, ensure_ascii=False))
            else:
                print(f"VALID: {config.asset.name} / {config.threat.name} | warnings={len(warnings)}")
            if args.strict and warnings:
                return 3
            return 0

        if args.command == "analyze":
            _write_or_print(_render_analysis(analyze(_load_config(args.config)), args.format), args.output)
            return 0

        if args.command == "batch":
            paths = _expand_inputs(args.inputs)
            if not paths:
                raise ValueError("no JSON scenario files found")
            named = [(str(path), _load_config(path)) for path in paths]
            _write_or_print(_render_portfolio(analyze_portfolio(named), args.format), args.output)
            return 0

        if args.command == "compare":
            result = compare_configs(_load_config(args.baseline), _load_config(args.candidate))
            _write_or_print(_render_comparison(result, args.format), args.output)
            return 0

        if args.command == "register":
            paths = _expand_inputs(args.inputs)
            if not paths:
                raise ValueError("no JSON scenario files found")
            named = [(str(path), _load_config(path)) for path in paths]
            _write_or_print(_render_register(build_risk_register(named), args.format), args.output)
            return 0

        if args.command == "ablate":
            result = run_ablation(_load_config(args.config))
            rendered = _json(result) if args.format == "json" else render_ablation_markdown(result) + "\n"
            _write_or_print(rendered, args.output)
            return 0

        if args.command == "benchmark":
            result = run_benchmark_manifest(args.manifest)
            rendered = _json(result) if args.format == "json" else render_benchmark_markdown(result) + "\n"
            _write_or_print(rendered, args.output)
            return 0 if result["passed"] else 4

        if args.command == "calibrate":
            result = calibration_diagnostics(load_calibration_csv(args.observations), bins=args.bins)
            rendered = _json(result) if args.format == "json" else render_calibration_markdown(result) + "\n"
            _write_or_print(rendered, args.output)
            return 0

        if args.command == "evidence":
            result = collect_vulnerability_evidence(
                args.cves,
                include_epss=not args.no_epss,
                include_kev=not args.no_kev,
                include_nvd=not args.no_nvd,
                timeout=args.timeout,
                strict_sources=args.strict_sources,
            )
            rendered = _json(result) if args.format == "json" else render_evidence_markdown(result) + "\n"
            _write_or_print(rendered, args.output)
            return 0

        if args.command == "provenance":
            _write_or_print(_json(environment_provenance(_load_config(args.config))), args.output)
            return 0

        if args.command == "study":
            result = evaluate_study(
                load_study_csv(args.observations),
                bins=args.bins,
                bootstrap=args.bootstrap,
                confidence=args.confidence,
                seed=args.seed,
                split_mode=args.split_mode,
                cutoff=args.cutoff,
                evaluation_sites=args.evaluation_sites,
                group_by=args.group_by,
                bootstrap_unit=args.bootstrap_unit,
            )
            rendered = _json(result) if args.format == "json" else render_study_markdown(result) + "\n"
            _write_or_print(rendered, args.output)
            return 0

        if args.command == "agreement":
            result = agreement_diagnostics(
                load_ratings_csv(args.ratings),
                bootstrap=args.bootstrap,
                confidence=args.confidence,
                seed=args.seed,
            )
            rendered = _json(result) if args.format == "json" else render_agreement_markdown(result) + "\n"
            _write_or_print(rendered, args.output)
            return 0

        if args.command == "manifest":
            parameters: dict[str, str] = {}
            for item in args.parameter:
                if "=" not in item:
                    raise ValueError("--parameter must use key=value syntax")
                key, value = item.split("=", 1)
                key = key.strip()
                if not key:
                    raise ValueError("--parameter key must not be empty")
                parameters[key] = value.strip()
            result = build_experiment_manifest(
                args.inputs,
                label=args.label,
                parameters=parameters,
                base_dir=args.base_dir,
            )
            _write_or_print(_json(result), args.output)
            return 0

        if args.command == "verify-manifest":
            result = verify_experiment_manifest(args.manifest, base_dir=args.base_dir)
            _write_or_print(_json(result), args.output)
            return 0 if result["passed"] else 5

        if args.command == "supplement":
            result = build_supplement_bundle(args.inputs, args.output, label=args.label)
            print(_json(result), end="")
            return 0

        if args.command == "verify-bundle":
            result = verify_supplement_bundle(args.bundle)
            _write_or_print(_json(result), args.output)
            return 0 if result["passed"] else 6

        if args.command == "schema":
            _write_or_print(analysis_config_schema_text(), args.output)
            return 0

        if args.command == "doctor":
            result = runtime_diagnostics()
            rendered = _json(result) if args.format == "json" else render_diagnostics_text(result)
            _write_or_print(rendered, args.output)
            return 0 if result["passed"] else 7

        if args.command == "template":
            _write_or_print(json.dumps(starter_config(), indent=2, ensure_ascii=False) + "\n", args.output)
            return 0

        raise AssertionError("unreachable")
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, EvidenceSourceError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
