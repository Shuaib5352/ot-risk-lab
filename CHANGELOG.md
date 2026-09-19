# Changelog

## 0.7.0 - 2026-09-19

### Added

- Bundled analysis JSON Schema and `ot-risk-lab schema` for installed integrations.
- Offline `ot-risk-lab doctor` diagnostics for Python, schema, parser, and filesystem readiness.
- CodeMeta 3.1 software metadata.
- Non-root Docker image and container usage documentation.
- Release metadata consistency checker across package, citation, README, and CodeMeta versions.
- Minimal CycloneDX 1.6 SBOM generation for the dependency-free core package.
- Quick-start, citation, release-process, container, and publication-readiness documentation.
- Maintainer Makefile for repeatable local quality and release commands.

### Quality

- Packaged schema is tested against the repository schema to prevent drift.
- CI smoke tests now cover `doctor`, `schema`, and release metadata consistency.
- Release workflow emits an SBOM alongside Python distributions and checksums.
- Core risk equations and v0.6 empirical-study semantics are unchanged.
- Normalized Ruff formatting and explicit `zip(..., strict=True)` compatibility checks; no model equations or benchmark values changed.

## 0.6.0 - 2026-09-19

### Added

- Empirical study diagnostics with bootstrap confidence intervals for calibration metrics.
- Record-level and site-level cluster bootstrap modes.
- Explicit temporal and site-disjoint validation partitions with leakage checks.
- Site/subgroup diagnostics without silent population pooling.
- Nominal Krippendorff alpha, pairwise agreement, unanimity, and bootstrap intervals for analyst ratings.
- Frozen experiment manifests with SHA-256 hashes, methodology versions, and parameters.
- Deterministic supplementary ZIP creation and integrity verification.
- Empirical-study, agreement, experiment-manifest, and supplementary-package documentation and examples.

### Quality

- Added regression tests for study splitting, bootstrap reproducibility, analyst agreement, manifest tamper detection, deterministic bundles, and new CLI workflows.
- Preserved the v0.5 analysis output schema and core risk-engine calculations.

## 0.5.0 - Validation & Evidence

- Added regression benchmark manifests and drift detection with explicit exit status.
- Added one-at-a-time control and deterministic-factor ablation reports.
- Added empirical probability-calibration diagnostics: Brier score, log loss, Brier skill score, ECE, MCE, calibration bins, and Wilson 95% intervals.
- Added optional public evidence retrieval from FIRST EPSS, CISA KEV, and NVD CVE API 2.0 without silently modifying scenario inputs.
- Added deterministic model signatures and environment provenance artifacts.
- Added validation, evidence-source, and reproducibility documentation.
- Expanded CLI and automated tests for the new research-validation workflow.

All notable changes are documented here.

## [0.4.0] - 2026-09-19

### Added

- Assessment metadata for traceable risk records.
- CVE identifiers, EPSS probability/percentile, CISA KEV status, evidence date, and likelihood-basis provenance.
- Explicit validation of ATT&CK technique IDs and CVE identifiers.
- Control implementation completeness, evidence notes, references, and optional control IDs.
- Organization-defined risk tolerance with Monte Carlo exceedance probability and mean excess above tolerance.
- Standalone dependency-free HTML reports for single analyses, portfolios, and scenario comparisons.
- `register` command for CSV/Markdown/JSON risk-register generation.
- `validate --strict` and JSON validation output for governance/CI workflows.
- Documentation for vulnerability evidence, model governance, operational workflows, and the data dictionary.
- Typed-package marker (`py.typed`).

### Changed

- Modeled control strength is now `effectiveness × coverage × confidence × implementation`.
- Report schema advanced to 3.0 and portfolio schema to 2.0.
- Portfolio exports now include vulnerability evidence and tolerance status.
- Model-quality warnings now cover confirmed exploitation, partial implementation, missing control evidence, and tolerance exceedance.
- Configuration JSON Schema is stricter and covers all major model sections.

### Methodological safeguard

- EPSS remains a calibrated exploitation-probability input/evidence field and is never multiplied by CVSS.
- CISA KEV remains confirmed-exploitation evidence and does not receive an invented numeric uplift.

## [0.3.0] - 2026-09-19

### Added

- Baseline-versus-candidate scenario comparison for before/after control analysis.
- CSV portfolio export for spreadsheet and GRC workflows.
- Modeled-control coverage summary across the six NIST CSF 2.0 Functions.
- Non-blocking model-quality warnings for uncertainty, mitigation, confidence, exposure, and OT consequence conditions.
- Normalized deterministic driver shares and top-driver reporting.
- Starter-configuration generator via `ot-risk-lab template`.
- Richer portfolio summary metrics and warning counts.

## [0.2.0] - 2026-09-19

### Added

- OT-specific safety and availability consequence factors.
- Parameterized vulnerability and consequence weight groups.
- Multi-control mitigation model with effectiveness, coverage, confidence, and CSF Function labels.
- Fixed, truncated-normal, and triangular uncertainty modes.
- Per-factor uncertainty overrides.
- Spearman rank sensitivity analysis.
- Configurable Markov transition parameters and expected compromise step within the modeled horizon.
- Stable SHA-256 configuration fingerprints.
- Markdown reports and multi-scenario batch/portfolio reporting.
- JSON Schema, prior-art/provenance documentation, scientific validation plan, and software-paper draft.
- CodeQL workflow.

## [0.1.0] - 2026-09-19

- Initial auditable research-software core with deterministic risk, Monte Carlo analysis, Markov attack progression, CLI, tests, and citation metadata.
