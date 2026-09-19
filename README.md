# OT-RiskLab

**Transparent, reproducible cyber-risk modeling for Industrial Control Systems (ICS) and Operational Technology (OT).**

OT-RiskLab is dependency-light research software for engineers, defenders, analysts, students, and researchers who need an auditable way to examine how **threat likelihood, vulnerability context, OT consequences, controls, uncertainty, exploitation evidence, and attack progression** interact.

> **Current release: v0.7.0 research beta.** The package is intended for research, teaching, method comparison, structured risk-register work, and decision-support experiments. It is not a certified safety tool, and its reference coefficients are not claimed to be universal incident probabilities.

## What the project does

OT-RiskLab deliberately keeps assumptions visible instead of hiding them inside one opaque score:

- separates susceptibility/vulnerability from consequence;
- represents OT-specific safety and availability consequences;
- models controls with **effectiveness × coverage × confidence × implementation**;
- propagates uncertainty with reproducible Monte Carlo simulation;
- calculates P05/P50/P95 and Spearman sensitivity;
- supports organization-defined risk tolerance and **P(simulated risk > tolerance)**;
- uses a configurable four-state Markov attack-progression model;
- records MITRE ATT&CK for ICS technique IDs;
- records CVE, EPSS, and CISA KEV evidence **without multiplying EPSS by CVSS**;
- produces JSON, Markdown, CSV, and standalone HTML reports;
- builds portfolio summaries and a practical risk register;
- compares before/after control scenarios;
- records assessment metadata, stable SHA-256 configuration fingerprints, and model signatures;
- runs regression benchmarks to detect numerical drift;
- performs control/factor ablation and counterfactual analysis;
- evaluates probability calibration with Brier score, log loss, ECE/MCE, and Wilson intervals;
- optionally retrieves reviewable CVE evidence from FIRST EPSS, CISA KEV, and NVD;
- evaluates empirical studies with record- or site-level bootstrap confidence intervals;
- supports explicit temporal and site-disjoint held-out validation partitions;
- quantifies subjective analyst consistency with nominal Krippendorff alpha;
- freezes experiment file hashes and parameters into reproducibility manifests;
- creates deterministic, checksummed supplementary ZIP packages;
- exposes the configuration JSON Schema from an installed package;
- includes offline installation diagnostics, release consistency checks, CodeMeta metadata, and a non-root Docker path;
- has zero runtime dependencies in the core package.

## Quick start

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1

pip install -e .
ot-risk-lab doctor
ot-risk-lab schema -o analysis-config.schema.json
ot-risk-lab template -o my-scenario.json
ot-risk-lab validate my-scenario.json
ot-risk-lab analyze my-scenario.json --format html -o report.html
```

Other useful commands:

```bash
ot-risk-lab analyze examples/demo_config.json --format markdown -o results/demo.md
ot-risk-lab batch examples/scenarios --format csv -o results/portfolio.csv
ot-risk-lab batch examples/scenarios --format html -o results/portfolio.html
ot-risk-lab register examples/scenarios --format csv -o results/risk-register.csv
ot-risk-lab compare examples/before_controls.json examples/after_controls.json --format html -o results/comparison.html
ot-risk-lab validate examples/demo_config.json --strict
ot-risk-lab ablate examples/demo_config.json --format markdown -o results/ablation.md
ot-risk-lab benchmark examples/benchmark_suite.json --format markdown -o results/benchmark.md
ot-risk-lab provenance examples/demo_config.json -o results/provenance.json
ot-risk-lab study examples/study_observations.csv --split-mode site-disjoint --evaluation-sites Plant-C --format markdown -o results/study.md
ot-risk-lab agreement examples/analyst_ratings.csv --format markdown -o results/agreement.md
ot-risk-lab manifest examples/study_observations.csv --base-dir examples --parameter split=site-disjoint -o results/experiment-manifest.json
ot-risk-lab supplement examples/study_observations.csv examples/analyst_ratings.csv docs/empirical-study.md -o results/supplement.zip
ot-risk-lab verify-bundle results/supplement.zip
```

Without installing:

```bash
PYTHONPATH=src python -m ot_risk_lab analyze examples/demo_config.json --format json
```

## Mathematical core

The reference susceptibility component is

\[
V = w_c\frac{CVSS}{10} + w_eE + w_gG,
\]

and the consequence component is

\[
C = w_iI + w_kK + w_sS + w_aA.
\]

Default weights are visible, configurable, and sum to one within each component. Inherent risk is

\[
R_{inherent}=100\,L\,V\,C.
\]

A control contributes modeled strength

\[
s_i=e_i c_i q_i m_i,
\]

where `e` is nominal effectiveness, `c` coverage, `q` confidence, and `m` implementation completeness. Under the documented independent-residual assumption,

\[
M = 1-(1-M_0)\prod_i(1-s_i),
\]

and

\[
R_{residual}=R_{inherent}(1-M).
\]

The defaults are **reference parameters**, not normative NIST, IEC, FIRST, CISA, or MITRE weights.

See [`docs/methodology.md`](docs/methodology.md).

## Vulnerability evidence: CVSS, EPSS, and KEV

OT-RiskLab preserves different evidence types as different concepts:

- **CVSS**: vulnerability severity/context input to the reference susceptibility model.
- **EPSS**: optional forward-looking 30-day exploitation probability. If `likelihood_basis="epss-30d"`, the scenario likelihood must equal the supplied EPSS probability.
- **CISA KEV**: boolean confirmed-exploitation evidence used as a workflow warning/flag; it is not converted into an invented probability.

This avoids the statistically invalid shortcut of multiplying a calibrated EPSS probability by an ordinal CVSS score. v0.7 can also retrieve a **separate, reviewable evidence snapshot** from FIRST EPSS, CISA KEV, and the NVD CVE API without silently changing a scenario. See [`docs/vulnerability-evidence.md`](docs/vulnerability-evidence.md) and [`docs/evidence-sources.md`](docs/evidence-sources.md).

## Organization-defined tolerance

If `decision.risk_tolerance` is supplied, the report includes:

- deterministic within/above-tolerance status;
- Monte Carlo probability that residual risk exceeds tolerance;
- mean excess above tolerance when exceedance occurs.

The tolerance is **your organization's criterion**, not a threshold claimed by OT-RiskLab.

## Practical outputs

A single-scenario report includes:

- inherent and residual risk;
- transparent decomposition and top drivers;
- control evidence and implementation state;
- Monte Carlo interval statistics and sensitivity;
- tolerance exceedance probability;
- attack-state transition matrix and compromise probability;
- CVE/EPSS/KEV evidence fields;
- CSF Function coverage of modeled controls;
- model-quality warnings;
- stable configuration fingerprint.

The `register` command converts multiple scenarios into a risk register for spreadsheet/GRC workflows.

For empirical validation, `study` reports bootstrap uncertainty, subgroup metrics, and explicitly frozen temporal or site-disjoint partitions. Use `--bootstrap-unit site` when facilities rather than individual rows are the independent sampling units. `agreement` quantifies analyst consistency without treating agreement as evidence of correctness.

## Standards context

OT-RiskLab is designed to be used alongside, not as a replacement for:

- NIST Cybersecurity Framework 2.0;
- NIST SP 800-82 Rev. 3, *Guide to Operational Technology (OT) Security*;
- MITRE ATT&CK for ICS;
- FIRST EPSS;
- CISA Known Exploited Vulnerabilities Catalog.

The package does **not** claim NIST, IEC, MITRE, FIRST, or CISA certification/conformance.

## Verification and model governance

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
python -m compileall -q src tests
```

Automated tests cover bounds, monotonicity, probability conservation, deterministic seeds, evidence validation, tolerance exceedance, report generation, CLI behavior, and risk-register construction. Software verification is intentionally separated from empirical model validation.

See:

- [`docs/validation-plan.md`](docs/validation-plan.md)
- [`docs/validation-framework.md`](docs/validation-framework.md)
- [`docs/model-governance.md`](docs/model-governance.md)
- [`docs/operational-workflow.md`](docs/operational-workflow.md)
- [`docs/reproducibility.md`](docs/reproducibility.md)
- [`docs/empirical-study.md`](docs/empirical-study.md)
- [`docs/interrater-agreement.md`](docs/interrater-agreement.md)
- [`docs/experiment-manifests.md`](docs/experiment-manifests.md)
- [`docs/supplementary-packages.md`](docs/supplementary-packages.md)
- [`VALIDATION.md`](VALIDATION.md)

## Distribution, citation, and publication

The repository includes a non-root Docker image, packaged JSON Schema access, release-consistency checks, `CITATION.cff`, and CodeMeta 3.1 metadata. See [`docs/quickstart.md`](docs/quickstart.md), [`docs/container.md`](docs/container.md), [`docs/citation.md`](docs/citation.md), and [`docs/publication-readiness.md`](docs/publication-readiness.md). An early software-paper draft is maintained in [`paper/paper.md`](paper/paper.md). Public tagged releases can later be archived in Zenodo for version-specific DOIs.

## License and responsible use

MIT License. OT-RiskLab is defensive decision-support software. It does not scan networks, exploit devices, generate payloads, or automate offensive actions. Site-specific safety, reliability, legal, regulatory, and engineering review remains the user's responsibility.
