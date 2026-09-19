# Quick start

OT-RiskLab is a command-line research tool. The core package has no runtime third-party dependencies.

## Install from source

```bash
python -m venv .venv
source .venv/bin/activate  # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install .
```

Confirm the installation:

```bash
ot-risk-lab --version
ot-risk-lab doctor
ot-risk-lab schema -o analysis-config.schema.json
```

## First analysis

```bash
ot-risk-lab template -o scenario.json
ot-risk-lab validate scenario.json
ot-risk-lab analyze scenario.json --format html -o report.html
```

The starter file is intentionally illustrative. Replace its assumptions with documented, reviewable evidence before using results for decision support.

## Portfolio workflow

```bash
ot-risk-lab batch examples/scenarios --format csv -o portfolio.csv
ot-risk-lab register examples/scenarios --format csv -o risk-register.csv
```

## Reproducible research workflow

```bash
ot-risk-lab provenance examples/demo_config.json -o provenance.json
ot-risk-lab benchmark examples/benchmark_suite.json -o benchmark.json
ot-risk-lab manifest examples/study_observations.csv --base-dir examples -o experiment-manifest.json
ot-risk-lab supplement examples/study_observations.csv docs/empirical-study.md -o supplement.zip
ot-risk-lab verify-bundle supplement.zip
```

## Container use

See [`container.md`](container.md) for a non-root Docker workflow.
