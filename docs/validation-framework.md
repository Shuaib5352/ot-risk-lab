# Validation and drift-detection framework

OT-RiskLab separates **software verification**, **computational regression testing**, and **empirical validation**. They answer different questions and must not be conflated.

## 1. Software verification

Unit tests, static checks, package builds, and deterministic seeds establish that the implementation behaves as specified. They do **not** prove that default risk coefficients predict real incidents.

## 2. Regression benchmarks

`ot-risk-lab benchmark` executes a manifest of fixed scenarios and checks selected output paths against approved reference values. This is designed to catch accidental computational drift across code changes.

```bash
ot-risk-lab benchmark examples/benchmark_suite.json --format markdown
```

A passing regression benchmark means the implementation remains numerically consistent with the approved reference. It is not empirical validation.

## 3. Ablation / counterfactual checks

`ot-risk-lab ablate` removes one modeled control at a time and also zeroes individual deterministic factors one at a time.

```bash
ot-risk-lab ablate examples/demo_config.json --format markdown
```

This helps reviewers understand which assumptions drive the result and whether control effects behave monotonically. One-at-a-time ablation is a local counterfactual sensitivity analysis, **not a causal estimate**.

## 4. Probability calibration

The attack-progression model outputs a final compromise probability over the configured horizon. If independently observed historical outcomes become available, use `calibrate` to compare those probabilities with binary outcomes.

CSV form A:

```csv
predicted_probability,observed
0.12,0
0.64,1
```

CSV form B computes the prediction from a stored scenario:

```csv
config,observed
scenarios/site-a.json,0
scenarios/site-b.json,1
```

Run:

```bash
ot-risk-lab calibrate observations.csv --bins 10 --format markdown
```

Reported diagnostics include Brier score, log loss, Brier skill score against the empirical base rate, expected calibration error (ECE), maximum calibration error (MCE), and Wilson 95% intervals for observed rates within populated bins.

Calibration is meaningful only when the sample is representative, outcomes are defined consistently, and assessment inputs were frozen before outcomes were observed.

## 5. Recommended empirical study design

For a publishable validation study:

1. Define the prediction target and horizon before collecting outcomes.
2. Freeze model coefficients and scenario-construction rules.
3. Keep a temporally later or site-disjoint validation set.
4. Report missingness and analyst disagreement.
5. Compare against simple baselines, including base-rate and deterministic alternatives.
6. Report discrimination only if relevant; do not substitute discrimination for calibration.
7. Report calibration and confidence intervals.
8. Perform ablation and sensitivity analysis.
9. Document every post-hoc change as a new model version.

This workflow is intentionally conservative so that software verification cannot be mistaken for evidence of real-world predictive validity.

## 6. Empirical study toolkit (v0.6)

`ot-risk-lab study` extends one-off calibration diagnostics into a reproducible study workflow. It can:

- report percentile bootstrap intervals around key probability metrics;
- resample individual records or complete sites;
- freeze a temporally later evaluation population;
- hold out one or more sites with no development/evaluation site overlap;
- report site or subgroup metrics separately.

Example:

```bash
ot-risk-lab study examples/study_observations.csv \
  --split-mode site-disjoint \
  --evaluation-sites Plant-C \
  --bootstrap-unit record \
  --bootstrap 2000 \
  --format markdown
```

When sites are the independent sampling units, use `--bootstrap-unit site`. A site-level interval is intentionally unavailable when a partition contains fewer than two sites; the software does not silently fall back to record-level resampling.

## 7. Analyst agreement

`ot-risk-lab agreement` reports nominal Krippendorff alpha, pairwise agreement, unanimous-item fraction, and item-level bootstrap intervals. Agreement measures consistency in subjective inputs, not correctness or predictive validity.

## 8. Frozen provenance and supplementary artifacts

`ot-risk-lab manifest` records SHA-256 hashes, sizes, software/methodology versions, and experiment parameters. `verify-manifest` detects changed or missing inputs.

`ot-risk-lab supplement` creates a deterministic ZIP with `MANIFEST.json` and `SHA256SUMS.txt`. `verify-bundle` checks archive path safety and every recorded digest. These controls support reproducibility but do not override institutional data-governance or confidentiality requirements.
