# Empirical study toolkit

OT-RiskLab v0.6 separates **software verification** from **empirical validation** and adds tools for evaluating probability outputs against observations without silently pooling populations.

## Study CSV

The `study` command accepts:

```csv
record_id,site,timestamp,subgroup,predicted_probability,observed
A-001,Plant-A,2026-01-05T08:00:00Z,PLC,0.08,0
```

Required columns are `predicted_probability` and `observed`. `record_id`, `site`, `timestamp`, and `subgroup` support reproducibility, held-out validation, and subgroup reporting.

## Bootstrap intervals

```bash
ot-risk-lab study examples/study_observations.csv \
  --bootstrap 2000 --confidence 0.95 --format markdown
```

The toolkit reports percentile bootstrap intervals for observed event rate, mean predicted probability, Brier score, log loss, expected calibration error, and maximum calibration error.

The current bootstrap resamples **records**, not sites. If observations are clustered within facilities, these intervals are not cluster-robust and should not be presented as such. A site-level bootstrap can be added for studies with sufficient independent sites.

## Temporal hold-out

```bash
ot-risk-lab study examples/study_observations.csv \
  --split-mode temporal \
  --cutoff 2026-05-01T00:00:00Z \
  --bootstrap 1000 \
  --format markdown
```

Development records must occur before the cutoff. Evaluation records occur at or after it. This is intended to prevent accidental future-to-past leakage in retrospective validation.

## Site-disjoint hold-out

```bash
ot-risk-lab study examples/study_observations.csv \
  --split-mode site-disjoint \
  --evaluation-sites Plant-C \
  --bootstrap 1000 \
  --format markdown
```

No site appears in both partitions. This makes the external population explicit instead of reporting a randomly mixed sample as external validation.

## Subgroup reporting

Use `--group-by site` or `--group-by subgroup`. OT-RiskLab reports each population separately. Small subgroup results should be treated as descriptive and uncertain rather than overinterpreted.

## What this tool does not prove

A narrow confidence interval does not prove that the model is valid. Calibration metrics depend on representative sampling, consistent outcome definitions, prospective or properly frozen retrospective inputs, and appropriate handling of clustering and missing data.
