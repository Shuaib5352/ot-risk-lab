# Frozen experiment manifests

A publication-quality experiment should make it possible to determine exactly which files were used.

Create a manifest:

```bash
ot-risk-lab manifest examples/study_observations.csv examples/scenarios \
  --base-dir examples \
  --label "external-validation-1" \
  --parameter split=site-disjoint \
  --parameter evaluation_site=Plant-C \
  -o experiment-manifest.json
```

Each file receives a SHA-256 digest and size. Methodology versions and the OT-RiskLab software version are stored alongside experiment parameters.

Verify later:

```bash
ot-risk-lab verify-manifest experiment-manifest.json --base-dir examples
```

A changed, missing, or replaced file causes verification to fail. This is a provenance control, not a substitute for data governance or access controls.
