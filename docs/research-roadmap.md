# Research roadmap

## Completed foundation — v0.1 to v0.4

- transparent OT susceptibility/consequence model;
- explicit safety and availability context;
- parameterized model weights and Markov coefficients;
- multi-control mitigation with effectiveness, coverage, confidence, and implementation;
- Monte Carlo uncertainty and Spearman sensitivity;
- before/after comparison, portfolio reports, risk register, standalone HTML;
- CVE/EPSS/KEV evidence fields, organization-defined tolerance, model-quality warnings;
- CI, CodeQL, release builds, citation metadata, and research-paper scaffold.

## v0.5 — Validation & Evidence

- computational regression benchmark manifests;
- control/factor ablation and counterfactual diagnostics;
- empirical probability-calibration diagnostics;
- reproducibility model signatures and environment provenance;
- optional reviewable evidence retrieval from FIRST EPSS, CISA KEV, and NVD;
- explicit partial-source handling so API failure is not mistaken for negative evidence.

## v0.6 — Empirical Study Toolkit

- bootstrap confidence intervals for empirical probability metrics;
- optional site-level cluster bootstrap to preserve within-site dependence;
- explicit temporal and site-disjoint validation partitions;
- subgroup/site reporting without silently pooling populations;
- nominal Krippendorff alpha and bootstrap intervals for analyst agreement;
- frozen experiment manifests with SHA-256 file provenance and parameters;
- deterministic supplementary ZIP bundles with internal checksums and verification.

## v0.7 — Release & Publication Readiness (current)

- packaged JSON Schema access for integrations and installed environments;
- offline `doctor` diagnostics for installation support;
- CodeMeta 3.1 metadata alongside `CITATION.cff`;
- non-root Docker distribution path;
- release metadata consistency checks;
- CycloneDX SBOM generation;
- explicit citation, container, quick-start, release, and publication-readiness documentation.

## v0.8 — Practitioner interface

- optional local-only web interface built on the stable core API;
- interactive scenario comparison and sensitivity visualizations;
- project workspaces and evidence snapshots;
- accessibility and internationalization review.

## v1.0 — Research release candidate

Requires documented external validation on appropriately scoped data, a stable schema/versioning policy, version-specific DOI, reproducible benchmark and empirical-study bundles, and a clear statement separating empirically supported parameters from reference defaults.
