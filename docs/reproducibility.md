# Reproducibility and provenance

Every scenario has a SHA-256 configuration fingerprint. v0.5 additionally exposes a model signature and methodology-version map so reviewers can distinguish:

- changed scenario inputs;
- changed model coefficients;
- changed implementation/methodology versions;
- changed execution environment.

```bash
ot-risk-lab provenance examples/demo_config.json -o provenance.json
```

The deterministic provenance block is also embedded in each `analyze` JSON result. Environment provenance includes Python implementation/version, platform, and generation timestamp.

For archived experiments, store together:

1. scenario JSON;
2. analysis output;
3. provenance JSON;
4. package version or release archive checksum;
5. any external evidence snapshot used to construct the scenario;
6. benchmark output for the release.
