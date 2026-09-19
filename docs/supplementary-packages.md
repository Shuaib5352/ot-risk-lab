# Reproducible supplementary packages

The `supplement` command creates a deterministic ZIP with an internal manifest and SHA-256 checksums.

```bash
ot-risk-lab supplement \
  examples/study_observations.csv \
  examples/analyst_ratings.csv \
  docs/empirical-study.md \
  --label "OT-RiskLab empirical study supplement" \
  -o supplement.zip
```

Verify it with:

```bash
ot-risk-lab verify-bundle supplement.zip
```

The bundler excludes common development residues such as `.git`, virtual environments, cache directories, `dist`, `build`, and compiled Python bytecode. ZIP metadata uses a fixed timestamp and sorted input order so unchanged inputs yield reproducible archives.

Do not place confidential packet captures, credentials, plant identifiers, or restricted vulnerability data into a public supplement merely because the tool can package them. Publication and data-release decisions remain the user's responsibility.
