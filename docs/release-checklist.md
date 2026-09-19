# Release checklist

1. Update `pyproject.toml`, `src/ot_risk_lab/__init__.py`, `report.SOFTWARE_VERSION`, `CITATION.cff`, README, and changelog to the same version.
2. Confirm methodology and schema match code semantics.
3. Run Ruff, compile checks, unit tests, and coverage.
4. Exercise JSON, Markdown, HTML, CSV, comparison, register, template, strict-validation, study, agreement, manifest, and supplementary-bundle CLI paths.
5. Build wheel and source distribution without modifying source files.
6. Inspect package contents for secrets, caches, build residue, and unintended files.
7. Confirm configuration fingerprints, study bootstrap seeds, and supplementary ZIP construction remain deterministic for unchanged inputs.
8. Update `VALIDATION.md` with the exact verification command and results.
9. Tag the verified commit only after the working tree is clean.
10. Archive the release artifact and checksum; create a DOI only from the public tagged release intended for citation.
