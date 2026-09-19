# Release process

This process is intentionally conservative so that a published artifact cannot silently disagree with its source metadata.

1. Update `src/ot_risk_lab/version.py`, `pyproject.toml`, `CITATION.cff`, `codemeta.json`, `README.md`, and `CHANGELOG.md`.
2. Keep `schemas/analysis-config.schema.json` synchronized with the packaged schema under `src/ot_risk_lab/resources/`.
3. Run:

```bash
python scripts/release_check.py
python -m compileall -q src tests scripts
python -m unittest discover -s tests -v
PYTHONPATH=src python -m ot_risk_lab benchmark examples/benchmark_suite.json
```

4. With development dependencies installed, run Ruff and coverage:

```bash
ruff check src tests scripts
coverage run -m unittest discover -s tests -v
coverage report --fail-under=80
```

5. Build distributions and install the wheel into a clean environment.
6. Run `ot-risk-lab doctor`, `ot-risk-lab schema`, and the reference benchmark from the installed wheel.
7. Build the Docker image and run `--version` plus `doctor` inside it.
8. Tag the exact reviewed commit as `vX.Y.Z`.
9. Publish immutable checksums with the release artifacts.
10. Archive the public release in Zenodo only after the GitHub tag is final.

The regression benchmark protects computational outputs; it does not substitute for empirical validation of the model assumptions.
