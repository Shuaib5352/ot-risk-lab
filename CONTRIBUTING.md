# Contributing

Contributions are welcome through focused issues and pull requests.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\Activate.ps1
pip install -e ".[dev]"
python scripts/release_check.py
ruff check src tests scripts
coverage run -m unittest discover -s tests -v
coverage report --fail-under=80
```

## Scientific changes

A pull request that changes a mathematical assumption, coefficient, probability model, or risk interpretation should include:

1. the rationale for the change;
2. the expected effect on outputs;
3. tests for the new behavior;
4. documentation updates;
5. references or validation evidence when the change is empirical rather than illustrative.

Please avoid presenting uncalibrated parameters as validated real-world probabilities.


## Release-impacting changes

Changes that affect package metadata, the JSON Schema, public imports, CLI arguments, report schemas, or container behavior should also update the relevant release documentation and tests. Before tagging a release, follow [`docs/release-process.md`](docs/release-process.md).

The root JSON Schema and the packaged copy under `src/ot_risk_lab/resources/` must remain byte-equivalent at the JSON object level; automated tests enforce this.
