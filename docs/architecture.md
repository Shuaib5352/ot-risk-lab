# Architecture

OT-RiskLab is intentionally small and dependency-light so the mathematical and governance behavior remains inspectable.

## Modules

- `models.py` — immutable validated domain objects and configuration normalization.
- `risk.py` — deterministic susceptibility, consequence, inherent risk, residual risk, and decomposition.
- `monte_carlo.py` — uncertainty propagation, quantiles, tolerance exceedance, and sensitivity.
- `markov.py` — configurable attack-progression state model.
- `evidence.py` — CVE/EPSS/KEV evidence preservation and workflow flags.
- `posture.py` — control coverage and non-blocking model-quality diagnostics.
- `report.py` — canonical single-scenario analysis plus Markdown/HTML rendering.
- `comparison.py` — baseline/candidate treatment comparison.
- `portfolio.py` — multi-scenario aggregation and portfolio rendering.
- `register.py` — risk-register projection for GRC/spreadsheet use.
- `cli.py` — filesystem boundary and command-line interface.

## Design constraints

1. Core runtime uses only the Python standard library.
2. Domain validation happens before risk calculations.
3. Report renderers consume analysis dictionaries; they do not alter model results.
4. External evidence is explicit metadata unless the analyst deliberately selects it as a likelihood basis.
5. Every normalized configuration has a SHA-256 fingerprint.
6. Versioned defaults are visible and documented.

## Trust boundaries

The CLI reads local JSON and writes local files. It does not perform network scanning, vulnerability exploitation, credential use, or automatic Internet enrichment. External data can be recorded by the analyst after collection through authorized organizational processes.
