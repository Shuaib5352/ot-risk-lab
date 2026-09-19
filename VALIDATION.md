# OT-RiskLab v0.7.0 verification record

**Release:** v0.7.0 — Release & Publication Readiness  
**Date:** 2026-09-19

## Scope

This record documents software verification, packaging, metadata consistency, and clean-install checks for v0.7.0. The release does not change the v0.6 risk equations, empirical-study semantics, reference coefficients, or regression benchmark expectations. It improves distribution, integration, citation metadata, and release controls.

Software verification is not empirical validation of real-world incident probabilities. Independent operational data remain necessary for external validity claims.

## Verification results

| Check | Result |
|---|---|
| Release metadata consistency | PASS |
| Python compile (`src`, `tests`, `scripts`) | PASS |
| Unit tests | PASS — 80/80 |
| Statement coverage | PASS — 89% |
| Coverage policy | PASS — minimum 80% |
| Regression benchmark | PASS — no numerical drift |
| Source CLI `--version` | PASS — 0.7.0 |
| Source `doctor` diagnostics | PASS |
| Source packaged-schema command | PASS |
| Source reference analysis | PASS |
| Wheel build | PASS |
| Bundled JSON Schema present in wheel | PASS |
| `py.typed` present in wheel | PASS |
| Clean virtual-environment install | PASS |
| Installed `doctor` diagnostics | PASS |
| Installed `schema` command | PASS |
| Installed reference analysis | PASS |
| Installed dependency check | PASS — no broken requirements |
| CycloneDX SBOM generation | PASS |
| Git whitespace check | PASS |
| Docker local execution | NOT RUN — Docker CLI unavailable in this environment |
| Ruff local execution | NOT RUN — Ruff unavailable in this environment |

GitHub CI is configured to install and run Ruff on Python 3.10–3.13. The tagged release workflow is configured to build the Docker image and run `--version` plus `doctor` inside the image.

## Release-control additions verified

- `CITATION.cff`, `codemeta.json`, `pyproject.toml`, `README.md`, `version.py`, and `sbom.cdx.json` agree on version `0.7.0`.
- The repository JSON Schema matches the copy bundled inside the Python wheel.
- `ot-risk-lab doctor` performs offline checks only and reports that network checks were not performed.
- `ot-risk-lab schema` exports valid JSON from the installed distribution.
- The wheel contains no runtime third-party dependency requirement.
- The Dockerfile is designed to run the CLI as a non-root user and exposes no service port.

## Regression guarantee for this release

The reference benchmark manifest passes without changing the computational expectations established before v0.7.0. The release-readiness work therefore does not intentionally alter deterministic risk scores, Monte Carlo semantics, Markov progression behavior, calibration diagnostics, empirical-study splitting, agreement analysis, or supplementary-bundle behavior.

## Environment limitations

The execution environment used for this local verification did not provide the `ruff`, `docker`, or `python -m build` commands. The wheel was therefore built successfully with:

```bash
python -m pip wheel --no-deps --no-build-isolation . -w dist
```

The resulting wheel was installed into a fresh virtual environment and exercised from that installed environment. CI/release workflows retain the standard `build`, Ruff, and Docker checks for the public repository.
