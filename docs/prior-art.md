# Prior art and design influences

OT-RiskLab was implemented independently. Public projects and standards were reviewed to understand useful patterns and avoid reinventing terminology.

## MITRE Center for Threat-Informed Defense — Attack Flow

Attack Flow demonstrates the value of representing adversary behavior as explicit, inspectable sequences rather than a flat list of techniques. OT-RiskLab adopts the **design principle** that attack progression should be separated from the risk-score calculation and represented transparently.

- Project: https://github.com/center-for-threat-informed-defense/attack-flow
- License: Apache-2.0
- Use in OT-RiskLab: conceptual/architectural inspiration only; no Attack Flow source code is vendored or copied.

## NIST guidance

NIST CSF 2.0 and NIST SP 800-82 Rev. 3 inform the project's vocabulary around risk-management functions and OT-specific safety/reliability context. NIST publications are cited rather than reproduced.

## Other public risk calculators

A number of public GitHub repositories implement small risk calculators or FAIR-inspired Monte Carlo exercises. They confirm community interest in reproducible cyber-risk quantification, but OT-RiskLab does not copy their source code. The project instead keeps a minimal standard-library core, explicit assumptions, reproducible seeds, and OT-specific consequence factors.

## Why this matters

Original implementation plus explicit attribution makes the provenance auditable. If third-party code is incorporated in a future release, its license, source, version, and modifications must be recorded in `THIRD_PARTY.md` before merge.
