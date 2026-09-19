# Model governance

## Purpose

OT-RiskLab is a transparent reference model for structured decision support. It is not a certified safety case, actuarial model, or universal incident-probability estimator.

## Governance principles

1. **Trace inputs.** Use `metadata.assessment_id`, analyst/scope fields, CVE IDs, evidence dates, control evidence notes, and references.
2. **Separate evidence types.** Do not collapse CVSS, EPSS, KEV, ATT&CK, and local engineering consequence into one undocumented number.
3. **Own thresholds.** `decision.risk_tolerance` belongs to the user/organization. OT-RiskLab does not prescribe a universal acceptable-risk threshold.
4. **Treat defaults as hypotheses.** Reference weights and Markov coefficients are versioned assumptions until externally calibrated.
5. **Distinguish nominal control quality from implementation.** A strong design that is only partially deployed should not receive full modeled credit.
6. **Preserve uncertainty.** Use Monte Carlo intervals and sensitivity rather than reporting only a point estimate.
7. **Review warnings.** `validate --strict` can be used in CI or governance workflows to reject scenarios with warning-severity quality issues.

## Change control

Any change to default weights, transition parameters, control-combination logic, or interpretation semantics should:

- increment the software version;
- be listed in `CHANGELOG.md`;
- add/modify tests;
- update methodology documentation;
- update the verification record.

## Validation hierarchy

- **Verification:** software behaves as specified.
- **Model validation:** outputs are compared with external evidence or expert elicitation.
- **Operational validation:** the model is evaluated in the actual site/process context.

Passing automated tests establishes verification only.
