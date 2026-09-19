# Methodology

## 1. Scope

OT-RiskLab is a transparent reference model for reproducible ICS/OT risk experiments. It separates software correctness from scientific calibration. Equations and coefficients are visible, configurable, and versioned.

## 2. Susceptibility / vulnerability

Let `V_cvss = CVSS/10`, `E` be Internet exposure, and `G` the legacy factor. By default:

\[
V=0.50V_{cvss}+0.30E+0.20G.
\]

The weights are OT-RiskLab defaults, not normative weights from NIST, IEC, MITRE, FIRST, or CISA.

## 3. Consequence

Let `I` be threat impact, `K` asset criticality, `S` safety impact, and `A` availability impact:

\[
C=0.25I+0.25K+0.25S+0.25A.
\]

Safety and availability are explicit because NIST SP 800-82 Rev. 3 emphasizes OT performance, reliability, and safety requirements.

## 4. Inherent risk

For scenario likelihood `L`:

\[
R_{inherent}=100LVC.
\]

The result is bounded to `[0,100]`. It is a project reference scale, not an annualized-loss metric.

## 5. Control model

For control `i`:

\[
s_i=e_i c_i q_i m_i,
\]

where `e_i` is nominal effectiveness, `c_i` coverage, `q_i` confidence, and `m_i` implementation completeness.

With optional aggregate manual mitigation `M_0`:

\[
M=1-(1-M_0)\prod_i(1-s_i),
\]

and

\[
R_{residual}=R_{inherent}(1-M).
\]

The residual combination assumes independent control effects. Real controls can be correlated or dependent; calibrated deployments may replace this logic.

## 6. Vulnerability evidence

CVSS, EPSS, and CISA KEV are stored separately. EPSS is optionally usable as the scenario likelihood only when `likelihood_basis="epss-30d"`; the supplied likelihood must then equal the EPSS probability. KEV does not numerically change the risk equation; it produces an explicit confirmed-exploitation workflow warning.

## 7. Uncertainty propagation

Supported modes are `fixed`, `truncated_normal`, and `triangular`. Global uncertainty can be overridden per factor. The simulation returns mean, population standard deviation, minimum, maximum, P05, P50, and P95.

## 8. Sensitivity

Spearman rank correlation is computed between each sampled factor and simulated residual risk. It measures association under the selected uncertainty model, not causality.

## 9. Organization-defined tolerance

If a tolerance `T` is supplied, the simulation estimates

\[
P(R_{residual}>T)
\]

as the fraction of Monte Carlo draws above `T`. It also reports the mean excess above tolerance conditional on exceedance. `T` is user-defined and not a standard-derived threshold.

## 10. Markov attack progression

The default states are

`Secure -> Reconnaissance -> Exploitation -> Compromised`.

For normalized residual risk `r`:

\[
p_{SR}=0.02+0.18r,\quad
p_{RE}=0.03+0.25r,\quad
p_{EC}=0.01+0.30r.
\]

The compromised state is absorbing. Coefficients are configurable reference parameters, not calibrated transition rates.

## 11. Reproducibility

A SHA-256 fingerprint is calculated from the normalized configuration. A fixed seed reproduces the same Monte Carlo summary on the same implementation version.

## 12. Validation layers

1. **Software verification:** bounds, monotonicity, probability conservation, deterministic seeds, parsing, reports, CLI behavior.
2. **Model validation:** comparison against external data, expert elicitation, alternative parameterizations, calibration tests.
3. **Operational validation:** site-specific evidence, process safety constraints, organizational controls, engineering judgment.

Automated tests assert the first layer only.

## 13. Computational regression benchmarks

A benchmark manifest stores approved scenario files and selected expected output values. The benchmark runner recomputes those values and checks absolute numerical drift within an explicit tolerance. This verifies computational continuity across releases; it does not establish external validity.

## 14. Counterfactual ablation

Control ablation removes one modeled control at a time and recomputes residual risk. Deterministic factor ablation sets one normalized model term to zero while all other terms remain fixed. These one-at-a-time counterfactuals expose local model dependence and monotonic behavior. They are not causal effect estimates.

## 15. Empirical probability calibration

The Markov module produces a final compromise probability over the configured horizon. Given independently observed binary outcomes, OT-RiskLab reports Brier score, log loss, Brier skill score relative to the empirical base rate, expected calibration error (ECE), maximum calibration error (MCE), and Wilson 95% intervals in populated probability bins.

Calibration diagnostics evaluate agreement between predicted probabilities and observations. They do not refit the model and should not be interpreted as valid when outcomes are post-selected, labels are inconsistent, or the same observations were used to choose the model coefficients.

## 16. Model provenance

In addition to the normalized configuration SHA-256 fingerprint, v0.5 records a model signature derived from the risk-model coefficients, Markov parameters, and methodology-version identifiers. Environment provenance can separately record Python/platform details and generation time. This permits reviewers to distinguish changed inputs from changed methodology or runtime environment.
