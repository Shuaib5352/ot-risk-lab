---
title: 'OT-RiskLab: Transparent Stochastic Cyber-Risk Modeling for Operational Technology'
tags:
  - Python
  - operational technology
  - industrial control systems
  - cybersecurity
  - risk analysis
  - uncertainty quantification
authors:
  - name: Shuaib Ayad Jasim
    affiliation: 1
affiliations:
  - name: Independent research software project
    index: 1
date: 19 September 2026
bibliography: paper.bib
---

# Summary

OT-RiskLab is open research software for transparent cyber-risk experiments in industrial control system and operational technology contexts. The software separates scenario likelihood, contextual susceptibility, OT consequence, mitigation, uncertainty propagation, and attack progression instead of collapsing them into an opaque point score. The core package has no runtime dependencies and produces machine-readable, Markdown, CSV, or standalone HTML reports with reproducible random seeds and configuration fingerprints.

# Statement of need

Operational technology risk analysis must account for characteristics that differ from generic IT assessment, including physical-process safety and availability constraints. NIST SP 800-82 Rev. 3 explicitly discusses these OT-specific performance, reliability, and safety requirements [@nist80082r3]. At the same time, risk inputs such as likelihood, control effectiveness, and consequence are frequently uncertain. A research tool should therefore expose assumptions, quantify uncertainty, and preserve enough provenance for another analyst to reproduce an experiment.

OT-RiskLab addresses this need with a compact auditable implementation designed for method comparison, teaching, benchmarking, and research prototyping. It is not presented as a certified or universally calibrated operational risk standard.

# Functionality

The package provides:

1. a parameterized inherent-risk model separating susceptibility and consequence;
2. OT-specific safety and availability consequence factors;
3. multi-control residual-risk modeling using effectiveness, coverage, confidence, and implementation;
4. reproducible Monte Carlo uncertainty propagation;
5. Spearman rank sensitivity analysis;
6. a configurable four-state Markov attack-progression model;
7. analyst-supplied MITRE ATT&CK for ICS technique metadata [@mitreics];
8. single-scenario, portfolio, HTML, and risk-register reporting;
9. explicit CVE/EPSS/CISA KEV evidence fields without collapsing unlike evidence types;
10. organization-defined risk tolerance with Monte Carlo exceedance probability;
11. regression benchmark manifests for computational drift detection;
12. control/factor ablation for transparent counterfactual analysis;
13. probability-calibration diagnostics for independently observed outcomes;
14. explicit model/environment provenance and optional reviewable vulnerability-evidence retrieval;
15. empirical-study diagnostics with record- or site-level bootstrap confidence intervals;
16. explicit temporally later and site-disjoint held-out validation partitions;
17. analyst inter-rater agreement using nominal Krippendorff alpha;
18. frozen experiment manifests with SHA-256 provenance; and
19. deterministic, checksummed supplementary-study archives.

Controls can be labeled using the six NIST Cybersecurity Framework 2.0 Functions—Govern, Identify, Protect, Detect, Respond, and Recover [@nistcsf20]—to aid communication without implying formal compliance.

Vulnerability evidence is intentionally separated by meaning: EPSS is retained as a forward-looking 30-day exploitation probability [@firstepss], while CISA KEV is retained as evidence of confirmed exploitation in the wild [@cisakev]. OT-RiskLab does not multiply EPSS by CVSS or convert KEV membership into an invented probability.

# Transparency and validation status

All reference weights and transition coefficients are visible and configurable. Automated tests verify numerical bounds, mitigation monotonicity, Monte Carlo reproducibility, stochastic-matrix probability conservation, and command-line behavior. These tests verify the implementation, not empirical predictive validity. The software now includes regression drift checks, counterfactual ablation, empirical probability-calibration diagnostics, bootstrap confidence intervals, explicit temporal/site-disjoint validation partitions, and analyst-agreement diagnostics. These tools make future external validation auditable, but they do not turn reference coefficients into validated incident probabilities. Representative site-disjoint or temporally later outcome data remain necessary for empirical claims, and cluster-aware uncertainty should be used when facilities rather than rows are independent sampling units.

# Prior art

MITRE Center for Threat-Informed Defense's Attack Flow project demonstrates the utility of explicit, inspectable attack sequences [@attackflow]. OT-RiskLab adopts the architectural principle of keeping attack progression distinct from risk scoring; it does not vendor or copy Attack Flow source code.

# Limitations

The default risk weights and Markov transition coefficients are reference parameters. Control-combination logic assumes multiplicative independent residual factors. Spearman sensitivity reflects association under the chosen input distributions and should not be interpreted as causality. Site-specific operational use requires engineering, safety, regulatory, and empirical validation beyond the software's reference defaults.

# Acknowledgements

The project uses public standards and threat knowledge resources from NIST and MITRE as cited above. No endorsement by those organizations is implied.

# References
