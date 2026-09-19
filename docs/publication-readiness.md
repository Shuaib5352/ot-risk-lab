# Publication readiness

OT-RiskLab separates three different claims that should not be conflated:

1. **software verification** — whether the implementation behaves as specified;
2. **computational reproducibility** — whether another environment can reproduce the same analysis from the same inputs;
3. **empirical validity** — whether the modeled probabilities and coefficients perform adequately on independent real-world data.

The first two are supported by automated tests, regression benchmarks, provenance, manifests, deterministic supplementary archives, metadata consistency checks, and container packaging. The third still requires external data that are independent of the reference examples in this repository.

Before a software-paper or validation-paper submission, complete the following:

- publish the repository and tagged releases;
- archive a versioned release with a DOI;
- demonstrate use by at least one reproducible research or engineering workflow;
- report independent site-disjoint or temporally later validation if predictive claims are made;
- preserve negative or null validation results rather than tuning them away;
- cite related software and explain the distinct contribution;
- state the limits of the reference coefficients and control-combination assumptions;
- follow the selected journal's current disclosure, authorship, and research-integrity requirements.
