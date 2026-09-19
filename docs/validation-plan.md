# Scientific validation plan

Automated tests establish software verification, not empirical predictive validity. A publication-grade validation program should proceed in layers.

## Layer A — implementation verification

- numerical bounds and monotonicity;
- probability conservation;
- reproducible seeded simulation;
- quantile ordering and sensitivity bounds;
- schema/domain validation;
- HTML/Markdown/CSV/JSON rendering;
- tolerance-exceedance calculation;
- evidence-provenance rules;
- CLI exit-code behavior.

## Layer B — structural model validation

- alternative weight sets and transition coefficients;
- uncertainty-distribution robustness;
- control-dependency stress tests instead of assuming independence;
- one-at-a-time and global sensitivity comparison;
- synthetic edge cases with analytically predictable results.

## Layer C — external evidence

- expert elicitation with documented inter-rater agreement;
- retrospective comparison against public OT incident/vulnerability datasets where licensing allows;
- calibration assessment when genuine probability outcomes are available;
- evaluation of EPSS-based likelihood only at its intended 30-day population horizon;
- separate analysis of KEV confirmed-exploitation status rather than treating it as a probability.

## Layer D — operational validation

- site-specific asset inventory and network architecture;
- process-safety review;
- actual control implementation evidence;
- incident-response and recovery constraints;
- local risk tolerance and governance approval.

No result should be described as an empirically calibrated incident probability until the relevant external validation has been completed.
