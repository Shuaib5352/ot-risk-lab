# Operational workflow

## 1. Create a scenario

```bash
ot-risk-lab template -o risk-001.json
```

Assign an assessment ID, describe the asset and threat, record evidence, and replace the example tolerance with your organization's criterion or `null`.

## 2. Validate inputs

```bash
ot-risk-lab validate risk-001.json
```

For gated workflows:

```bash
ot-risk-lab validate risk-001.json --strict
```

Exit code `3` means the file is structurally valid but warning-severity model-quality issues require review.

## 3. Generate a human-readable report

```bash
ot-risk-lab analyze risk-001.json --format html -o risk-001.html
```

The HTML report is standalone and contains no external JavaScript dependencies.

## 4. Compare a proposed treatment

```bash
ot-risk-lab compare before.json after.json --format markdown -o treatment-comparison.md
```

Do not interpret modeled percentage reduction as measured incident reduction unless the parameters have been externally calibrated.

## 5. Build a portfolio and risk register

```bash
ot-risk-lab batch scenarios/ --format html -o portfolio.html
ot-risk-lab register scenarios/ --format csv -o risk-register.csv
```

The register includes residual risk, P95, tolerance status, CVE/EPSS/KEV evidence, top drivers, missing CSF Functions, and a configuration fingerprint.

## 6. Archive evidence

Store the input JSON, generated report, software version, and fingerprint with the assessment record. If vulnerability evidence changes, create a new assessment revision rather than silently overwriting the prior evidence snapshot.
