# External vulnerability-evidence sources

OT-RiskLab v0.5 adds an **optional** evidence-retrieval command. The core risk engine remains offline and deterministic; network evidence is fetched into a separate artifact for review before analysts decide whether it applies to a scenario.

```bash
ot-risk-lab evidence CVE-2021-44228 --format markdown -o evidence.md
```

## FIRST EPSS

Endpoint used: `https://api.first.org/data/v1/epss`

EPSS is preserved as its own 30-day exploitation-probability signal plus percentile. It is not multiplied by CVSS.

## CISA Known Exploited Vulnerabilities

Feed used: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

KEV membership is treated as confirmed exploitation in the wild and a prioritization signal. It is not converted into an invented numeric probability.

## NVD CVE API 2.0

Endpoint used: `https://services.nvd.nist.gov/rest/json/cves/2.0`

The adapter records vulnerability metadata and selects a primary CVSS metric in the order v4.0, v3.1, v3.0, then v2 when available. `NVD_API_KEY` can be supplied as an environment variable for environments that use an NVD API key.

## Data-governance rule

External evidence is never silently injected into an existing assessment. The retrieval artifact must be reviewed for product/version applicability, timestamp, and source consistency before it is copied into a scenario file. This protects reproducibility and makes later audits possible.

## Source availability

By default, the command returns partial results when one provider is temporarily unavailable and marks the provider status as `error` or `partial`. This distinction is important: **unavailable evidence is not negative evidence**. Use `--strict-sources` when CI or a controlled pipeline should fail if any selected provider cannot be queried.
