# Data dictionary

Normalized fields use `[0,1]` unless noted.

| Field | Meaning |
|---|---|
| `asset.criticality` | Importance of the asset/process to mission or operations |
| `asset.safety_impact` | Potential safety consequence if the scenario succeeds |
| `asset.availability_impact` | Potential continuity/availability consequence |
| `asset.internet_exposure` | Degree of direct/indirect Internet exposure |
| `asset.legacy_factor` | Degree to which legacy/unsupported characteristics increase susceptibility |
| `threat.cvss` | CVSS base score on `[0,10]` |
| `threat.likelihood` | Scenario likelihood used by the reference risk equation |
| `threat.likelihood_basis` | Provenance category for the likelihood input |
| `threat.epss_probability` | Optional EPSS 30-day exploitation probability |
| `threat.cisa_kev` | Confirmed-exploitation evidence from CISA KEV |
| `control.effectiveness` | Nominal expected effect of the control |
| `control.coverage` | Fraction of relevant scope covered |
| `control.confidence` | Confidence in the control-effect estimate |
| `control.implementation` | Degree to which the control is actually implemented |
| `decision.risk_tolerance` | Optional organization-defined risk threshold on `[0,100]` |
