# Standards and public-evidence context

OT-RiskLab uses public standards and threat/vulnerability knowledge as context, not as a claim of certification.

## NIST Cybersecurity Framework 2.0

CSF 2.0 organizes cybersecurity outcomes under six concurrent Functions: Govern, Identify, Protect, Detect, Respond, and Recover. OT-RiskLab lets users label modeled controls with one Function to support communication. This is not a CSF maturity or conformance assessment.

Reference: https://doi.org/10.6028/NIST.CSWP.29

## NIST SP 800-82 Rev. 3

NIST SP 800-82 Rev. 3 addresses OT security while recognizing performance, reliability, and safety requirements. OT-RiskLab therefore represents safety and availability consequence inputs explicitly.

Reference: https://doi.org/10.6028/NIST.SP.800-82r3

## MITRE ATT&CK for ICS

Analysts may record ATT&CK for ICS technique identifiers. OT-RiskLab validates identifier format but does not infer techniques, download ATT&CK data at runtime, or convert technique presence into opaque score multipliers.

Reference: https://attack.mitre.org/matrices/ics/

## FIRST EPSS

EPSS is a forward-looking 30-day probability of observed exploitation activity for a CVE. OT-RiskLab preserves the probability/percentile as evidence and permits the probability to be the explicit scenario likelihood when requested.

Reference: https://www.first.org/epss/

## CISA KEV

The Known Exploited Vulnerabilities Catalog records vulnerabilities confirmed as exploited in the wild. OT-RiskLab preserves KEV as a workflow-priority signal and does not invent a numeric probability from membership.

Reference: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
