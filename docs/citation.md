# Citation and archival metadata

`CITATION.cff` is the canonical human-facing citation metadata in the repository. GitHub can use this file to display citation guidance, and Zenodo can ingest supported fields when archiving a GitHub release.

The repository also includes `codemeta.json` using the CodeMeta 3.1 context for software discovery and metadata exchange.

## Version-specific citation

When a public release is archived in Zenodo, cite the DOI for the exact software version used in the research. Record that DOI together with the Git tag, configuration fingerprint, and provenance artifact.

## Why there is no `.zenodo.json` by default

Zenodo gives `.zenodo.json` precedence over `CITATION.cff` when both are present. OT-RiskLab therefore keeps `CITATION.cff` as the primary release metadata unless Zenodo-specific fields such as grants or communities are actually needed.

## Reproducibility citation bundle

For a study, preserve at minimum:

- software version and Git tag;
- archived release DOI, when available;
- configuration files and their SHA-256 fingerprints;
- `provenance` output;
- experiment manifest;
- supplementary bundle checksum.
