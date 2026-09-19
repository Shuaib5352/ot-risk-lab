# Security policy

OT-RiskLab is defensive research software. Please report vulnerabilities privately to the repository maintainer before public disclosure when practical.

The project does not intentionally include exploit payloads, credential collection, network scanning, autonomous control of industrial devices, or commands that modify OT assets.

## Network behavior

The core analysis, simulation, reporting, benchmark, ablation, calibration, and provenance functions operate locally. The optional `evidence` command makes outbound **read-only HTTPS** requests only to the documented public FIRST EPSS, CISA KEV, and NVD CVE API endpoints. Scenario files are not uploaded to those services; only CVE identifiers are queried.

`NVD_API_KEY` may be supplied through the environment. The application does not print or persist the key. Do not place secrets in scenario JSON files, control evidence notes, or repository commits.

## Data handling

Assessment files can contain operationally sensitive asset names, zones, control evidence, and analyst notes. Treat generated JSON/Markdown/HTML/CSV reports with the same classification and handling rules as their source assessment data.

## Supplementary data handling

The `supplement` command is an archive utility, not a data-classification system. Review every input before publication. Do not publish credentials, plant identifiers, restricted PCAPs, proprietary configurations, or regulated data merely because the package can archive them. Symbolic links are rejected or skipped so an archive cannot silently follow a link outside the intended study directory. Bundle verification uses path-safety and size limits before hashing archive content.


## Container behavior

The supplied Docker image runs the CLI as a non-root user. It does not expose a server port. The same network rule applies inside the container: only an explicit `evidence` command is designed to contact external public services. Mount assessment directories read-only when reports do not need to be written back into the source directory.
