# Container usage

The repository includes a minimal Dockerfile for reproducible CLI deployment. The image runs as a non-root user and performs no network access unless the user explicitly invokes the `evidence` command.

Build:

```bash
docker build -t ot-risk-lab:0.7.0 .
```

Check the image:

```bash
docker run --rm ot-risk-lab:0.7.0 --version
docker run --rm ot-risk-lab:0.7.0 doctor
```

Analyze a local configuration by mounting the working directory:

```bash
docker run --rm \
  -v "$PWD:/work" \
  ot-risk-lab:0.7.0 \
  analyze examples/demo_config.json --format markdown -o results/demo.md
```

On Windows PowerShell, replace `$PWD` with the appropriate absolute path if Docker does not expand it as expected.

## Operational note

Treat production OT configuration, network captures, incident data, and vulnerability inventories as sensitive. Prefer local execution and mount only the files required for the analysis.
