#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]


def _match(path: Path, pattern: str, label: str) -> str:
    text = path.read_text(encoding="utf-8")
    match = re.search(pattern, text, flags=re.MULTILINE)
    if not match:
        raise ValueError(f"cannot determine {label} from {path.relative_to(ROOT)}")
    return match.group(1)


def main() -> int:
    failures: list[str] = []
    try:
        version_py = _match(ROOT / "src/ot_risk_lab/version.py", r'^SOFTWARE_VERSION = "([^"]+)"', "software version")
        pyproject = _match(ROOT / "pyproject.toml", r'^version = "([^"]+)"', "pyproject version")
        citation = _match(ROOT / "CITATION.cff", r'^version:\s*([^\s]+)', "citation version")
        readme = _match(ROOT / "README.md", r'Current release:\s*v([0-9]+\.[0-9]+\.[0-9]+)', "README release")
        codemeta = json.loads((ROOT / "codemeta.json").read_text(encoding="utf-8"))["version"]
        sbom = json.loads((ROOT / "sbom.cdx.json").read_text(encoding="utf-8"))["metadata"]["component"]["version"]
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"release-check: FAIL: {exc}", file=sys.stderr)
        return 2

    versions = {
        "version.py": version_py,
        "pyproject.toml": pyproject,
        "CITATION.cff": citation,
        "README.md": readme,
        "codemeta.json": str(codemeta),
        "sbom.cdx.json": str(sbom),
    }
    unique = set(versions.values())
    if len(unique) != 1:
        failures.append("version mismatch: " + ", ".join(f"{k}={v}" for k, v in versions.items()))

    root_schema = json.loads((ROOT / "schemas/analysis-config.schema.json").read_text(encoding="utf-8"))
    packaged_schema = json.loads((ROOT / "src/ot_risk_lab/resources/analysis-config.schema.json").read_text(encoding="utf-8"))
    if root_schema != packaged_schema:
        failures.append("packaged JSON Schema differs from schemas/analysis-config.schema.json")

    required = [
        "LICENSE", "README.md", "SECURITY.md", "CITATION.cff", "codemeta.json",
        "docs/quickstart.md", "docs/release-process.md", "docs/citation.md", "Dockerfile", "sbom.cdx.json",
    ]
    for relative in required:
        if not (ROOT / relative).is_file():
            failures.append(f"missing required release file: {relative}")

    if failures:
        for failure in failures:
            print(f"release-check: FAIL: {failure}", file=sys.stderr)
        return 1

    version = next(iter(unique))
    print(f"release-check: PASS (v{version})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
