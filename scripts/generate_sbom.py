#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def version() -> str:
    text = (ROOT / "src/ot_risk_lab/version.py").read_text(encoding="utf-8")
    match = re.search(r'^SOFTWARE_VERSION = "([^"]+)"', text, re.MULTILINE)
    if not match:
        raise RuntimeError("cannot determine software version")
    return match.group(1)


def build_sbom() -> dict[str, object]:
    ver = version()
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": f"pkg:pypi/ot-risk-lab@{ver}",
                "name": "ot-risk-lab",
                "version": ver,
                "purl": f"pkg:pypi/ot-risk-lab@{ver}",
                "licenses": [{"license": {"id": "MIT"}}],
            }
        },
        "components": [],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a minimal CycloneDX SBOM for the dependency-free core package.")
    parser.add_argument("output", nargs="?", type=Path, default=Path("sbom.cdx.json"))
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(build_sbom(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
