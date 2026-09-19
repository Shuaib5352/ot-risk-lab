from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import platform
import sys

from .models import AnalysisConfig
from .version import METHODOLOGY_VERSIONS, OUTPUT_SCHEMA_VERSION, SOFTWARE_VERSION


def config_fingerprint(config: AnalysisConfig) -> str:
    canonical = json.dumps(config.to_mapping(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def model_signature(config: AnalysisConfig) -> str:
    mapping = config.to_mapping()
    payload = {
        "risk_model": mapping.get("risk_model", {}),
        "markov": mapping.get("markov", {}),
        "methodology_versions": METHODOLOGY_VERSIONS,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def deterministic_provenance(config: AnalysisConfig) -> dict[str, object]:
    return {
        "software": {"name": "OT-RiskLab", "version": SOFTWARE_VERSION},
        "output_schema_version": OUTPUT_SCHEMA_VERSION,
        "config_fingerprint_sha256": config_fingerprint(config),
        "model_signature_sha256": model_signature(config),
        "methodology_versions": dict(METHODOLOGY_VERSIONS),
    }


def environment_provenance(config: AnalysisConfig) -> dict[str, object]:
    payload = deterministic_provenance(config)
    payload.update(
        {
            "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "python": sys.version.split()[0],
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
        }
    )
    return payload
