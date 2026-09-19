from __future__ import annotations

import json
from importlib.resources import files


def analysis_config_schema() -> dict[str, object]:
    """Return the bundled JSON Schema for analysis configuration files."""
    resource = files("ot_risk_lab.resources").joinpath("analysis-config.schema.json")
    return json.loads(resource.read_text(encoding="utf-8"))


def analysis_config_schema_text(*, indent: int = 2) -> str:
    """Return the bundled JSON Schema as normalized JSON text."""
    return json.dumps(analysis_config_schema(), indent=indent, sort_keys=True, ensure_ascii=False) + "\n"
