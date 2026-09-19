from __future__ import annotations

import platform
import sys
import tempfile
from pathlib import Path

from .models import AnalysisConfig
from .schema import analysis_config_schema
from .templates import starter_config
from .version import SOFTWARE_VERSION

_MIN_PYTHON = (3, 10)


def runtime_diagnostics() -> dict[str, object]:
    """Run offline installation diagnostics without contacting external services."""
    checks: list[dict[str, object]] = []

    py_ok = sys.version_info >= _MIN_PYTHON
    checks.append({
        "name": "python_version",
        "passed": py_ok,
        "detail": platform.python_version(),
    })

    try:
        schema = analysis_config_schema()
        schema_ok = isinstance(schema, dict) and schema.get("type") == "object"
        detail = str(schema.get("$id") or schema.get("title") or "bundled schema loaded")
    except Exception as exc:  # pragma: no cover - defensive diagnostics
        schema_ok = False
        detail = f"{type(exc).__name__}: {exc}"
    checks.append({"name": "bundled_schema", "passed": schema_ok, "detail": detail})

    try:
        AnalysisConfig.from_mapping(starter_config())
        config_ok = True
        detail = "starter configuration parsed"
    except Exception as exc:  # pragma: no cover - defensive diagnostics
        config_ok = False
        detail = f"{type(exc).__name__}: {exc}"
    checks.append({"name": "configuration_parser", "passed": config_ok, "detail": detail})

    try:
        with tempfile.TemporaryDirectory(prefix="ot-risk-lab-") as tmp:
            target = Path(tmp) / "probe.txt"
            target.write_text("ok\n", encoding="utf-8")
            writable_ok = target.read_text(encoding="utf-8") == "ok\n"
        detail = "temporary-file round trip succeeded"
    except OSError as exc:  # pragma: no cover - environment dependent
        writable_ok = False
        detail = f"{type(exc).__name__}: {exc}"
    checks.append({"name": "filesystem_write", "passed": writable_ok, "detail": detail})

    passed = all(bool(item["passed"]) for item in checks)
    return {
        "passed": passed,
        "software_version": SOFTWARE_VERSION,
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "checks": checks,
        "network_checks_performed": False,
    }


def render_diagnostics_text(result: dict[str, object]) -> str:
    lines = [
        f"OT-RiskLab {result['software_version']} diagnostics",
        f"overall: {'PASS' if result['passed'] else 'FAIL'}",
    ]
    for item in result["checks"]:  # type: ignore[index]
        status = "PASS" if item["passed"] else "FAIL"
        lines.append(f"- {status} {item['name']}: {item['detail']}")
    lines.append("- INFO network checks: not performed")
    return "\n".join(lines) + "\n"
