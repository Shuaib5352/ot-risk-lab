from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Iterable

from .version import METHODOLOGY_VERSIONS, SOFTWARE_VERSION


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _expand_files(inputs: Iterable[Path]) -> list[Path]:
    files: list[Path] = []
    for input_path in inputs:
        if not input_path.exists():
            raise ValueError(f"input does not exist: {input_path}")
        if input_path.is_symlink():
            raise ValueError(f"manifest input must not be a symbolic link: {input_path}")
        if input_path.is_dir():
            for path in input_path.rglob("*"):
                if path.is_symlink():
                    continue
                if path.is_file():
                    files.append(path)
        else:
            files.append(input_path)
    unique = sorted({path.resolve() for path in files}, key=lambda path: str(path))
    if not unique:
        raise ValueError("manifest requires at least one file")
    return unique


def build_experiment_manifest(
    inputs: Iterable[Path],
    *,
    label: str = "",
    parameters: dict[str, str] | None = None,
    base_dir: Path | None = None,
) -> dict[str, object]:
    files = _expand_files(inputs)
    if base_dir is None:
        common = Path(files[0]).parent
        for path in files[1:]:
            while common not in path.parents and common != path:
                if common.parent == common:
                    break
                common = common.parent
        base_dir = common
    base_dir = base_dir.resolve()
    entries = []
    for path in files:
        try:
            relative = path.relative_to(base_dir)
        except ValueError as exc:
            raise ValueError(f"{path} is outside manifest base directory {base_dir}") from exc
        entries.append(
            {
                "path": relative.as_posix(),
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    return {
        "manifest_schema_version": "1.0",
        "software": {"name": "OT-RiskLab", "version": SOFTWARE_VERSION},
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "label": str(label).strip(),
        "base_dir": str(base_dir),
        "methodology_versions": dict(METHODOLOGY_VERSIONS),
        "parameters": dict(sorted((parameters or {}).items())),
        "files": entries,
    }


def verify_experiment_manifest(manifest_path: Path, *, base_dir: Path | None = None) -> dict[str, object]:
    with manifest_path.open("r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
        raise ValueError("invalid experiment manifest")
    root = base_dir.resolve() if base_dir is not None else Path(manifest.get("base_dir") or manifest_path.parent).resolve()
    checks = []
    for entry in manifest["files"]:
        relative = Path(entry["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"unsafe manifest path: {relative}")
        path = (root / relative).resolve()
        if root not in path.parents and path != root:
            raise ValueError(f"manifest path escapes base directory: {relative}")
        symlink = path.is_symlink()
        exists = path.is_file() and not symlink
        actual_size = path.stat().st_size if exists else None
        actual_hash = sha256_file(path) if exists else None
        passed = exists and actual_size == entry.get("size") and actual_hash == entry.get("sha256")
        checks.append(
            {
                "path": relative.as_posix(),
                "exists": exists,
                "symlink": symlink,
                "size_matches": exists and actual_size == entry.get("size"),
                "sha256_matches": exists and actual_hash == entry.get("sha256"),
                "passed": bool(passed),
            }
        )
    return {
        "passed": all(check["passed"] for check in checks),
        "base_dir": str(root),
        "checks": checks,
    }
