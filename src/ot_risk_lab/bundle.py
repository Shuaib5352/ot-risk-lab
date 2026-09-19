from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import zipfile

from .manifest import sha256_file
from .version import SOFTWARE_VERSION

_EXCLUDED_PARTS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".ruff_cache", "dist", "build"}
_EXCLUDED_SUFFIXES = {".pyc", ".pyo"}
_FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
_MAX_VERIFY_ENTRIES = 10000
_MAX_VERIFY_FILE_BYTES = 2 * 1024 * 1024 * 1024
_MAX_VERIFY_TOTAL_BYTES = 5 * 1024 * 1024 * 1024
_RESERVED_NAMES = {"MANIFEST.json", "SHA256SUMS.txt"}


def _allowed(path: Path) -> bool:
    return not any(part in _EXCLUDED_PARTS for part in path.parts) and path.suffix.lower() not in _EXCLUDED_SUFFIXES


def _collect(inputs: list[Path]) -> list[tuple[Path, str]]:
    entries: list[tuple[Path, str]] = []
    seen_names: set[str] = set()
    for input_path in inputs:
        if not input_path.exists():
            raise ValueError(f"input does not exist: {input_path}")
        if input_path.is_symlink():
            raise ValueError(f"supplement input must not be a symbolic link: {input_path}")
        if input_path.is_dir():
            root_name = input_path.name
            for path in sorted((p for p in input_path.rglob("*") if p.is_file() and not p.is_symlink() and _allowed(p)), key=lambda p: str(p)):
                name = (PurePosixPath(root_name) / PurePosixPath(path.relative_to(input_path).as_posix())).as_posix()
                if name in seen_names:
                    raise ValueError(f"duplicate archive path: {name}")
                seen_names.add(name)
                entries.append((path, name))
        elif _allowed(input_path):
            name = input_path.name
            if name in seen_names:
                raise ValueError(f"duplicate archive path: {name}")
            seen_names.add(name)
            entries.append((input_path, name))
    if not entries:
        raise ValueError("supplement bundle contains no eligible files")
    return entries


def _write_bytes(archive: zipfile.ZipFile, name: str, payload: bytes) -> None:
    info = zipfile.ZipInfo(filename=name, date_time=_FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    archive.writestr(info, payload)


def build_supplement_bundle(inputs: list[Path], output: Path, *, label: str = "") -> dict[str, object]:
    entries = _collect(inputs)
    output_resolved = output.resolve()
    entries = [(source, name) for source, name in entries if source.resolve() != output_resolved]
    if not entries:
        raise ValueError("supplement bundle contains no eligible files after excluding the output archive")
    conflicting = sorted(name for _, name in entries if name in _RESERVED_NAMES)
    if conflicting:
        raise ValueError("input conflicts with reserved bundle metadata name(s): " + ", ".join(conflicting))
    files = []
    for source, name in entries:
        files.append({"path": name, "size": source.stat().st_size, "sha256": sha256_file(source)})
    manifest = {
        "bundle_schema_version": "1.0",
        "software": {"name": "OT-RiskLab", "version": SOFTWARE_VERSION},
        "label": str(label).strip(),
        "deterministic_zip": True,
        "files": files,
    }
    checksums = "".join(f"{entry['sha256']}  {entry['path']}\n" for entry in files)
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w") as archive:
        for source, name in entries:
            _write_bytes(archive, name, source.read_bytes())
        _write_bytes(archive, "MANIFEST.json", json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8") + b"\n")
        _write_bytes(archive, "SHA256SUMS.txt", checksums.encode("utf-8"))
    return {
        "output": str(output),
        "files": len(files),
        "size": output.stat().st_size,
        "sha256": sha256_file(output),
        "label": str(label).strip(),
    }


def verify_supplement_bundle(path: Path) -> dict[str, object]:
    with zipfile.ZipFile(path, "r") as archive:
        infos = archive.infolist()
        if len(infos) > _MAX_VERIFY_ENTRIES:
            raise ValueError(f"bundle contains too many entries ({len(infos)} > {_MAX_VERIFY_ENTRIES})")
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            raise ValueError("bundle contains duplicate archive paths")
        total_size = 0
        for info in infos:
            name = info.filename
            pure = PurePosixPath(name)
            if pure.is_absolute() or ".." in pure.parts:
                raise ValueError(f"unsafe archive path: {name}")
            if info.file_size > _MAX_VERIFY_FILE_BYTES:
                raise ValueError(f"bundle entry exceeds verification size limit: {name}")
            total_size += info.file_size
            if total_size > _MAX_VERIFY_TOTAL_BYTES:
                raise ValueError("bundle exceeds total verification size limit")
        try:
            manifest = json.loads(archive.read("MANIFEST.json"))
        except KeyError as exc:
            raise ValueError("bundle is missing MANIFEST.json") from exc
        checks = []
        for entry in manifest.get("files", []):
            name = entry["path"]
            try:
                info = archive.getinfo(name)
            except KeyError:
                checks.append({"path": name, "exists": False, "passed": False})
                continue
            digest = hashlib.sha256()
            with archive.open(info, "r") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            actual_hash = digest.hexdigest()
            passed = info.file_size == entry.get("size") and actual_hash == entry.get("sha256")
            checks.append(
                {
                    "path": name,
                    "exists": True,
                    "size_matches": info.file_size == entry.get("size"),
                    "sha256_matches": actual_hash == entry.get("sha256"),
                    "passed": passed,
                }
            )
        extras = sorted(set(names) - {entry["path"] for entry in manifest.get("files", [])} - _RESERVED_NAMES)
        expected_checksums = "".join(f"{entry['sha256']}  {entry['path']}\n" for entry in manifest.get("files", []))
        try:
            actual_checksums = archive.read("SHA256SUMS.txt").decode("utf-8")
            checksums_match = actual_checksums == expected_checksums
        except (KeyError, UnicodeDecodeError):
            checksums_match = False
        return {
            "passed": bool(checks) and all(check["passed"] for check in checks) and not extras and checksums_match,
            "checks": checks,
            "unexpected_entries": extras,
            "checksums_file_matches_manifest": checksums_match,
            "bundle_sha256": sha256_file(path),
        }
