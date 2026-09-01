"""Parse and validate per-repo security exception files.

Policy (spec §7): exceptions are a last resort. An entry is legitimate only
when no fixed version exists AND the package cannot be replaced AND a second
reviewer has confirmed the vulnerable path is unreachable in our usage.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from pathlib import Path

import yaml

REQUIRED_FIELDS: tuple[str, ...] = (
    "id", "package", "scanner", "reason",
    "replacement_considered", "usage_analysis", "approved_by", "recheck",
)
VALID_SCANNERS: tuple[str, ...] = ("pip-audit", "trivy", "npm")


class ExceptionFileError(ValueError):
    """The exception file is malformed or violates policy."""


@dataclass(frozen=True)
class SecurityException:
    id: str
    package: str
    scanner: str
    reason: str
    replacement_considered: str
    usage_analysis: str
    approved_by: str
    recheck: dt.date


def load(path: str | Path) -> list[SecurityException]:
    path = Path(path)
    if not path.exists():
        return []

    raw = yaml.safe_load(path.read_text()) or {}
    entries = raw.get("exceptions") or []

    out: list[SecurityException] = []
    seen: set[str] = set()
    for i, entry in enumerate(entries):
        missing = [f for f in REQUIRED_FIELDS if not str(entry.get(f, "")).strip()]
        if missing:
            raise ExceptionFileError(
                f"{path}: entry {i} is missing required field(s): {', '.join(missing)}"
            )
        if entry["scanner"] not in VALID_SCANNERS:
            raise ExceptionFileError(
                f"{path}: entry {i} has unknown scanner {entry['scanner']!r}; "
                f"expected one of {', '.join(VALID_SCANNERS)}"
            )
        if not isinstance(entry["recheck"], dt.date):
            raise ExceptionFileError(
                f"{path}: entry {i} field 'recheck' must be a YAML date "
                f"(YYYY-MM-DD), got {entry['recheck']!r}"
            )
        if entry["id"] in seen:
            raise ExceptionFileError(f"{path}: duplicate exception id {entry['id']!r}")
        seen.add(entry["id"])

        out.append(SecurityException(
            id=entry["id"],
            package=entry["package"],
            scanner=entry["scanner"],
            reason=entry["reason"],
            replacement_considered=entry["replacement_considered"],
            usage_analysis=entry["usage_analysis"],
            approved_by=entry["approved_by"],
            recheck=entry["recheck"],
        ))
    return out
