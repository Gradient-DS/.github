"""Parse and validate per-repo security exception files.

Policy (spec §7): exceptions are a last resort. An entry is legitimate only
when no fixed version exists AND the package cannot be replaced AND a second
reviewer has confirmed the vulnerable path is unreachable in our usage.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

REQUIRED_FIELDS: tuple[str, ...] = (
    "id", "package", "scanner", "reason",
    "replacement_considered", "usage_analysis", "approved_by", "recheck",
)
VALID_SCANNERS: tuple[str, ...] = ("pip-audit", "trivy", "npm")
NPM_BLOCKING_SEVERITIES = frozenset({"high", "critical"})


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


def expired(excs: list[SecurityException], today: dt.date) -> list[SecurityException]:
    """Entries whose recheck date has passed. Inclusive: due today is not expired."""
    return [e for e in excs if e.recheck < today]


def pip_audit_args(excs: list[SecurityException]) -> list[str]:
    args: list[str] = []
    for e in excs:
        if e.scanner == "pip-audit":
            args += ["--ignore-vuln", e.id]
    return args


def trivyignore_text(excs: list[SecurityException]) -> str:
    lines = ["# Generated from .github/security-exceptions.yml — do not edit by hand."]
    for e in excs:
        if e.scanner == "trivy":
            lines.append(f"# {e.package}: {e.reason} (approved by {e.approved_by}, recheck {e.recheck})")
            lines.append(e.id)
    return "\n".join(lines) + "\n"


def _advisory_ids(entry: dict) -> list[str]:
    ids = []
    for via in entry.get("via", []):
        if isinstance(via, dict) and "url" in via:
            ids.append(via["url"].rstrip("/").split("/")[-1])
    return ids


def npm_unexcepted(audit_json: dict, excs: list[SecurityException]) -> list[str]:
    """Advisory ids at high/critical that no npm-scanner exception covers."""
    allowed = {e.id for e in excs if e.scanner == "npm"}
    found: list[str] = []
    for entry in (audit_json.get("vulnerabilities") or {}).values():
        if entry.get("severity") not in NPM_BLOCKING_SEVERITIES:
            continue
        for aid in _advisory_ids(entry):
            if aid not in allowed and aid not in found:
                found.append(aid)
    return found


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--file", required=True)
    ap.add_argument("--emit-args", action="store_true")
    ap.add_argument("--emit-trivyignore")
    ap.add_argument("--check-expiry", action="store_true")
    ap.add_argument("--npm-audit-json")
    args = ap.parse_args(argv)

    try:
        excs = load(args.file)
    except ExceptionFileError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1

    if args.check_expiry:
        stale = expired(excs, dt.date.today())
        for e in stale:
            print(
                f"::error::Security exception {e.id} ({e.package}) expired on "
                f"{e.recheck}. Re-verify with @Gradient-DS/security, fix the "
                f"finding, or extend the recheck date with fresh analysis.",
                file=sys.stderr,
            )
        if stale:
            return 1

    if args.emit_args:
        print(" ".join(pip_audit_args(excs)))

    if args.emit_trivyignore:
        Path(args.emit_trivyignore).write_text(trivyignore_text(excs))

    if args.npm_audit_json:
        audit = json.loads(Path(args.npm_audit_json).read_text())
        blocking = npm_unexcepted(audit, excs)
        for aid in blocking:
            print(f"::error::npm advisory {aid} is high or critical and has no exception.",
                  file=sys.stderr)
        if blocking:
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
