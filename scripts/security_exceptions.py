"""Parse and validate per-repo security exception files.

Policy (spec §7): exceptions are a last resort. An entry is legitimate only
when no fixed version exists AND the package cannot be replaced AND a second
reviewer has confirmed the vulnerable path is unreachable in our usage.

Scoping. A trivy entry may carry an optional `paths` list naming the files
that actually produce the finding. Without it the exception is tree-wide,
which means a NEW offending file added anywhere under the scanned roots
inherits the exception silently -- acceptable for a CVE in a pinned package,
dangerous for an IaC check like "container runs privileged". With it, the
suppression covers only the listed files and a new one still fails the build.
Paths are relative to the trivy SCAN ROOT (the directory handed to
`trivy config`, or the path inside the image), not to the repository root.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import yaml

REQUIRED_FIELDS: tuple[str, ...] = (
    "id", "package", "scanner", "reason",
    "replacement_considered", "usage_analysis", "approved_by", "recheck",
)
# `paths` is the one OPTIONAL field. It scopes a trivy exception to the files
# that actually produce the finding, so a new offending file elsewhere in the
# tree is NOT silently covered by an existing entry. Omitting it keeps the
# original tree-wide behaviour.
OPTIONAL_FIELDS: tuple[str, ...] = ("paths",)
VALID_SCANNERS: tuple[str, ...] = ("pip-audit", "trivy", "npm", "gitleaks")
NPM_BLOCKING_SEVERITIES = frozenset({"high", "critical"})

# Exception ids are interpolated into scanner command lines and into
# $GITHUB_OUTPUT. A newline or a shell metacharacter in a caller-authored id
# would let a PR inject extra step outputs or extra arguments, so the id is
# restricted to the character set every real advisory id already uses.
ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")

# gitleaks ids are fingerprints of the form <commit-sha>:<file-path>:<rule-id>:
# <line>, e.g. ba0a0d...4d:infrastructure/README.md:curl-auth-header:70 — they
# legitimately contain ':' and '/', so ID_PATTERN is too strict for them. This
# relaxed pattern is safe only because gitleaks ids are written to a
# .gitleaksignore file and are never interpolated into a shell argument or
# into $GITHUB_OUTPUT; it still forbids any whitespace, including newlines and
# tabs, so an id can never inject an extra line into that file.
GITLEAKS_ID_PATTERN = re.compile(r"^\S+$")

# Reported npm findings that carry no resolvable advisory id are labelled with
# this prefix so a package name is never mistaken for an advisory id.
NPM_PACKAGE_PREFIX = "package:"


class ExceptionFileError(ValueError):
    """The exception file is malformed or violates policy."""


class NpmAuditError(ValueError):
    """`npm audit` did not produce a usable report — the scan did not happen."""


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
    # Empty means tree-wide, which is what every entry written before this
    # field existed means. A tuple, not a list, so the dataclass stays frozen
    # and hashable.
    paths: tuple[str, ...] = ()


def _parse_paths(entry: dict, path: Path, index: int) -> tuple[str, ...]:
    """Validate and normalise an entry's optional `paths` list.

    Paths are matched by trivy against the file path it REPORTS, which is
    relative to the scan root -- the directory handed to `trivy config`, or the
    path inside the image for `trivy image`. They are therefore NOT relative to
    the repository root: scanning `infrastructure/` reports
    `previder-prod/node-tuning/x.yaml`, not `infrastructure/previder-prod/...`.
    """
    raw = entry.get("paths")
    if raw is None:
        return ()
    if entry["scanner"] != "trivy":
        raise ExceptionFileError(
            f"{path}: entry {index} sets 'paths' with scanner "
            f"{entry['scanner']!r}; only trivy supports path scoping. Leaving "
            f"it here would read as scoped while suppressing tree-wide."
        )
    if not isinstance(raw, list) or not raw:
        raise ExceptionFileError(
            f"{path}: entry {index} field 'paths' must be a non-empty list of "
            f"strings, got {raw!r}. Omit the field for a tree-wide exception."
        )
    out: list[str] = []
    for value in raw:
        if not isinstance(value, str) or not value.strip():
            raise ExceptionFileError(
                f"{path}: entry {index} has a non-string or empty entry in "
                f"'paths': {value!r}"
            )
        if value != value.strip() or any(c in value for c in "\n\r\t"):
            raise ExceptionFileError(
                f"{path}: entry {index} path {value!r} has leading, trailing "
                f"or embedded whitespace"
            )
        if value.startswith("/") or ".." in PurePosixPath(value).parts:
            raise ExceptionFileError(
                f"{path}: entry {index} path {value!r} must be relative to the "
                f"trivy scan root, with no '..' segments"
            )
        out.append(value)
    return tuple(out)


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
        # Each id is validated against the pattern for ITS OWN scanner.
        # gitleaks fingerprints legitimately contain ':' and '/', which
        # ID_PATTERN forbids, so gitleaks gets its own, wider pattern — never
        # the other way around. `fullmatch` (not `match`) is deliberate: `$`
        # without MULTILINE matches just before a trailing newline as well as
        # at the true end of string, so `match` alone would let an id ending
        # in "\n" slip through both patterns.
        if entry["scanner"] == "gitleaks":
            id_pattern = GITLEAKS_ID_PATTERN
            id_pattern_desc = "no whitespace"
        else:
            id_pattern = ID_PATTERN
            id_pattern_desc = "letters, digits, dot, underscore, hyphen"
        if not id_pattern.fullmatch(str(entry["id"])):
            raise ExceptionFileError(
                f"{path}: entry {i} has invalid id {entry['id']!r}; ids must match "
                f"{id_pattern.pattern} ({id_pattern_desc})"
            )
        if entry["id"] in seen:
            raise ExceptionFileError(f"{path}: duplicate exception id {entry['id']!r}")
        seen.add(entry["id"])

        out.append(SecurityException(
            paths=_parse_paths(entry, path, i),
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


def _statement(e: SecurityException) -> str:
    """The one-line note trivy echoes next to a suppressed finding.

    Mirrors the comment the plain format carries, collapsed to one line so it
    cannot break the YAML document.
    """
    return " ".join(
        f"{e.package}: {e.reason} (approved by {e.approved_by}, "
        f"recheck {e.recheck})".split()
    )


def trivyignore_yaml_text(excs: list[SecurityException]) -> str:
    """Render trivy's YAML ignore format, which supports per-path scoping.

    Every trivy id is written under BOTH `misconfigurations` and
    `vulnerabilities`. That is not belt-and-braces: the plain `.trivyignore`
    format this replaces is kind-agnostic -- one id there suppresses a
    misconfiguration and a vulnerability alike -- so listing the id under both
    kinds is what makes the YAML file EQUIVALENT rather than narrower. The
    `scanner: trivy` field records which tool produced the finding, not which
    of trivy's two scanners, and inventing a classifier over id shapes would
    fail silently in both directions. An id under the wrong kind simply never
    matches.
    """
    misconfigurations: list[dict] = []
    vulnerabilities: list[dict] = []
    for e in excs:
        if e.scanner != "trivy":
            continue
        item: dict = {"id": e.id, "statement": _statement(e)}
        if e.paths:
            item["paths"] = list(e.paths)
        misconfigurations.append(item)
        vulnerabilities.append(dict(item))
    header = (
        "# Generated from .github/security-exceptions.yml - do not edit by hand.\n"
        "# `paths` are relative to the trivy scan root, not the repo root.\n"
    )
    body = yaml.safe_dump(
        {"misconfigurations": misconfigurations, "vulnerabilities": vulnerabilities},
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
    )
    return header + body


def write_trivyignore(excs: list[SecurityException], base_path: str) -> Path:
    """Write the ignore file trivy should use, and return the path written.

    Trivy selects its parser BY FILE EXTENSION, so the YAML format has to be
    written at `<base>.yaml`. The plain format is kept for the common case
    where no exception is path-scoped: it is the format every repo used before
    this field existed, and keeping it means adding `paths` to one repo cannot
    change what any other repo's scan does.
    """
    if any(e.paths for e in excs if e.scanner == "trivy"):
        out = Path(f"{base_path}.yaml")
        out.write_text(trivyignore_yaml_text(excs))
    else:
        out = Path(base_path)
        out.write_text(trivyignore_text(excs))
    return out


def gitleaksignore_text(excs: list[SecurityException]) -> str:
    lines = ["# Generated from .github/security-exceptions.yml — do not edit by hand."]
    for e in excs:
        if e.scanner == "gitleaks":
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
    """Blocking npm findings that no npm-scanner exception covers.

    Raises NpmAuditError when the report has no `vulnerabilities` key. `npm
    audit` exits non-zero both on findings and on genuine failures (registry
    outage, ENOLOCK, EAUDITNOPJSON), and the workflow cannot tell the two apart
    from the exit code, so a report that never audited anything must fail the
    job rather than read as a clean scan.
    """
    if not isinstance(audit_json, dict) or "vulnerabilities" not in audit_json:
        detail = ""
        if isinstance(audit_json, dict) and "error" in audit_json:
            err = audit_json["error"]
            if isinstance(err, dict):
                parts = [str(err[k]) for k in ("code", "summary", "detail") if err.get(k)]
                detail = f": {' — '.join(parts)}" if parts else f": {err!r}"
            else:
                detail = f": {err!r}"
        raise NpmAuditError(
            "npm audit produced no 'vulnerabilities' report — nothing was "
            f"audited, failing closed{detail}"
        )

    allowed = {e.id for e in excs if e.scanner == "npm"}
    found: list[str] = []
    for pkg, entry in (audit_json.get("vulnerabilities") or {}).items():
        if not isinstance(entry, dict):
            continue
        if str(entry.get("severity", "")).lower() not in NPM_BLOCKING_SEVERITIES:
            continue
        ids = _advisory_ids(entry)
        # A blocking entry that resolves to no advisory id is still a blocking
        # entry: report it by its package key rather than dropping it.
        if not ids:
            ids = [f"{NPM_PACKAGE_PREFIX}{pkg}"]
        for aid in ids:
            bare = aid[len(NPM_PACKAGE_PREFIX):] if aid.startswith(NPM_PACKAGE_PREFIX) else aid
            if aid in allowed or bare in allowed or aid in found:
                continue
            found.append(aid)
    return found


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--file", required=True)
    ap.add_argument("--emit-args", action="store_true")
    # Takes a BASE path, not a final one: the helper appends `.yaml` when it
    # has to emit trivy's YAML format (trivy picks the parser by extension) and
    # prints the path it actually wrote on stdout, which is the caller's only
    # contract. Do not combine with --emit-args in one call; both write to
    # stdout.
    ap.add_argument("--emit-trivyignore", metavar="BASE_PATH")
    ap.add_argument("--emit-gitleaksignore")
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
        print(write_trivyignore(excs, args.emit_trivyignore))

    if args.emit_gitleaksignore:
        Path(args.emit_gitleaksignore).write_text(gitleaksignore_text(excs))

    if args.npm_audit_json:
        try:
            audit = json.loads(Path(args.npm_audit_json).read_text())
        except (OSError, json.JSONDecodeError) as exc:
            print(f"::error::cannot read npm audit report {args.npm_audit_json}: {exc}",
                  file=sys.stderr)
            return 1
        try:
            blocking = npm_unexcepted(audit, excs)
        except NpmAuditError as exc:
            print(f"::error::{exc}", file=sys.stderr)
            return 1
        for aid in blocking:
            print(f"::error::npm finding {aid} is high or critical and has no exception.",
                  file=sys.stderr)
        if blocking:
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
