import datetime as dt
import pytest
from scripts.security_exceptions import (
    ExceptionFileError, NpmAuditError, SecurityException, load,
    expired, gitleaksignore_text, main, npm_unexcepted, pip_audit_args,
    trivyignore_text,
)

VALID_ENTRY = """
version: 1
exceptions:
  - id: PYSEC-2026-3412
    package: weasyprint
    scanner: pip-audit
    reason: No fixed release exists; latest 68.1 is still affected.
    replacement_considered: >-
      Evaluated reportlab and wkhtmltopdf; neither supports the CSS
      paged-media features the export templates depend on.
    usage_analysis: >-
      The advisory needs attacker-controlled CSS. We render only
      server-side templates; no user input reaches the stylesheet.
    approved_by: "@some-reviewer"
    recheck: 2026-12-01
"""

def _write(tmp_path, text):
    p = tmp_path / "security-exceptions.yml"
    p.write_text(text)
    return p

def test_missing_file_yields_no_exceptions(tmp_path):
    assert load(tmp_path / "nope.yml") == []

def test_empty_file_yields_no_exceptions(tmp_path):
    assert load(_write(tmp_path, "")) == []

def test_valid_entry_is_parsed(tmp_path):
    (exc,) = load(_write(tmp_path, VALID_ENTRY))
    assert isinstance(exc, SecurityException)
    assert exc.id == "PYSEC-2026-3412"
    assert exc.package == "weasyprint"
    assert exc.scanner == "pip-audit"
    assert exc.recheck == dt.date(2026, 12, 1)

def test_missing_required_field_is_rejected(tmp_path):
    text = VALID_ENTRY.replace('    approved_by: "@some-reviewer"\n', "")
    with pytest.raises(ExceptionFileError, match="approved_by"):
        load(_write(tmp_path, text))

def test_unknown_scanner_is_rejected(tmp_path):
    text = VALID_ENTRY.replace("scanner: pip-audit", "scanner: snyk")
    with pytest.raises(ExceptionFileError, match="snyk"):
        load(_write(tmp_path, text))

def test_duplicate_id_is_rejected(tmp_path):
    doubled = VALID_ENTRY + VALID_ENTRY.split("exceptions:")[1]
    with pytest.raises(ExceptionFileError, match="duplicate"):
        load(_write(tmp_path, doubled))

def test_non_date_recheck_is_rejected(tmp_path):
    text = VALID_ENTRY.replace("recheck: 2026-12-01", 'recheck: "soon"')
    with pytest.raises(ExceptionFileError, match="recheck"):
        load(_write(tmp_path, text))

def test_whitespace_only_required_field_is_rejected(tmp_path):
    text = VALID_ENTRY.replace(
        "    usage_analysis: >-\n", "    usage_analysis: '   '\n"
    )
    # collapse the now-orphaned continuation lines of the folded block
    text = "\n".join(
        l for l in text.split("\n")
        if not l.startswith("      The advisory needs")
        and not l.startswith("      server-side templates")
    )
    with pytest.raises(ExceptionFileError, match="usage_analysis"):
        load(_write(tmp_path, text))


def _exc(id_, scanner="pip-audit", recheck=dt.date(2026, 12, 1)):
    return SecurityException(
        id=id_, package="pkg", scanner=scanner, reason="r",
        replacement_considered="rc", usage_analysis="ua",
        approved_by="@r", recheck=recheck,
    )


def test_expired_returns_only_past_recheck_dates():
    fresh = _exc("A", recheck=dt.date(2026, 12, 1))
    stale = _exc("B", recheck=dt.date(2026, 8, 1))
    assert expired([fresh, stale], today=dt.date(2026, 9, 1)) == [stale]


def test_recheck_date_is_inclusive():
    on_the_day = _exc("A", recheck=dt.date(2026, 9, 1))
    assert expired([on_the_day], today=dt.date(2026, 9, 1)) == []


def test_pip_audit_args_only_include_pip_audit_scanner():
    excs = [_exc("A"), _exc("B", scanner="trivy")]
    assert pip_audit_args(excs) == ["--ignore-vuln", "A"]


def test_pip_audit_args_empty_when_no_exceptions():
    assert pip_audit_args([]) == []


def test_trivyignore_text_lists_ids_with_comments():
    text = trivyignore_text([_exc("CVE-1", scanner="trivy")])
    assert "CVE-1" in text
    assert "pkg" in text


def test_npm_unexcepted_flags_high_and_critical_only():
    audit = {"vulnerabilities": {
        "lodash":  {"severity": "critical", "via": [{"url": "https://github.com/advisories/GHSA-aaa"}]},
        "chalk":   {"severity": "moderate", "via": [{"url": "https://github.com/advisories/GHSA-bbb"}]},
    }}
    assert npm_unexcepted(audit, []) == ["GHSA-aaa"]


def test_npm_unexcepted_respects_exceptions():
    audit = {"vulnerabilities": {
        "lodash": {"severity": "critical", "via": [{"url": "https://github.com/advisories/GHSA-aaa"}]},
    }}
    assert npm_unexcepted(audit, [_exc("GHSA-aaa", scanner="npm")]) == []


def test_npm_unexcepted_handles_mixed_via_shapes():
    audit = {"vulnerabilities": {
        "lodash": {"severity": "critical", "via": [
            "some-transitive-pkg",
            {"url": "https://github.com/advisories/GHSA-aaa"},
        ]},
        "only-string-via": {"severity": "high", "via": ["lodash"]},
    }}
    # A blocking entry that resolves to no advisory id must still be reported,
    # by package key — dropping it would be a silent fail-open.
    assert npm_unexcepted(audit, []) == ["GHSA-aaa", "package:only-string-via"]


def test_npm_unexcepted_reports_blocking_entry_with_unresolvable_via():
    audit = {"vulnerabilities": {
        "left-pad": {"severity": "critical", "via": [{"source": 123, "title": "t"}]},
    }}
    assert npm_unexcepted(audit, []) == ["package:left-pad"]


def test_npm_unexcepted_package_fallback_respects_exception_on_package_name():
    audit = {"vulnerabilities": {
        "left-pad": {"severity": "critical", "via": [{"source": 123, "title": "t"}]},
    }}
    assert npm_unexcepted(audit, [_exc("left-pad", scanner="npm")]) == []


def test_npm_unexcepted_severity_comparison_is_case_insensitive():
    audit = {"vulnerabilities": {
        "lodash": {"severity": "Critical", "via": [{"url": "https://github.com/advisories/GHSA-aaa"}]},
        "chalk": {"severity": "HIGH", "via": [{"url": "https://github.com/advisories/GHSA-bbb"}]},
        "quiet": {"severity": "Moderate", "via": [{"url": "https://github.com/advisories/GHSA-ccc"}]},
    }}
    assert npm_unexcepted(audit, []) == ["GHSA-aaa", "GHSA-bbb"]


def test_npm_unexcepted_rejects_error_shaped_report():
    """`npm audit` writes {"error": ...} on registry outage / ENOLOCK and still
    exits non-zero; the workflow's `|| true` swallows that, so an audit report
    with no `vulnerabilities` key must fail closed, never read as clean."""
    audit = {"error": {"code": "ENOLOCK", "summary": "no lockfile", "detail": "…"}}
    with pytest.raises(NpmAuditError, match="ENOLOCK"):
        npm_unexcepted(audit, [])


def test_npm_unexcepted_rejects_report_without_vulnerabilities_key():
    with pytest.raises(NpmAuditError, match="vulnerabilities"):
        npm_unexcepted({}, [])


def test_npm_unexcepted_accepts_empty_vulnerabilities_map():
    assert npm_unexcepted({"vulnerabilities": {}}, []) == []


def test_cli_fails_on_error_shaped_npm_audit_json(tmp_path, capsys):
    """End to end: the exit code, not just the function, must be non-zero."""
    report = tmp_path / "audit.json"
    report.write_text('{"error": {"code": "ENOLOCK", "summary": "no lockfile"}}')
    rc = main(["--file", str(tmp_path / "nope.yml"), "--npm-audit-json", str(report)])
    assert rc == 1
    assert "ENOLOCK" in capsys.readouterr().err


def test_exception_id_with_newline_is_rejected(tmp_path):
    """An id carrying a newline would inject extra keys into $GITHUB_OUTPUT."""
    text = VALID_ENTRY.replace(
        "id: PYSEC-2026-3412", 'id: "GHSA-a\\nEVIL=1"'
    )
    with pytest.raises(ExceptionFileError, match="invalid id"):
        load(_write(tmp_path, text))


def test_exception_id_with_trailing_newline_only_is_rejected(tmp_path):
    """Regression test for the match->fullmatch fix.

    `$` without re.MULTILINE matches both at the true end of string AND just
    before a trailing newline at the end of the string. An id that is
    otherwise valid, followed by a single trailing "\\n" and nothing else,
    is the one shape that `ID_PATTERN.match()` would have let through even
    though `ID_PATTERN.fullmatch()` rejects it — the two existing newline
    tests above append content *after* the newline, which `.match()` already
    caught, so neither exercises this quirk.
    """
    text = VALID_ENTRY.replace(
        "id: PYSEC-2026-3412", 'id: "GHSA-a\\n"'
    )
    with pytest.raises(ExceptionFileError, match="invalid id"):
        load(_write(tmp_path, text))


@pytest.mark.parametrize("bad", ["GHSA a", "GHSA-a;rm -rf /", "GHSA-$(id)", "GHSA-a>out"])
def test_exception_ids_with_shell_metacharacters_are_rejected(tmp_path, bad):
    text = VALID_ENTRY.replace("id: PYSEC-2026-3412", f'id: "{bad}"')
    with pytest.raises(ExceptionFileError, match="invalid id"):
        load(_write(tmp_path, text))


def test_trivyignore_text_excludes_other_scanners():
    """Negative isolation: a pip-audit exception must never reach trivy."""
    text = trivyignore_text([
        _exc("CVE-1", scanner="trivy"),
        _exc("PYSEC-2026-3412", scanner="pip-audit"),
        _exc("GHSA-aaa", scanner="npm"),
    ])
    assert "CVE-1" in text
    assert "PYSEC-2026-3412" not in text
    assert "GHSA-aaa" not in text


GITLEAKS_FINGERPRINT = (
    "ba0a0dcd23d3a8b864fe258686e77422db7397d4:infrastructure/README.md:"
    "curl-auth-header:70"
)


def test_gitleaks_entry_with_fingerprint_id_is_accepted(tmp_path):
    text = VALID_ENTRY.replace("scanner: pip-audit", "scanner: gitleaks")
    text = text.replace("id: PYSEC-2026-3412", f"id: {GITLEAKS_FINGERPRINT}")
    (exc,) = load(_write(tmp_path, text))
    assert exc.id == GITLEAKS_FINGERPRINT
    assert exc.scanner == "gitleaks"


def test_gitleaks_fingerprint_id_is_rejected_for_pip_audit_scanner(tmp_path):
    """Proves the strict ID_PATTERN still applies to scanners other than
    gitleaks: a gitleaks-shaped id (colons, slashes) is not a valid pip-audit
    id even though it would be fine for gitleaks itself."""
    text = VALID_ENTRY.replace("id: PYSEC-2026-3412", f"id: {GITLEAKS_FINGERPRINT}")
    with pytest.raises(ExceptionFileError, match="invalid id"):
        load(_write(tmp_path, text))


def test_gitleaks_id_with_newline_is_rejected(tmp_path):
    text = VALID_ENTRY.replace("scanner: pip-audit", "scanner: gitleaks")
    text = text.replace(
        "id: PYSEC-2026-3412", 'id: "abc:def:rule:1\\nEVIL=1"'
    )
    with pytest.raises(ExceptionFileError, match="invalid id"):
        load(_write(tmp_path, text))


def test_gitleaks_id_with_space_is_rejected(tmp_path):
    text = VALID_ENTRY.replace("scanner: pip-audit", "scanner: gitleaks")
    text = text.replace(
        "id: PYSEC-2026-3412", 'id: "abc:def:rule id:1"'
    )
    with pytest.raises(ExceptionFileError, match="invalid id"):
        load(_write(tmp_path, text))


def test_gitleaks_id_with_trailing_newline_only_is_rejected(tmp_path):
    """Same regression as test_exception_id_with_trailing_newline_only_is_
    rejected, but for GITLEAKS_ID_PATTERN (`^\\S+$`): a fingerprint followed
    by a single trailing "\\n" and nothing else is exactly the shape
    `.match()` would wrongly accept and `.fullmatch()` correctly rejects.
    """
    text = VALID_ENTRY.replace("scanner: pip-audit", "scanner: gitleaks")
    text = text.replace(
        "id: PYSEC-2026-3412", 'id: "abc:def:rule:1\\n"'
    )
    with pytest.raises(ExceptionFileError, match="invalid id"):
        load(_write(tmp_path, text))


def test_gitleaksignore_text_lists_ids_with_comments():
    text = gitleaksignore_text([_exc(GITLEAKS_FINGERPRINT, scanner="gitleaks")])
    assert GITLEAKS_FINGERPRINT in text
    assert "pkg" in text


def test_gitleaksignore_text_excludes_other_scanners():
    """Negative isolation: exceptions for other scanners must never reach
    the gitleaksignore file."""
    text = gitleaksignore_text([
        _exc(GITLEAKS_FINGERPRINT, scanner="gitleaks"),
        _exc("PYSEC-2026-3412", scanner="pip-audit"),
        _exc("CVE-1", scanner="trivy"),
        _exc("GHSA-aaa", scanner="npm"),
    ])
    assert GITLEAKS_FINGERPRINT in text
    assert "PYSEC-2026-3412" not in text
    assert "CVE-1" not in text
    assert "GHSA-aaa" not in text
