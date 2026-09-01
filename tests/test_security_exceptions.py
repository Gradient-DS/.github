import datetime as dt
import pytest
from scripts.security_exceptions import (
    ExceptionFileError, SecurityException, load,
    expired, npm_unexcepted, pip_audit_args, trivyignore_text,
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
