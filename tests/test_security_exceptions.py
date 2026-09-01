import datetime as dt
import pytest
from scripts.security_exceptions import (
    ExceptionFileError, SecurityException, load,
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
