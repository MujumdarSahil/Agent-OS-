"""Tests for check_pip_audit.py (fail-closed dependency audit gate).

All tests run fully offline without any network calls.
"""

import datetime
from unittest.mock import MagicMock, patch

import pytest
import requests

from check_pip_audit import (
    audit,
    check_exemption,
    get_osv_severity,
    load_and_validate_exemptions,
    parse_cvss_severity,
)


def _make_pip_audit_output(dependencies):
    return (0, {"dependencies": dependencies}, "")


def _make_dep(name, version, vuln_ids):
    return {
        "name": name,
        "version": version,
        "vulns": [{"id": vid} for vid in vuln_ids],
    }


def test_cvss_vector_parsing():
    # CVSS v3.1 High (8.1)
    v3_high = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
    assert parse_cvss_severity(v3_high) == "HIGH"

    # CVSS v3.1 Low (3.7)
    v3_low = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
    assert parse_cvss_severity(v3_low) == "LOW"

    # CVSS v4.0 Critical (9.3)
    v4_crit = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P"
    assert parse_cvss_severity(v4_crit) == "CRITICAL"

    # Unparseable / corrupted vector -> UNKNOWN
    assert parse_cvss_severity("CVSS:3.1/NOT_A_VALID_VECTOR") == "UNKNOWN"
    assert parse_cvss_severity("RANDOM_STRING") == "UNKNOWN"
    assert parse_cvss_severity("") == "UNKNOWN"


def test_high_fails(tmp_path):
    mock_audit = _make_pip_audit_output([
        _make_dep("vulnerable-pkg", "1.0.0", ["CVE-2026-99999"])
    ])

    with patch("check_pip_audit.fetch_osv_record") as mock_fetch:
        mock_fetch.return_value = (
            {"database_specific": {"severity": "HIGH"}, "aliases": []},
            True,
        )
        exit_code, summary, errors = audit(
            exemptions_path=str(tmp_path / "exemptions.json"),
            mock_pip_audit=mock_audit,
        )

    assert exit_code == 1
    assert len(summary) == 1
    assert summary[0]["decision"] == "FAIL"
    assert summary[0]["severity"] == "HIGH"
    assert any("not exempted" in err for err in errors)


def test_low_passes(tmp_path):
    mock_audit = _make_pip_audit_output([
        _make_dep("low-pkg", "2.1.0", ["CVE-2026-11111"])
    ])

    with patch("check_pip_audit.fetch_osv_record") as mock_fetch:
        mock_fetch.return_value = (
            {"database_specific": {"severity": "LOW"}, "aliases": []},
            True,
        )
        exit_code, summary, errors = audit(
            exemptions_path=str(tmp_path / "exemptions.json"),
            mock_pip_audit=mock_audit,
        )

    assert exit_code == 0
    assert len(summary) == 1
    assert summary[0]["decision"] == "BELOW THRESHOLD"
    assert summary[0]["severity"] == "LOW"
    assert len(errors) == 0


def test_unknown_fails(tmp_path):
    # Severity cannot be resolved -> must fail closed
    mock_audit = _make_pip_audit_output([
        _make_dep("mysterious-pkg", "0.5.0", ["PYSEC-2026-00000"])
    ])

    with patch("check_pip_audit.fetch_osv_record") as mock_fetch:
        mock_fetch.return_value = (
            {"database_specific": {}, "severity": [], "aliases": []},
            True,
        )
        exit_code, summary, errors = audit(
            exemptions_path=str(tmp_path / "exemptions.json"),
            mock_pip_audit=mock_audit,
        )

    assert exit_code == 1
    assert len(summary) == 1
    assert summary[0]["decision"] == "FAIL"
    assert summary[0]["severity"] == "UNKNOWN"
    assert any("not exempted" in err for err in errors)


def test_osv_down_fails(tmp_path):
    # OSV unreachable after retries -> must fail closed
    mock_audit = _make_pip_audit_output([
        _make_dep("some-pkg", "1.2.3", ["CVE-2026-55555"])
    ])

    with patch("check_pip_audit.fetch_osv_record") as mock_fetch:
        mock_fetch.return_value = (None, False)
        exit_code, summary, errors = audit(
            exemptions_path=str(tmp_path / "exemptions.json"),
            mock_pip_audit=mock_audit,
        )

    assert exit_code == 1
    assert len(summary) == 1
    assert summary[0]["decision"] == "FAIL"
    assert "OSV UNREACHABLE" in summary[0]["severity"]


def test_exempted_passes(tmp_path):
    ex_file = tmp_path / "exemptions.json"
    ex_file.write_text(
        """[
      {
        "id": "PYSEC-2026-311",
        "package": "chromadb",
        "reason": "Known unpatched",
        "added": "2026-11-01",
        "expires": "2026-12-01",
        "link": "https://example.com"
      }
    ]"""
    )

    mock_audit = _make_pip_audit_output([
        _make_dep("chromadb", "1.5.9", ["PYSEC-2026-311"])
    ])

    fixed_today = datetime.date(2026, 11, 13)

    with patch("check_pip_audit.fetch_osv_record") as mock_fetch:
        mock_fetch.return_value = (
            {"database_specific": {"severity": "HIGH"}, "aliases": []},
            True,
        )
        exit_code, summary, errors = audit(
            exemptions_path=str(ex_file),
            current_date=fixed_today,
            mock_pip_audit=mock_audit,
        )

    assert exit_code == 0
    assert len(summary) == 1
    assert summary[0]["decision"] == "EXEMPT"
    assert summary[0]["version"] == "1.5.9"
    assert len(errors) == 0


def test_expired_exemption_fails(tmp_path):
    ex_file = tmp_path / "exemptions.json"
    ex_file.write_text(
        """[
      {
        "id": "PYSEC-2026-311",
        "package": "chromadb",
        "reason": "Expired exemption",
        "added": "2026-08-01",
        "expires": "2026-09-01",
        "link": "https://example.com"
      }
    ]"""
    )

    mock_audit = _make_pip_audit_output([
        _make_dep("chromadb", "1.5.9", ["PYSEC-2026-311"])
    ])

    fixed_today = datetime.date(2026, 11, 13)

    with patch("check_pip_audit.fetch_osv_record") as mock_fetch:
        mock_fetch.return_value = (
            {"database_specific": {"severity": "HIGH"}, "aliases": []},
            True,
        )
        exit_code, summary, errors = audit(
            exemptions_path=str(ex_file),
            current_date=fixed_today,
            mock_pip_audit=mock_audit,
        )

    assert exit_code == 1
    assert len(summary) == 1
    assert "FAIL (EXPIRED: 2026-09-01)" in summary[0]["decision"]
    assert any("expired on 2026-09-01" in err for err in errors)


def test_same_id_different_package_fails(tmp_path):
    ex_file = tmp_path / "exemptions.json"
    ex_file.write_text(
        """[
      {
        "id": "PYSEC-2026-311",
        "package": "chromadb",
        "reason": "Exempt for chromadb only",
        "added": "2026-11-01",
        "expires": "2027-01-01",
        "link": "https://example.com"
      }
    ]"""
    )

    # Same vuln ID, but on a different package (e.g. evil-pkg)
    mock_audit = _make_pip_audit_output([
        _make_dep("evil-pkg", "2.0.0", ["PYSEC-2026-311"])
    ])

    fixed_today = datetime.date(2026, 11, 13)

    with patch("check_pip_audit.fetch_osv_record") as mock_fetch:
        mock_fetch.return_value = (
            {"database_specific": {"severity": "HIGH"}, "aliases": []},
            True,
        )
        exit_code, summary, errors = audit(
            exemptions_path=str(ex_file),
            current_date=fixed_today,
            mock_pip_audit=mock_audit,
        )

    assert exit_code == 1
    assert len(summary) == 1
    assert summary[0]["decision"] == "FAIL"


def test_pip_audit_error_fails(tmp_path):
    # pip-audit returns non-zero with error output (e.g. pip upgrade failed or bad requirements)
    mock_audit = (2, None, "error: invalid requirement line in requirements.txt")

    exit_code, summary, errors = audit(
        exemptions_path=str(tmp_path / "exemptions.json"),
        mock_pip_audit=mock_audit,
    )

    assert exit_code == 1
    assert len(summary) == 0
    assert any("pip-audit execution failed" in err for err in errors)


def test_cvss_vector_only_high_fails(tmp_path):
    # database_specific has no severity, but severity vector has CVSS:3.1 with 7.5 (High)
    mock_audit = _make_pip_audit_output([
        _make_dep("crypto-lib", "1.0.0", ["CVE-2026-77777"])
    ])

    with patch("check_pip_audit.fetch_osv_record") as mock_fetch:
        mock_fetch.return_value = (
            {
                "database_specific": {},
                "severity": [
                    {
                        "type": "CVSS_V3",
                        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    }
                ],
                "aliases": [],
            },
            True,
        )
        exit_code, summary, errors = audit(
            exemptions_path=str(tmp_path / "exemptions.json"),
            mock_pip_audit=mock_audit,
        )

    assert exit_code == 1
    assert len(summary) == 1
    assert summary[0]["severity"] == "HIGH"
    assert summary[0]["decision"] == "FAIL"


def test_ghsa_alias_only_high_fails(tmp_path):
    # Primary record has no severity and no CVSS vector, but GHSA alias has HIGH
    mock_audit = _make_pip_audit_output([
        _make_dep("web-framework", "3.0.0", ["CVE-2026-88888"])
    ])

    def mock_fetch_osv(vuln_id, session=None, retries=3):
        if vuln_id == "CVE-2026-88888":
            return (
                {
                    "database_specific": {},
                    "severity": [],
                    "aliases": ["GHSA-xxxx-yyyy-zzzz"],
                },
                True,
            )
        elif vuln_id == "GHSA-xxxx-yyyy-zzzz":
            return (
                {
                    "database_specific": {"severity": "HIGH"},
                    "severity": [],
                    "aliases": [],
                },
                True,
            )
        return None, True

    with patch("check_pip_audit.fetch_osv_record", side_effect=mock_fetch_osv):
        exit_code, summary, errors = audit(
            exemptions_path=str(tmp_path / "exemptions.json"),
            mock_pip_audit=mock_audit,
        )

    assert exit_code == 1
    assert len(summary) == 1
    assert summary[0]["severity"] == "HIGH"
    assert summary[0]["decision"] == "FAIL"


def test_invalid_exemption_file_fails(tmp_path):
    # 1. Missing field
    f1 = tmp_path / "missing_field.json"
    f1.write_text("""[{"id": "A", "package": "B"}]""")
    valid, _, err = load_and_validate_exemptions(str(f1))
    assert not valid
    assert "missing required fields" in err

    # 2. Bad date format
    f2 = tmp_path / "bad_date.json"
    f2.write_text(
        """[{"id": "A", "package": "B", "reason": "R", "added": "NOT-A-DATE", "expires": "2026-12-01", "link": "L"}]"""
    )
    valid, _, err = load_and_validate_exemptions(str(f2))
    assert not valid
    assert "must be YYYY-MM-DD" in err

    # 3. Expiry > 180 days after added
    f3 = tmp_path / "too_long.json"
    f3.write_text(
        """[{"id": "A", "package": "B", "reason": "R", "added": "2026-01-01", "expires": "2026-10-01", "link": "L"}]"""
    )
    valid, _, err = load_and_validate_exemptions(str(f3))
    assert not valid
    assert "exceeds maximum allowed 180 days" in err

    # Ensure audit fails on invalid exemption file
    exit_code, summary, errors = audit(exemptions_path=str(f1))
    assert exit_code == 1
    assert any("Exemption file validation error" in e for e in errors)
