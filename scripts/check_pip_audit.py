#!/usr/bin/env python3
"""Fail-closed dependency audit gate using pip-audit, OSV API, and cvss."""

import datetime
import json
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import requests
from cvss import CVSS2, CVSS3, CVSS4
from cvss.exceptions import CVSSError

EXEMPTIONS_PATH = "security/audit-exemptions.json"
REQUIREMENTS_PATH = "requirements.txt"
HIGH_CRITICAL_SEVERITIES = {"HIGH", "CRITICAL"}
BELOW_THRESHOLD_SEVERITIES = {"LOW", "MODERATE", "MEDIUM"}


def load_and_validate_exemptions(
    path: str = EXEMPTIONS_PATH,
) -> Tuple[bool, List[Dict[str, Any]], Optional[str]]:
    """Load and validate exemptions JSON.

    Validates schema, dates, and ensures (expires - added) <= 180 days.
    Returns (is_valid, exemptions_list, error_message).
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return True, [], None
    except json.JSONDecodeError as e:
        return False, [], f"Invalid JSON in {path}: {e}"
    except Exception as e:
        return False, [], f"Error reading {path}: {e}"

    if not isinstance(data, list):
        return False, [], f"Root of {path} must be a list of exemption objects"

    required_fields = {"id", "package", "reason", "added", "expires", "link"}
    parsed_exemptions = []

    for idx, entry in enumerate(data):
        if not isinstance(entry, dict):
            return False, [], f"Entry at index {idx} in {path} is not an object"

        missing = required_fields - set(entry.keys())
        if missing:
            return False, [], (
                f"Entry {idx} ({entry.get('id', 'unknown')}) missing required"
                f" fields: {sorted(missing)}"
            )

        for field in required_fields:
            if not isinstance(entry[field], str) or not entry[field].strip():
                return False, [], (
                    f"Entry {idx} ({entry['id']}) field '{field}' must be a"
                    " non-empty string"
                )

        try:
            added_date = datetime.datetime.strptime(
                entry["added"], "%Y-%m-%d"
            ).date()
        except ValueError:
            return False, [], (
                f"Entry {idx} ({entry['id']}) 'added' date '{entry['added']}'"
                " must be YYYY-MM-DD"
            )

        try:
            expires_date = datetime.datetime.strptime(
                entry["expires"], "%Y-%m-%d"
            ).date()
        except ValueError:
            return False, [], (
                f"Entry {idx} ({entry['id']}) 'expires' date"
                f" '{entry['expires']}' must be YYYY-MM-DD"
            )

        if expires_date <= added_date:
            return False, [], (
                f"Entry {idx} ({entry['id']}) 'expires' ({entry['expires']})"
                f" must be after 'added' ({entry['added']})"
            )

        duration_days = (expires_date - added_date).days
        if duration_days > 180:
            return False, [], (
                f"Entry {idx} ({entry['id']}) expiry duration ({duration_days}"
                " days) exceeds maximum allowed 180 days"
            )

        parsed_entry = dict(entry)
        parsed_entry["_added_date"] = added_date
        parsed_entry["_expires_date"] = expires_date
        parsed_exemptions.append(parsed_entry)

    return True, parsed_exemptions, None


def check_exemption(
    vuln_id: str,
    package_name: str,
    exemptions: List[Dict[str, Any]],
    current_date: Optional[datetime.date] = None,
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """Check if (vuln_id, package_name) is exempted.

    Returns (is_exempt, status, exemption_record).
    status is one of: 'EXEMPT', 'EXPIRED', 'NOT_EXEMPT'
    """
    if current_date is None:
        current_date = datetime.datetime.now(datetime.timezone.utc).date()

    norm_pkg = package_name.strip().lower()

    for ex in exemptions:
        if (
            ex["id"] == vuln_id
            and ex["package"].strip().lower() == norm_pkg
        ):
            expires_date = ex.get("_expires_date")
            if not expires_date:
                expires_date = datetime.datetime.strptime(
                    ex["expires"], "%Y-%m-%d"
                ).date()

            if current_date > expires_date:
                return False, "EXPIRED", ex
            return True, "EXEMPT", ex

    return False, "NOT_EXEMPT", None


def parse_cvss_severity(vector_or_score: str) -> str:
    """Parse CVSS v2, v3, or v4 vector or numeric score to severity string.

    Returns 'LOW', 'MODERATE', 'HIGH', 'CRITICAL', or 'UNKNOWN'.
    """
    if not isinstance(vector_or_score, str) or not vector_or_score.strip():
        return "UNKNOWN"

    s = vector_or_score.strip()

    if s.startswith("CVSS:4"):
        try:
            c4 = CVSS4(s)
            sevs = c4.severities()
            if sevs:
                return sevs[0].upper()
        except (CVSSError, Exception):
            return "UNKNOWN"

    if s.startswith("CVSS:3"):
        try:
            c3 = CVSS3(s)
            sevs = c3.severities()
            if sevs:
                sev = sevs[0].upper()
                return "MODERATE" if sev == "MEDIUM" else sev
        except (CVSSError, Exception):
            return "UNKNOWN"

    if s.startswith("CVSS:2") or s.startswith("AV:"):
        try:
            c2 = CVSS2(s)
            sevs = c2.severities()
            if sevs:
                sev = sevs[0].upper()
                return "MODERATE" if sev == "MEDIUM" else sev
        except (CVSSError, Exception):
            return "UNKNOWN"

    # Numeric score fallback
    try:
        val = float(s)
        if val >= 9.0:
            return "CRITICAL"
        elif val >= 7.0:
            return "HIGH"
        elif val >= 4.0:
            return "MODERATE"
        elif val > 0.0:
            return "LOW"
    except ValueError:
        pass

    return "UNKNOWN"


def fetch_osv_record(
    vuln_id: str,
    session: Optional[requests.Session] = None,
    retries: int = 3,
    backoff_factor: float = 0.5,
) -> Tuple[Optional[Dict[str, Any]], bool]:
    """Fetch vulnerability JSON from OSV API with retries on 429, 5xx, and network errors.

    Returns (record_dict_or_none, is_reachable).
    """
    url = f"https://api.osv.dev/v1/vulns/{vuln_id}"
    req_func = session.get if session else requests.get

    for attempt in range(retries):
        try:
            r = req_func(url, timeout=10)
            if r.status_code == 200:
                return r.json(), True
            if r.status_code == 404:
                return None, True
            if r.status_code == 429 or r.status_code >= 500:
                if attempt < retries - 1:
                    time.sleep(backoff_factor * (2**attempt))
                    continue
                return None, False
            return None, True
        except (requests.RequestException, Exception):
            if attempt < retries - 1:
                time.sleep(backoff_factor * (2**attempt))
                continue
            return None, False

    return None, False


def get_osv_severity(
    vuln_id: str,
    session: Optional[requests.Session] = None,
    retries: int = 3,
) -> Tuple[str, bool]:
    """Resolve severity from OSV record, CVSS vectors, and aliases.

    Returns (severity, is_reachable).
    Severity is one of: 'CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'UNKNOWN'.
    """
    data, reachable = fetch_osv_record(vuln_id, session=session, retries=retries)
    if not reachable:
        return "UNKNOWN", False
    if not data:
        return "UNKNOWN", True

    # 1. database_specific.severity
    db_sev = data.get("database_specific", {}).get("severity")
    if db_sev and isinstance(db_sev, str):
        up = db_sev.strip().upper()
        if up in ("HIGH", "CRITICAL", "LOW"):
            return up, True
        if up in ("MODERATE", "MEDIUM"):
            return "MODERATE", True

    # 2. CVSS vectors in severity
    for item in data.get("severity", []):
        score_val = item.get("score")
        if score_val:
            sev = parse_cvss_severity(score_val)
            if sev != "UNKNOWN":
                return sev, True

    # 3. Aliases (e.g. GHSA-*)
    for alias in data.get("aliases", []):
        if not isinstance(alias, str):
            continue
        alias_data, alias_reachable = fetch_osv_record(
            alias, session=session, retries=retries
        )
        if not alias_reachable:
            return "UNKNOWN", False
        if not alias_data:
            continue

        alias_db_sev = alias_data.get("database_specific", {}).get("severity")
        if alias_db_sev and isinstance(alias_db_sev, str):
            up = alias_db_sev.strip().upper()
            if up in ("HIGH", "CRITICAL", "LOW"):
                return up, True
            if up in ("MODERATE", "MEDIUM"):
                return "MODERATE", True

        for item in alias_data.get("severity", []):
            score_val = item.get("score")
            if score_val:
                sev = parse_cvss_severity(score_val)
                if sev != "UNKNOWN":
                    return sev, True

    return "UNKNOWN", True


def run_pip_audit(
    requirements_path: str = REQUIREMENTS_PATH,
) -> Tuple[int, Optional[Dict[str, Any]], str]:
    """Execute pip-audit and return (exit_code, parsed_json_or_none, stderr)."""
    cmd = ["pip-audit", "-r", requirements_path, "--format", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        return -1, None, "pip-audit executable not found on PATH"

    raw_stdout = result.stdout.strip()
    if not raw_stdout:
        return result.returncode, None, result.stderr

    try:
        data = json.loads(raw_stdout)
        if not isinstance(data, dict) or "dependencies" not in data:
            return result.returncode, None, f"JSON missing 'dependencies': {raw_stdout}"
        return result.returncode, data, result.stderr
    except json.JSONDecodeError as e:
        return result.returncode, None, f"Failed to parse pip-audit JSON: {e}\n{raw_stdout}"


def audit(
    requirements_path: str = REQUIREMENTS_PATH,
    exemptions_path: str = EXEMPTIONS_PATH,
    current_date: Optional[datetime.date] = None,
    session: Optional[requests.Session] = None,
    mock_pip_audit: Optional[Tuple[int, Optional[Dict[str, Any]], str]] = None,
) -> Tuple[int, List[Dict[str, Any]], List[str]]:
    """Run the complete audit gate.

    Returns (exit_code, summary_items, error_messages).
    """
    errors: List[str] = []
    summary_items: List[Dict[str, Any]] = []

    # 1. Load and validate exemptions file
    is_valid, exemptions, val_error = load_and_validate_exemptions(exemptions_path)
    if not is_valid:
        errors.append(f"[FAIL] Exemption file validation error: {val_error}")
        return 1, [], errors

    # 2. Run or mock pip-audit
    if mock_pip_audit is not None:
        rc, audit_data, audit_stderr = mock_pip_audit
    else:
        print(f"Running pip-audit on {requirements_path}...")
        rc, audit_data, audit_stderr = run_pip_audit(requirements_path)

    # Fail if pip-audit exited with an error that is not "vulnerabilities found" (rc 1 with valid JSON)
    if audit_data is None:
        errors.append(
            f"[FAIL] pip-audit execution failed (exit code {rc}):\n{audit_stderr}"
        )
        return 1, [], errors

    dependencies = audit_data.get("dependencies", [])
    overall_failure = False

    for dep in dependencies:
        pkg_name = dep.get("name", "unknown")
        pkg_version = dep.get("version", "unknown")
        vulns = dep.get("vulns", [])

        for vuln in vulns:
            vid = vuln.get("id", "unknown")

            # Check exemption
            is_exempt, ex_status, ex_record = check_exemption(
                vid, pkg_name, exemptions, current_date=current_date
            )

            # Resolve severity
            severity, reachable = get_osv_severity(vid, session=session)

            if not reachable:
                severity = "UNKNOWN (OSV UNREACHABLE)"

            # Determine decision
            if ex_status == "EXPIRED":
                overall_failure = True
                decision = f"FAIL (EXPIRED: {ex_record.get('expires', 'unknown')})"
                errors.append(
                    f"[FAIL] Exemption for {vid} ({pkg_name}) expired on"
                    f" {ex_record.get('expires')}"
                )
            elif is_exempt:
                decision = "EXEMPT"
            elif severity in ("LOW", "MODERATE", "MEDIUM"):
                decision = "BELOW THRESHOLD"
            else:
                # HIGH, CRITICAL, UNKNOWN, or OSV unreachable without valid exemption -> FAIL
                overall_failure = True
                decision = "FAIL"
                errors.append(
                    f"[FAIL] {vid} in {pkg_name} ({pkg_version}) with severity"
                    f" {severity} is not exempted"
                )

            summary_items.append({
                "id": vid,
                "package": pkg_name,
                "version": pkg_version,
                "severity": severity,
                "decision": decision,
            })

    return (1 if overall_failure else 0), summary_items, errors


def print_summary_table(summary_items: List[Dict[str, Any]]) -> None:
    """Print aligned summary table of audit results."""
    if not summary_items:
        print("\nNo vulnerabilities reported by pip-audit.")
        return

    col_id = max(len(item["id"]) for item in summary_items)
    col_id = max(col_id, len("ID"))

    col_pkg = max(len(item["package"]) for item in summary_items)
    col_pkg = max(col_pkg, len("Package"))

    col_ver = max(len(item["version"]) for item in summary_items)
    col_ver = max(col_ver, len("Version"))

    col_sev = max(len(item["severity"]) for item in summary_items)
    col_sev = max(col_sev, len("Severity"))

    col_dec = max(len(item["decision"]) for item in summary_items)
    col_dec = max(col_dec, len("Decision"))

    sep_line = (
        f"+-{'-' * col_id}-+-{'-' * col_pkg}-+-{'-' * col_ver}-+-{'-' * col_sev}-+-{'-' * col_dec}-+"
    )
    header_line = (
        f"| {'ID':<{col_id}} | {'Package':<{col_pkg}} | {'Version':<{col_ver}} |"
        f" {'Severity':<{col_sev}} | {'Decision':<{col_dec}} |"
    )

    print("\nDependency Vulnerability Audit Summary Table:")
    print(sep_line)
    print(header_line)
    print(sep_line)

    for item in summary_items:
        print(
            f"| {item['id']:<{col_id}} | {item['package']:<{col_pkg}} |"
            f" {item['version']:<{col_ver}} | {item['severity']:<{col_sev}} |"
            f" {item['decision']:<{col_dec}} |"
        )

    print(sep_line)


def main() -> None:
    exit_code, summary_items, errors = audit()
    print_summary_table(summary_items)

    if errors:
        print("\n[!] Audit Gate Failures:")
        for err in errors:
            print(f"  {err}")

    if exit_code != 0:
        print("\n[!] Audit gate FAILED (fail-closed policy enforced).")
        sys.exit(1)
    else:
        print("\n[OK] Audit gate PASSED.")
        sys.exit(0)


if __name__ == "__main__":
    main()
