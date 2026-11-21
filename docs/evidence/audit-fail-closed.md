# Evidence report: Fail-Closed Dependency Audit Gate (`check_pip_audit.py`)

Branch: `fix/2.0-audit-fail-closed`, PR into `2.0`.  
Date: 2026-11-13.

---

## (a) What changed

| File | Summary |
|---|---|
| `security/audit-exemptions.json` | Created structured exemptions registry containing the 4 upstream unpatched `chromadb` vulnerabilities with strict schema (`id`, `package`, `reason`, `added`, `expires`, `link`), expiry set to `2027-02-11` (90 days out, <= 180 day policy limit). |
| `check_pip_audit.py` | Refactored to enforce a fail-closed policy: validates exemption file schema/dates/durations; queries OSV with retries (on 429, 5xx, network errors); uses PyPI `cvss` package (`CVSS2`, `CVSS3`, `CVSS4`) to calculate base severity from vectors; inspects `database_specific.severity` and alias chains (e.g. `GHSA-*`); fails gate on unknown severities or unreachable OSV; fails on `pip-audit` execution errors; prints structured summary table with real resolved dependency versions. Supports injectable UTC date (`current_date`). |
| `tests/ci/test_check_pip_audit.py` | Added comprehensive offline unit test suite (12 tests) verifying HIGH fails, LOW passes, UNKNOWN fails, OSV down fails, valid exemption passes, expired exemption fails, mismatched package fails, pip-audit errors fail, CVSS vector-only high fails, GHSA alias-only high fails, and invalid exemption file schema/dates fail. |
| `requirements.txt` | Added `cvss==3.6` under Testing dependencies. |
| `.github/workflows/ci.yml` | Updated `python-ci` job: pinned `cvss==3.6` in installation step, added `tests/ci` to the pytest test command. |

---

## (b) Commands run and raw output

### 1. Offline Tooling Test Suite
```powershell
.\venv\Scripts\python.exe -m pytest tests/ci/test_check_pip_audit.py -v
```
**Output:**
```text
============================= test session starts =============================
platform win32 -- Python 3.11.9, pytest-9.0.1, pluggy-1.6.0
collected 12 items

tests/ci/test_check_pip_audit.py::test_cvss_vector_parsing PASSED        [  8%]
tests/ci/test_check_pip_audit.py::test_high_fails PASSED                 [ 16%]
tests/ci/test_check_pip_audit.py::test_low_passes PASSED                 [ 25%]
tests/ci/test_check_pip_audit.py::test_unknown_fails PASSED              [ 33%]
tests/ci/test_check_pip_audit.py::test_osv_down_fails PASSED             [ 41%]
tests/ci/test_check_pip_audit.py::test_exempted_passes PASSED            [ 50%]
tests/ci/test_check_pip_audit.py::test_expired_exemption_fails PASSED    [ 58%]
tests/ci/test_check_pip_audit.py::test_same_id_different_package_fails PASSED [ 66%]
tests/ci/test_check_pip_audit.py::test_pip_audit_error_fails PASSED      [ 75%]
tests/ci/test_check_pip_audit.py::test_cvss_vector_only_high_fails PASSED [ 83%]
tests/ci/test_check_pip_audit.py::test_ghsa_alias_only_high_fails PASSED [ 91%]
tests/ci/test_check_pip_audit.py::test_invalid_exemption_file_fails PASSED [100%]

============================= 12 passed in 0.29s ==============================
```

### 2. Live Audit Gate Run Against requirements.txt
```powershell
.\venv\Scripts\python.exe check_pip_audit.py
```
**Output:**
```text
Running pip-audit on requirements.txt...

Dependency Vulnerability Audit Summary Table:
+-----------------+----------+---------+----------+----------+
| ID              | Package  | Version | Severity | Decision |
+-----------------+----------+---------+----------+----------+
| PYSEC-2026-311  | chromadb | 1.5.9   | CRITICAL | EXEMPT   |
| PYSEC-2026-311  | chromadb | 1.5.9   | CRITICAL | EXEMPT   |
| PYSEC-2026-3814 | chromadb | 1.5.9   | CRITICAL | EXEMPT   |
| PYSEC-2026-3815 | chromadb | 1.5.9   | HIGH     | EXEMPT   |
| PYSEC-2026-3813 | chromadb | 1.5.9   | HIGH     | EXEMPT   |
+-----------------+----------+---------+----------+----------+

[OK] Audit gate PASSED.
```

### 3. Full Local Pytest Run with LIVE Mongo
```powershell
$vals = @{}; Get-Content docker\.env.mongo | ForEach-Object { $k, $v = $_ -split '=', 2; $vals[$k] = $v }
$env:AGENTOS_MONGO_URI = "mongodb://$($vals.MONGO_INITDB_ROOT_USERNAME):$($vals.MONGO_INITDB_ROOT_PASSWORD)@127.0.0.1:27018/?replicaSet=rs0&authSource=admin"
$env:AGENTOS_REQUIRE_LIVE_MONGO = "1"
$env:AGENTOS_MOCK_LLM = "1"
.\venv\Scripts\python.exe -m pytest agentos/tests agentos_server/tests agentos/packaging/tests tests/ci -q -rs
```
**Output:**
```text
280 passed, 17 skipped, 254 warnings in 87.22s (0:01:27)
```

### 4. SWE Regression Suite
```powershell
.\venv\Scripts\python.exe -m pytest SWE/tests/swe -q
```
**Output:**
```text
671 passed in 95.75s (0:01:35)
```

### 5. Linter Check
```powershell
.\venv\Scripts\python.exe -m ruff check agentos agentos_server check_pip_audit.py tests/ci
```
**Output:**
```text
All checks passed!
```

---

## (c) Tests added and counts vs baseline

- **Tests added:** 12 offline unit tests in `tests/ci/test_check_pip_audit.py` (MOCK).
- **Counts vs Baselines:**
  - 1.3 Baseline (with live Mongo): **268 passed, 17 skipped**
  - Current Run (with live Mongo + `tests/ci`): **280 passed, 17 skipped** (+12 tests)
  - SWE Suite: **671 passed**
  - Regressions: **0**

---

## (d) Known gaps

- None. All unpatched chromadb vulnerabilities are tracked in `security/audit-exemptions.json` with active expiry (`2027-02-11`).

---

## (e) How the owner can reproduce

```powershell
git switch fix/2.0-audit-fail-closed
.\venv\Scripts\python.exe -m pytest tests/ci/test_check_pip_audit.py -v
.\venv\Scripts\python.exe check_pip_audit.py
```

---

## (f) PR link and CI result

- **Pull Request:** [#20 (fix/2.0-audit-fail-closed -> 2.0)](https://github.com/MujumdarSahil/Agent-OS-/pull/20)
- **CI Status:** Green (GitHub Actions Run [43386803398](https://github.com/MujumdarSahil/Agent-OS-/actions/runs/43386803398)):
  - `frontend-ci`: pass (49s)
  - `mongo-live`: pass (2m 23s)
  - `wheel-install`: pass (2m 27s)
  - `python-ci`: pass (3m 36s)
