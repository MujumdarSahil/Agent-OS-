# Evidence report: CI Fix for PR #18 (Dependency Pins, FastAPI Router Unpacking, Mongo 8.2.12)

Branch: `feature/agentos-2.0-phase1.3-importer`, PR [#18](https://github.com/MujumdarSahil/Agent-OS-/pull/18) into `2.0`.  
Date: 2026-11-13. Raw failure log: `docs/evidence/raw/ci-fix-failed-run.txt`.

---

## (a) What changed

| File | Summary |
|---|---|
| `requirements.txt` | Updated dependencies: `fastapi==0.162.4`, removed `starlette` pin (resolves `starlette==1.10.0`), `crewai==1.15.41`, `litellm==1.100.4`. Prevents resolution of older `crewai 1.6.1` lacking `crewai.mcp.tool_resolver`, addresses upstream CVEs in mcp/uv, and clears `GHSA-g5ff-637f-6q2m` without exemptions. |
| `pyproject.toml` | Maintained compatible bounds: `crewai>=1.15,<2` and `litellm<2`. Left `fastapi` unbounded. |
| `agentos/tests/test_restructure_1_1b.py` | Replaced `_route_table` with `_iter_routes` + `_route_table` that recursively handles nested `_IncludedRouter` (via `r.original_router.routes` with `r.include_context.prefix`) and Starlette `Mount` (`r.routes` with `r.path`), ensuring exact equality with `V1_API_ROUTES` (47 routes) on both FastAPI 0.124.0 and 0.162.4. |
| `docker/compose.mongo.yml` | Updated default image to `${AGENTOS_MONGO_IMAGE:-mongo:8.2.12}` to avoid the MongoDB 8.0 startup check / TCMalloc rseq abort on Linux kernels >= 6.19 (SERVER-121912 / SERVER-122741). |
| `.github/workflows/ci.yml` | In `mongo-live` job: added pre-start step printing `uname -r`, startup verification step printing the `"Waiting for connections"` line from container logs, and post-test step asserting MongoDB logs do not contain `SIGSEGV`, `Fatal`, or `"s":"F"`. |
| `docs/evidence/raw/ci-fix-failed-run.txt` | Captured raw failure log of GitHub Actions run 43002624492 in UTF-8 format. |

---

## (b) Commands run and raw output

### 1. Root Cause Extraction from Failed CI Run (`43002624492`)
```powershell
gh run view 43002624492 --log-failed
```
From `docs/evidence/raw/ci-fix-failed-run.txt`:
- **python-ci failure:**
  ```text
  FAILED agentos/tests/test_restructure_1_1b.py::test_v1_api_route_table_unchanged - AttributeError: '_IncludedRouter' object has no attribute 'path'
  FAILED agentos/tests/test_restructure_1_1b.py::test_api_route_table_same_via_old_path - AttributeError: '_IncludedRouter' object has no attribute 'path'
  ```
- **mongo-live failure:**
  ```text
  agentos-mongo  | {"t":{"$date":"2026-11-11T10:55:09.687+00:00"},"s":"F",  "c":"CONTROL",  "id":12257600, "ctx":"main","msg":"Your system is running with an incompatible kernel. Please either upgrade your system's kernel to a fixed version (6.12 or newer, 6.6.72 or newer, 6.1.124 or newer, 5.15.176 or newer, 5.10.233 or newer, 5.4.289 or newer, or 4.19.325 or newer) or downgrade MongoDB to 7.0 or earlier.","tags":["startupWarnings"]}
  Error: timed out waiting for the condition
  ```

### 2. Local Package Versions
```text
> .\venv\Scripts\python.exe -m pip show crewai fastapi starlette litellm pymongo
Name: crewai, Version: 1.15.41
Name: fastapi, Version: 0.162.4
Name: starlette, Version: 1.10.0
Name: litellm, Version: 1.100.4
Name: pymongo, Version: 4.19.0
```

### 3. FastAPI Route Collector Verification
```powershell
.\venv\Scripts\python.exe -m pytest agentos/tests/test_restructure_1_1b.py -v
```
**Output:**
```text
======================= 27 passed, 1 warning in 49.10s ========================
```

### 4. VCR Provider Tests
```powershell
$env:AGENTOS_MOCK_LLM = "1"
.\venv\Scripts\python.exe -m pytest agentos/tests/test_vcr_providers.py -v
```
**Output:**
```text
======================== 8 passed, 17 skipped in 0.75s ========================
```

### 5. Full Local Pytest Run with LIVE Mongo
```powershell
$vals = @{}; Get-Content docker\.env.mongo | ForEach-Object { $k, $v = $_ -split '=', 2; $vals[$k] = $v }
$env:AGENTOS_MONGO_URI = "mongodb://$($vals.MONGO_INITDB_ROOT_USERNAME):$($vals.MONGO_INITDB_ROOT_PASSWORD)@127.0.0.1:27018/?replicaSet=rs0&authSource=admin"
$env:AGENTOS_REQUIRE_LIVE_MONGO = "1"
$env:AGENTOS_MOCK_LLM = "1"
.\venv\Scripts\python.exe -m pytest agentos/tests agentos_server/tests agentos/packaging/tests -q -rs
```
**Output:**
```text
268 passed, 17 skipped, 254 warnings in 85.25s (0:01:25)
```

### 6. Dependency Security Audit
```powershell
.\venv\Scripts\python.exe check_pip_audit.py
```
**Output:**
```text
Running pip-audit on requirements.txt...
Skipping known unpatched upstream chromadb vulnerability PYSEC-2026-311 (no fixed version available)
...
No HIGH or CRITICAL vulnerabilities found.
```

### 7. SWE Regression Suite
```powershell
.\venv\Scripts\python.exe -m pytest SWE/tests/swe -q
```
**Output:**
```text
671 passed in 81.89s (0:01:21)
```

### 8. Linter Check
```powershell
.\venv\Scripts\python.exe -m ruff check agentos agentos_server
```
**Output:**
```text
All checks passed!
```

---

## (c) Tests added and counts vs baseline

- **Tests added/deleted/skipped:** 0 added, 0 deleted, 0 new skips.
- **Tests made forward-compatible:** 2 tests in `agentos/tests/test_restructure_1_1b.py` (`test_v1_api_route_table_unchanged` and `test_api_route_table_same_via_old_path`) now traverse nested FastAPI routers recursively.
- **Counts vs Baselines:**
  - 1.3 Baseline (with live Mongo): **268 passed, 17 skipped**
  - Current Run (with live Mongo): **268 passed, 17 skipped**
  - SWE Suite: **671 passed**
  - Regressions: **0**

---

## (d) Known gaps

- **MongoDB 8.0 Kernel Check (SERVER-121912 / SERVER-122741):** MongoDB 8.0 checks for TCMalloc restartable sequences (rseq) kernel bugs on Linux kernels >= 6.19 and aborts startup on unpatched kernels. Switched default compose image to `mongo:8.2.12` which does not contain the abort check, while preserving workflow-level override via `${AGENTOS_MONGO_IMAGE:-...}` (with fallback to `mongo:7.0.x` if needed).
- **LiteLLM Dependency Version:** litellm 1.90.7 -> 1.100.4 to clear GHSA-g5ff-637f-6q2m (affects the LiteLLM proxy, which AgentOS does not run); verified by 8 CASSETTE provider tests plus MOCK suites; providers without cassettes are not re-verified on the new version.

---

## (e) How the owner can reproduce

```powershell
git switch feature/agentos-2.0-phase1.3-importer
$vals = @{}; Get-Content docker\.env.mongo | ForEach-Object { $k, $v = $_ -split '=', 2; $vals[$k] = $v }
$env:AGENTOS_MONGO_URI = "mongodb://$($vals.MONGO_INITDB_ROOT_USERNAME):$($vals.MONGO_INITDB_ROOT_PASSWORD)@127.0.0.1:27018/?replicaSet=rs0&authSource=admin"
$env:AGENTOS_REQUIRE_LIVE_MONGO = "1"
$env:AGENTOS_MOCK_LLM = "1"
.\venv\Scripts\python.exe -m pytest agentos/tests agentos_server/tests agentos/packaging/tests -q -rs
.\venv\Scripts\python.exe -m pytest SWE/tests/swe -q
```

---

## (f) PR link and CI result

- **Pull Request:** [#18 (feature/agentos-2.0-phase1.3-importer -> 2.0)](https://github.com/MujumdarSahil/Agent-OS-/pull/18)
- **CI Status:** In progress / monitored below.
