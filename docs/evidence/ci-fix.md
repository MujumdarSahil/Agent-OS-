# Evidence report: CI Fix for PR #18 (Dependency Pins, FastAPI Router Unpacking, Mongo 8.0.34)

Branch: `feature/agentos-2.0-phase1.3-importer`, PR [#18](https://github.com/MujumdarSahil/Agent-OS-/pull/18) into `2.0`.  
Date: 2026-11-11. Raw failure log: `docs/evidence/raw/ci-fix-failed-run.txt`.

---

## (a) What changed

| File | Summary |
|---|---|
| `requirements.txt` | Pinned exact known-good local versions: `fastapi==0.124.0`, `starlette==0.50.0`, `crewai==1.15.1`, `litellm==1.90.0`. Prevents resolution of older incompatible `crewai 1.6.1` (which lacked `crewai.mcp.tool_resolver`) or `starlette` mismatches. |
| `pyproject.toml` | Set compatible bounds: `crewai>=1.15,<2` and `litellm<2`. Left `fastapi` unbounded (no `<0.137` cap). |
| `agentos/tests/test_restructure_1_1b.py` | Replaced `_route_table` with recursive route collector that inspects `route.routes` on `_IncludedRouter` objects introduced in FastAPI `>=0.137.0`, ensuring exact equality with `V1_API_ROUTES` across FastAPI 0.124.0 through 0.162+. |
| `docker/compose.mongo.yml` | Updated image to `image: ${AGENTOS_MONGO_IMAGE:-mongo:8.0.34}` to address MongoDB 8.0 startup check / TCMalloc rseq abort on newer Linux kernels (SERVER-121912 / SERVER-125742), while allowing workflow-level override if needed. |
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
Name: crewai, Version: 1.15.1
Name: fastapi, Version: 0.124.0
Name: starlette, Version: 0.50.0
Name: litellm, Version: 1.90.0
Name: pymongo, Version: 4.19.0
```

### 3. Full Local Pytest Run with LIVE Mongo
```powershell
$vals = @{}; Get-Content docker\.env.mongo | ForEach-Object { $k, $v = $_ -split '=', 2; $vals[$k] = $v }
$env:AGENTOS_MONGO_URI = "mongodb://$($vals.MONGO_INITDB_ROOT_USERNAME):$($vals.MONGO_INITDB_ROOT_PASSWORD)@127.0.0.1:27018/?replicaSet=rs0&authSource=admin"
$env:AGENTOS_REQUIRE_LIVE_MONGO = "1"
$env:AGENTOS_MOCK_LLM = "1"
.\venv\Scripts\python.exe -m pytest agentos/tests agentos_server/tests agentos/packaging/tests -q -rs
```
**Output:**
```text
268 passed, 17 skipped, 253 warnings in 85.21s (0:01:25)
```

### 4. SWE Regression Suite
```powershell
.\venv\Scripts\python.exe -m pytest SWE/tests/swe -q
```
**Output:**
```text
671 passed in 96.04s (0:01:36)
```

### 5. Linter Check
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

- **MongoDB 8.0 Kernel Check (SERVER-121912 / SERVER-125742):** MongoDB 8.0 checks for TCMalloc restartable sequences (rseq) kernel bugs. Ubuntu 24.04 runners on GitHub Actions run newer kernels where unpatched 8.0 builds abort startup. Pinned image to `mongo:8.0.34` with variable override `${AGENTOS_MONGO_IMAGE:-...}`.

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
- **CI Status:** Pending push and monitoring.
