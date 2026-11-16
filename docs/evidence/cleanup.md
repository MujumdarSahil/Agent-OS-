# Evidence report: 2.0 cleanup (`chore/2.0-cleanup`)

Branch off `origin/2.0` (b5d97f4). No new features. All test results are **MOCK** unless noted;
packaging checks are local builds. One small commit per item.

## (a) What changed (one commit each)
| Commit | Item |
|---|---|
| `chore(cleanup): move CI check scripts…` | `check_pip_audit.py`, `check_wheel_install.py`, `check_coverage.py` → `scripts/`; `ci.yml`, THREAT_MODEL and `tests/ci` import updated; wheel check resolves the repo root from `scripts/`. |
| `delete unused check_system.py and simple_check.py` | No CI/test/code references. |
| `delete unused my_custom_agents/` | Unreferenced, not packaged; `examples/external_plugin_demo` covers plugins. |
| `untrack generated coverage.json` | Already in `.gitignore`. |
| `ci(cleanup): delete obsolete test.yml` | Ran only on main/develop; duplicated by `ci.yml`. |
| `chore(swe): delete dead remediation/planner.py` | Shadowed by the `remediation/planner/` package (unreachable). |
| `chore(swe): DeprecationWarning on the 17 legacy facade packages` | Facades kept (documented contract); each warns with the replacement path and "removed when SWE ships as a separate pack". |
| `delete unused agent_strategies/ and resource_monitor.py` | Not v1 API, no importers; README claims removed (rule 4). |
| `fix(modelhub): training and performance classes raise NotImplementedError` | 13 classes; constructor and all methods raise (e.g. `LoRAUtils.apply_lora_adapters` used to return `success: True`). Import paths kept. |
| `fix(modelhub): VerifierModel.classify_hallucination raises` | Fixed-score stub. Callers (GovernanceEngine, ScriptAuthorAgent) use only `classify_policy_violation` (unchanged). |
| `fix(planner): warn that LLM decomposition is not implemented` | v1 `Planner` signature/output unchanged; `llm_func` mode logs a warning. |
| `docs(cleanup): label constitutional_ai and composite_agent experimental` | Docstring labels. |
| `fix(triggers): fail loudly when croniter is missing` | Startup raises `CroniterMissingError` if schedules exist; `tick()` raises; schedules API returns 503 instead of storing an unvalidated cron. |
| `fix(security): trusted internal domains come from admin config, default empty` | See (d) 1. |
| `ci(packaging): wheel check also verifies agentos_swe import and version` | |
| `build: pyproject.toml is the single packaging and version source; delete setup.py` | See (b). |
| `docs: replace ARCHITECTURE.md with a one-page 2.0 architecture` | Supersedes the 517-line pre-2.0 doc (in git history). |
| `fix(2.4): drain final run events before sending run_finished` | Bug found by the final full run (see (d) 3). |

Not done (not allowed / not approved): no `features/`/`core/` reshuffle, no `__init__.py` removed, no style refactors; `demo/` and `main.py` kept.

## (b) Commands and raw output (logs in `docs/evidence/raw/cleanup-*`)
| Command | Result | Raw log |
|---|---|---|
| `pytest agentos/tests agentos_server/tests agentos/packaging/tests tests/ci -q` (first final run) | `1 failed, 417 passed, 44 skipped` (WS replay race, fixed) | overwritten; failure quoted in (d) 3 |
| same, after the fix | **`418 passed, 44 skipped`** | `cleanup-pytest-core.txt` |
| `pytest agentos_server/tests/test_v2_inprocess_worker.py` × 5 after the fix | `6 passed` × 5 | chat output |
| `pytest SWE/tests/swe -q` | **`688 passed`** | `cleanup-pytest-swe.txt` |
| `ruff check agentos agentos_server` | `All checks passed!` | `cleanup-ruff-wheel.txt` |
| `python scripts/check_wheel_install.py` (no `setup.py`) | exit 0: `agentos`, `agentos_server`, `agentos_swe` import from the clean venv; installed `0.2.0 == agentos.__version__`; `/api/health` 200; packaged UI present | `cleanup-ruff-wheel.txt`, `cleanup-check-wheel-install-no-setup-py.txt` |
| editable install without `setup.py` (`pip install --no-deps -e .` in a scratch venv) | exit 0; `agentos` and `agentos_swe` map to the source tree; version 0.2.0; `agentos` console script present | chat output |
| `examples/usecases/04-webhook-trigger/run.py` | exit 0, "completed all scenarios cleanly" | chat output |
| `cd ui; npm run lint; npm run build` | lint clean, build OK | `cleanup-ui-lint-build.txt` |

## (c) Tests and counts vs baseline
Baseline = `origin/2.0` after 2.4 (core **388 passed / 44 skipped**, SWE **671 passed**).

| Suite | Baseline | Now | Delta (all intentional, all MOCK) |
|---|---|---|---|
| Core | 388 / 44 skipped | **418 / 44 skipped** | +30 new: `test_modelhub_unavailable.py` (15), `test_governance_verifier_unavailable.py` (4), `test_planner_llm_mode.py` (2), `test_croniter_required.py` (4), `test_internal_domains_config.py` (5). Skips unchanged. |
| SWE | 671 | **688** | +17: `test_legacy_facades.py` (one per facade). |

Existing tests changed (setup only): `test_flow_api_and_approval_2_1.py`, `test_v2_node_specs.py`, `test_v2_inprocess_worker.py` now configure `corp.local` explicitly; `tests/ci/test_check_pip_audit.py` imports from `scripts/`. The v1 characterization tests pass unchanged.

## (d) Known gaps, intentional changes, notes
1. **Intentional secure-default change:** `agentos_server/app.py` no longer hard-codes `internal.local`/`corp.local`. Trusted domains come from `AGENTOS_INTERNAL_DOMAINS` (comma-separated; wins, empty string = none) or `security.internal_domains` in `agentos.config.yaml`; **default is none trusted**. On a default install, untrusted bodies sent to `corp.local` are now refused. Use case 04, the use case 05 walkthrough and the Playwright builder config set it explicitly; use case 01 already passed an explicit policy.
2. Verifier: only the stubbed `classify_hallucination` raises. `classify_policy_violation`/`classify_toxicity` (keyword based) are unchanged, so GovernanceEngine decisions are unchanged (pinned by tests, including the unavailable-verifier path: warning logged, same decision as no verifier).
3. **Bug fixed during final checks:** the 2.4 run-event WebSocket could send `run_finished` before the last event (`assert [4, …, 10] == [4, …, 9]`: the first stream missed seq 10). The route now drains events before `run_finished`.
4. SWE facades are kept (documented compatibility contract); removal is deferred to the SWE pack split.
5. Playwright builder e2e was not re-run locally; the `ui-e2e` CI job runs it with the new `AGENTOS_INTERNAL_DOMAINS` env.
6. `ARCHITECTURE.md` notes that Platform has no packaged worker command yet and that `MongoLeaderLock` exists but is not wired by `app.py`.

## (e) Reproduce
```powershell
$env:AGENTOS_MOCK_LLM="1"
.\venv\Scripts\python.exe -m pytest agentos/tests agentos_server/tests agentos/packaging/tests tests/ci -q
.\venv\Scripts\python.exe -m pytest SWE/tests/swe -q
.\venv\Scripts\python.exe scripts/check_wheel_install.py
```

## (f) PR and CI
Pushed to `chore/2.0-cleanup`; the owner opens the PR (base `2.0`).
