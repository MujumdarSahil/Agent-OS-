# AgentOS-SWE Architecture & Release Documentation

## Overview

**AgentOS-SWE** is an enterprise-grade autonomous software verification and repair system built on top of the **AgentOS** multi-agent framework foundation. It acts as an extension layer over AgentOS's multi-provider LLM router, fallback mechanism, memory/UMB, checkpointing, squad coordination, governance engines, telemetry collectors, and scientific benchmark evaluation frameworks.

End-to-End Release Architecture:
```
GitHub Repository → Repository Intake → Code Graph (Graphify) → RepositoryContext → AgentOS Squad → Investigation Squad → Finding Aggregator → Independent Verification → Controlled Autonomous Repair → Risk Governance → GitHub PR Automation → Observability Telemetry → Scientific Benchmark Suite
```

---

## Complete Phase Summary (M0 — M9)

| Phase | Module | Status | Description |
| :--- | :--- | :--- | :--- |
| **M0** | Architecture | **COMPLETE** | Core domain models (`Finding`, `Evidence`, `CodeNode`), exception taxonomy, and system contracts. |
| **M1** | Repository Intelligence | **COMPLETE** | Intake analyzer (`RepositoryIntake`), code graph provider (`GraphifyAdapter`), and context builder (`build_repository_context`). |
| **M2** | Investigation Squad | **COMPLETE** | Read-only investigation squad (`BugAgent`, `SecurityAgent`, `PerformanceAgent`, `ArchitectureAgent`) & `FindingAggregator`. |
| **M3** | Verification | **COMPLETE** | Multi-strategy verification pipeline (`VerificationAgent`, `IsolatedSandbox`, static/graph/test reproduction strategies). |
| **M4** | Controlled Repair | **COMPLETE** | Autonomous patch generation inside `IsolatedSandbox` (`ImpactAnalyzer`, `FixPlanner`, `FixAgent`, `IndependentPatchReviewer`, `RepairPipeline`). Target repository remains 100% UNCHANGED. |
| **M5** | PR Automation | **COMPLETE** | Risk scoring (`RiskAnalyzer`), AgentOS governance policy integration (`GovernanceGate`), `GitHubAdapter` (secret redaction & dry-run mode), and `PRPipeline`. |
| **M6** | Security Hardening | **COMPLETE** | Configurable `ResourceLimits`, explicit `CommandPolicy` (allow/deny lists), `SecretProtection`, default network egress denial, and process lifetime management. |
| **M7** | Observability | **COMPLETE** | Lightweight structured event tracing (`TraceCollector`) and machine-readable JSON / Markdown run report generator (`ReportGenerator`). |
| **M8** | Benchmarking | **COMPLETE** | Ground truth dataset (`BenchmarkFixtures`), precision/recall/F1 evaluator (`BenchmarkEvaluator`), resilience experiments, and ablation matrix (`BenchmarkRunner`). |
| **M9** | Final Release | **COMPLETE** | System integration validation, security audits, complete documentation, release checklist, and 63/63 passing tests on canonical `SWE` branch. |
| **M10** | Semantic Code Intelligence | **COMPLETE** | Provider-agnostic semantic intelligence layer (`PythonSemanticResolver`). Eliminates dict `.get()` false positives, analyzes exception intent (`INTENTIONAL_FALLBACK`), classifies module roles (`ENTRYPOINT_LAUNCHER`), and performs semantic verification. |
| **M11** | Polyglot Semantic Intelligence | **COMPLETE** | Extends semantic analysis to JavaScript, TypeScript, React, and Vue. Added `ModuleRole.TEST_HARNESS` (M11.1) classification and cross-language API contract checking. |
| **M12** | Security Data-Flow & Taint Analysis | **COMPLETE** | Deterministic, provider-agnostic taint tracking engine (`SWE/agentos_swe/security/taint/`). Tracks untrusted data from `SOURCE → PROPAGATION → SINK` with inter-procedural flow, sanitizer awareness (`shlex.quote`, parameterized SQL, `html.escape`), and evidence-driven severity scoring. |
| **M12.5** | Single-File Unified UI | **COMPLETE** | Complete user-facing Streamlit dashboard implemented in ONE single file (`SWE/agentos_swe/ui.py`). Connects live SWE engine pipeline with 11 navigation pages, interactive Graphviz code graph, findings explorer, security/taint flow visualizer, stage timeline, markdown/JSON/HTML report exports, and safety indicators. |
| **M12.6** | Test-Harness Exception Semantic Hardening | **COMPLETE** | Hardened deterministic exception intent resolver (`PythonSemanticResolver.analyze_exception_block`). Combines exception variable binding, logging/print diagnostics detection, controlled fallback analysis (`return`, `assign`, `continue`, `break`), and module role context (`TEST_HARNESS`). Eliminates CLI smoke test logging false positives while preserving genuine silent `except Exception: pass` detections. |
| **M13** | Vulnerability Correlation & Intelligent Repair | **COMPLETE** | Evidence-driven correlation engine (`EvidenceCorrelator`), deterministic root-cause analyzer (`RootCauseAnalyzer`), explainable confidence scoring, vulnerability-specific repair engine (`IntelligentRepairEngine`), sandboxed patch validator (`SandboxedPatchValidator`), security regression analyzer (`SecurityRegressionAnalyzer`), governance integration (`GovernanceGate`), single-file UI dashboard (Page 12: Vulnerability Intelligence), and executive reporting. |
| **M13.1** | Real-World Repair Validation & Regression Hardening | **COMPLETE** | Empirical repair validation engine (`RealWorldRepairValidator`), sandboxed re-analysis, differential before/after finding comparison (`FIXED`, `REMAINING`, `NEW`), patch quality metrics (`PatchQualityMetrics`), regression detection (`REGRESSION_DETECTED`), intentional pattern preservation (`NO_REPAIR_REQUIRED`), single-file UI repair validation section, and executive report summaries. |
| **M14** | Repository Security Intelligence & Historical Regression | **COMPLETE** | Persistent local SQLite scan store (`HistoricalScanStore`), deterministic SHA-256 finding fingerprinter (`FindingFingerprinter`), finding lifecycle states (`NEW`, `FIXED`, `UNCHANGED`, `REOPENED`, `REGRESSION`), security score formula ($0 - 100$), risk trend analyzer (`SecurityScorer`), read-only git diff impact analyzer (`ChangedCodeImpactAnalyzer`), historical scan comparator (`HistoricalScanComparator`), single-file UI Page 13 ("Security History"), and executive reports. |

---

## M14 — Repository Security Intelligence & Historical Regression Architecture

M14 transforms AgentOS-SWE from a single-snapshot security scanner into a historical repository security intelligence system:

```
Repository / Commit → Repository Baseline → Current Scan → Finding Fingerprinting 
    → Historical Correlation → Finding Lifecycles (NEW | FIXED | UNCHANGED | REOPENED | REGRESSION) 
    → Security Score & Risk Trend → Changed-Code Impact → Historical Timeline 
    → Executive Report & Single-File UI
```

### Key Architectural Components:

1. **`HistoricalScanStore` (`agentos_swe/history/store.py`)**: Persistent SQLite database store (`agentos_swe_history.db`) operating 100% locally. Manages historical `ScanRecord` snapshots with secret redaction and multi-repository isolation.
2. **`FindingFingerprinter` (`agentos_swe/history/fingerprint.py`)**: Line-number-invariant SHA-256 fingerprinter based on root cause, category, affected function, sink/source, and normalized code context.
3. **`SecurityScorer` (`agentos_swe/history/scoring.py`)**: Computes explainable internal security score ($0 - 100$) based on severity weights ($\text{CRITICAL}=25, \text{HIGH}=15, \text{MEDIUM}=5, \text{LOW}=1$), score deltas, and `RiskTrend` (`IMPROVING`, `DEGRADING`, `STABLE`).
4. **`ChangedCodeImpactAnalyzer` (`agentos_swe/history/impact.py`)**: Read-only Git diff analyzer correlating recently changed files/functions with security findings.
5. **`HistoricalScanComparator` (`agentos_swe/history/comparator.py`)**: Structural comparator evaluating finding lifecycle transitions (`FOUND → UNCHANGED → FIXED → REOPENED`).
6. **Single-File UI Integration (`agentos_swe/ui.py`)**: Enforces single-file UI invariant with Page 13 ("Security History & Risk Trend Analysis").


---

## M13.1 — Real-World Repair Validation & Security Regression Hardening Architecture

M13.1 introduces empirical sandboxed validation proving that generated patches eliminate targeted vulnerabilities without introducing security regressions:

```
Original Repository → M13 Detection → Correlated Finding → Root Cause → Repair Proposal → Minimal Patch 
    → IsolatedSandbox → Syntax Check → Repro Test → Security Re-Scan → Taint Re-Analysis 
    → Finding Differential → Regression Status → Governance Decision → Final Repair Verdict 
    → Report & Single-File UI
```

### Key Architectural Invariants & Components:

1. **`RealWorldRepairValidator` (`SWE/agentos_swe/repair/repair_validator.py`)**:
   - Executes pre-patch baseline analysis and checks intentional pattern signals (`INTENTIONAL_FALLBACK`, `TEST_HARNESS`, `DICT_LOOKUP`). Returns `RepairVerdict.NO_REPAIR_REQUIRED` for safe diagnostic patterns.
   - Applies candidate patches strictly inside `IsolatedSandbox`, validating syntax (`py_compile`) and reproduction test execution.
   - Performs post-patch security re-scanning and taint re-analysis on patched workspace code.

2. **Differential Finding Comparison (`SecurityRegressionAnalyzer`)**:
   - Computes structural finding sets: `Removed Findings`, `Remaining Findings`, and `Newly Introduced Findings`.
   - Assigns `RegressionStatus.NEW_VULNERABILITY_INTRODUCED` and `RepairVerdict.REGRESSION_DETECTED` if any new `CRITICAL` or `HIGH` vulnerability appears.

3. **`PatchQualityMetrics`**:
   - Evaluates modified file count, line diff size, API signature preservation, and formatting noise to score patch quality (`HIGH`, `MEDIUM`, `LOW`).

4. **Single-File UI & Executive Report Integration (`SWE/agentos_swe/ui.py` & `report.py`)**:
   - Extends Page 12 `"Vulnerability Intelligence"` with a dedicated subsection **"Repair Validation & Security Regression Hardening"**.
   - Displays `BEFORE → VULNERABILITY → PROPOSED PATCH → SANDBOX VALIDATION → AFTER → REGRESSION → VERDICT` cards and differential comparison tables.


---

## M13 — Evidence-Driven Vulnerability Correlation & Intelligent Repair Architecture

M13 completes the end-to-end vulnerability intelligence and remediation pipeline:

```
Repository Intake → Code Graph → Investigation Squad → Semantic Analysis → Taint/Data-Flow 
    → Finding Aggregation → Evidence Correlation → Root-Cause Analysis → Verification 
    → Repair Generation → Patch Validation → Security Regression Validation → Governance Decision 
    → Report & Single-File UI
```

### Key Architectural Components:

1. **`EvidenceCorrelator` (`SWE/agentos_swe/correlation/correlator.py`)**:
   - Provider-agnostic correlation engine combining evidence from BugAgent, SecurityAgent, PerformanceAgent, ArchitectureAgent, PythonSemanticResolver, PythonTaintAnalyzer, Code Graph, VerificationAgent, and StaticVerificationStrategy.
   - Correlates findings using multi-dimensional criteria: same file, nearby lines (+/- 5 lines), same function, same tainted variable/source/sink, shared call chain, and graph node overlap into unified `CorrelatedFinding` objects.

2. **`RootCauseAnalyzer` (`SWE/agentos_swe/correlation/root_cause.py`)**:
   - Deterministic root cause analyzer mapping raw findings, taint paths, and semantic signals into `RootCauseCategory` values (`COMMAND_INJECTION`, `CODE_INJECTION`, `SQL_INJECTION`, `XSS`, `SSRF`, `PATH_TRAVERSAL`, `UNSAFE_DESERIALIZATION`, `SENSITIVE_DATA_EXPOSURE`, `EXCEPTION_SWALLOWING`, `PERFORMANCE_ANTI_PATTERN`, `ARCHITECTURE_COUPLING`, `UNKNOWN`).

3. **Explainable Confidence Model**:
   - Computes weighted confidence scores based on empirical evidence (`+ untrusted source identified`, `+ propagation chain confirmed`, `+ dangerous sink confirmed`, `+ semantic type resolved`, `+ verification passed`, `+ multi-agent agreement`). Returns `ConfidenceExplanation` with explicit rationale strings.

4. **`IntelligentRepairEngine` (`SWE/agentos_swe/repair/repair_strategy.py`)**:
   - Strategy selector mapping root vulnerability cause to safe, minimal repair rules (e.g. converting `shell=True` to argument arrays, parameterized SQL queries, context-aware HTML escaping, path canonicalization, safe deserializer substitution, narrowing swallowed exception clauses).
   - Produces structured `RepairProposal` explaining WHY THIS FIX, WHAT FILE, WHAT LINES, WHAT CHANGES, WHY IT REDUCES RISK.

5. **`SandboxedPatchValidator` & `SecurityRegressionAnalyzer` (`SWE/agentos_swe/repair/`)**:
   - Runs candidate patches inside `IsolatedSandbox`.
   - Validates syntax correctness (`py_compile`), reproduction test execution, taint re-analysis on patched files, and security regression status (`CLEAN`, `PARTIAL_FIX`, `NEW_VULNERABILITY_INTRODUCED`). Returns `ValidationResult` and `SecurityRegressionResult`.

6. **Single-File UI & Executive Report Integration (`SWE/agentos_swe/ui.py` & `report.py`)**:
   - Enforces single-file UI invariant in `SWE/agentos_swe/ui.py` with Page 12 `"Vulnerability Intelligence"`.
   - Displays visual chain `SOURCE → PROPAGATION → SINK → ROOT CAUSE → REPAIR → VALIDATION` and diagnostic rationale cards.
   - Extends executive reports (`ReportGenerator`) with correlated finding tables, root cause metrics, repair proposal diffs, governance decisions, and final verdict.


---

## M12.6 — Test-Harness Exception Semantic Hardening Architecture

M12.6 enhances the semantic exception analysis pipeline in `PythonSemanticResolver`:

```
                       Exception Block Analysis (analyze_exception_block)
                                       ↓
           ┌───────────────────────────┴───────────────────────────┐
           │                                                       │
  Signal 1: Exception Type & Variable Binding        Signal 2: Logging / Diagnostic Calls
   (except Exception as e / bare except)               (print, logger.error, logging)
           │                                                       │
           └───────────────────────────┬───────────────────────────┘
                                       ↓
           ┌───────────────────────────┴───────────────────────────┐
           │                                                       │
  Signal 3: Controlled Fallback Check                Signal 4: Module Role Context
   (return None, assign, continue, break)             (ModuleRole.TEST_HARNESS)
           │                                                       │
           └───────────────────────────┬───────────────────────────┘
                                       ↓
                             Semantic Intent Decision:
   ├── Logged Diagnostic Exception + Fallback ───→ INTENTIONAL_FALLBACK (No Bug)
   └── Generic Silent `except Exception: pass` ──→ POSSIBLE_ERROR_SWALLOW (Confirmed Bug)
```

### Semantic Exception Handling Rationale:
- **Diagnostic Exception Handler** (`INTENTIONAL_FALLBACK`):
  ```python
  except Exception as e:
      print(f"GET {path} failed: {e}")
      return None
  ```
  *Reasoning*: Exception is bound, printed to stdout as diagnostic test feedback, and returns a controlled fallback value (`None`).

- **Silent Exception Handler** (`POSSIBLE_ERROR_SWALLOW`):
  ```python
  except Exception:
      pass
  ```
  *Reasoning*: Catches all exceptions blindly without logging, reporting, or fallback value. Correctly reported as a bug regardless of whether it resides in production code or a test harness.

---

## M12.5 — AgentOS-SWE Single-File Unified UI

M12.5 introduces a single-file Streamlit developer & security platform UI (`SWE/agentos_swe/ui.py`):

```
                                  Streamlit UI (agentos_swe/ui.py)
                                                ↓
                    ┌───────────────────────────┴───────────────────────────┐
                    │                                                       │
             Scan Controls & Sidebar                               11 Navigation Pages
     (Repo, Branch, Commit, Mode, [Run Scan])              (Overview, Agents, Graph, Findings,
                    │                                       Security/Taint, Arch, Perf,
                    ↓                                       Verif, Pipeline, Report, Safety)
             run_swe_scan_engine()                                          │
                    ↓                                                       │
    ┌───────────────┴───────────────────────┐                               │
    │  Intake → Graph Build → Investigation │                               │
    │  → Taint → Verification → Repair     │ ──────────────────────────────┘
    │  → Governance → PR → Observability   │ (Reads Session State Scan Results)
    └───────────────────────────────────────┘
```

### Key Architectural Invariants:
1. **Single-File Architecture**: The complete user-facing UI is fully contained in `SWE/agentos_swe/ui.py` without external frontend dependencies (`ui/components/`, `frontend/`, React, or Node).
2. **Actual SWE Execution**: The UI invokes the real SWE pipeline (`RepositoryIntake`, `build_repository_context`, `InvestigationSquad`, `PythonTaintAnalyzer`, `VerificationPipeline`, `RepairPipeline`, `PRPipeline`, `ReportGenerator`).
3. **No Terminal Scraping / No Hardcoding**: All metrics, graphs, findings, taint paths, evidence chains, and stage timings are derived dynamically from typed backend scan objects.
4. **Safety & Immutability**: Enforces `AGENTOS_SWE_DRY_RUN=1` and `IsolatedSandbox` execution guarantees.

### UI Launch Command:
```bash
streamlit run SWE/agentos_swe/ui.py
```

## M12 — Security Data-Flow & Taint Analysis Architecture

M12 introduces deterministic, provider-agnostic **security data-flow and taint analysis**:

```
                          Source Code (.py / JS / TS)
                                       ↓
                             SemanticTaintProvider
                                       ↓
   ┌───────────────────────────────────┼───────────────────────────────────┐
   │                                   │                                   │
Taint Source Detector        Propagation Tracker                  Taint Sink Detector
 (HTTP, env, CLI, input)   (Intra- & Inter-Procedural)       (Shell, eval, SQL, Deser)
   │                                   │                                   │
   └───────────────────────────────────┼───────────────────────────────────┘
                                       ↓
                               Sanitizer Detector
                 (shlex.quote, html.escape, parameterized SQL)
                                       ↓
                             Taint Path & Finding
                 (Source → Propagation Chain → Sink + Evidence)
                                       ↓
                           Evidence Severity Model
                      (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN)
                                       ↓
                    StaticVerificationStrategy Integration
                     (Structural Path & Line Verification)
```

### Key M12 Architectural Components:

1. **`SemanticTaintProvider`**: Provider-agnostic interface enabling multi-language taint engines (`PythonTaintAnalyzer` for Python, `UnsupportedTaintProvider` stub for JS/TS returning UNSUPPORTED without false positives).
2. **`SourceDetector`**: Identifies untrusted entrypoints across HTTP requests (`request.args`, `request.form`, `request.get_json()`), environment variables (`os.environ`, `os.getenv`), CLI arguments (`sys.argv`, `argparse`), and user input (`input()`).
3. **`SinkDetector`**: Detects dangerous endpoints including shell execution (`subprocess` with `shell=True`, `os.system`), dynamic evaluation (`eval`, `exec`), SQL injection (`cursor.execute`), unsafe deserialization (`pickle.loads`, `yaml.load`), and template rendering (`render_template_string`).
4. **`PropagationTracker` & `InterProceduralTracker`**: Tracks taint flow through assignments, string concatenation (`+`), f-strings, format strings (`%`), container construction, and bounded inter-procedural wrapper function calls (`MAX_TAINT_DEPTH = 8`).
5. **`SanitizerDetector`**: Recognizes deterministic sanitizers (`shlex.quote`, `html.escape`, `markupsafe.escape`, `bleach.clean`, parameterized SQL placeholders, primitive type casts `int`/`float`/`bool`) to mark safe paths as `is_sanitized=True` and avoid false positives.
6. **`StaticVerificationStrategy` Integration**: Performs structural validation of taint findings (line existence, snippet presence, chain validity) and rejects broken or incomplete paths as `REJECTED` or `INCONCLUSIVE`.

### Static Analysis Limitations:

Static taint analysis is deterministic and bounded. It has explicit limitations:
- Whole-program symbolic execution is not performed; inter-procedural depth is bounded at 8 hops.
- Dynamic reflection or `getattr` string manipulation outside static resolution cannot be fully tracked.
- High confidence is reserved for deterministic evidence; ambiguous paths become `INCONCLUSIVE`.

---

## Security & Production Safety Invariants

1. **Repository Immutability**: Host source code is strictly read-only. All modifications occur inside temporary `IsolatedSandbox` environments.
2. **No Automatic Merge**: Pull requests require manual human review; no auto-merge functionality is implemented.
3. **Secret Redaction**: Environment credentials and tokens are automatically redacted from logs, prompts, stdout/stderr, and PR descriptions.
4. **Command Execution Policy**: Subshell commands are checked against explicit allow lists; unauthorized binaries or dangerous patterns are rejected.
5. **Dry-Run Default**: Remote write operations (push/PR POST) require explicit configuration (`AGENTOS_SWE_DRY_RUN=0`).

---

## Known Limitations

1. **Remote Git Commit Push**: Requires valid `GITHUB_TOKEN` and setting `AGENTOS_SWE_DRY_RUN=0`.
2. **Language Support**: Polyglot static analysis available for Python, JavaScript, TypeScript, Vue, and React. Taint analysis engine fully implemented for Python with JS/TS provider interface prepared for future expansion.

