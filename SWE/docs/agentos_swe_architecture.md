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
| **M15** | Intelligent Security Prioritization & Cross-Repository Risk Intelligence | **COMPLETE** | Evidence-driven priority scoring engine (`SecurityPriorityEngine`), priority tiers (`P0`–`P4`), exploitability analyzer (`ExploitabilityAnalyzer`), internet exposure analyzer (`ExposureAnalyzer`), blast radius analyzer (`BlastRadiusAnalyzer`), historical recurrence analyzer (`HistoricalRecurrenceAnalyzer`), cross-repository intelligence engine (`CrossRepositoryIntelligenceEngine`), security recommendation engine (`SecurityRecommendationEngine`), single-file UI Page 14 ("Security Intelligence"), and executive report summaries. |
| **M16** | Autonomous Attack-Path Reasoning & Security Investigation | **COMPLETE** | End-to-end attack path builder (`AttackPathBuilder`), entrypoint detector (`EntrypointDetector`), trust boundary analyzer (`TrustBoundaryAnalyzer`), auth analyzer (`AuthenticationAnalyzer`), attack graph generator (`AttackGraphBuilder`), attack path scorer (`AttackPathScorer`), autonomous investigator (`AutonomousSecurityInvestigator`), single-file UI Page 15 ("Attack Paths"), and executive reports. |
| **M17** | Intelligent Security Remediation Orchestration | **COMPLETE** | Fix ordering engine (`RemediationPlanner`), patch impact analyzer, security score projection, single-file UI Page 16 ("Remediation Center"). |
| **M18** | Continuous Security Monitoring & Regression Detection | **COMPLETE** | Posture snapshot manager (`SnapshotManager`), commit diff change detector, regression classification (`RegressionDetector`), alert engine, single-file UI Page 17 ("Security Monitoring"). |
| **M19** | Security Release Readiness & Risk Decision Engine | **COMPLETE** | Release readiness evaluator (`SecurityReleaseReadinessEngine`), decision engine (`GO_FOR_RELEASE`, `CONDITIONAL_GO`, `NO_GO_BLOCKED`), release gate verdict, single-file UI Page 18 ("Release Readiness"). |
| **M20** | Security Engineering Orchestration Workflow | **COMPLETE** | Master engineering workflow orchestrator (`SecurityEngineeringOrchestrator`), adaptive plan generator, security case manager (`SecurityCase`), decision pipeline, single-file UI Page 19 ("Security Engineering"). |
| **M21** | Security Knowledge Graph & Learning Intelligence | **COMPLETE** | Persistent SQLite pattern store (`KnowledgeStore`), pattern learner (`SecurityPatternLearner`), cross-scan knowledge graph (`KnowledgeGraph`), adaptive recommender, single-file UI Page 20 ("Security Knowledge"). |
| **M22** | Safe Security Simulation & Exploitability Validation | **COMPLETE** | Safe simulation engine (`SecuritySimulationEngine`), safety gate (`SafetyGate`), reachability analyzer, scenario builder, sandboxed executor (`IsolatedSandbox`), differential before/after analysis, single-file UI Page 21 ("Security Simulation"). |
| **M23** | Continuous Security Monitoring & Security Drift Intelligence | **COMPLETE** | Posture snapshot engine (`SecuritySnapshotEngine`), deterministic drift analyzer & scorer (`SecurityDriftAnalyzer`, `SecurityDriftScorer`), read-only git diff change analyzer (`SecurityChangeAnalyzer`), impact correlator (`SecurityChangeImpactCorrelator`), alert engine, release drift assessment, single-file UI Page 22 ("Security Drift Monitoring"). |
| **M24** | Autonomous Security Decision & Remediation Orchestration | **COMPLETE** | Deterministic security decision engine (`SecurityDecisionEngine`), policy engine (`SecurityPolicyEngine`, rules `P01`–`P09`), weighted decision confidence model (`DecisionConfidenceEngine`), action selector (`ActionSelector`), local in-memory approval engine (`HumanApprovalEngine`), ranked remediation queue (`RemediationQueue`), decision explainability (`DecisionExplainabilityEngine`), single-file UI Page 23 ("Security Decision Center"), and executive reporting. |

---

## M24 — Autonomous Security Decision & Remediation Orchestration Architecture

M24 introduces an autonomous decision orchestration layer on top of M0–M23 that deterministically decides:
> **Given a verified vulnerability, what should AgentOS-SWE recommend doing next?**

```
Repository Scan → Investigation Squad → Semantic Intelligence → Taint Analysis → Evidence Correlation
     → Root Cause → Priority Intelligence → Attack Path → Historical + Drift Intelligence
     → Decision Orchestrator (M24) → Policy Engine (P01–P09) → Confidence Engine → Action Selector
     → Remediation Queue → Human Approval Engine → Governance Gate → Report + Single-File UI (Page 23)
```

### Key Architectural Components:

1. **`SecurityPolicyEngine` (`agentos_swe/orchestration/policy_engine.py`)**: Evaluates deterministic security rules (`P01` to `P09`):
   - `P01`: Critical + Exploitable Taint + Internet Exposed -> `BLOCK_RELEASE`
   - `P02`: High Severity + Reachable Attack Path -> `GENERATE_REPAIR`
   - `P03`: Medium Severity + Recurring History -> `INVESTIGATE`
   - `P04`: Reopened Vulnerability -> `HUMAN_REVIEW`
   - `P05`: Intentional Fallback -> `IGNORE`
   - `P06`: Test Harness Exception -> `IGNORE`
   - `P07`: Sanitized Taint Flow -> `MONITOR`
   - `P08`: Low Confidence Finding -> `HUMAN_REVIEW`
   - `P09`: Degrading Drift -> `BLOCK_RELEASE`

2. **`DecisionConfidenceEngine` (`agentos_swe/orchestration/confidence_engine.py`)**: Computes weighted deterministic confidence scores (0.0 to 1.0) with contributions: Verification (+0.25), Taint (+0.25), Attack Path (+0.15), Drift (+0.15), History (+0.10), Semantic (+0.10).

3. **`ActionSelector` (`agentos_swe/orchestration/action_selector.py`)**: Maps policy rule evaluations and confidence metrics to concrete `DecisionRecommendation` objects (`IGNORE`, `MONITOR`, `INVESTIGATE`, `HUMAN_REVIEW`, `GENERATE_REPAIR`, `VALIDATE_REPAIR`, `BLOCK_RELEASE`).

4. **`HumanApprovalEngine` (`agentos_swe/orchestration/approval_engine.py`)**: Manages local, in-memory `ApprovalRequest` objects (`PENDING`, `APPROVED`, `DECLINED`, `EXPIRED`) for Streamlit session simulation with 0 automatic repository modifications.

5. **`RemediationQueue` (`agentos_swe/orchestration/remediation_queue.py`)**: Constructs and ranks the autonomous remediation queue sorted by priority score, severity, exploitability, exposure, and confidence.

6. **`DecisionExplainabilityEngine` (`agentos_swe/orchestration/explainability.py`)**: Generates step-by-step trace explanations for every decision and policy rule trigger.

7. **`SecurityDecisionOrchestrator` (`agentos_swe/orchestration/orchestrator.py`)**: Master facade orchestrating data intake from all preceding stages (M0–M23) and outputting `OrchestrationResult`.

8. **Single-File UI Integration (`agentos_swe/ui.py`)**: Enforces single-file UI invariant with Page 23 ("Security Decision Center").

---

## M16 — Autonomous Attack-Path Reasoning & Security Investigation Architecture

M16 transforms AgentOS-SWE into an autonomous evidence-driven attack-path reasoning and security investigation engine:

```
Repository / Commit → Entrypoint Discovery → Trust Boundary & Auth Verification 
    → Inter-Procedural Path Construction (Bounded Depth <= 12) → Sanitizer & Defense Tracking 
    → Attack Graph Builder → Attack Path Correlation & Deduplication → Risk Scoring (0–100) 
    → Autonomous Security Investigator → M13/M13.1 Repair Strategy Connection → UI Page 15
```

### Key Architectural Components:

1. **`AttackPathBuilder` (`agentos_swe/attackpath/path_builder.py`)**: Connects Code Graph, Taint flows, and Entrypoints into end-to-end `AttackPath` models with bounded depth (`MAX_ATTACK_PATH_DEPTH = 12`).
2. **`EntrypointDetector` (`agentos_swe/attackpath/entrypoints.py`)**: Structural entrypoint discovery across FastAPI, Flask, Django, CLI, WebSocket, and MCP (`INTERNET`, `AUTHENTICATED_HTTP`, `USER_CLI`, `INTERNAL_API`, `SCHEDULED`, `UNKNOWN`).
3. **`TrustBoundaryAnalyzer` (`agentos_swe/attackpath/trust_boundaries.py`)**: Detects cross-boundary transitions (`INTERNET → APPLICATION → OPERATING_SYSTEM / DATABASE`).
4. **`AuthenticationAnalyzer` (`agentos_swe/attackpath/auth_analyzer.py`)**: Verifies structural auth controls (`Depends(get_current_user)`, `@login_required`) $\rightarrow$ (`AUTHENTICATED`, `AUTHORIZATION_REQUIRED`, `UNAUTHENTICATED`).
5. **`AttackGraphBuilder` (`agentos_swe/attackpath/attack_graph.py`)**: Generates directed `AttackGraph` node-edge models and renders Graphviz DOT strings.
6. **`AutonomousSecurityInvestigator` (`agentos_swe/attackpath/investigation.py`)**: Produces "Why is this dangerous?" narratives and "How to break the attack path" remediation instructions connected to M13/M13.1 repair strategies.
7. **Single-File UI Integration (`agentos_swe/ui.py`)**: Enforces single-file UI invariant with Page 15 ("Attack Paths").


---

## M15 — Intelligent Security Prioritization & Cross-Repository Risk Intelligence Architecture

M15 builds an evidence-driven intelligence layer on top of M0–M14, prioritizing findings by exploitability, internet exposure, blast radius, historical recurrence, and cross-repository patterns:

```
Repository / Commit → Taint Analysis & Code Graph → Historical Scan History 
    → Exploitability Engine → Internet Exposure Engine → Blast Radius Engine 
    → Recurrence Engine → Security Priority Engine (P0–P4, Score 0–100) 
    → Cross-Repository Engine → Recommendation Engine → Report & Single-File UI
```

### Key Architectural Components:

1. **`SecurityPriorityEngine` (`agentos_swe/intelligence/prioritizer.py`)**: Computes explainable priority score ($0 - 100$) and assigns priority tiers (`P0`: 90-100, `P1`: 75-89, `P2`: 60-74, `P3`: 40-59, `P4`: 0-39) based on documented evidence weights.
2. **`ExploitabilityAnalyzer` (`agentos_swe/intelligence/exploitability.py`)**: Evaluates M12 taint sources, sinks, propagation paths, and sanitizers (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NOT_EXPLOITABLE`).
3. **`ExposureAnalyzer` (`agentos_swe/intelligence/exposure.py`)**: Analyzes AST & Code Graph decorators (`@app.get`, `@app.post`, `@router.get`, `request.args`, `argparse`) to classify reachability (`INTERNET_EXPOSED`, `USER_CONTROLLED`, `INTERNAL`).
4. **`BlastRadiusAnalyzer` (`agentos_swe/intelligence/blast_radius.py`)**: Analyzes Code Graph callers and dependents to estimate system impact scope (`SYSTEM_WIDE`, `BROAD`, `LIMITED`, `LOCAL`).
5. **`CrossRepositoryIntelligenceEngine` (`agentos_swe/intelligence/cross_repository.py`)**: Groups stored multi-repository historical findings into normalized vulnerability families (`COMMAND_INJECTION`, `SQL_INJECTION`, etc.) and calculates cross-repo occurrence metrics.
6. **`SecurityRecommendationEngine` (`agentos_swe/intelligence/recommendation.py`)**: Generates explainable remediation guidance (`WHY_THIS_MATTERS`, `WHAT_TO_FIX`, `WHY_IT_IS_PRIORITIZED`, `RECOMMENDED_ACTION`, `EXPECTED_RISK_REDUCTION`) connected to M13/M13.1 repair strategies.
7. **Single-File UI Integration (`agentos_swe/ui.py`)**: Enforces single-file UI invariant with Page 14 ("Security Intelligence & Remediation Queue").


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

## M25 — Continuous Security Learning, Trend Intelligence & Adaptive Risk Architecture

M25 equips AgentOS-SWE with continuous security learning, trend intelligence, vulnerability recurrence classification, remediation efficacy tracking, and adaptive risk signal generation:

```
Repository Scan → M14 Historical Memory → SecurityPatternDetector (10 Pattern Types)
    → SecurityTrendAnalyzer (Posture Trends & Volatility) → RecurrenceAnalyzer (FIRST_SEEN to CHRONIC)
    → RemediationLearningEngine (Strategy Efficacy) → AdaptiveRiskEngine (1.0x-2.5x Multipliers)
    → LearningExplainabilityEngine → UI Page 24
```

### Key Architectural Components:
1. **`SecurityMemory` (`agentos_swe/learning/security_memory.py`)**: Persists finding memories and scan snapshots using M14 SQLite infrastructure (`agentos_swe_history.db`) with secret sanitization.
2. **`SecurityPatternDetector` (`agentos_swe/learning/pattern_detector.py`)**: Detects 10 core security patterns (`RECURRING_VULNERABILITY`, `REOPENED_VULNERABILITY`, `REPEATED_ROOT_CAUSE`, `REPEATED_FILE_PATTERN`, `REPEATED_ATTACK_PATH`, `REPEATED_SECURITY_DRIFT`, `FAILED_REMEDIATION`, `SUCCESSFUL_REMEDIATION`, `PERSISTENT_VULNERABILITY`, `NEW_EMERGING_PATTERN`).
3. **`SecurityTrendAnalyzer` (`agentos_swe/learning/trend_analyzer.py`)**: Computes score deltas, posture directions (`RAPIDLY_IMPROVING` to `RAPIDLY_DEGRADING`), and standard deviation volatility.
4. **`RecurrenceAnalyzer` (`agentos_swe/learning/recurrence_analyzer.py`)**: Classifies vulnerability lifecycle behavior (`FIRST_SEEN`, `OCCASIONAL`, `RECURRING`, `PERSISTENT`, `CHRONIC`).
5. **`RemediationLearningEngine` (`agentos_swe/learning/remediation_learning.py`)**: Tracks repair strategy success rates per root cause.
6. **`AdaptiveRiskEngine` (`agentos_swe/learning/risk_adaptation.py`)**: Computes evidence-backed risk multipliers ($1.0\times$ to $2.5\times$) and priority boosts.
7. **`LearningExplainabilityEngine` (`agentos_swe/learning/explainability.py`)**: Produces transparent audit reports explaining learning decisions.

---

## M26 — Continuous Security Monitoring & Security Drift Detection Architecture

M26 transforms AgentOS-SWE into a continuous monitoring and postural drift detection engine:

```
Baseline Scan Snapshot + Current Scan Snapshot → SecurityPosturalComparator
    → ChangedSurfaceAnalyzer (Git Diff Mapping) → SecurityDriftDetector (16 Drift Event Rules)
    → SecurityDriftScorer (0-100 Impact Score & Severity) → SecurityDriftCorrelator (M14-M25 Signals)
    → SecurityDriftInvestigator ("WHY DID SECURITY DRIFT?") → M24 Governance Integration → UI Page 25
```

### Key Architectural Components:
1. **`SecurityPosturalComparator` (`agentos_swe/drift/comparator.py`)**: Fine-grained differential analysis beyond finding counts (detects impact escalation).
2. **`ChangedSurfaceAnalyzer` (`agentos_swe/drift/changed_surface.py`)**: Maps read-only git diff changes to security-sensitive code surfaces.
3. **`SecurityDriftDetector` (`agentos_swe/drift/drift_detector.py`)**: Evaluates 16 drift event rules while enforcing strict false positive protection (`dict.get()`, test-harness diagnostic handlers, intentional fallbacks, formatting/comment changes produce `NO_DRIFT`).
4. **`SecurityDriftScorer` (`agentos_swe/drift/drift_scorer.py`)**: Computes deterministic $0$–$100$ impact scores and maps severity (`NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
5. **`SecurityDriftCorrelator` (`agentos_swe/drift/drift_correlator.py`)**: Correlates drift events with M14 history, M15 priorities, M16 attack paths, M24 decisions, and M25 learning signals.
6. **`SecurityDriftInvestigator` (`agentos_swe/drift/drift_investigator.py`)**: Produces structured root-cause answers to "WHY DID SECURITY DRIFT?".
7. **`SecurityMonitoringDriftEngine` (`agentos_swe/drift/drift_engine.py`)**: Master facade orchestrator.

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
3. **Historical Baseline Dependency**: Drift detection and continuous learning require at least 2 historical scan snapshots for comparative deltas; initial scans report `INSUFFICIENT_HISTORY`.

