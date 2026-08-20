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
| **M12** | Security Data-Flow & Taint Analysis | **COMPLETE** | Deterministic, provider-agnostic taint tracking engine (`agentos_swe/security/taint/`). Tracks untrusted data from `SOURCE → PROPAGATION → SINK` with inter-procedural flow, sanitizer awareness (`shlex.quote`, parameterized SQL, `html.escape`), and evidence-driven severity scoring. |

---

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

