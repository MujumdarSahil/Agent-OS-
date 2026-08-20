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

---

## M10 — Semantic Code Intelligence Architecture

M10 enhances AgentOS-SWE from syntactic pattern matching to **semantic code understanding**:

```
AST / Code Graph
       ↓
Semantic Resolver (PythonSemanticResolver)
 ├── Symbol & Type Resolution (dict.get vs requests.get)
 ├── Call Categorization (DICT_LOOKUP, HTTP_NETWORK_CALL, FILE_IO_CALL, DATABASE_QUERY)
 ├── Exception Intent Analysis (INTENTIONAL_FALLBACK vs POSSIBLE_ERROR_SWALLOW)
 └── Module Role Classification (ENTRYPOINT_LAUNCHER vs LIBRARY_MODULE)
       ↓
Semantic Evidence (EvidenceSource.SEMANTIC_ANALYSIS)
       ↓
Investigation Agents & Semantic Verification (StaticVerificationStrategy)
       ↓
Confirmed / Rejected / Inconclusive Findings
```

Key M10 Capabilities:
1. **Dict `.get()` Resolution**: Disambiguates receiver types so standard dictionary key lookups (e.g. `job.get("title")`) are recognized as `DICT_LOOKUP` and excluded from loop network I/O analysis.
2. **Exception Intent Analysis**: Evaluates surrounding AST context to detect intentional fallback blocks (`ImportError`, multi-stage parsing, DB init fallback, compatibility branches) and skip false-positive bug reports.
3. **Module Role Classification**: Identifies application entrypoints (`main.py`, `server.py`, `streamlit_app.py`, `cli.py`) to prevent false-positive high fan-out coupling reports on composition roots.
4. **Semantic Verification**: `StaticVerificationStrategy` validates semantic evidence to reject syntactic false positives before confirmation.

## M11 — Polyglot Semantic Intelligence & Advanced Analysis

M11 extends AgentOS-SWE beyond Python-only semantic intelligence to support multi-language repositories containing **Python, JavaScript, TypeScript, React, and Vue** frontend code.

```
                  Polyglot Source Code (.py, .js, .jsx, .ts, .tsx, .vue)
                                            ↓
                                 SemanticProviderRegistry
  ┌───────────────────────┬──────────────────────────┬────────────────────────┬───────────────────────┐
  │                       │                          │                        │                       │
PythonResolver    JavaScriptResolver         TypeScriptResolver          VueResolver            ReactResolver
 (Python AST)     (JS / HTTP fetch)        (TS Typed ApiClient)     (<script setup> Vue)     (Hooks & JSX XSS)
  │                       │                          │                        │                       │
  └───────────────────────┴──────────────────────────┴────────────────────────┴───────────────────────┘
                                            ↓
                              Cross-Language API Contract Analyzer
                      (Frontend fetch/axios <-> Backend FastAPI/Flask routes)
                                            ↓
                          Semantic Confidence & Provenance Model
                            (0.90-1.00 = Strong, 0.70-0.89 = Inferred)
                                            ↓
                        Investigation Squad & Verification Integration
```

### Key M11 Architectural Components:
1. **`SemanticProviderRegistry`**: Central registry matching file extensions (`.py`, `.js`, `.jsx`, `.ts`, `.tsx`, `.vue`) to language-specific semantic providers with graceful `UNKNOWN` fallback on unsupported extensions or parser errors.
2. **`JavaScriptSemanticResolver` & `TypeScriptSemanticResolver`**: Static resolvers distinguishing network requests (`fetch`, `axios.get`, `client.get`, `apiClient.get<T>()`) from standard object key lookups (`job.get("title")`, `map.get()`, `config.get()`). Also audits JS security risks (`dangerouslySetInnerHTML`, `eval`, `new Function`, `child_process.exec`).
3. **`VueSemanticResolver` & `ReactSemanticResolver`**: Vue SFC script block parser (<script setup>, lifecycle hooks `onMounted`, SFC imports) and React Hook/JSX analyzer (`useEffect`, `useState`, API calls).
4. **`APIContractAnalyzer`**: Cross-language contract auditing matching frontend request paths (`fetch("/api/users")`) against backend Python routes (`@app.get("/api/user")`), reporting path mismatches (singular/plural), HTTP method mismatches, and missing backend endpoints as `INFERRED` contract findings with confidence scores.
5. **Semantic Confidence & Provenance Model**: All semantic findings maintain provenance fields (`language`, `provider`, `rule`, `confidence`), using 0.90–1.00 for deterministic evidence, 0.70–0.89 for strong inferences, and 0.40–0.69 for weak inferences.

---

## AgentOS Framework Integration Matrix

- **`Agent` & `Squad`**: Investigation squad agents inherit from `agentos.core.agent.Agent` and execute under `agentos.core.squad.Squad` mission orchestration.
- **`GovernanceEngine` & `Policy`**: `GovernanceGate` registers `PolicyType.ACTION` policies to enforce risk thresholds before PR creation.
- **`SQLiteCheckpointStore`**: `VerificationPipeline`, `RepairPipeline`, and `PRPipeline` persist task checkpoints for seamless interruption recovery.
- **`LLMClient` & Multi-Provider Router**: Fallback chains automatically re-route requests across OpenAI, Anthropic, and Ollama providers during outages.

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
2. **Language Support**: Polyglot static analysis available for Python, JavaScript, TypeScript, Vue, and React. Dynamic runtime analysis requires dedicated language sandboxes.
