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
2. **Language Support**: Optimized for Python codebases; additional AST parsers can be registered for non-Python languages.
