# AgentOS-SWE — Developer & Contributor Guide

Welcome to **AgentOS-SWE**, an enterprise-grade autonomous software verification and repair system built on the **AgentOS** framework.

This guide provides architectural guidelines, codebase organization, testing protocols, and safety rules for developers and open-source contributors.

---

## 1. Codebase Architecture & Domain Mapping

The production codebase is structured into **10 responsibility-driven domain packages** under `SWE/agentos_swe/`:

```
SWE/agentos_swe/
├── core/                   # Base data models, intake, context builder, investigation squad, aggregator
├── analysis/               # Code graph (GraphifyAdapter), AST semantic resolvers, verification pipeline & sandbox
├── security/               # Taint tracking engine, secret protection, command policy, resource limits
├── intelligence/           # Vulnerability prioritizer (P0-P4), attack paths, historical scan store, drift, knowledge, learning
├── remediation/            # Remediation planner, repair pipeline, safe simulation engine, PR pipeline & governance
├── operations/             # Security decision orchestrator, continuous monitoring, control plane, incident response
├── persistence/            # Operational state store & repository registry
├── observability/          # Real-time execution telemetry (events.py), trace collector (tracer.py), report generator (report.py)
├── release/                # Enterprise release readiness engine & safety gates
├── benchmark/              # Synthetic evaluation fixtures, resilience experiments & benchmark runner
└── ui.py                   # Single-file Streamlit UI dashboard
```

---

## 2. Mandatory Architectural Invariants

When contributing to AgentOS-SWE, you **MUST** adhere to the following strict system invariants:

### A. Strict Single-File UI Invariant
- **Rule**: All UI logic, page layouts, Streamlit components, state management, and visualizers **MUST** remain exclusively within `SWE/agentos_swe/ui.py`.
- **Prohibited**: Do NOT create `ui/`, `pages/`, `frontend/`, `components/`, or `templates/` directories.

### B. Legacy Facade Backward Compatibility
- **Rule**: Legacy package paths (`agentos_swe.attackpath`, `history`, `drift`, `learning`, `knowledge`, `repair`, `pr`, `monitoring`, `orchestration`, `controlplane`, `incident`, `simulation`, `correlation`, `graph`, `semantic`, `verification`) must remain intact.
- **Implementation**: Facade files must only re-export symbols from their new domain locations (`from agentos_swe.<domain>... import *`).

### C. AgentOS Core Immutability
- **Rule**: Do NOT modify files inside the `agentos/` core framework directory unless explicitly instructed by project maintainers. AgentOS-SWE operates as an extension layer over AgentOS.

### D. Target Repository Immutability
- **Rule**: Target repositories under analysis **MUST NOT** be modified directly on disk.
- **Implementation**: All test reproduction, patch application, subshell command execution, and verification MUST occur inside temporary `IsolatedSandbox` directories.

### E. Dry-Run & Governance Safety
- **Rule**: Dry-run mode (`AGENTOS_SWE_DRY_RUN=1`) must be enforced by default.
- **Rule**: Remote git pushes, PR creation POST calls, or destructive commands are strictly forbidden without explicit human approval.

### F. Secret Protection & Redaction
- **Rule**: Secrets, tokens (`ghp_`, `Bearer`, `sk-`), and passwords must be automatically redacted via `SecretProtection` before writing to logs, prompts, reports, or stdout/stderr.

---

## 3. Where to Add New Code

| Task / Feature Type | Target Location | Guidelines |
| :--- | :--- | :--- |
| **New Core Data Model** | `SWE/agentos_swe/core/models.py` | Add dataclasses or enums with `to_dict()` and `from_dict()` methods. |
| **New AST Resolver** | `SWE/agentos_swe/analysis/semantic/` | Inherit from `BaseSemanticResolver` and register in `SemanticResolverRegistry`. |
| **New Taint Sink / Source** | `SWE/agentos_swe/security/taint/` | Update `TaintAnalyzer` rules while preserving evidence correlation. |
| **New Intelligence Scorer** | `SWE/agentos_swe/intelligence/` | Add to appropriate subfolder (`priority/`, `attackpath/`, `drift/`, `knowledge/`). |
| **New Remediation Strategy** | `SWE/agentos_swe/remediation/repair/` | Implement in `repair_strategy.py` and register with `RepairPipeline`. |
| **New Unit or Integration Test** | `SWE/tests/swe/<purpose>/` | Place in the corresponding purpose directory (`unit/`, `analysis/`, etc.). |

---

## 4. Testing Protocols

All code changes must pass the full pytest suite without errors or warnings.

### Running the Full Test Suite
```bash
pytest SWE/tests -v
```

### Running Test Collection Audit
```bash
pytest SWE/tests --collect-only -q
```

### Running Targeted Test Directories
```bash
# Run unit tests only
pytest SWE/tests/swe/unit -v

# Run analysis tests only
pytest SWE/tests/swe/analysis -v

# Run UI & observability tests only
pytest SWE/tests/swe/ui -v

# Run real-world benchmark tests
pytest SWE/tests/swe/real_world -v
```

---

## 5. UI & Telemetry Validation

Before submitting a pull request, verify that:
1. Streamlit can import `agentos_swe.ui` cleanly:
   ```bash
   python -c "import agentos_swe.ui; print('UI OK')"
   ```
2. Scan execution lifecycle remains strictly finite (`IDLE` -> `RUNNING` -> `COMPLETE` / `FAILED` -> `STOP`).
3. Report bundles and ZIP archives generate cleanly in `outputs/scans/`.
