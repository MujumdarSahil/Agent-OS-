# AgentOS-SWE — Enterprise Autonomous Software Verification and Repair System

[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests: 670 Passed](https://img.shields.io/badge/tests-670%20passed-brightgreen.svg)]()
[![Architecture: 10--Domain](https://img.shields.io/badge/architecture-10--domain-purple.svg)]()
[![UI: Single--File](https://img.shields.io/badge/UI-single--file%20invariant-orange.svg)]()

**AgentOS-SWE** is an enterprise-grade, autonomous software verification, security intelligence, and automated repair platform built on top of the **AgentOS** multi-agent framework.

It provides an end-to-end security engineering lifecycle — automatically ingesting repositories, parsing AST code graphs, performing deterministic taint analysis, prioritizing vulnerabilities, mapping attack surfaces, generating sandboxed patches, validating repairs, tracking security drift, and evaluating enterprise release readiness.

---

## 📋 Table of Contents

- [Overview & Value Proposition](#overview--value-proposition)
- [End-to-End Security Lifecycle](#end-to-end-security-lifecycle)
- [System Architecture](#system-architecture)
- [Repository Structure](#repository-structure)
- [Installation](#installation)
- [Configuration Reference](#configuration-reference)
- [Running AgentOS-SWE](#running-agentos-swe)
  - [Command Line & Programmatic Usage](#command-line--programmatic-usage)
  - [Streamlit Dashboard Workflow](#streamlit-dashboard-workflow)
- [Real-Time Terminal Telemetry](#real-time-terminal-telemetry)
- [13-Artifact Report Bundle & Downloads](#13-artifact-report-bundle--downloads)
- [Security Analysis & Remediation Capabilities](#security-analysis--remediation-capabilities)
- [Safety & Governance Invariants](#safety--governance-invariants)
- [Testing & Quality Assurance](#testing--quality-assurance)
- [Example Real-World Scan](#example-real-world-scan)
- [Output Directory Structure](#output-directory-structure)
- [Documentation Index](#documentation-index)
- [Troubleshooting Guide](#troubleshooting-guide)
- [Development & Contributing](#development--contributing)
- [Roadmap](#roadmap)
- [License](#license)

---

## 💡 Overview & Value Proposition

Traditional Static Application Security Testing (SAST) tools generate overwhelming volumes of unverified candidate alerts with zero contextual awareness or automated remediation.

**AgentOS-SWE** bridges the gap between security discovery and software engineering by transforming static code analysis into an autonomous, explainable, and sandboxed security engineering pipeline:

- **What problem does it solve?** Eliminates false-positive fatigue, maps full attack-path exposure, calculates quantitative vulnerability risk, generates minimal safe code repairs inside isolated sandboxes, and determines whether a codebase is safe for enterprise release.
- **Who is it for?** Security Engineers, Software Engineers, DevSecOps Leads, AI/ML Engineers, and Technical Audit Teams.
- **How is safety guaranteed?** Target repositories remain **100% UNCHANGED** on disk. All patch generation, test reproduction, and command executions run in temporary isolated sandboxes with default network egress denial and secret redaction.

---

## 🔄 End-to-End Security Lifecycle

AgentOS-SWE coordinates a 13-stage security engineering lifecycle:

```
┌──────────┐     ┌────────────┐     ┌───────────┐     ┌────────────┐
│1. DETECT │ ──> │2.UNDERSTAND│ ──> │3.CORRELATE│ ──> │4.PRIORITIZE│
└──────────┘     └────────────┘     └───────────┘     └────────────┘
     │                                                      │
     ▼                                                      ▼
┌──────────┐     ┌────────────┐     ┌───────────┐     ┌────────────┐
│8.VALIDATE│ <── │ 7. REPAIR  │ <── │ 6. DECIDE │ <── │5.ATTACKPATH│
└──────────┘     └────────────┘     └───────────┘     └────────────┘
     │
     ▼
┌──────────┐     ┌────────────┐     ┌───────────┐     ┌────────────┐     ┌─────────────────────┐
│ 9. LEARN │ ──> │10. MONITOR │ ──> │11.OPERATE │ ──> │12.INCIDENT │ ──> │13. RELEASE READINESS│
└──────────┘     └────────────┘     └───────────┘     └────────────┘     └─────────────────────┘
```

1. **DETECT**: Ingests codebases, parses AST relationships, and deploys multi-agent investigation squad.
2. **UNDERSTAND**: Resolves polyglot semantic definitions (Python, JS, TS, React, Vue), intentional try/except fallbacks, and test harness functions.
3. **CORRELATE**: Maps deterministic data-flow taint paths from untrusted `SOURCE` to vulnerable `SINK`.
4. **PRIORITIZE**: Assigns objective `P0`–`P4` risk scores based on internet exposure, exploitability, and blast radius.
5. **ATTACK PATH**: Synthesizes entrypoints, trust boundaries, and authentication posture into multi-hop attack graphs.
6. **DECIDE**: Evaluates policy rules (`P01`–`P09`) to select optimal remediation actions (`REPAIR`, `INVESTIGATE`, `MONITOR`, `BLOCK`).
7. **REPAIR**: Synthesizes minimal defensive patches inside isolated subshell sandboxes.
8. **VALIDATE**: Executes pre/post patch differential analysis and security regression checks.
9. **LEARN**: Records recurring vulnerability patterns in a local SQLite Security Knowledge Graph.
10. **MONITOR**: Tracks post-scan security drift and posture changes across commits.
11. **OPERATE**: Maintains control plane health, repository registries, and operational state.
12. **INCIDENT RESPONSE**: Correlates active security anomalies into structured incident timelines.
13. **RELEASE READINESS**: Computes release scores ($0 - 100$) and issues final `GO` / `REVIEW_REQUIRED` / `BLOCKED` verdicts.

---

## 🏗️ System Architecture

AgentOS-SWE is architected into 10 responsibility-driven domain packages, wrapped by lightweight backward-compatibility facades:

```
                                  ┌─────────────────────────────┐
                                  │      Streamlit Dashboard    │
                                  │   (agentos_swe/ui.py - 1 file)│
                                  └──────────────┬──────────────┘
                                                 │
 ┌───────────────────────────────────────────────┴───────────────────────────────────────────────┐
 │                                 AgentOS-SWE 10-Domain Engine                                  │
 ├─────────────┬─────────────┬─────────────┬──────────────┬──────────────┬──────────────┬─────────┤
 │    core     │  analysis   │  security   │ intelligence │ remediation  │  operations  │ release │
 ├─────────────┼─────────────┼─────────────┼──────────────┼──────────────┼──────────────┼─────────┤
 │ Intake,     │ Graph, AST  │ Taint Flow, │ Prioritizer, │ Planner,     │ Orchestrator,│ Release │
 │ Context,    │ Resolvers,  │ Secret      │ Attack Paths,│ Repair,      │ Monitoring,  │ Gate,   │
 │ Squad,      │ Verification│ Protection, │ History,     │ Simulation,  │ ControlPlane,│ Score   │
 │ Aggregator  │ Sandbox     │ Policy      │ Drift, Graph │ PR Pipeline  │ Incident Resp│ Model   │
 └─────────────┴─────────────┴─────────────┴──────────────┴──────────────┴──────────────┴─────────┘
        │                            │                             │                    │
        ▼                            ▼                             ▼                    ▼
 ┌──────────────┐             ┌──────────────┐              ┌──────────────┐     ┌──────────────┐
 │ persistence  │             │ observability│              │  benchmark   │     │   facades    │
 │ State Store, │             │ Telemetry,   │              │ Evaluation,  │     │ Legacy API   │
 │ Registry     │             │ Report/ZIP   │              │ Fixtures     │     │ Wrappers     │
 └──────────────┘             └──────────────┘              └──────────────┘     └──────────────┘
```

---

## 📁 Repository Structure

```
SWE/
├── agentos_swe/                # Core Production Package (10 Domains)
│   ├── core/                   # Base data models, intake, context, investigation squad, aggregator
│   ├── analysis/               # Code graph provider, AST semantic resolvers, verification pipeline & sandbox
│   ├── security/               # Taint tracking engine, secret protection, command policy, resource limits
│   ├── intelligence/           # Priority engine (P0-P4), attack paths, historical scan store, drift, knowledge
│   ├── remediation/            # Remediation planner, repair pipeline, safe simulation engine, PR pipeline
│   ├── operations/             # Security decision orchestrator, continuous monitoring, control plane, incident
│   ├── persistence/            # Operational state store & repository registry
│   ├── observability/          # Real-time execution telemetry (events.py), trace collector, report exporter
│   ├── release/                # Enterprise release readiness engine & safety gates
│   ├── benchmark/              # Synthetic evaluation fixtures, resilience experiments & benchmark runner
│   ├── attackpath/             # Legacy compatibility facade wrapper
│   ├── history/                # Legacy compatibility facade wrapper
│   ├── drift/                  # Legacy compatibility facade wrapper
│   ├── learning/               # Legacy compatibility facade wrapper
│   ├── knowledge/              # Legacy compatibility facade wrapper
│   ├── repair/                 # Legacy compatibility facade wrapper
│   ├── pr/                     # Legacy compatibility facade wrapper
│   ├── monitoring/             # Legacy compatibility facade wrapper
│   ├── orchestration/          # Legacy compatibility facade wrapper
│   ├── controlplane/           # Legacy compatibility facade wrapper
│   ├── incident/               # Legacy compatibility facade wrapper
│   ├── simulation/             # Legacy compatibility facade wrapper
│   ├── correlation/            # Legacy compatibility facade wrapper
│   ├── graph/                  # Legacy compatibility facade wrapper
│   ├── semantic/               # Legacy compatibility facade wrapper
│   ├── verification/           # Legacy compatibility facade wrapper
│   └── ui.py                   # Single-File Streamlit UI Dashboard (Strict Invariant)
├── tests/
│   └── swe/                    # 9 Purpose-Organized Test Folders (670 Tests)
│       ├── unit/
│       ├── analysis/
│       ├── intelligence/
│       ├── remediation/
│       ├── operations/
│       ├── release/
│       ├── integration/
│       ├── real_world/
│       └── ui/
├── docs/                       # Structured Documentation
│   ├── architecture/
│   ├── history/
│   └── operations/
├── outputs/                    # Scan Outputs & Report Bundles (Gitignored)
│   └── scans/
└── checkpoints/                # Operational Pipeline Checkpoints
```

---

## ⚡ Installation

### Prerequisites
- **Python**: 3.11+
- **Git**: Installed and available on system `PATH`

### 1. Clone Repository & Setup Environment
```bash
git clone https://github.com/MujumdarSahil/Agent-OS-.git
cd Agent-OS-
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
pip install -e .
```

### 3. Verify Installation
```bash
pytest SWE/tests -v
```

---

## ⚙️ Configuration Reference

AgentOS-SWE behavior is controlled via environment variables and resource limits:

| Environment Variable | Default | Purpose & Safety Implications |
| :--- | :--- | :--- |
| `AGENTOS_SWE_DRY_RUN` | `1` | **Dry-Run Enforcement**: Prevents remote git pushes or PR creation POST requests. |
| `AGENTOS_MOCK_LLM` | `0` | **Mock LLM Mode**: Set to `1` to run offline without external API keys. |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Optional local Ollama LLM provider base URL. |
| `GITHUB_TOKEN` | `""` | Optional GitHub Personal Access Token (automatically redacted from logs). |

### Sandbox Resource Limits (`ResourceLimits`)
- **Execution Time**: `15.0s` maximum per subshell command execution.
- **Subshell Memory**: `512MB` maximum memory per sandbox process.
- **Output Size**: `1MB` maximum stdout/stderr output before truncation.
- **Network Policy**: `network_allowed = False` (Denies internet egress by default).

---

## 🚀 Running AgentOS-SWE

### Programmatic Scan Pipeline
```python
from agentos_swe.core.intake import RepositoryIntake
from agentos_swe.core.context import build_repository_context
from agentos_swe.observability.events import ExecutionEventBus, TerminalLogger
from agentos_swe.observability.report import generate_report_bundle
from agentos_swe.ui import run_swe_scan_engine

# 1. Attach Terminal Telemetry Logger
bus = ExecutionEventBus()
logger = TerminalLogger()
bus.subscribe(logger.handle_event)

# 2. Execute Full Security Scan Lifecycle
scan_results = run_swe_scan_engine(
    repo_input="https://github.com/example/target-repo.git",
    scan_type="Full Pipeline (M0-M30)",
    event_bus=bus,
)

# 3. Export 13-Artifact Report Bundle & ZIP Archive
report_info = generate_report_bundle(scan_results, output_root="outputs/scans")
print(f"Report Bundle Generated: {report_info['zip_path']}")
```

### Streamlit Dashboard Workflow
Launch the single-file UI dashboard:
```bash
streamlit run SWE/agentos_swe/ui.py
```

1. **Dashboard Launch**: Open browser at `http://localhost:8501`.
2. **Repository Entry**: Enter a local path (e.g. `C:\Projects\target-repo`) or GitHub URL.
3. **Trigger Scan**: Click **"Start AgentOS-SWE Scan"**.
4. **Live Visualization**: Watch real-time execution progress across the 19 pipeline stages.
5. **Explore Intelligence**: Navigate between 24 dedicated security pages (Code Graph, Taint Flow, Prioritization, Attack Paths, Remediation, Monitoring, Release Readiness).
6. **Download Bundle**: Download the complete report ZIP package directly from the dashboard sidebar.

---

## 🖥️ Real-Time Terminal Telemetry

During scan execution, real-time events stream to the terminal via `TerminalLogger`:

```text
Scanning target repository: C:\Projects\target-repo
        [23:08:50.199] [REPOSITORY INTAKE] ⚙ Starting stage: REPOSITORY INTAKE
        [23:08:50.269] [REPOSITORY INTAKE] ✓ Analyzed 86 files (0.07s)
        [23:08:50.269] [GRAPH BUILD] ⚙ Starting stage: GRAPH BUILD
        [23:08:50.492] [GRAPH BUILD] ✓ Nodes: 430, Edges: 3336 (0.22s)
        [23:08:50.492] [INVESTIGATION SQUAD] ⚙ Starting stage: INVESTIGATION SQUAD
        [23:08:53.673] [INVESTIGATION SQUAD] ✓ Discovered 18 candidate findings (3.18s)
        [23:08:53.674] [TAINT ANALYSIS] ⚙ Starting stage: TAINT ANALYSIS
        [23:08:54.052] [TAINT ANALYSIS] ✓ Paths: 0 (0.38s)
        [23:08:56.375] [VERIFICATION] ✓ Verified: 18 Confirmed, 0 Rejected (0.00s)
        [23:08:56.617] [SECURITY INTELLIGENCE] ✓ Prioritized 18 findings (Score: 10/100) (0.24s)
        [23:08:56.630] [ATTACK PATH] ✓ Correlated 14 attack paths (0.01s)
        [23:08:56.781] [DECISION ORCHESTRATION] ✓ Global Decision: INVESTIGATE (0.15s)
        [23:09:03.053] [REPAIR] ✓ Generated 18 repair proposals (6.27s)
        [23:09:03.590] [RELEASE READINESS] ✓ Level: REVIEW_REQUIRED, Score: 62.75/100 (0.05s)
        [23:09:03.903] [FINAL REPORT] ✓ Generated report bundle (JSON, MD, HTML, ZIP) (0.31s)

============================================================
FINAL SECURITY SUMMARY
============================================================
Files analyzed        : 86
Graph nodes           : 430
Graph edges           : 3336
Verified findings     : 18 (Confirmed: 18, Rejected: 0)
Attack paths          : 14
Security score        : 10 / 100
Risk trend            : RiskTrend.STABLE
Release readiness     : REVIEW_REQUIRED
FINAL VERDICT         : NEEDS INVESTIGATION
Total runtime         : 13.45s
============================================================
```

---

## 📦 13-Artifact Report Bundle & Downloads

AgentOS-SWE generates a comprehensive 13-artifact report package in every scan:

| Artifact File | Description & Contents |
| :--- | :--- |
| `executive_summary.md` | Non-technical summary with release verdict, security score, and key metrics. |
| `full_report.md` | Detailed technical report listing all verified findings, taint paths, and remediation plans. |
| `execution.json` | Complete scan metadata, agent timings, and stage durations. |
| `findings.json` | Raw candidate and confirmed findings with line numbers and code snippets. |
| `security.json` | Categorized security findings and severity metrics. |
| `attack_paths.json` | Synthesized attack surface paths, entrypoints, and trust boundary nodes. |
| `history.json` | Historical scan comparison, score deltas, and finding lifecycle status. |
| `drift.json` | Post-scan security drift metrics and regression indicators. |
| `intelligence.json` | Prioritized finding tiers (`P0`–`P4`), exploitability, and blast radius scores. |
| `incidents.json` | Correlated security incident timelines and anomaly clusters. |
| `release_readiness.json` | Quantitative release readiness evaluation, blockers table, and final verdict. |
| `execution_log.txt` | Complete stdout/stderr console log with timestamps. |
| `pipeline_timeline.json` | Microsecond-accurate stage timeline for performance analysis. |

All 13 artifacts are packaged into a single downloadable `agentos_swe_report.zip` archive.

---

## 🛡️ Safety & Governance Invariants

AgentOS-SWE enforces strict safety invariants across all execution modes:

1. **Target Repository Immutability**: The system **NEVER** mutates target repository files on disk during analysis, verification, or repair. All patch testing executes inside temporary `IsolatedSandbox` directories.
2. **Dry-Run Mode Enforcement**: `AGENTOS_SWE_DRY_RUN=1` is enabled by default. Git push operations and GitHub PR creation POST requests are disabled unless explicitly overridden.
3. **Automatic Secret Redaction**: API keys, Bearer tokens, private keys, and passwords are automatically scrubbed by `SecretProtection` before writing to disk, logs, or UI displays.
4. **Command Execution Policy**: Subshell commands inside sandboxes are checked against an explicit binary allowlist (`python`, `pytest`, `unittest`, `git`, `flake8`, `mypy`). Unauthorized binaries (`powershell`, `cmd.exe`, `curl`, `wget`) are rejected.
5. **Finite Scan Lifecycle**: Scans terminate cleanly upon completion (`IDLE` → `RUNNING` → `COMPLETE` → `STOP`). No auto-restarting background tasks or daemon processes remain active.

---

## 🧪 Testing & Quality Assurance

AgentOS-SWE includes a comprehensive, purpose-organized test suite:

```bash
# Run full pytest suite
pytest SWE/tests -v
```

- **Test Suite Status**: **670 Passed**, 0 Failed, 0 Skipped (at the time of R5 pass).
- **Test Execution Time**: `~52.0s`.
- **Coverage**: Covers all 10 domain packages, 16 compatibility facades, single-file UI dashboard, telemetry event bus, report generator, and real-world benchmark targets.

---

## 📊 Example Real-World Scan

Below are verified scan baseline metrics from a dry-run analysis on the real-world `Cadresec` repository:

- **Files Analyzed**: 86 Python modules
- **Code Graph Metrics**: 430 nodes, 3,336 edges
- **Raw Candidate Findings**: 18
- **Verified Confirmed Findings**: 18 (Medium: 10, Low: 8)
- **Correlated Attack Paths**: 14
- **Security Score**: `10 / 100` (Release Verdict: `REVIEW_REQUIRED`)
- **Total Pipeline Runtime**: `13.45s`

---

## 📂 Output Directory Structure

Scan outputs write strictly to gitignored `outputs/scans/` directories:

```text
outputs/
└── scans/
    └── Cadresec/
        └── 20260824_230903/
            ├── agentos_swe_report/
            │   ├── executive_summary.md
            │   ├── full_report.md
            │   ├── execution.json
            │   ├── findings.json
            │   ├── security.json
            │   ├── attack_paths.json
            │   ├── history.json
            │   ├── drift.json
            │   ├── intelligence.json
            │   ├── incidents.json
            │   ├── release_readiness.json
            │   ├── execution_log.txt
            │   └── pipeline_timeline.json
            └── agentos_swe_report.zip
```

---

## 📖 Documentation Index

- [Architecture & System Design](SWE/docs/architecture/agentos_swe_architecture.md) — Technical deep-dive into the 10-domain architecture, semantic resolvers, and taint tracking.
- [Milestone Evolution Index](SWE/docs/history/milestone_index.md) — Chronological history covering M0–M30 and R1–R5 passes.
- [Developer & Contributor Guide](SWE/docs/operations/development.md) — Guidelines for code placement, testing protocols, and architectural invariants.

---

## ❓ Troubleshooting Guide

### 1. `ModuleNotFoundError: No module named 'agentos_swe'`
- **Cause**: Python path missing repository root or `SWE` directory.
- **Fix**: Ensure you have installed the package in editable mode (`pip install -e .`) or add `SWE` to your `PYTHONPATH`:
  ```bash
  export PYTHONPATH=".:SWE:$PYTHONPATH"
  ```

### 2. Streamlit Warning: `Session state does not function when running a script without streamlit run`
- **Cause**: Running `ui.py` directly with `python` instead of Streamlit CLI.
- **Fix**: Launch the UI using Streamlit:
  ```bash
  streamlit run SWE/agentos_swe/ui.py
  ```

### 3. `Ollama is unreachable at OLLAMA_BASE_URL`
- **Cause**: Ollama service is not running locally.
- **Fix**: If you do not intend to use Ollama local LLMs, this warning can be safely ignored. AgentOS-SWE automatically falls back to LiteLLM or Mock LLM mode (`AGENTOS_MOCK_LLM=1`).

---

## 🤝 Development & Contributing

Contributions to AgentOS-SWE are welcome! Please review [SWE/docs/operations/development.md](SWE/docs/operations/development.md) before submitting code.

1. Preserve the **Single-File UI Invariant** (`SWE/agentos_swe/ui.py`).
2. Preserve **Legacy Compatibility Facades** (`agentos_swe.repair`, `attackpath`, etc.).
3. Ensure all tests pass (`pytest SWE/tests -v`).

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
