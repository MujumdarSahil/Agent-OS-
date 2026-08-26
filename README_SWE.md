# AgentOS-SWE — Enterprise Autonomous Software Verification and Repair System

[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests: 670 Passed](https://img.shields.io/badge/tests-670%20passed-brightgreen.svg)](SWE/tests/)
[![Architecture: 10-Domain](https://img.shields.io/badge/architecture-10--domain-purple.svg)](SWE/docs/architecture/agentos_swe_architecture.md)
[![UI: Single-File](https://img.shields.io/badge/UI-single--file%20invariant-orange.svg)](SWE/agentos_swe/ui.py)

**AgentOS-SWE** is an enterprise-grade autonomous software verification, security intelligence, and automated repair platform built on the **AgentOS** multi-agent framework.

It provides a complete end-to-end security engineering lifecycle — automatically ingesting repositories, parsing AST code graphs, performing static AST-based pattern detection, prioritizing vulnerabilities, mapping attack surfaces, generating sandboxed patches, validating repairs, tracking security drift, and evaluating enterprise release readiness — all through a single 29-page Streamlit dashboard.

---

## 📋 Table of Contents

- [What Is AgentOS-SWE?](#-what-is-agentos-swe)
- [Who Is It For?](#-who-is-it-for)
- [End-to-End Security Lifecycle](#-end-to-end-security-lifecycle)
- [System Architecture](#️-system-architecture)
- [Repository Structure](#-repository-structure)
- [Installation](#-installation)
- [Configuration Reference](#️-configuration-reference)
- [Running AgentOS-SWE](#-running-agentos-swe)
- [Dashboard Pages](#-dashboard-pages-29-pages)
- [Real-Time Terminal Telemetry](#️-real-time-terminal-telemetry)
- [13-Artifact Report Bundle](#-13-artifact-report-bundle--downloads)
- [Safety & Governance Invariants](#️-safety--governance-invariants)
- [Known Limitations](#-known-limitations)
- [Screenshots & Demo](#-screenshots--demo)
- [Example Real-World Scan](#-example-real-world-scan-cadresec)
- [Output Directory Structure](#-output-directory-structure)
- [Testing & Quality Assurance](#-testing--quality-assurance)
- [Documentation Index](#-documentation-index)
- [Changelog](#-changelog)
- [Troubleshooting](#-troubleshooting)
- [Development & Contributing](#-development--contributing)
- [License](#-license)

---

## 💡 What Is AgentOS-SWE?

Traditional Static Application Security Testing (SAST) tools produce large volumes of unverified alerts with no contextual ranking or automated remediation path.

**AgentOS-SWE** bridges the gap between security discovery and software engineering. Rather than producing a flat list of potential issues, it runs a 13-stage security engineering lifecycle that:

- **Executes deterministic candidate discovery** via AST structure inspection and regex pattern scanning across specialized investigator agents.
- **Identifies dynamic subprocess execution** by detecting `shell=True` calls with non-constant command arguments (with documented one-hop literal constant scope).
- **Maps attack-path exposure** from source file locations across repository boundaries.
- **Quantifies risk** using a P0–P4 priority score based on severity, blast radius, and graph reachability.
- **Generates minimal defensive patches** and validates file persistence inside isolated subshell sandboxes.
- **Tracks security posture drift** across scan history.
- **Issues a release verdict** (`GO` / `REVIEW_REQUIRED` / `BLOCKED`) with a 0–100 score.

This makes AgentOS-SWE an **integrated security/software-engineering intelligence platform** — not merely a static scanner.

---

## 👥 Who Is It For?

| Persona | Primary Use |
| :--- | :--- |
| **Security Engineers** | Full vulnerability lifecycle: detect → investigate → remediate → validate |
| **Software Engineers** | Identify and fix code-quality and security defects with generated patches |
| **DevSecOps Leads** | Automated release-gate evaluation with quantitative release scores |
| **AI/ML Engineers** | Continuous security learning, knowledge graph, and trend analysis |
| **Technical Audit Teams** | 13-artifact report bundles with executive summaries and evidence chains |

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
┌──────────┐   ┌────────────┐   ┌───────────┐   ┌──────────┐   ┌──────────────────┐
│ 9. LEARN │──>│10. MONITOR │──>│11.OPERATE │──>│12.INCIDENT│──>│13.RELEASE READY  │
└──────────┘   └────────────┘   └───────────┘   └──────────┘   └──────────────────┘
```

| Stage | What Happens |
| :--- | :--- |
| **1. DETECT** | Ingests codebase, parses AST relationships (Python AST; JS/TS/React/Vue heuristics), deploys rule-based investigator agents |
| **2. UNDERSTAND** | Resolves polyglot semantic definitions (Python native AST; JS/TS/React/Vue regex heuristics), intentional try/except fallbacks, test harness functions |
| **3. CORRELATE** | Performs static pattern matching and AST node inspection for security defects |
| **4. PRIORITIZE** | Assigns objective P0–P4 risk scores based on internet exposure, exploitability, and blast radius |
| **5. ATTACK PATH** | Synthesizes entrypoints, trust boundaries, and authentication posture into multi-hop attack graphs |
| **6. DECIDE** | Evaluates policy rules (P01–P09) to select optimal remediation actions (REPAIR / INVESTIGATE / MONITOR / BLOCK) |
| **7. REPAIR** | Synthesizes minimal defensive patches inside isolated subshell sandboxes |
| **8. VALIDATE** | Executes sandboxed test reproduction runner — confirms source file presence on disk only; does not reproduce or execute the exploit (see Known Limitations). |
| **9. LEARN** | Records recurring vulnerability patterns in a local SQLite Security Knowledge Graph |
| **10. MONITOR** | Tracks post-scan security drift and posture changes across commits |
| **11. OPERATE** | Maintains control plane health, repository registries, and operational state |
| **12. INCIDENT RESPONSE** | Correlates active security anomalies into structured incident timelines |
| **13. RELEASE READINESS** | Computes release scores (0–100) and issues final GO / REVIEW_REQUIRED / BLOCKED verdicts |

---

## 🏗️ System Architecture

AgentOS-SWE is architected into **10 responsibility-driven domain packages** wrapped by lightweight backward-compatibility facades:

```
                              ┌────────────────────────────────┐
                              │       Streamlit Dashboard      │
                              │  SWE/agentos_swe/ui.py (1 file)│
                              └───────────────┬────────────────┘
                                              │
┌─────────────────────────────────────────────┴──────────────────────────────────────┐
│                           AgentOS-SWE 10-Domain Engine                             │
├──────────┬──────────┬──────────┬─────────────┬─────────────┬──────────┬───────────┤
│  core    │ analysis │ security │ intelligence │ remediation │operations│  release  │
├──────────┼──────────┼──────────┼─────────────┼─────────────┼──────────┼───────────┤
│ Intake   │ Graph    │ Taint    │ Priority     │ Planner     │Decision  │ Release   │
│ Context  │ AST      │ Secret   │ AttackPaths  │ Repair      │Monitoring│ Gates     │
│ Squad    │ Verif.   │ Policy   │ History      │ Simulation  │ControlPl.│ Score     │
│ Models   │ Sandbox  │ Limits   │ Drift, Know. │ PR Pipeline │ Incident │ Evidence  │
└──────────┴──────────┴──────────┴─────────────┴─────────────┴──────────┴───────────┘
      │                  │                  │                        │
      ▼                  ▼                  ▼                        ▼
┌──────────┐      ┌──────────────┐   ┌──────────────┐       ┌──────────────┐
│persistence│     │ observability│   │  benchmark   │       │  16 legacy   │
│ StateStore│     │ Events, Tracer│  │ Cadresec     │       │  compat.     │
│ Registry │      │ Reports, ZIP │   │ Fixtures     │       │  facades     │
└──────────┘      └──────────────┘   └──────────────┘       └──────────────┘
```

### Domain Responsibilities

| Domain | Purpose |
| :--- | :--- |
| `core` | Base data models, repository intake, context builder, investigation squad, finding aggregator |
| `analysis` | CPG code graph provider, polyglot AST semantic resolvers (Python/JS/TS/React/Vue), verification pipeline, isolated sandbox |
| `security` | AST-based subprocess pattern checker (with documented one-hop literal constant scope), secret protection, command policy, resource limits |
| `intelligence` | P0–P4 vulnerability priority engine, autonomous attack-path correlator, historical scan store, security drift, knowledge graph |
| `remediation` | Intelligent repair planner, sandboxed patch generation, security simulation engine, PR governance pipeline |
| `operations` | Security decision orchestrator, continuous monitoring scheduler, security operations control plane, incident response engine |
| `persistence` | Persistent operational state store and repository registry (SQLite-backed) |
| `observability` | Real-time execution event bus, terminal logger, trace collector, 13-artifact report generator and ZIP exporter |
| `release` | Enterprise release readiness engine, multi-gate evaluation, release score model (0–100), final verdict |
| `benchmark` | Synthetic evaluation fixtures, real-world Cadresec benchmark target, resilience experiments |

---

## 📁 Repository Structure

```
Agent-OS-/
├── README_SWE.md               ← This file
├── README.md                   ← AgentOS framework README
├── LICENSE                     ← MIT License
├── requirements.txt            ← Python dependencies
├── pyproject.toml              ← Build metadata & pytest config
├── .env.example                ← Environment variable template (no secrets)
├── .gitignore                  ← Git exclusions
│
├── SWE/                        ← AgentOS-SWE production package root
│   ├── agentos_swe/            ← Core production package (10 domains)
│   │   ├── core/               ← Models, intake, context, squad, aggregator
│   │   ├── analysis/           ← Graph, AST resolvers, verification, sandbox
│   │   ├── security/           ← Taint, secret protection, command policy, limits
│   │   ├── intelligence/       ← Prioritizer, attack paths, history, drift, knowledge
│   │   ├── remediation/        ← Planner, repair, simulation, PR pipeline
│   │   ├── operations/         ← Orchestrator, monitoring, control plane, incident
│   │   ├── persistence/        ← State store, repository registry
│   │   ├── observability/      ← Events, telemetry, report generator, ZIP
│   │   ├── release/            ← Release readiness engine, gates, evidence
│   │   ├── benchmark/          ← Benchmark fixtures, Cadresec target
│   │   │
│   │   │   # Legacy compatibility facades (backward-compatible re-exports)
│   │   ├── attackpath/         ← → intelligence.attackpath
│   │   ├── history/            ← → intelligence.history
│   │   ├── drift/              ← → intelligence.drift
│   │   ├── learning/           ← → intelligence.learning
│   │   ├── knowledge/          ← → intelligence.knowledge
│   │   ├── repair/             ← → remediation.repair
│   │   ├── pr/                 ← → remediation.pr
│   │   ├── monitoring/         ← → operations.monitoring
│   │   ├── orchestration/      ← → operations.orchestration
│   │   ├── controlplane/       ← → operations.controlplane
│   │   ├── incident/           ← → operations.incident
│   │   ├── simulation/         ← → remediation.simulation
│   │   ├── correlation/        ← → remediation.correlation
│   │   ├── graph/              ← → analysis.graph
│   │   ├── semantic/           ← → analysis.semantic
│   │   ├── verification/       ← → analysis.verification
│   │   └── ui.py               ← ★ Single-File Streamlit Dashboard (strict invariant)
│   │
│   ├── tests/
│   │   └── swe/                ← 670 tests across 9 purpose-organized folders
│   │       ├── unit/           ← Core models, intake, context, security hardening
│   │       ├── analysis/       ← Graph, semantic, pattern detection, verification
│   │       ├── intelligence/   ← Prioritizer, attack paths, history, knowledge
│   │       ├── remediation/    ← Repair, validation, simulation, PR automation
│   │       ├── operations/     ← Orchestration, monitoring, control plane
│   │       ├── release/        ← Release readiness, gates, evidence
│   │       ├── integration/    ← End-to-end pipeline integration
│   │       ├── real_world/     ← Cadresec real-world benchmark
│   │       └── ui/             ← Dashboard, telemetry, observability
│   │
│   └── docs/
│       ├── architecture/       ← Technical deep-dive: 10-domain design, AST parsing, pattern detection
│       ├── history/            ← Milestone evolution index (M0–M30, R1–R11)
│       └── operations/         ← Developer guide, contribution protocol
│
├── docs/                       ← Top-level community docs
│   ├── CHANGELOG.md
│   ├── CONTRIBUTING.md
│   └── SECURITY.md
│
└── outputs/                    ← Scan outputs (gitignored)
    └── scans/<repo>/<timestamp>/
```

---

## ⚡ Installation

### Prerequisites

- **Python**: 3.11 or higher
- **Git**: Installed and available on system `PATH`
- **pip**: Up to date (`pip install --upgrade pip`)

### 1. Clone the Repository

```bash
git clone https://github.com/MujumdarSahil/Agent-OS-.git
cd Agent-OS-
git checkout SWE
```

### 2. Create a Virtual Environment (Recommended)

```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux / macOS:
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
pip install -e .
```

### 4. Configure Environment Variables (Optional)

```bash
cp .env.example .env
# Edit .env — add LLM API keys if available.
# AgentOS-SWE works fully offline with AGENTOS_MOCK_LLM=1
```

### 5. Verify Installation

```bash
pytest SWE/tests -v
# Expected: 670 passed, 0 failed, 0 skipped
```

---

## ⚙️ Configuration Reference

All configuration is via **environment variables** — no files are required.

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `AGENTOS_SWE_DRY_RUN` | `1` | **Safety**: Prevents remote git pushes and GitHub PR POST requests. Set to `0` only in authorized live environments. |
| `AGENTOS_MOCK_LLM` | `0` | **Offline mode**: Set to `1` to run the full pipeline without any external API key. All LLM responses use a deterministic mock. |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Optional local [Ollama](https://ollama.com) LLM provider endpoint. |
| `OPENAI_API_KEY` | `""` | Optional OpenAI API key. Auto-detected; automatically redacted from all logs. |
| `ANTHROPIC_API_KEY` | `""` | Optional Anthropic Claude API key. Auto-redacted. |
| `GEMINI_API_KEY` | `""` | Optional Google Gemini API key. Auto-redacted. |
| `GITHUB_TOKEN` | `""` | Optional GitHub Personal Access Token for PR creation (dry-run blocked by default). Auto-redacted. |

### Sandbox Resource Limits (enforced by `ResourceLimits`)

| Limit | Value |
| :--- | :--- |
| Max execution time per command | `15.0 seconds` |
| Max sandbox memory | `512 MB` |
| Max stdout/stderr output | `1 MB` (truncated beyond this) |
| Network egress | `Denied by default` |

---

## 🚀 Running AgentOS-SWE

### Streamlit Dashboard (Primary Interface)

```bash
streamlit run SWE/agentos_swe/ui.py
```

Then open your browser at **http://localhost:8501**.

**Demo workflow:**

1. **Enter Repository** — type a local path (e.g. `C:\Projects\target`) or GitHub URL (e.g. `https://github.com/org/repo`)
2. **Select Scan Mode** — `Full Audit` | `Fast Security Audit` | `Deep Taint Analysis` | `Synthetic Benchmark`
3. **Click "🔍 START SWE SCAN"** — single click; scan will not auto-restart on Streamlit reruns
4. **Watch Live Pipeline** — 19 stages execute with real-time terminal telemetry and duration metrics
5. **Navigate 29 Pages** — explore Code Graph, Findings, Security Intelligence, Attack Paths, Remediation, Monitoring, Release Readiness, and more
6. **Download Report ZIP** — complete 13-artifact bundle available after scan completes

### Offline / CI Mode (No LLM Keys Required)

```bash
AGENTOS_SWE_DRY_RUN=1 AGENTOS_MOCK_LLM=1 streamlit run SWE/agentos_swe/ui.py
```

### Programmatic Usage

```python
import os
os.environ["AGENTOS_SWE_DRY_RUN"] = "1"
os.environ["AGENTOS_MOCK_LLM"] = "1"

from agentos_swe.core.intake import RepositoryIntake
from agentos_swe.core.context import build_repository_context
from agentos_swe.core.squad import InvestigationSquad
from agentos_swe.analysis.verification.pipeline import VerificationPipeline
from agentos_swe.observability.events import ExecutionEventBus

# Initialize telemetry
bus = ExecutionEventBus.reset_instance()

# Run core pipeline stages
intake = RepositoryIntake()
meta = intake.analyze("/path/to/target/repo")

ctx = build_repository_context("/path/to/target/repo")
squad = InvestigationSquad()
candidates = squad.analyze_repository(ctx)

verif = VerificationPipeline()
findings = verif.verify_findings(candidates, ctx, mission_id="my_scan")
print(f"Verified findings: {len(findings)}")
```

---

## 📺 Dashboard Pages (29 Pages)

| # | Page | What You See |
| :--- | :--- | :--- |
| 1 | Executive Overview | Final verdict banner, repository info, key metrics summary |
| 2 | Agent Activity | Status of all 11 analysis agents with runtime and finding counts |
| 3 | Code Graph | AST code graph nodes and edges, module relationships |
| 4 | Findings Explorer | All verified findings with evidence, severity, and code context |
| 5 | Security / Taint | Taint flow paths from source to sink, sanitizer status |
| 6 | Architecture | Module role classification and dependency mapping |
| 7 | Performance | Complexity analysis and N+1 loop detection |
| 8 | Verification | Multi-strategy independent verification results |
| 9 | Pipeline Timeline | Live 19-stage execution timeline with per-stage durations |
| 10 | Report & Download | Download 13-artifact report ZIP bundle |
| 11 | Safety Panel | Dry-run status, sandbox counters, secret protection indicators |
| 12 | Vulnerability Intelligence | Correlated findings with root cause chains and repair proposals |
| 13 | Security History | Historical scan comparison and risk trend over time |
| 14 | Security Intelligence | P0–P4 priority tiers, exploitability, blast radius, cross-repo patterns |
| 15 | Attack Paths | Multi-hop attack graph with entrypoints, trust boundaries, auth status |
| 16 | Remediation Center | Remediation plans, effort estimates, repair status |
| 17 | Security Monitoring | Regression detection, monitoring alerts, posture changes |
| 18 | Release Readiness | Security gates, blockers table, release score (0–100) |
| 19 | Security Engineering | Workflow state machine, decision orchestration results |
| 20 | Security Knowledge | Knowledge graph entries, recurrence patterns |
| 21 | Security Simulation | Sandboxed exploitability reproduction and repair differentials |
| 22 | Security Drift Monitoring | Baseline delta analysis, drift score, category |
| 23 | Security Decision Center | Global decision (REPAIR / INVESTIGATE / BLOCK), policy evaluation |
| 24 | Security Learning & Trends | Continuous learning metrics, recurrence analyzer output |
| 25 | Security Drift Center | Detailed drift breakdown, posture timeline |
| 26 | Security Operations Control Plane | Operational health, repository registry, control plane status |
| 27 | Continuous Security Monitoring | Monitoring scheduler status, alert categories |
| 28 | Security Incident Response | Active incidents, severity, timeline, resolution history |
| 29 | Enterprise Release Readiness | Full M30 release audit, mandatory gates, final enterprise verdict |

---

## 🖥️ Real-Time Terminal Telemetry

During scan execution, real-time events stream via `TerminalLogger` and are visible in both the terminal and the Streamlit dashboard (Page 9 — Pipeline Timeline):

```text
Scanning target repository: /path/to/target

        [23:08:50.199] [REPOSITORY INTAKE] ⚙ Starting stage: REPOSITORY INTAKE
        [23:08:50.269] [REPOSITORY INTAKE] ✓ Analyzed 86 files (0.07s)
        [23:08:50.269] [GRAPH BUILD] ⚙ Starting stage: GRAPH BUILD
        [23:08:50.492] [GRAPH BUILD] ✓ Nodes: 430, Edges: 3,336 (0.22s)
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
Graph edges           : 3,336
Verified findings     : 18 (Confirmed: 18, Rejected: 0)
Attack paths          : 14
Security score        : 10 / 100
Risk trend            : STABLE
Release readiness     : REVIEW_REQUIRED
FINAL VERDICT         : NEEDS INVESTIGATION
Total runtime         : 13.45s
============================================================
```

---

## 📦 13-Artifact Report Bundle & Downloads

Every scan generates a comprehensive 13-artifact report package:

| Artifact | Format | Description |
| :--- | :--- | :--- |
| `executive_summary.md` | Markdown | Non-technical summary: release verdict, security score, key metrics |
| `full_report.md` | Markdown | Full technical report: all verified findings, candidate evidence, remediation plans |
| `execution.json` | JSON | Complete scan metadata, agent timings, stage durations |
| `findings.json` | JSON | Candidate and confirmed findings with line numbers and code snippets |
| `security.json` | JSON | Security findings categorized by severity and vulnerability type |
| `attack_paths.json` | JSON | Attack surface paths, entrypoints, trust boundary nodes, auth status |
| `history.json` | JSON | Historical scan comparison, score deltas, finding lifecycle status |
| `drift.json` | JSON | Post-scan security drift metrics and regression indicators |
| `intelligence.json` | JSON | Prioritized finding tiers (P0–P4), exploitability, and blast radius |
| `incidents.json` | JSON | Correlated security incident timelines and anomaly clusters |
| `release_readiness.json` | JSON | Quantitative release readiness evaluation, blockers, and final verdict |
| `execution_log.txt` | Text | Complete console log with timestamps |
| `pipeline_timeline.json` | JSON | Microsecond-accurate stage timeline for performance analysis |

All 13 artifacts are packaged into a single downloadable `agentos_swe_report.zip` archive available from Page 10 of the dashboard.

---

## 🛡️ Safety & Governance Invariants

AgentOS-SWE enforces strict safety invariants **by design**:

> **Important distinction**: AgentOS-SWE is a *security analysis tool* — it identifies and helps remediate vulnerabilities in *other* codebases. The safety invariants below describe the guarantees AgentOS-SWE provides about its *own* behavior, not about the security of target repositories.

| Invariant | Mechanism | Behavior |
| :--- | :--- | :--- |
| **Target repository immutability** | `RepositoryIntake`, scan pipeline | Target repository files on disk are **never modified** during analysis, verification, or repair. All patch testing runs in temporary `IsolatedSandbox` directories. |
| **Dry-run enforcement** | `AGENTOS_SWE_DRY_RUN=1` (default) | Git push operations and GitHub PR creation POST requests are disabled unless explicitly overridden. |
| **Secret redaction** | `SecretProtection` | API keys, Bearer tokens, private keys, and passwords are automatically scrubbed before writing to disk, logs, or UI displays. |
| **Command execution policy** | `CommandPolicy` | Subshell commands are checked against an explicit binary allowlist (`python`, `pytest`, `git`, `flake8`, `mypy`). Unauthorized binaries (`powershell`, `cmd.exe`, `curl`, `wget`) are rejected. |
| **Network egress denial** | `ResourceLimits` | Sandbox subprocesses default to `network_allowed=False`. |
| **Finite scan lifecycle** | UI state machine | Scans terminate cleanly: `IDLE → RUNNING → COMPLETE → STOP`. No auto-restarting background tasks or daemon processes remain active after scan completion. |
| **No automatic commits/pushes** | Pipeline, UI | AgentOS-SWE never creates commits, pushes branches, or creates PRs without explicit human authorization. |
| **Explicit PR approval** | `GovernanceGate` | PR creation requires governance policy evaluation and approval before any remote write. |

---

## ⚠️ Known Limitations

The following documented limitations describe the exact current capabilities and verified boundary behaviors of AgentOS-SWE:

- **Detection is Rule-Based, Not LLM-Driven**: All candidate discovery across investigator agents relies on deterministic AST parsing and regex pattern matching. Zero LLM calls occur during candidate discovery across the 13 pipeline stages (0 active call sites for `query_llm_reasoning()`).
- **Non-Python Semantic Analysis Scope**: JS, TS, React, and Vue support in the polyglot semantic resolver uses regex-based heuristic pattern matching, not full AST parsing (unlike the Python resolver, which uses Python's native ast module). Detection precision and false-positive/negative rates for non-Python languages have not been tested to the same standard as the Python subprocess shell=True case documented above.
- **One-Hop Literal Heuristic (Taint Tracking Scope)**: Subprocess `shell=True` detection checks whether the command argument is an `ast.Constant` literal. It does not perform full inter-procedural data-flow tracking or recognize validation gates; sanitized dynamic values produce false positives identical to un-sanitized values (documented test case: `sanitized_but_dynamic.py`).
- **Sandbox Verification Scope**: The isolated sandbox test reproduction fixture confirms source file existence on disk (`os.path.exists`), not exploit execution or payload reproduction (`File presence check only — exploit not reproduced`).
- **Security Score Model**: The score displayed to users across the UI dashboard, report bundle (`security.json`, `executive_summary.md`), and release readiness evaluation is **currently authoritative** via `risk_reduction.py`'s `current_security_score` model (clamped floor of 10 for un-remediated high/critical findings). A separate linear deduction formula exists in `history/scoring.py` (`SecurityScorer`), but is **not** used for the displayed score — it is used internally by `HistoricalComparator` (`intelligence/history/comparator.py`) strictly for historical scan delta comparison and score trend analysis.

---

## 📸 Screenshots & Demo

> **Note**: Screenshots should be captured by running the dashboard against the built-in `Synthetic Benchmark` scan mode, which requires no external repository.

### Recommended Screenshots to Capture

To launch the dashboard for screenshot capture:

```bash
AGENTOS_SWE_DRY_RUN=1 AGENTOS_MOCK_LLM=1 streamlit run SWE/agentos_swe/ui.py
```

Then select **"Synthetic Benchmark"** as the Scan Mode and click **"🔍 START SWE SCAN"**.

| # | Page | What to Capture |
| :--- | :--- | :--- |
| 1 | **Executive Overview** (Page 1) | Final verdict banner, repository info card, metric columns |
| 2 | **Pipeline Timeline** (Page 9) | Live 19-stage execution with green checkmarks and timings |
| 3 | **Terminal Console** | Real-time terminal telemetry output with stage events |
| 4 | **Findings Explorer** (Page 4) | Finding cards with severity badges and code context |
| 5 | **Attack Paths** (Page 15) | Multi-hop attack graph visualization |
| 6 | **Security Decision Center** (Page 23) | Global decision banner and policy evaluation |
| 7 | **Security Drift Center** (Page 25) | Drift score and baseline delta chart |
| 8 | **Security Operations Control Plane** (Page 26) | Operational health dashboard |
| 9 | **Incident Response** (Page 28) | Active incident timeline |
| 10 | **Enterprise Release Readiness** (Page 29) | Release score gauge and gate evaluation table |
| 11 | **Report Download** (Page 10) | Report bundle structure and download button |

---

## 📊 Example Real-World Scan (Cadresec)

The Cadresec benchmark is an intentionally vulnerable Python application included in the benchmark suite. Below are verified scan baseline metrics from a dry-run analysis:

```bash
AGENTOS_SWE_DRY_RUN=1 AGENTOS_MOCK_LLM=1 streamlit run SWE/agentos_swe/ui.py
# Repository: SWE/agentos_swe/benchmark/cadresec
# Scan Mode: Full Audit
```

| Metric | Value |
| :--- | :--- |
| Files analyzed | 86 Python modules |
| Code graph nodes | 430 |
| Code graph edges | 3,336 |
| Raw candidate findings | 18 |
| Verified confirmed findings | 18 (Medium: 10, Low: 8) |
| Taint paths | 0 (Python AST pattern inspection) |
| Correlated attack paths | 14 |
| Security score | 10 / 100 |
| Release verdict | `REVIEW_REQUIRED` |
| Total pipeline runtime | ~13.5s |

> The Cadresec scan is fully reproducible and deterministic in `AGENTOS_MOCK_LLM=1` mode. The target repository is never modified.

---

## 📂 Output Directory Structure

Scan outputs are written to gitignored `outputs/scans/` directories:

```text
outputs/
└── scans/
    └── <repository-name>/
        └── <YYYYMMDD_HHMMSS>/
            ├── agentos_swe_report/
            │   ├── executive_summary.md      ← Executive summary (Markdown)
            │   ├── full_report.md            ← Full technical report (Markdown)
            │   ├── execution.json            ← Scan metadata and stage timings
            │   ├── findings.json             ← All findings with evidence
            │   ├── security.json             ← Security-specific metrics
            │   ├── attack_paths.json         ← Attack surface graph
            │   ├── history.json              ← Historical comparison
            │   ├── drift.json                ← Security drift metrics
            │   ├── intelligence.json         ← Prioritized findings (P0–P4)
            │   ├── incidents.json            ← Incident timelines
            │   ├── release_readiness.json    ← Release verdict and gates
            │   ├── execution_log.txt         ← Full console log
            │   └── pipeline_timeline.json    ← Stage-by-stage timeline
            └── agentos_swe_report.zip        ← Complete bundle (download from dashboard)
```

---

## 🧪 Testing & Quality Assurance

```bash
# Run the full test suite (expected: 670 passed, 0 failed, 0 skipped)
pytest SWE/tests -v

# Run only UI and telemetry tests
pytest SWE/tests/swe/ui -v

# Run only security hardening tests
pytest SWE/tests/swe/unit/test_security_hardening.py -v

# Collect tests without running
pytest SWE/tests --collect-only -q
```

**Current verified status** (as of R11):

| Metric | Value |
| :--- | :--- |
| Total tests | 670 |
| Passing | 670 (100%) |
| Failed | 0 |
| Skipped | 0 |
| Execution time | ~53s |

**Test coverage includes**:
- All 10 domain packages
- All 16 legacy compatibility facades
- Single-file Streamlit UI dashboard (state machine, scan lifecycle, reruns)
- Real-time telemetry event bus and terminal logger
- 13-artifact report generator and ZIP bundler
- Security hardening (command policy, secret protection, sandbox isolation)
- Real-world Cadresec benchmark target

---

## 📖 Documentation Index

| Document | Location | Description |
| :--- | :--- | :--- |
| Architecture & System Design | [SWE/docs/architecture/agentos_swe_architecture.md](SWE/docs/architecture/agentos_swe_architecture.md) | Technical deep-dive: 10-domain design, AST resolvers, pattern detection |
| Milestone Evolution Index | [SWE/docs/history/milestone_index.md](SWE/docs/history/milestone_index.md) | Chronological history: M0–M30 and R1–R11 |
| Developer & Contributor Guide | [SWE/docs/operations/development.md](SWE/docs/operations/development.md) | Code placement, testing protocols, architectural invariants |
| Changelog (SWE) | [CHANGELOG_SWE.md](CHANGELOG_SWE.md) | AgentOS-SWE release history |
| Contributing | [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) | Contribution guidelines |
| Security Policy | [docs/SECURITY.md](docs/SECURITY.md) | Responsible disclosure and security policy |

---

## 📋 Changelog

See [CHANGELOG_SWE.md](CHANGELOG_SWE.md) for the full AgentOS-SWE evolution from M0 through R11.

---

## ❓ Troubleshooting

### `ModuleNotFoundError: No module named 'agentos_swe'`

**Cause**: Python path missing the `SWE` directory.

**Fix**:
```bash
pip install -e .
# or explicitly:
export PYTHONPATH=".:SWE:$PYTHONPATH"   # Linux/macOS
$env:PYTHONPATH = ".;SWE;$env:PYTHONPATH"  # Windows PowerShell
```

### Streamlit Warning: `Session state does not function when running a script without streamlit run`

**Cause**: Running `ui.py` directly with `python` instead of Streamlit CLI.

**Fix**:
```bash
streamlit run SWE/agentos_swe/ui.py
```

### `Ollama is unreachable at OLLAMA_BASE_URL`

**Cause**: Ollama service is not running locally.

**Fix**: If you are not using Ollama, this warning is harmless. AgentOS-SWE automatically falls back to available LLM providers, or use `AGENTOS_MOCK_LLM=1` for fully offline execution.

### Scan starts automatically when I open the dashboard

**This should not happen.** The scan only starts when you explicitly click **"🔍 START SWE SCAN"**. Streamlit reruns (triggered by page navigation or widget interaction) do not restart a completed or in-progress scan. If you observe a scan auto-starting, please open an issue with the browser console log.

---

## 🤝 Development & Contributing

See [SWE/docs/operations/development.md](SWE/docs/operations/development.md) for the full contributor guide.

**Core invariants to preserve:**

1. **Single-File UI Invariant** — All Streamlit UI code must remain in `SWE/agentos_swe/ui.py`. Do not create `pages/`, `components/`, or additional UI files.
2. **Legacy Compatibility Facades** — The 16 legacy facade packages (`agentos_swe.repair`, `.attackpath`, etc.) must remain importable. Do not delete them.
3. **Test Suite** — All 670 tests must pass before merging. Add tests for new functionality.
4. **No Production Code in Audits** — Read-only audit passes (R-passes) must not modify production modules.
5. **Security Invariants** — `AGENTOS_SWE_DRY_RUN=1` must remain the default. Never weaken safety controls.

**Contribution workflow:**
```bash
git checkout -b feature/your-feature
# make changes
pytest SWE/tests -v          # all 670 tests must pass
git add .
git commit -m "feat(domain): description"
# open pull request against SWE branch
```

---

## 📄 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

*AgentOS-SWE — Autonomous Security Intelligence. Engineering Quality. Enterprise Readiness.*

