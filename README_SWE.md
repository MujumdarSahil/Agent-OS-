# AgentOS-SWE — Autonomous Software Verification and Repair System

**AgentOS-SWE** is an enterprise-grade autonomous software verification and repair system built on top of the **AgentOS** multi-agent AI framework foundation.

It provides end-to-end repository intelligence, multi-agent defect investigation, independent multi-strategy verification, controlled autonomous repair in isolated sandbox environments, risk governance, dry-run GitHub PR automation, telemetry event tracing, and scientific benchmark evaluation.

---

## 🏗️ End-to-End Architecture

```
Repository Intake (M1)
       ↓
Code Graph & Context Assembly (M1)
       ↓
AgentOS Multi-Agent Investigation Squad (M2)
  [BugAgent, SecurityAgent, PerformanceAgent, ArchitectureAgent]
       ↓
Finding Aggregation & Deduplication (M2)
       ↓
Independent Multi-Strategy Verification (M3)
  [Static Analysis + Code Graph Reachability + Subprocess Test Reproduction]
       ↓
Confirmed Finding Filter (M3/M4 Safety Gate)
       ↓
Impact Analysis & Fix Planning (M4)
       ↓
Controlled Autonomous Repair in Isolated Sandbox (M4)
       ↓
Reproduction & Regression Testing + Independent Code Review (M4)
       ↓
Risk Assessment & AgentOS Governance Engine Policy Check (M5)
       ↓
GitHub PR Automation with Token Redaction & Dry-Run Mode (M5)
       ↓
Observability Telemetry Tracing & Run Report (M7)
       ↓
Scientific Benchmark Suite & Ablation Evaluation (M8)
```

---

## 🚀 Quickstart Guide

### 1. Installation
Ensure Python 3.10+ is installed:
```bash
pip install -e .
```

### 2. Set Up Environment
Configure LLM credentials (or enable mock mode for testing):
```bash
export AGENTOS_MOCK_LLM=1
export GITHUB_TOKEN="ghp_your_github_token_here"
export AGENTOS_SWE_DRY_RUN=1  # Recommended default: no remote git pushes or PR POST requests
```

### 3. Programmatic Usage Example
```python
from agentos_swe import (
    RepositoryIntake,
    build_repository_context,
    InvestigationSquad,
    VerificationPipeline,
    RepairPipeline,
    PRPipeline,
    TraceCollector,
    ReportGenerator,
    FindingStatus,
)

# Step 1: Repository Intake & Context Building
repo_path = "/path/to/target/repository"
intake = RepositoryIntake()
intake_metadata = intake.analyze(repo_path)
context = build_repository_context(repo_path)

# Step 2: Investigation Squad
squad = InvestigationSquad()
candidate_findings = squad.analyze_repository(context)

# Step 3: Independent Verification
verif_pipeline = VerificationPipeline()
verified_findings = verif_pipeline.verify_findings(candidate_findings, context)

# Step 4: Controlled Autonomous Repair (Target repository remains 100% untouched)
repair_pipeline = RepairPipeline()
validated_patches = []

for finding in verified_findings:
    if finding.status == FindingStatus.CONFIRMED:
        patch = repair_pipeline.repair_finding(finding, context)
        if patch:
            validated_patches.append(patch)

# Step 5: Risk Governance & GitHub PR Automation (Dry-run mode by default)
pr_pipeline = PRPipeline(dry_run=True)
for patch in validated_patches:
    pr_result = pr_pipeline.execute_pr_pipeline(finding, patch, context)
    print(f"PR Result: Success={pr_result.success}, URL={pr_result.pr_url}, DryRun={pr_result.dry_run}")
```

---

## ⚙️ Configuration Reference

| Parameter | Environment Variable / Setting | Default | Description |
| :--- | :--- | :--- | :--- |
| **Mock LLM Mode** | `AGENTOS_MOCK_LLM` | `0` | Set `1` for deterministic un-credentialed LLM fallback verification |
| **Dry-Run Mode** | `AGENTOS_SWE_DRY_RUN` | `1` | Enforces dry-run mode (prevents remote git push and PR POST writes) |
| **GitHub Token** | `GITHUB_TOKEN` | `""` | GitHub personal access token (automatically redacted from logs/outputs) |
| **Max Sandbox Time** | `ResourceLimits.max_execution_time_sec` | `15.0s` | Maximum execution time allowed for sandbox subshell commands |
| **Max Memory** | `ResourceLimits.max_memory_mb` | `512MB` | Maximum memory limit per sandbox subshell process |
| **Max Output Size** | `ResourceLimits.max_output_size_bytes` | `1MB` | Maximum stdout/stderr output size before truncation |
| **Network Egress** | `ResourceLimits.network_allowed` | `False` | Network policy (denies external internet access by default) |

---

## 🛡️ Security Invariants & Redaction

1. **Original Repository Immutability**: All patch application and test reproduction commands execute strictly inside temporary `IsolatedSandbox` directories. The target repository remains 100% UNCHANGED.
2. **No Automatic Merge**: The system NEVER automatically merges pull requests. All PR descriptions feature prominent alerts requiring human review.
3. **Secret Redaction**: Environment API keys (`ghp_`, `Bearer`, `sk-`, passwords, tokens) are stripped from subshell processes and redacted from logs, stdout/stderr, prompts, and PR bodies.
4. **Command Execution Policy**: Commands are validated against an explicit allow list (`python`, `pytest`, `unittest`, `git`, `flake8`, `mypy`). Dangerous binaries (`powershell`, `cmd.exe`, `curl`, `wget`, `eval`) are blocked.

---

## 🚨 Failure Modes & Fallback Behavior

- **LLM Provider Failure**: AgentOS `LLMClient` automatically routes failed API requests to secondary providers (e.g. OpenAI → Anthropic → Ollama → Mock).
- **Process Timeout / Infinite Loop**: Sandbox subshell processes exceeding `max_execution_time_sec` are forcefully terminated (`proc.kill()`).
- **Interruption Recovery**: `VerificationPipeline`, `RepairPipeline`, and `PRPipeline` automatically save stage state via `SQLiteCheckpointStore`, allowing seamless recovery (`resume=True`).
- **Governance Denial**: High or Critical risk patches are denied or flagged for review by `GovernanceGate`, preventing unauthorized PR creation.

---

## 🔬 Benchmark Methodology (M8)

Scientific performance is evaluated using `BenchmarkRunner` on controlled ground truth target repositories:
- **Detection Metrics**: Precision, Recall, and F1-Score (Overall & per category: Bug, Security, Performance, Architecture).
- **Verification Accuracy**: Confusion matrix measuring true positive confirmations and false positive rejections.
- **Repair Effectiveness**: **Repair Success Rate** ($\frac{\text{Validated Patches}}{\text{Confirmed Findings}}$) and **Regression-Free Repair Rate**.
- **Ablation Matrix**: Evaluates multi-agent vs single-agent, squad + verification vs squad alone, and multi-provider fallback vs primary-only LLMs.

---

## 📋 Release Readiness Checklist

- [x] All 9 system modules (`models`, `graph`, `intake`, `context`, `agents`, `aggregator`, `squad`, `verification`, `repair`, `pr`, `security`, `observability`, `benchmark`) implemented on canonical `SWE` branch.
- [x] Complete test suite passing 63 out of 63 unit, integration, safety, fallback, checkpoint recovery, and benchmark tests.
- [x] Zero hardcoded secrets in source code or documentation.
- [x] Clean working directory on git branch `SWE`.
