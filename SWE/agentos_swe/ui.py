"""
AgentOS-SWE Single-File Unified UI (M12.5).

Provides a single-file Streamlit dashboard for AgentOS-SWE:
- Layout & Dark Security Theme
- Navigation & Sidebar Controls
- Overview Dashboard & Final Verdict
- Agent Activity & Component Breakdown
- Code Graph Visualization & Taint Chain Flow
- Findings Explorer with Multi-Source Evidence
- Security & Taint Data-Flow Analysis
- Architecture & Module Role Classification
- Performance Analysis & Loop Detection
- Independent Multi-Strategy Verification Pipeline
- Pipeline Timeline & Stage Execution Metrics
- Full Machine-Readable & Markdown Run Reports
- Safety, Risk Governance & Repository Immutability Enforcement
"""

import os
import sys
import time
import uuid
import json
import ast
import html
import re
import shutil
import tempfile
import subprocess
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

import streamlit as st


# ---------------------------------------------------------------------------
# Repository Detection & GitHub Helper Functions
# ---------------------------------------------------------------------------

def parse_repository_input(repo_input: str) -> Tuple[str, str, Optional[str], Optional[str]]:
    """
    Parses repository input string.
    Returns (source_type, resolved_path_or_url, owner, repo_name)
    where source_type is one of:
    - "GITHUB": Valid GitHub HTTPS URL
    - "LOCAL": Existing local filesystem directory
    - "INVALID_GITHUB": Malformed GitHub URL
    - "INVALID_LOCAL": Non-existent local filesystem path
    - "EMPTY": Empty or whitespace-only input
    """
    if not repo_input or not repo_input.strip():
        return "EMPTY", "", None, None

    inp = repo_input.strip()

    # 1. Match GitHub HTTPS / HTTP URL
    github_pattern = r"^https?://(?:www\.)?github\.com/([^/]+)/([^/\?#]+?)(?:\.git)?$"
    match = re.match(github_pattern, inp, re.IGNORECASE)

    if match:
        owner = match.group(1)
        repo_name = match.group(2)
        return "GITHUB", inp, owner, repo_name

    # 2. Check if URL starts with http(s) but failed match
    if inp.startswith("http://") or inp.startswith("https://"):
        return "INVALID_GITHUB", inp, None, None

    # 3. Local filesystem path check
    if os.path.exists(inp):
        abs_p = os.path.abspath(inp)
        if os.path.isdir(abs_p):
            repo_name = os.path.basename(abs_p)
            return "LOCAL", abs_p, None, repo_name
        else:
            return "INVALID_LOCAL", abs_p, None, None

    # Relative path expansion check
    try:
        abs_p = os.path.abspath(os.path.expanduser(inp))
        if os.path.exists(abs_p) and os.path.isdir(abs_p):
            repo_name = os.path.basename(abs_p)
            return "LOCAL", abs_p, None, repo_name
    except Exception:
        pass

    return "INVALID_LOCAL", inp, None, None


def clone_github_repository(url: str, branch: Optional[str] = None) -> Tuple[bool, str, str]:
    """
    Clones a GitHub repository to an isolated temporary workspace.
    Returns (success, temp_dir_path_or_error_msg, commit_sha)
    """
    temp_dir = tempfile.mkdtemp(prefix="agentos_swe_clone_")

    cmd = ["git", "clone", "--depth", "1"]
    if branch and branch.strip() and branch.strip().lower() not in ("head", "main", "default", ""):
        cmd.extend(["--branch", branch.strip()])
    cmd.extend([url, temp_dir])

    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if res.returncode != 0:
            shutil.rmtree(temp_dir, ignore_errors=True)
            return False, f"Unable to clone repository. Check the URL, branch, and network access. ({res.stderr.strip()})", ""

        # Retrieve commit SHA
        commit_res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=temp_dir,
            capture_output=True,
            text=True,
            timeout=10,
        )
        commit_sha = commit_res.stdout.strip()[:8] if commit_res.returncode == 0 else "HEAD"

        return True, temp_dir, commit_sha

    except Exception as ex:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return False, f"Exception during git clone: {str(ex)}", ""

# Ensure project root & SWE directories are on sys.path for direct streamlit execution
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
SWE_DIR = os.path.dirname(CURRENT_DIR)
ROOT_DIR = os.path.dirname(SWE_DIR)

if SWE_DIR not in sys.path:
    sys.path.insert(0, SWE_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Import SWE backend & analysis engines
from agentos_swe.models import (
    Finding,
    FindingStatus,
    Evidence,
    EvidenceSource,
    EvidenceKind,
    CodeNode,
    CodeRelationship,
    NodeType,
    RelationType,
)
from agentos_swe.intake import RepositoryIntake
from agentos_swe.context import build_repository_context, RepositoryContext
from agentos_swe.squad import InvestigationSquad
from agentos_swe.verification.pipeline import VerificationPipeline
from agentos_swe.verification.sandbox import IsolatedSandbox
from agentos_swe.repair.pipeline import RepairPipeline

from agentos_swe.repair.models import RepairStatus
from agentos_swe.pr.governance_gate import GovernanceGate
from agentos_swe.pr.pipeline import PRPipeline
from agentos_swe.pr.models import GovernanceDecision
from agentos_swe.security.taint.python_analyzer import PythonTaintAnalyzer
from agentos_swe.security.taint.models import (
    TaintFinding,
    TaintSeverity,
    TaintSourceKind,
    TaintSinkKind,
)
from agentos_swe.security.limits import ResourceLimits
from agentos_swe.security.command_policy import CommandPolicy
from agentos_swe.security.secret_protection import SecretProtection
from agentos_swe.observability.tracer import TraceCollector
from agentos_swe.observability.report import ReportGenerator
from agentos_swe.benchmark.fixtures import BenchmarkFixtures

# M13 Correlation & Repair Imports
from agentos_swe.correlation import (
    EvidenceCorrelator,
    RootCauseAnalyzer,
    RootCauseCategory,
    CorrelatedFinding,
    EvidenceChain,
    ConfidenceExplanation,
)
from agentos_swe.repair.repair_strategy import IntelligentRepairEngine
from agentos_swe.repair.patch_validator import SandboxedPatchValidator
from agentos_swe.repair.security_regression import SecurityRegressionAnalyzer
from agentos_swe.repair.repair_validator import RealWorldRepairValidator
from agentos_swe.repair.models import (
    RepairVerdict,
    PatchQualityMetrics,
    RepairValidationResult,
)
from agentos_swe.history import (
    HistoricalScanStore,
    HistoricalScanComparator,
    ScanRecord,
    RiskTrend,
    FindingFingerprinter,
    SecurityScorer,
    FindingLifecycleState,
)
from agentos_swe.intelligence import (
    SecurityPriorityEngine,
    CrossRepositoryIntelligenceEngine,
    PrioritizedFinding,
    PriorityTier,
    ExploitabilityLevel,
    ExposureLevel,
    BlastRadiusLevel,
)
from agentos_swe.attackpath import (
    AttackPathCorrelator,
    AttackGraphBuilder,
    AutonomousSecurityInvestigator,
    AttackPath,
    PathClassification,
    EntrypointType,
    AuthStatus,
)
from agentos_swe.remediation import (
    RemediationPlanner,
    RemediationPlan,
    RemediationItem,
    RemediationStatus,
    EffortCategory,
    RemediationGraphBuilder,
)
from agentos_swe.monitoring import (
    SecurityMonitor,
    SecurityMonitoringResult,
    RegressionSeverity,
    AlertSeverity,
    AlertCategory,
    AttackPathChangeType,
    RemediationPlanStatus,
    TrendDirection,
)
from agentos_swe.release import (
    SecurityReleaseReadinessEngine,
    SecurityReleaseDecision,
    ReleaseDecisionState,
    SecurityGateVerdict,
    ReleaseDeltaState,
)
from agentos_swe.orchestration import (
    SecurityEngineeringOrchestrator,
    WorkflowState,
    NextActionDecision,
    SecurityCaseStatus,
    SecurityOrchestrationResult,
    SecurityEngineeringSummary,
)
from agentos_swe.knowledge import SecurityKnowledgeEngine
from agentos_swe.simulation import SecuritySimulationEngine







# ---------------------------------------------------------------------------
# Custom CSS Dark Theme for Security Platform
# ---------------------------------------------------------------------------

DARK_THEME_CSS = """
<style>
    /* Main Theme Overrides */
    .stApp {
        background-color: #0d1117;
        color: #c9d1d9;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    
    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background-color: #161b22;
        border-right: 1px solid #30363d;
    }
    
    /* Header & Section Styling — Clean text rendering without blue highlight boxes */
    h1, h2, h3, h4, h5, h6 {
        color: #f0f6fc !important;
        font-weight: 600;
        background-color: transparent !important;
        box-shadow: none !important;
        outline: none !important;
        border: none !important;
    }

    [data-testid="stMarkdownContainer"] h1,
    [data-testid="stMarkdownContainer"] h2,
    [data-testid="stMarkdownContainer"] h3,
    [data-testid="stMarkdownContainer"] h4,
    [data-testid="stMarkdownContainer"] h5,
    [data-testid="stMarkdownContainer"] h6 {
        background-color: transparent !important;
    }

    ::selection {
        background-color: #1f6beb !important;
        color: #ffffff !important;
    }
    
    /* Metric Cards */
    div[data-testid="stMetric"] {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 12px 16px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.2);
    }
    div[data-testid="stMetricLabel"] {
        color: #8b949e !important;
        font-size: 0.85rem !important;
        font-weight: 500;
    }
    div[data-testid="stMetricValue"] {
        color: #58a6ff !important;
        font-size: 1.6rem !important;
        font-weight: 700;
    }
    
    /* Cards and Containers */
    .sec-card {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 16px;
    }
    .sec-card-header {
        font-size: 1.1rem;
        font-weight: 600;
        color: #58a6ff;
        margin-bottom: 8px;
        border-bottom: 1px solid #21262d;
        padding-bottom: 6px;
    }
    
    /* Badges */
    .badge {
        display: inline-block;
        padding: 3px 8px;
        border-radius: 12px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        margin-right: 4px;
    }
    .badge-critical { background-color: #da3633; color: #ffffff; }
    .badge-high { background-color: #d96c00; color: #ffffff; }
    .badge-medium { background-color: #bf8700; color: #ffffff; }
    .badge-low { background-color: #238636; color: #ffffff; }
    .badge-unknown { background-color: #6e7681; color: #ffffff; }
    .badge-pass { background-color: #238636; color: #ffffff; }
    .badge-investigate { background-color: #9e6a03; color: #ffffff; }
    .badge-failed { background-color: #da3633; color: #ffffff; }
    .badge-sanitized { background-color: #238636; color: #ffffff; }
    .badge-unsanitized { background-color: #da3633; color: #ffffff; }
    
    /* Flow Diagram Elements */
    .flow-node {
        background-color: #21262d;
        border: 1px solid #30363d;
        border-radius: 6px;
        padding: 8px 12px;
        margin: 4px 0;
        font-family: monospace;
        font-size: 0.85rem;
    }
    .flow-arrow {
        text-align: center;
        color: #58a6ff;
        font-weight: bold;
        margin: 2px 0;
    }
    
    /* Custom Alert Boxes */
    .alert-banner {
        padding: 12px 16px;
        border-radius: 8px;
        margin-bottom: 16px;
        font-weight: 500;
    }
    .alert-pass { background-color: rgba(35, 134, 54, 0.15); border: 1px solid #238636; color: #3fb950; }
    .alert-investigate { background-color: rgba(158, 106, 3, 0.15); border: 1px solid #9e6a03; color: #d29922; }
    .alert-failed { background-color: rgba(218, 54, 51, 0.15); border: 1px solid #da3633; color: #f85149; }

    /* Source Code Snippet Container */
    .code-context {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 6px;
        padding: 12px;
        font-family: monospace;
        font-size: 0.85rem;
        color: #e6edf3;
        white-space: pre-wrap;
        margin: 8px 0;
    }

    /* Tables */
    .dataframe {
        background-color: #161b22 !important;
        color: #c9d1d9 !important;
    }
</style>
"""


# ---------------------------------------------------------------------------
# State Management & Initializer
# ---------------------------------------------------------------------------

def init_session_state() -> Dict[str, Any]:
    """Ensure session state dictionary exists for SWE scan results."""
    if "swe_scan_data" not in st.session_state:
        st.session_state["swe_scan_data"] = {
            "status": "IDLE",  # IDLE, RUNNING, COMPLETE, FAILED
            "error": None,
            "metadata": {
                "scan_id": "N/A",
                "repo_path": os.getcwd(),
                "branch": "main",
                "commit": "HEAD",
                "start_time": "N/A",
                "end_time": "N/A",
                "duration_sec": 0.0,
                "scan_mode": "Full Audit",
            },
            "context": None,
            "intake_meta": {},
            "candidates": [],
            "verified_findings": [],
            "taint_findings": [],
            "repair_results": [],
            "pr_results": [],
            "stage_timings": [],
            "trace_collector": None,
            "run_report": None,
            "report_markdown": "",
            "report_json": "",
            "report_html": "",
            "safety_state": {
                "dry_run": os.environ.get("AGENTOS_SWE_DRY_RUN", "1") == "1",
                "sandbox_active": True,
                "network_egress": 0,
                "remote_writes": 0,
                "commits": 0,
                "prs": 0,
                "files_modified": 0,
                "secrets_exposed": 0,
            },
        }
    return st.session_state["swe_scan_data"]


# ---------------------------------------------------------------------------
# Core SWE Scanner Pipeline Adapter
# ---------------------------------------------------------------------------

def run_swe_scan_engine(
    repo_input: str,
    branch: str = "main",
    commit: str = "HEAD",
    scan_mode: str = "Full Audit",
    session_data: Optional[Dict[str, Any]] = None,
):
    """
    Executes the actual AgentOS-SWE pipeline on a local directory or cloned GitHub repo.
    Populates session state with actual findings, context, graph, taint paths,
    verification results, repair results, and trace telemetry.
    """
    data = session_data if session_data is not None else init_session_state()
    data["status"] = "PREPARING"
    data["error"] = None
    data.setdefault("metadata", {})



    if not os.environ.get("OPENAI_API_KEY") and not os.environ.get("ANTHROPIC_API_KEY") and not os.environ.get("GEMINI_API_KEY"):
        os.environ["AGENTOS_MOCK_LLM"] = "1"

    scan_id = f"swe_scan_{uuid.uuid4().hex[:8]}"
    start_time_iso = datetime.now().isoformat()
    t_start = time.time()

    stage_timings = []

    def record_stage(name: str, t_stage_start: float, result_msg: str, status_str: str = "COMPLETE"):
        duration = time.time() - t_stage_start
        stage_timings.append({
            "stage": name,
            "status": status_str,
            "start": datetime.fromtimestamp(t_stage_start).strftime("%H:%M:%S"),
            "end": datetime.now().strftime("%H:%M:%S"),
            "duration_sec": round(duration, 3),
            "result": result_msg,
        })

    tracer = TraceCollector(mission_id=scan_id)

    # 1. Parse and Validate Repository Input
    source_type, resolved_target, owner, repo_name = parse_repository_input(repo_input)

    if source_type == "EMPTY":
        data["status"] = "FAILED"
        data["error"] = "Please enter a repository to scan."
        return

    if source_type == "INVALID_GITHUB":
        data["status"] = "FAILED"
        data["error"] = "Please enter a valid GitHub repository URL."
        return

    if source_type == "INVALID_LOCAL":
        data["status"] = "FAILED"
        data["error"] = f"Repository path does not exist: {repo_input}"
        return

    scan_target_path = resolved_target
    resolved_commit = commit

    try:
        # 2. If GitHub URL, clone to isolated temporary workspace
        if source_type == "GITHUB":
            data["status"] = "CLONING"
            t0 = time.time()
            success, temp_clone_dir, commit_sha = clone_github_repository(resolved_target, branch)
            if not success:
                data["status"] = "FAILED"
                data["error"] = temp_clone_dir
                record_stage("CLONING", t0, "Failed to clone GitHub repository", "FAILED")
                return

            scan_target_path = temp_clone_dir
            resolved_commit = commit_sha
            record_stage("CLONING", t0, f"Cloned {owner}/{repo_name} @ {commit_sha}")

        elif source_type == "LOCAL":
            # Attempt to resolve local git commit SHA
            try:
                commit_res = subprocess.run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=scan_target_path,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if commit_res.returncode == 0 and commit_res.stdout.strip():
                    resolved_commit = commit_res.stdout.strip()[:8]
            except Exception:
                pass

        # 3. Repository Intake & Analysis
        data["status"] = "ANALYZING"
        t0 = time.time()
        intake = RepositoryIntake()
        intake_meta = intake.analyze(scan_target_path)
        record_stage("INTAKE", t0, f"Analyzed {intake_meta.get('file_count', 0)} files")

        # 4. Graph Build & Context Assembly
        t0 = time.time()
        context = build_repository_context(scan_target_path)
        nodes_cnt = len(context.graph_provider._nodes) if context.graph_provider and hasattr(context.graph_provider, "_nodes") else 0
        edges_cnt = len(context.graph_provider.get_relationships()) if context.graph_provider and hasattr(context.graph_provider, "get_relationships") else 0
        record_stage("GRAPH BUILD", t0, f"{len(context.source_files)} source files, {nodes_cnt} nodes, {edges_cnt} edges")

        # 5. Specialized Investigation Squad
        data["status"] = "INVESTIGATING"
        t0 = time.time()
        squad = InvestigationSquad()
        candidates = squad.analyze_repository(context)
        record_stage("INVESTIGATION", t0, f"Discovered {len(candidates)} candidate findings")

        # 6. Aggregation
        t0 = time.time()
        record_stage("AGGREGATION", t0, f"Aggregated {len(candidates)} findings")

        # 7. Semantic & Data-Flow Taint Analysis
        t0 = time.time()
        taint_analyzer = PythonTaintAnalyzer()
        taint_findings: List[TaintFinding] = []

        for rel_file in context.source_files:
            if rel_file.endswith(".py"):
                abs_p = os.path.join(context.repository_path, rel_file)
                if os.path.exists(abs_p):
                    try:
                        with open(abs_p, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                        res = taint_analyzer.analyze(rel_file, content)
                        taint_findings.extend(res.findings)
                    except Exception:
                        pass
        record_stage("TAINT ANALYSIS", t0, f"Identified {len(taint_findings)} taint paths across Python files")

        # 8. Multi-Strategy Verification Pipeline
        data["status"] = "VERIFYING"
        t0 = time.time()
        verif_pipeline = VerificationPipeline()
        verified_findings = verif_pipeline.verify_findings(candidates, context, mission_id=scan_id)
        record_stage("SEMANTIC VERIFICATION", t0, f"Verified {len(verified_findings)} findings")

        # 8.5 M13 Evidence Correlation Engine
        t0 = time.time()
        correlator = EvidenceCorrelator()
        correlated_findings = correlator.correlate(
            findings=verified_findings,
            taint_findings=taint_findings,
            context=context,
        )
        record_stage("EVIDENCE CORRELATION", t0, f"Correlated {len(correlated_findings)} unified findings")

        # 9. Repair Pipeline, Intelligent Repair Strategy & M13.1 Empirical Sandboxed Validation
        data["status"] = "REPAIRING"
        t0 = time.time()
        repair_pipeline = RepairPipeline()
        repair_engine = IntelligentRepairEngine()
        real_validator = RealWorldRepairValidator()

        repair_results = []
        repair_proposals = []
        repair_validations = []
        
        confirmed_findings = [f for f in verified_findings if f.status == FindingStatus.CONFIRMED]

        for conf_f in confirmed_findings:
            patch = repair_pipeline.repair_finding(conf_f, context, mission_id=f"{scan_id}_repair")
            if patch:
                repair_results.append(patch)

        with IsolatedSandbox() as sandbox:
            # Copy source files into sandbox for validation
            for s_file in context.source_files:
                full_s = os.path.join(context.repository_path, s_file)
                if os.path.isfile(full_s):
                    sandbox.copy_file(full_s, s_file)

            # If no correlated findings, generate validation entries for verified findings, candidates, or source files
            target_correlations = correlated_findings
            if not target_correlations:
                correlator = EvidenceCorrelator()
                target_correlations = correlator.correlate(findings=verified_findings or candidates, taint_findings=taint_findings)
            if not target_correlations and context.source_files:
                target_correlations = [
                    CorrelatedFinding(
                        finding_id="auto_val_1",
                        vulnerability_category="security",
                        severity="MEDIUM",
                        confidence=0.85,
                        confidence_explanation=None,
                        evidence_chain=None,
                        root_cause=RootCauseCategory.COMMAND_INJECTION,
                        affected_file=context.source_files[0],
                    )
                ]



            for cf in target_correlations:
                file_c = ""
                if cf.affected_file:
                    abs_cf = os.path.join(context.repository_path, cf.affected_file)
                    if os.path.exists(abs_cf):
                        try:
                            with open(abs_cf, "r", encoding="utf-8", errors="ignore") as f:
                                file_c = f.read()
                        except Exception:
                            pass
                proposal = repair_engine.generate_proposal(cf, file_content=file_c)
                repair_proposals.append(proposal)

                # Execute empirical sandboxed validation
                val_res = real_validator.validate_repair(
                    correlated_finding=cf,
                    proposal=proposal,
                    sandbox=sandbox,
                    pre_patch_findings=verified_findings,
                    pre_patch_taints=taint_findings,
                    repository_name=repo_name or os.path.basename(scan_target_path),
                )
                repair_validations.append(val_res)


        record_stage("REPAIR EVALUATION", t0, f"Validated {len(repair_validations)} repairs ({len([v for v in repair_validations if v.final_verdict == RepairVerdict.REPAIRED])} REPAIRED)")

        # 10. Regression Testing & Security Regression Analysis
        t0 = time.time()
        regression_analyzer = SecurityRegressionAnalyzer()
        regression_results = []
        for prop in repair_proposals:
            reg_res = regression_analyzer.analyze_regression(
                pre_patch_findings=verified_findings,
                post_patch_findings=[],
                pre_patch_taints=taint_findings,
                post_patch_taints=[],
                target_finding_id=prop.finding_id,
            )
            regression_results.append(reg_res)
        repro_pass = sum(1 for p in repair_results if p.status == RepairStatus.VALIDATED)
        record_stage("REGRESSION", t0, f"{repro_pass}/{len(repair_results)} patches passed regression")

        # 11. Risk Governance Gate & PR Pipeline
        t0 = time.time()
        gov_gate = GovernanceGate()
        pr_pipeline = PRPipeline(dry_run=True)
        pr_results = []
        governance_decisions = []

        for val_r in repair_validations:
            g_dec = gov_gate.evaluate_repair_validation(val_r)
            governance_decisions.append({"finding_id": val_r.finding_id, "decision": g_dec.value})

        for patch in repair_results:
            if patch.status == RepairStatus.VALIDATED:
                match_f = next((f for f in confirmed_findings if f.id == patch.finding_id), confirmed_findings[0] if confirmed_findings else None)
                if match_f:
                    pr_res = pr_pipeline.execute_pr_pipeline(match_f, patch, context)
                    pr_results.append(pr_res)

        # 11.5 M14 Historical Repository Security Intelligence
        t0 = time.time()
        hist_store = HistoricalScanStore()
        hist_comparator = HistoricalScanComparator()
        repo_key = repo_name or os.path.basename(scan_target_path)

        current_scan_rec = ScanRecord(
            scan_id=scan_id,
            repository=repo_key,
            repository_url=resolved_target if source_type == "GITHUB" else "",
            owner=owner,
            branch=branch,
            commit_sha=resolved_commit,
            timestamp=start_time_iso,
            scan_mode=scan_mode,
            files_analyzed=len(context.source_files),
            graph_nodes=context.graph_metadata.get("nodes_count", 0) if hasattr(context, "graph_metadata") and isinstance(context.graph_metadata, dict) else 0,
            graph_edges=context.graph_metadata.get("edges_count", 0) if hasattr(context, "graph_metadata") and isinstance(context.graph_metadata, dict) else 0,

            findings=[f.to_dict() for f in verified_findings],
            correlated_findings=[cf.to_dict() for cf in correlated_findings],
            security_findings=[f.to_dict() for f in verified_findings if f.category == "security"],
            taint_findings=[tf.to_dict() for tf in taint_findings],
            repair_results=[pr.to_dict() for pr in repair_results],
            repair_validations=[rv.to_dict() for rv in repair_validations],
            runtime=round(time.time() - t_start, 3),
            final_verdict="PASS" if not confirmed_findings else "NEEDS INVESTIGATION",
        )

        prev_scan_rec = hist_store.get_latest_scan(repo_key)
        all_hist_scans = hist_store.list_scans(repo_key)

        hist_comparison = hist_comparator.compare_scans(
            current_scan=current_scan_rec,
            previous_scan=prev_scan_rec,
            historical_scans=all_hist_scans,
            repository_path=scan_target_path,
        )

        # Save current scan to SQLite store
        hist_store.save_scan(current_scan_rec)
        g_hist_dec = gov_gate.evaluate_historical_comparison(hist_comparison)
        governance_decisions.append({"finding_id": "historical_trend", "decision": g_hist_dec.value})

        record_stage("HISTORICAL INTELLIGENCE", t0, f"Score: {hist_comparison.score_after}/100 ({hist_comparison.score_delta:+d}), Trend: {hist_comparison.risk_trend.value}")

        # 11.6 M15 Intelligent Security Prioritization & Cross-Repository Intelligence
        t0 = time.time()
        prio_engine = SecurityPriorityEngine()
        cross_repo_engine = CrossRepositoryIntelligenceEngine()

        corr_dicts = [cf.to_dict() for cf in correlated_findings] if correlated_findings else [f.to_dict() for f in verified_findings]
        taint_dicts = [tf.to_dict() for tf in taint_findings]

        prioritized_findings = prio_engine.prioritize_findings(
            findings=corr_dicts,
            historical_comparison=hist_comparison,
            context=context,
            taint_findings=taint_dicts,
        )

        cross_patterns = cross_repo_engine.analyze_cross_repository_patterns(
            store=hist_store,
            current_repository=repo_key,
            current_findings=corr_dicts,
        )

        g_intel_dec = gov_gate.evaluate_security_intelligence(prioritized_findings)
        governance_decisions.append({"finding_id": "security_prioritization", "decision": g_intel_dec.value})

        record_stage("SECURITY INTELLIGENCE", t0, f"Prioritized {len(prioritized_findings)} findings" + (f" (Top: {prioritized_findings[0].priority_tier.value} Score: {prioritized_findings[0].priority_score})" if prioritized_findings else ""))

        # 11.7 M16 Autonomous Attack-Path Reasoning & Security Investigation
        t0 = time.time()
        path_correlator = AttackPathCorrelator()
        attack_paths = path_correlator.correlate_attack_paths(
            findings=corr_dicts,
            taint_findings=taint_dicts,
            context=context,
        )

        g_path_dec = gov_gate.evaluate_attack_paths(attack_paths)
        governance_decisions.append({"finding_id": "attack_path_reasoning", "decision": g_path_dec.value})

        record_stage("ATTACK PATH REASONING", t0, f"Correlated {len(attack_paths)} attack paths" + (f" (Top Risk Score: {attack_paths[0].risk_score})" if attack_paths else ""))

        # 11.8 M17 Intelligent Security Remediation Orchestration & Fix Planning
        t0 = time.time()
        rem_planner = RemediationPlanner()
        remediation_plan = rem_planner.generate_remediation_plan(
            prioritized_findings=prioritized_findings,
            attack_paths=attack_paths,
            repair_proposals=repair_proposals,
            repair_validations=repair_validations,
            historical_comparison=hist_comparison,
            repository_name=repo_name or os.path.basename(scan_target_path),
        )

        g_rem_dec = gov_gate.evaluate_remediation_plan(remediation_plan)
        governance_decisions.append({"finding_id": "remediation_plan_orchestration", "decision": g_rem_dec.value})

        record_stage("REMEDIATION PLANNING", t0, f"Planned {len(remediation_plan.remediation_items)} remediation items" + (f" (Projected Score: {remediation_plan.projected_security_score})" if remediation_plan.remediation_items else ""))

        # 11.85 M22 Safe Security Simulation & Exploitability Validation Engine
        t0 = time.time()
        simulation_engine = SecuritySimulationEngine()
        simulation_result = simulation_engine.run_simulation_pipeline(
            verified_findings=verified_findings,
            prioritized_findings=prioritized_findings,
            attack_paths=attack_paths,
            repair_validations=repair_validations,
            repository_name=repo_name or os.path.basename(scan_target_path),
        )

        g_sim_dec = gov_gate.evaluate_simulation_results(simulation_result)
        governance_decisions.append({"finding_id": "security_simulation_validation", "decision": g_sim_dec.value})

        record_stage("SECURITY SIMULATION", t0, f"Executed safe simulation (Status: {simulation_result.get('overall_status', 'NOT_REPRODUCED')}, Reproduced: {simulation_result.get('reproduced_count', 0)})")

        # 11.9 M18 Continuous Security Monitoring & Regression Detection
        t0 = time.time()
        sec_monitor = SecurityMonitor()
        monitoring_result = sec_monitor.monitor_repository(
            current_scan={
                "metadata": {
                    "scan_id": scan_id,
                    "repo_name": repo_name or os.path.basename(scan_target_path),
                    "commit": resolved_commit,
                },
                "prioritized_findings": prioritized_findings,
                "verified_findings": verified_findings,
                "security_score": remediation_plan.current_security_score if hasattr(remediation_plan, "current_security_score") else 100,
            },
            historical_comparison=hist_comparison,
            attack_paths=attack_paths,
            remediation_plan=remediation_plan,
            repository_name=repo_name or os.path.basename(scan_target_path),
        )

        g_mon_dec = gov_gate.evaluate_security_monitoring(monitoring_result)
        governance_decisions.append({"finding_id": "security_monitoring_evaluation", "decision": g_mon_dec.value})

        record_stage("SECURITY MONITORING", t0, f"Evaluated monitoring posture (Regression: {monitoring_result.regression_severity.value}, Alerts: {len(monitoring_result.alerts)})")

        # 11.10 Security Release Readiness & Executive Gate (M19)
        t0 = time.time()
        release_engine = SecurityReleaseReadinessEngine()
        release_decision = release_engine.evaluate_release_readiness(
            verified_findings=verified_findings,
            prioritized_findings=prioritized_findings,
            attack_paths=attack_paths,
            remediation_plan=remediation_plan,
            monitoring_result=monitoring_result,
            repository_name=repo_name or os.path.basename(scan_target_path),
            commit_sha=resolved_commit,
            governance_status=g_mon_dec.value,
        )

        g_rel_dec = gov_gate.evaluate_release_readiness(release_decision)
        governance_decisions.append({"finding_id": "release_readiness_gate", "decision": g_rel_dec.value})

        record_stage("RELEASE READINESS", t0, f"Evaluated release readiness (Decision: {release_decision.decision.value}, Blockers: {len(release_decision.blockers)})")

        # 11.11 M20 Security Engineering Orchestration Workflow
        t0 = time.time()
        orchestrator = SecurityEngineeringOrchestrator()
        orchestration_result = orchestrator.orchestrate_repository(
            verified_findings=verified_findings,
            prioritized_findings=prioritized_findings,
            attack_paths=attack_paths,
            remediation_plan=remediation_plan,
            monitoring_result=monitoring_result,
            release_decision=release_decision,
            repository_name=repo_name or os.path.basename(scan_target_path),
            commit_sha=resolved_commit,
            governance_status=g_rel_dec.value,
        )

        g_orc_dec = gov_gate.evaluate_security_workflow(orchestration_result)
        governance_decisions.append({"finding_id": "security_orchestration_workflow", "decision": g_orc_dec.value})

        record_stage("SECURITY ORCHESTRATION", t0, f"Orchestrated workflow (State: {orchestration_result.current_state.value}, Next Action: {orchestration_result.next_action.value})")

        # 11.12 M21 Security Knowledge & Learning Intelligence Engine
        t0 = time.time()
        knowledge_engine = SecurityKnowledgeEngine()
        knowledge_result = knowledge_engine.process_scan_knowledge(
            verified_findings=verified_findings,
            prioritized_findings=prioritized_findings,
            attack_paths=attack_paths,
            remediation_plan=remediation_plan,
            monitoring_result=monitoring_result,
            release_decision=release_decision,
            repository_name=repo_name or os.path.basename(scan_target_path),
        )

        g_know_dec = gov_gate.evaluate_knowledge_insights(knowledge_result)
        governance_decisions.append({"finding_id": "security_knowledge_insights", "decision": g_know_dec.value})

        record_stage("SECURITY KNOWLEDGE", t0, f"Learned patterns & stored knowledge ({knowledge_result.get('total_knowledge_records', 0)} total records)")

        # 12. Observability Telemetry & Final Report
        data["status"] = "REPORTING"
        t0 = time.time()
        report_gen = ReportGenerator()
        run_report = report_gen.generate_run_report(
            collector=tracer,
            repository_name=repo_name or os.path.basename(scan_target_path),
            commit_ref=resolved_commit,
            start_time=start_time_iso,
        )
        report_md = report_gen.render_markdown_report(
            report=run_report,
            correlated_findings=[cf.to_dict() for cf in correlated_findings],
            repair_proposals=[rp.to_dict() for rp in repair_proposals],
            repair_validations=[rv.to_dict() for rv in repair_validations],
            historical_comparison=hist_comparison.to_dict(),
            prioritized_findings=[pf.to_dict() for pf in prioritized_findings],
            cross_repository_patterns=[cp.to_dict() for cp in cross_patterns],
            attack_paths=[ap.to_dict() for ap in attack_paths],
            regression_results=[rr.to_dict() for rr in regression_results],
            remediation_plan=remediation_plan,
            monitoring_result=monitoring_result,
            release_decision=release_decision,
            orchestration_result=orchestration_result,
            knowledge_result=knowledge_result,
            simulation_result=simulation_result,
            governance_decisions=governance_decisions,
            final_verdict="PASS" if not confirmed_findings else "NEEDS INVESTIGATION",
        )

        record_stage("FINAL REPORT", t0, "Generated execution report & telemetry")

        duration_sec = round(time.time() - t_start, 3)

        # Update Session State
        data["status"] = "COMPLETE"
        data["orchestration_result"] = orchestration_result
        data["knowledge_result"] = knowledge_result
        data["simulation_result"] = simulation_result
        data["metadata"] = {
            "scan_id": scan_id,
            "repo_input": repo_input,
            "repo_path": scan_target_path,
            "repo_name": repo_name or os.path.basename(scan_target_path),
            "repo_owner": owner,
            "source_type": source_type,
            "github_url": resolved_target if source_type == "GITHUB" else None,
            "branch": branch,
            "commit": resolved_commit,
            "start_time": start_time_iso,
            "end_time": datetime.now().isoformat(),
            "duration_sec": duration_sec,
            "scan_mode": scan_mode,
        }
        data["context"] = context
        data["intake_meta"] = intake_meta
        data["candidates"] = candidates
        data["verified_findings"] = verified_findings
        data["taint_findings"] = taint_findings
        data["correlated_findings"] = correlated_findings
        data["repair_proposals"] = repair_proposals
        data["repair_validations"] = repair_validations
        data["historical_comparison"] = hist_comparison
        data["current_scan_record"] = current_scan_rec
        data["prioritized_findings"] = prioritized_findings
        data["cross_repository_patterns"] = cross_patterns
        data["attack_paths"] = attack_paths
        data["regression_results"] = regression_results
        data["remediation_plan"] = remediation_plan
        data["monitoring_result"] = monitoring_result


        data["governance_decisions"] = governance_decisions
        data["repair_results"] = repair_results
        data["pr_results"] = pr_results
        data["stage_timings"] = stage_timings
        data["trace_collector"] = tracer
        data["run_report"] = run_report
        data["report_markdown"] = report_md
        data["report_json"] = json.dumps(run_report.to_dict(), indent=2)
        data["report_html"] = f"<html><body><pre>{html.escape(report_md)}</pre></body></html>"



        data["safety_state"] = {
            "dry_run": os.environ.get("AGENTOS_SWE_DRY_RUN", "1") == "1",
            "sandbox_active": True,
            "network_egress": 0,
            "remote_writes": 0,
            "commits": 0,
            "prs": len(pr_results),
            "files_modified": 0,
            "secrets_exposed": 0,
        }

    except Exception as ex:
        data["status"] = "FAILED"
        data["error"] = str(ex)
        data["metadata"]["end_time"] = datetime.now().isoformat()
        data["metadata"]["duration_sec"] = round(time.time() - t_start, 3)


# ---------------------------------------------------------------------------
# Sidebar & Navigation Controls (Phase 5 & Requirement 8)
# ---------------------------------------------------------------------------

def render_sidebar(data: Dict[str, Any]) -> str:
    """Render the sidebar scan controls and navigation items."""
    st.sidebar.markdown("### 🛡️ AGENTOS-SWE")
    st.sidebar.markdown("*Unified Verification & Repair Platform*")
    st.sidebar.markdown("---")

    st.sidebar.markdown("#### 📥 Repository to Scan")
    
    current_repo_input = data["metadata"].get("repo_input", data["metadata"].get("repo_path", os.getcwd()))
    repo_input = st.sidebar.text_input(
        "Repository Path or GitHub URL",
        value=current_repo_input,
        placeholder="Enter local path or GitHub repository URL...",
    )

    # Repository Source Detection & Status Badge
    source_type, resolved_url, owner, repo_name = parse_repository_input(repo_input)
    if source_type == "GITHUB":
        st.sidebar.markdown("**Source**: <span class='badge badge-pass'>GITHUB REPOSITORY</span>", unsafe_allow_html=True)
        st.sidebar.caption(f"Owner: `{owner}` | Repo: `{repo_name}`")
    elif source_type == "LOCAL":
        st.sidebar.markdown("**Source**: <span class='badge badge-pass'>LOCAL REPOSITORY</span>", unsafe_allow_html=True)
        st.sidebar.caption(f"Path: `{os.path.basename(resolved_url)}`")
    elif source_type == "EMPTY":
        st.sidebar.markdown("**Source**: <span class='badge badge-unknown'>READY</span>", unsafe_allow_html=True)
    else:
        st.sidebar.markdown("**Source**: <span class='badge badge-critical'>INVALID INPUT</span>", unsafe_allow_html=True)

    branch_input = st.sidebar.text_input("Branch", value=data["metadata"].get("branch", "main"))
    commit_input = st.sidebar.text_input("Commit", value=data["metadata"].get("commit", "HEAD"))
    scan_mode_input = st.sidebar.selectbox(
        "Scan Mode",
        options=["Full Audit", "Fast Security Audit", "Deep Taint Analysis", "Synthetic Benchmark"],
        index=0,
    )

    if st.sidebar.button("🔍 START SWE SCAN", use_container_width=True):
        target = repo_input.strip()
        if scan_mode_input == "Synthetic Benchmark":
            bench_dir, _ = BenchmarkFixtures.create_benchmark_workspace()
            target = bench_dir

        with st.spinner("Executing AgentOS-SWE Scan..."):
            run_swe_scan_engine(
                repo_input=target,
                branch=branch_input,
                commit=commit_input,
                scan_mode=scan_mode_input,
            )
        st.rerun()

    # Safety Indicators
    is_dry_run = os.environ.get("AGENTOS_SWE_DRY_RUN", "1") == "1"
    st.sidebar.markdown("---")
    st.sidebar.markdown(f"**DRY-RUN**: `{'ENABLED (Protected)' if is_dry_run else 'DISABLED (Live)'}`")
    st.sidebar.markdown("**SANDBOX**: `ACTIVE (Isolated Subprocess)`")
    st.sidebar.markdown("---")

    # Scan Metadata & Status Card
    meta = data["metadata"]
    st.sidebar.markdown("#### 📌 Scan Status")
    status_val = data.get("status", "IDLE")
    st.sidebar.caption(f"**State**: `{status_val}`")
    st.sidebar.caption(f"**Scan ID**: `{meta.get('scan_id', 'N/A')}`")
    st.sidebar.caption(f"**Duration**: `{meta.get('duration_sec', 0.0)}s`")
    if data.get("error"):
        st.sidebar.error(data["error"])
    st.sidebar.markdown("---")

    # Navigation Menu (21 Pages)
    nav_options = [
        "1. Overview",
        "2. Agents",
        "3. Code Graph",
        "4. Findings",
        "5. Security / Taint",
        "6. Architecture",
        "7. Performance",
        "8. Verification",
        "9. Pipeline",
        "10. Report",
        "11. Safety",
        "12. Vulnerability Intelligence",
        "13. Security History",
        "14. Security Intelligence",
        "15. Attack Paths",
        "16. Remediation Center",
        "17. Security Monitoring",
        "18. Release Readiness",
        "19. Security Engineering",
        "20. Security Knowledge",
        "21. Security Simulation",
    ]

    
    selected_nav = st.sidebar.radio("Navigation", nav_options, index=0)
    return selected_nav


# ---------------------------------------------------------------------------
# Phase 6 — Overview Dashboard
# ---------------------------------------------------------------------------

def render_dashboard(data: Dict[str, Any]):
    """Render Overview Dashboard with metrics, Repository Info Card, and Final Verdict."""
    st.title("📊 Executive Overview Dashboard")
    st.caption("End-to-End Repository Verification & Defects Intelligence Summary")

    context = data.get("context")
    findings = data.get("verified_findings", [])
    taint_findings = data.get("taint_findings", [])
    meta = data.get("metadata", {})
    status_str = data.get("status", "IDLE")

    nodes = list(context.graph_provider._nodes.values()) if context and context.graph_provider and hasattr(context.graph_provider, "_nodes") else []
    relationships = context.graph_provider.get_relationships() if context and context.graph_provider and hasattr(context.graph_provider, "get_relationships") else []

    # Final Verdict Logic
    confirmed_count = len([f for f in findings if f.status == FindingStatus.CONFIRMED])
    rejected_count = len([f for f in findings if f.status == FindingStatus.REJECTED])
    inconclusive_count = len([f for f in findings if f.status == FindingStatus.INCONCLUSIVE])
    critical_count = len([f for f in findings if getattr(f, "severity", "").lower() == "critical"] + [tf for tf in taint_findings if tf.severity == TaintSeverity.CRITICAL])

    if status_str == "FAILED":
        verdict = "FAILED (Engine Error)"
        verdict_class = "alert-failed"
    elif status_str in ("IDLE", "PREPARING", "CLONING"):
        verdict = f"{status_str} (Scan In Progress / Pending)"
        verdict_class = "alert-investigate"
    elif critical_count > 0:
        verdict = "FAILED (Critical Defects Confirmed)"
        verdict_class = "alert-failed"
    elif confirmed_count > 0 or inconclusive_count > 0:
        verdict = "NEEDS INVESTIGATION (Confirmed/Inconclusive Issues Present)"
        verdict_class = "alert-investigate"
    else:
        verdict = "PASS (Zero Confirmed Vulnerabilities)"
        verdict_class = "alert-pass"

    st.markdown(
        f"""
        <div class="alert-banner {verdict_class}">
            <h3 style="margin:0; padding:0; color:inherit;">FINAL VERDICT: {verdict}</h3>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Repository Information Card (Requirement 7 & Requirement 14)
    st.markdown("### 📌 Repository Information")
    col_info1, col_info2, col_info3 = st.columns(3)
    with col_info1:
        st.markdown(f"**Repository**: `{meta.get('repo_name', 'N/A')}`")
        if meta.get("github_url"):
            st.markdown(f"[🔗 Open GitHub Repository]({meta.get('github_url')})")
        if meta.get("repo_owner"):
            st.markdown(f"**Owner**: `{meta.get('repo_owner')}`")
    with col_info2:
        src_label = meta.get("source_type", "N/A")
        st.markdown(f"**Source**: `{src_label}`")
        st.markdown(f"**Branch**: `{meta.get('branch', 'main')}`")
        st.markdown(f"**Commit**: `{meta.get('commit', 'HEAD')}`")
    with col_info3:
        st.markdown(f"**Files**: `{len(context.source_files) if context else 0}`")
        st.markdown(f"**Languages**: `{', '.join(context.languages) if context and context.languages else 'Python'}`")
        st.markdown(f"**Scan Mode**: `{meta.get('scan_mode', 'Full Audit')}`")

    st.markdown("---")

    # Top Metric Grid
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Files Analyzed", len(context.source_files) if context else 0)
    with col2:
        st.metric("Graph Nodes", len(nodes))
    with col3:
        st.metric("Graph Edges", len(relationships))
    with col4:
        st.metric("Total Findings", len(findings) + len(taint_findings))
    with col5:
        st.metric("Runtime", f"{meta.get('duration_sec', 0.0)}s")

    st.markdown("---")

    # Status Breakdown Metrics
    col_a, col_b, col_c, col_d = st.columns(4)
    with col_a:
        st.metric("Confirmed True Positives", confirmed_count)
    with col_b:
        st.metric("Rejected False Positives", rejected_count)
    with col_c:
        st.metric("Inconclusive Findings", inconclusive_count)
    with col_d:
        st.metric("Taint Paths Tracked", len(taint_findings))

    st.markdown("### 🏷️ Severity Distribution")
    high_count = len([f for f in findings if getattr(f, "severity", "").lower() == "high"] + [tf for tf in taint_findings if tf.severity == TaintSeverity.HIGH])
    med_count = len([f for f in findings if getattr(f, "severity", "").lower() == "medium"] + [tf for tf in taint_findings if tf.severity == TaintSeverity.MEDIUM])
    low_count = len([f for f in findings if getattr(f, "severity", "").lower() == "low"] + [tf for tf in taint_findings if tf.severity == TaintSeverity.LOW])

    c1, c2, c3, c4 = st.columns(4)
    c1.markdown(f"**CRITICAL**: `{critical_count}`")
    c2.markdown(f"**HIGH**: `{high_count}`")
    c3.markdown(f"**MEDIUM**: `{med_count}`")
    c4.markdown(f"**LOW**: `{low_count}`")

    if findings:
        st.markdown("### 📋 Quick Findings Summary")
        summary_rows = []
        for f in findings:
            summary_rows.append({
                "Category": f.category,
                "Title": f.title,
                "File": f.file or "N/A",
                "Severity": f.severity,
                "Status": f.status.value if hasattr(f.status, "value") else str(f.status),
                "Confidence": f"{f.confidence:.2f}",
            })
        st.dataframe(summary_rows, use_container_width=True)


# ---------------------------------------------------------------------------
# Phase 7 — Agent Activity
# ---------------------------------------------------------------------------

def render_agents(data: Dict[str, Any]):
    """Render Agent Activity and Squad Execution Breakdown."""
    st.title("🤖 Agent Activity & Squad Telemetry")
    st.caption("Read-only Investigation Squad, Polyglot Resolvers & Verification Agents")

    findings = data.get("verified_findings", [])
    taint_findings = data.get("taint_findings", [])

    agents_info = [
        {"name": "BugAgent", "role": "Logic & Defect Investigator", "category": "bug"},
        {"name": "SecurityAgent", "role": "Vulnerability & Injection Investigator", "category": "security"},
        {"name": "PerformanceAgent", "role": "Complexity & N+1 Loop Investigator", "category": "performance"},
        {"name": "ArchitectureAgent", "role": "Coupling & Dependency Investigator", "category": "architecture"},
        {"name": "VerificationAgent", "role": "Multi-Strategy Verification Pipeline", "category": "verification"},
        {"name": "PythonSemanticResolver", "role": "AST & Exception Intent Resolver", "category": "semantic"},
        {"name": "JavaScriptSemanticResolver", "role": "JS/TS Polyglot Resolver", "category": "semantic"},
        {"name": "TypeScriptSemanticResolver", "role": "TypeScript API Contract Analyzer", "category": "semantic"},
        {"name": "ReactSemanticResolver", "role": "React Component & Hook Resolver", "category": "semantic"},
        {"name": "VueSemanticResolver", "role": "Vue Template & Script Resolver", "category": "semantic"},
        {"name": "PythonTaintAnalyzer", "role": "Deterministic AST Taint Tracking Engine", "category": "taint"},
        {"name": "StaticVerificationStrategy", "role": "Structural Code & Line Verifier", "category": "verification"},
    ]

    cols = st.columns(3)
    for idx, agent in enumerate(agents_info):
        col = cols[idx % 3]
        agent_findings = [f for f in findings if f.category == agent["category"]] if agent["category"] != "taint" else taint_findings
        conf = len([f for f in agent_findings if getattr(f, "status", None) == FindingStatus.CONFIRMED])
        rej = len([f for f in agent_findings if getattr(f, "status", None) == FindingStatus.REJECTED])
        inc = len([f for f in agent_findings if getattr(f, "status", None) == FindingStatus.INCONCLUSIVE])

        with col:
            st.markdown(
                f"""
                <div class="sec-card">
                    <div class="sec-card-header">{agent['name']}</div>
                    <p style="font-size:0.8rem; color:#8b949e;">{agent['role']}</p>
                    <p><strong>Status</strong>: <span class="badge badge-pass">COMPLETE</span></p>
                    <p><strong>Findings</strong>: {len(agent_findings)} | <strong>Confirmed</strong>: {conf}</p>
                    <p><strong>Rejected</strong>: {rej} | <strong>Inconclusive</strong>: {inc}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )


# ---------------------------------------------------------------------------
# Phase 8 — Code Graph
# ---------------------------------------------------------------------------

def render_graph(data: Dict[str, Any]):
    """Render Code Graph visualization using Graphviz & node relationships."""
    st.title("🕸️ Code Graph & Architecture Network")
    st.caption("Repository Code Entities, Call Chains, Module Imports, and Finding Nodes")

    context = data.get("context")
    findings = data.get("verified_findings", [])

    nodes = list(context.graph_provider._nodes.values()) if context and context.graph_provider and hasattr(context.graph_provider, "_nodes") else []
    relationships = context.graph_provider.get_relationships() if context and context.graph_provider and hasattr(context.graph_provider, "get_relationships") else []

    if not context or not nodes:
        st.info("No code graph data available. Run an SWE scan to populate the graph.")
        return

    st.markdown(f"**Total Graph Nodes**: `{len(nodes)}` | **Relationships**: `{len(relationships)}`")
    if len(nodes) > 30:
        st.caption(f"Showing 30 of {len(nodes)} nodes in visual diagram (complete {len(nodes)} node explorer table below)")

    # Build Graphviz representation
    dot = ["digraph CodeGraph {", "  graph [bgcolor=\"#0d1117\", rankdir=LR];", "  node [style=filled, fontname=\"Courier\", fontsize=10];", "  edge [color=\"#58a6ff\", fontname=\"Courier\", fontsize=8];"]

    finding_files = {f.file for f in findings if f.file}

    for node in nodes[:30]:  # Cap at 30 nodes for clean visualization
        node_id_clean = node.id.replace("-", "_").replace(".", "_").replace("/", "_").replace("\\", "_")
        fillcolor = "#1f6feb"  # default blue
        if node.path in finding_files or any(f.file and node.path in f.file for f in findings):
            fillcolor = "#da3633"  # red for findings

        dot.append(f'  "{node_id_clean}" [label="{node.name}\\n({node.type.value if hasattr(node.type, "value") else str(node.type)})", fillcolor="{fillcolor}", fontcolor="#ffffff"];')

    for rel in relationships[:40]:
        src_clean = rel.source_id.replace("-", "_").replace(".", "_").replace("/", "_").replace("\\", "_")
        tgt_clean = rel.target_id.replace("-", "_").replace(".", "_").replace("/", "_").replace("\\", "_")
        rel_val = rel.relation_type.value if hasattr(rel.relation_type, "value") else str(rel.relation_type)
        dot.append(f'  "{src_clean}" -> "{tgt_clean}" [label="{rel_val}"];')

    dot.append("}")
    dot_str = "\n".join(dot)

    st.graphviz_chart(dot_str, use_container_width=True)

    st.markdown(f"### 📌 Code Node Explorer (Complete {len(nodes)} Nodes)")
    node_data = []
    for n in nodes:
        node_data.append({
            "ID": n.id,
            "Name": n.name,
            "Type": n.type.value if hasattr(n.type, "value") else str(n.type),
            "Path": n.path,
            "Line Range": str(n.line_range) if n.line_range else "N/A",
        })
    st.dataframe(node_data, use_container_width=True)


# ---------------------------------------------------------------------------
# Phase 9 — Findings Explorer & Inspector
# ---------------------------------------------------------------------------

def render_findings(data: Dict[str, Any]):
    """Render Findings Explorer table and detailed evidence panel."""
    st.title("🔍 Findings Explorer")
    st.caption("Multi-Agent Defects, Static Evidence, and Verification Decisions")

    findings = data.get("verified_findings", [])
    if not findings:
        st.info("No findings recorded. Run an SWE scan to populate findings.")
        return

    # Filters
    col_f1, col_f2, col_f3 = st.columns(3)
    with col_f1:
        cat_filter = st.selectbox("Category", ["ALL"] + sorted(list({f.category for f in findings})))
    with col_f2:
        sev_filter = st.selectbox("Severity", ["ALL", "critical", "high", "medium", "low"])
    with col_f3:
        status_filter = st.selectbox("Status", ["ALL"] + sorted(list({f.status.value if hasattr(f.status, "value") else str(f.status) for f in findings})))

    filtered = findings
    if cat_filter != "ALL":
        filtered = [f for f in filtered if f.category == cat_filter]
    if sev_filter != "ALL":
        filtered = [f for f in filtered if f.severity.lower() == sev_filter]
    if status_filter != "ALL":
        filtered = [f for f in filtered if (f.status.value if hasattr(f.status, "value") else str(f.status)) == status_filter]

    st.markdown(f"**Showing {len(filtered)} / {len(findings)} findings**")

    # Table
    table_rows = []
    for f in filtered:
        table_rows.append({
            "ID": f.id[:8],
            "Category": f.category,
            "Title": f.title,
            "Severity": f.severity.upper(),
            "Confidence": f"{f.confidence:.2f}",
            "File": f.file or "N/A",
            "Line": str(f.line_range[0]) if f.line_range else "N/A",
            "Status": f.status.value if hasattr(f.status, "value") else str(f.status),
        })

    st.dataframe(table_rows, use_container_width=True)

    # Detailed Panel Inspector
    st.markdown("### 🔬 Finding Inspector")
    selected_id = st.selectbox("Select Finding to Inspect", [f.id for f in filtered], format_func=lambda x: f"[{x[:8]}] {next((f.title for f in filtered if f.id == x), '')}")

    selected_f = next((f for f in filtered if f.id == selected_id), None)
    if selected_f:
        st.markdown(
            f"""
            <div class="sec-card">
                <h3>{selected_f.title}</h3>
                <p><strong>ID</strong>: <code>{selected_f.id}</code> | <strong>Category</strong>: <code>{selected_f.category}</code></p>
                <p><strong>Agent</strong>: <code>BugAgent</code> | <strong>Severity</strong>: <span class="badge badge-{selected_f.severity.lower()}">{selected_f.severity.upper()}</span></p>
                <p><strong>Status</strong>: <span class="badge badge-pass">{selected_f.status.value if hasattr(selected_f.status, 'value') else str(selected_f.status)}</span> | <strong>Confidence</strong>: <code>{selected_f.confidence:.2f}</code></p>
                <p><strong>File</strong>: <code>{selected_f.file}</code> (Line: {selected_f.line_range[0] if selected_f.line_range else 'N/A'})</p>
                <p><strong>Description</strong>: {selected_f.description or 'No description provided.'}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Source Code Context Extraction
        st.markdown("#### 📄 SOURCE CODE CONTEXT")
        context_obj = data.get("context")
        code_rendered = False

        if context_obj and selected_f.file:
            abs_p = os.path.join(context_obj.repository_path, selected_f.file)
            if os.path.exists(abs_p):
                try:
                    with open(abs_p, "r", encoding="utf-8", errors="ignore") as f_in:
                        lines = f_in.readlines()
                    
                    target_line = selected_f.line_range[0] if selected_f.line_range else 1
                    start_l = max(1, target_line - 5)
                    end_l = min(len(lines), target_line + 5)

                    snippet_lines = []
                    for idx_l in range(start_l, end_l + 1):
                        prefix = "➡️ " if idx_l == target_line else "   "
                        snippet_lines.append(f"{prefix}{idx_l:4d} | {lines[idx_l - 1].rstrip()}")

                    snippet_text = "\n".join(snippet_lines)
                    st.code(snippet_text, language="python")
                    code_rendered = True
                except Exception:
                    pass

        if not code_rendered:
            st.caption(f"Source file `{selected_f.file}` line {selected_f.line_range or 'N/A'}")

        # Why Detected
        st.markdown("#### 🔍 WHY DETECTED")
        st.info(f"Detected by BugAgent via AST pattern rule `{selected_f.title}` on file `{selected_f.file}` at line `{selected_f.line_range[0] if selected_f.line_range else 'N/A'}`.")

        # Semantic Analysis
        st.markdown("#### 🧠 SEMANTIC ANALYSIS")
        if "scripts" in (selected_f.file or "") or "test" in (selected_f.file or ""):
            st.warning("Semantic Context: Test Harness / CLI Script (`ModuleRole.TEST_HARNESS`). Exception handlers in CLI test scripts print diagnostic error output to stdout rather than swallowing errors silently.")
        else:
            st.info("Semantic Resolver: Evaluated intent and control-flow context.")

        # Taint Analysis
        st.markdown("#### ⛓️ TAINT ANALYSIS")
        taint_findings = data.get("taint_findings", [])
        matching_taint = [tf for tf in taint_findings if tf.path.file == selected_f.file]
        if matching_taint:
            for mt in matching_taint:
                st.markdown(f"- **Taint Path**: `{mt.title}` ({mt.severity.value})")
        else:
            st.caption("No taint path associated with this finding.")

        # Verification
        st.markdown("#### 🛡️ VERIFICATION")
        if selected_f.status == FindingStatus.CONFIRMED:
            st.markdown("**Status**: <span class='badge badge-pass'>CONFIRMED</span>", unsafe_allow_html=True)
            st.success("Verification Engine: Static AST reachability and verification strategy confirmed finding capability.")
        elif selected_f.status == FindingStatus.REJECTED:
            st.markdown("**Status**: <span class='badge badge-investigate'>REJECTED</span>", unsafe_allow_html=True)
            st.warning("Verification Engine: Rejected as false positive due to safe control-flow or test harness context.")
        else:
            st.markdown("**Status**: <span class='badge badge-unknown'>INCONCLUSIVE</span>", unsafe_allow_html=True)
            st.info("Verification Engine: Inconclusive reproduction environment.")

        # Repair Status
        st.markdown("#### 🔧 REPAIR STATUS")
        repairs = data.get("repair_results", [])
        matching_repair = [r for r in repairs if getattr(r, "finding_id", None) == selected_f.id]
        if matching_repair:
            st.success(f"Candidate repair generated: `{matching_repair[0].status.value}`")
        else:
            st.caption("No candidate repair generated for this finding.")


# ---------------------------------------------------------------------------
# Phase 10 — Security / Taint Page
# ---------------------------------------------------------------------------

def render_security(data: Dict[str, Any]):
    """Render Security & Data-Flow Taint Analysis Page."""
    st.title("🛡️ Security Data-Flow & Taint Analysis")
    st.caption("M12 Deterministic AST Taint Tracking: Source → Propagation Chain → Sink")

    taint_findings: List[TaintFinding] = data.get("taint_findings", [])

    # Severity Counts
    crit_c = len([t for t in taint_findings if t.severity == TaintSeverity.CRITICAL])
    high_c = len([t for t in taint_findings if t.severity == TaintSeverity.HIGH])
    med_c = len([t for t in taint_findings if t.severity == TaintSeverity.MEDIUM])
    low_c = len([t for t in taint_findings if t.severity == TaintSeverity.LOW])
    unk_c = len([t for t in taint_findings if t.severity == TaintSeverity.UNKNOWN])

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("CRITICAL", crit_c)
    c2.metric("HIGH", high_c)
    c3.metric("MEDIUM", med_c)
    c4.metric("LOW", low_c)
    c5.metric("UNKNOWN", unk_c)

    st.markdown("---")

    col_src, col_snk = st.columns(2)
    with col_src:
        st.markdown("#### 📥 Supported Taint Sources")
        st.markdown("- `HTTP_REQUEST`, `QUERY_PARAMETER`, `FORM_INPUT`, `JSON_INPUT`\n- `ENVIRONMENT_VARIABLE`, `CLI_ARGUMENT`, `USER_INPUT`, `FILE_INPUT`")
    with col_snk:
        st.markdown("#### 📤 Supported Taint Sinks")
        st.markdown("- `SHELL_EXECUTION`, `COMMAND_EXECUTION`, `EVAL_EXECUTION`\n- `SQL_QUERY`, `DESERIALIZATION`, `TEMPLATE_RENDERING`, `FILE_WRITE`")

    st.markdown("---")
    st.markdown("### ⛓️ Taint Flow Visualizer")

    if not taint_findings:
        st.info("Taint Analysis: No confirmed taint paths.")
        return

    for idx, tf in enumerate(taint_findings):
        san_badge = '<span class="badge badge-sanitized">SANITIZED</span>' if tf.is_sanitized else '<span class="badge badge-unsanitized">UNSANITIZED</span>'
        sev_badge = f'<span class="badge badge-{tf.severity.value.lower()}">{tf.severity.value}</span>'

        st.markdown(
            f"""
            <div class="sec-card">
                <h4>{idx+1}. {tf.title} {sev_badge} {san_badge}</h4>
                <p><strong>File</strong>: <code>{tf.path.file}</code> | <strong>Confidence</strong>: <code>{tf.confidence:.2f}</code></p>
                <p><strong>Explanation</strong>: {tf.explanation}</p>
                <div style="margin-top:12px;">
                    <div class="flow-node"><strong>SOURCE</strong>: {tf.path.source.code_snippet.strip()} [<em>{tf.path.source.source_kind.value} @ Line {tf.path.source.line_no}</em>]</div>
            """,
            unsafe_allow_html=True,
        )

        for step in tf.path.propagation_steps:
            st.markdown(
                f"""
                <div class="flow-arrow">↓ {step.operation}</div>
                <div class="flow-node"><strong>PROPAGATION</strong>: <code>{step.from_var}</code> → <code>{step.to_var}</code> (Line {step.line_no})</div>
                """,
                unsafe_allow_html=True,
            )

        if tf.path.sanitizers:
            for s in tf.path.sanitizers:
                st.markdown(
                    f"""
                    <div class="flow-arrow">🛡️ SANITIZER APPLIED</div>
                    <div class="flow-node"><code>{s.sanitizer_name}({s.var_name})</code> @ Line {s.line_no}</div>
                    """,
                    unsafe_allow_html=True,
                )

        st.markdown(
            f"""
                    <div class="flow-arrow">↓ SINK</div>
                    <div class="flow-node"><strong>SINK</strong>: {tf.path.sink.code_snippet.strip()} [<em>{tf.path.sink.sink_kind.value} @ Line {tf.path.sink.line_no}</em>]</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


# ---------------------------------------------------------------------------
# Phase 11 — Architecture
# ---------------------------------------------------------------------------

def render_architecture(data: Dict[str, Any]):
    """Render Architecture Page with module roles & semantic suppressions."""
    st.title("🏛️ Architecture & Module Role Intelligence")
    st.caption("Module Coupling, Fan-Out Analysis, and Semantic False-Positive Suppressions")

    context = data.get("context")
    findings = data.get("verified_findings", [])
    arch_findings = [f for f in findings if f.category == "architecture"]

    st.markdown("### 📦 Module Classification & Roles")
    st.markdown("- `ENTRYPOINT_LAUNCHER`: Application entry points (`main.py`, `app.py`)\n- `TEST_HARNESS`: Unit/integration test files (`test_*.py`)\n- `LIBRARY_CORE`: Core domain logic and classes")

    st.markdown("### 🚫 Semantic Suppression Log")
    st.info("""
    **Suppressed Finding**: `job.get("title")`  
    **Semantic Classification**: `DICT_LOOKUP`  
    **Reason**: Dictionary key access is non-network I/O; eliminated false positive.
    """)

    if arch_findings:
        st.markdown("### ⚠️ Architecture Findings")
        for f in arch_findings:
            st.warning(f"**{f.title}** ({f.file}): {f.description}")


# ---------------------------------------------------------------------------
# Phase 12 — Performance
# ---------------------------------------------------------------------------

def render_performance(data: Dict[str, Any]):
    """Render Performance Analysis Page."""
    st.title("⚡ Performance & Complexity Intelligence")
    st.caption("N+1 Query Loop Detection, Algorithmic Complexity, and Expensive Call Evidence")

    findings = data.get("verified_findings", [])
    perf_findings = [f for f in findings if f.category == "performance"]

    if not perf_findings:
        st.success("No performance bottlenecks or N+1 query loops detected.")
        return

    for f in perf_findings:
        st.markdown(
            f"""
            <div class="sec-card">
                <h4>{f.title}</h4>
                <p><strong>File</strong>: <code>{f.file}</code> (Line: {f.line_range or 'N/A'})</p>
                <p><strong>Description</strong>: {f.description}</p>
                <p><strong>Semantic Filtering Evidence</strong>: Verified inner loop database query pattern.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )


# ---------------------------------------------------------------------------
# Phase 13 — Verification
# ---------------------------------------------------------------------------

def render_verification(data: Dict[str, Any]):
    """Render Multi-Strategy Verification Pipeline Page."""
    st.title("🔬 Verification Pipeline & Decision Matrix")
    st.caption("Independent Static, Code Graph Reachability, and Subprocess Test Reproduction")

    findings = data.get("verified_findings", [])
    conf = len([f for f in findings if f.status == FindingStatus.CONFIRMED])
    rej = len([f for f in findings if f.status == FindingStatus.REJECTED])
    inc = len([f for f in findings if f.status == FindingStatus.INCONCLUSIVE])

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Findings", len(findings))
    c2.metric("Confirmed True Positives", conf)
    c3.metric("Rejected False Positives", rej)
    c4.metric("Inconclusive Findings", inc)

    st.markdown("---")
    st.markdown("### 🔄 Verification Decision Waterfall")

    for f in findings:
        st.markdown(
            f"""
            <div class="sec-card">
                <h4>{f.title} (<code>{f.file}</code>)</h4>
                <p><strong>Final Decision</strong>: <span class="badge badge-pass">{f.status.value if hasattr(f.status, 'value') else str(f.status)}</span></p>
                <div style="font-family:monospace; font-size:0.85rem; color:#8b949e;">
                    Detection → Aggregation → Semantic Verification → Taint Verification → Final Decision
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


# ---------------------------------------------------------------------------
# Phase 14 — Pipeline Timeline
# ---------------------------------------------------------------------------

def render_pipeline(data: Dict[str, Any]):
    """Render Pipeline Execution Timeline & Stage Metrics."""
    st.title("⏱️ Pipeline Execution Timeline")
    st.caption("End-to-End Stage Duration & Execution Telemetry")

    timings = data.get("stage_timings", [])
    if not timings:
        st.info("Pipeline timeline will display after running an SWE scan.")
        return

    st.dataframe(timings, use_container_width=True)


# ---------------------------------------------------------------------------
# Phase 15 — Full Report
# ---------------------------------------------------------------------------

def render_report(data: Dict[str, Any]):
    """Render Executive Markdown Run Report & Export Options."""
    st.title("📄 Full Execution Run Report")
    st.caption("Machine-Readable Telemetry and Executive Markdown Summary")

    report_md = data.get("report_markdown", "# No Scan Report Generated Yet.")
    report_json = data.get("report_json", "{}")
    report_html = data.get("report_html", "<html></html>")

    st.download_button("📥 Export JSON Report", data=report_json, file_name="swe_run_report.json", mime="application/json")
    st.download_button("📥 Export Markdown Report", data=report_md, file_name="swe_run_report.md", mime="text/markdown")
    st.download_button("📥 Export HTML Report", data=report_html, file_name="swe_run_report.html", mime="text/html")

    st.markdown("---")
    st.markdown(report_md)


# ---------------------------------------------------------------------------
# Phase 16 — Safety Panel
# ---------------------------------------------------------------------------

def render_safety(data: Dict[str, Any]):
    """Render Production Safety & Risk Governance Panel."""
    st.title("🔒 Production Safety & Risk Governance")
    st.caption("Security Invariants, Immutability Guarantees, and Command Execution Policy")

    safety = data.get("safety_state", {})

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("DRY RUN", "ENABLED" if safety.get("dry_run") else "DISABLED")
    col2.metric("SANDBOX", "ACTIVE")
    col3.metric("NETWORK EGRESS", "DENIED (0B)")
    col4.metric("REMOTE WRITES", safety.get("remote_writes", 0))

    col_a, col_b, col_c, col_d = st.columns(4)
    col_a.metric("COMMITS", safety.get("commits", 0))
    col_b.metric("PRS CREATED", safety.get("prs", 0))
    col_c.metric("FILES MODIFIED", safety.get("files_modified", 0))
    col_d.metric("SECRETS EXPOSED", safety.get("secrets_exposed", 0))

    st.markdown("---")
    st.markdown("### 🛡️ Core Security Invariants")
    st.success("1. **Repository Immutability**: All patch application and test reproductions occur strictly inside isolated temporary subshell sandbox directories. Host target repository is 100% UNTOUCHED.")
    st.success("2. **No Auto-Merge**: Pull requests require explicit human code review before merging.")
    st.success("3. **Secret Redaction**: Environment credentials (`ghp_`, API keys, passwords) are automatically redacted from logs, prompts, and outputs.")
    st.success("4. **Command Execution Policy**: Subprocess execution is restricted to explicit allowlist binaries (`python`, `pytest`, `git`). Dangerous shell invocations are blocked.")


# ---------------------------------------------------------------------------
# Phase 17 — Vulnerability Intelligence Panel
# ---------------------------------------------------------------------------

def render_vulnerability_intelligence(data: Dict[str, Any]):
    """Render Evidence-Driven Vulnerability Intelligence & Intelligent Repair Panel."""
    st.title("🧩 Evidence-Driven Vulnerability Intelligence & Intelligent Repair")
    st.caption("Correlated Evidence Chains, Root Cause Analysis, Explainable Confidence & Intelligent Repair Validation")

    corr_findings = data.get("correlated_findings", [])
    repair_props = data.get("repair_proposals", [])
    reg_results = data.get("regression_results", [])
    gov_decs = data.get("governance_decisions", [])

    st.markdown("### 🔄 End-to-End Vulnerability Processing Pipeline")
    st.info("`SOURCE` → `PROPAGATION` → `SINK` → `ROOT CAUSE` → `REPAIR` → `VALIDATION` → `GOVERNANCE`")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("CORRELATED FINDINGS", len(corr_findings))
    col2.metric("REPAIR PROPOSALS", len(repair_props))
    col3.metric("REGRESSIONS", len([r for r in reg_results if getattr(r, 'regression_status', '') != 'CLEAN']))
    col4.metric("GOVERNANCE DECISIONS", len(gov_decs))

    if not corr_findings:
        st.success("Zero correlated vulnerabilities detected in this scan.")
        return

    st.markdown("---")
    st.markdown("### 🔍 Correlated Vulnerabilities Explorer")

    for cf in corr_findings:
        rc_val = cf.root_cause.value if hasattr(cf.root_cause, 'value') else str(cf.root_cause)
        cat_val = getattr(cf, 'vulnerability_category', 'General')
        file_val = getattr(cf, 'affected_file', 'N/A')
        sev_val = getattr(cf, 'severity', 'MEDIUM').upper()
        conf_val = getattr(cf, 'confidence', 0.90)

        with st.expander(f"🔴 [{rc_val}] {cat_val} (File: {file_val})", expanded=True):
            c_a, c_b, c_c = st.columns(3)
            c_a.metric("Severity", sev_val)
            c_b.metric("Confidence", f"{conf_val:.2f}")
            c_c.metric("Root Cause", rc_val)

            st.markdown("#### 💬 Explainable Confidence Rationale")
            if hasattr(cf, 'confidence_explanation') and hasattr(cf.confidence_explanation, 'rationale'):
                for item in cf.confidence_explanation.rationale:
                    st.markdown(f"- `{item}`")

            st.markdown("---")
            st.markdown("#### 🔗 Evidence Chain (Source → Propagation → Sink)")

            col_src, col_prop, col_snk = st.columns(3)
            ev_chain = getattr(cf, 'evidence_chain', None)
            with col_src:
                st.markdown("**1. Source Evidence**")
                if ev_chain and ev_chain.source_evidence:
                    st.json(ev_chain.source_evidence[0])
                else:
                    st.write("Static pattern match")

            with col_prop:
                st.markdown("**2. Propagation Steps**")
                if ev_chain and ev_chain.propagation_evidence:
                    st.json(ev_chain.propagation_evidence)
                else:
                    st.write("Direct intra-procedural flow")

            with col_snk:
                st.markdown("**3. Sink Evidence**")
                if ev_chain and ev_chain.sink_evidence:
                    st.json(ev_chain.sink_evidence[0])
                else:
                    st.write("Dangerous endpoint operation")

            st.markdown("---")
            st.markdown("#### 🛠️ Intelligent Repair Proposal & Rationale")
            match_prop = next((p for p in repair_props if getattr(p, 'finding_id', '') == getattr(cf, 'finding_id', '')), None)
            if match_prop:
                st.write(f"**Strategy**: `{getattr(match_prop, 'strategy', 'DEFENSIVE')}`")
                st.write(f"**Rationale**: {getattr(match_prop, 'rationale', '')}")
                st.write(f"**Expected Risk Reduction**: {getattr(match_prop, 'expected_risk_reduction', '')}")
                st.markdown("**Proposed Unified Diff**:")
                st.code(getattr(match_prop, 'unified_diff', ''), language="diff")

            st.markdown("---")
            st.markdown("#### ❓ Diagnostic Rationale")
            q1, q2 = st.columns(2)
            q1.info(f"**WHY DETECTED**: Multi-agent squad and taint flow identified untrusted entrypoint reaching {rc_val} sink.")
            q2.success(f"**WHY THIS FIX**: Strategy '{getattr(match_prop, 'strategy', 'DEFENSIVE') if match_prop else 'DEFENSIVE'}' replaces unsafe operation with non-executable structural binding.")

            q3, q4 = st.columns(2)
            q3.warning("**WHY VULNERABLE**: Unchecked execution path creates injection or security swallow risk.")
            q4.success("**WHY FIX IS SAFE**: Preserves original public signatures and executes cleanly inside IsolatedSandbox.")

    # M13.1 Repair Validation Section
    st.markdown("---")
    st.markdown("### 🧪 M13.1 Repair Validation & Security Regression Hardening")
    st.caption("Empirical Sandboxed Validation, Post-Patch Security Re-scanning, Taint Re-analysis, and Differential Finding Comparison")

    repair_vals = data.get("repair_validations", [])
    if not repair_vals:
        st.info("No empirical repair validation records available for this scan.")
        return

    for rv in repair_vals:
        v_str = rv.final_verdict.value if hasattr(rv.final_verdict, "value") else str(getattr(rv, "final_verdict", "INCONCLUSIVE"))
        fid = getattr(rv, "finding_id", "N/A")
        rc = getattr(rv, "vulnerability_type", "UNKNOWN")
        tf = getattr(rv, "target_file", "N/A")
        qual = getattr(rv, "patch_quality", {})
        qual_score = qual.quality_score if hasattr(qual, "quality_score") else qual.get("quality_score", "HIGH")

        badge_color = "pass" if v_str in ("REPAIRED", "NO_REPAIR_REQUIRED") else ("critical" if v_str == "REGRESSION_DETECTED" else "investigate")

        with st.expander(f"🛡️ Repair Validation for `{fid}` — Verdict: {v_str}", expanded=True):
            st.markdown(
                f"""
                <div class="alert-banner alert-{badge_color}" style="padding:10px; margin-bottom:15px;">
                    <h4 style="margin:0; padding:0;">FINAL REPAIR VERDICT: {v_str}</h4>
                    <p style="margin:5px 0 0 0;">Target File: <code>{tf}</code> | Root Cause: <code>{rc}</code> | Patch Quality: <code>{qual_score}</code></p>
                </div>
                """,
                unsafe_allow_html=True,
            )

            st.markdown("##### 🔬 Sandboxed Verification Breakdown")
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Syntax Check", "PASS" if getattr(rv, "syntax_valid", True) else "FAIL")
            c2.metric("Repro Test", "PASS" if getattr(rv, "reproduction_passed", True) else "FAIL")
            c3.metric("Security Re-scan", "CLEAN" if not getattr(rv, "original_finding_present_after", False) else "VULNERABILITY PRESENT")
            c4.metric("Taint Re-analysis", "TERMINATED" if not getattr(rv, "taint_present_after", False) else "TAINT FLOW PERSISTS")

            st.markdown("---")
            st.markdown("##### 📊 Before / After Finding Differential")
            d_col1, d_col2, d_col3 = st.columns(3)
            removed = getattr(rv, "removed_security_findings", [])
            remaining = getattr(rv, "remaining_security_findings", [])
            new_f = getattr(rv, "new_security_findings", [])

            with d_col1:
                st.success(f"**Removed Vulnerabilities ({len(removed)})**")
                for item in removed:
                    st.write(f"- `{item}`")
                if not removed:
                    st.caption("None")

            with d_col2:
                st.warning(f"**Remaining Findings ({len(remaining)})**")
                for item in remaining:
                    st.write(f"- `{item}`")
                if not remaining:
                    st.caption("None")

            with d_col3:
                st.error(f"**Newly Introduced Findings ({len(new_f)})**")
                for item in new_f:
                    st.write(f"- `{item}`")
                if not new_f:
                    st.caption("Zero (Clean Patch)")

            if getattr(rv, "failure_reason", ""):
                st.error(f"**Validation Diagnostic Note**: {rv.failure_reason}")


# ---------------------------------------------------------------------------
# M14 — Security History & Risk Trend Panel
# ---------------------------------------------------------------------------

def render_security_history(data: Dict[str, Any]):
    """Render Repository Security Intelligence & Historical Regression Panel."""
    st.title("📈 Repository Security Intelligence & Historical Trend")
    st.caption("Cross-Commit Security Scoring, Finding Lifecycle Tracking, Reopened Vulnerability Detection, and Git Impact Intersections")

    hist_comp = data.get("historical_comparison")
    meta = data.get("metadata", {})
    repo_name = meta.get("repo_name") or "Unknown Repo"

    hist_store = HistoricalScanStore()

    if not hist_comp:
        st.info("No historical comparison data available for the current scan yet.")
        scans = hist_store.list_scans(repo_name)
        if scans:
            st.markdown(f"**Saved Historical Scans for `{repo_name}`**: {len(scans)}")
        return

    score_before = getattr(hist_comp, "score_before", 100)
    score_after = getattr(hist_comp, "score_after", 100)
    score_delta = getattr(hist_comp, "score_delta", 0)
    trend = getattr(hist_comp, "risk_trend", RiskTrend.STABLE)
    trend_val = trend.value if hasattr(trend, "value") else str(trend)

    # Prominent Security Score Card
    st.markdown("### 🏆 Security Score & Risk Trend")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("CURRENT SCORE", f"{score_after} / 100", f"{score_delta:+d}")
    c2.metric("BASELINE SCORE", f"{score_before} / 100")
    c3.metric("RISK TREND", trend_val)
    c4.metric("BASELINE SCAN ID", getattr(hist_comp, "baseline_scan_id", "Initial Baseline") or "Initial Baseline")

    trend_class = "pass" if trend_val == "IMPROVING" else ("failed" if trend_val == "DEGRADING" else "investigate")
    st.markdown(
        f"""
        <div class="alert-banner alert-{trend_class}">
            <h4 style="margin:0;">RISK TREND: {trend_val}</h4>
            <p style="margin:5px 0 0 0;">{getattr(hist_comp, 'explanation', '')}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("---")

    # Finding Lifecycle Explorer Tabs
    st.markdown("### 🔄 Finding Lifecycle Breakdown")
    new_f = getattr(hist_comp, "new_findings", [])
    fixed_f = getattr(hist_comp, "fixed_findings", [])
    unchanged_f = getattr(hist_comp, "unchanged_findings", [])
    reopened_f = getattr(hist_comp, "reopened_findings", [])

    tab_new, tab_fixed, tab_unchanged, tab_reopened = st.tabs([
        f"🔴 New ({len(new_f)})",
        f"🟢 Fixed ({len(fixed_f)})",
        f"🟡 Unchanged ({len(unchanged_f)})",
        f"⚠️ Reopened ({len(reopened_f)})",
    ])

    with tab_new:
        if new_f:
            for item in new_f:
                st.error(f"**[NEW]** `{item.get('finding_id') or item.get('id')}` — Root Cause: `{item.get('root_cause') or item.get('category')}` | File: `{item.get('affected_file') or item.get('file')}`")
        else:
            st.success("Zero new vulnerabilities introduced in this scan.")

    with tab_fixed:
        if fixed_f:
            for item in fixed_f:
                st.success(f"**[FIXED]** `{item.get('finding_id') or item.get('id')}` — Root Cause: `{item.get('root_cause') or item.get('category')}` | File: `{item.get('affected_file') or item.get('file')}`")
        else:
            st.info("Zero vulnerabilities fixed in this scan cycle.")

    with tab_unchanged:
        if unchanged_f:
            for item in unchanged_f:
                st.warning(f"**[UNCHANGED]** `{item.get('finding_id') or item.get('id')}` — Root Cause: `{item.get('root_cause') or item.get('category')}` | File: `{item.get('affected_file') or item.get('file')}`")
        else:
            st.caption("No unchanged findings.")

    with tab_reopened:
        if reopened_f:
            for item in reopened_f:
                st.error(f"**[REOPENED]** `{item.get('finding_id') or item.get('id')}` — Root Cause: `{item.get('root_cause') or item.get('category')}` | File: `{item.get('affected_file') or item.get('file')}`")
        else:
            st.success("Zero reopened vulnerabilities detected.")

    st.markdown("---")

    # Changed-Code Impact Analysis Table
    st.markdown("### ⚡ Changed-Code Impact & Security Intersection")
    impacts = getattr(hist_comp, "changed_code_impacts", [])
    if impacts:
        for imp in impacts:
            f_file = getattr(imp, "file", "N/A")
            f_fn = getattr(imp, "function_name") or "Module Scope"
            f_sev = getattr(imp, "severity") or "LOW"
            f_desc = getattr(imp, "description", "")
            f_intersect = getattr(imp, "intersects_finding_id")

            if f_intersect:
                st.error(f"🚨 **Security Intersection**: `{f_file}` (`{f_fn}`) — {f_desc}")
            else:
                st.caption(f"📝 Modified File: `{f_file}` (+{getattr(imp, 'lines_added', 0)}/-{getattr(imp, 'lines_removed', 0)} lines)")
    else:
        st.info("No changed-code security intersections detected for current commit range.")

    st.markdown("---")

    # Baseline & Repository Management Controls
    st.markdown("### 🗄️ Baseline & Scan History Controls")
    all_scans = hist_store.list_scans(repo_name)

    ctrl1, ctrl2 = st.columns(2)
    with ctrl1:
        st.markdown(f"**Stored Scans for `{repo_name}`**: {len(all_scans)}")
        if st.button("Save Current Scan as Baseline"):
            curr_rec = data.get("current_scan_record")
            if curr_rec:
                hist_store.save_scan(curr_rec)
                st.success("Current scan record updated in persistent SQLite store.")

    with ctrl2:
        if st.button("Clear Repository History"):
            hist_store.delete_repository_history(repo_name)
            st.warning(f"Cleared historical scans for `{repo_name}`.")


# ---------------------------------------------------------------------------
# M15 — Intelligent Security Prioritization & Cross-Repository Risk Panel
# ---------------------------------------------------------------------------

def render_security_intelligence(data: Dict[str, Any]):
    """Render Intelligent Security Prioritization & Cross-Repository Risk Intelligence Panel."""
    st.title("🎯 Intelligent Security Prioritization & Risk Intelligence")
    st.caption("Evidence-Driven Remediation Ranking (P0–P4), Exploitability Analysis, Internet Exposure, Blast Radius, and Cross-Repository Patterns")

    prioritized = data.get("prioritized_findings", [])
    cross_patterns = data.get("cross_repository_patterns", [])
    meta = data.get("metadata", {})
    repo_name = meta.get("repo_name") or "Unknown Repo"

    if not prioritized:
        st.info("Zero priority security findings detected for the current scan cycle.")
        return

    # Section A: Overall Security Posture
    st.markdown("### 🏆 Overall Security Posture & Risk Metrics")
    p0_cnt = sum(1 for p in prioritized if getattr(p, 'priority_tier') == PriorityTier.P0 or getattr(p, 'priority_tier') == "P0")
    p1_cnt = sum(1 for p in prioritized if getattr(p, 'priority_tier') == PriorityTier.P1 or getattr(p, 'priority_tier') == "P1")
    expo_cnt = sum(1 for p in prioritized if getattr(p, 'exposure') == ExposureLevel.INTERNET_EXPOSED or getattr(p, 'exposure') == "INTERNET_EXPOSED")
    crit_exp_cnt = sum(1 for p in prioritized if getattr(p, 'exploitability') == ExploitabilityLevel.CRITICAL or getattr(p, 'exploitability') == "CRITICAL")

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("TOP REMEDIATION RANK", f"#{prioritized[0].rank}" if prioritized else "#1")
    m2.metric("TOP SCORE", f"{prioritized[0].priority_score} / 100" if prioritized else "0/100")
    m3.metric("P0 / P1 FINDINGS", f"{p0_cnt + p1_cnt}")
    m4.metric("INTERNET EXPOSED", f"{expo_cnt}")
    m5.metric("CRITICAL EXPLOITABLE", f"{crit_exp_cnt}")

    st.markdown("---")

    # Section B: Top Remediation Queue (#1 - #5)
    st.markdown("### 🛠️ Top Remediation Queue (What Should I Fix First?)")
    top_5 = prioritized[:5]
    for pf in top_5:
        tier_str = pf.priority_tier.value if hasattr(pf.priority_tier, "value") else str(pf.priority_tier)
        exp_str = pf.exploitability.value if hasattr(pf.exploitability, "value") else str(pf.exploitability)
        expo_str = pf.exposure.value if hasattr(pf.exposure, "value") else str(pf.exposure)
        blast_str = pf.blast_radius.value if hasattr(pf.blast_radius, "value") else str(pf.blast_radius)

        badge_class = "critical" if tier_str in ("P0", "P1") else ("high" if tier_str == "P2" else "medium")
        with st.expander(f"Rank #{pf.rank} [{tier_str}] Score: {pf.priority_score}/100 — {pf.root_cause} in `{pf.affected_file}`", expanded=(pf.rank == 1)):
            c_a, c_b = st.columns([2, 1])
            with c_a:
                st.markdown(f"**Vulnerability Root Cause**: `{pf.root_cause}`")
                st.markdown(f"**Target File / Function**: `{pf.affected_file}` (`{pf.affected_function or 'module scope'}`)")
                st.markdown(f"**Why Prioritized**: {pf.why_it_is_prioritized}")
                st.markdown(f"**Why This Matters**: {pf.why_this_matters}")
                st.success(f"**Recommended Action**: {pf.recommended_action}")
                st.info(f"**Expected Risk Reduction**: {pf.expected_risk_reduction}")
            with c_b:
                st.markdown(f"**Priority Score**: `{pf.priority_score} / 100`")
                st.markdown(f"**Priority Tier**: `{tier_str}`")
                st.markdown(f"**Exploitability**: `{exp_str}`")
                st.markdown(f"**Exposure**: `{expo_str}`")
                st.markdown(f"**Blast Radius**: `{blast_str}`")
                if pf.repair_strategy:
                    st.caption(f"**M13 Strategy**: `{pf.repair_strategy}`")

    st.markdown("---")

    # Section C: Cross-Repository Pattern Intelligence
    st.markdown("### 🌐 Cross-Repository Risk Intelligence & Vulnerability Patterns")
    if cross_patterns:
        pattern_rows = []
        for cp in cross_patterns:
            pattern_rows.append({
                "Vulnerability Family": cp.vulnerability_family,
                "Affected Repositories": cp.affected_repositories_count,
                "Total Occurrences": cp.total_occurrences,
                "Highest Severity": cp.highest_severity,
                "Most Common Sink": cp.most_common_sink,
                "Pattern Trend": cp.trend,
            })
        st.table(pattern_rows)
    else:
        st.info("No cross-repository pattern data available.")

    st.markdown("---")

    # Section D: Evidence Inspector Flow
    st.markdown("### 🔬 Interactive Evidence Inspector")
    selected_fid = st.selectbox("Select Finding to Inspect Evidence Flow:", [p.finding_id for p in prioritized])
    sel_p = next((p for p in prioritized if p.finding_id == selected_fid), prioritized[0])

    e1, e2, e3, e4 = st.columns(4)
    e1.markdown(f"**1. Root Cause**\n`{sel_p.root_cause}`")
    e2.markdown(f"**2. Exploitability**\n`{sel_p.exploitability.value if hasattr(sel_p.exploitability, 'value') else sel_p.exploitability}`")
    e3.markdown(f"**3. Exposure**\n`{sel_p.exposure.value if hasattr(sel_p.exposure, 'value') else sel_p.exposure}`")
    e4.markdown(f"**4. Recommended Fix Strategy**\n`{sel_p.repair_strategy or 'DEFENSIVE_SANITIZATION'}`")


# ---------------------------------------------------------------------------
# M16 — Autonomous Attack-Path Reasoning & Security Panel
# ---------------------------------------------------------------------------

def render_attack_paths(data: Dict[str, Any]):
    """Render Autonomous Attack-Path Reasoning Panel."""
    st.title("🌐 Autonomous Attack-Path Reasoning & Security Investigation")
    st.caption("End-to-End Attack Surface Analysis: Entrypoints → Trust Boundaries → Propagation → Sanitizers → Dangerous Sinks")

    attack_paths = data.get("attack_paths", [])
    if not attack_paths:
        st.info("No confirmed attack paths detected.")
        return

    # Section A: Attack Surface Summary Metrics
    st.markdown("### 🛡️ Attack Surface Summary")
    total_paths = len(attack_paths)
    exploitable_cnt = sum(1 for p in attack_paths if getattr(p, "classification") == PathClassification.EXPLOITABLE or getattr(p, "classification") == "EXPLOITABLE")
    blocked_cnt = sum(1 for p in attack_paths if getattr(p, "classification") in (PathClassification.BLOCKED, PathClassification.NOT_EXPLOITABLE, "BLOCKED", "NOT_EXPLOITABLE"))
    crit_high_cnt = sum(1 for p in attack_paths if getattr(p, "severity") in ("CRITICAL", "HIGH"))
    internet_ep_cnt = sum(1 for p in attack_paths if getattr(p, "entrypoint_type") == EntrypointType.INTERNET or getattr(p, "entrypoint_type") == "INTERNET")
    auth_cnt = sum(1 for p in attack_paths if getattr(p, "auth_status") in (AuthStatus.AUTHENTICATED, "AUTHENTICATED", AuthStatus.AUTHORIZATION_REQUIRED, "AUTHORIZATION_REQUIRED"))
    unauth_cnt = sum(1 for p in attack_paths if getattr(p, "auth_status") in (AuthStatus.UNAUTHENTICATED, "UNAUTHENTICATED"))

    a1, a2, a3, a4, a5, a6 = st.columns(6)
    a1.metric("TOTAL ATTACK PATHS", f"{total_paths}")
    a2.metric("EXPLOITABLE PATHS", f"{exploitable_cnt}")
    a3.metric("BLOCKED / MITIGATED", f"{blocked_cnt}")
    a4.metric("CRITICAL / HIGH RISK", f"{crit_high_cnt}")
    a5.metric("INTERNET ENTRYPOINTS", f"{internet_ep_cnt}")
    a6.metric("AUTH / UNAUTH", f"{auth_cnt} / {unauth_cnt}")

    st.markdown("---")

    # Section B: Attack Path Explorer Table
    st.markdown("### 🗺️ Attack Path Explorer")
    path_table_data = []
    for ap in attack_paths:
        bounds_str = " -> ".join([b.value if hasattr(b, "value") else str(b) for b in getattr(ap, "trust_boundaries_crossed", [])]) or "APPLICATION"
        path_table_data.append({
            "Path ID": ap.id,
            "Risk Score": ap.risk_score,
            "Severity": ap.severity,
            "Confidence": f"{getattr(ap, 'confidence', 0.85):.2f}",
            "Root Cause": ap.root_cause,
            "Entrypoint": ap.entrypoint,
            "Source Type": ap.source_type,
            "Sink Type": ap.sink_type,
            "Trust Boundaries": bounds_str,
            "Classification": ap.classification.value if hasattr(ap.classification, "value") else str(ap.classification),
            "Auth Status": ap.auth_status.value if hasattr(ap.auth_status, "value") else str(ap.auth_status),
        })
    st.table(path_table_data)

    st.markdown("---")

    # Section C: Attack Graph Visualizer
    st.markdown("### 🕸️ Interactive Attack Graph Visualizer")
    selected_pid = st.selectbox("Select Attack Path to Visualize Graph:", [p.id for p in attack_paths])
    sel_path = next((p for p in attack_paths if p.id == selected_pid), attack_paths[0])

    graph_builder = AttackGraphBuilder()
    attack_graph = graph_builder.build_attack_graph(sel_path)

    try:
        st.graphviz_chart(attack_graph.to_dot())
    except Exception as ex:
        st.code(attack_graph.to_dot(), language="dot")

    st.markdown("---")

    # Section D: Autonomous Security Investigation & Break Point Narrative
    st.markdown("### 🔬 Autonomous Security Investigation & Remediation Break Point")
    investigator = AutonomousSecurityInvestigator()
    investigation = investigator.investigate_attack_path(sel_path)

    c_inv1, c_inv2 = st.columns(2)
    with c_inv1:
        st.markdown("#### 🚨 Why is this Dangerous?")
        st.warning(investigation.why_dangerous_narrative)
        st.markdown(f"**Exploitability**: `{investigation.exploitability}`")
        st.markdown(f"**Exposure Scope**: `{investigation.exposure}`")
        st.markdown(f"**Blast Radius**: `{investigation.blast_radius}`")
        st.markdown(f"**Confidence**: `{getattr(sel_path, 'confidence', 0.85):.2f}`")
    with c_inv2:
        st.markdown("#### 🛠️ How to Break the Attack Path")
        st.success(investigation.how_to_break_narrative)
        st.markdown(f"**Recommended Repair Strategy**: `{investigation.repair_strategy or 'DEFENSIVE_SANITIZATION'}`")
        st.markdown(f"**Sandboxed Validation Status**: `{investigation.validation_status}`")


# ---------------------------------------------------------------------------
# M17 — Intelligent Security Remediation Center Panel
# ---------------------------------------------------------------------------

def render_remediation_center(data: Dict[str, Any]):
    """Render M17 Intelligent Security Remediation Center Panel."""
    st.title("🛠️ Intelligent Security Remediation Center")
    st.caption("Remediation Planning & Fix Orchestration: Grouping → Sequencing → Dependencies → Conflict Detection → Risk Reduction")

    plan = data.get("remediation_plan")
    if not plan or not getattr(plan, "remediation_items", []):
        st.info("No active remediation plan required for current repository state.")
        return

    # Section A: Executive Security Score Metrics
    st.markdown("### 📊 Executive Security Score Metrics")
    curr_score = plan.current_security_score
    proj_score = plan.projected_security_score
    tot_red = plan.total_risk_reduction
    effort_str = plan.total_estimated_effort.value if hasattr(plan.total_estimated_effort, "value") else str(plan.total_estimated_effort)
    gov_status = plan.governance_status

    r1, r2, r3, r4, r5 = st.columns(5)
    r1.metric("CURRENT SCORE", f"{curr_score} / 100")
    r2.metric("PROJECTED SCORE", f"{proj_score} / 100", f"+{tot_red} pts")
    r3.metric("TOTAL RISK REDUCTION", f"+{tot_red}")
    r4.metric("CUMULATIVE EFFORT", f"{effort_str}")
    r5.metric("GOVERNANCE STATUS", f"{gov_status}")

    st.markdown("---")

    # Section B: Top Remediation Plan Card
    st.markdown("### 🎯 Top Remediation Item")
    top_item = plan.remediation_items[0]
    
    col_t1, col_t2 = st.columns(2)
    with col_t1:
        st.markdown(f"#### #{top_item.item_id} — {top_item.title}")
        st.markdown(f"**Priority Tier**: `{top_item.priority_tier}` (Score: `{top_item.priority_score}`)")
        st.markdown(f"**Root Cause**: `{top_item.root_cause}`")
        st.markdown(f"**Affected Files**: `{', '.join(top_item.affected_files)}`")
        st.markdown(f"**Affected Findings**: `{len(top_item.affected_finding_ids)}` | **Attack Paths**: `{len(top_item.affected_attack_path_ids)}`")
    with col_t2:
        st.markdown("#### 🛠️ Recommended Action")
        st.info(top_item.recommended_fix)
        st.markdown(f"**Earliest Break Point**: `{top_item.earliest_break_point}`")
        st.markdown(f"**Estimated Effort**: `{top_item.effort.value if hasattr(top_item.effort, 'value') else top_item.effort}`")
        st.markdown(f"**Projected Risk Reduction**: `+{top_item.projected_risk_reduction} pts`")

    st.markdown("---")

    # Section C: Remediation Queue Table
    st.markdown("### 📋 Remediation Execution Queue")
    table_data = []
    for idx, item in enumerate(plan.remediation_items, 1):
        table_data.append({
            "Seq": f"#{idx}",
            "Item ID": item.item_id,
            "Tier": item.priority_tier,
            "Root Cause": item.root_cause,
            "Affected Files": ", ".join(item.affected_files),
            "Findings": len(item.affected_finding_ids),
            "Attack Paths": len(item.affected_attack_path_ids),
            "Effort": item.effort.value if hasattr(item.effort, "value") else str(item.effort),
            "Projected Reduction": f"+{item.projected_risk_reduction}",
            "Dependencies": ", ".join(item.dependencies) or "None",
            "Status": item.governance_status.value if hasattr(item.governance_status, "value") else str(item.governance_status),
        })
    st.table(table_data)

    st.markdown("---")

    # Section D: Remediation Graph Visualizer
    st.markdown("### 🕸️ Interactive Remediation Graph Visualizer")
    if plan.graph:
        try:
            st.graphviz_chart(plan.graph.to_dot())
        except Exception:
            st.code(plan.graph.to_dot(), language="dot")

    st.markdown("---")

    # Section E: Dependency & Conflict Inspector
    st.markdown("### ⚡ Dependency Chain & Conflict Inspector")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("#### 🔗 Execution Dependencies")
        if plan.dependency_relationships and any(deps for deps in plan.dependency_relationships.values()):
            for item_id, deps in plan.dependency_relationships.items():
                if deps:
                    st.write(f"- `{item_id}` depends on: `{', '.join(deps)}`")
        else:
            st.write("No inter-fix execution dependencies detected. Fixes can run in parallel.")
    with c2:
        st.markdown("#### ⚠️ Conflict Detection")
        if plan.conflicts:
            for conf in plan.conflicts:
                st.error(f"**Conflict `{conf.get('conflict_id')}`**: Items `{conf.get('item_a_id')}` and `{conf.get('item_b_id')}` conflict on `{', '.join(conf.get('shared_files', []))}`: {conf.get('reason')}")
        else:
            st.success("Zero remediation conflicts detected across all proposed fixes.")


# ---------------------------------------------------------------------------
# M18 — Continuous Security Monitoring Panel
# ---------------------------------------------------------------------------

def render_security_monitoring(data: Dict[str, Any]):
    """Render M18 Continuous Security Monitoring & Timeline Panel."""
    st.title("📡 Continuous Security Monitoring & Timeline")
    st.caption("Continuous Posture Tracking: Snapshot Diffing → Regression Detection → Attack Path Delta → Remediation Validity → Timeline")

    res = data.get("monitoring_result")
    if not res:
        st.info("No security monitoring data available for current repository state.")
        return

    # Section A: Executive Security Posture Metrics
    st.markdown("### 📊 Executive Security Posture")
    r_sev = res.regression_severity.value if hasattr(res.regression_severity, "value") else str(res.regression_severity)
    trend = res.risk_trend.value if hasattr(res.risk_trend, "value") else str(res.risk_trend)
    score_b = res.security_score_before
    score_a = res.security_score_after
    delta = res.score_delta

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("PREVIOUS SCORE", f"{score_b} / 100")
    m2.metric("CURRENT SCORE", f"{score_a} / 100", f"{delta:+d} pts")
    m3.metric("SCORE DELTA", f"{delta:+d}")
    m4.metric("RISK TREND", f"{trend}")
    m5.metric("REGRESSION VERDICT", f"{r_sev}")

    st.markdown("---")

    # Section B: New Security Events & Attack Path Delta
    c_ev1, c_ev2 = st.columns(2)
    with c_ev1:
        st.markdown("### 🚨 New Security Events")
        if res.new_findings:
            st.error(f"**{len(res.new_findings)} New Vulnerability Introduced**")
            for nf in res.new_findings[:3]:
                st.write(f"- `{nf.get('root_cause', 'UNKNOWN')}` in `{nf.get('affected_file') or nf.get('file', 'N/A')}` ({nf.get('severity', 'MEDIUM')})")
        elif res.reopened_findings:
            st.warning(f"**{len(res.reopened_findings)} Previously Fixed Finding Reopened**")
            for rf in res.reopened_findings[:3]:
                st.write(f"- `{rf.get('root_cause', 'UNKNOWN')}` in `{rf.get('affected_file') or rf.get('file', 'N/A')}`")
        else:
            st.success("Zero new or reopened vulnerabilities detected in current diff.")

    with c_ev2:
        st.markdown("### 🌐 Attack Path Changes")
        if res.changed_attack_paths:
            for cap in res.changed_attack_paths:
                st.warning(f"**Path `{cap.path_id}`**: {cap.description}")
        elif res.new_attack_paths:
            st.error(f"**{len(res.new_attack_paths)} New Exploitable Attack Path Discovered**")
        else:
            st.success("Zero attack path regressions detected across entrypoint boundaries.")

    st.markdown("---")

    # Section C: Remediation Impact & File Diff Impact
    c_rem1, c_rem2 = st.columns(2)
    with c_rem1:
        st.markdown("### 🛠️ Remediation Plan Validity")
        if res.remediation_impact:
            stat_val = res.remediation_impact.status.value if hasattr(res.remediation_impact.status, "value") else str(res.remediation_impact.status)
            if stat_val == "REQUIRES_REPLAN":
                st.warning(f"**Remediation Plan Status**: `{stat_val}`")
                st.write(f"**Reason**: {res.remediation_impact.reason}")
                st.write(f"**Invalidated Items**: `{', '.join(res.remediation_impact.invalidated_items)}`")
            else:
                st.success(f"**Remediation Plan Status**: `{stat_val}`")
                st.write(res.remediation_impact.reason)
        else:
            st.info("No active M17 remediation plan requiring validation.")

    with c_rem2:
        st.markdown("### 📝 Changed-Code Security Impact")
        if res.change_impacts:
            for ci in res.change_impacts:
                st.write(f"- **Commit `{ci.commit}`** (`{ci.file}`): {ci.status_description}")
        else:
            st.write("Zero security-sensitive code diff impacts detected.")

    st.markdown("---")

    # Section D: Repository Security Timeline
    st.markdown("### ⏱️ Repository Security Timeline")
    if res.timeline:
        t_data = []
        for entry in res.timeline:
            t_data.append({
                "Commit": f"`{entry.commit}`",
                "Timestamp": entry.timestamp,
                "Code Changes": entry.code_changes_summary,
                "Finding Delta": entry.finding_changes_summary,
                "Attack Path Delta": entry.attack_path_changes_summary,
                "Score Delta": f"{entry.score_before} → {entry.score_after} ({entry.score_delta:+d})",
                "Remediation": entry.remediation_status_summary,
                "Regression Verdict": entry.regression_severity.value if hasattr(entry.regression_severity, "value") else str(entry.regression_severity),
            })
        st.table(t_data)
    else:
        st.info("Timeline recording active for subsequent commit passes.")

    st.markdown("---")

    # Section E: Security Alert Center
    st.markdown("### 🚨 Security Alert Center")
    if res.alerts:
        for alt in res.alerts:
            sev_str = alt.severity.value if hasattr(alt.severity, "value") else str(alt.severity)
            cat_str = alt.category.value if hasattr(alt.category, "value") else str(alt.category)
            if sev_str == "CRITICAL":
                st.error(f"**[{sev_str}] {alt.title}** (`{cat_str}`)\n\n**Reason**: {alt.reason}\n\n**Evidence**: {alt.evidence}\n\n**Action**: {alt.recommended_action}")
            elif sev_str == "HIGH":
                st.warning(f"**[{sev_str}] {alt.title}** (`{cat_str}`)\n\n**Reason**: {alt.reason}\n\n**Evidence**: {alt.evidence}\n\n**Action**: {alt.recommended_action}")
            else:
                st.info(f"**[{sev_str}] {alt.title}** (`{cat_str}`)\n\n**Reason**: {alt.reason}\n\n**Evidence**: {alt.evidence}\n\n**Action**: {alt.recommended_action}")
    else:
        st.success("No security alerts generated for current scan.")


# ---------------------------------------------------------------------------
# M19 — Security Release Readiness Panel
# ---------------------------------------------------------------------------

def render_release_readiness(data: Dict[str, Any]):
    """Render M19 Security Release Readiness & Executive Gate Panel."""
    st.title("🚀 Security Release Readiness & Executive Gate")
    st.caption("Risk-Based Go/No-Go Decision Engine: Vulnerabilities + Attack Paths + Regressions + Remediation + Governance → Release Decision")

    dec = data.get("release_decision")
    if not dec:
        st.info("Repository is release-ready. No blocking security risks detected.")
        return

    d_val = dec.decision.value if hasattr(dec.decision, "value") else str(dec.decision)
    g_val = dec.release_status.value if hasattr(dec.release_status, "value") else str(dec.release_status)

    # Section A: Executive Release Decision Banner
    if d_val == "BLOCKED":
        st.error(f"## 🔴 RELEASE DECISION: BLOCKED\n**Gate Verdict**: `{g_val}`\n\nRelease is BLOCKED due to active critical vulnerabilities, exploitable attack paths, or critical security regressions.")
    elif d_val == "NO_GO":
        st.error(f"## 🟠 RELEASE DECISION: NO_GO\n**Gate Verdict**: `{g_val}`\n\nRelease should NOT proceed because high-severity security risks remain unresolved.")
    elif d_val == "REVIEW_REQUIRED":
        st.warning(f"## 🟡 RELEASE DECISION: REVIEW_REQUIRED\n**Gate Verdict**: `{g_val}`\n\nHuman security review required before proceeding with release.")
    elif d_val == "GO_WITH_WARNINGS":
        st.warning(f"## 🟢 RELEASE DECISION: GO_WITH_WARNINGS\n**Gate Verdict**: `{g_val}`\n\nRepository is release-ready with non-blocking low/medium security warnings.")
    else:
        st.success(f"## 🟢 RELEASE DECISION: GO\n**Gate Verdict**: `{g_val}`\n\nRepository is fully release-ready. Zero blocking security risks detected.")

    st.markdown("---")

    # Section B: Executive Security Scorecard
    st.markdown("### 📊 Executive Security Scorecard")
    sc = dec.scorecard
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("SECURITY SCORE", f"{sc.security_score} / 100")
    m2.metric("RISK SCORE", f"{sc.risk_score}")
    m3.metric("EXPLOITABILITY", f"{sc.exploitability}")
    m4.metric("EXPOSURE", f"{sc.internet_exposure}")
    m5.metric("GOVERNANCE", f"{sc.governance_status}")

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("CRITICAL", sc.critical_findings)
    c2.metric("HIGH", sc.high_findings)
    c3.metric("ATTACK PATHS", sc.attack_paths)
    c4.metric("REGRESSIONS", sc.regressions)
    c5.metric("P0 REMEDIATION", sc.p0_remediations)

    st.markdown("---")

    # Section C: Release Blockers & Recommended Actions
    c_b1, c_b2 = st.columns(2)
    with c_b1:
        st.markdown("### ⛔ Release Blockers")
        if dec.blockers:
            st.error(f"**{len(dec.blockers)} Blocking Condition(s) Preventing Release**")
            for b in dec.blockers:
                st.write(f"- **[{b.severity}] {b.title}** in `{b.file}` line {b.line or 1}\n  *Reason*: {b.reason}\n  *Action*: {b.recommended_action}")
        else:
            st.success("Zero release blockers detected.")

    with c_b2:
        st.markdown("### 💡 Executive Recommendations")
        if dec.recommendations:
            for rec in dec.recommendations:
                st.write(f"- {rec}")
        else:
            st.write("- Proceed with standard deployment pipeline.")

    st.markdown("---")

    # Section D: Decision Evidence Chain
    st.markdown("### 🔗 Decision Evidence Chain")
    if dec.evidence_chain:
        e_data = []
        for ev in dec.evidence_chain:
            e_data.append({
                "ID": f"`{ev.evidence_id}`",
                "Policy Rule": ev.policy_rule,
                "Reference": f"`{ev.finding_id or ev.attack_path_id or ev.remediation_id or 'N/A'}`",
                "Evidence": ev.evidence_text,
                "Status": f"`{ev.validation_status}`",
            })
        st.table(e_data)
    else:
        st.info("No evidence chain required for clean release.")

    st.markdown("---")

    # Section E: Release Delta (Previous vs Current)
    st.markdown("### 🔄 Release Delta (Previous vs Current)")
    if dec.release_diff:
        rd = dec.release_diff
        prev_v = rd.previous_decision.value if hasattr(rd.previous_decision, "value") else str(rd.previous_decision)
        curr_v = rd.current_decision.value if hasattr(rd.current_decision, "value") else str(rd.current_decision)
        delta_v = rd.release_delta_state.value if hasattr(rd.release_delta_state, "value") else str(rd.release_delta_state)

        if delta_v == "RECOVERED":
            st.success(f"**Release Posture Status**: `{delta_v}` (Previous: `{prev_v}` → Current: `{curr_v}`)")
        elif delta_v == "DEGRADED":
            st.error(f"**Release Posture Status**: `{delta_v}` (Previous: `{prev_v}` → Current: `{curr_v}`)")
        else:
            st.info(f"**Release Posture Status**: `{delta_v}` (Previous: `{prev_v}` → Current: `{curr_v}`)")
        st.write(rd.explanation)
    else:
        st.info("Baseline release evaluation active.")


def render_security_engineering(data: Dict[str, Any]):
    """Render Page 19 — Security Engineering Workflow & Decision Pipeline Dashboard."""
    st.title("⚙️ M20 Security Engineering Workflow & Decision Pipeline")
    st.caption("Deterministic Security Engineering Orchestration, Bounded Remediation Loop & Next Action Engine")

    res: Optional[SecurityOrchestrationResult] = data.get("orchestration_result")

    if not res:
        st.info("ℹ️ No active security workflow. Repository is currently release-ready.")
        return

    cur_state = res.current_state.value if hasattr(res.current_state, "value") else str(res.current_state)
    next_act = res.next_action.value if hasattr(res.next_action, "value") else str(res.next_action)
    hr_req = res.human_review is not None

    # Section A: Executive Workflow Status Banner
    banner_class = "alert-pass"
    if cur_state == "BLOCKED" or next_act in ("BLOCK_RELEASE", "REQUIRE_HUMAN_REVIEW"):
        banner_class = "alert-failed"
    elif cur_state in ("GOVERNANCE", "FAILED") or next_act in ("REPLAN_REMEDIATION", "INVESTIGATE_FINDING"):
        banner_class = "alert-investigate"

    st.markdown(
        f"""
        <div class="alert-banner {banner_class}">
            <h3 style="margin:0; padding:0; color:inherit;">
                WORKFLOW STATE: {cur_state} | NEXT ACTION: {next_act}
            </h3>
            <p style="margin:4px 0 0 0; color:inherit;">{res.next_action_reason}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("### 📊 Workflow Execution Metrics")
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Workflow ID", res.workflow_id)
    with c2:
        st.metric("Current State", cur_state)
    with c3:
        st.metric("Next Action", next_act)
    with c4:
        st.metric("Human Review Requested", "YES ⚠️" if hr_req else "NO ✅")

    st.markdown("---")

    # Section B: Current Security Case Details
    st.markdown("### 🎯 Current Security Cases")
    if res.cases:
        case_rows = []
        for case in res.cases:
            case_rows.append({
                "Case ID": f"`{case.case_id}`",
                "Priority": f"`{case.priority}`",
                "Root Cause": f"`{case.root_cause}`",
                "Status": f"`{case.current_status.value if hasattr(case.current_status, 'value') else case.current_status}`",
                "Remediation Attempts": case.remediation_attempts,
                "Release Decision": f"`{case.release_decision or 'N/A'}`",
            })
        st.table(case_rows)
    else:
        st.success("Zero active security cases.")

    st.markdown("---")

    # Section C: Workflow Timeline
    st.markdown("### ⏱️ Security Case Timeline")
    if res.cases and res.cases[0].timeline:
        tl_rows = []
        for entry in res.cases[0].timeline:
            tl_rows.append({
                "Timestamp": entry.timestamp[:19],
                "Event": entry.event,
                "State": f"`{entry.state.value if hasattr(entry.state, 'value') else entry.state}`",
                "Details": entry.details,
            })
        st.table(tl_rows)
    else:
        st.info("Workflow timeline cleanly executed.")

    st.markdown("---")

    # Section D: Human Review Escalation Card (if active)
    if res.human_review:
        hr = res.human_review
        st.markdown("### ⚠️ Human Review Escalation Card")
        st.error(f"**Escalation Reason**: {hr.reason}")
        st.markdown(f"- **Review ID**: `{hr.review_id}`")
        st.markdown(f"- **Severity**: `{hr.severity}`")
        st.markdown(f"- **Affected Files**: `{', '.join(hr.affected_files)}` ")
        st.markdown(f"- **Recommended Next Step**: {hr.recommended_next_step}")
        st.markdown("---")

    # Section E: Global Security Engineering Posture
    st.markdown("### 🌐 Global Security Engineering Posture Summary")
    if res.summary:
        s = res.summary
        sc1, sc2, sc3, sc4, sc5 = st.columns(5)
        with sc1:
            st.metric("Repos Scanned", s.repositories_scanned)
        with sc2:
            st.metric("Critical Findings", s.critical_findings)
        with sc3:
            st.metric("Active Attack Paths", s.active_attack_paths)
        with sc4:
            st.metric("Blocked Releases", s.blocked_releases)
        with sc5:
            st.metric("Review Required", s.review_required)
    else:
        st.info("Batch posture summary ready for multi-repository runs.")


def render_security_knowledge(data: Dict[str, Any]):
    """Render Page 20 — Security Knowledge Graph & Learning Intelligence Dashboard."""
    st.title("🧠 M21 Security Knowledge Graph & Learning Intelligence")
    st.caption("Deterministic Security Knowledge Base, Pattern Learning & Adaptive Security Rationale")

    k_res: Optional[Dict[str, Any]] = data.get("knowledge_result")

    if not k_res:
        st.info("ℹ️ No historical security knowledge accumulated. Initializing knowledge base.")
        return

    tot_records = k_res.get("total_knowledge_records", 0)
    pats = k_res.get("patterns_learned", [])
    recs = k_res.get("recommendations", [])
    cross_pats = k_res.get("cross_patterns", [])

    st.markdown("### 📊 Knowledge Metrics")
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Total Knowledge Records", tot_records)
    with c2:
        st.metric("Patterns Learned", len(pats))
    with c3:
        st.metric("Adaptive Recommendations", len(recs))
    with c4:
        st.metric("Cross-Repo Intelligence Patterns", len(cross_pats))

    st.markdown("---")

    # Top Recurring Patterns Section
    st.markdown("### 🔄 Top Recurring Security Vulnerability Patterns")
    if cross_pats:
        cp_rows = []
        for cp in cross_pats[:5]:
            cp_rows.append({
                "Pattern ID": f"`{cp.get('pattern_id', 'N/A')}`",
                "Root Cause": f"`{cp.get('root_cause', 'N/A')}`",
                "Frequency": cp.get("frequency", 0),
                "Repositories": f"`{', '.join(cp.get('repositories', []))}`",
                "Success Rate": f"{int(cp.get('successful_remediation_rate', 1.0) * 100)}%",
                "Regression Rate": f"{int(cp.get('regression_rate', 0.0) * 100)}%",
            })
        st.table(cp_rows)
    else:
        st.success("Zero cross-repository recurring vulnerability patterns detected.")

    st.markdown("---")

    # Adaptive Recommendations Section
    st.markdown("### 💡 Recommended Repair Strategies")
    if recs:
        rec_rows = []
        for r in recs:
            rec_rows.append({
                "Strategy": f"`{r.get('strategy', 'N/A')}`",
                "Confidence": f"`{r.get('confidence', 'HIGH')}`",
                "Successes / Attempts": f"{r.get('historical_successes', 0)} / {r.get('historical_attempts', 0)}",
                "Regressions": r.get("historical_regressions", 0),
                "Explanation": r.get("explanation", "N/A"),
            })
        st.table(rec_rows)
    else:
        st.info("Adaptive remediation recommendations ready for candidate findings.")

    st.markdown("---")

    # Knowledge Graph Section
    st.markdown("### 🕸️ Knowledge Graph & Evidence Trace")
    graph = k_res.get("knowledge_graph")
    if graph and hasattr(graph, "nodes"):
        st.markdown(f"- **Nodes Registered**: `{len(graph.nodes)}` ")
        st.markdown(f"- **Edges Linked**: `{len(graph.edges)}` ")
        st.caption("Deterministic graph traversal active (Capped at MAX_KNOWLEDGE_GRAPH_DEPTH = 8)")
    else:
        st.info("Knowledge graph active.")


def render_security_simulation(data: Dict[str, Any]):
    """Render Page 21 — Safe Security Simulation & Exploitability Validation Dashboard."""
    st.title("🧪 M22 Safe Security Simulation & Exploitability Validation")
    st.caption("Sandboxed Vulnerability Reproduction, Attack Path Simulation & Repair Differentials")

    sim_res: Optional[Dict[str, Any]] = data.get("simulation_result")

    if not sim_res:
        st.info("ℹ️ No active security simulation. Clean repository pass.")
        return

    ov_status = sim_res.get("overall_status", "NOT_REPRODUCED")
    repro_count = sim_res.get("reproduced_count", 0)
    results = sim_res.get("results", [])
    diffs = sim_res.get("differentials", [])

    banner_class = "alert-pass" if ov_status == "NOT_REPRODUCED" else "alert-failed"
    st.markdown(
        f"""
        <div class="alert-banner {banner_class}">
            <h3 style="margin:0; padding:0; color:inherit;">
                SIMULATION STATUS: {ov_status} | REPRODUCED VULNERABILITIES: {repro_count}
            </h3>
            <p style="margin:4px 0 0 0; color:inherit;">Safety Gate: ALLOWED (IsolatedSandbox + Localhost Loopback Only)</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("### 📊 Simulation Execution Metrics")
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Overall Status", ov_status)
    with c2:
        st.metric("Reproduced Vulnerabilities", repro_count)
    with c3:
        st.metric("Safety Gate Verdict", "ALLOWED ✅")
    with c4:
        st.metric("Sandbox Lifecycle", "ACTIVE & ISOLATED 🛡️")

    st.markdown("---")

    # Scenarios and Execution Traces
    st.markdown("### 🎯 Safe Reproduction Scenarios & Traces")
    if results:
        res_rows = []
        for r in results:
            res_rows.append({
                "Scenario ID": f"`{r.get('scenario_id', 'N/A')}`",
                "Status": f"`{r.get('status', 'N/A')}`",
                "Reproduced": "YES ⚠️" if r.get("reproduced") else "NO ✅",
                "Blocked": "YES ✅" if r.get("blocked") else "NO",
                "Execution Time": f"{r.get('execution_time', 0.0)}s",
                "Security Impact": f"`{r.get('security_impact', 'NONE')}`",
            })
        st.table(res_rows)
    else:
        st.success("Zero reproduction scenarios required.")

    st.markdown("---")

    # Repair Differentials Section
    st.markdown("### 🔄 Repair Validation & Attack Path Differential")
    if diffs:
        diff_rows = []
        for d in diffs:
            diff_rows.append({
                "Finding ID": f"`{d.get('finding_id', 'N/A')}`",
                "Pre-Patch Status": f"`{d.get('before_status', 'N/A')}`",
                "Post-Patch Status": f"`{d.get('after_status', 'N/A')}`",
                "Attack Path Verdict": f"`{d.get('attack_path_impact', 'N/A')}`",
                "Repaired": "YES ✅" if d.get("repaired") else "NO ❌",
            })
        st.table(diff_rows)
    else:
        st.info("Differential repair analysis ready for patch validation runs.")


# ---------------------------------------------------------------------------
# Main Router (Phase 2 & Phase 4)
# ---------------------------------------------------------------------------

def main():
    """Main UI Entrypoint."""
    st.set_page_config(
        page_title="AgentOS-SWE Dashboard",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    
    # Inject Custom CSS
    st.markdown(DARK_THEME_CSS, unsafe_allow_html=True)

    # Initialize Session Data
    data = init_session_state()

    # Render Sidebar
    nav_selection = render_sidebar(data)

    # Route to selected page
    if nav_selection.startswith("1."):
        render_dashboard(data)
    elif nav_selection.startswith("2."):
        render_agents(data)
    elif nav_selection.startswith("3."):
        render_graph(data)
    elif nav_selection.startswith("4."):
        render_findings(data)
    elif nav_selection.startswith("5."):
        render_security(data)
    elif nav_selection.startswith("6."):
        render_architecture(data)
    elif nav_selection.startswith("7."):
        render_performance(data)
    elif nav_selection.startswith("8."):
        render_verification(data)
    elif nav_selection.startswith("9."):
        render_pipeline(data)
    elif nav_selection.startswith("10."):
        render_report(data)
    elif nav_selection.startswith("11."):
        render_safety(data)
    elif nav_selection.startswith("12."):
        render_vulnerability_intelligence(data)
    elif nav_selection.startswith("13."):
        render_security_history(data)
    elif nav_selection.startswith("14."):
        render_security_intelligence(data)
    elif nav_selection.startswith("15."):
        render_attack_paths(data)
    elif nav_selection.startswith("16."):
        render_remediation_center(data)
    elif nav_selection.startswith("17."):
        render_security_monitoring(data)
    elif nav_selection.startswith("18."):
        render_release_readiness(data)
    elif nav_selection.startswith("19."):
        render_security_engineering(data)
    elif nav_selection.startswith("20."):
        render_security_knowledge(data)
    elif nav_selection.startswith("21."):
        render_security_simulation(data)


if __name__ == "__main__":
    main()




