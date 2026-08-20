"""
Targeted tests for M4 Controlled Autonomous Repair, Sandbox Safety, Checkpointing, and Patch Review.
"""

import os
import pytest
from unittest.mock import MagicMock

from agentos_swe.models import Finding, FindingStatus, Evidence, EvidenceSource
from agentos_swe.context import build_repository_context, RepositoryContext
from agentos_swe.repair.models import (
    RepairStatus,
    ReviewStatus,
    ImpactReport,
    FixPlan,
    PatchResult,
)
from agentos_swe.repair.impact import ImpactAnalyzer
from agentos_swe.repair.planner import FixPlanner
from agentos_swe.repair.fix_agent import FixAgent
from agentos_swe.repair.reviewer import IndependentPatchReviewer
from agentos_swe.repair.pipeline import RepairPipeline
from agentos_swe.verification.sandbox import IsolatedSandbox
from agentos.core.checkpoint import SQLiteCheckpointStore
from agentos.llm.llm_client import LLMClient


@pytest.fixture(autouse=True)
def mock_llm_env(monkeypatch):
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")


def test_safety_non_confirmed_findings_rejected(tmp_path):
    """
    Mandatory Safety Invariant Test:
    Findings with INCONCLUSIVE, REJECTED, or DISCOVERED status MUST NOT be repaired.
    """
    repo_dir = tmp_path / "safety_repo"
    repo_dir.mkdir()
    (repo_dir / "app.py").write_text("def f(): pass\n")

    context = build_repository_context(str(repo_dir))
    pipeline = RepairPipeline()

    for invalid_status in [FindingStatus.INCONCLUSIVE, FindingStatus.REJECTED, FindingStatus.DISCOVERED, FindingStatus.INVESTIGATING]:
        finding = Finding(
            title="Non Confirmed Finding",
            file="app.py",
            status=invalid_status,
        )
        res = pipeline.repair_finding(finding, context)
        assert res.status == RepairStatus.NOT_CONFIRMED
        assert res.patch_diff == ""


def test_original_repository_remains_unchanged(tmp_path):
    """
    Mandatory Safety Invariant Test:
    Original repository source code must remain 100% UNCHANGED after repair execution.
    """
    repo_dir = tmp_path / "unchanged_repo"
    repo_dir.mkdir()
    app_path = repo_dir / "app.py"
    original_content = "def process(items=[]):\n    pass\n"
    app_path.write_text(original_content)

    context = build_repository_context(str(repo_dir))
    pipeline = RepairPipeline()

    confirmed_finding = Finding(
        title="Mutable Default Argument",
        file="app.py",
        status=FindingStatus.CONFIRMED,
    )

    validated_patch = pipeline.repair_finding(confirmed_finding, context)

    # Validated patch produced
    assert validated_patch.status == RepairStatus.VALIDATED
    assert validated_patch.patch_diff != ""

    # ORIGINAL FILE MUST BE UNCHANGED
    current_content = app_path.read_text()
    assert current_content == original_content


def test_impact_analyzer_and_fix_planner(tmp_path):
    repo_dir = tmp_path / "impact_repo"
    repo_dir.mkdir()
    (repo_dir / "mod_a.py").write_text("import mod_b\n")
    (repo_dir / "mod_b.py").write_text("def helper(): pass\n")

    context = build_repository_context(str(repo_dir))

    finding = Finding(
        title="Refactor bug",
        file="mod_b.py",
        symbol="helper",
        status=FindingStatus.CONFIRMED,
    )

    analyzer = ImpactAnalyzer()
    report = analyzer.analyze(finding, context)

    assert report.target_file == "mod_b.py"
    assert "mod_b.py" in report.affected_files

    planner = FixPlanner()
    plan = planner.plan_fix(finding, report, context)
    assert plan.target_file == "mod_b.py"


def test_fix_agent_sandbox_patch_generation(tmp_path):
    repo_dir = tmp_path / "patch_repo"
    repo_dir.mkdir()
    (repo_dir / "vuln.py").write_text("eval_func = eval\n")

    context = build_repository_context(str(repo_dir))
    fix_agent = FixAgent()

    finding = Finding(title="Use of Dangerous Function 'eval'", file="vuln.py", status=FindingStatus.CONFIRMED)
    plan = FixPlan(finding_id=finding.id, target_file="vuln.py", defect_summary="eval flaw", proposed_fix_strategy="Use literal_eval")

    with IsolatedSandbox() as sandbox:
        patch_res = fix_agent.generate_patch(finding, plan, sandbox, context)
        assert patch_res.success is True
        assert "ast.literal_eval" in patch_res.patch_content
        assert patch_res.diff != ""

    # Check original repo untouched
    assert (repo_dir / "vuln.py").read_text() == "eval_func = eval\n"


def test_independent_patch_reviewer_approval_and_rejection():
    reviewer = IndependentPatchReviewer()
    finding = Finding(title="Test Bug", status=FindingStatus.CONFIRMED)
    plan = FixPlan(finding_id=finding.id, target_file="app.py", defect_summary="bug", proposed_fix_strategy="fix")

    # 1. Approved Minimal Patch
    good_patch = PatchResult(success=True, diff="--- a/app.py\n+++ b/app.py\n-x=1\n+x=2\n", changed_files=["app.py"])
    review_good = reviewer.review_patch(finding, plan, good_patch)
    assert review_good.status == ReviewStatus.APPROVED

    # 2. Rejected Dangerous Patch
    bad_patch = PatchResult(success=True, diff="--- a/app.py\n+++ b/app.py\n+os.system('rm -rf /')\n", changed_files=["app.py"])
    review_bad = reviewer.review_patch(finding, plan, bad_patch)
    assert review_bad.status == ReviewStatus.REJECTED


def test_repair_pipeline_checkpoint_saving_and_resume(tmp_path):
    db_file = str(tmp_path / "repair_checkpoints.db")
    store = SQLiteCheckpointStore(db_file)
    pipeline = RepairPipeline(checkpoint_store=store)

    repo_dir = tmp_path / "chk_repair_repo"
    repo_dir.mkdir()
    (repo_dir / "app.py").write_text("def f(items=[]): pass\n")

    context = build_repository_context(str(repo_dir))
    finding = Finding(title="Mutable Default Argument", file="app.py", status=FindingStatus.CONFIRMED)

    mission_id = "repair_chk_test_555"
    validated = pipeline.repair_finding(finding, context, mission_id=mission_id)

    assert validated.status == RepairStatus.VALIDATED
    latest = store.load_latest_checkpoint(mission_id)
    assert latest is not None
    assert latest["stage"] == "VALIDATED"

    # Test resume recovery
    resumed = pipeline.repair_finding(finding, context, mission_id=mission_id, resume=True)
    assert resumed.status == RepairStatus.VALIDATED


def test_repair_llm_fallback_resilience():
    mock_client = MagicMock(spec=LLMClient)
    mock_client.complete.return_value = {
        "choices": [{"message": {"content": "Fallback patch generation strategy"}}]
    }

    fix_agent = FixAgent(llm_client=mock_client)
    res = fix_agent.query_llm_reasoning("Repair prompt")

    assert res == "Fallback patch generation strategy"
    assert mock_client.complete.call_count == 1
