"""
Targeted tests for M5 GitHub PR Automation & Risk Governance.
"""

import os
import pytest
from unittest.mock import MagicMock

from agentos_swe.core.models import Finding, FindingStatus
from agentos_swe.remediation.repair.models import ValidatedPatch, ImpactReport, PatchReviewResult, ReviewStatus, RepairStatus
from agentos_swe.core.context import build_repository_context
from agentos_swe.remediation.pr.models import RiskLevel, GovernanceDecision, PRResult
from agentos_swe.remediation.pr.risk import RiskAnalyzer
from agentos_swe.remediation.pr.governance_gate import GovernanceGate
from agentos_swe.remediation.pr.provider import GitHubAdapter, redact_secrets
from agentos_swe.remediation.pr.pr_generator import PRDescriptionGenerator
from agentos_swe.remediation.pr.pipeline import PRPipeline
from agentos.core.checkpoint import SQLiteCheckpointStore
from agentos.core.governance import GovernanceEngine


@pytest.fixture(autouse=True)
def mock_llm_env(monkeypatch):
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")


def test_risk_analyzer_scoring():
    analyzer = RiskAnalyzer()

    finding_low = Finding(title="Minor doc update", severity="low")
    impact_low = ImpactReport(finding_id=finding_low.id, target_file="utils.py")
    patch_low = ValidatedPatch(
        finding_id=finding_low.id,
        patch_diff="--- a/utils.py\n+++ b/utils.py\n+# comment\n",
        changed_files=["utils.py"],
        impact_report=impact_low,
        reproduction_result={"success": True},
        regression_result={"success": True},
        review_result=PatchReviewResult(status=ReviewStatus.APPROVED, reason="ok"),
    )

    risk_low = analyzer.analyze_risk(finding_low, patch_low)
    assert risk_low.risk_level == RiskLevel.LOW

    # High risk security sensitive file
    finding_high = Finding(title="Auth vulnerability", severity="critical")
    impact_high = ImpactReport(finding_id=finding_high.id, target_file="auth_config.py")
    patch_high = ValidatedPatch(
        finding_id=finding_high.id,
        patch_diff="--- a/auth_config.py\n+++ b/auth_config.py\n+secret=1\n",
        changed_files=["auth_config.py"],
        impact_report=impact_high,
        reproduction_result={"success": True},
        regression_result={"success": True},
        review_result=PatchReviewResult(status=ReviewStatus.APPROVED, reason="ok"),
    )

    risk_high = analyzer.analyze_risk(finding_high, patch_high)
    assert risk_high.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)


def test_governance_gate_decisions():
    gate = GovernanceGate()

    finding = Finding(title="Low Risk Bug", severity="low")
    patch = ValidatedPatch(
        finding_id=finding.id,
        patch_diff="",
        changed_files=["app.py"],
        impact_report=ImpactReport(finding_id=finding.id, target_file="app.py"),
        reproduction_result={"success": True},
        regression_result={"success": True},
        review_result=PatchReviewResult(status=ReviewStatus.APPROVED, reason="ok"),
    )

    risk_low = RiskAnalyzer().analyze_risk(finding, patch)
    decision = gate.evaluate(risk_low)
    assert decision == GovernanceDecision.ALLOW


def test_secret_token_redaction():
    raw_token_text = "Connecting with token ghp_1234567890abcdef1234567890abcdef1234 and Bearer secret_xyz"
    redacted = redact_secrets(raw_token_text)

    assert "ghp_" not in redacted
    assert "[REDACTED_GITHUB_TOKEN]" in redacted
    assert "[REDACTED_TOKEN]" in redacted


def test_github_adapter_dry_run_mode():
    adapter = GitHubAdapter(github_token="ghp_mock123", dry_run=True)
    res = adapter.create_pull_request(
        repository_path="/mock/path",
        title="fix: patch",
        body="details",
        head_branch="patch_branch",
    )

    assert res["success"] is True
    assert res["dry_run"] is True
    assert "https://github.com/example/repo/pull/" in res["pr_url"]


def test_duplicate_pr_idempotency_detection():
    adapter = GitHubAdapter(dry_run=True)
    res = adapter.create_pull_request(
        repository_path="/mock/path",
        title="fix: patch",
        body="details",
        head_branch="patch_branch_existing_pr",
    )

    assert res["success"] is True
    assert res.get("duplicate") is True
    assert res["pr_number"] == 42


def test_pr_pipeline_dry_run_execution(tmp_path):
    db_file = str(tmp_path / "pr_checkpoints.db")
    store = SQLiteCheckpointStore(db_file)
    pipeline = PRPipeline(checkpoint_store=store, dry_run=True)

    repo_dir = tmp_path / "pr_repo"
    repo_dir.mkdir()
    (repo_dir / "app.py").write_text("def f(): pass\n")
    context = build_repository_context(str(repo_dir))

    finding = Finding(title="Default arg flaw", file="app.py", severity="low")
    patch = ValidatedPatch(
        finding_id=finding.id,
        patch_diff="--- a/app.py\n+++ b/app.py\n+pass\n",
        changed_files=["app.py"],
        impact_report=ImpactReport(finding_id=finding.id, target_file="app.py"),
        reproduction_result={"success": True},
        regression_result={"success": True},
        review_result=PatchReviewResult(status=ReviewStatus.APPROVED, reason="ok"),
    )

    mission_id = "pr_mission_test_99"
    pr_result = pipeline.execute_pr_pipeline(finding, patch, context, mission_id=mission_id)

    assert pr_result.success is True
    assert pr_result.dry_run is True
    assert "AgentOS-SWE Automated Repair Patch" in pr_result.pr_body

    # Checkpoint recovery test
    latest = store.load_latest_checkpoint(mission_id)
    assert latest is not None
    assert latest["stage"] == "PR_CREATED"

    resumed = pipeline.execute_pr_pipeline(finding, patch, context, mission_id=mission_id, resume=True)
    assert resumed.success is True
