"""
Targeted tests for M3 Independent Verification, Sandbox, Checkpointing, and True/False Positive Handling.
"""

import os
import pytest
from unittest.mock import MagicMock

from agentos_swe.core.models import (
    Finding,
    Evidence,
    FindingStatus,
    EvidenceSource,
    EvidenceKind,
)
from agentos_swe.core.context import build_repository_context, RepositoryContext
from agentos_swe.analysis.verification.sandbox import IsolatedSandbox
from agentos_swe.analysis.verification.verification_agent import VerificationAgent
from agentos_swe.analysis.verification.pipeline import VerificationPipeline
from agentos.core.checkpoint import SQLiteCheckpointStore
from agentos.llm.llm_client import LLMClient


@pytest.fixture(autouse=True)
def mock_llm_env(monkeypatch):
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")


def test_isolated_sandbox_lifecycle(tmp_path):
    saved_path = None
    with IsolatedSandbox() as sandbox:
        saved_path = sandbox.path
        assert os.path.exists(saved_path)
        sandbox.write_file("test.py", "print('hello from sandbox')\n")
        res = sandbox.run_command(["python", "test.py"])

        assert res["success"] is True
        assert "hello from sandbox" in res["stdout"]

    # Verify workspace destroyed after exit
    assert saved_path is not None
    assert not os.path.exists(saved_path)


def test_verification_confirmed_true_positive(tmp_path):
    repo_dir = tmp_path / "true_positive_repo"
    repo_dir.mkdir()
    (repo_dir / "vuln.py").write_text("eval_func = eval\n")

    context = build_repository_context(str(repo_dir))
    verifier = VerificationAgent()

    candidate = Finding(
        category="security",
        severity="critical",
        title="Use of Dangerous Function 'eval'",
        file="vuln.py",
        status=FindingStatus.DISCOVERED,
        confidence=0.8,
    )

    result = verifier.verify_finding(candidate, context)

    assert result.status == FindingStatus.CONFIRMED
    assert result.confidence >= 0.8
    assert len(result.evidence) >= 2


def test_verification_rejected_false_positive(tmp_path):
    repo_dir = tmp_path / "false_positive_repo"
    repo_dir.mkdir()
    (repo_dir / "safe.py").write_text(
        "import shlex\n"
        "def safe_run(cmd):\n"
        "    quoted = shlex.quote(cmd)\n"
    )

    context = build_repository_context(str(repo_dir))
    verifier = VerificationAgent()

    # Suspicious injection claim on missing file
    candidate_missing = Finding(
        category="bug",
        title="Logic defect in missing file",
        file="non_existent.py",
        status=FindingStatus.DISCOVERED,
    )
    result_missing = verifier.verify_finding(candidate_missing, context)
    assert result_missing.status == FindingStatus.REJECTED

    # False positive claim on sanitized code
    candidate_sanitized = Finding(
        category="security",
        title="Use of Dangerous Function 'eval'",
        file="safe.py",
        status=FindingStatus.DISCOVERED,
    )
    result_sanitized = verifier.verify_finding(candidate_sanitized, context)
    assert result_sanitized.status == FindingStatus.REJECTED


def test_verification_inconclusive_insufficient_evidence(tmp_path):
    repo_dir = tmp_path / "inconclusive_repo"
    repo_dir.mkdir()
    (repo_dir / "ambiguous.py").write_text("x = 10\n")

    context = build_repository_context(str(repo_dir))
    verifier = VerificationAgent()

    # Candidate finding without exact symbol or test reproduction capability
    candidate = Finding(
        category="performance",
        title="Potential subtle performance regression",
        file="ambiguous.py",
        status=FindingStatus.DISCOVERED,
    )

    # Force graph and test strategy to return False for ambiguous checks
    verifier.graph_strategy.verify = MagicMock(return_value=(False, Evidence(source=EvidenceSource.CODE_GRAPH, description="Unclear graph context")))
    verifier.test_strategy.verify = MagicMock(return_value=(False, Evidence(source=EvidenceSource.TEST, description="Reproduction test unavailable")))
    result = verifier.verify_finding(candidate, context)
    assert result.status == FindingStatus.INCONCLUSIVE


def test_verification_pipeline_checkpoint_and_recovery(tmp_path):
    db_file = str(tmp_path / "test_checkpoints.db")
    store = SQLiteCheckpointStore(db_file)
    pipeline = VerificationPipeline(checkpoint_store=store)

    repo_dir = tmp_path / "chk_repo"
    repo_dir.mkdir()
    (repo_dir / "f1.py").write_text("pass\n")
    (repo_dir / "f2.py").write_text("pass\n")

    context = build_repository_context(str(repo_dir))

    findings = [
        Finding(title="F1", file="f1.py"),
        Finding(title="F2", file="f2.py"),
    ]

    mission_id = "test_chk_mission_100"
    verified = pipeline.verify_findings(findings, context, mission_id=mission_id)
    assert len(verified) == 2

    # Check latest checkpoint loaded
    latest = store.load_latest_checkpoint(mission_id)
    assert latest is not None
    assert latest["task_index"] == 1

    # Test resume
    resumed_results = pipeline.verify_findings(findings, context, mission_id=mission_id, resume=True)
    assert len(resumed_results) == 2


def test_verification_llm_fallback_resilience():
    mock_client = MagicMock(spec=LLMClient)
    mock_client.complete.return_value = {
        "choices": [{"message": {"content": "Fallback LLM verification rationale"}}]
    }

    verifier = VerificationAgent(llm_client=mock_client)
    res = verifier.query_llm_reasoning("Adversarial prompt")
    assert res == "Fallback LLM verification rationale"
    assert mock_client.complete.call_count == 1
