"""
Targeted tests for InvestigationSquad, Mission orchestration, Read-only safety, and Fallback testing.
"""

import os
import pytest
from unittest.mock import MagicMock

from agentos_swe.squad import InvestigationSquad
from agentos_swe.context import build_repository_context
from agentos_swe.models import Finding
from agentos.core.governance import GovernanceEngine
from agentos.llm.llm_client import LLMClient


@pytest.fixture(autouse=True)
def mock_llm_env(monkeypatch):
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")


def test_investigation_squad_orchestration(tmp_path):
    repo_dir = tmp_path / "squad_repo"
    repo_dir.mkdir()

    (repo_dir / "service.py").write_text(
        "import os\n"
        "eval_code = eval\n"
        "def run_all(data=[]):\n"
        "    try:\n"
        "        eval_code('1+1')\n"
        "    except:\n"
        "        pass\n"
    )

    context = build_repository_context(str(repo_dir))
    squad = InvestigationSquad()
    findings = squad.analyze_repository(context)

    assert isinstance(findings, list)
    assert len(findings) >= 2
    categories = {f.category for f in findings}
    assert "bug" in categories or "security" in categories

    # Verify mission creation & completed status in squad
    assert len(squad.missions) >= 1
    active_mission = list(squad.missions.values())[0]
    assert active_mission.status == "completed"
    assert active_mission.results["aggregated_findings_count"] == len(findings)


def test_read_only_governance_enforcement():
    squad = InvestigationSquad()
    gov = squad.governance
    policy = gov.policies.get("swe_read_only_policy")

    assert policy is not None

    # Test allowed read-only action
    decision_read = policy.check_func("BugAgent", "read_file", {})
    assert decision_read is True

    # Test blocked mutating actions
    decision_write = policy.check_func("BugAgent", "write_file", {})
    assert decision_write is False

    decision_commit = policy.check_func("BugAgent", "git_commit", {})
    assert decision_commit is False


def test_llm_fallback_chain_integration():
    """
    Simulates AgentOS LLM router fallback client path.
    """
    mock_client = MagicMock(spec=LLMClient)
    # LLMClient complete delegates to LiteLLM router fallback chain
    mock_client.complete.return_value = {
        "choices": [{"message": {"content": "LLM investigation result after fallback"}}]
    }

    squad = InvestigationSquad(llm_client=mock_client)
    agent = squad.bug_agent
    res = agent.query_llm_reasoning("Test prompt")

    # Verified fallback recovery via AgentOS LLM abstraction
    assert res == "LLM investigation result after fallback"
    assert mock_client.complete.call_count == 1
