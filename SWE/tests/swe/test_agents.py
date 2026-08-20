"""
Targeted tests for M2 Specialized Investigation Agents.
"""

import os
import pytest
from unittest.mock import MagicMock

from agentos_swe.agents.bug_agent import BugAgent
from agentos_swe.agents.security_agent import SecurityAgent
from agentos_swe.agents.performance_agent import PerformanceAgent
from agentos_swe.agents.architecture_agent import ArchitectureAgent
from agentos_swe.context import build_repository_context, RepositoryContext
from agentos_swe.models import EvidenceSource, EvidenceKind
from agentos.llm.llm_client import LLMClient


@pytest.fixture(autouse=True)
def mock_llm_env(monkeypatch):
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")


def test_bug_agent_investigation(tmp_path):
    repo_dir = tmp_path / "bug_repo"
    repo_dir.mkdir()

    (repo_dir / "buggy.py").write_text(
        "def process(items=[]):\n"
        "    try:\n"
        "        pass\n"
        "    except:\n"
        "        pass\n"
        "    return 1\n"
        "    print('unreachable')\n"
    )

    context = build_repository_context(str(repo_dir))
    agent = BugAgent()
    findings = agent.investigate(context)

    assert len(findings) >= 2
    titles = [f.title for f in findings]
    assert any("Mutable Default Argument" in t for t in titles)
    assert any("Swallowed or Bare Exception" in t for t in titles)

    for f in findings:
        assert f.category == "bug"
        assert len(f.evidence) > 0
        assert f.evidence[0].source == EvidenceSource.STATIC_ANALYSIS


def test_security_agent_investigation(tmp_path):
    repo_dir = tmp_path / "sec_repo"
    repo_dir.mkdir()

    (repo_dir / "unsafe.py").write_text(
        "import subprocess\n"
        "import pickle\n"
        "api_key = 'AKIA1234567890ABCDEF'\n"
        "def run_cmd(user_input):\n"
        "    eval(user_input)\n"
        "    subprocess.run(user_input, shell=True)\n"
        "    pickle.loads(user_input)\n"
    )

    context = build_repository_context(str(repo_dir))
    agent = SecurityAgent()
    findings = agent.investigate(context)

    assert len(findings) >= 3
    titles = [f.title for f in findings]
    assert any("Dangerous Function 'eval'" in t for t in titles)
    assert any("shell=True" in t for t in titles)
    assert any("Unsafe Deserialization" in t for t in titles)

    for f in findings:
        assert f.category == "security"


def test_performance_agent_investigation(tmp_path):
    repo_dir = tmp_path / "perf_repo"
    repo_dir.mkdir()

    (repo_dir / "slow.py").write_text(
        "import requests\n"
        "def fetch_all(urls):\n"
        "    for url in urls:\n"
        "        open(url, 'r')\n"
    )

    context = build_repository_context(str(repo_dir))
    agent = PerformanceAgent()
    findings = agent.investigate(context)

    assert len(findings) >= 1
    assert findings[0].category == "performance"
    assert "Repeated 'open' Call inside Loop" in findings[0].title
    assert any(e.kind == EvidenceKind.INFERRED for e in findings[0].evidence)


def test_architecture_agent_investigation(tmp_path):
    repo_dir = tmp_path / "arch_repo"
    repo_dir.mkdir()

    (repo_dir / "mod_a.py").write_text("import mod_b\n")
    (repo_dir / "mod_b.py").write_text("import mod_a\n")

    context = build_repository_context(str(repo_dir))
    agent = ArchitectureAgent()
    findings = agent.investigate(context)

    assert len(findings) >= 1
    assert findings[0].category == "architecture"
    assert "Circular Module Dependency" in findings[0].title
    assert findings[0].evidence[0].source == EvidenceSource.CODE_GRAPH


def test_agent_no_finding_case(tmp_path):
    repo_dir = tmp_path / "clean_repo"
    repo_dir.mkdir()
    (repo_dir / "clean.py").write_text("def add(a, b):\n    return a + b\n")

    context = build_repository_context(str(repo_dir))
    bug_agent = BugAgent()
    sec_agent = SecurityAgent()

    assert len(bug_agent.investigate(context)) == 0
    assert len(sec_agent.investigate(context)) == 0


def test_agent_malformed_context_and_error_handling():
    ctx = RepositoryContext(name="malformed", repository_path="/invalid/path/99999")
    agent = BugAgent()
    # Should handle gracefully without crashing
    findings = agent.investigate(ctx)
    assert isinstance(findings, list)
