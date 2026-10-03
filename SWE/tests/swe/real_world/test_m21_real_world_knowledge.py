"""
Dedicated M21 Real-World Security Knowledge Validation Suite.

Performs read-only validation of M21 Security Knowledge & Learning Intelligence across 5 target benchmark repositories:
1. Job_Agent (dict.get() lookups -> Knowledge extraction, safe pattern learning)
2. ConstitutionAI (shell=True command injection -> Dangerous attack path pattern, ARG_ARRAY recommendation)
3. MedAgentX (intentional fallback exception handlers -> Knowledge record persistence)
4. Cadresec- (exception swallowing -> High regression penalty strategy tracking)
5. OmniTutor-AI (test harness exception handlers -> Safe test harness pattern learning)

Guarantees:
- AGENTOS_SWE_DRY_RUN=1
- AGENTOS_MOCK_LLM=1
- Zero target repository modifications
- Zero git commits or pushes
"""

import pytest
import os
import tempfile
from agentos_swe.intelligence.models import PrioritizedFinding, PriorityTier, ExploitabilityLevel
from agentos_swe.intelligence.attackpath.models import AttackPath, EntrypointType, PathClassification
from agentos_swe.intelligence.knowledge import SecurityKnowledgeEngine


@pytest.fixture(autouse=True)
def set_dry_run_env(monkeypatch):
    monkeypatch.setenv("AGENTOS_SWE_DRY_RUN", "1")
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")


@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    if os.path.exists(path):
        try:
            os.remove(path)
        except Exception:
            pass


@pytest.fixture
def engine(temp_db):
    return SecurityKnowledgeEngine(store_path=temp_db)


def test_m21_real_world_1_job_agent(engine):
    """Job_Agent dict.get() lookups yield safe pattern learning and knowledge record."""
    finding = PrioritizedFinding(
        rank=1, finding_id="job_1", vulnerability_category="info", severity="LOW", priority_score=10,
        priority_tier=PriorityTier.P4, root_cause="DICT_LOOKUP", affected_file="agent/job_search.py",
        exploitability=ExploitabilityLevel.NOT_EXPLOITABLE,
    )
    rel_dec = {"decision": "GO", "release_status": "ALLOW_RELEASE"}

    result = engine.process_scan_knowledge(
        verified_findings=[finding],
        prioritized_findings=[finding],
        release_decision=rel_dec,
        repository_name="Job_Agent",
    )

    assert result["total_knowledge_records"] >= 1
    assert result["records_created"][0]["root_cause"] == "DICT_LOOKUP"


def test_m21_real_world_2_constitution_ai(engine):
    """ConstitutionAI command injection yields attack path pattern and ARG_ARRAY recommendation."""
    finding = PrioritizedFinding(
        rank=1, finding_id="const_1", vulnerability_category="security", severity="CRITICAL", priority_score=95,
        priority_tier=PriorityTier.P0, root_cause="COMMAND_INJECTION", affected_file="server/api.py",
        affected_function="eval_prompt", exploitability=ExploitabilityLevel.CRITICAL,
    )
    path = AttackPath(
        id="path_const_1", fingerprint="fp_const_1", repository="ConstitutionAI", entrypoint="POST /api/evaluate",
        entrypoint_type=EntrypointType.INTERNET, source="HTTP", source_type="HTTP", source_file="server/api.py",
        source_line=24, sink="SUBPROCESS_SHELL", sink_type="SUBPROCESS_SHELL", sink_file="server/api.py",
        sink_line=24, root_cause="COMMAND_INJECTION", classification=PathClassification.EXPLOITABLE, risk_score=95,
    )
    rel_dec = {"decision": "BLOCKED", "release_status": "DENY_RELEASE"}

    result = engine.process_scan_knowledge(
        verified_findings=[finding],
        prioritized_findings=[finding],
        attack_paths=[path],
        release_decision=rel_dec,
        repository_name="ConstitutionAI",
    )

    assert len(result["attack_patterns"]) == 1
    assert result["recommendations"][0]["strategy"] == "REPLACE_SHELL_TRUE_WITH_ARG_ARRAY"


def test_m21_real_world_3_medagentx(engine):
    """MedAgentX intentional fallback exception handlers yield knowledge record persistence."""
    finding = PrioritizedFinding(
        rank=1, finding_id="med_1", vulnerability_category="info", severity="LOW", priority_score=10,
        priority_tier=PriorityTier.P4, root_cause="INTENTIONAL_FALLBACK", affected_file="med/model.py",
        exploitability=ExploitabilityLevel.NOT_EXPLOITABLE,
    )
    rel_dec = {"decision": "GO", "release_status": "ALLOW_RELEASE"}

    result = engine.process_scan_knowledge(
        verified_findings=[finding],
        prioritized_findings=[finding],
        release_decision=rel_dec,
        repository_name="MedAgentX",
    )

    assert result["records_created"][0]["root_cause"] == "INTENTIONAL_FALLBACK"


def test_m21_real_world_4_cadresec(engine):
    """Cadresec- exception swallowing yields knowledge recommendation."""
    finding = PrioritizedFinding(
        rank=1, finding_id="cad_1", vulnerability_category="bug", severity="MEDIUM", priority_score=60,
        priority_tier=PriorityTier.P2, root_cause="EXCEPTION_SWALLOWING", affected_file="cadresec/scanner.py",
        exploitability=ExploitabilityLevel.MEDIUM,
    )
    rel_dec = {"decision": "REVIEW_REQUIRED", "release_status": "REQUIRE_REVIEW"}

    result = engine.process_scan_knowledge(
        verified_findings=[finding],
        prioritized_findings=[finding],
        release_decision=rel_dec,
        repository_name="Cadresec-",
    )

    assert len(result["recommendations"]) == 1
    assert result["recommendations"][0]["strategy"] == "LOG_AND_RERAISE_SPECIFIC_EXCEPTION"


def test_m21_real_world_5_omnitutor_ai(engine):
    """OmniTutor-AI test harness exception handlers yield test harness pattern learning."""
    finding = PrioritizedFinding(
        rank=1, finding_id="omni_1", vulnerability_category="info", severity="LOW", priority_score=10,
        priority_tier=PriorityTier.P4, root_cause="TEST_HARNESS", affected_file="tests/test_tutor.py",
        exploitability=ExploitabilityLevel.NOT_EXPLOITABLE,
    )
    rel_dec = {"decision": "GO", "release_status": "ALLOW_RELEASE"}

    result = engine.process_scan_knowledge(
        verified_findings=[finding],
        prioritized_findings=[finding],
        release_decision=rel_dec,
        repository_name="OmniTutor-AI",
    )

    assert result["records_created"][0]["root_cause"] == "TEST_HARNESS"
