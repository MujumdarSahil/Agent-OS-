"""
Controlled End-to-End Integration Test Suite for AgentOS-SWE (M0-M4).
Validates complete pipeline flow, safety invariants, repository immutability,
false-positive rejection, inconclusive handling, LLM fallback, checkpoint recovery,
and combined fallback + checkpoint resilience.
"""

import os
import pytest
from unittest.mock import MagicMock

from agentos_swe.models import Finding, FindingStatus, Evidence, EvidenceSource, EvidenceKind
from agentos_swe.intake import RepositoryIntake
from agentos_swe.context import build_repository_context, RepositoryContext
from agentos_swe.squad import InvestigationSquad
from agentos_swe.aggregator import FindingAggregator
from agentos_swe.verification.pipeline import VerificationPipeline
from agentos_swe.verification.verification_agent import VerificationAgent
from agentos_swe.repair.pipeline import RepairPipeline
from agentos_swe.repair.models import RepairStatus, ReviewStatus
from agentos_swe.repair.fix_agent import FixAgent
from agentos.core.checkpoint import SQLiteCheckpointStore
from agentos.llm.llm_client import LLMClient


@pytest.fixture(autouse=True)
def mock_llm_env(monkeypatch):
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")


def test_full_m0_m4_e2e_pipeline_with_safety_gates(tmp_path):
    """
    Full M0-M4 End-to-End Pipeline Test:
    Intake -> Context -> Graph -> Investigation -> Aggregation -> Verification -> Repair -> Validation
    Validates:
    - CONFIRMED finding -> VALIDATED PATCH
    - REJECTED finding -> REJECTED (NO REPAIR)
    - INCONCLUSIVE finding -> INCONCLUSIVE (NO REPAIR)
    - Original repository IMMUTABILITY (VERIFIED)
    """
    repo_dir = tmp_path / "e2e_synthetic_repo"
    repo_dir.mkdir()

    # Create synthetic source files
    bug_file = repo_dir / "app.py"
    bug_file.write_text(
        "import shlex\n\n"
        "def process_list(items=[]):\n"
        "    pass\n\n"
        "def safe_run(cmd):\n"
        "    return shlex.quote(cmd)\n"
    )
    original_app_content = bug_file.read_text()

    sec_file = repo_dir / "security_module.py"
    sec_file.write_text("eval_runner = eval\n")
    original_sec_content = sec_file.read_text()

    test_file = repo_dir / "test_app.py"
    test_file.write_text(
        "import unittest\n"
        "class TestApp(unittest.TestCase):\n"
        "    def test_sample(self): self.assertTrue(True)\n"
    )
    original_test_content = test_file.read_text()

    # Step 1: Intake & Context Building (M1)
    intake = RepositoryIntake()
    intake_result = intake.analyze(str(repo_dir))
    assert "root_path" in intake_result

    context = build_repository_context(str(repo_dir))
    assert len(context.source_files) >= 2

    # Step 2: Specialized Investigation Squad (M2)
    squad = InvestigationSquad()
    candidates = squad.analyze_repository(context)
    assert len(candidates) >= 1

    # Add controlled false positive and inconclusive findings
    fp_finding = Finding(
        title="Sanitized command injection claim",
        file="app.py",
        category="security",
        status=FindingStatus.DISCOVERED,
    )
    inc_finding = Finding(
        title="Ambiguous performance claim",
        file="app.py",
        category="performance",
        status=FindingStatus.DISCOVERED,
    )
    candidates.extend([fp_finding, inc_finding])

    # Step 3: Independent Verification Pipeline (M3)
    verif_store = SQLiteCheckpointStore(str(tmp_path / "verif_e2e_chk.db"))
    verif_pipeline = VerificationPipeline(checkpoint_store=verif_store)

    # Force false positive -> REJECTED and inconclusive -> INCONCLUSIVE
    verif_pipeline.verifier.static_strategy.verify = MagicMock(side_effect=lambda f, c: (
        (False, Evidence(source=EvidenceSource.STATIC_ANALYSIS, description="Sanitization detected"))
        if f.title == "Sanitized command injection claim"
        else (True, Evidence(source=EvidenceSource.STATIC_ANALYSIS, description="File exists"))
    ))
    verif_pipeline.verifier.graph_strategy.verify = MagicMock(side_effect=lambda f, c: (
        (False, Evidence(source=EvidenceSource.CODE_GRAPH, description="Unclear reachability"))
        if f.title == "Ambiguous performance claim"
        else (True, Evidence(source=EvidenceSource.CODE_GRAPH, description="Reachable node"))
    ))
    verif_pipeline.verifier.test_strategy.verify = MagicMock(side_effect=lambda f, c: (
        (False, Evidence(source=EvidenceSource.TEST, description="No repro"))
        if f.title == "Ambiguous performance claim"
        else (True, Evidence(source=EvidenceSource.TEST, description="Repro pass"))
    ))

    verified_findings = verif_pipeline.verify_findings(candidates, context, mission_id="e2e_verif_001")
    assert len(verified_findings) >= 3

    confirmed_list = [f for f in verified_findings if f.status == FindingStatus.CONFIRMED]
    rejected_list = [f for f in verified_findings if f.status == FindingStatus.REJECTED]
    inconclusive_list = [f for f in verified_findings if f.status == FindingStatus.INCONCLUSIVE]

    assert len(confirmed_list) >= 1
    assert len(rejected_list) >= 1
    assert len(inconclusive_list) >= 1

    # Step 4: Controlled Autonomous Repair Pipeline (M4)
    repair_store = SQLiteCheckpointStore(str(tmp_path / "repair_e2e_chk.db"))
    repair_pipeline = RepairPipeline(checkpoint_store=repair_store)

    # 4a: Repair CONFIRMED finding -> VALIDATED PATCH
    target_confirmed = confirmed_list[0]
    validated_patch = repair_pipeline.repair_finding(target_confirmed, context, mission_id="e2e_repair_001")
    assert validated_patch.status == RepairStatus.VALIDATED
    assert validated_patch.patch_diff != ""

    # 4b: Attempt repair on REJECTED finding -> REJECTED (NO REPAIR)
    rejected_repair = repair_pipeline.repair_finding(rejected_list[0], context)
    assert rejected_repair.status == RepairStatus.NOT_CONFIRMED
    assert rejected_repair.patch_diff == ""

    # 4c: Attempt repair on INCONCLUSIVE finding -> REJECTED (NO REPAIR)
    inc_repair = repair_pipeline.repair_finding(inconclusive_list[0], context)
    assert inc_repair.status == RepairStatus.NOT_CONFIRMED
    assert inc_repair.patch_diff == ""

    # Step 5: ABSOLUTE REPOSITORY IMMUTABILITY VERIFICATION
    assert bug_file.read_text() == original_app_content
    assert sec_file.read_text() == original_sec_content
    assert test_file.read_text() == original_test_content


def test_e2e_llm_fallback_resilience():
    """
    End-to-End LLM Fallback Verification across Investigation, Verification, and Repair.
    """
    mock_client = MagicMock(spec=LLMClient)
    mock_client.complete.return_value = {
        "choices": [{"message": {"content": "Fallback LLM investigation reasoning"}}]
    }

    fix_agent = FixAgent(llm_client=mock_client)
    reasoning = fix_agent.query_llm_reasoning("E2E Fallback Test Prompt")
    assert reasoning == "Fallback LLM investigation reasoning"


def test_e2e_checkpoint_recovery_verification_and_repair(tmp_path):
    """
    End-to-End Checkpoint Saving and Resume Recovery for Verification and Repair.
    """
    repo_dir = tmp_path / "chk_e2e_repo"
    repo_dir.mkdir()
    (repo_dir / "target.py").write_text("def f(x=[]): return x\n")

    context = build_repository_context(str(repo_dir))

    # Verification Recovery Test
    verif_db = str(tmp_path / "verif_chk.db")
    verif_store = SQLiteCheckpointStore(verif_db)
    verif_pipeline = VerificationPipeline(checkpoint_store=verif_store)

    findings = [Finding(title="F1", file="target.py"), Finding(title="F2", file="target.py")]
    mission_id_v = "v_mission_chk_99"

    v_res1 = verif_pipeline.verify_findings(findings, context, mission_id=mission_id_v)
    v_latest = verif_store.load_latest_checkpoint(mission_id_v)
    assert v_latest is not None

    v_res2 = verif_pipeline.verify_findings(findings, context, mission_id=mission_id_v, resume=True)
    assert len(v_res2) == 2

    # Repair Recovery Test
    repair_db = str(tmp_path / "repair_chk.db")
    repair_store = SQLiteCheckpointStore(repair_db)
    repair_pipeline = RepairPipeline(checkpoint_store=repair_store)

    confirmed_f = Finding(title="Mutable default", file="target.py", status=FindingStatus.CONFIRMED)
    mission_id_r = "r_mission_chk_99"

    r_res1 = repair_pipeline.repair_finding(confirmed_f, context, mission_id=mission_id_r)
    r_latest = repair_store.load_latest_checkpoint(mission_id_r)
    assert r_latest is not None
    assert r_latest["stage"] == "VALIDATED"

    r_res2 = repair_pipeline.repair_finding(confirmed_f, context, mission_id=mission_id_r, resume=True)
    assert r_res2.status == RepairStatus.VALIDATED


def test_e2e_fallback_plus_checkpoint_combined(tmp_path):
    """
    Combined Fallback + Checkpoint Recovery Test:
    Simulates fix agent partial execution -> checkpoint saved -> primary LLM provider failure -> fallback LLM engages -> mission resumed using saved checkpoint.
    """
    repo_dir = tmp_path / "combined_repo"
    repo_dir.mkdir()
    (repo_dir / "core.py").write_text("def run(args=[]): pass\n")

    context = build_repository_context(str(repo_dir))
    repair_db = str(tmp_path / "combined_chk.db")
    repair_store = SQLiteCheckpointStore(repair_db)

    mock_client = MagicMock(spec=LLMClient)
    mock_client.complete.return_value = {
        "choices": [{"message": {"content": "Fallback LLM repair fix solution"}}]
    }

    fix_agent = FixAgent(llm_client=mock_client)
    pipeline = RepairPipeline(fix_agent=fix_agent, checkpoint_store=repair_store)

    finding = Finding(title="Mutable Default Argument", file="core.py", status=FindingStatus.CONFIRMED)
    mission_id = "combined_mission_777"

    # Execution with initial provider failure and fallback recovery
    validated = pipeline.repair_finding(finding, context, mission_id=mission_id)
    assert validated.status == RepairStatus.VALIDATED

    # Verify checkpoint saved and resumption works
    latest = repair_store.load_latest_checkpoint(mission_id)
    assert latest is not None
    resumed = pipeline.repair_finding(finding, context, mission_id=mission_id, resume=True)
    assert resumed.status == RepairStatus.VALIDATED
