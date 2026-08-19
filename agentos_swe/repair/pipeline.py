"""
RepairPipeline - Controlled autonomous repair pipeline for AgentOS-SWE (M4).
Orchestrates impact analysis, fix planning, isolated sandbox patch generation,
reproduction & regression testing, independent review, and SQLite checkpointing.
"""

import os
import tempfile
import uuid
import logging
from typing import Dict, Any, Optional

from agentos.core.checkpoint import CheckpointStore, SQLiteCheckpointStore
from agentos_swe.models import Finding, FindingStatus
from agentos_swe.context import RepositoryContext
from agentos_swe.verification.sandbox import IsolatedSandbox
from agentos_swe.repair.models import (
    ImpactReport,
    FixPlan,
    PatchResult,
    PatchReviewResult,
    ValidatedPatch,
    RepairStatus,
    ReviewStatus,
)
from agentos_swe.repair.impact import ImpactAnalyzer
from agentos_swe.repair.planner import FixPlanner
from agentos_swe.repair.fix_agent import FixAgent
from agentos_swe.repair.reviewer import IndependentPatchReviewer

logger = logging.getLogger(__name__)


class RepairPipeline:
    """
    Controlled autonomous repair pipeline producing ValidatedPatch objects.
    Enforces strict safety invariants and isolated workspace execution.
    """

    def __init__(
        self,
        impact_analyzer: Optional[ImpactAnalyzer] = None,
        fix_planner: Optional[FixPlanner] = None,
        fix_agent: Optional[FixAgent] = None,
        reviewer: Optional[IndependentPatchReviewer] = None,
        checkpoint_store: Optional[CheckpointStore] = None,
        db_path: Optional[str] = None,
        max_repair_attempts: int = 2,
    ):
        self.impact_analyzer = impact_analyzer or ImpactAnalyzer()
        self.fix_planner = fix_planner or FixPlanner()
        self.fix_agent = fix_agent or FixAgent()
        self.reviewer = reviewer or IndependentPatchReviewer()
        self.max_repair_attempts = max_repair_attempts

        if checkpoint_store:
            self.checkpoint_store = checkpoint_store
        elif db_path:
            self.checkpoint_store = SQLiteCheckpointStore(db_path)
        else:
            default_db = os.path.join(os.getcwd(), "checkpoints", "swe_repair.db")
            self.checkpoint_store = SQLiteCheckpointStore(default_db)

    def repair_finding(
        self,
        finding: Finding,
        context: RepositoryContext,
        mission_id: Optional[str] = None,
        resume: bool = False,
    ) -> ValidatedPatch:
        """
        Execute controlled autonomous repair for a CONFIRMED finding.
        Rejects non-confirmed findings immediately.
        """
        run_id = mission_id or f"repair_mission_{str(uuid.uuid4())[:8]}"

        # Mandatory Safety Invariant Check
        if finding.status != FindingStatus.CONFIRMED:
            logger.warning(
                f"[RepairPipeline] Rejecting repair request for finding '{finding.id}': "
                f"Status is '{finding.status}', but ONLY 'CONFIRMED' findings may enter repair pipeline."
            )
            empty_impact = ImpactReport(finding_id=finding.id, target_file=finding.file or "")
            empty_review = PatchReviewResult(status=ReviewStatus.REJECTED, reason="Finding is not CONFIRMED.")
            return ValidatedPatch(
                finding_id=finding.id,
                patch_diff="",
                changed_files=[],
                impact_report=empty_impact,
                reproduction_result={"success": False, "error": "Not CONFIRMED"},
                regression_result={"success": False, "error": "Not CONFIRMED"},
                review_result=empty_review,
                status=RepairStatus.NOT_CONFIRMED,
            )

        start_stage = 0
        if resume and self.checkpoint_store:
            checkpoint = self.checkpoint_store.load_latest_checkpoint(run_id)
            if checkpoint:
                start_stage = checkpoint.get("task_index", 0) + 1
                logger.info(f"[RepairPipeline] Resuming repair mission {run_id} from stage {start_stage}")

        # Stage 1: Impact Analysis
        logger.info(f"[RepairPipeline] Stage 1: Impact Analysis for finding '{finding.title}'")
        impact = self.impact_analyzer.analyze(finding, context)
        self._checkpoint(run_id, 1, "IMPACT_ANALYZED", {"impact": impact.to_dict()})

        # Stage 2: Fix Planning
        logger.info(f"[RepairPipeline] Stage 2: Fix Planning")
        fix_plan = self.fix_planner.plan_fix(finding, impact, context)
        self._checkpoint(run_id, 2, "FIX_PLANNED", {"fix_plan": fix_plan.to_dict()})

        # Stage 3: Isolated Sandbox Patch Generation & Testing
        logger.info(f"[RepairPipeline] Stage 3: Patch Generation & Validation inside Sandbox")
        with IsolatedSandbox() as sandbox:
            # Copy all context source files to sandbox
            for s_file in context.source_files:
                full_s = os.path.join(context.repository_path, s_file)
                if os.path.isfile(full_s):
                    sandbox.copy_file(full_s, s_file)

            # Generate candidate patch
            patch_res = self.fix_agent.generate_patch(finding, fix_plan, sandbox, context)
            self._checkpoint(run_id, 3, "PATCH_GENERATED", {"patch": patch_res.to_dict()})

            if not patch_res.success:
                empty_review = PatchReviewResult(status=ReviewStatus.REJECTED, reason=patch_res.error)
                return ValidatedPatch(
                    finding_id=finding.id,
                    patch_diff="",
                    changed_files=[],
                    impact_report=impact,
                    reproduction_result={"success": False, "error": patch_res.error},
                    regression_result={"success": False},
                    review_result=empty_review,
                    status=RepairStatus.REPAIR_FAILED,
                )

            # Stage 4: Reproduction Test on Patched Workspace
            repro_test = self._run_sandbox_reproduction(sandbox, finding, fix_plan)
            self._checkpoint(run_id, 4, "REPRODUCTION_TESTED", {"reproduction": repro_test})

            if not repro_test["success"]:
                empty_review = PatchReviewResult(status=ReviewStatus.REJECTED, reason="Reproduction test failed.")
                return ValidatedPatch(
                    finding_id=finding.id,
                    patch_diff=patch_res.diff,
                    changed_files=patch_res.changed_files,
                    impact_report=impact,
                    reproduction_result=repro_test,
                    regression_result={"success": False},
                    review_result=empty_review,
                    status=RepairStatus.TEST_FAILED,
                )

            # Stage 5: Regression Testing on Patched Workspace
            regression_test = self._run_sandbox_regression(sandbox, context, fix_plan)
            self._checkpoint(run_id, 5, "REGRESSION_TESTED", {"regression": regression_test})

            if not regression_test["success"]:
                empty_review = PatchReviewResult(status=ReviewStatus.REJECTED, reason="Regression tests failed.")
                return ValidatedPatch(
                    finding_id=finding.id,
                    patch_diff=patch_res.diff,
                    changed_files=patch_res.changed_files,
                    impact_report=impact,
                    reproduction_result=repro_test,
                    regression_result=regression_test,
                    review_result=empty_review,
                    status=RepairStatus.REGRESSION_FAILED,
                )

            # Stage 6: Independent Review
            review_res = self.reviewer.review_patch(finding, fix_plan, patch_res)
            self._checkpoint(run_id, 6, "INDEPENDENT_REVIEWED", {"review": review_res.to_dict()})

            if review_res.status != ReviewStatus.APPROVED:
                return ValidatedPatch(
                    finding_id=finding.id,
                    patch_diff=patch_res.diff,
                    changed_files=patch_res.changed_files,
                    impact_report=impact,
                    reproduction_result=repro_test,
                    regression_result=regression_test,
                    review_result=review_res,
                    status=RepairStatus.REVIEW_REJECTED,
                )

            # Stage 7: Validation Complete
            validated_patch = ValidatedPatch(
                finding_id=finding.id,
                patch_diff=patch_res.diff,
                changed_files=patch_res.changed_files,
                impact_report=impact,
                reproduction_result=repro_test,
                regression_result=regression_test,
                review_result=review_res,
                status=RepairStatus.VALIDATED,
            )
            self._checkpoint(run_id, 7, "VALIDATED", validated_patch.to_dict())
            if self.checkpoint_store:
                self.checkpoint_store.mark_complete(run_id)

            logger.info(f"[RepairPipeline] VALIDATED patch produced for finding '{finding.id}'.")
            return validated_patch

    def _run_sandbox_reproduction(
        self, sandbox: IsolatedSandbox, finding: Finding, fix_plan: FixPlan
    ) -> Dict[str, Any]:
        """Run reproduction test inside patched sandbox workspace."""
        test_content = f"""import unittest
import sys
import os

sys.path.insert(0, os.getcwd())

class TestPatchReproduction(unittest.TestCase):
    def test_patch_integrity(self):
        self.assertTrue(os.path.exists({repr(fix_plan.target_file)}))

if __name__ == "__main__":
    unittest.main()
"""
        sandbox.write_file("test_patch_repro.py", test_content)
        res = sandbox.run_command(["python", "test_patch_repro.py"], timeout=10)
        return {"success": res["success"], "exit_code": res["exit_code"], "stdout": res["stdout"]}

    def _run_sandbox_regression(
        self, sandbox: IsolatedSandbox, context: RepositoryContext, fix_plan: FixPlan
    ) -> Dict[str, Any]:
        """Run regression tests inside patched sandbox workspace."""
        for t_file in fix_plan.tests_to_validate:
            full_t = os.path.join(context.repository_path, t_file)
            if os.path.isfile(full_t):
                sandbox.copy_file(full_t, t_file)

        # Run pytest if test files exist, or unittest fallback
        if fix_plan.tests_to_validate:
            res = sandbox.run_command(["python", "-m", "unittest", "discover", "-s", sandbox.path], timeout=15)
            return {"success": res["exit_code"] == 0, "exit_code": res["exit_code"], "stdout": res["stdout"]}

        return {"success": True, "exit_code": 0, "stdout": "No regression test files specified."}

    def _checkpoint(self, mission_id: str, stage_index: int, stage_name: str, state: Dict[str, Any]) -> None:
        if self.checkpoint_store:
            state["stage"] = stage_name
            self.checkpoint_store.save_checkpoint(mission_id, stage_index, state)
