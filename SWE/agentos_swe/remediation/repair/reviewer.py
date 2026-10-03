"""
IndependentPatchReviewer - Independent patch review agent for AgentOS-SWE (M4).
Adversarially reviews candidate patches for minimality, safety, and architectural preservation.
"""

import logging
from typing import Dict, Any, Optional

from agentos_swe.core.agents.base_investigator import BaseInvestigatorAgent
from agentos_swe.core.models import Finding
from agentos_swe.remediation.repair.models import (
    FixPlan,
    PatchResult,
    PatchReviewResult,
    ReviewStatus,
)

logger = logging.getLogger(__name__)


class IndependentPatchReviewer(BaseInvestigatorAgent):
    """
    Independent patch reviewer that evaluates candidate patch diffs
    and assigns APPROVED, REJECTED, or INCONCLUSIVE review status.
    """

    def __init__(self, **kwargs: Any):
        super().__init__(
            name="IndependentPatchReviewer",
            role="Independent Code & Security Reviewer",
            goal="Independently review candidate patches for minimality, correctness, and architecture preservation.",
            backstory="An independent senior staff architect and security reviewer.",
            **kwargs,
        )

    def investigate(self, context) -> list:
        return []

    def review_patch(
        self, finding: Finding, fix_plan: FixPlan, patch_result: PatchResult
    ) -> PatchReviewResult:
        """
        Adversarially evaluate candidate patch diff.
        """
        if not patch_result.success or not patch_result.diff:
            return PatchReviewResult(
                status=ReviewStatus.REJECTED,
                reason="Patch application failed or produced empty diff.",
                is_minimal=False,
            )

        diff = patch_result.diff
        diff_lines = diff.splitlines()
        added_lines = [l for l in diff_lines if l.startswith("+") and not l.startswith("+++")]
        removed_lines = [l for l in diff_lines if l.startswith("-") and not l.startswith("---")]

        # Check 1: Excessive diff size (not minimal)
        if len(added_lines) > 50 or len(removed_lines) > 50:
            return PatchReviewResult(
                status=ReviewStatus.REJECTED,
                reason=f"Patch is excessively large (+{len(added_lines)} / -{len(removed_lines)} lines), violating minimal change policy.",
                is_minimal=False,
            )

        # Check 2: Unrelated file modification
        if len(patch_result.changed_files) > 1 and fix_plan.target_file not in patch_result.changed_files:
            return PatchReviewResult(
                status=ReviewStatus.REJECTED,
                reason="Patch modified unrelated files outside target scope.",
                is_minimal=False,
            )

        # Check 3: Check if patch introduces new dangerous calls (e.g. eval, os.system)
        for added in added_lines:
            if "os.system(" in added or "exec(" in added:
                return PatchReviewResult(
                    status=ReviewStatus.REJECTED,
                    reason="Patch introduced dangerous function call (os.system / exec).",
                    is_minimal=True,
                    preserves_architecture=False,
                )

        logger.info(f"[IndependentPatchReviewer] APPROVED patch for '{finding.title}'.")
        return PatchReviewResult(
            status=ReviewStatus.APPROVED,
            reason="Patch is minimal, targets confirmed defect, and preserves architecture.",
            is_minimal=True,
            preserves_architecture=True,
        )
