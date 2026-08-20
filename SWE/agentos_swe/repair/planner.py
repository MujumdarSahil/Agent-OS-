"""
FixPlanner - Generates targeted fix plan for confirmed findings (M4).
"""

import logging
from typing import Dict, Any, Optional

from agentos_swe.models import Finding
from agentos_swe.context import RepositoryContext
from agentos_swe.repair.models import ImpactReport, FixPlan

logger = logging.getLogger(__name__)


class FixPlanner:
    """
    Creates structured fix plans specifying the smallest safe code modification.
    """

    def plan_fix(
        self, finding: Finding, impact_report: ImpactReport, context: RepositoryContext
    ) -> FixPlan:
        target_file = finding.file or impact_report.target_file

        defect_summary = f"{finding.title}: {finding.description}"
        proposed_strategy = (
            f"Apply minimal targeted modification to '{target_file}' to resolve {finding.category} flaw. "
            f"Preserve all existing function signatures and caller contracts."
        )

        tests_to_validate = list(impact_report.related_tests)
        if not tests_to_validate and context.test_files:
            tests_to_validate = context.test_files[:3]

        return FixPlan(
            finding_id=finding.id,
            target_file=target_file,
            defect_summary=defect_summary,
            proposed_fix_strategy=proposed_strategy,
            allowed_line_range=finding.line_range,
            tests_to_validate=tests_to_validate,
        )
