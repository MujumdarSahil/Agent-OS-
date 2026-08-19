"""
ImpactAnalyzer - Targeted blast radius and code graph impact analysis for AgentOS-SWE (M4).
"""

import os
import logging
from typing import List, Dict, Any, Optional

from agentos_swe.models import Finding
from agentos_swe.context import RepositoryContext
from agentos_swe.repair.models import ImpactReport

logger = logging.getLogger(__name__)


class ImpactAnalyzer:
    """
    Analyzes blast radius and code graph dependencies for a confirmed finding.
    """

    def analyze(self, finding: Finding, context: RepositoryContext) -> ImpactReport:
        target_file = finding.file or ""
        callers: List[str] = []
        dependents: List[str] = []
        related_tests: List[str] = []
        affected_symbols: List[str] = []

        if target_file:
            file_node_id = f"file::{target_file}"
            callers_nodes = context.get_callers(file_node_id)
            dependents_nodes = context.get_dependents(file_node_id)

            callers = [c.id for c in callers_nodes]
            dependents = [d.id for d in dependents_nodes]

            if finding.symbol:
                affected_symbols.append(finding.symbol)

            # Match related tests
            for test_file in context.test_files:
                base_name = os.path.basename(target_file).replace(".py", "")
                if base_name in test_file:
                    related_tests.append(test_file)

        risk_signals = []
        if len(callers) > 5:
            risk_signals.append("High caller fan-in: fix affects multiple call sites.")
        if len(dependents) > 5:
            risk_signals.append("High module dependency fan-out.")

        summary = (
            f"Impact Analysis for '{finding.title}' in '{target_file}': "
            f"{len(callers)} callers, {len(dependents)} dependents, {len(related_tests)} related test files."
        )

        return ImpactReport(
            finding_id=finding.id,
            target_file=target_file,
            affected_files=[target_file],
            affected_symbols=affected_symbols,
            callers=callers,
            dependents=dependents,
            related_tests=related_tests,
            risk_signals=risk_signals,
            summary=summary,
        )
