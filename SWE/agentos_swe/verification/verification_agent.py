"""
VerificationAgent - Independent verification agent for AgentOS-SWE (M3).
Adversarially evaluates candidate findings and assigns CONFIRMED, REJECTED, or INCONCLUSIVE status.
"""

import os
import logging
from typing import List, Dict, Any, Optional

from agentos_swe.agents.base_investigator import BaseInvestigatorAgent
from agentos_swe.models import (
    Finding,
    Evidence,
    FindingStatus,
    EvidenceSource,
    EvidenceKind,
)
from agentos_swe.context import RepositoryContext
from agentos_swe.verification.strategies import (
    StaticVerificationStrategy,
    GraphVerificationStrategy,
    TestReproductionStrategy,
)

logger = logging.getLogger(__name__)


class VerificationAgent(BaseInvestigatorAgent):
    """
    Independent verification agent that challenges candidate LLM findings
    and determines final status (CONFIRMED, REJECTED, INCONCLUSIVE).
    """

    def __init__(self, **kwargs: Any):
        super().__init__(
            name="VerificationAgent",
            role="Independent Software Verifier",
            goal="Independently verify or refute candidate finding hypotheses using static, graph, and reproduction evidence.",
            backstory="An independent security and software verification auditor challenging candidate bug reports.",
            **kwargs,
        )
        self.static_strategy = StaticVerificationStrategy()
        self.graph_strategy = GraphVerificationStrategy()
        self.test_strategy = TestReproductionStrategy()

    def investigate(self, context: RepositoryContext) -> List[Finding]:
        """Not directly used for repo-wide intake; call verify_finding() per finding."""
        return []

    def verify_finding(self, finding: Finding, context: RepositoryContext) -> Finding:
        """
        Adversarially verify candidate finding.
        Updates finding status, evidence chain, and confidence score.
        """
        finding.status = FindingStatus.VERIFYING
        logger.info(f"[VerificationAgent] Verifying finding: '{finding.title}' ({finding.file})")

        # Step 1: Cheap Static Verification
        static_ok, static_ev = self.static_strategy.verify(finding, context)
        if static_ev:
            finding.evidence.append(static_ev)

        if not static_ok and static_ev and "does not exist" in static_ev.description:
            # File missing -> REJECTED
            finding.status = FindingStatus.REJECTED
            finding.confidence = 0.1
            logger.info(f"[VerificationAgent] REJECTED finding '{finding.title}': target file missing.")
            return finding

        if not static_ok and static_ev and "Sanitization" in static_ev.description:
            # Refuted by sanitization -> REJECTED
            finding.status = FindingStatus.REJECTED
            finding.confidence = 0.2
            logger.info(f"[VerificationAgent] REJECTED finding '{finding.title}': defensive sanitization detected.")
            return finding

        # Step 2: Graph Verification
        graph_ok, graph_ev = self.graph_strategy.verify(finding, context)
        if graph_ev:
            finding.evidence.append(graph_ev)

        # Step 3: Reproduction Test Verification
        test_ok, test_ev = self.test_strategy.verify(finding, context)
        if test_ev:
            finding.evidence.append(test_ev)

        # Step 4: Adversarial Decision Matrix
        if static_ok and graph_ok and test_ok:
            finding.status = FindingStatus.CONFIRMED
            finding.confidence = 1.0
            logger.info(f"[VerificationAgent] CONFIRMED finding '{finding.title}'.")
        elif (static_ok and test_ok) or (graph_ok and test_ok):
            finding.status = FindingStatus.CONFIRMED
            finding.confidence = 0.9
            logger.info(f"[VerificationAgent] CONFIRMED finding '{finding.title}'.")
        elif static_ok and graph_ok:
            finding.status = FindingStatus.CONFIRMED
            finding.confidence = 0.8
            logger.info(f"[VerificationAgent] CONFIRMED finding '{finding.title}'.")
        elif static_ok or graph_ok or test_ok:
            finding.status = FindingStatus.INCONCLUSIVE
            finding.confidence = 0.5
            logger.info(f"[VerificationAgent] INCONCLUSIVE finding '{finding.title}': partial evidence only.")
        else:
            finding.status = FindingStatus.REJECTED
            finding.confidence = 0.3
            logger.info(f"[VerificationAgent] REJECTED finding '{finding.title}': failed static and graph checks.")

        return finding
