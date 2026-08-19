"""
PRPipeline - GitHub PR Automation & Risk Governance Pipeline for AgentOS-SWE (M5).
Integrates RiskAnalyzer, GovernanceGate, GitHubAdapter, PRDescriptionGenerator, and SQLite CheckpointStore.
"""

import os
import uuid
import logging
from typing import Dict, Any, Optional

from agentos.core.checkpoint import CheckpointStore, SQLiteCheckpointStore
from agentos_swe.models import Finding
from agentos_swe.repair.models import ValidatedPatch
from agentos_swe.context import RepositoryContext
from agentos_swe.pr.models import (
    RiskLevel,
    RiskAssessment,
    GovernanceDecision,
    PRResult,
)
from agentos_swe.pr.risk import RiskAnalyzer
from agentos_swe.pr.governance_gate import GovernanceGate
from agentos_swe.pr.provider import GitProvider, GitHubAdapter
from agentos_swe.pr.pr_generator import PRDescriptionGenerator

logger = logging.getLogger(__name__)


class PRPipeline:
    """
    PR Automation & Governance Pipeline producing PRResult objects.
    """

    def __init__(
        self,
        risk_analyzer: Optional[RiskAnalyzer] = None,
        governance_gate: Optional[GovernanceGate] = None,
        provider: Optional[GitProvider] = None,
        generator: Optional[PRDescriptionGenerator] = None,
        checkpoint_store: Optional[CheckpointStore] = None,
        db_path: Optional[str] = None,
        dry_run: bool = True,
    ):
        self.risk_analyzer = risk_analyzer or RiskAnalyzer()
        self.governance_gate = governance_gate or GovernanceGate()
        self.provider = provider or GitHubAdapter(dry_run=dry_run)
        self.generator = generator or PRDescriptionGenerator()
        self.dry_run = dry_run

        if checkpoint_store:
            self.checkpoint_store = checkpoint_store
        elif db_path:
            self.checkpoint_store = SQLiteCheckpointStore(db_path)
        else:
            default_db = os.path.join(os.getcwd(), "checkpoints", "swe_pr.db")
            self.checkpoint_store = SQLiteCheckpointStore(default_db)

    def execute_pr_pipeline(
        self,
        finding: Finding,
        patch: ValidatedPatch,
        context: RepositoryContext,
        mission_id: Optional[str] = None,
        resume: bool = False,
    ) -> PRResult:
        """
        Run PR automation pipeline for a validated patch.
        Enforces governance checks and supports dry-run execution.
        """
        run_id = mission_id or f"pr_mission_{str(uuid.uuid4())[:8]}"

        start_stage = 0
        if resume and self.checkpoint_store:
            checkpoint = self.checkpoint_store.load_latest_checkpoint(run_id)
            if checkpoint:
                start_stage = checkpoint.get("task_index", 0) + 1
                logger.info(f"[PRPipeline] Resuming PR mission {run_id} from stage {start_stage}")

        # Stage 1: Risk Assessment
        logger.info(f"[PRPipeline] Stage 1: Risk Assessment for finding '{finding.id}'")
        risk = self.risk_analyzer.analyze_risk(finding, patch)
        self._checkpoint(run_id, 1, "RISK_ANALYZED", {"risk": risk.to_dict()})

        # Stage 2: Governance Gate Check
        logger.info(f"[PRPipeline] Stage 2: AgentOS Governance Gate Check")
        gov_decision = self.governance_gate.evaluate(risk)
        self._checkpoint(run_id, 2, "GOVERNANCE_CHECKED", {"governance": gov_decision.value})

        if gov_decision == GovernanceDecision.DENY:
            logger.warning(f"[PRPipeline] DENIED PR creation for finding '{finding.id}' by Governance Engine.")
            return PRResult(
                success=False,
                governance_decision=gov_decision,
                risk_level=risk.risk_level,
                dry_run=self.dry_run,
                error="PR creation denied by AgentOS Governance Engine policy.",
            )

        # Stage 3: Branch Creation & PR Preparation
        branch_name = f"agentos-swe/patch-{finding.id[:8]}"
        payload = self.generator.generate_pr_payload(finding, patch, risk, branch_name)
        self._checkpoint(run_id, 3, "BRANCH_CREATED", {"branch_name": branch_name, "title": payload["title"]})

        # Stage 4: Commit & Push Changes
        self.provider.create_branch(context.repository_path, branch_name)
        self.provider.commit_changes(context.repository_path, payload["title"], patch.changed_files)
        self._checkpoint(run_id, 4, "PATCH_COMMITTED", {"changed_files": patch.changed_files})

        self.provider.push_branch(context.repository_path, branch_name)
        self._checkpoint(run_id, 5, "PUSHED", {"branch_name": branch_name})

        # Stage 5: Create Pull Request
        pr_response = self.provider.create_pull_request(
            repository_path=context.repository_path,
            title=payload["title"],
            body=payload["body"],
            head_branch=branch_name,
        )

        res = PRResult(
            success=pr_response.get("success", False),
            pr_number=pr_response.get("pr_number"),
            pr_url=pr_response.get("pr_url"),
            branch_name=branch_name,
            governance_decision=gov_decision,
            risk_level=risk.risk_level,
            dry_run=pr_response.get("dry_run", self.dry_run),
            pr_title=payload["title"],
            pr_body=payload["body"],
        )

        self._checkpoint(run_id, 6, "PR_CREATED", res.to_dict())
        if self.checkpoint_store:
            self.checkpoint_store.mark_complete(run_id)

        logger.info(f"[PRPipeline] Successfully created PR Result for '{finding.id}' (dry_run={res.dry_run}).")
        return res

    def _checkpoint(self, mission_id: str, stage_index: int, stage_name: str, state: Dict[str, Any]) -> None:
        if self.checkpoint_store:
            state["stage"] = stage_name
            self.checkpoint_store.save_checkpoint(mission_id, stage_index, state)
