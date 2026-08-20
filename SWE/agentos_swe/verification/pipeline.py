"""
VerificationPipeline - Orchestrates evidence verification strategies and integrates AgentOS CheckpointStore (M3).
"""

import os
import uuid
import logging
from typing import List, Dict, Any, Optional

from agentos.core.checkpoint import CheckpointStore, SQLiteCheckpointStore
from agentos_swe.models import Finding, FindingStatus
from agentos_swe.context import RepositoryContext
from agentos_swe.verification.verification_agent import VerificationAgent

logger = logging.getLogger(__name__)


class VerificationPipeline:
    """
    Verification Pipeline managing step-by-step evidence verification and SQLite checkpoint persistence.
    """

    def __init__(
        self,
        verifier: Optional[VerificationAgent] = None,
        checkpoint_store: Optional[CheckpointStore] = None,
        db_path: Optional[str] = None,
    ):
        self.verifier = verifier or VerificationAgent()
        if checkpoint_store:
            self.checkpoint_store = checkpoint_store
        elif db_path:
            self.checkpoint_store = SQLiteCheckpointStore(db_path)
        else:
            default_db = os.path.join(tempfile_dir := os.getcwd(), "checkpoints", "swe_verification.db")
            self.checkpoint_store = SQLiteCheckpointStore(default_db)

    def verify_findings(
        self,
        findings: List[Finding],
        context: RepositoryContext,
        mission_id: Optional[str] = None,
        resume: bool = False,
    ) -> List[Finding]:
        """
        Run verification pipeline over candidate findings with step-by-step checkpointing.
        """
        run_id = mission_id or f"verif_mission_{str(uuid.uuid4())[:8]}"
        verified_results: List[Finding] = []

        start_index = 0
        if resume and self.checkpoint_store:
            checkpoint = self.checkpoint_store.load_latest_checkpoint(run_id)
            if checkpoint and "verified_findings" in checkpoint:
                logger.info(f"[VerificationPipeline] Resuming mission {run_id} from task_index {checkpoint.get('task_index', 0)}")
                start_index = checkpoint.get("task_index", 0) + 1
                restored = checkpoint.get("verified_findings", [])
                verified_results = [Finding.from_dict(f) for f in restored]

        for idx, finding in enumerate(findings):
            if idx < start_index:
                continue

            logger.info(f"[VerificationPipeline] Step {idx + 1}/{len(findings)}: Verifying '{finding.title}'")

            # Execute verification
            verified_finding = self.verifier.verify_finding(finding, context)
            verified_results.append(verified_finding)

            # Save checkpoint
            if self.checkpoint_store:
                checkpoint_state = {
                    "mission_id": run_id,
                    "task_index": idx,
                    "status": "in_progress",
                    "processed_finding_id": finding.id,
                    "verified_findings": [f.to_dict() for f in verified_results],
                }
                self.checkpoint_store.save_checkpoint(run_id, idx, checkpoint_state)

        if self.checkpoint_store:
            self.checkpoint_store.mark_complete(run_id)

        return verified_results
