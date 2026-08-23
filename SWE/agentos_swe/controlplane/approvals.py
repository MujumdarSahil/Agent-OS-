"""
M27 Control Plane Approval Manager.

Integrates with M24 HumanApprovalEngine to track, simulate, and manage human approval state safely.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime

from agentos_swe.controlplane.models import ApprovalState


class ControlPlaneApprovalManager:
    """
    Manages human security approvals for the control plane.
    """

    def __init__(self):
        self.approvals_registry: Dict[str, List[ApprovalState]] = {}

    def get_pending_approvals(self, repository_name: str) -> List[ApprovalState]:
        """Returns pending approval requests for repository."""
        return [
            app for app in self.approvals_registry.get(repository_name, [])
            if app.status == "PENDING"
        ]

    def get_approval_history(self, repository_name: str) -> List[ApprovalState]:
        """Returns full approval history for repository."""
        return self.approvals_registry.get(repository_name, [])

    def request_approval(
        self,
        repository_name: str,
        finding_id: str,
        proposed_action: str,
        risk_level: str,
        reason: str,
    ) -> ApprovalState:
        """Registers a new pending approval request."""
        req_id = f"req_{repository_name}_{len(self.approvals_registry.get(repository_name, []))+1}"
        app = ApprovalState(
            request_id=req_id,
            finding_id=finding_id,
            proposed_action=proposed_action,
            risk_level=risk_level,
            reason=reason,
            timestamp=datetime.now().isoformat()[:19].replace("T", " "),
            status="PENDING",
        )

        if repository_name not in self.approvals_registry:
            self.approvals_registry[repository_name] = []
        self.approvals_registry[repository_name].append(app)
        return app

    def process_approval(
        self, repository_name: str, request_id: str, decision: str
    ) -> Optional[ApprovalState]:
        """
        Processes approval decision (APPROVED / DECLINED / EXPIRED).
        Safety Invariant: Performs ONLY local state updates; NEVER modifies target repository directly.
        """
        apps = self.approvals_registry.get(repository_name, [])
        for app in apps:
            if app.request_id == request_id:
                app.status = decision.upper()
                return app
        return None
