"""
M24 Human Approval Engine.

Manages local in-memory ApprovalRequest objects for human review simulation
without performing automatic repository writes or external network authentication.
"""

import uuid
from typing import Dict, Any, List, Optional
from agentos_swe.operations.orchestration.models import (
    ApprovalRequest,
    DecisionAction,
    DecisionStatus,
)


class HumanApprovalEngine:
    """
    Manages local, in-memory ApprovalRequest objects.
    """

    def __init__(self):
        self.requests: Dict[str, ApprovalRequest] = {}

    def create_request(
        self,
        finding_id: str,
        proposed_action: DecisionAction,
        explanation: str,
        risk: str = "HIGH",
    ) -> ApprovalRequest:
        """
        Creates a new ApprovalRequest object.
        """
        req_id = f"appr_{uuid.uuid4().hex[:8]}"
        req = ApprovalRequest(
            approval_id=req_id,
            finding_id=finding_id,
            proposed_action=proposed_action,
            explanation=explanation,
            risk=risk,
            status=DecisionStatus.PENDING,
        )
        self.requests[req_id] = req
        return req

    def approve_request(self, approval_id: str) -> Optional[ApprovalRequest]:
        """
        Marks an approval request as APPROVED.
        """
        req = self.requests.get(approval_id)
        if req:
            req.status = DecisionStatus.APPROVED
        return req

    def decline_request(self, approval_id: str) -> Optional[ApprovalRequest]:
        """
        Marks an approval request as REJECTED.
        """
        req = self.requests.get(approval_id)
        if req:
            req.status = DecisionStatus.REJECTED
        return req

    def expire_request(self, approval_id: str) -> Optional[ApprovalRequest]:
        """
        Marks an approval request as EXPIRED.
        """
        req = self.requests.get(approval_id)
        if req:
            req.status = DecisionStatus.ESCALATED
        return req
