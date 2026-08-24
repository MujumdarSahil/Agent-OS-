"""
M27 Repository Lifecycle State Machine.

Enforces valid state transitions across repository operational lifecycle stages.
"""

from typing import Set, Dict
from agentos_swe.operations.controlplane.models import OperationalMode


class RepositoryLifecycleEngine:
    """
    Enforces valid repository operational lifecycle state machine transitions.
    """

    VALID_TRANSITIONS: Dict[str, Set[str]] = {
        "IDLE": {"SCANNING", "COMPLETE", "FAILED", "MONITORING"},
        "SCANNING": {"ANALYZING", "FAILED"},
        "ANALYZING": {"INVESTIGATING", "FAILED"},
        "INVESTIGATING": {"VERIFYING", "FAILED"},
        "VERIFYING": {"INTELLIGENCE_READY", "FAILED"},
        "INTELLIGENCE_READY": {"DECISION_PENDING", "MONITORING", "COMPLETE", "FAILED"},
        "DECISION_PENDING": {"REPAIR_PENDING", "APPROVAL_PENDING", "WAITING_APPROVAL", "MONITORING", "BLOCKED", "COMPLETE"},
        "REPAIR_PENDING": {"REPAIRING", "REPAIR_VALIDATING", "APPROVAL_PENDING", "WAITING_APPROVAL", "FAILED"},
        "REPAIRING": {"REPAIR_VALIDATING", "FAILED"},
        "APPROVAL_PENDING": {"REPAIR_PENDING", "REPAIR_VALIDATING", "RESCAN_REQUIRED", "BLOCKED", "MONITORING"},
        "WAITING_APPROVAL": {"REPAIR_PENDING", "REPAIR_VALIDATING", "RESCAN_REQUIRED", "BLOCKED", "MONITORING"},
        "REPAIR_VALIDATING": {"RESCAN_REQUIRED", "INVESTIGATING", "FAILED", "COMPLETE"},
        "RESCAN_REQUIRED": {"SCANNING", "MONITORING"},
        "MONITORING": {"SCANNING", "COMPLETE", "IDLE"},
        "BLOCKED": {"APPROVAL_PENDING", "WAITING_APPROVAL", "INVESTIGATING", "IDLE", "MONITORING"},
        "COMPLETE": {"SCANNING", "IDLE", "MONITORING"},
        "FAILED": {"IDLE", "SCANNING"},
    }

    @classmethod
    def can_transition(cls, current_stage: str, target_stage: str) -> bool:
        """Evaluates whether a lifecycle state transition is valid."""
        c_stage = current_stage.upper()
        t_stage = target_stage.upper()

        if c_stage == t_stage:
            return True

        valid_targets = cls.VALID_TRANSITIONS.get(c_stage, set())
        return t_stage in valid_targets

    @classmethod
    def transition(cls, current_stage: str, target_stage: str) -> str:
        """
        Executes lifecycle state transition if valid, raising ValueError on invalid transition.
        """
        if cls.can_transition(current_stage, target_stage):
            return target_stage.upper()
        raise ValueError(
            f"Invalid lifecycle transition: Cannot move from '{current_stage}' to '{target_stage}'."
        )
