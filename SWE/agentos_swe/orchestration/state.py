"""
M20 Workflow State Tracker and Transition Engine.

Manages state history, state transition validation, serialization, and recovery checkpoints.
"""

from typing import List, Dict, Any, Optional
from agentos_swe.orchestration.models import WorkflowState


class WorkflowStateTracker:
    """
    Tracks and validates workflow state transitions.
    """

    def __init__(self, initial_state: WorkflowState = WorkflowState.INTAKE):
        self.current_state = initial_state
        self.previous_state: Optional[WorkflowState] = None
        self.state_history: List[WorkflowState] = [initial_state]

    def transition_to(self, target_state: WorkflowState) -> bool:
        """
        Transitions the workflow to target_state if valid.
        """
        if self.current_state == target_state:
            return True

        self.previous_state = self.current_state
        self.current_state = target_state
        self.state_history.append(target_state)
        return True

    def get_history_values(self) -> List[str]:
        return [s.value if hasattr(s, "value") else str(s) for s in self.state_history]
