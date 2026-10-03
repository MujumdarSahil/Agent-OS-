"""
TraceCollector - Lightweight structured telemetry and execution trace collector for AgentOS-SWE (M7).
"""

import uuid
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional

from agentos_swe.security.secret_protection import SecretProtection
from agentos_swe.observability.models import (
    TraceEvent,
    AgentMetrics,
    FindingMetrics,
    RepairMetrics,
)
from agentos_swe.observability.events import ExecutionEventBus, ExecutionEvent, ExecutionStatus

logger = logging.getLogger(__name__)


class TraceCollector:
    """
    Lightweight, thread-safe telemetry collector tracking execution events,
    fallback triggers, checkpoint actions, agent performance, and resource usage.
    """

    def __init__(self, mission_id: Optional[str] = None):
        self.mission_id = mission_id or f"mission_{str(uuid.uuid4())[:8]}"
        self.events: List[TraceEvent] = []
        self.agent_metrics: Dict[str, AgentMetrics] = {}
        self.finding_metrics = FindingMetrics()
        self.repair_metrics = RepairMetrics()
        self.fallback_count = 0
        self.checkpoint_recoveries = 0

    def record_event(
        self,
        stage: str,
        agent_name: Optional[str] = None,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        tokens: int = 0,
        latency_sec: float = 0.0,
        fallback_triggered: bool = False,
        fallback_from: Optional[str] = None,
        fallback_to: Optional[str] = None,
        checkpoint_action: Optional[str] = None,
        finding_id: Optional[str] = None,
        status: Optional[str] = None,
        cost_est: float = 0.0,
        details: Optional[Dict[str, Any]] = None,
    ) -> TraceEvent:
        clean_details = {}
        if details:
            for k, v in details.items():
                if isinstance(v, str):
                    clean_details[k] = SecretProtection.sanitize_text(v)
                else:
                    clean_details[k] = v

        event = TraceEvent(
            event_id=str(uuid.uuid4())[:8],
            timestamp=datetime.now().isoformat(),
            mission_id=self.mission_id,
            stage=stage,
            agent_name=agent_name,
            provider=provider,
            model=model,
            tokens=tokens,
            latency_sec=latency_sec,
            fallback_triggered=fallback_triggered,
            fallback_from=fallback_from,
            fallback_to=fallback_to,
            checkpoint_action=checkpoint_action,
            finding_id=finding_id,
            status=status,
            cost_est=cost_est,
            details=clean_details,
        )

        self.events.append(event)

        # Update Fallback metrics
        if fallback_triggered:
            self.fallback_count += 1

        # Update Checkpoint metrics
        if checkpoint_action == "restored":
            self.checkpoint_recoveries += 1

        # Update Agent metrics
        if agent_name:
            if agent_name not in self.agent_metrics:
                self.agent_metrics[agent_name] = AgentMetrics(agent_name=agent_name)
            metrics = self.agent_metrics[agent_name]
            metrics.execution_count += 1
            metrics.total_duration_sec += latency_sec
            metrics.total_tokens += tokens
            if fallback_triggered:
                metrics.fallback_count += 1
            if status and status.upper() in ("SUCCESS", "CONFIRMED", "VALIDATED", "APPROVED"):
                metrics.success_count += 1
            elif status and status.upper() in ("FAILED", "REJECTED", "ERROR"):
                metrics.failure_count += 1

        # Update Finding metrics
        if status:
            s_upper = status.upper()
            if s_upper == "DISCOVERED":
                self.finding_metrics.total_discovered += 1
            elif s_upper == "CONFIRMED":
                self.finding_metrics.confirmed += 1
            elif s_upper == "REJECTED":
                self.finding_metrics.rejected += 1
            elif s_upper == "INCONCLUSIVE":
                self.finding_metrics.inconclusive += 1

        # Update Repair metrics
        if stage.startswith("REPAIR_") or stage.startswith("PATCH_") or stage == "VALIDATED":
            if stage == "PATCH_GENERATED":
                self.repair_metrics.patches_generated += 1
            elif stage == "REPRODUCTION_TESTED" and status == "PASS":
                self.repair_metrics.reproduction_pass += 1
            elif stage == "REGRESSION_TESTED" and status == "PASS":
                self.repair_metrics.regression_pass += 1
            elif stage == "INDEPENDENT_REVIEWED" and status == "APPROVED":
                self.repair_metrics.independent_review_pass += 1
            elif stage == "VALIDATED" or status == "VALIDATED":
                self.repair_metrics.validated_patches += 1

        logger.debug(f"[TraceCollector] Recorded event '{stage}' for agent '{agent_name}'")
        return event
