"""
Canonical Execution Telemetry Event Model and Event Bus for AgentOS-SWE (R2).

Provides a single, thread-safe execution event model and publisher that feeds:
- Terminal live logger
- Streamlit live pipeline visualization
- Final execution reports
- Trace collector and debugging
"""

import sys
import time
import uuid
import queue
import logging
from enum import Enum
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Callable

from agentos_swe.security.secret_protection import SecretProtection

logger = logging.getLogger(__name__)


class ExecutionStatus(str, Enum):
    """Standardized event and stage execution statuses."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    NO_CHANGE = "NO_CHANGE"
    BLOCKED = "BLOCKED"
    WARNING = "WARNING"


# Standardized 19 Pipeline Lifecycle Stages (R2 Canonical Pipeline)
CANONICAL_PIPELINE_STAGES = [
    "Repository Intake",
    "Code Graph Construction",
    "Agent Investigation",
    "Semantic Analysis",
    "Security / Taint Analysis",
    "Evidence Correlation",
    "Verification",
    "Security Intelligence",
    "Attack Path Analysis",
    "Historical Analysis",
    "Security Learning",
    "Drift Analysis",
    "Decision Orchestration",
    "Remediation Planning",
    "Repair Validation",
    "Control Plane",
    "Incident Response",
    "Release Readiness",
    "Report Generation",
]


@dataclass
class ExecutionEvent:
    """Canonical Execution Event Data Model."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    stage: str = "General"
    component: str = "Engine"
    status: str = ExecutionStatus.RUNNING.value
    message: str = ""
    elapsed_time: float = 0.0
    repository: str = ""
    file: Optional[str] = None
    finding_count: Optional[int] = None
    raw_finding_count: Optional[int] = None
    verified_finding_count: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    severity: Optional[str] = None
    error: Optional[str] = None
    duration: Optional[float] = None

    def __post_init__(self):
        # Sanitize text fields automatically
        if self.message:
            self.message = SecretProtection.sanitize_text(self.message)
        if self.error:
            self.error = SecretProtection.sanitize_text(self.error)
        if self.repository:
            self.repository = SecretProtection.sanitize_text(self.repository)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


class TerminalLogger:
    """Formatted Terminal Logger that prints real-time execution events."""

    def __init__(self, stream=None, verbose: bool = True):
        self.stream = stream or sys.stdout
        self.verbose = verbose

    def format_event(self, event: ExecutionEvent) -> str:
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        status_symbol = {
            ExecutionStatus.PENDING.value: "⚪",
            ExecutionStatus.RUNNING.value: "▶",
            ExecutionStatus.COMPLETED.value: "✓",
            ExecutionStatus.FAILED.value: "✖",
            ExecutionStatus.SKIPPED.value: "⊝",
            ExecutionStatus.WARNING.value: "⚠️",
            ExecutionStatus.BLOCKED.value: "⛔",
        }.get(event.status, "•")

        dur_str = f" ({event.duration:.2f}s)" if event.duration is not None else ""
        msg = f"[{ts}] [{event.stage}] {status_symbol} {event.message}{dur_str}"
        return msg

    def _safe_print(self, text: str):
        try:
            print(text, file=self.stream, flush=True)
        except UnicodeEncodeError:
            enc = getattr(self.stream, "encoding", None) or "utf-8"
            safe_text = text.encode(enc, errors="replace").decode(enc, errors="replace")
            print(safe_text, file=self.stream, flush=True)

    def print_stage_header(self, index: int, total: int, stage_name: str):
        if not self.verbose:
            return
        header = f"\n[{index:02d}/{total:02d}] ▶ {stage_name}"
        self._safe_print(header)

    def print_event(self, event: ExecutionEvent):
        if not self.verbose:
            return
        formatted = self.format_event(event)
        self._safe_print(f"        {formatted}")

    def print_scan_header(self, repo: str, branch: str, commit: str, mode: str):
        if not self.verbose:
            return
        banner = f"""
============================================================
AgentOS-SWE SECURITY SCAN
============================================================
Repository : {repo}
Branch     : {branch}
Commit     : {commit}
Mode       : {mode}
Started    : {datetime.now().strftime('%H:%M:%S')}
============================================================
"""
        self._safe_print(banner)

    def print_final_summary(self, metrics: Dict[str, Any], duration: float, verdict: str):
        if not self.verbose:
            return
        summary = f"""
============================================================
FINAL SECURITY SUMMARY
============================================================
Files analyzed        : {metrics.get('files_analyzed', 'N/A')}
Graph nodes           : {metrics.get('graph_nodes', 'N/A')}
Graph edges           : {metrics.get('graph_edges', 'N/A')}
Raw candidate findings: {metrics.get('raw_findings', 'N/A')}
Verified findings     : {metrics.get('verified_findings', 'N/A')}
Confirmed findings    : {metrics.get('confirmed_findings', 'N/A')}
Rejected findings     : {metrics.get('rejected_findings', 'N/A')}
Inconclusive findings : {metrics.get('inconclusive_findings', 'N/A')}
Critical              : {metrics.get('critical', 0)}
High                  : {metrics.get('high', 0)}
Medium                : {metrics.get('medium', 0)}
Low                   : {metrics.get('low', 0)}
Taint paths           : {metrics.get('taint_paths', 'N/A')}
Attack paths          : {metrics.get('attack_paths', 'N/A')}
Security score        : {metrics.get('security_score', 'N/A')} / 100
Risk trend            : {metrics.get('risk_trend', 'STABLE')}
Release readiness     : {metrics.get('release_readiness', 'N/A')}

FINAL VERDICT: {verdict}
Total runtime: {duration:.2f}s
============================================================
"""
        self._safe_print(summary)


class ExecutionEventBus:
    """
    Centralized, thread-safe execution event publisher and hub.
    Receives events from scanning operations and dispatches to registered listeners:
    - Terminal logger
    - UI live queue
    - Trace collector
    """

    _instance: Optional["ExecutionEventBus"] = None

    def __init__(self):
        self.listeners: List[Callable[[ExecutionEvent], None]] = []
        self.events_history: List[ExecutionEvent] = []
        self.event_queue: queue.Queue = queue.Queue()
        self.terminal_logger = TerminalLogger()
        self.start_time: float = time.time()
        self._max_history = 1000

    @classmethod
    def get_instance(cls) -> "ExecutionEventBus":
        if cls._instance is None:
            cls._instance = ExecutionEventBus()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> "ExecutionEventBus":
        cls._instance = ExecutionEventBus()
        return cls._instance

    def subscribe(self, listener: Callable[[ExecutionEvent], None]):
        """Subscribe a callback to receive live execution events."""
        if listener not in self.listeners:
            self.listeners.append(listener)

    def unsubscribe(self, listener: Callable[[ExecutionEvent], None]):
        """Unsubscribe a callback."""
        if listener in self.listeners:
            self.listeners.remove(listener)

    def publish(self, event: ExecutionEvent):
        """Publish a new execution event to all subscribers and history."""
        if event.elapsed_time == 0.0:
            event.elapsed_time = round(time.time() - self.start_time, 3)

        self.events_history.append(event)
        if len(self.events_history) > self._max_history:
            self.events_history.pop(0)

        self.event_queue.put(event)

        # Notify terminal logger
        self.terminal_logger.print_event(event)

        # Notify active listeners
        for listener in self.listeners:
            try:
                listener(event)
            except Exception as ex:
                logger.warning(f"Error in event bus subscriber: {ex}")

    def emit(
        self,
        stage: str,
        message: str,
        status: str = ExecutionStatus.RUNNING.value,
        component: str = "Engine",
        file: Optional[str] = None,
        finding_count: Optional[int] = None,
        raw_finding_count: Optional[int] = None,
        verified_finding_count: Optional[int] = None,
        severity: Optional[str] = None,
        error: Optional[str] = None,
        duration: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ExecutionEvent:
        """Convenience method to construct and publish an event."""
        event = ExecutionEvent(
            stage=stage,
            component=component,
            status=status,
            message=message,
            file=file,
            finding_count=finding_count,
            raw_finding_count=raw_finding_count,
            verified_finding_count=verified_finding_count,
            severity=severity,
            error=error,
            duration=duration,
            metadata=metadata or {},
        )
        self.publish(event)
        return event

    def get_history(self) -> List[ExecutionEvent]:
        return list(self.events_history)
