"""
M27 Security Audit Trail Engine.

Maintains a secret-safe, deterministic audit log of all control plane events.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime

from agentos_swe.controlplane.models import ControlPlaneEventRecord, ControlPlaneEvent
from agentos_swe.security.secret_protection import SecretProtection


class SecurityAuditTrailEngine:
    """
    Records and queries deterministic control plane audit trail entries.
    """

    _audit_logs: Dict[str, List[ControlPlaneEventRecord]] = {}

    @classmethod
    def record_event(
        cls,
        repository_name: str,
        event: ControlPlaneEvent,
        severity: str = "INFO",
        actor: str = "System",
        reason: str = "",
        evidence_ref: str = "N/A",
        resulting_state: str = "IDLE",
    ) -> ControlPlaneEventRecord:
        """Records a secret-safe audit trail entry."""
        ev_id = f"aud_{len(cls._audit_logs.get(repository_name, []))+1:04d}"
        now_str = datetime.now().isoformat()[:19].replace("T", " ")

        rec = ControlPlaneEventRecord(
            event_id=ev_id,
            timestamp=now_str,
            repository=SecretProtection.sanitize_text(repository_name),
            event=event,
            severity=severity,
            actor=SecretProtection.sanitize_text(actor),
            reason=SecretProtection.sanitize_text(reason),
            evidence_ref=SecretProtection.sanitize_text(evidence_ref),
            resulting_state=resulting_state,
        )

        if repository_name not in cls._audit_logs:
            cls._audit_logs[repository_name] = []
        cls._audit_logs[repository_name].append(rec)
        return rec

    @classmethod
    def get_audit_trail(cls, repository_name: str) -> List[ControlPlaneEventRecord]:
        """Returns recorded audit trail for repository."""
        return cls._audit_logs.get(repository_name, [])
