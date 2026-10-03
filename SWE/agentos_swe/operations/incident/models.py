"""
M29 Security Incident Response & Investigation Models.

Defines strongly typed enums and dataclasses for incident detection,
evidence correlation, timeline reconstruction, impact assessment,
investigation findings, response planning, and lifecycle management.
"""

from enum import Enum
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime


class IncidentSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentStatus(str, Enum):
    DETECTED = "DETECTED"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    CONTAINMENT_RECOMMENDED = "CONTAINMENT_RECOMMENDED"
    REPAIR_PENDING = "REPAIR_PENDING"
    VALIDATING = "VALIDATING"
    MONITORING = "MONITORING"
    RESOLVED = "RESOLVED"
    REOPENED = "REOPENED"
    ESCALATED = "ESCALATED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"


class IncidentType(str, Enum):
    NEW_CRITICAL_VULNERABILITY = "NEW_CRITICAL_VULNERABILITY"
    NEW_HIGH_VULNERABILITY = "NEW_HIGH_VULNERABILITY"
    SECURITY_REGRESSION = "SECURITY_REGRESSION"
    REOPENED_VULNERABILITY = "REOPENED_VULNERABILITY"
    CRITICAL_ATTACK_PATH = "CRITICAL_ATTACK_PATH"
    SEVERE_SECURITY_DRIFT = "SEVERE_SECURITY_DRIFT"
    REPEATED_FAILED_REMEDIATION = "REPEATED_FAILED_REMEDIATION"
    GOVERNANCE_BLOCK = "GOVERNANCE_BLOCK"
    MONITORING_SECURITY_EVENT = "MONITORING_SECURITY_EVENT"
    COMPOUND_SECURITY_INCIDENT = "COMPOUND_SECURITY_INCIDENT"


class IncidentPhase(str, Enum):
    DETECTION = "DETECTION"
    CORRELATION = "CORRELATION"
    TIMELINE_RECONSTRUCTION = "TIMELINE_RECONSTRUCTION"
    IMPACT_ANALYSIS = "IMPACT_ANALYSIS"
    INVESTIGATION = "INVESTIGATION"
    RESPONSE_PLANNING = "RESPONSE_PLANNING"
    CONTAINMENT = "CONTAINMENT"
    REMEDIATION = "REMEDIATION"
    RESOLUTION = "RESOLUTION"


class EvidenceType(str, Enum):
    FINDING = "FINDING"
    TAINT_PATH = "TAINT_PATH"
    ATTACK_PATH = "ATTACK_PATH"
    GIT_DIFF = "GIT_DIFF"
    ROOT_CAUSE = "ROOT_CAUSE"
    HISTORICAL_RECORD = "HISTORICAL_RECORD"
    DRIFT_EVENT = "DRIFT_EVENT"
    GOVERNANCE_DECISION = "GOVERNANCE_DECISION"
    MONITORING_EVENT = "MONITORING_EVENT"


class ResponseAction(str, Enum):
    MONITOR = "MONITOR"
    INVESTIGATE = "INVESTIGATE"
    GENERATE_REPAIR = "GENERATE_REPAIR"
    VALIDATE_REPAIR = "VALIDATE_REPAIR"
    REQUEST_HUMAN_APPROVAL = "REQUEST_HUMAN_APPROVAL"
    BLOCK_RELEASE = "BLOCK_RELEASE"
    ESCALATE = "ESCALATE"
    RESCAN = "RESCAN"
    CLOSE_INCIDENT = "CLOSE_INCIDENT"


class InvestigationConfidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    VERY_HIGH = "VERY_HIGH"


@dataclass
class IncidentEvidence:
    """Represents a piece of evidence supporting a security incident."""
    evidence_id: str
    evidence_type: EvidenceType
    source_module: str
    title: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    severity: str = "MEDIUM"
    confidence: str = "HIGH"
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["evidence_type"] = self.evidence_type.value if isinstance(self.evidence_type, Enum) else self.evidence_type
        return d


@dataclass
class IncidentTimelineEvent:
    """Represents a chronological step in an incident's lifecycle."""
    event_id: str
    timestamp: str
    event_type: str
    description: str
    source_module: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    commit_sha: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IncidentImpact:
    """Blast radius and impact assessment for an incident."""
    repository_name: str
    affected_files: List[str] = field(default_factory=list)
    affected_functions: List[str] = field(default_factory=list)
    affected_security_surfaces: List[str] = field(default_factory=list)
    affected_trust_boundaries: List[str] = field(default_factory=list)
    internet_exposed: bool = False
    attack_path_reachable: bool = False
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    blast_radius_score: float = 0.0
    recurrence_classification: str = "FIRST_SEEN"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value if isinstance(self.severity, Enum) else self.severity
        return d


@dataclass
class IncidentAttackPath:
    """Attack path details linked to an incident."""
    path_id: str
    entrypoint: str
    source_type: str
    sink_type: str
    is_internet_exposed: bool = False
    exploitable: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IncidentResponsePlan:
    """Actionable response recommendation plan for an incident."""
    plan_id: str
    incident_id: str
    recommended_actions: List[ResponseAction] = field(default_factory=list)
    primary_action: ResponseAction = ResponseAction.MONITOR
    risk_level: str = "MEDIUM"
    governance_decision: str = "ALLOW"
    rationale: str = ""
    requires_human_approval: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["recommended_actions"] = [
            a.value if isinstance(a, Enum) else a for a in self.recommended_actions
        ]
        d["primary_action"] = self.primary_action.value if isinstance(self.primary_action, Enum) else self.primary_action
        return d


@dataclass
class SecurityIncident:
    """Master Security Incident record combining detection, evidence, timeline, impact, and response."""
    incident_id: str
    repository_name: str
    commit_sha: str
    title: str
    description: str
    incident_type: IncidentType
    severity: IncidentSeverity
    status: IncidentStatus
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    evidence_list: List[IncidentEvidence] = field(default_factory=list)
    timeline: List[IncidentTimelineEvent] = field(default_factory=list)
    impact: Optional[IncidentImpact] = None
    attack_paths: List[IncidentAttackPath] = field(default_factory=list)
    response_plan: Optional[IncidentResponsePlan] = None
    confidence: InvestigationConfidence = InvestigationConfidence.HIGH
    unknowns: List[str] = field(default_factory=list)
    explanation: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "repository_name": self.repository_name,
            "commit_sha": self.commit_sha,
            "title": self.title,
            "description": self.description,
            "incident_type": self.incident_type.value if isinstance(self.incident_type, Enum) else self.incident_type,
            "severity": self.severity.value if isinstance(self.severity, Enum) else self.severity,
            "status": self.status.value if isinstance(self.status, Enum) else self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "evidence_list": [e.to_dict() for e in self.evidence_list],
            "timeline": [t.to_dict() for t in self.timeline],
            "impact": self.impact.to_dict() if self.impact else None,
            "attack_paths": [ap.to_dict() for ap in self.attack_paths],
            "response_plan": self.response_plan.to_dict() if self.response_plan else None,
            "confidence": self.confidence.value if isinstance(self.confidence, Enum) else self.confidence,
            "unknowns": self.unknowns,
            "explanation": self.explanation,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityIncident":
        inc_type = data.get("incident_type", IncidentType.NEW_HIGH_VULNERABILITY.value)
        if isinstance(inc_type, str):
            try:
                inc_type = IncidentType(inc_type)
            except ValueError:
                inc_type = IncidentType.NEW_HIGH_VULNERABILITY

        sev = data.get("severity", IncidentSeverity.MEDIUM.value)
        if isinstance(sev, str):
            try:
                sev = IncidentSeverity(sev)
            except ValueError:
                sev = IncidentSeverity.MEDIUM

        st = data.get("status", IncidentStatus.DETECTED.value)
        if isinstance(st, str):
            try:
                st = IncidentStatus(st)
            except ValueError:
                st = IncidentStatus.DETECTED

        conf = data.get("confidence", InvestigationConfidence.HIGH.value)
        if isinstance(conf, str):
            try:
                conf = InvestigationConfidence(conf)
            except ValueError:
                conf = InvestigationConfidence.HIGH

        return cls(
            incident_id=data.get("incident_id", "inc_unknown"),
            repository_name=data.get("repository_name", "UNKNOWN"),
            commit_sha=data.get("commit_sha", "HEAD"),
            title=data.get("title", "Security Incident"),
            description=data.get("description", ""),
            incident_type=inc_type,
            severity=sev,
            status=st,
            created_at=data.get("created_at", datetime.now().isoformat()),
            updated_at=data.get("updated_at", datetime.now().isoformat()),
            evidence_list=[IncidentEvidence(**e) if isinstance(e, dict) else e for e in data.get("evidence_list", [])],
            timeline=[IncidentTimelineEvent(**t) if isinstance(t, dict) else t for t in data.get("timeline", [])],
            impact=IncidentImpact(**data["impact"]) if isinstance(data.get("impact"), dict) else data.get("impact"),
            attack_paths=[IncidentAttackPath(**ap) if isinstance(ap, dict) else ap for ap in data.get("attack_paths", [])],
            response_plan=IncidentResponsePlan(**data["response_plan"]) if isinstance(data.get("response_plan"), dict) else data.get("response_plan"),
            confidence=conf,
            unknowns=data.get("unknowns", []),
            explanation=data.get("explanation", {}),
        )


@dataclass
class IncidentInvestigationResult:
    """Aggregate investigation output across all active incidents."""
    incidents: List[SecurityIncident] = field(default_factory=list)
    active_incident_count: int = 0
    critical_incident_count: int = 0
    summary_explanation: str = "Zero active security incidents identified."

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incidents": [inc.to_dict() for inc in self.incidents],
            "active_incident_count": self.active_incident_count,
            "critical_incident_count": self.critical_incident_count,
            "summary_explanation": self.summary_explanation,
        }
