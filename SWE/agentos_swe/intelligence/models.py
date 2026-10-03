"""
Domain models for M15 Intelligent Security Prioritization & Cross-Repository Risk Intelligence.
Defines PriorityTier, ExploitabilityLevel, ExposureLevel, BlastRadiusLevel, RecurrenceLevel,
PrioritizedFinding, CrossRepositoryPattern, and SecurityIntelligenceOverview.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional, Tuple

from datetime import datetime


class PriorityTier(str, Enum):
    """Remediation Priority Tiers."""
    P0 = "P0"  # Immediate (Score 90-100)
    P1 = "P1"  # Critical (Score 75-89)
    P2 = "P2"  # High (Score 60-74)
    P3 = "P3"  # Medium (Score 40-59)
    P4 = "P4"  # Low (Score 0-39)


class ExploitabilityLevel(str, Enum):
    """Likelihood and ease of exploiting a vulnerability."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NOT_EXPLOITABLE = "NOT_EXPLOITABLE"
    UNKNOWN = "UNKNOWN"


class ExposureLevel(str, Enum):
    """Reachability of vulnerable code path from external or untrusted entrypoints."""
    INTERNET_EXPOSED = "INTERNET_EXPOSED"
    USER_CONTROLLED = "USER_CONTROLLED"
    INTERNAL = "INTERNAL"
    UNKNOWN = "UNKNOWN"


class BlastRadiusLevel(str, Enum):
    """Scope of system impact if vulnerable code path is compromised."""
    SYSTEM_WIDE = "SYSTEM_WIDE"
    BROAD = "BROAD"
    LIMITED = "LIMITED"
    LOCAL = "LOCAL"
    UNKNOWN = "UNKNOWN"


class RecurrenceLevel(str, Enum):
    """Historical recurrence state across scan records."""
    REOPENED = "REOPENED"
    RECURRING = "RECURRING"
    REGRESSION = "REGRESSION"
    LONG_STANDING = "LONG_STANDING"
    FIRST_SEEN = "FIRST_SEEN"
    UNCHANGED = "UNCHANGED"


@dataclass
class PrioritizedFinding:
    """A security finding enriched with evidence-driven priority scoring and remediation guidance."""
    rank: int
    finding_id: str
    vulnerability_category: str
    severity: str
    priority_score: int  # 0 - 100
    priority_tier: PriorityTier
    score_breakdown: Dict[str, int] = field(default_factory=dict)
    exploitability: ExploitabilityLevel = ExploitabilityLevel.UNKNOWN
    exposure: ExposureLevel = ExposureLevel.UNKNOWN
    blast_radius: BlastRadiusLevel = BlastRadiusLevel.UNKNOWN
    recurrence: RecurrenceLevel = RecurrenceLevel.FIRST_SEEN
    affected_file: str = ""
    affected_function: Optional[str] = None
    affected_lines: Optional[Tuple[int, int]] = None
    root_cause: str = "UNKNOWN"
    confidence: float = 0.85
    fingerprint: Optional[str] = None
    
    # Recommendation details
    why_this_matters: str = ""
    what_to_fix: str = ""
    why_it_is_prioritized: str = ""
    recommended_action: str = ""
    expected_risk_reduction: str = ""
    repair_strategy: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["priority_tier"] = self.priority_tier.value if isinstance(self.priority_tier, Enum) else self.priority_tier
        d["exploitability"] = self.exploitability.value if isinstance(self.exploitability, Enum) else self.exploitability
        d["exposure"] = self.exposure.value if isinstance(self.exposure, Enum) else self.exposure
        d["blast_radius"] = self.blast_radius.value if isinstance(self.blast_radius, Enum) else self.blast_radius
        d["recurrence"] = self.recurrence.value if isinstance(self.recurrence, Enum) else self.recurrence
        return d


@dataclass
class CrossRepositoryPattern:
    """Recurring vulnerability pattern spanning multiple repository historical scans."""
    vulnerability_family: str
    affected_repositories_count: int
    total_occurrences: int
    repositories: List[str] = field(default_factory=list)
    highest_severity: str = "MEDIUM"
    most_common_sink: str = "N/A"
    trend: str = "STABLE"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityIntelligenceOverview:
    """Overall security posture and prioritized remediation queue."""
    repository: str
    security_score: int
    risk_level: str
    total_findings: int
    priority_findings_count: int
    critical_findings_count: int
    internet_exposed_count: int
    reopened_count: int
    top_remediation_queue: List[PrioritizedFinding] = field(default_factory=list)
    risk_breakdowns: Dict[str, Dict[str, int]] = field(default_factory=dict)
    cross_repository_patterns: List[CrossRepositoryPattern] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["top_remediation_queue"] = [p.to_dict() for p in self.top_remediation_queue]
        d["cross_repository_patterns"] = [c.to_dict() for c in self.cross_repository_patterns]
        return d
