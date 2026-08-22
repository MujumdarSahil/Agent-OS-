"""
Domain models for M14 Repository Security Intelligence & Historical Regression.
Includes ScanRecord, FindingLifecycleState, RiskTrend, HistoricalFindingRecord,
ChangedCodeImpact, and ScanComparisonResult.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime


class FindingLifecycleState(str, Enum):
    """Lifecycle state of a security finding across commits and historical scans."""
    NEW = "NEW"
    FIXED = "FIXED"
    UNCHANGED = "UNCHANGED"
    REOPENED = "REOPENED"
    REGRESSION = "REGRESSION"
    UNKNOWN = "UNKNOWN"


class RiskTrend(str, Enum):
    """Overall security risk trend of a repository over time."""
    IMPROVING = "IMPROVING"
    DEGRADING = "DEGRADING"
    STABLE = "STABLE"
    UNKNOWN = "UNKNOWN"


@dataclass
class ScanRecord:
    """Persistent snapshot container representing a single scan execution."""
    scan_id: str
    repository: str
    repository_url: str = ""
    owner: str = ""
    branch: str = "main"
    commit_sha: str = "HEAD"
    parent_commit_sha: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    scan_mode: str = "FULL"
    files_analyzed: int = 0
    graph_nodes: int = 0
    graph_edges: int = 0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    correlated_findings: List[Dict[str, Any]] = field(default_factory=list)
    security_findings: List[Dict[str, Any]] = field(default_factory=list)
    taint_findings: List[Dict[str, Any]] = field(default_factory=list)
    repair_results: List[Dict[str, Any]] = field(default_factory=list)
    repair_validations: List[Dict[str, Any]] = field(default_factory=list)
    security_score: int = 100
    risk_summary: Dict[str, Any] = field(default_factory=dict)
    runtime: float = 0.0
    final_verdict: str = "PASS"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HistoricalFindingRecord:
    """Historical tracking entry for an individual vulnerability fingerprint."""
    fingerprint: str
    first_seen_scan_id: str
    last_seen_scan_id: str
    first_seen_commit: str
    last_seen_commit: str
    first_seen_timestamp: str
    last_seen_timestamp: str
    current_state: FindingLifecycleState = FindingLifecycleState.NEW
    state_history: List[Tuple[str, str]] = field(default_factory=list)  # [(timestamp, state)]
    root_cause: str = "UNKNOWN"
    severity: str = "MEDIUM"
    file: str = ""
    affected_function: Optional[str] = None
    title: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["current_state"] = self.current_state.value if isinstance(self.current_state, Enum) else self.current_state
        return d


@dataclass
class ChangedCodeImpact:
    """Intersection between security-sensitive git diff changes and security findings."""
    file: str
    function_name: Optional[str] = None
    lines_added: int = 0
    lines_removed: int = 0
    intersects_finding_id: Optional[str] = None
    finding_fingerprint: Optional[str] = None
    root_cause: Optional[str] = None
    severity: Optional[str] = None
    impact_level: str = "MEDIUM"
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanComparisonResult:
    """Detailed differential analysis between a baseline scan and a current scan."""
    repository: str
    baseline_scan_id: Optional[str]
    current_scan_id: str
    baseline_commit: Optional[str]
    current_commit: str
    new_findings: List[Dict[str, Any]] = field(default_factory=list)
    fixed_findings: List[Dict[str, Any]] = field(default_factory=list)
    unchanged_findings: List[Dict[str, Any]] = field(default_factory=list)
    reopened_findings: List[Dict[str, Any]] = field(default_factory=list)
    regressions: List[Dict[str, Any]] = field(default_factory=list)
    improvements: List[Dict[str, Any]] = field(default_factory=list)
    unknown_findings: List[Dict[str, Any]] = field(default_factory=list)
    score_before: int = 100
    score_after: int = 100
    score_delta: int = 0
    risk_before: str = "LOW"
    risk_after: str = "LOW"
    risk_trend: RiskTrend = RiskTrend.STABLE
    explanation: str = ""
    changed_code_impacts: List[ChangedCodeImpact] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["risk_trend"] = self.risk_trend.value if isinstance(self.risk_trend, Enum) else self.risk_trend
        d["changed_code_impacts"] = [c.to_dict() for c in self.changed_code_impacts]
        return d
