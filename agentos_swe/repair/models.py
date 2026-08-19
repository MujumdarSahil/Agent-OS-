"""
Domain models for M4 Controlled Autonomous Repair.
Includes ImpactReport, FixPlan, PatchResult, PatchReviewResult, ValidatedPatch, and RepairStatus.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional


class RepairStatus(str, Enum):
    """Status of an autonomous repair attempt."""
    VALIDATED = "VALIDATED"
    REPAIR_FAILED = "REPAIR_FAILED"
    TEST_FAILED = "TEST_FAILED"
    REGRESSION_FAILED = "REGRESSION_FAILED"
    REVIEW_REJECTED = "REVIEW_REJECTED"
    NOT_CONFIRMED = "NOT_CONFIRMED"


class ReviewStatus(str, Enum):
    """Status of independent patch review."""
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class ImpactReport:
    """Blast radius and code graph impact analysis for a confirmed finding."""
    finding_id: str
    target_file: str
    affected_files: List[str] = field(default_factory=list)
    affected_symbols: List[str] = field(default_factory=list)
    callers: List[str] = field(default_factory=list)
    dependents: List[str] = field(default_factory=list)
    related_tests: List[str] = field(default_factory=list)
    risk_signals: List[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FixPlan:
    """Structured plan outlining the smallest safe code modification."""
    finding_id: str
    target_file: str
    defect_summary: str
    proposed_fix_strategy: str
    allowed_line_range: Optional[tuple] = None
    tests_to_validate: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PatchResult:
    """Result of candidate patch generation and application inside sandbox."""
    success: bool
    diff: str = ""
    changed_files: List[str] = field(default_factory=list)
    patch_content: str = ""
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PatchReviewResult:
    """Result of independent patch review."""
    status: ReviewStatus
    reason: str
    is_minimal: bool = True
    preserves_architecture: bool = True

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value if isinstance(self.status, Enum) else self.status
        return data


@dataclass
class ValidatedPatch:
    """Validated patch container representing a fully verified code repair."""
    finding_id: str
    patch_diff: str
    changed_files: List[str]
    impact_report: ImpactReport
    reproduction_result: Dict[str, Any]
    regression_result: Dict[str, Any]
    review_result: PatchReviewResult
    status: RepairStatus = RepairStatus.VALIDATED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "patch_diff": self.patch_diff,
            "changed_files": self.changed_files,
            "impact_report": self.impact_report.to_dict(),
            "reproduction_result": self.reproduction_result,
            "regression_result": self.regression_result,
            "review_result": self.review_result.to_dict(),
            "status": self.status.value if isinstance(self.status, Enum) else self.status,
        }
