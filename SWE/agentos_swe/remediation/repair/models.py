"""
Domain models for M4, M13 & M13.1 Controlled Autonomous Repair & Patch Validation.
Includes ImpactReport, FixPlan, PatchResult, PatchReviewResult, ValidatedPatch,
RepairStatus, RepairProposal, ValidationResult, SecurityRegressionResult,
RepairVerdict, PatchQualityMetrics, and RepairValidationResult.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional, Tuple


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


class RegressionStatus(str, Enum):
    """Status of post-patch security regression comparison."""
    CLEAN = "CLEAN"
    PARTIAL_FIX = "PARTIAL_FIX"
    NEW_VULNERABILITY_INTRODUCED = "NEW_VULNERABILITY_INTRODUCED"
    UNRELATED_REGRESSION = "UNRELATED_REGRESSION"


class RepairVerdict(str, Enum):
    """Final empirical validation verdict for an intelligent repair attempt."""
    REPAIRED = "REPAIRED"
    PARTIALLY_REPAIRED = "PARTIALLY_REPAIRED"
    REPAIR_FAILED = "REPAIR_FAILED"
    NO_REPAIR_REQUIRED = "NO_REPAIR_REQUIRED"
    REGRESSION_DETECTED = "REGRESSION_DETECTED"
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


# ---------------------------------------------------------------------------
# M13 & M13.1 Intelligent Repair & Validation Extensions
# ---------------------------------------------------------------------------

@dataclass
class RepairProposal:
    """Structured proposal generated before patch application explaining remediation strategy."""
    finding_id: str
    root_cause: str
    strategy: str
    target_file: str
    target_lines: Optional[Tuple[int, int]] = None
    original_snippet: str = ""
    proposed_snippet: str = ""
    unified_diff: str = ""
    rationale: str = ""
    expected_risk_reduction: str = ""
    confidence: float = 0.90

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.target_lines is not None:
            d["target_lines"] = list(self.target_lines)
        return d


@dataclass
class ValidationResult:
    """Detailed sandboxed validation result for a candidate patch."""
    success: bool
    syntax_valid: bool = True
    repro_valid: bool = True
    regression_valid: bool = True
    taint_valid: bool = True
    error_reason: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityRegressionResult:
    """Structured post-patch security regression comparison."""
    original_findings_count: int
    post_patch_findings_count: int
    fixed_findings: List[str] = field(default_factory=list)
    remaining_findings: List[str] = field(default_factory=list)
    newly_introduced_findings: List[str] = field(default_factory=list)
    regression_status: RegressionStatus = RegressionStatus.CLEAN
    confidence: float = 0.95

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["regression_status"] = self.regression_status.value if isinstance(self.regression_status, Enum) else self.regression_status
        return d


@dataclass
class PatchQualityMetrics:
    """Deterministic patch quality metrics evaluating diff minimalness and API preservation."""
    modified_files_count: int = 1
    lines_added: int = 0
    lines_removed: int = 0
    total_lines_changed: int = 0
    api_signatures_preserved: bool = True
    unrelated_formatting_changes: bool = False
    quality_score: str = "HIGH"
    eval_reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RepairValidationResult:
    """
    Comprehensive empirical validation result proving repair efficacy and security regression status.
    """
    finding_id: str
    repository: str
    target_file: str
    target_lines: Optional[Tuple[int, int]] = None
    vulnerability_type: str = "UNKNOWN"
    original_severity: str = "MEDIUM"
    repair_strategy: str = "NONE"
    patch_generated: bool = False
    patch_applied: bool = False
    syntax_valid: bool = True
    tests_passed: bool = True
    reproduction_passed: bool = True
    original_finding_present_before: bool = True
    original_finding_present_after: bool = False
    taint_present_before: bool = False
    taint_present_after: bool = False
    removed_security_findings: List[str] = field(default_factory=list)
    remaining_security_findings: List[str] = field(default_factory=list)
    new_security_findings: List[str] = field(default_factory=list)
    regression_status: RegressionStatus = RegressionStatus.CLEAN
    patch_quality: PatchQualityMetrics = field(default_factory=PatchQualityMetrics)
    risk_reduction: str = ""
    validation_confidence: float = 0.95
    final_verdict: RepairVerdict = RepairVerdict.INCONCLUSIVE
    failure_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["regression_status"] = self.regression_status.value if isinstance(self.regression_status, Enum) else self.regression_status
        d["final_verdict"] = self.final_verdict.value if isinstance(self.final_verdict, Enum) else self.final_verdict
        d["patch_quality"] = self.patch_quality.to_dict()
        if self.target_lines is not None:
            d["target_lines"] = list(self.target_lines)
        return d
