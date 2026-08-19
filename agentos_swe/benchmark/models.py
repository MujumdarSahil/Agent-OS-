"""
Domain models for M8 Benchmarking & Research Evaluation.
Includes GroundTruthCase, DetectionMetrics, VerificationMetrics, RepairMetrics, ExperimentResult, and BenchmarkReport.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from enum import Enum


class ExpectedStatus(str, Enum):
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class GroundTruthCase:
    """Single benchmark target case with ground truth metadata."""
    case_id: str
    category: str  # bug, security, performance, architecture
    file: str
    line: int
    title: str
    expected_status: ExpectedStatus
    expected_fix_file: str = ""
    description: str = ""


@dataclass
class DetectionMetrics:
    """Precision, Recall, and F1 evaluation metrics."""
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0

    def compute(self):
        tp, fp, fn = self.true_positives, self.false_positives, self.false_negatives
        self.precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        self.recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        p, r = self.precision, self.recall
        self.f1_score = (2 * p * r) / (p + r) if (p + r) > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VerificationEvaluationMetrics:
    """Verification strategy accuracy metrics."""
    correctly_confirmed: int = 0
    correctly_rejected: int = 0
    incorrectly_confirmed: int = 0
    incorrectly_rejected: int = 0
    inconclusive_accuracy: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RepairEvaluationMetrics:
    """Repair pipeline effectiveness metrics."""
    confirmed_findings: int = 0
    successful_fixes: int = 0
    failed_fixes: int = 0
    regression_failures: int = 0
    review_rejections: int = 0
    validated_patches: int = 0
    repair_success_rate: float = 0.0
    regression_free_repair_rate: float = 0.0
    avg_changed_files: float = 0.0
    avg_changed_lines: float = 0.0
    unrelated_changes_count: int = 0

    def compute(self):
        if self.confirmed_findings > 0:
            self.repair_success_rate = self.validated_patches / self.confirmed_findings
        if self.successful_fixes > 0 or self.validated_patches > 0:
            total_patches = max(self.validated_patches + self.regression_failures, 1)
            self.regression_free_repair_rate = self.validated_patches / total_patches

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExperimentResult:
    """Result for a fallback, checkpoint, or ablation experiment."""
    experiment_name: str
    baseline_completion_rate: float
    treatment_completion_rate: float
    repeated_work_reduction_pct: float = 0.0
    latency_delta_sec: float = 0.0
    token_delta: int = 0
    cost_delta_est: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BenchmarkReport:
    """Complete scientific research evaluation report for AgentOS-SWE."""
    total_cases: int
    overall_detection: DetectionMetrics
    category_detection: Dict[str, DetectionMetrics]
    verification_metrics: VerificationEvaluationMetrics
    repair_metrics: RepairEvaluationMetrics
    fallback_experiment: ExperimentResult
    checkpoint_experiment: ExperimentResult
    ablation_study_results: Dict[str, Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_cases": self.total_cases,
            "overall_detection": self.overall_detection.to_dict(),
            "category_detection": {k: v.to_dict() for k, v in self.category_detection.items()},
            "verification_metrics": self.verification_metrics.to_dict(),
            "repair_metrics": self.repair_metrics.to_dict(),
            "fallback_experiment": self.fallback_experiment.to_dict(),
            "checkpoint_experiment": self.checkpoint_experiment.to_dict(),
            "ablation_study_results": self.ablation_study_results,
        }
