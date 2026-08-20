"""
BenchmarkEvaluator - Computes Precision, Recall, F1, Verification Accuracy, Repair Success Rates, and Patch Quality (M8).
"""

import logging
from typing import List, Dict, Any, Tuple

from agentos_swe.models import Finding, FindingStatus
from agentos_swe.repair.models import ValidatedPatch
from agentos_swe.benchmark.models import (
    GroundTruthCase,
    ExpectedStatus,
    DetectionMetrics,
    VerificationEvaluationMetrics,
    RepairEvaluationMetrics,
)

logger = logging.getLogger(__name__)


class BenchmarkEvaluator:
    """
    Evaluates AgentOS-SWE candidate findings, verification decisions, and validated patches against ground truth.
    """

    def evaluate_detection(
        self,
        findings: List[Finding],
        ground_truth: List[GroundTruthCase],
    ) -> Tuple[DetectionMetrics, Dict[str, DetectionMetrics]]:
        overall = DetectionMetrics()
        category_metrics: Dict[str, DetectionMetrics] = {
            "bug": DetectionMetrics(),
            "security": DetectionMetrics(),
            "performance": DetectionMetrics(),
            "architecture": DetectionMetrics(),
        }

        tp_cases = {gt.case_id: gt for gt in ground_truth if gt.expected_status == ExpectedStatus.TRUE_POSITIVE}

        # Match detected findings to ground truth cases
        matched_gt_ids = set()

        for f in findings:
            cat = (f.category or "bug").lower()
            if cat not in category_metrics:
                category_metrics[cat] = DetectionMetrics()

            matched = False
            for gt in tp_cases.values():
                if gt.category.lower() == cat and gt.file.lower() in f.file.lower():
                    matched = True
                    matched_gt_ids.add(gt.case_id)
                    overall.true_positives += 1
                    category_metrics[cat].true_positives += 1
                    break

            if not matched:
                overall.false_positives += 1
                category_metrics[cat].false_positives += 1

        # Unmatched ground truth true positives are false negatives
        for gt in tp_cases.values():
            if gt.case_id not in matched_gt_ids:
                overall.false_negatives += 1
                cat = gt.category.lower()
                if cat in category_metrics:
                    category_metrics[cat].false_negatives += 1

        overall.compute()
        for m in category_metrics.values():
            m.compute()

        return overall, category_metrics

    def evaluate_verification(
        self,
        verified_findings: List[Finding],
        ground_truth: List[GroundTruthCase],
    ) -> VerificationEvaluationMetrics:
        metrics = VerificationEvaluationMetrics()
        gt_map = {gt.title.lower(): gt for gt in ground_truth}

        for vf in verified_findings:
            title_lower = vf.title.lower()
            gt_case = None
            for key, val in gt_map.items():
                if key in title_lower or title_lower in key:
                    gt_case = val
                    break

            if not gt_case:
                continue

            if vf.status == FindingStatus.CONFIRMED:
                if gt_case.expected_status == ExpectedStatus.TRUE_POSITIVE:
                    metrics.correctly_confirmed += 1
                else:
                    metrics.incorrectly_confirmed += 1
            elif vf.status == FindingStatus.REJECTED:
                if gt_case.expected_status == ExpectedStatus.FALSE_POSITIVE:
                    metrics.correctly_rejected += 1
                else:
                    metrics.incorrectly_rejected += 1
            elif vf.status == FindingStatus.INCONCLUSIVE:
                if gt_case.expected_status == ExpectedStatus.INCONCLUSIVE:
                    metrics.inconclusive_accuracy += 1.0

        total_verif = (
            metrics.correctly_confirmed
            + metrics.correctly_rejected
            + metrics.incorrectly_confirmed
            + metrics.incorrectly_rejected
        )
        if total_verif > 0:
            metrics.inconclusive_accuracy = (
                metrics.correctly_confirmed + metrics.correctly_rejected
            ) / total_verif

        return metrics

    def evaluate_repair_and_quality(
        self,
        confirmed_count: int,
        validated_patches: List[ValidatedPatch],
    ) -> RepairEvaluationMetrics:
        metrics = RepairEvaluationMetrics()
        metrics.confirmed_findings = confirmed_count
        metrics.validated_patches = len(validated_patches)
        metrics.successful_fixes = len(validated_patches)

        total_files = 0
        total_lines = 0

        for p in validated_patches:
            total_files += len(p.changed_files)
            diff_lines = p.patch_diff.splitlines()
            added = len([l for l in diff_lines if l.startswith("+") and not l.startswith("+++")])
            removed = len([l for l in diff_lines if l.startswith("-") and not l.startswith("---")])
            total_lines += added + removed

        if validated_patches:
            metrics.avg_changed_files = total_files / len(validated_patches)
            metrics.avg_changed_lines = total_lines / len(validated_patches)

        metrics.compute()
        return metrics
