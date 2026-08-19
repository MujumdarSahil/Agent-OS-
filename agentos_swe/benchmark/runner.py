"""
BenchmarkRunner - Complete scientific research benchmark evaluation runner for AgentOS-SWE (M8).
"""

import os
import shutil
import logging
from typing import Dict, Any, Optional

from agentos_swe.intake import RepositoryIntake
from agentos_swe.context import build_repository_context
from agentos_swe.squad import InvestigationSquad
from agentos_swe.verification import VerificationPipeline
from agentos_swe.repair import RepairPipeline
from agentos_swe.models import FindingStatus
from agentos_swe.benchmark.models import BenchmarkReport
from agentos_swe.benchmark.fixtures import BenchmarkFixtures
from agentos_swe.benchmark.evaluator import BenchmarkEvaluator
from agentos_swe.benchmark.experiments import ResilienceExperiments

logger = logging.getLogger(__name__)


class BenchmarkRunner:
    """
    Executes full scientific research evaluation suite across M0-M7 phases.
    """

    def __init__(self, evaluator: Optional[BenchmarkEvaluator] = None):
        self.evaluator = evaluator or BenchmarkEvaluator()

    def run_benchmark_suite(self) -> BenchmarkReport:
        """
        Executes benchmark evaluation on synthetic ground truth repository dataset.
        Returns comprehensive BenchmarkReport.
        """
        repo_dir, ground_truth = BenchmarkFixtures.create_benchmark_workspace()

        try:
            # 1. Intake & Context Building (M1)
            intake = RepositoryIntake()
            intake_res = intake.analyze(repo_dir)
            context = build_repository_context(repo_dir)

            # 2. Investigation Squad (M2)
            squad = InvestigationSquad()
            candidates = squad.analyze_repository(context)

            # 3. Verification Pipeline (M3)
            verif_pipeline = VerificationPipeline()
            verified_findings = verif_pipeline.verify_findings(candidates, context, mission_id="bm_verif_001")

            # 4. Repair Pipeline (M4)
            repair_pipeline = RepairPipeline()
            validated_patches = []
            confirmed_count = 0

            for f in verified_findings:
                if f.status == FindingStatus.CONFIRMED:
                    confirmed_count += 1
                    patch = repair_pipeline.repair_finding(f, context, mission_id="bm_repair_001")
                    if patch:
                        validated_patches.append(patch)

            # 5. Evaluate Detection Metrics (Precision, Recall, F1)
            overall_det, cat_det = self.evaluator.evaluate_detection(candidates, ground_truth)

            # 6. Evaluate Verification Metrics
            verif_metrics = self.evaluator.evaluate_verification(verified_findings, ground_truth)

            # 7. Evaluate Repair & Patch Quality Metrics
            repair_metrics = self.evaluator.evaluate_repair_and_quality(confirmed_count, validated_patches)

            # 8. Run Resilience Experiments & Ablation Studies
            fallback_exp = ResilienceExperiments.run_fallback_experiment()
            checkpoint_exp = ResilienceExperiments.run_checkpoint_experiment()
            ablation_results = ResilienceExperiments.run_ablation_studies()

            report = BenchmarkReport(
                total_cases=len(ground_truth),
                overall_detection=overall_det,
                category_detection=cat_det,
                verification_metrics=verif_metrics,
                repair_metrics=repair_metrics,
                fallback_experiment=fallback_exp,
                checkpoint_experiment=checkpoint_exp,
                ablation_study_results=ablation_results,
            )

            logger.info(f"[BenchmarkRunner] Suite completed. Overall F1: {overall_det.f1_score:.2f}, Repair Success Rate: {repair_metrics.repair_success_rate * 100:.1f}%")
            return report

        finally:
            # Clean up temp benchmark directory
            if os.path.exists(repo_dir):
                try:
                    shutil.rmtree(repo_dir, ignore_errors=True)
                except Exception as ex:
                    logger.debug(f"Benchmark cleanup note: {ex}")
