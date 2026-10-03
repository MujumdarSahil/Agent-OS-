"""
Targeted tests for M8 Benchmarking & Research Evaluation.
"""

import pytest
from agentos_swe.core.models import Finding, FindingStatus
from agentos_swe.remediation.repair.models import ValidatedPatch, ImpactReport, PatchReviewResult, ReviewStatus
from agentos_swe.benchmark.models import GroundTruthCase, ExpectedStatus, DetectionMetrics
from agentos_swe.benchmark.fixtures import BenchmarkFixtures
from agentos_swe.benchmark.evaluator import BenchmarkEvaluator
from agentos_swe.benchmark.experiments import ResilienceExperiments
from agentos_swe.benchmark.runner import BenchmarkRunner


@pytest.fixture(autouse=True)
def mock_llm_env(monkeypatch):
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")


def test_benchmark_fixtures_creation(tmp_path):
    repo_dir, ground_truth = BenchmarkFixtures.create_benchmark_workspace()
    assert len(ground_truth) == 6
    assert any(gt.category == "bug" for gt in ground_truth)
    assert any(gt.expected_status == ExpectedStatus.FALSE_POSITIVE for gt in ground_truth)


def test_detection_precision_recall_f1_calculation():
    evaluator = BenchmarkEvaluator()

    ground_truth = [
        GroundTruthCase(case_id="1", category="bug", file="app.py", line=1, title="Bug", expected_status=ExpectedStatus.TRUE_POSITIVE),
        GroundTruthCase(case_id="2", category="security", file="auth.py", line=1, title="Sec", expected_status=ExpectedStatus.TRUE_POSITIVE),
    ]

    findings = [
        Finding(title="Bug", category="bug", file="app.py"),
        Finding(title="Unknown", category="bug", file="other.py"),
    ]

    overall, cat_metrics = evaluator.evaluate_detection(findings, ground_truth)

    assert overall.true_positives == 1
    assert overall.false_positives == 1
    assert overall.false_negatives == 1
    assert abs(overall.precision - 0.50) < 0.01
    assert abs(overall.recall - 0.50) < 0.01
    assert abs(overall.f1_score - 0.50) < 0.01


def test_verification_accuracy_evaluation():
    evaluator = BenchmarkEvaluator()

    ground_truth = [
        GroundTruthCase(case_id="1", category="bug", file="app.py", line=1, title="Bug", expected_status=ExpectedStatus.TRUE_POSITIVE),
        GroundTruthCase(case_id="2", category="security", file="app.py", line=5, title="Sanitized claim", expected_status=ExpectedStatus.FALSE_POSITIVE),
    ]

    verified = [
        Finding(title="Bug", file="app.py", status=FindingStatus.CONFIRMED),
        Finding(title="Sanitized claim", file="app.py", status=FindingStatus.REJECTED),
    ]

    verif_metrics = evaluator.evaluate_verification(verified, ground_truth)
    assert verif_metrics.correctly_confirmed == 1
    assert verif_metrics.correctly_rejected == 1
    assert verif_metrics.incorrectly_confirmed == 0
    assert verif_metrics.incorrectly_rejected == 0


def test_repair_and_patch_quality_metrics():
    evaluator = BenchmarkEvaluator()

    patch = ValidatedPatch(
        finding_id="f1",
        patch_diff="--- a/app.py\n+++ b/app.py\n+pass\n",
        changed_files=["app.py"],
        impact_report=ImpactReport(finding_id="f1", target_file="app.py"),
        reproduction_result={"success": True},
        regression_result={"success": True},
        review_result=PatchReviewResult(status=ReviewStatus.APPROVED, reason="ok"),
    )

    repair_metrics = evaluator.evaluate_repair_and_quality(confirmed_count=1, validated_patches=[patch])
    assert repair_metrics.confirmed_findings == 1
    assert repair_metrics.validated_patches == 1
    assert repair_metrics.repair_success_rate == 1.0
    assert repair_metrics.regression_free_repair_rate == 1.0


def test_resilience_experiments():
    fallback_res = ResilienceExperiments.run_fallback_experiment()
    assert fallback_res.treatment_completion_rate > fallback_res.baseline_completion_rate

    chk_res = ResilienceExperiments.run_checkpoint_experiment()
    assert chk_res.repeated_work_reduction_pct > 80.0

    ablation = ResilienceExperiments.run_ablation_studies()
    assert "single_vs_multi_agent" in ablation
    assert "investigation_vs_verification" in ablation


def test_benchmark_runner_full_suite():
    runner = BenchmarkRunner()
    report = runner.run_benchmark_suite()

    assert report.total_cases > 0
    assert report.overall_detection.precision >= 0.0
    assert report.repair_metrics.repair_success_rate >= 0.0
    assert report.fallback_experiment.treatment_completion_rate == 1.0
