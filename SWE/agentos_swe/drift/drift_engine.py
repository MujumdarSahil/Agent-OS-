"""
M26 Security Monitoring & Drift Engine Master Facade.

Coordinates postural comparison, changed surface analysis, drift detection, impact scoring,
drift correlation, root-cause investigation, and governance decision integration.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

from agentos_swe.drift.models import DriftEngineResult, DriftSummary, DriftSeverity
from agentos_swe.drift.comparator import SecurityPosturalComparator
from agentos_swe.drift.changed_surface import ChangedSurfaceAnalyzer
from agentos_swe.drift.drift_detector import SecurityDriftDetector
from agentos_swe.drift.drift_scorer import SecurityDriftScorer
from agentos_swe.drift.drift_correlator import SecurityDriftCorrelator
from agentos_swe.drift.drift_investigator import SecurityDriftInvestigator

logger = logging.getLogger(__name__)


class SecurityMonitoringDriftEngine:
    """
    Master engine facade for M26 Continuous Security Monitoring & Drift Detection.
    """

    def __init__(self):
        self.comparator = SecurityPosturalComparator()
        self.surface_analyzer = ChangedSurfaceAnalyzer()
        self.detector = SecurityDriftDetector()
        self.scorer = SecurityDriftScorer()
        self.correlator = SecurityDriftCorrelator()
        self.investigator = SecurityDriftInvestigator()

    def run_monitoring_pipeline(
        self,
        repository_name: str,
        current_commit: str = "HEAD",
        baseline_commit: Optional[str] = None,
        current_findings: Optional[List[Dict[str, Any]]] = None,
        baseline_findings: Optional[List[Dict[str, Any]]] = None,
        attack_paths: Optional[List[Dict[str, Any]]] = None,
        baseline_attack_paths: Optional[List[Dict[str, Any]]] = None,
        simulation_results: Optional[Any] = None,
        repository_path: Optional[str] = None,
        current_security_score: int = 100,
        baseline_security_score: int = 100,
        historical_memories: Optional[List[Dict[str, Any]]] = None,
        learning_result: Optional[Any] = None,
    ) -> DriftEngineResult:
        """
        Executes the end-to-end continuous security monitoring and drift detection pipeline.
        """
        curr_f = [f.to_dict() if hasattr(f, "to_dict") else f for f in (current_findings or [])]
        base_f = [f.to_dict() if hasattr(f, "to_dict") else f for f in (baseline_findings or [])]
        paths = [ap.to_dict() if hasattr(ap, "to_dict") else ap for ap in (attack_paths or [])]
        base_paths = [ap.to_dict() if hasattr(ap, "to_dict") else ap for ap in (baseline_attack_paths or [])]

        # 1. Postural Differential Analysis
        comparison = self.comparator.compare_postures(
            current_findings=curr_f,
            baseline_findings=base_f,
            current_attack_paths=paths,
            baseline_attack_paths=base_paths,
            current_score=current_security_score,
            baseline_score=baseline_security_score,
            current_commit=current_commit,
            baseline_commit=baseline_commit,
        )

        # 2. Changed Security Surface Analysis
        surface = self.surface_analyzer.analyze_changed_surface(
            repository_path=repository_path,
            current_commit=current_commit,
            baseline_commit=baseline_commit,
            findings=curr_f,
            attack_paths=paths,
        )

        # 3. Detect Security Drift Events
        raw_events = self.detector.detect_drift_events(
            comparison=comparison,
            surface=surface,
            current_findings=curr_f,
        )

        # 4. Correlate with History and Learning Signals
        correlated_events = self.correlator.correlate_drift_events(
            events=raw_events,
            historical_memories=historical_memories,
            learning_patterns=getattr(learning_result, "detected_patterns", []) if learning_result else None,
        )

        # 5. Score Drift Impact
        impact = self.scorer.compute_drift_impact(
            events=correlated_events,
            score_delta=comparison.score_delta,
            new_findings_count=len(comparison.new_findings),
            fixed_findings_count=len(comparison.fixed_findings),
            reopened_findings_count=len(comparison.reopened_findings),
        )

        # 6. Investigate Drift Root Cause ("WHY DID SECURITY DRIFT?")
        investigations = self.investigator.investigate_drift_events(
            events=correlated_events,
            comparison=comparison,
            surface=surface,
        )

        # 7. Summary and Governance Verdict
        crit_count = sum(1 for e in correlated_events if e.severity == DriftSeverity.CRITICAL)
        high_count = sum(1 for e in correlated_events if e.severity == DriftSeverity.HIGH)

        if crit_count > 0 or impact.drift_score >= 70.0:
            gov_verdict = "DENY"
            status = "CRITICAL_SECURITY_DRIFT"
        elif high_count > 0 or impact.drift_score >= 40.0:
            gov_verdict = "REVIEW_REQUIRED"
            status = "HIGH_SECURITY_DRIFT"
        elif impact.drift_score > 0:
            gov_verdict = "ALLOW"
            status = "MODERATE_DRIFT"
        else:
            gov_verdict = "ALLOW"
            status = "NO_DRIFT"

        summary = DriftSummary(
            overall_status=status,
            drift_score=impact.drift_score,
            drift_severity=impact.severity,
            drift_direction=impact.direction,
            total_drift_events=len(correlated_events),
            critical_events_count=crit_count,
            high_events_count=high_count,
        )

        return DriftEngineResult(
            repository_name=repository_name,
            commit_sha=current_commit,
            timestamp=datetime.now().isoformat(),
            summary=summary,
            impact=impact,
            drift_events=correlated_events,
            changed_surface=surface,
            comparison=comparison,
            investigations=investigations,
            governance_verdict=gov_verdict,
        )
