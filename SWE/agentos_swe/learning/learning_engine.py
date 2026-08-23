"""
M25 Continuous Security Learning Engine Master Facade.

Coordinates historical security memory persistence, pattern detection, trend analysis,
vulnerability recurrence classification, remediation efficacy learning, adaptive risk signal
generation, and explainability reporting for AgentOS-SWE.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

from agentos_swe.learning.models import LearningEngineResult
from agentos_swe.learning.security_memory import SecurityMemory
from agentos_swe.learning.pattern_detector import SecurityPatternDetector
from agentos_swe.learning.trend_analyzer import SecurityTrendAnalyzer
from agentos_swe.learning.recurrence_analyzer import RecurrenceAnalyzer
from agentos_swe.learning.remediation_learning import RemediationLearningEngine
from agentos_swe.learning.risk_adaptation import AdaptiveRiskEngine
from agentos_swe.learning.explainability import LearningExplainabilityEngine
from agentos_swe.history.models import ScanRecord

logger = logging.getLogger(__name__)


class ContinuousSecurityLearningEngine:
    """
    Master facade engine for M25 Continuous Security Learning, Trend Intelligence & Adaptive Risk Engine.
    """

    def __init__(self, memory_store: Optional[SecurityMemory] = None):
        self.memory = memory_store or SecurityMemory()
        self.pattern_detector = SecurityPatternDetector()
        self.trend_analyzer = SecurityTrendAnalyzer()
        self.recurrence_analyzer = RecurrenceAnalyzer()
        self.remediation_learning = RemediationLearningEngine()
        self.risk_adapter = AdaptiveRiskEngine()
        self.explainability_engine = LearningExplainabilityEngine()

    def run_learning_pipeline(
        self,
        repository_name: str,
        commit_sha: str = "HEAD",
        current_findings: Optional[List[Dict[str, Any]]] = None,
        attack_paths: Optional[List[Dict[str, Any]]] = None,
        drift_result: Optional[Dict[str, Any]] = None,
        orchestration_result: Optional[Any] = None,
        repair_validations: Optional[List[Dict[str, Any]]] = None,
        repair_results: Optional[List[Dict[str, Any]]] = None,
        current_security_score: int = 100,
        parent_commit_sha: Optional[str] = None,
    ) -> LearningEngineResult:
        """
        Executes the end-to-end continuous learning and trend intelligence pipeline.
        """
        findings = current_findings or []

        # 1. Build and save ScanRecord snapshot into SecurityMemory
        scan_id = f"scan_{repository_name}_{commit_sha[:8]}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        scan_rec = ScanRecord(
            scan_id=scan_id,
            repository=repository_name,
            commit_sha=commit_sha,
            parent_commit_sha=parent_commit_sha,
            timestamp=datetime.now().isoformat(),
            findings=findings,
            correlated_findings=findings,
            security_findings=findings,
            repair_results=[rp.to_dict() if hasattr(rp, "to_dict") else rp for rp in (repair_results or [])],
            repair_validations=[rv.to_dict() if hasattr(rv, "to_dict") else rv for rv in (repair_validations or [])],
            security_score=current_security_score,
            final_verdict=getattr(orchestration_result, "governance_outcome", "PASS") if orchestration_result else "PASS",
        )
        self.memory.record_scan_snapshot(scan_rec)

        # 2. Extract historical scan records & finding memories
        historical_scans = self.memory.get_repository_scans(repository_name)
        finding_memories = self.memory.extract_finding_memories(repository_name)

        # 3. Analyze Posture Trends over history
        trend = self.trend_analyzer.analyze_trends(
            historical_scans=historical_scans[1:],  # Exclude current scan record just saved
            current_score=current_security_score,
            current_findings=findings,
        )

        # 4. Detect Recurring & Emerging Security Patterns
        detected_patterns = self.pattern_detector.detect_patterns(
            finding_memories=finding_memories,
            historical_scans=historical_scans,
            current_findings=findings,
            attack_paths=[ap.to_dict() if hasattr(ap, "to_dict") else ap for ap in (attack_paths or [])],
            drift_result=drift_result,
        )

        # 5. Analyze Vulnerability Recurrence & Classifications
        recurrence_analysis = self.recurrence_analyzer.analyze_recurrence(finding_memories)

        # 6. Learn Remediation Strategy Efficacy
        remediation_learning = self.remediation_learning.analyze_remediation_efficacy(
            historical_scans=historical_scans,
            finding_memories=finding_memories,
        )

        # 7. Generate Adaptive Risk Signals
        adaptive_signals = self.risk_adapter.compute_adaptive_signals(
            current_findings=findings,
            recurrence_insights=recurrence_analysis,
            patterns=detected_patterns,
        )

        # 8. Generate Explainability Report
        explainability = self.explainability_engine.generate_explainability_report(
            repository_name=repository_name,
            detected_patterns=detected_patterns,
            trend=trend,
            recurrence_insights=recurrence_analysis,
            remediation_lessons=remediation_learning,
            adaptive_signals=adaptive_signals,
        )

        return LearningEngineResult(
            repository_name=repository_name,
            commit_sha=commit_sha,
            timestamp=datetime.now().isoformat(),
            scan_count=len(historical_scans),
            memory_records=len(finding_memories),
            detected_patterns=detected_patterns,
            trend=trend,
            recurrence_analysis=recurrence_analysis,
            remediation_learning=remediation_learning,
            adaptive_signals=adaptive_signals,
            explainability=explainability,
        )
