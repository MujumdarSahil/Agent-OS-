"""
M23 Security Drift Analyzer & Scorer.

Compares baseline and current snapshots to detect new/fixed/reopened findings,
severity shifts, attack path shifts, and security score deltas.
Computes deterministic drift scores (0 to 100) and categories.
"""

import uuid
from typing import Dict, Any, List, Optional
from agentos_swe.operations.monitoring.models import (
    SecuritySnapshot,
    SecurityDrift,
    DriftScoreCategory,
)


class SecurityDriftScorer:
    """
    Computes deterministic security drift score (0 - 100).
    Weighting:
    - NEW CRITICAL = +30
    - NEW HIGH = +20
    - NEW MEDIUM = +8
    - NEW LOW = +2
    - NEW ATTACK PATH = +15
    - NEW EXPLOITABLE PATH = +25
    - REOPENED FINDING = +20
    - SEVERITY INCREASE = +15
    - FIXED CRITICAL = -30
    - FIXED HIGH = -20
    - FIXED MEDIUM = -8
    - FIXED LOW = -2
    """

    def calculate_drift_score(self, drift: SecurityDrift) -> float:
        score = 0.0

        for f in drift.new_findings:
            sev = str(f.get("severity", "")).upper()
            if sev == "CRITICAL":
                score += 30.0
            elif sev == "HIGH":
                score += 20.0
            elif sev == "MEDIUM":
                score += 8.0
            else:
                score += 2.0

        score += len(drift.new_attack_paths) * 15.0
        score += len(drift.new_exploitable_paths) * 25.0
        score += len(drift.reopened_findings) * 20.0
        score += len(drift.severity_increases) * 15.0

        for f in drift.fixed_findings:
            sev = str(f.get("severity", "")).upper()
            if sev == "CRITICAL":
                score -= 30.0
            elif sev == "HIGH":
                score -= 20.0
            elif sev == "MEDIUM":
                score -= 8.0
            else:
                score -= 2.0

        # Score delta penalty
        if drift.security_score_delta < 0:
            score += abs(drift.security_score_delta) * 2.0

        # Clamp to 0..100
        return round(max(0.0, min(100.0, score)), 2)

    def categorize_drift(self, drift_score: float) -> DriftScoreCategory:
        if drift_score >= 50.0:
            return DriftScoreCategory.CRITICAL_DRIFT
        elif drift_score >= 30.0:
            return DriftScoreCategory.HIGH_DRIFT
        elif drift_score >= 15.0:
            return DriftScoreCategory.MEDIUM_DRIFT
        elif drift_score > 0.0:
            return DriftScoreCategory.LOW_DRIFT
        return DriftScoreCategory.NO_DRIFT


class SecurityDriftAnalyzer:
    """
    Analyzes differences between baseline and current security snapshots.
    """

    def __init__(self):
        self.scorer = SecurityDriftScorer()

    def analyze_drift(
        self,
        baseline: SecuritySnapshot,
        current: SecuritySnapshot,
    ) -> SecurityDrift:
        """
        Determines structural drift between baseline and current snapshots.
        """
        b_findings_map = {f.get("finding_id", f.get("id", "")): f for f in baseline.findings if f.get("finding_id") or f.get("id")}
        c_findings_map = {f.get("finding_id", f.get("id", "")): f for f in current.findings if f.get("finding_id") or f.get("id")}

        new_findings: List[Dict[str, Any]] = []
        fixed_findings: List[Dict[str, Any]] = []
        reopened_findings: List[Dict[str, Any]] = []
        sev_increases: List[Dict[str, Any]] = []
        sev_decreases: List[Dict[str, Any]] = []

        # Find new & reopened
        for fid, c_f in c_findings_map.items():
            if fid not in b_findings_map:
                if c_f.get("previously_fixed") or c_f.get("lifecycle_state") == "REOPENED":
                    reopened_findings.append(c_f)
                else:
                    new_findings.append(c_f)
            else:
                b_f = b_findings_map[fid]
                b_sev = str(b_f.get("severity", "")).upper()
                c_sev = str(c_f.get("severity", "")).upper()
                sev_order = {"LOW": 1, "INFO": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
                if sev_order.get(c_sev, 0) > sev_order.get(b_sev, 0):
                    sev_increases.append(c_f)
                elif sev_order.get(c_sev, 0) < sev_order.get(b_sev, 0):
                    sev_decreases.append(c_f)

        # Find fixed
        for fid, b_f in b_findings_map.items():
            if fid not in c_findings_map:
                fixed_findings.append(b_f)

        # Attack paths
        b_paths = {ap.get("id", ap.get("fingerprint", "")): ap for ap in baseline.attack_paths if ap.get("id") or ap.get("fingerprint")}
        c_paths = {ap.get("id", ap.get("fingerprint", "")): ap for ap in current.attack_paths if ap.get("id") or ap.get("fingerprint")}

        new_paths = [ap for pid, ap in c_paths.items() if pid not in b_paths]
        removed_paths = [ap for pid, ap in b_paths.items() if pid not in c_paths]
        new_exploitable = [ap for ap in new_paths if ap.get("classification") in ("EXPLOITABLE", "PARTIALLY_MITIGATED")]

        score_delta = round(current.security_score - baseline.security_score, 2)

        drift = SecurityDrift(
            drift_id=f"drift_{uuid.uuid4().hex[:8]}",
            repository=current.repository,
            baseline_commit=baseline.commit_sha,
            current_commit=current.commit_sha,
            new_findings=new_findings,
            fixed_findings=fixed_findings,
            reopened_findings=reopened_findings,
            severity_increases=sev_increases,
            severity_decreases=sev_decreases,
            new_attack_paths=new_paths,
            removed_attack_paths=removed_paths,
            new_exploitable_paths=new_exploitable,
            security_score_delta=score_delta,
        )

        drift.drift_score = self.scorer.calculate_drift_score(drift)
        drift.category = self.scorer.categorize_drift(drift.drift_score)

        return drift
