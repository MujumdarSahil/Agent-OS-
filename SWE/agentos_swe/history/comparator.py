"""
M14 Historical Scan Comparator.

Compares a baseline ScanRecord with a current ScanRecord using deterministic fingerprints.
Categorizes finding lifecycle states (NEW, FIXED, UNCHANGED, REOPENED, REGRESSION, IMPROVEMENT),
security score deltas, and risk trends.
"""

from typing import List, Dict, Any, Optional
from agentos_swe.history.models import (
    ScanRecord,
    ScanComparisonResult,
    FindingLifecycleState,
    RiskTrend,
)
from agentos_swe.history.fingerprint import FindingFingerprinter
from agentos_swe.history.scoring import SecurityScorer
from agentos_swe.history.impact import ChangedCodeImpactAnalyzer


class HistoricalScanComparator:
    """
    Historical Scan Comparison Engine comparing security snapshots across commits.
    """

    def __init__(self):
        self.fingerprinter = FindingFingerprinter()
        self.scorer = SecurityScorer()
        self.impact_analyzer = ChangedCodeImpactAnalyzer()

    def compare_scans(
        self,
        current_scan: ScanRecord,
        previous_scan: Optional[ScanRecord] = None,
        historical_scans: Optional[List[ScanRecord]] = None,
        repository_path: Optional[str] = None,
    ) -> ScanComparisonResult:
        """
        Executes structural comparison between baseline and current scan snapshots.
        """
        repository = current_scan.repository
        current_id = current_scan.scan_id
        current_commit = current_scan.commit_sha

        if not previous_scan:
            # Baseline first-run scenario
            score, _ = self.scorer.calculate_score(current_scan.correlated_findings or current_scan.findings)
            current_scan.security_score = score
            return ScanComparisonResult(
                repository=repository,
                baseline_scan_id=None,
                current_scan_id=current_id,
                baseline_commit=None,
                current_commit=current_commit,
                new_findings=current_scan.correlated_findings or current_scan.findings,
                fixed_findings=[],
                unchanged_findings=[],
                reopened_findings=[],
                regressions=[],
                improvements=[],
                score_before=score,
                score_after=score,
                score_delta=0,
                risk_trend=RiskTrend.STABLE,
                explanation="Initial baseline scan record.",
            )

        prev_id = previous_scan.scan_id
        prev_commit = previous_scan.commit_sha

        # 1. Map Previous & Historical Fingerprints
        prev_findings = previous_scan.correlated_findings or previous_scan.findings or []
        curr_findings = current_scan.correlated_findings or current_scan.findings or []

        prev_map: Dict[str, Dict[str, Any]] = {}
        for pf in prev_findings:
            fp = pf.get("fingerprint") or self.fingerprinter.compute_fingerprint(pf)
            pf["fingerprint"] = fp
            prev_map[fp] = pf

        curr_map: Dict[str, Dict[str, Any]] = {}
        for cf in curr_findings:
            fp = cf.get("fingerprint") or self.fingerprinter.compute_fingerprint(cf)
            cf["fingerprint"] = fp
            curr_map[fp] = cf

        # Collect historical fixed fingerprints for REOPENED detection
        all_historical_fixed = set()
        if historical_scans:
            for hs in historical_scans:
                h_fps = {f.get("fingerprint") or self.fingerprinter.compute_fingerprint(f) for f in (hs.correlated_findings or hs.findings or [])}
                # If a fingerprint was in older scan hs but missing from previous_scan, it was fixed in between
                for h_fp in h_fps:
                    if h_fp not in prev_map:
                        all_historical_fixed.add(h_fp)

        # 2. Categorize Finding Lifecycles
        new_findings = []
        fixed_findings = []
        unchanged_findings = []
        reopened_findings = []

        for fp, cf in curr_map.items():
            if fp in prev_map:
                cf["lifecycle_state"] = FindingLifecycleState.UNCHANGED.value
                unchanged_findings.append(cf)
            elif fp in all_historical_fixed:
                cf["lifecycle_state"] = FindingLifecycleState.REOPENED.value
                reopened_findings.append(cf)
            else:
                cf["lifecycle_state"] = FindingLifecycleState.NEW.value
                new_findings.append(cf)

        for fp, pf in prev_map.items():
            if fp not in curr_map:
                pf["lifecycle_state"] = FindingLifecycleState.FIXED.value
                fixed_findings.append(pf)

        # 3. Security Scores & Deltas
        score_before, _ = self.scorer.calculate_score(prev_findings)
        score_after, _ = self.scorer.calculate_score(curr_findings)
        score_delta = score_after - score_before

        current_scan.security_score = score_after
        previous_scan.security_score = score_before

        # 4. Check New Critical / High
        has_new_crit_high = any(
            (f.get("severity") or "MEDIUM").upper() in ("CRITICAL", "HIGH")
            for f in (new_findings + reopened_findings)
        )

        trend, explanation = self.scorer.evaluate_trend(
            score_before=score_before,
            score_after=score_after,
            new_critical_or_high=has_new_crit_high,
            reopened_count=len(reopened_findings),
        )

        regressions = []
        if trend == RiskTrend.DEGRADING:
            regressions = new_findings + reopened_findings

        improvements = fixed_findings if trend == RiskTrend.IMPROVING or score_delta > 0 else []

        # 5. Changed-Code Impact Analysis if repository_path provided
        changed_impacts = []
        if repository_path:
            changed_impacts = self.impact_analyzer.analyze_git_diff(
                repository_path=repository_path,
                commit_a=prev_commit,
                commit_b=current_commit,
                findings=curr_findings,
            )

        return ScanComparisonResult(
            repository=repository,
            baseline_scan_id=prev_id,
            current_scan_id=current_id,
            baseline_commit=prev_commit,
            current_commit=current_commit,
            new_findings=new_findings,
            fixed_findings=fixed_findings,
            unchanged_findings=unchanged_findings,
            reopened_findings=reopened_findings,
            regressions=regressions,
            improvements=improvements,
            score_before=score_before,
            score_after=score_after,
            score_delta=score_delta,
            risk_before="HIGH" if score_before < 70 else ("MEDIUM" if score_before < 90 else "LOW"),
            risk_after="HIGH" if score_after < 70 else ("MEDIUM" if score_after < 90 else "LOW"),
            risk_trend=trend,
            explanation=explanation,
            changed_code_impacts=changed_impacts,
        )
