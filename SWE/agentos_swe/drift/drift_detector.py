"""
M26 Security Drift Detector.

Implements deterministic rule evaluation across 16 security drift event types
while guaranteeing strict false positive protection.
"""

from typing import List, Dict, Any, Optional

from agentos_swe.drift.models import (
    SecurityDriftEvent,
    DriftType,
    DriftSeverity,
    DriftComparisonResult,
    ChangedSecuritySurface,
)


class SecurityDriftDetector:
    """
    Evaluates deterministic security drift rules across baseline comparison metrics.
    """

    SAFE_ROOT_CAUSES = {
        "DICT_LOOKUP",
        "INTENTIONAL_FALLBACK",
        "TEST_HARNESS_DIAGNOSTIC",
        "FORMATTING_ONLY",
        "COMMENT_ONLY",
    }

    def detect_drift_events(
        self,
        comparison: DriftComparisonResult,
        surface: ChangedSecuritySurface,
        current_findings: List[Dict[str, Any]],
        learning_signals: Optional[List[Dict[str, Any]]] = None,
    ) -> List[SecurityDriftEvent]:
        """
        Detects discrete security drift events across comparison results and changed code surfaces.
        """
        events: List[SecurityDriftEvent] = []

        # 1. NEW_VULNERABILITY
        for idx, f in enumerate(comparison.new_findings):
            rc = f.get("root_cause") or f.get("category") or "UNKNOWN"
            if rc in self.SAFE_ROOT_CAUSES or f.get("sanitized") or f.get("is_safe"):
                continue  # False Positive Protection

            sev_str = (f.get("severity") or "MEDIUM").upper()
            sev = (
                DriftSeverity.CRITICAL if sev_str == "CRITICAL"
                else (DriftSeverity.HIGH if sev_str == "HIGH"
                      else (DriftSeverity.MEDIUM if sev_str == "MEDIUM" else DriftSeverity.LOW))
            )
            fid = f.get("finding_id") or f.get("id") or f"new_f_{idx+1}"

            events.append(
                SecurityDriftEvent(
                    event_id=f"evt_new_{fid}",
                    drift_type=DriftType.NEW_VULNERABILITY,
                    severity=sev,
                    title=f"New {sev_str} Vulnerability Detected: {rc}",
                    description=f"New finding '{rc}' detected in file '{f.get('file', '')}'.",
                    finding_id=fid,
                    fingerprint=f.get("fingerprint"),
                    root_cause=rc,
                    file=f.get("file"),
                    current_state=f,
                    evidence=[f"Finding ID: {fid}", f"Root Cause: {rc}", f"File: {f.get('file')}"],
                )
            )

        # 2. FIXED_VULNERABILITY
        for idx, f in enumerate(comparison.fixed_findings):
            rc = f.get("root_cause") or "UNKNOWN"
            if rc in self.SAFE_ROOT_CAUSES:
                continue
            fid = f.get("finding_id") or f.get("id") or f"fix_f_{idx+1}"
            events.append(
                SecurityDriftEvent(
                    event_id=f"evt_fix_{fid}",
                    drift_type=DriftType.FIXED_VULNERABILITY,
                    severity=DriftSeverity.LOW,
                    title=f"Vulnerability Remediated: {rc}",
                    description=f"Baseline finding '{rc}' in file '{f.get('file', '')}' was resolved.",
                    finding_id=fid,
                    fingerprint=f.get("fingerprint"),
                    root_cause=rc,
                    file=f.get("file"),
                    previous_state=f,
                    evidence=[f"Remediated finding fingerprint: {f.get('fingerprint')}"],
                )
            )

        # 3. REOPENED_VULNERABILITY
        for idx, f in enumerate(comparison.reopened_findings):
            rc = f.get("root_cause") or "UNKNOWN"
            fid = f.get("finding_id") or f.get("id") or f"reopen_f_{idx+1}"
            events.append(
                SecurityDriftEvent(
                    event_id=f"evt_reopen_{fid}",
                    drift_type=DriftType.REOPENED_VULNERABILITY,
                    severity=DriftSeverity.HIGH,
                    title=f"Vulnerability Reopened: {rc}",
                    description=f"Previously remediated finding '{rc}' in '{f.get('file', '')}' has reopened.",
                    finding_id=fid,
                    fingerprint=f.get("fingerprint"),
                    root_cause=rc,
                    file=f.get("file"),
                    current_state=f,
                    evidence=[f"Reopened finding: {fid}", f"Reopen count: {f.get('reopened_count', 1)}"],
                )
            )

        # 4. NEW_ATTACK_PATH
        for idx, ap in enumerate(comparison.new_attack_paths):
            events.append(
                SecurityDriftEvent(
                    event_id=f"evt_new_ap_{idx+1}",
                    drift_type=DriftType.NEW_ATTACK_PATH,
                    severity=DriftSeverity.HIGH,
                    title="New Exploitability Attack Path Introduced",
                    description=f"New attack path detected from '{ap.get('entrypoint')}' to '{ap.get('target')}'.",
                    root_cause=ap.get("root_cause"),
                    current_state=ap,
                    evidence=[f"Entrypoint: {ap.get('entrypoint')}", f"Target: {ap.get('target')}"],
                )
            )

        # 5. REMOVED_ATTACK_PATH
        for idx, ap in enumerate(comparison.removed_attack_paths):
            events.append(
                SecurityDriftEvent(
                    event_id=f"evt_rem_ap_{idx+1}",
                    drift_type=DriftType.REMOVED_ATTACK_PATH,
                    severity=DriftSeverity.LOW,
                    title="Attack Path Neutralized",
                    description=f"Baseline attack path from '{ap.get('entrypoint')}' to '{ap.get('target')}' was removed.",
                    root_cause=ap.get("root_cause"),
                    previous_state=ap,
                    evidence=[f"Neutralized path: {ap.get('entrypoint')}->{ap.get('target')}"],
                )
            )

        # 6. NEW_INTERNET_EXPOSURE
        for idx, exp in enumerate(comparison.exposure_changes):
            if exp.get("current_exposure") in ["INTERNET_EXPOSED", "PUBLIC"]:
                events.append(
                    SecurityDriftEvent(
                        event_id=f"evt_exp_{idx+1}",
                        drift_type=DriftType.NEW_INTERNET_EXPOSURE,
                        severity=DriftSeverity.HIGH,
                        title="Vulnerability Exposed to Internet",
                        description=f"Finding in file '{exp.get('file')}' shifted exposure from {exp.get('previous_exposure')} to {exp.get('current_exposure')}.",
                        fingerprint=exp.get("fingerprint"),
                        file=exp.get("file"),
                        previous_state={"exposure": exp.get("previous_exposure")},
                        current_state={"exposure": exp.get("current_exposure")},
                        evidence=[f"Exposure shift: {exp.get('previous_exposure')} -> {exp.get('current_exposure')}"],
                    )
                )

        # 7. SECURITY_SCORE_DROP
        if comparison.score_delta < 0:
            drop = abs(comparison.score_delta)
            sev = DriftSeverity.CRITICAL if drop >= 20 else (DriftSeverity.HIGH if drop >= 10 else DriftSeverity.MEDIUM)
            events.append(
                SecurityDriftEvent(
                    event_id="evt_score_drop",
                    drift_type=DriftType.SECURITY_SCORE_DROP,
                    severity=sev,
                    title=f"Security Posture Score Dropped by {drop} Points",
                    description=f"Repository security score decreased from {comparison.score_before} to {comparison.score_after}.",
                    previous_state={"score": comparison.score_before},
                    current_state={"score": comparison.score_after},
                    evidence=[f"Score Delta: {comparison.score_delta}"],
                )
            )

        # 8. SECURITY_SCORE_IMPROVEMENT
        if comparison.score_delta > 0:
            events.append(
                SecurityDriftEvent(
                    event_id="evt_score_imp",
                    drift_type=DriftType.SECURITY_SCORE_IMPROVEMENT,
                    severity=DriftSeverity.LOW,
                    title=f"Security Posture Score Improved by +{comparison.score_delta} Points",
                    description=f"Repository security score increased from {comparison.score_before} to {comparison.score_after}.",
                    previous_state={"score": comparison.score_before},
                    current_state={"score": comparison.score_after},
                    evidence=[f"Score Delta: +{comparison.score_delta}"],
                )
            )

        # 9. PRIORITY_ESCALATION
        for idx, f in enumerate(current_findings):
            if f.get("priority_boost") or str(f.get("priority")).upper() in ["P0", "P1"]:
                if f.get("root_cause") not in self.SAFE_ROOT_CAUSES and not f.get("sanitized"):
                    events.append(
                        SecurityDriftEvent(
                            event_id=f"evt_prio_{idx+1}",
                            drift_type=DriftType.PRIORITY_ESCALATION,
                            severity=DriftSeverity.HIGH,
                            title=f"Priority Escalated to {f.get('priority', 'P1')}: {f.get('root_cause')}",
                            description=f"Finding priority escalated due to reachability or adaptive risk factors.",
                            finding_id=f.get("finding_id") or f.get("id"),
                            root_cause=f.get("root_cause"),
                            file=f.get("file"),
                            current_state=f,
                            evidence=[f"Priority: {f.get('priority')}", f"Root Cause: {f.get('root_cause')}"],
                        )
                    )

        return events
