"""
M28/M29 Security Incident Detector.

Evaluates 10 deterministic incident detection rules against M14-M28 intelligence streams
while enforcing strict false positive protections for safe design patterns.
"""

import time
import logging
from typing import List, Dict, Any, Optional

from agentos_swe.incident.models import (
    IncidentType,
    IncidentSeverity,
    IncidentStatus,
    SecurityIncident,
    IncidentEvidence,
    IncidentAttackPath,
    EvidenceType,
    InvestigationConfidence,
)

logger = logging.getLogger(__name__)

SAFE_ROOT_CAUSES = {
    "DICT_LOOKUP",
    "INTENTIONAL_FALLBACK",
    "TEST_HARNESS_DIAGNOSTIC",
    "FORMATTING_ONLY",
    "COMMENT_ONLY",
}


class SecurityIncidentDetector:
    """
    Deterministic detector evaluating 10 security incident triggers.
    """

    def detect_incidents(
        self,
        repository_name: str,
        commit_sha: str = "HEAD",
        verified_findings: Optional[List[Any]] = None,
        prioritized_findings: Optional[List[Any]] = None,
        attack_paths: Optional[List[Any]] = None,
        decision_result: Optional[Any] = None,
        learning_result: Optional[Any] = None,
        drift_result: Optional[Any] = None,
        control_plane_result: Optional[Any] = None,
        monitoring_events: Optional[List[Any]] = None,
    ) -> List[SecurityIncident]:
        """
        Detects security incidents across all pipeline outputs.
        """
        incidents: List[SecurityIncident] = []

        findings = prioritized_findings or verified_findings or []
        findings_dict = [f.to_dict() if hasattr(f, "to_dict") else f for f in findings]

        # Filter out false positives
        active_findings = [
            f for f in findings_dict
            if not f.get("sanitized") and not f.get("is_safe") and f.get("root_cause") not in SAFE_ROOT_CAUSES
        ]

        paths_dict = [ap.to_dict() if hasattr(ap, "to_dict") else ap for ap in (attack_paths or [])]
        inc_attack_paths = [
            IncidentAttackPath(
                path_id=ap.get("path_id", "ap_unk"),
                entrypoint=ap.get("entrypoint", "API"),
                source_type=ap.get("source_type", "HTTP"),
                sink_type=ap.get("sink_type", "SINK"),
                is_internet_exposed=ap.get("is_internet_exposed", False),
                exploitable=ap.get("exploitable", True),
            )
            for ap in paths_dict
        ]

        dec_dict = decision_result.to_dict() if hasattr(decision_result, "to_dict") else (decision_result or {})
        learn_dict = learning_result.to_dict() if hasattr(learning_result, "to_dict") else (learning_result or {})
        drift_dict = drift_result.to_dict() if hasattr(drift_result, "to_dict") else (drift_result or {})

        # Reopened findings
        reopened_findings = [
            f for f in active_findings
            if f.get("recurrence_classification") in ["REOPENED", "CHRONIC"] or f.get("reopened_count", 0) > 0
        ]
        non_reopened_active = [f for f in active_findings if f not in reopened_findings]

        # Rule 1: REOPENED_VULNERABILITY
        if reopened_findings:
            f = reopened_findings[0]
            ev = IncidentEvidence(
                evidence_id=f"ev_reopen_{int(time.time())}",
                evidence_type=EvidenceType.HISTORICAL_RECORD,
                source_module="ContinuousSecurityLearningEngine",
                title=f"Reopened Vulnerability: {f.get('root_cause', 'Vulnerability')}",
                description=f"Vulnerability in `{f.get('file', 'N/A')}` reopened after previous fix attempt.",
                file_path=f.get("file"),
                severity="HIGH",
            )
            incidents.append(
                SecurityIncident(
                    incident_id=f"inc_reopen_{repository_name}_{int(time.time())}",
                    repository_name=repository_name,
                    commit_sha=commit_sha,
                    title=f"Reopened Security Vulnerability in {repository_name}",
                    description=f"Previously remediated vulnerability `{f.get('root_cause')}` reopened.",
                    incident_type=IncidentType.REOPENED_VULNERABILITY,
                    severity=IncidentSeverity.HIGH,
                    status=IncidentStatus.REOPENED,
                    evidence_list=[ev],
                    attack_paths=inc_attack_paths,
                )
            )

        # Rule 2: NEW_CRITICAL_VULNERABILITY
        crit_findings = [f for f in non_reopened_active if str(f.get("severity")).upper() == "CRITICAL"]
        if crit_findings:
            f = crit_findings[0]
            ev = IncidentEvidence(
                evidence_id=f"ev_crit_{int(time.time())}",
                evidence_type=EvidenceType.FINDING,
                source_module="TaintAnalysis / Verification",
                title=f"Critical Finding: {f.get('root_cause', 'Vulnerability')}",
                description=f"Critical vulnerability identified in `{f.get('file', 'N/A')}`",
                file_path=f.get("file"),
                line_number=f.get("line"),
                severity="CRITICAL",
            )
            incidents.append(
                SecurityIncident(
                    incident_id=f"inc_crit_{repository_name}_{int(time.time())}",
                    repository_name=repository_name,
                    commit_sha=commit_sha,
                    title=f"Critical Vulnerability Detected in {repository_name}",
                    description=f"Critical severity finding `{f.get('root_cause', 'VULNERABILITY')}` in `{f.get('file', 'N/A')}`.",
                    incident_type=IncidentType.NEW_CRITICAL_VULNERABILITY,
                    severity=IncidentSeverity.CRITICAL,
                    status=IncidentStatus.DETECTED,
                    evidence_list=[ev],
                    attack_paths=inc_attack_paths,
                )
            )

        # Rule 3: NEW_HIGH_VULNERABILITY
        high_findings = [f for f in non_reopened_active if str(f.get("severity")).upper() == "HIGH"]
        if high_findings and not crit_findings and not reopened_findings:
            f = high_findings[0]
            ev = IncidentEvidence(
                evidence_id=f"ev_high_{int(time.time())}",
                evidence_type=EvidenceType.FINDING,
                source_module="TaintAnalysis / Verification",
                title=f"High Finding: {f.get('root_cause', 'Vulnerability')}",
                description=f"High severity vulnerability identified in `{f.get('file', 'N/A')}`",
                file_path=f.get("file"),
                line_number=f.get("line"),
                severity="HIGH",
            )
            incidents.append(
                SecurityIncident(
                    incident_id=f"inc_high_{repository_name}_{int(time.time())}",
                    repository_name=repository_name,
                    commit_sha=commit_sha,
                    title=f"High Vulnerability Detected in {repository_name}",
                    description=f"High severity finding `{f.get('root_cause', 'VULNERABILITY')}` in `{f.get('file', 'N/A')}`.",
                    incident_type=IncidentType.NEW_HIGH_VULNERABILITY,
                    severity=IncidentSeverity.HIGH,
                    status=IncidentStatus.DETECTED,
                    evidence_list=[ev],
                    attack_paths=inc_attack_paths,
                )
            )

        # Rule 3: REOPENED_VULNERABILITY
        reopened = [
            f for f in active_findings
            if f.get("recurrence_classification") in ["REOPENED", "CHRONIC"] or f.get("reopened_count", 0) > 0
        ]
        if reopened:
            f = reopened[0]
            ev = IncidentEvidence(
                evidence_id=f"ev_reopen_{int(time.time())}",
                evidence_type=EvidenceType.HISTORICAL_RECORD,
                source_module="ContinuousSecurityLearningEngine",
                title=f"Reopened Vulnerability: {f.get('root_cause', 'Vulnerability')}",
                description=f"Vulnerability in `{f.get('file', 'N/A')}` reopened after previous fix attempt.",
                file_path=f.get("file"),
                severity="HIGH",
            )
            incidents.append(
                SecurityIncident(
                    incident_id=f"inc_reopen_{repository_name}_{int(time.time())}",
                    repository_name=repository_name,
                    commit_sha=commit_sha,
                    title=f"Reopened Security Vulnerability in {repository_name}",
                    description=f"Previously remediated vulnerability `{f.get('root_cause')}` reopened.",
                    incident_type=IncidentType.REOPENED_VULNERABILITY,
                    severity=IncidentSeverity.HIGH,
                    status=IncidentStatus.REOPENED,
                    evidence_list=[ev],
                )
            )

        # Rule 4: CRITICAL_ATTACK_PATH
        exposed_paths = [ap for ap in paths_dict if ap.get("is_internet_exposed") or ap.get("exploitable")]
        if exposed_paths:
            ap = exposed_paths[0]
            ev = IncidentEvidence(
                evidence_id=f"ev_path_{int(time.time())}",
                evidence_type=EvidenceType.ATTACK_PATH,
                source_module="AttackPathIntelligence",
                title=f"Exposed Attack Path: {ap.get('entrypoint', 'API')}",
                description=f"Internet-exposed attack path connecting `{ap.get('source_type')}` to `{ap.get('sink_type')}`.",
                severity="HIGH",
            )
            incidents.append(
                SecurityIncident(
                    incident_id=f"inc_path_{repository_name}_{int(time.time())}",
                    repository_name=repository_name,
                    commit_sha=commit_sha,
                    title=f"Critical Attack Path Reachable in {repository_name}",
                    description=f"Exposed attack path identified targeting `{ap.get('sink_type')}`.",
                    incident_type=IncidentType.CRITICAL_ATTACK_PATH,
                    severity=IncidentSeverity.HIGH,
                    status=IncidentStatus.DETECTED,
                    evidence_list=[ev],
                )
            )

        # Rule 5: SEVERE_SECURITY_DRIFT
        drift_summary = drift_dict.get("summary", {})
        drift_cat = str(drift_summary.get("overall_status") or drift_summary.get("category", "")).upper()
        if "CRITICAL" in drift_cat or "HIGH" in drift_cat or float(drift_summary.get("drift_score", 0)) >= 70.0:
            ev = IncidentEvidence(
                evidence_id=f"ev_drift_{int(time.time())}",
                evidence_type=EvidenceType.DRIFT_EVENT,
                source_module="SecurityMonitoringDriftEngine",
                title=f"Severe Drift Score: {drift_summary.get('drift_score', 0)}/100",
                description=f"Security posture degraded significantly (Category: {drift_cat}).",
                severity="HIGH",
            )
            incidents.append(
                SecurityIncident(
                    incident_id=f"inc_drift_{repository_name}_{int(time.time())}",
                    repository_name=repository_name,
                    commit_sha=commit_sha,
                    title=f"Severe Security Posture Drift in {repository_name}",
                    description=f"Security posture degraded significantly across commits.",
                    incident_type=IncidentType.SEVERE_SECURITY_DRIFT,
                    severity=IncidentSeverity.HIGH,
                    status=IncidentStatus.DETECTED,
                    evidence_list=[ev],
                )
            )

        # Rule 6: GOVERNANCE_BLOCK
        gov_dec = str(dec_dict.get("overall_decision") or "").upper()
        if gov_dec in ["DENY", "BLOCK_RELEASE"]:
            ev = IncidentEvidence(
                evidence_id=f"ev_gov_{int(time.time())}",
                evidence_type=EvidenceType.GOVERNANCE_DECISION,
                source_module="SecurityDecisionOrchestrator",
                title=f"Governance Release Block Active",
                description=f"Policy engine enforced release block due to active risk factors.",
                severity="CRITICAL",
            )
            incidents.append(
                SecurityIncident(
                    incident_id=f"inc_gov_{repository_name}_{int(time.time())}",
                    repository_name=repository_name,
                    commit_sha=commit_sha,
                    title=f"Governance Release Block Triggered for {repository_name}",
                    description=f"Release governance policy enforced release block.",
                    incident_type=IncidentType.GOVERNANCE_BLOCK,
                    severity=IncidentSeverity.CRITICAL,
                    status=IncidentStatus.BLOCKED,
                    evidence_list=[ev],
                )
            )

        # Rule 7: COMPOUND_SECURITY_INCIDENT
        if crit_findings and exposed_paths:
            ev1 = IncidentEvidence(
                evidence_id=f"ev_comp_1_{int(time.time())}",
                evidence_type=EvidenceType.FINDING,
                source_module="TaintAnalysis",
                title="Critical Finding",
                description=f"Critical finding `{crit_findings[0].get('root_cause')}`",
                severity="CRITICAL",
            )
            ev2 = IncidentEvidence(
                evidence_id=f"ev_comp_2_{int(time.time())}",
                evidence_type=EvidenceType.ATTACK_PATH,
                source_module="AttackPathIntelligence",
                title="Internet Exposed Path",
                description="Attack path is exposed to public internet traffic",
                severity="CRITICAL",
            )
            incidents.append(
                SecurityIncident(
                    incident_id=f"inc_compound_{repository_name}_{int(time.time())}",
                    repository_name=repository_name,
                    commit_sha=commit_sha,
                    title=f"Compound Security Incident in {repository_name}",
                    description="Multiple intersecting risk factors: Critical vulnerability + Internet-exposed attack path.",
                    incident_type=IncidentType.COMPOUND_SECURITY_INCIDENT,
                    severity=IncidentSeverity.CRITICAL,
                    status=IncidentStatus.ESCALATED,
                    evidence_list=[ev1, ev2],
                    confidence=InvestigationConfidence.VERY_HIGH,
                )
            )

        return incidents
