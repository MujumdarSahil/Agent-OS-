"""
M30 Deterministic Release Gate Validator.

Evaluates 12 mandatory release gates consuming outputs from M14-M29.
Enforces strict release blocking rules for critical risk factors.
"""

import logging
from typing import List, Dict, Any, Optional
from agentos_swe.release.models import ReleaseGate, SecurityGateStatus, ReleaseBlocker

logger = logging.getLogger(__name__)


class ReleaseGateValidator:
    """
    Evaluates 12 mandatory enterprise release gates.
    """

    def evaluate_gates(
        self,
        verified_findings: Optional[List[Any]] = None,
        prioritized_findings: Optional[List[Any]] = None,
        attack_paths: Optional[List[Any]] = None,
        decision_result: Optional[Any] = None,
        learning_result: Optional[Any] = None,
        drift_result: Optional[Any] = None,
        control_plane_result: Optional[Any] = None,
        monitoring_health: Optional[Any] = None,
        incident_result: Optional[Any] = None,
        repair_validations: Optional[List[Any]] = None,
        remediation_plan: Optional[Any] = None,
        **kwargs,
    ) -> List[ReleaseGate]:
        """
        Evaluates 12 deterministic release gates.
        """
        gates: List[ReleaseGate] = []

        findings = prioritized_findings or verified_findings or []
        findings_dict = [f.to_dict() if hasattr(f, "to_dict") else f for f in findings]

        active_findings = [
            f for f in findings_dict
            if not f.get("sanitized") and not f.get("is_safe") and f.get("root_cause") not in {
                "DICT_LOOKUP", "INTENTIONAL_FALLBACK", "TEST_HARNESS_DIAGNOSTIC", "TEST_HARNESS", "FORMATTING_ONLY", "COMMENT_ONLY"
            }
        ]

        paths_dict = [ap.to_dict() if hasattr(ap, "to_dict") else ap for ap in (attack_paths or [])]
        dec_dict = decision_result.to_dict() if hasattr(decision_result, "to_dict") else (decision_result or {})
        drift_dict = drift_result.to_dict() if hasattr(drift_result, "to_dict") else (drift_result or {})
        inc_dict = incident_result.to_dict() if hasattr(incident_result, "to_dict") else (incident_result or {})

        # GATE-01: Any unresolved CRITICAL vulnerability -> BLOCKED
        crit_findings = [f for f in active_findings if str(f.get("severity")).upper() == "CRITICAL"]
        if crit_findings:
            gates.append(
                ReleaseGate(
                    gate_id="GATE-01",
                    name="Unresolved Critical Vulnerability Check",
                    status=SecurityGateStatus.BLOCKED,
                    rationale=f"Found {len(crit_findings)} unresolved CRITICAL severity vulnerability/vulnerabilities.",
                    evidence_summary=f"Critical finding: `{crit_findings[0].get('root_cause')}` in `{crit_findings[0].get('file', 'N/A')}`.",
                    severity="CRITICAL",
                    governance_effect="BLOCK_RELEASE",
                )
            )
        else:
            gates.append(
                ReleaseGate(
                    gate_id="GATE-01",
                    name="Unresolved Critical Vulnerability Check",
                    status=SecurityGateStatus.PASS,
                    rationale="Zero unresolved CRITICAL severity vulnerabilities identified.",
                    governance_effect="ALLOW",
                )
            )

        # GATE-02: Internet-exposed CRITICAL attack path -> BLOCKED
        exposed_crit_paths = [
            ap for ap in paths_dict
            if (ap.get("is_internet_exposed") or str(ap.get("entrypoint_type") or "").upper() == "INTERNET")
            and (ap.get("exploitable", True) or str(ap.get("auth_status") or "").upper() in ("UNAUTHENTICATED", "UNKNOWN"))
        ]
        if exposed_crit_paths:
            gates.append(
                ReleaseGate(
                    gate_id="GATE-02",
                    name="Internet-Exposed Critical Attack Path Check",
                    status=SecurityGateStatus.BLOCKED,
                    rationale=f"Found {len(exposed_crit_paths)} active internet-exposed attack path(s).",
                    evidence_summary=f"Attack path entrypoint: `{exposed_crit_paths[0].get('entrypoint')}` targeting `{exposed_crit_paths[0].get('sink_type')}`.",
                    severity="CRITICAL",
                    governance_effect="BLOCK_RELEASE",
                )
            )
        else:
            gates.append(
                ReleaseGate(
                    gate_id="GATE-02",
                    name="Internet-Exposed Critical Attack Path Check",
                    status=SecurityGateStatus.PASS,
                    rationale="Zero internet-exposed critical attack paths identified.",
                    governance_effect="ALLOW",
                )
            )

        # GATE-03: Active CRITICAL incident -> BLOCKED
        crit_incidents = inc_dict.get("critical_incident_count", 0)
        if crit_incidents > 0:
            gates.append(
                ReleaseGate(
                    gate_id="GATE-03",
                    name="Active Critical Security Incident Check",
                    status=SecurityGateStatus.BLOCKED,
                    rationale=f"Active critical incident count is {crit_incidents}.",
                    evidence_summary=f"Incident response engine flagged {crit_incidents} unresolved critical security incident(s).",
                    severity="CRITICAL",
                    governance_effect="BLOCK_RELEASE",
                )
            )
        else:
            gates.append(
                ReleaseGate(
                    gate_id="GATE-03",
                    name="Active Critical Security Incident Check",
                    status=SecurityGateStatus.PASS,
                    rationale="Zero active critical security incidents.",
                    governance_effect="ALLOW",
                )
            )

        # GATE-04: M24 governance BLOCK_RELEASE -> BLOCKED
        gov_dec = str(dec_dict.get("overall_decision") or "").upper()
        rem_p = remediation_plan or kwargs.get("remediation_plan") or kwargs.get("plan") or {}
        rem_conflicts = rem_p.get("conflicts") if isinstance(rem_p, dict) else getattr(rem_p, "conflicts", [])
        if gov_dec in ["DENY", "BLOCK_RELEASE"]:
            gates.append(
                ReleaseGate(
                    gate_id="GATE-04",
                    name="Governance Release Decision Check",
                    status=SecurityGateStatus.BLOCKED,
                    rationale="Policy engine enforced release block.",
                    evidence_summary=f"Overall governance decision: `{gov_dec}`.",
                    severity="CRITICAL",
                    governance_effect="BLOCK_RELEASE",
                )
            )
        elif rem_conflicts:
            gates.append(
                ReleaseGate(
                    gate_id="GATE-04",
                    name="Governance Release Decision Check",
                    status=SecurityGateStatus.WARNING,
                    rationale="Remediation plan contains strategy conflicts.",
                    evidence_summary=f"Remediation conflict: `{rem_conflicts[0]}`.",
                    severity="HIGH",
                    governance_effect="REVIEW_REQUIRED",
                )
            )
        else:
            gates.append(
                ReleaseGate(
                    gate_id="GATE-04",
                    name="Governance Release Decision Check",
                    status=SecurityGateStatus.PASS,
                    rationale="Governance policy engine permits release.",
                    governance_effect="ALLOW",
                )
            )

        # GATE-05: P0 unresolved finding -> BLOCKED
        p0_findings = [f for f in active_findings if str(f.get("priority") or f.get("priority_tier")).upper() in ["P0", "TIER_0"]]
        if p0_findings:
            gates.append(
                ReleaseGate(
                    gate_id="GATE-05",
                    name="Unresolved P0 Priority Finding Check",
                    status=SecurityGateStatus.BLOCKED,
                    rationale=f"Found {len(p0_findings)} unresolved P0 priority security finding(s).",
                    evidence_summary=f"P0 finding: `{p0_findings[0].get('root_cause')}`.",
                    severity="CRITICAL",
                    governance_effect="BLOCK_RELEASE",
                )
            )
        else:
            gates.append(
                ReleaseGate(
                    gate_id="GATE-05",
                    name="Unresolved P0 Priority Finding Check",
                    status=SecurityGateStatus.PASS,
                    rationale="Zero unresolved P0 priority findings.",
                    governance_effect="ALLOW",
                )
            )

        # GATE-06: Security monitoring FAILED/STALE beyond configured threshold -> WARNING / BLOCKED
        if hasattr(monitoring_health, "to_dict"):
            mon_dict = monitoring_health.to_dict()
        elif isinstance(monitoring_health, dict):
            mon_dict = monitoring_health
        else:
            mon_dict = {}

        m_status = str(
            getattr(monitoring_health, "monitoring_health", None)
            or getattr(monitoring_health, "status", None)
            or mon_dict.get("monitoring_health")
            or mon_dict.get("status")
            or "ACTIVE"
        ).upper()
        m_reg = str(
            getattr(monitoring_health, "regression_severity", None)
            or mon_dict.get("regression_severity")
            or ""
        ).upper()

        if "CRITICAL" in m_reg:
            gates.append(
                ReleaseGate(
                    gate_id="GATE-06",
                    name="Security Monitoring Infrastructure Health Check",
                    status=SecurityGateStatus.BLOCKED,
                    rationale=f"Monitoring infrastructure reported critical regression `{m_reg}`.",
                    evidence_summary=f"Monitoring health: `{m_reg}`.",
                    severity="CRITICAL",
                    governance_effect="BLOCK_RELEASE",
                )
            )
        elif m_status in ["FAILED", "STALE"]:
            gates.append(
                ReleaseGate(
                    gate_id="GATE-06",
                    name="Security Monitoring Infrastructure Health Check",
                    status=SecurityGateStatus.WARNING,
                    rationale=f"Monitoring infrastructure status is `{m_status}`.",
                    evidence_summary=f"Monitoring health reported `{m_status}` requiring operational check.",
                    severity="HIGH",
                    governance_effect="REVIEW_REQUIRED",
                )
            )
        else:
            gates.append(
                ReleaseGate(
                    gate_id="GATE-06",
                    name="Security Monitoring Infrastructure Health Check",
                    status=SecurityGateStatus.PASS,
                    rationale="Continuous security monitoring infrastructure healthy.",
                    governance_effect="ALLOW",
                )
            )

        # GATE-07: New HIGH vulnerability without validated remediation -> WARNING / REVIEW_REQUIRED
        high_findings = [f for f in active_findings if str(f.get("severity")).upper() == "HIGH"]
        if high_findings:
            gates.append(
                ReleaseGate(
                    gate_id="GATE-07",
                    name="Unresolved High Severity Vulnerability Check",
                    status=SecurityGateStatus.WARNING,
                    rationale=f"Found {len(high_findings)} unresolved HIGH severity finding(s).",
                    evidence_summary=f"High finding: `{high_findings[0].get('root_cause')}`.",
                    severity="HIGH",
                    governance_effect="REVIEW_REQUIRED",
                )
            )
        else:
            gates.append(
                ReleaseGate(
                    gate_id="GATE-07",
                    name="Unresolved High Severity Vulnerability Check",
                    status=SecurityGateStatus.PASS,
                    rationale="Zero unresolved HIGH severity findings.",
                    governance_effect="ALLOW",
                )
            )

        # GATE-08: Reopened vulnerability -> REVIEW_REQUIRED
        reopened = [f for f in active_findings if f.get("recurrence_classification") == "REOPENED"]
        if reopened:
            gates.append(
                ReleaseGate(
                    gate_id="GATE-08",
                    name="Reopened Vulnerability Check",
                    status=SecurityGateStatus.WARNING,
                    rationale=f"Found {len(reopened)} reopened vulnerability/vulnerabilities.",
                    evidence_summary=f"Reopened finding: `{reopened[0].get('root_cause')}`.",
                    severity="HIGH",
                    governance_effect="REVIEW_REQUIRED",
                )
            )
        else:
            gates.append(
                ReleaseGate(
                    gate_id="GATE-08",
                    name="Reopened Vulnerability Check",
                    status=SecurityGateStatus.PASS,
                    rationale="Zero reopened vulnerabilities.",
                    governance_effect="ALLOW",
                )
            )

        # GATE-09: Chronic vulnerability -> REVIEW_REQUIRED
        chronic = [f for f in active_findings if f.get("recurrence_classification") == "CHRONIC"]
        if chronic:
            gates.append(
                ReleaseGate(
                    gate_id="GATE-09",
                    name="Chronic Recurring Vulnerability Check",
                    status=SecurityGateStatus.WARNING,
                    rationale=f"Found {len(chronic)} chronic recurring vulnerability/vulnerabilities.",
                    evidence_summary=f"Chronic finding: `{chronic[0].get('root_cause')}`.",
                    severity="HIGH",
                    governance_effect="REVIEW_REQUIRED",
                )
            )
        else:
            gates.append(
                ReleaseGate(
                    gate_id="GATE-09",
                    name="Chronic Recurring Vulnerability Check",
                    status=SecurityGateStatus.PASS,
                    rationale="Zero chronic recurring vulnerabilities.",
                    governance_effect="ALLOW",
                )
            )

        # GATE-10: All findings resolved and monitoring healthy -> PASS
        if not active_findings and m_status in ["ACTIVE", "HEALTHY"]:
            gates.append(
                ReleaseGate(
                    gate_id="GATE-10",
                    name="Complete Posture Resolution & Health Check",
                    status=SecurityGateStatus.PASS,
                    rationale="All findings resolved and monitoring infrastructure healthy.",
                    governance_effect="ALLOW",
                )
            )
        else:
            gates.append(
                ReleaseGate(
                    gate_id="GATE-10",
                    name="Complete Posture Resolution & Health Check",
                    status=SecurityGateStatus.PASS if not active_findings else SecurityGateStatus.WARNING,
                    rationale="Active findings or monitoring warnings present.",
                    governance_effect="ALLOW",
                )
            )

        # GATE-11: Intentional fallback / test harness / safe dict.get() -> MUST NOT block release
        safe_findings = [f for f in findings_dict if f.get("sanitized") or f.get("root_cause") in {
            "DICT_LOOKUP", "INTENTIONAL_FALLBACK", "TEST_HARNESS_DIAGNOSTIC", "FORMATTING_ONLY", "COMMENT_ONLY"
        }]
        gates.append(
            ReleaseGate(
                gate_id="GATE-11",
                name="Safe Design Pattern Protection Check",
                status=SecurityGateStatus.PASS,
                rationale=f"Enforced protection across {len(safe_findings)} safe design patterns; safe patterns never block release.",
                governance_effect="ALLOW",
            )
        )

        # GATE-12: Unknown evidence -> REVIEW_REQUIRED
        unknown_findings = [f for f in active_findings if str(f.get("confidence")).upper() == "UNKNOWN"]
        if unknown_findings:
            gates.append(
                ReleaseGate(
                    gate_id="GATE-12",
                    name="Unknown Evidence Review Gate",
                    status=SecurityGateStatus.WARNING,
                    rationale=f"Found {len(unknown_findings)} finding(s) with UNKNOWN evidence confidence.",
                    evidence_summary="Unknown evidence never automatically assumed safe.",
                    severity="HIGH",
                    governance_effect="REVIEW_REQUIRED",
                )
            )
        else:
            gates.append(
                ReleaseGate(
                    gate_id="GATE-12",
                    name="Unknown Evidence Review Gate",
                    status=SecurityGateStatus.PASS,
                    rationale="Zero unknown evidence items.",
                    governance_effect="ALLOW",
                )
            )

        return gates
