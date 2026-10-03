"""
M30 Release Readiness Calculator & Scoring Engine.

Calculates an explainable 0-100 numerical readiness score and enforces
the mandatory blocking gate override rule.
"""

import logging
from typing import List, Dict, Any, Tuple, Optional

from agentos_swe.release.models import (
    ReleaseGate,
    SecurityGateStatus,
    ReadinessLevel,
    ReleaseReadinessScore,
    ReleaseSummary,
)

logger = logging.getLogger(__name__)


class ReleaseReadinessCalculator:
    """
    Calculates 0-100 release readiness score and evaluates final readiness level.
    """

    @classmethod
    def calculate_readiness(
        self,
        repository_name: str,
        commit_sha: str,
        gates: List[ReleaseGate],
        active_findings: List[Dict[str, Any]],
        monitoring_health_str: str = "ACTIVE",
        governance_dec: str = "ALLOW",
        remediation_plan: Optional[Any] = None,
    ) -> Tuple[ReadinessLevel, ReleaseReadinessScore, ReleaseSummary]:
        """
        Computes numerical score and final readiness level with mandatory gate override enforcement.
        """
        total_gates = len(gates)
        blocked_gates = [g for g in gates if g.status == SecurityGateStatus.BLOCKED]
        warn_gates = [g for g in gates if g.status == SecurityGateStatus.WARNING]
        passed_gates = [g for g in gates if g.status == SecurityGateStatus.PASS]

        # Component Scores
        crit_count = sum(1 for f in active_findings if str(f.get("severity")).upper() == "CRITICAL")
        high_count = sum(1 for f in active_findings if str(f.get("severity")).upper() == "HIGH")

        sec_score = max(0.0, round(100.0 - (crit_count * 40.0 + high_count * 15.0 + len(active_findings) * 5.0), 2))
        gov_score = 100.0 if governance_dec == "ALLOW" else (50.0 if governance_dec in ["REVIEW_REQUIRED", "HUMAN_REVIEW"] else 0.0)
        mon_score = 100.0 if monitoring_health_str in ["ACTIVE", "HEALTHY"] else (50.0 if monitoring_health_str == "STALE" else 0.0)
        stab_score = round((len(passed_gates) / max(1, total_gates)) * 100.0, 2)

        overall_score = round((sec_score * 0.40) + (gov_score * 0.25) + (mon_score * 0.20) + (stab_score * 0.15), 2)

        score_obj = ReleaseReadinessScore(
            overall_score=overall_score,
            security_score=sec_score,
            governance_score=gov_score,
            monitoring_score=mon_score,
            stability_score=stab_score,
            breakdown={
                "security_weight_40": round(sec_score * 0.40, 2),
                "governance_weight_25": round(gov_score * 0.25, 2),
                "monitoring_weight_20": round(mon_score * 0.20, 2),
                "stability_weight_15": round(stab_score * 0.15, 2),
            },
        )

        # Filter out safe test harness and fallback findings
        real_active = [
            f for f in active_findings
            if str(f.get("root_cause")).upper() not in {"TEST_HARNESS", "TEST_HARNESS_DIAGNOSTIC", "INTENTIONAL_FALLBACK", "DICT_LOOKUP", "FORMATTING_ONLY", "COMMENT_ONLY"}
            and not str(f.get("affected_file") or "").startswith("tests/")
        ]

        rem_conflicts = getattr(remediation_plan, "conflicts", []) if not isinstance(remediation_plan, dict) else (remediation_plan.get("conflicts") or [])

        # Mandatory Gate Override Rule:
        # A high numerical score (e.g. 95) MUST NOT override a mandatory blocking gate!
        if blocked_gates:
            level = ReadinessLevel.BLOCKED
            rec = f"RELEASE BLOCKED — Mandatory security gate(s) failed ({blocked_gates[0].name})."
        elif real_active:
            crit_findings = [f for f in real_active if str(f.get("severity")).upper() == "CRITICAL"]
            p0_findings = [f for f in real_active if str(f.get("priority") or f.get("priority_tier")).upper() in ["P0", "TIER_0"]]
            p1_findings = [f for f in real_active if str(f.get("priority") or f.get("priority_tier")).upper() in ["P1", "TIER_1"]]
            high_exploitable = [
                f for f in real_active
                if str(f.get("severity")).upper() == "HIGH" and (
                    str(f.get("exploitability")).upper() in ["HIGH", "CRITICAL", "EXPLOITABLELEVEL.HIGH"]
                    or str(f.get("priority") or f.get("priority_tier")).upper() in ["P1", "TIER_1"]
                )
            ]
            high_findings = [f for f in real_active if str(f.get("severity")).upper() == "HIGH"]
            med_findings = [f for f in real_active if str(f.get("severity")).upper() == "MEDIUM"]

            if crit_findings or p0_findings:
                level = ReadinessLevel.BLOCKED
                rec = f"RELEASE BLOCKED — Critical or P0 finding(s) active."
            elif high_exploitable or p1_findings:
                level = ReadinessLevel.NO_GO
                rec = f"NO GO — High exploitable vulnerability or P1 finding active."
            elif high_findings:
                level = ReadinessLevel.READY_WITH_WARNINGS
                rec = f"READY WITH WARNINGS — High severity finding(s) active."
            elif med_findings:
                level = ReadinessLevel.REVIEW_REQUIRED
                rec = f"REVIEW REQUIRED — {len(med_findings)} medium severity finding(s) require review."
            elif warn_gates:
                level = ReadinessLevel.GO_WITH_WARNINGS
                rec = f"READY WITH WARNINGS — {len(warn_gates)} release warning(s) flagged."
            else:
                level = ReadinessLevel.GO_WITH_WARNINGS
                rec = f"READY WITH WARNINGS — {len(real_active)} minor issue(s) open."
        elif rem_conflicts:
            level = ReadinessLevel.REVIEW_REQUIRED
            rec = f"REVIEW REQUIRED — Remediation plan contains strategy conflicts: {rem_conflicts[0]}."
        elif warn_gates:
            warn_ids = {g.gate_id for g in warn_gates}
            if any("GATE-04" in gid or "GATE-08" in gid or "GATE-09" in gid or "GATE-12" in gid for gid in warn_ids):
                level = ReadinessLevel.REVIEW_REQUIRED
                rec = f"REVIEW REQUIRED — {len(warn_gates)} release review gate(s) flagged."
            else:
                level = ReadinessLevel.GO_WITH_WARNINGS
                rec = f"READY WITH WARNINGS — {len(warn_gates)} release warning(s) flagged."
        else:
            level = ReadinessLevel.GO
            rec = "RELEASE READY — All mandatory security gates passed; repository security posture optimal."

        summary = ReleaseSummary(
            repository_name=repository_name,
            commit_sha=commit_sha,
            readiness_level=level,
            overall_score=overall_score,
            gate_summary={
                "total": total_gates,
                "passed": len(passed_gates),
                "warnings": len(warn_gates),
                "blocked": len(blocked_gates),
            },
            blocker_count=len(blocked_gates),
            warning_count=len(warn_gates),
            recommendation=rec,
        )

        return level, score_obj, summary
