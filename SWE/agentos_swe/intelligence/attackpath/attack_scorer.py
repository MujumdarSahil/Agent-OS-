"""
M16 Attack Path Scorer.

Calculates evidence-driven Attack Risk Score (0 - 100) and severity rating
incorporating root cause, exploitability, trust boundaries, auth status, blast radius, and historical recurrence.
"""

from typing import Dict, Any, Optional
from agentos_swe.intelligence.attackpath.models import (
    AttackPath,
    PathClassification,
    EntrypointType,
    AuthStatus,
)


class AttackPathScorer:
    """
    Deterministic Risk Scorer evaluating end-to-end AttackPath risk metrics.
    """

    def score_attack_path(self, attack_path: AttackPath) -> int:
        """
        Calculates 0-100 Attack Risk Score for an AttackPath.
        """
        breakdown = {}

        # 1. Classification Override: NOT_EXPLOITABLE or BLOCKED cap score
        if attack_path.classification == PathClassification.NOT_EXPLOITABLE:
            attack_path.risk_score = 15
            attack_path.severity = "LOW"
            return 15

        if attack_path.classification == PathClassification.BLOCKED:
            attack_path.risk_score = 30
            attack_path.severity = "LOW"
            return 30

        # 2. Base Root Cause Severity Weight
        rc = attack_path.root_cause
        if rc in ("COMMAND_INJECTION", "CODE_INJECTION", "SQL_INJECTION"):
            breakdown["root_cause_weight"] = 50
        elif rc in ("SSRF", "PATH_TRAVERSAL", "UNSAFE_DESERIALIZATION"):
            breakdown["root_cause_weight"] = 30

        elif rc == "EXCEPTION_SWALLOWING":
            breakdown["root_cause_weight"] = 15
        else:
            breakdown["root_cause_weight"] = 10


        # 3. Entrypoint Reachability Weight
        ep_type = attack_path.entrypoint_type
        if ep_type == EntrypointType.INTERNET:
            breakdown["entrypoint_weight"] = 25
        elif ep_type == EntrypointType.USER_CLI:
            breakdown["entrypoint_weight"] = 15
        elif ep_type == EntrypointType.AUTHENTICATED_HTTP:
            breakdown["entrypoint_weight"] = 15
        else:
            breakdown["entrypoint_weight"] = 5

        # 4. Authentication Status Weight
        if attack_path.auth_status == AuthStatus.UNAUTHENTICATED:
            breakdown["auth_weight"] = 20
        elif attack_path.auth_status == AuthStatus.AUTHORIZATION_REQUIRED:
            breakdown["auth_weight"] = 10
        elif attack_path.auth_status == AuthStatus.AUTHENTICATED:
            breakdown["auth_weight"] = 5
        else:
            breakdown["auth_weight"] = 10

        # 5. Trust Boundaries Weight (More boundaries crossed = higher sensitivity)
        boundary_count = len(attack_path.trust_boundaries_crossed)
        breakdown["boundary_weight"] = min(15, boundary_count * 5)

        # 6. Sanitizer Mitigation Weight
        if attack_path.classification == PathClassification.PARTIALLY_MITIGATED:
            breakdown["sanitizer_penalty"] = -20
        else:
            breakdown["sanitizer_penalty"] = 0

        raw_score = sum(breakdown.values())
        final_score = int(round(max(0, min(100, raw_score)) * attack_path.confidence))

        # Assign Severity Rating
        if attack_path.classification == PathClassification.PARTIALLY_MITIGATED:
            sev = "MEDIUM" if final_score >= 50 else "LOW"
        elif final_score >= 90:
            sev = "CRITICAL"
        elif final_score >= 70:
            sev = "HIGH"
        elif final_score >= 45:
            sev = "MEDIUM"
        else:
            sev = "LOW"

        attack_path.risk_score = final_score
        attack_path.severity = sev
        return final_score
