"""
M24 Decision Confidence Engine.

Calculates weighted deterministic confidence scores (0.0 to 1.0) based on
contributions from verification, semantic, taint, correlation, attack path, history, and drift.
"""

from typing import Dict, Any, Optional
from agentos_swe.operations.orchestration.models import DecisionConfidence


class DecisionConfidenceEngine:
    """
    Computes weighted deterministic decision confidence.
    """

    def compute_confidence(
        self,
        finding: Dict[str, Any],
        attack_path: Optional[Dict[str, Any]] = None,
        drift_result: Optional[Dict[str, Any]] = None,
    ) -> DecisionConfidence:
        """
        Calculates weighted confidence score (0.0 to 1.0).
        Weights:
        - Verification: +0.25
        - Semantic: +0.10
        - Taint: +0.25
        - Attack Path: +0.15
        - History: +0.10
        - Drift: +0.15
        """
        breakdown: Dict[str, float] = {}

        # 1. Verification
        if finding.get("verified") is True:
            breakdown["verification"] = 0.25
        elif finding.get("verified") is False:
            breakdown["verification"] = 0.05
        else:
            breakdown["verification"] = 0.15

        # 2. Semantic
        rc = str(finding.get("root_cause") or "").upper()
        if rc in ("COMMAND_INJECTION", "SQL_INJECTION", "INTENTIONAL_FALLBACK", "TEST_HARNESS", "DICT_LOOKUP"):
            breakdown["semantic"] = 0.10
        else:
            breakdown["semantic"] = 0.05

        # 3. Taint
        if finding.get("taint_flow") or finding.get("source_type"):
            breakdown["taint"] = 0.25
        else:
            breakdown["taint"] = 0.10

        # 4. Attack Path
        if attack_path:
            breakdown["attack_path"] = 0.15
        else:
            breakdown["attack_path"] = 0.05

        # 5. History
        if finding.get("historical_recurrent") or finding.get("previously_fixed"):
            breakdown["history"] = 0.10
        else:
            breakdown["history"] = 0.05

        # 6. Drift
        if drift_result:
            breakdown["drift"] = 0.15
        else:
            breakdown["drift"] = 0.10

        total_score = round(sum(breakdown.values()), 2)
        total_score = min(1.0, max(0.0, total_score))

        if total_score >= 0.85:
            level = "VERY_HIGH"
        elif total_score >= 0.70:
            level = "HIGH"
        elif total_score >= 0.50:
            level = "MEDIUM"
        else:
            level = "LOW"

        rationale = f"Confidence score {int(total_score * 100)}% ({level}): " + ", ".join([f"{k} (+{int(v*100)}%)" for k, v in breakdown.items()])

        return DecisionConfidence(
            score=total_score,
            level=level,
            rationale=rationale,
            breakdown=breakdown,
        )
