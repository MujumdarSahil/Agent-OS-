"""
M21 Remediation Success Learner & Confidence Decay Engine.

Tracks repair strategy effectiveness (successes, failures, regressions) and computes
deterministic confidence decay based on historical age and recent outcome ratios.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from agentos_swe.knowledge.models import RemediationPattern, SecurityOutcome


class RemediationSuccessLearner:
    """
    Tracks repair strategy success/failure metrics and calculates confidence.
    """

    def calculate_effectiveness(
        self,
        strategy_name: str,
        vulnerability_family: str,
        root_cause: str,
        historical_records: List[Dict[str, Any]],
    ) -> RemediationPattern:
        """
        Computes remediation effectiveness statistics and confidence tier.
        """
        attempts = 0
        successes = 0
        failures = 0
        regressions = 0

        for rec in historical_records:
            if rec.get("remediation_strategy") == strategy_name or rec.get("root_cause") == root_cause:
                attempts += 1
                val_res = rec.get("validation_result")
                reg_res = rec.get("regression_result")

                if val_res == SecurityOutcome.SUCCESSFUL_REPAIR.value or val_res == "SUCCESSFUL_REPAIR":
                    successes += 1
                elif val_res in (SecurityOutcome.FAILED_VALIDATION.value, "FAILED_VALIDATION"):
                    failures += 1

                if reg_res == SecurityOutcome.INTRODUCED_REGRESSION.value or reg_res == "INTRODUCED_REGRESSION":
                    regressions += 1

        rate = (successes / attempts) if attempts > 0 else 1.0

        # Confidence level computation
        confidence = "HIGH"
        if regressions > 0 or rate < 0.60:
            confidence = "LOW"
        elif attempts < 2 or rate < 0.85:
            confidence = "MEDIUM"

        return RemediationPattern(
            strategy_id=f"strat_{root_cause.lower()}_{hash(strategy_name) % 10000}",
            vulnerability_family=vulnerability_family,
            root_cause=root_cause,
            recommended_fix=strategy_name,
            attempts=attempts,
            successes=successes,
            failures=failures,
            regressions=regressions,
            success_rate=round(rate, 2),
            confidence_level=confidence,
        )

    def apply_confidence_decay(
        self,
        base_confidence: float,
        first_seen_iso: str,
        last_seen_iso: str,
        regressions_count: int,
    ) -> float:
        """
        Calculates deterministic confidence decay based on time and regression history.
        """
        try:
            last_t = datetime.fromisoformat(last_seen_iso)
            age_days = (datetime.now() - last_t).days
        except Exception:
            age_days = 0

        decay = 0.0
        if age_days > 180:
            decay += 0.20
        elif age_days > 90:
            decay += 0.10

        # Heavy penalty for regressions
        decay += (regressions_count * 0.25)

        return max(0.10, round(base_confidence - decay, 2))
