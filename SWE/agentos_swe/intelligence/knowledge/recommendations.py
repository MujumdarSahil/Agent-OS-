"""
M21 Adaptive Security Recommendation Engine.

Evaluates candidate remediation strategies against historical learning statistics to produce
ranked, explainable recommendations with historical confidence rationale.
"""

from typing import List, Dict, Any, Optional
from agentos_swe.intelligence.knowledge.models import RemediationRecommendation
from agentos_swe.intelligence.knowledge.learning import RemediationSuccessLearner


class AdaptiveSecurityRecommendationEngine:
    """
    Generates explainable adaptive remediation recommendations based on historical learning.
    """

    def __init__(self):
        self.learner = RemediationSuccessLearner()

    def generate_recommendation(
        self,
        finding: Dict[str, Any],
        historical_records: List[Dict[str, Any]],
    ) -> RemediationRecommendation:
        """
        Outputs ranked RemediationRecommendation for a vulnerability finding.
        """
        rc = str(finding.get("root_cause") or finding.get("category") or "UNKNOWN").upper()
        fam = finding.get("vulnerability_family") or rc

        # Candidate strategies map
        strategies_map = {
            "COMMAND_INJECTION": "REPLACE_SHELL_TRUE_WITH_ARG_ARRAY",
            "SQL_INJECTION": "PARAMETERIZE_SQL_QUERY_ARGUMENTS",
            "PATH_TRAVERSAL": "VALIDATE_ABSOLUTE_PATH_SANDBOX",
            "EXCEPTION_SWALLOWING": "LOG_AND_RERAISE_SPECIFIC_EXCEPTION",
            "DICT_LOOKUP": "SAFE_GET_KEY_FALLBACK",
            "TEST_HARNESS": "MARK_AS_SAFE_TEST_HARNESS",
            "INTENTIONAL_FALLBACK": "DOCUMENT_FALLBACK_HANDLER",
        }
        strat_name = strategies_map.get(rc, "APPLY_DEFENSIVE_SANITIZATION")

        eff = self.learner.calculate_effectiveness(
            strategy_name=strat_name,
            vulnerability_family=fam,
            root_cause=rc,
            historical_records=historical_records,
        )

        explanation = (
            f"Strategy '{strat_name}' recommended with {eff.confidence_level} confidence based on "
            f"{eff.successes}/{eff.attempts if eff.attempts > 0 else 1} historical successes and "
            f"{eff.regressions} recorded regressions."
        )

        return RemediationRecommendation(
            strategy=strat_name,
            confidence=eff.confidence_level,
            historical_attempts=eff.attempts,
            historical_successes=eff.successes,
            historical_failures=eff.failures,
            historical_regressions=eff.regressions,
            compatibility="HIGH",
            expected_risk_reduction=25 if eff.confidence_level == "HIGH" else 15,
            explanation=explanation,
        )
