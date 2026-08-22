"""
M24 Security Decision Engine.

Coordinates policy evaluation, confidence scoring, action selection, and explainability
for individual findings.
"""

from typing import Dict, Any, List, Optional, Tuple
from agentos_swe.orchestration.models import (
    DecisionAction,
    DecisionRecommendation,
)
from agentos_swe.orchestration.policy_engine import SecurityPolicyEngine
from agentos_swe.orchestration.confidence_engine import DecisionConfidenceEngine
from agentos_swe.orchestration.action_selector import ActionSelector
from agentos_swe.orchestration.explainability import DecisionExplainabilityEngine


class SecurityDecisionEngine:
    """
    Evaluates individual finding decision recommendations.
    """

    def __init__(self):
        self.policy_engine = SecurityPolicyEngine()
        self.confidence_engine = DecisionConfidenceEngine()
        self.action_selector = ActionSelector()
        self.explainability_engine = DecisionExplainabilityEngine()

    def evaluate_finding(
        self,
        finding: Dict[str, Any],
        attack_path: Optional[Dict[str, Any]] = None,
        drift_result: Optional[Dict[str, Any]] = None,
    ) -> Tuple[DecisionRecommendation, List[Dict[str, Any]]]:
        """
        Evaluates a finding and returns DecisionRecommendation.
        """
        # 1. Compute Confidence
        conf = self.confidence_engine.compute_confidence(finding, attack_path, drift_result)

        # 2. Evaluate Policy
        drift_cat = drift_result.get("drift", {}).get("category", "NO_DRIFT") if isinstance(drift_result, dict) else "NO_DRIFT"
        action, reasons, traces = self.policy_engine.evaluate_finding_policy(finding, attack_path or (), drift_cat, conf.score)

        trig_rules = [t["rule_id"] for t in traces if t.get("triggered")]

        # 3. Select Action Recommendation
        rec = self.action_selector.select_action(finding, action, conf, reasons, trig_rules)

        return rec, traces
