"""
Verifier Models - Small classifiers for safety checks

Classifies: hallucination, toxicity, policy violation
"""

import logging
import re
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class VerifierModel:
    """
    Verifier Model - Small classifier for safety verification.
    
    Classifies hallucination, toxicity, and policy violations.
    """
    
    def __init__(self, verifier_type: str = "policy"):
        """
        Initialize Verifier Model.
        
        Args:
            verifier_type: Type of verifier (hallucination, toxicity, policy)
        """
        self.verifier_type = verifier_type
        logger.info(f"VerifierModel initialized: {verifier_type}")
    
    def classify_hallucination(
        self,
        text: str,
        context: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Classify if text contains hallucinations.
        
        Args:
            text: Text to check
            context: Context documents for verification
            
        Returns:
            Classification result
        """
        # NOT AVAILABLE in AgentOS 2.0: this used to return a fixed low score (0.1) without
        # checking anything. It now fails loudly instead of reporting a fake "no hallucination".
        raise NotImplementedError(
            "VerifierModel.classify_hallucination is not available in AgentOS 2.0; "
            "see docs/SPEC_2.0.md (no hallucination classifier is shipped)."
        )
        score = 0.1  # unreachable; kept so the original return shape stays documented

        return {
            "is_hallucination": score > 0.5,
            "hallucination_score": score,
            "confidence": 0.85,
        }
    
    def classify_toxicity(self, text: str) -> Dict[str, Any]:
        """
        Classify if text is toxic.
        
        Args:
            text: Text to check
            
        Returns:
            Classification result
        """
        # Simple keyword-based check
        toxic_keywords = ["hate", "violence", "harassment"]
        text_lower = text.lower()
        
        toxic_count = sum(1 for keyword in toxic_keywords if keyword in text_lower)
        toxicity_score = min(1.0, toxic_count / len(toxic_keywords))
        
        return {
            "is_toxic": toxicity_score > 0.3,
            "toxicity_score": toxicity_score,
            "confidence": 0.8,
        }
    
    def classify_policy_violation(
        self,
        text: str,
        policy_rules: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Classify if text violates policy rules.
        
        Args:
            text: Text to check
            policy_rules: List of policy rules
            
        Returns:
            Classification result
        """
        policy_rules = policy_rules or [
            "no_exploit_code",
            "no_malware",
            "no_password_cracking",
        ]
        
        violations = []
        text_lower = text.lower()
        
        if "no_exploit_code" in policy_rules:
            if re.search(r"exploit|vulnerability.*exploit", text_lower):
                violations.append("exploit_code")
        
        if "no_malware" in policy_rules:
            if re.search(r"malware|trojan|virus", text_lower):
                violations.append("malware")
        
        if "no_password_cracking" in policy_rules:
            if re.search(r"password.*crack|brute.*force", text_lower):
                violations.append("password_cracking")
        
        return {
            "violates_policy": len(violations) > 0,
            "violations": violations,
            "violation_score": len(violations) / len(policy_rules),
            "confidence": 0.9,
        }

