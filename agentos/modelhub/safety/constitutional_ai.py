"""
Constitutional AI - Rule-based self-critique and remediation
"""

import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class ConstitutionalAI:
    """
    Constitutional AI - Runs rule-checks and asks LLM to self-critique.
    
    Provides remediation or blocking based on constitutional rules.
    """
    
    # Constitutional rules
    CONSTITUTION = [
        "Do not generate exploit code or malware",
        "Do not provide instructions for unauthorized access",
        "Do not generate password cracking tools",
        "Prioritize defensive and educational content",
        "Respect privacy and data protection",
    ]
    
    def __init__(self, llm_connector=None):
        """
        Initialize Constitutional AI.
        
        Args:
            llm_connector: LLM connector for self-critique
        """
        self.llm_connector = llm_connector
        logger.info("ConstitutionalAI initialized")
    
    async def check_output(
        self,
        candidate_output: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Check candidate output against constitutional rules.
        
        Args:
            candidate_output: Candidate model output
            context: Additional context
            
        Returns:
            Check result with remediation or blocking
        """
        violations = []
        
        # Check against constitution
        for rule in self.CONSTITUTION:
            if self._violates_rule(candidate_output, rule):
                violations.append(rule)
        
        if violations:
            # Request self-critique if LLM available
            if self.llm_connector:
                remediation = await self._request_remediation(candidate_output, violations)
            else:
                remediation = "Output violates constitutional rules. Please revise."
            
            return {
                "allowed": False,
                "violations": violations,
                "remediation": remediation,
                "blocked": True,
            }
        
        return {
            "allowed": True,
            "violations": [],
            "remediation": None,
            "blocked": False,
        }
    
    def _violates_rule(self, output: str, rule: str) -> bool:
        """Check if output violates a rule"""
        output_lower = output.lower()
        rule_lower = rule.lower()
        
        # Simple keyword-based check
        if "exploit" in rule_lower and ("exploit" in output_lower or "vulnerability" in output_lower):
            return True
        if "malware" in rule_lower and "malware" in output_lower:
            return True
        if "password.*crack" in rule_lower or ("password" in rule_lower and "crack" in output_lower):
            return True
        
        return False
    
    async def _request_remediation(self, output: str, violations: List[str]) -> str:
        """Request LLM to provide remediation"""
        if not self.llm_connector:
            return "Please revise output to comply with constitutional rules."
        
        prompt = f"""The following output violates these rules: {', '.join(violations)}

Output: {output}

Please provide a revised version that complies with all rules."""
        
        result = await self.llm_connector.call(prompt, max_tokens=500)
        return result.get("response", "Please revise output.")

