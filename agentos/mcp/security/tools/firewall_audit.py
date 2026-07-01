"""
Firewall Audit Tool - Defensive firewall configuration auditing

SAFETY: Read-only configuration analysis. No firewall rule modification.
"""

import logging
from typing import Dict, Any, List

from agentos.core.base import BaseTool

logger = logging.getLogger(__name__)


class FirewallAudit(BaseTool):
    """
    Firewall Audit - Audits firewall rules for security best practices.
    
    All operations are read-only. No firewall modifications.
    """
    name: str = "audit_firewall"
    description: str = "Audits firewall rules for security best practices."

    def run(self, **kwargs: Any) -> Dict[str, Any]:
        return self.audit_firewall_rules(
            kwargs.get("firewall_rules", []),
            kwargs.get("firewall_type", "generic")
        )
    
    @staticmethod
    def audit_firewall_rules(
        firewall_rules: List[Dict[str, Any]],
        firewall_type: str = "generic"
    ) -> Dict[str, Any]:
        """
        Audit firewall rules for security issues.
        
        Args:
            firewall_rules: List of firewall rule dictionaries
            firewall_type: Type of firewall (iptables, ufw, windows, etc.)
            
        Returns:
            Audit results with safety_metadata
        """
        vulnerable_rules = []
        security_score = 1.0
        recommendations = []
        
        for rule in firewall_rules:
            rule_id = rule.get("id", "unknown")
            action = rule.get("action", "").lower()
            source = rule.get("source") or rule.get("src_ip") or rule.get("source_ip", "")
            port = rule.get("port") or rule.get("dest_port")
            
            issues = []
            
            # Check for overly permissive rules
            if action == "allow" and source in ["0.0.0.0/0", "::/0", "any", "*"]:
                issues.append("Allows traffic from any source (0.0.0.0/0)")
                security_score -= 0.2
            
            # Check for dangerous ports open to all
            dangerous_ports = ["22", "3389", "1433", "3306", "5432"]
            if str(port) in dangerous_ports and source in ["0.0.0.0/0", "::/0", "any", "*"]:
                issues.append(f"Port {port} open to all sources")
                security_score -= 0.3
            
            # Check for missing logging
            if action == "allow" and not rule.get("log", False):
                issues.append("Allow rule without logging enabled")
                security_score -= 0.05
            
            if issues:
                vulnerable_rules.append({
                    "rule_id": rule_id,
                    "issues": issues,
                    "severity": "high" if "0.0.0.0/0" in str(issues) else "medium",
                })
        
        security_score = max(0.0, security_score)
        
        # Generate recommendations
        if vulnerable_rules:
            recommendations.append("Restrict source IPs for sensitive services")
            recommendations.append("Enable logging for all allow rules")
            recommendations.append("Review and remove overly permissive rules")
        
        result = {
            "firewall_status": "secure" if security_score >= 0.8 else "vulnerable",
            "security_score": security_score,
            "vulnerable_rules": vulnerable_rules,
            "recommendations": recommendations,
            "safety_metadata": {
                "operation": "read_only",
                "firewall_modification": False,
                "rule_changes": False,
                "compliance": "defensive_audit_only",
            }
        }
        
        logger.info(f"Firewall audit completed: {len(vulnerable_rules)} vulnerable rules found")
        return result

