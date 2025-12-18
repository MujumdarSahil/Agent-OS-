"""
System Hardening Tool - Defensive system hardening recommendations

SAFETY: Read-only analysis. No system modifications.
"""

import logging
import re
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class SystemHardening:
    """
    System Hardening - Generates hardening recommendations.
    
    All operations are read-only. No system modifications.
    """
    
    @staticmethod
    def generate_hardening_recommendations(
        audit_results: Dict[str, Any],
        system_info: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Generate system hardening recommendations from audit results.
        
        Args:
            audit_results: Combined results from various audits
            system_info: System information (OS, version, etc.)
            
        Returns:
            Hardening recommendations with safety_metadata
        """
        recommendations = []
        priority = "medium"
        hardening_score = 1.0
        
        # Analyze firewall audit results
        if "firewall_result" in audit_results:
            firewall_result = audit_results["firewall_result"]
            if firewall_result.get("security_score", 1.0) < 0.8:
                recommendations.append({
                    "category": "firewall",
                    "recommendation": "Review and restrict firewall rules",
                    "priority": "high",
                })
                priority = "high"
                hardening_score -= 0.2
        
        # Analyze config audit results
        if "config_result" in audit_results:
            config_result = audit_results["config_result"]
            issues = config_result.get("issues_found", [])
            if issues:
                recommendations.append({
                    "category": "configuration",
                    "recommendation": "Fix configuration security issues",
                    "priority": "high",
                    "issue_count": len(issues),
                })
                priority = "high"
                hardening_score -= 0.2
        
        # Analyze permission audit results
        if "permission_result" in audit_results:
            permission_result = audit_results["permission_result"]
            if permission_result.get("excessive_permissions"):
                recommendations.append({
                    "category": "permissions",
                    "recommendation": "Implement principle of least privilege",
                    "priority": "medium",
                })
                hardening_score -= 0.1
        
        # General recommendations
        if not recommendations:
            recommendations = [
                {
                    "category": "general",
                    "recommendation": "Enable firewall logging",
                    "priority": "low",
                },
                {
                    "category": "general",
                    "recommendation": "Review user permissions regularly",
                    "priority": "low",
                },
                {
                    "category": "general",
                    "recommendation": "Update system packages",
                    "priority": "medium",
                },
            ]
        
        hardening_score = max(0.0, hardening_score)
        
        result = {
            "hardening_score": hardening_score,
            "recommendations": recommendations,
            "priority": priority,
            "safety_metadata": {
                "operation": "read_only",
                "system_modification": False,
                "automated_changes": False,
                "compliance": "defensive_recommendations_only",
            }
        }
        
        logger.info(f"Hardening recommendations generated: {len(recommendations)} recommendations")
        return result

