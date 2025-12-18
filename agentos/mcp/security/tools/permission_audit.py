"""
Permission Audit Tool - Defensive user and permission auditing

SAFETY: Read-only permission analysis. No permission modification.
"""

import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class PermissionAudit:
    """
    Permission Audit - Audits user permissions and access controls.
    
    All operations are read-only. No permission modifications.
    """
    
    @staticmethod
    def audit_permissions(
        user_list: List[Dict[str, Any]],
        permission_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Audit user permissions for security issues.
        
        Args:
            user_list: List of user dictionaries with permissions
            permission_data: Additional permission context
            
        Returns:
            Audit results with safety_metadata
        """
        permission_issues = []
        excessive_permissions = []
        recommendations = []
        
        for user in user_list:
            user_id = user.get("id") or user.get("username", "unknown")
            permissions = user.get("permissions", [])
            roles = user.get("roles", [])
            
            # Check for excessive permissions
            if "root" in roles or "admin" in roles:
                if len(permissions) > 10:
                    excessive_permissions.append({
                        "user": user_id,
                        "issue": "User has admin role with excessive permissions",
                        "permission_count": len(permissions),
                    })
            
            # Check for missing explicit permissions
            if not permissions and not roles:
                permission_issues.append({
                    "user": user_id,
                    "issue": "User has no explicit permissions defined",
                })
            
            # Check for overly broad permissions
            broad_permissions = ["*", "all", "admin", "root"]
            if any(perm in broad_permissions for perm in permissions):
                permission_issues.append({
                    "user": user_id,
                    "issue": "User has overly broad permissions",
                })
        
        # Generate recommendations
        if excessive_permissions:
            recommendations.append("Implement principle of least privilege")
            recommendations.append("Review and reduce excessive permissions")
        
        if permission_issues:
            recommendations.append("Define explicit permissions for all users")
            recommendations.append("Remove overly broad permissions")
        
        result = {
            "permission_issues": permission_issues,
            "excessive_permissions": excessive_permissions,
            "recommendations": recommendations,
            "safety_metadata": {
                "operation": "read_only",
                "permission_modification": False,
                "user_modification": False,
                "compliance": "defensive_audit_only",
            }
        }
        
        logger.info(f"Permission audit completed: {len(permission_issues)} issues found")
        return result

