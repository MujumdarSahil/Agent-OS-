"""
System Audit MCP - Safe system configuration auditing

Provides:
- audit_firewall_status(): Audit firewall configuration
- audit_config_security(): Audit system configuration files
- check_user_permissions(): Check user permissions
- analyze_running_services(): Analyze running services
- generate_hardening_recommendations(): Generate hardening recommendations
- detect_misconfigurations(): Detect security misconfigurations

SAFETY: Read-only operations only. No system modifications.
"""

import logging
import re
from typing import Dict, Any, List
from agentos.mcp_connectors.base_mcp import BaseMCPConnector

logger = logging.getLogger(__name__)


class SystemAuditMCP(BaseMCPConnector):
    """
    System Audit MCP - Safe system configuration auditing.
    
    All operations are read-only.
    NO system modifications or privilege escalation.
    """
    
    def __init__(self, endpoint: str = "audit://system"):
        super().__init__(endpoint, "audit_mcp", "system_audit")
        self.skills = [
            {
                "id": "audit_firewall_status",
                "name": "audit_firewall_status",
                "description": "Audit firewall configuration and status",
                "type": "tool",
                "inputs": {"firewall_rules": "list"},
                "outputs": {
                    "firewall_status": "string",
                    "vulnerable_rules": "list",
                    "security_score": "float",
                },
                "latency_estimate": 0.8,
                "accuracy_estimate": 0.85,
                "data_sensitivity": "confidential",
                "cost_estimate": {"cost": 0.08},
            },
            {
                "id": "audit_config_security",
                "name": "audit_config_security",
                "description": "Audit system configuration files for security issues",
                "type": "tool",
                "inputs": {"config_files": "list", "config_type": "string"},
                "outputs": {
                    "issues_found": "list",
                    "compliance_score": "float",
                    "risk_level": "string",
                },
                "latency_estimate": 1.0,
                "accuracy_estimate": 0.9,
                "data_sensitivity": "confidential",
                "cost_estimate": {"cost": 0.1},
            },
            {
                "id": "check_user_permissions",
                "name": "check_user_permissions",
                "description": "Check user permissions and access controls",
                "type": "tool",
                "inputs": {"user_list": "list", "permission_data": "dict"},
                "outputs": {
                    "permission_issues": "list",
                    "excessive_permissions": "list",
                },
                "latency_estimate": 0.6,
                "accuracy_estimate": 0.85,
                "data_sensitivity": "confidential",
                "cost_estimate": {"cost": 0.06},
            },
            {
                "id": "analyze_running_services",
                "name": "analyze_running_services",
                "description": "Analyze running services for security issues",
                "type": "tool",
                "inputs": {"services_data": "list"},
                "outputs": {
                    "vulnerable_services": "list",
                    "recommendations": "list",
                },
                "latency_estimate": 0.7,
                "accuracy_estimate": 0.8,
                "data_sensitivity": "confidential",
                "cost_estimate": {"cost": 0.07},
            },
            {
                "id": "generate_hardening_recommendations",
                "name": "generate_hardening_recommendations",
                "description": "Generate system hardening recommendations",
                "type": "tool",
                "inputs": {"audit_results": "dict", "system_info": "dict"},
                "outputs": {
                    "recommendations": "list",
                    "priority": "string",
                },
                "latency_estimate": 1.0,
                "accuracy_estimate": 0.9,
                "data_sensitivity": "confidential",
                "cost_estimate": {"cost": 0.1},
            },
            {
                "id": "detect_misconfigurations",
                "name": "detect_misconfigurations",
                "description": "Detect security misconfigurations",
                "type": "tool",
                "inputs": {"config_data": "dict"},
                "outputs": {
                    "misconfigurations": "list",
                    "severity": "string",
                },
                "latency_estimate": 0.9,
                "accuracy_estimate": 0.85,
                "data_sensitivity": "confidential",
                "cost_estimate": {"cost": 0.09},
            },
        ]
    
    async def connect(self) -> bool:
        """Connect to System Audit MCP service"""
        self.status = "active"
        logger.info("System Audit MCP connected")
        return True
    
    async def disconnect(self):
        """Disconnect from System Audit MCP"""
        self.status = "inactive"
        logger.info("System Audit MCP disconnected")
    
    def _audit_firewall_status(self, firewall_rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Audit firewall configuration and status"""
        if not firewall_rules:
            return {
                "firewall_status": "unknown",
                "vulnerable_rules": [],
                "security_score": 0.0,
            }
        
        vulnerable_rules = []
        security_score = 1.0
        
        for rule in firewall_rules:
            rule_id = rule.get("id", "unknown")
            action = rule.get("action", "").lower()
            source = rule.get("source") or rule.get("src_ip") or rule.get("source_ip")
            
            if action == "allow" and source in ["0.0.0.0/0", "::/0", "any", "*"]:
                vulnerable_rules.append({
                    "rule_id": rule_id,
                    "issue": "Allows traffic from any source (0.0.0.0/0)",
                })
                security_score -= 0.2
        
        security_score = max(0.0, security_score)
        
        if security_score >= 0.8:
            firewall_status = "secure"
        elif security_score >= 0.5:
            firewall_status = "moderate"
        else:
            firewall_status = "vulnerable"
        
        return {
            "firewall_status": firewall_status,
            "vulnerable_rules": vulnerable_rules,
            "security_score": security_score,
        }
    
    def _audit_config_security(self, config_files: List[Dict[str, Any]], config_type: str = "generic") -> Dict[str, Any]:
        """Audit system configuration files for security issues"""
        if not config_files:
            return {
                "issues_found": [],
                "compliance_score": 1.0,
                "risk_level": "low",
            }
        
        issues = []
        compliance_score = 1.0
        
        insecure_patterns = [
            (r"password\s*=\s*['\"]?[^'\"]+['\"]?", "Plaintext password in config"),
            (r"secret\s*=\s*['\"]?[^'\"]+['\"]?", "Secret in plaintext"),
            (r"key\s*=\s*['\"]?[^'\"]+['\"]?", "API key in plaintext"),
            (r"permission\s*=\s*777", "Overly permissive file permissions"),
            (r"debug\s*=\s*true", "Debug mode enabled in production"),
            (r"ssl\s*=\s*false", "SSL/TLS disabled"),
        ]
        
        for config_file in config_files:
            file_path = config_file.get("path", "unknown")
            content = config_file.get("content", "")
            
            if not content:
                continue
            
            for pattern, description in insecure_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    issues.append({
                        "file": file_path,
                        "issue": description,
                        "severity": "high" if "password" in description.lower() or "secret" in description.lower() else "medium",
                    })
                    compliance_score -= 0.1
        
        compliance_score = max(0.0, compliance_score)
        
        high_issues = sum(1 for issue in issues if issue.get("severity") == "high")
        if high_issues > 0:
            risk_level = "high"
        elif len(issues) > 5:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return {
            "issues_found": issues,
            "compliance_score": compliance_score,
            "risk_level": risk_level,
        }
    
    def _check_user_permissions(self, user_list: List[Dict[str, Any]], permission_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Check user permissions and access controls"""
        if not user_list:
            return {
                "permission_issues": [],
                "excessive_permissions": [],
            }
        
        permission_issues = []
        excessive_permissions = []
        
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
                    })
            
            # Check for permission issues
            if not permissions:
                permission_issues.append({
                    "user": user_id,
                    "issue": "User has no explicit permissions defined",
                })
        
        return {
            "permission_issues": permission_issues,
            "excessive_permissions": excessive_permissions,
        }
    
    def _analyze_running_services(self, services_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze running services for security issues"""
        if not services_data:
            return {
                "vulnerable_services": [],
                "recommendations": [],
            }
        
        vulnerable_services = []
        recommendations = []
        
        dangerous_services = ["telnet", "ftp", "rsh", "rlogin"]
        
        for service in services_data:
            service_name = service.get("name", "").lower()
            service_status = service.get("status", "").lower()
            
            if service_status == "running":
                if any(dangerous in service_name for dangerous in dangerous_services):
                    vulnerable_services.append({
                        "service": service_name,
                        "issue": "Dangerous service is running",
                    })
                    recommendations.append(f"Disable {service_name} service")
        
        return {
            "vulnerable_services": vulnerable_services,
            "recommendations": recommendations,
        }
    
    def _generate_hardening_recommendations(self, audit_results: Dict[str, Any], system_info: Dict[str, Any] = None) -> Dict[str, Any]:
        """Generate system hardening recommendations"""
        recommendations = []
        priority = "medium"
        
        # From firewall audit
        if "vulnerable_rules" in audit_results:
            if len(audit_results["vulnerable_rules"]) > 0:
                recommendations.append("Review and restrict firewall rules")
                priority = "high"
        
        # From config audit
        if "issues_found" in audit_results:
            if len(audit_results["issues_found"]) > 0:
                recommendations.append("Fix configuration security issues")
                priority = "high"
        
        # From service analysis
        if "vulnerable_services" in audit_results:
            if len(audit_results["vulnerable_services"]) > 0:
                recommendations.append("Disable vulnerable services")
                priority = "high"
        
        # General recommendations
        if not recommendations:
            recommendations = [
                "Enable firewall logging",
                "Review user permissions regularly",
                "Update system packages",
                "Enable security monitoring",
            ]
        
        return {
            "recommendations": recommendations,
            "priority": priority,
        }
    
    def _detect_misconfigurations(self, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect security misconfigurations"""
        misconfigurations = []
        severity = "low"
        
        # Check for common misconfigurations
        if config_data.get("ssl_enabled") == False:
            misconfigurations.append({
                "type": "ssl_disabled",
                "description": "SSL/TLS is disabled",
                "severity": "high",
            })
            severity = "high"
        
        if config_data.get("debug_mode") == True:
            misconfigurations.append({
                "type": "debug_enabled",
                "description": "Debug mode is enabled in production",
                "severity": "medium",
            })
            if severity == "low":
                severity = "medium"
        
        if config_data.get("default_credentials") == True:
            misconfigurations.append({
                "type": "default_credentials",
                "description": "Default credentials are in use",
                "severity": "high",
            })
            severity = "high"
        
        return {
            "misconfigurations": misconfigurations,
            "severity": severity,
        }
    
    async def call_skill(self, skill_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Call System Audit MCP skill"""
        try:
            logger.info(f"System Audit MCP skill called: {skill_name}")
            
            if skill_name == "audit_firewall_status":
                firewall_rules = params.get("firewall_rules", [])
                if not firewall_rules:
                    return {"success": False, "error": "Firewall rules list required"}
                result = self._audit_firewall_status(firewall_rules)
                return {"success": True, **result}
            
            elif skill_name == "audit_config_security":
                config_files = params.get("config_files", [])
                config_type = params.get("config_type", "generic")
                if not config_files:
                    return {"success": False, "error": "Config files list required"}
                result = self._audit_config_security(config_files, config_type)
                return {"success": True, **result}
            
            elif skill_name == "check_user_permissions":
                user_list = params.get("user_list", [])
                permission_data = params.get("permission_data", {})
                if not user_list:
                    return {"success": False, "error": "User list required"}
                result = self._check_user_permissions(user_list, permission_data)
                return {"success": True, **result}
            
            elif skill_name == "analyze_running_services":
                services_data = params.get("services_data", [])
                if not services_data:
                    return {"success": False, "error": "Services data list required"}
                result = self._analyze_running_services(services_data)
                return {"success": True, **result}
            
            elif skill_name == "generate_hardening_recommendations":
                audit_results = params.get("audit_results", {})
                system_info = params.get("system_info", {})
                if not audit_results:
                    return {"success": False, "error": "Audit results dictionary required"}
                result = self._generate_hardening_recommendations(audit_results, system_info)
                return {"success": True, **result}
            
            elif skill_name == "detect_misconfigurations":
                config_data = params.get("config_data", {})
                if not config_data:
                    return {"success": False, "error": "Config data dictionary required"}
                result = self._detect_misconfigurations(config_data)
                return {"success": True, **result}
            
            else:
                return {"success": False, "error": f"Unknown skill: {skill_name}"}
        
        except Exception as e:
            logger.error(f"Error executing System Audit MCP skill {skill_name}: {e}")
            return {"success": False, "error": f"Error executing skill: {str(e)}"}

