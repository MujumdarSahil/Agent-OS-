"""
System Audit MCP - Safe system configuration auditing and vulnerability assessment

This MCP provides:
- Configuration audit (file permissions, service configs, etc.)
- Firewall rule validation
- Log scanning and analysis
- Vulnerability advisory generator

SAFETY GUARANTEES:
- Read-only operations (no system modifications)
- Configuration analysis only
- Defensive and compliance purposes
- No exploitation or privilege escalation
"""

from typing import Dict, Any, List
import re
from datetime import datetime
from agentos.mcp_connectors.base_mcp import BaseMCPConnector


class SystemAuditMCP(BaseMCPConnector):
    """
    System Audit MCP - Safe system configuration auditing.
    
    Provides configuration auditing, firewall validation, log scanning,
    and vulnerability advisory generation without modifying systems.
    """
    
    def __init__(self, endpoint: str = "audit://system"):
        super().__init__(endpoint, "audit_mcp", "system_audit")
        self.skills = [
            {
                "id": "audit_config",
                "name": "audit_config",
                "description": "Audit system configuration files (read-only analysis)",
                "type": "tool",
                "inputs": {"config_files": "list", "config_type": "string"},
                "outputs": {
                    "issues_found": "list",
                    "compliance_score": "float",
                    "recommendations": "list",
                    "risk_level": "string"
                },
                "latency_estimate": 1.0,
                "accuracy_estimate": 0.9,
                "data_sensitivity": "confidential",
                "cost_estimate": {"cost": 0.1},
            },
            {
                "id": "validate_firewall_rules",
                "name": "validate_firewall_rules",
                "description": "Validate firewall rules for security best practices",
                "type": "tool",
                "inputs": {"firewall_rules": "list"},
                "outputs": {
                    "validation_results": "list",
                    "security_score": "float",
                    "vulnerable_rules": "list",
                    "recommendations": "list"
                },
                "latency_estimate": 0.8,
                "accuracy_estimate": 0.85,
                "data_sensitivity": "confidential",
                "cost_estimate": {"cost": 0.08},
            },
            {
                "id": "scan_logs",
                "name": "scan_logs",
                "description": "Scan system logs for security events and anomalies",
                "type": "tool",
                "inputs": {"log_files": "list", "log_type": "string"},
                "outputs": {
                    "security_events": "list",
                    "anomalies": "list",
                    "risk_indicators": "list",
                    "summary": "dict"
                },
                "latency_estimate": 1.5,
                "accuracy_estimate": 0.8,
                "data_sensitivity": "confidential",
                "cost_estimate": {"cost": 0.12},
            },
            {
                "id": "generate_advisory",
                "name": "generate_advisory",
                "description": "Generate vulnerability advisory from audit findings",
                "type": "tool",
                "inputs": {"audit_results": "dict", "system_info": "dict"},
                "outputs": {
                    "advisory": "dict",
                    "severity": "string",
                    "affected_components": "list",
                    "remediation_steps": "list"
                },
                "latency_estimate": 1.0,
                "accuracy_estimate": 0.9,
                "data_sensitivity": "confidential",
                "cost_estimate": {"cost": 0.1},
            },
        ]
    
    async def connect(self) -> bool:
        """Connect to System Audit MCP service"""
        self.status = "active"
        return True
    
    async def disconnect(self):
        """Disconnect from System Audit MCP"""
        self.status = "inactive"
    
    def _audit_config(self, config_files: List[Dict[str, Any]], config_type: str = "generic") -> Dict[str, Any]:
        """Audit system configuration files"""
        issues = []
        compliance_score = 1.0
        
        # Common security issues to check
        insecure_patterns = [
            (r"password\s*=\s*['\"]?[^'\"]+['\"]?", "Plaintext password in config"),
            (r"secret\s*=\s*['\"]?[^'\"]+['\"]?", "Secret in plaintext"),
            (r"key\s*=\s*['\"]?[^'\"]+['\"]?", "API key in plaintext"),
            (r"permission\s*=\s*777", "Overly permissive file permissions"),
            (r"permission\s*=\s*666", "World-writable file permissions"),
            (r"debug\s*=\s*true", "Debug mode enabled in production"),
            (r"ssl\s*=\s*false", "SSL/TLS disabled"),
        ]
        
        for config_file in config_files:
            file_path = config_file.get("path", "unknown")
            content = config_file.get("content", "")
            
            if not content:
                continue
            
            # Check for insecure patterns
            for pattern, description in insecure_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    issues.append({
                        "file": file_path,
                        "issue": description,
                        "severity": "high" if "password" in description.lower() or "secret" in description.lower() else "medium",
                    })
                    compliance_score -= 0.1
        
        # Check for missing security headers (if web config)
        if config_type == "web" or "nginx" in str(config_files).lower() or "apache" in str(config_files).lower():
            for config_file in config_files:
                content = config_file.get("content", "")
                if "X-Frame-Options" not in content and "security" in content.lower():
                    issues.append({
                        "file": config_file.get("path", "unknown"),
                        "issue": "Missing security headers (X-Frame-Options, CSP, etc.)",
                        "severity": "medium",
                    })
                    compliance_score -= 0.05
        
        compliance_score = max(0.0, compliance_score)
        
        # Determine risk level
        high_issues = sum(1 for issue in issues if issue.get("severity") == "high")
        if high_issues > 0:
            risk_level = "high"
        elif len(issues) > 5:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        recommendations = [
            "Use environment variables or secret management for sensitive data",
            "Enable SSL/TLS for all connections",
            "Disable debug mode in production",
            "Review and restrict file permissions",
            "Implement security headers for web applications",
        ]
        
        return {
            "issues_found": issues,
            "compliance_score": compliance_score,
            "recommendations": recommendations,
            "risk_level": risk_level,
        }
    
    def _validate_firewall_rules(self, firewall_rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Validate firewall rules for security best practices"""
        validation_results = []
        vulnerable_rules = []
        security_score = 1.0
        
        for rule in firewall_rules:
            rule_id = rule.get("id", "unknown")
            action = rule.get("action", "").lower()
            protocol = rule.get("protocol", "").lower()
            port = rule.get("port") or rule.get("dst_port")
            source = rule.get("source") or rule.get("src_ip") or rule.get("source_ip")
            
            issues = []
            
            # Check for overly permissive rules
            if action == "allow" and source in ["0.0.0.0/0", "::/0", "any", "*"]:
                issues.append("Allows traffic from any source (0.0.0.0/0)")
                security_score -= 0.2
            
            # Check for dangerous ports
            dangerous_ports = {
                "22": "SSH - ensure restricted source",
                "3389": "RDP - ensure restricted source",
                "1433": "SQL Server - ensure restricted source",
                "3306": "MySQL - ensure restricted source",
                "5432": "PostgreSQL - ensure restricted source",
            }
            
            if str(port) in dangerous_ports:
                if source in ["0.0.0.0/0", "::/0", "any", "*"]:
                    issues.append(f"Port {port} ({dangerous_ports[str(port)]}) open to all sources")
                    security_score -= 0.3
            
            # Check for missing logging
            if not rule.get("log", False) and action == "allow":
                issues.append("Allow rule without logging enabled")
                security_score -= 0.05
            
            if issues:
                vulnerable_rules.append({
                    "rule_id": rule_id,
                    "issues": issues,
                })
                validation_results.append({
                    "rule_id": rule_id,
                    "status": "vulnerable",
                    "issues": issues,
                })
            else:
                validation_results.append({
                    "rule_id": rule_id,
                    "status": "secure",
                    "issues": [],
                })
        
        security_score = max(0.0, security_score)
        
        recommendations = [
            "Restrict source IPs for sensitive services",
            "Enable logging for all allow rules",
            "Review and remove overly permissive rules",
            "Use deny-by-default policy",
            "Regularly audit firewall rules",
        ]
        
        return {
            "validation_results": validation_results,
            "security_score": security_score,
            "vulnerable_rules": vulnerable_rules,
            "recommendations": recommendations,
        }
    
    def _scan_logs(self, log_files: List[Dict[str, Any]], log_type: str = "generic") -> Dict[str, Any]:
        """Scan system logs for security events"""
        security_events = []
        anomalies = []
        risk_indicators = []
        
        # Common security event patterns
        security_patterns = [
            (r"failed\s+login", "Failed login attempt", "medium"),
            (r"unauthorized\s+access", "Unauthorized access attempt", "high"),
            (r"permission\s+denied", "Permission denied", "low"),
            (r"sql\s+injection", "Potential SQL injection", "high"),
            (r"xss", "Potential XSS attack", "high"),
            (r"brute\s+force", "Brute force attack", "high"),
            (r"port\s+scan", "Port scan detected", "medium"),
            (r"malware", "Malware detected", "high"),
            (r"root\s+login", "Root login detected", "high"),
            (r"sudo", "Sudo command executed", "medium"),
        ]
        
        for log_file in log_files:
            file_path = log_file.get("path", "unknown")
            content = log_file.get("content", "")
            lines = content.split("\n") if content else []
            
            for line_num, line in enumerate(lines[:1000], 1):  # Limit to first 1000 lines
                line_lower = line.lower()
                
                # Check for security patterns
                for pattern, description, severity in security_patterns:
                    if re.search(pattern, line_lower):
                        security_events.append({
                            "file": file_path,
                            "line": line_num,
                            "event": description,
                            "severity": severity,
                            "log_line": line[:200],  # Truncate long lines
                        })
                
                # Check for anomalies (unusual patterns)
                if re.search(r"error|exception|critical|fatal", line_lower):
                    if line_num not in [a.get("line") for a in anomalies]:
                        anomalies.append({
                            "file": file_path,
                            "line": line_num,
                            "type": "error_log",
                            "log_line": line[:200],
                        })
        
        # Identify risk indicators
        high_severity_events = [e for e in security_events if e.get("severity") == "high"]
        if len(high_severity_events) > 5:
            risk_indicators.append("Multiple high-severity security events detected")
        
        failed_logins = [e for e in security_events if "login" in e.get("event", "").lower()]
        if len(failed_logins) > 10:
            risk_indicators.append("High number of failed login attempts (potential brute force)")
        
        summary = {
            "total_events": len(security_events),
            "high_severity": len(high_severity_events),
            "medium_severity": len([e for e in security_events if e.get("severity") == "medium"]),
            "low_severity": len([e for e in security_events if e.get("severity") == "low"]),
            "anomalies_count": len(anomalies),
            "risk_indicators_count": len(risk_indicators),
        }
        
        return {
            "security_events": security_events[:50],  # Limit output
            "anomalies": anomalies[:20],
            "risk_indicators": risk_indicators,
            "summary": summary,
        }
    
    def _generate_advisory(self, audit_results: Dict[str, Any], system_info: Dict[str, Any] = None) -> Dict[str, Any]:
        """Generate vulnerability advisory from audit findings"""
        system_info = system_info or {}
        
        # Collect all issues
        issues = []
        
        # From config audit
        if "issues_found" in audit_results:
            issues.extend(audit_results["issues_found"])
        
        # From firewall validation
        if "vulnerable_rules" in audit_results:
            for rule in audit_results["vulnerable_rules"]:
                issues.append({
                    "component": "firewall",
                    "issue": f"Vulnerable firewall rule: {', '.join(rule.get('issues', []))}",
                    "severity": "high",
                })
        
        # From log scanning
        if "security_events" in audit_results:
            high_events = [e for e in audit_results["security_events"] if e.get("severity") == "high"]
            if high_events:
                issues.append({
                    "component": "logs",
                    "issue": f"{len(high_events)} high-severity security events detected",
                    "severity": "high",
                })
        
        # Determine overall severity
        high_severity_count = sum(1 for issue in issues if issue.get("severity") == "high")
        if high_severity_count > 0:
            severity = "high"
        elif len(issues) > 5:
            severity = "medium"
        else:
            severity = "low"
        
        # Collect affected components
        affected_components = list(set(issue.get("component", "unknown") for issue in issues))
        
        # Generate remediation steps
        remediation_steps = [
            "Review all identified security issues",
            "Prioritize high-severity vulnerabilities",
            "Implement recommended security controls",
            "Update firewall rules to restrict access",
            "Enable logging and monitoring for all critical services",
            "Conduct regular security audits",
            "Implement security best practices from NIST/OWASP guidelines",
        ]
        
        advisory = {
            "advisory_id": f"ADV-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "title": f"Security Audit Advisory - {severity.upper()} Severity",
            "severity": severity,
            "date": datetime.now().isoformat(),
            "system_info": system_info,
            "issues": issues,
            "affected_components": affected_components,
            "remediation_steps": remediation_steps,
        }
        
        return {
            "advisory": advisory,
            "severity": severity,
            "affected_components": affected_components,
            "remediation_steps": remediation_steps,
        }
    
    async def call_skill(self, skill_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Call System Audit MCP skill"""
        try:
            if skill_name == "audit_config":
                config_files = params.get("config_files", [])
                config_type = params.get("config_type", "generic")
                
                if not config_files:
                    return {"success": False, "error": "Config files list required"}
                
                result = self._audit_config(config_files, config_type)
                return {"success": True, **result}
            
            elif skill_name == "validate_firewall_rules":
                firewall_rules = params.get("firewall_rules", [])
                
                if not firewall_rules:
                    return {"success": False, "error": "Firewall rules list required"}
                
                result = self._validate_firewall_rules(firewall_rules)
                return {"success": True, **result}
            
            elif skill_name == "scan_logs":
                log_files = params.get("log_files", [])
                log_type = params.get("log_type", "generic")
                
                if not log_files:
                    return {"success": False, "error": "Log files list required"}
                
                result = self._scan_logs(log_files, log_type)
                return {"success": True, **result}
            
            elif skill_name == "generate_advisory":
                audit_results = params.get("audit_results", {})
                system_info = params.get("system_info", {})
                
                if not audit_results:
                    return {"success": False, "error": "Audit results dictionary required"}
                
                result = self._generate_advisory(audit_results, system_info)
                return {"success": True, **result}
            
            else:
                return {"success": False, "error": f"Unknown skill: {skill_name}"}
        
        except Exception as e:
            return {"success": False, "error": f"Error executing skill: {str(e)}"}

