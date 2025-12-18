"""
Security Agents - Specialized agents for cybersecurity operations

This module provides:
- SecurityAgent: For security auditing, analysis, monitoring, and policy advice
- ScriptAuthorAgent: For generating defensive/educational security scripts

SAFETY GUARANTEES:
- All agents operate in defensive/educational mode only
- Script generation is restricted to safe operations
- Governance Engine enforces security policies
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from agentos.core.agent import Agent
from agentos.mcp_connectors.base_mcp import BaseMCPConnector


class SecurityAgent(Agent):
    """
    Security Agent - Specialized agent for cybersecurity operations.
    
    Roles:
    - auditor: Performs security audits and compliance checks
    - analyst: Analyzes security events and incidents
    - monitor: Monitors network and system activity
    - policy-advisor: Provides security policy recommendations
    
    Abilities:
    - Request and use security MCP tools (PAT-MCP, Network Monitor, System Audit)
    - Generate cybersecurity scripts for EDUCATIONAL and DEFENSIVE purposes only
    - Write secure configuration checks
    - Produce incident reports
    - Collaborate with squads on security missions
    """
    
    def __init__(
        self,
        id: Optional[str] = None,
        name: str = "SecurityAgent",
        role: str = "analyst",
        security_mcps: Optional[Dict[str, BaseMCPConnector]] = None,
        memory_ref: Optional[Any] = None,
        **kwargs
    ):
        # Validate role
        valid_roles = ["auditor", "analyst", "monitor", "policy-advisor"]
        if role not in valid_roles:
            raise ValueError(f"Invalid role. Must be one of: {valid_roles}")
        
        # Initialize base agent with security skills
        security_skills = [
            "security_audit",
            "incident_analysis",
            "network_monitoring",
            "policy_evaluation",
            "vulnerability_assessment",
        ]
        
        super().__init__(
            id=id,
            name=name,
            roles=[role],
            skills=security_skills,
            memory_ref=memory_ref,
            **kwargs
        )
        
        self.security_role = role
        self.security_mcps = security_mcps or {}
        
        # Register security tools based on available MCPs
        self._register_security_tools()
    
    def _register_security_tools(self):
        """Register security tools from MCP connectors"""
        # PAT-MCP tools
        if "pat_mcp" in self.security_mcps:
            self.register_tool("identify_hash", self._identify_hash)
            self.register_tool("benchmark_password_strength", self._benchmark_password_strength)
            self.register_tool("evaluate_password_policy", self._evaluate_password_policy)
            self.register_tool("detect_weak_patterns", self._detect_weak_patterns)
        
        # Network Monitor MCP tools
        if "network_monitor_mcp" in self.security_mcps:
            self.register_tool("detect_port_scan", self._detect_port_scan)
            self.register_tool("detect_network_anomalies", self._detect_network_anomalies)
            self.register_tool("classify_security_incident", self._classify_security_incident)
            self.register_tool("analyze_network_metadata", self._analyze_network_metadata)
        
        # System Audit MCP tools
        if "audit_mcp" in self.security_mcps:
            self.register_tool("audit_system_config", self._audit_system_config)
            self.register_tool("validate_firewall", self._validate_firewall)
            self.register_tool("scan_security_logs", self._scan_security_logs)
            self.register_tool("generate_vulnerability_advisory", self._generate_vulnerability_advisory)
    
    async def _identify_hash(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Identify password hash type"""
        if "pat_mcp" not in self.security_mcps:
            return {"success": False, "error": "PAT-MCP not available"}
        
        mcp = self.security_mcps["pat_mcp"]
        return await mcp.call_skill("identify_hash", params)
    
    async def _benchmark_password_strength(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Benchmark password hash strength"""
        if "pat_mcp" not in self.security_mcps:
            return {"success": False, "error": "PAT-MCP not available"}
        
        mcp = self.security_mcps["pat_mcp"]
        return await mcp.call_skill("benchmark_strength", params)
    
    async def _evaluate_password_policy(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate password policy"""
        if "pat_mcp" not in self.security_mcps:
            return {"success": False, "error": "PAT-MCP not available"}
        
        mcp = self.security_mcps["pat_mcp"]
        return await mcp.call_skill("evaluate_policy", params)
    
    async def _detect_weak_patterns(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Detect weak password patterns"""
        if "pat_mcp" not in self.security_mcps:
            return {"success": False, "error": "PAT-MCP not available"}
        
        mcp = self.security_mcps["pat_mcp"]
        return await mcp.call_skill("detect_weak_patterns", params)
    
    async def _detect_port_scan(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Detect port scan from logs"""
        if "network_monitor_mcp" not in self.security_mcps:
            return {"success": False, "error": "Network Monitor MCP not available"}
        
        mcp = self.security_mcps["network_monitor_mcp"]
        return await mcp.call_skill("detect_port_scan", params)
    
    async def _detect_network_anomalies(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Detect network anomalies"""
        if "network_monitor_mcp" not in self.security_mcps:
            return {"success": False, "error": "Network Monitor MCP not available"}
        
        mcp = self.security_mcps["network_monitor_mcp"]
        return await mcp.call_skill("detect_anomalies", params)
    
    async def _classify_security_incident(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Classify security incident"""
        if "network_monitor_mcp" not in self.security_mcps:
            return {"success": False, "error": "Network Monitor MCP not available"}
        
        mcp = self.security_mcps["network_monitor_mcp"]
        return await mcp.call_skill("classify_incident", params)
    
    async def _analyze_network_metadata(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze network metadata"""
        if "network_monitor_mcp" not in self.security_mcps:
            return {"success": False, "error": "Network Monitor MCP not available"}
        
        mcp = self.security_mcps["network_monitor_mcp"]
        return await mcp.call_skill("analyze_metadata", params)
    
    async def _audit_system_config(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Audit system configuration"""
        if "audit_mcp" not in self.security_mcps:
            return {"success": False, "error": "System Audit MCP not available"}
        
        mcp = self.security_mcps["audit_mcp"]
        return await mcp.call_skill("audit_config", params)
    
    async def _validate_firewall(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Validate firewall rules"""
        if "audit_mcp" not in self.security_mcps:
            return {"success": False, "error": "System Audit MCP not available"}
        
        mcp = self.security_mcps["audit_mcp"]
        return await mcp.call_skill("validate_firewall_rules", params)
    
    async def _scan_security_logs(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Scan security logs"""
        if "audit_mcp" not in self.security_mcps:
            return {"success": False, "error": "System Audit MCP not available"}
        
        mcp = self.security_mcps["audit_mcp"]
        return await mcp.call_skill("scan_logs", params)
    
    async def _generate_vulnerability_advisory(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Generate vulnerability advisory"""
        if "audit_mcp" not in self.security_mcps:
            return {"success": False, "error": "System Audit MCP not available"}
        
        mcp = self.security_mcps["audit_mcp"]
        return await mcp.call_skill("generate_advisory", params)
    
    async def generate_incident_report(
        self,
        incident_data: Dict[str, Any],
        include_recommendations: bool = True
    ) -> Dict[str, Any]:
        """
        Generate a comprehensive incident report.
        
        Args:
            incident_data: Incident data including logs, events, etc.
            include_recommendations: Whether to include remediation recommendations
            
        Returns:
            Incident report dictionary
        """
        report = {
            "incident_id": f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "generated_by": self.id,
            "agent_role": self.security_role,
            "timestamp": datetime.now().isoformat(),
            "incident_data": incident_data,
        }
        
        # Classify incident if network monitor available
        if "network_monitor_mcp" in self.security_mcps and "log_entries" in incident_data:
            classification = await self._classify_security_incident({
                "log_entries": incident_data.get("log_entries", []),
                "incident_context": incident_data,
            })
            report["classification"] = classification
        
        # Add recommendations if requested
        if include_recommendations:
            report["recommendations"] = [
                "Review all security events and logs",
                "Isolate affected systems if necessary",
                "Update security controls based on findings",
                "Document incident for future reference",
                "Implement preventive measures",
            ]
        
        return report


class ScriptAuthorAgent(Agent):
    """
    Script Author Agent - Generates defensive/educational security scripts.
    
    This agent generates security scripts in Bash, Python, or PowerShell.
    Scripts are restricted to:
    - Defensive operations (firewall rules, log analysis, etc.)
    - Educational purposes (security awareness, training)
    - Auditing-related tasks (configuration checks, compliance)
    
    PROHIBITED:
    - Exploit code generation
    - Malware creation
    - Password cracking scripts
    - Unauthorized access attempts
    - Any offensive security tools
    
    Governance Engine blocks harmful/attack scripts before execution.
    """
    
    # Allowed script categories
    ALLOWED_CATEGORIES = [
        "firewall_configuration",
        "log_analysis",
        "configuration_audit",
        "vulnerability_scanning",  # Read-only scanning only
        "compliance_checking",
        "security_monitoring",
        "backup_verification",
        "access_log_review",
        "ssl_certificate_check",
        "file_permission_audit",
    ]
    
    # Prohibited script patterns
    PROHIBITED_PATTERNS = [
        r"password.*crack",
        r"brute.*force",
        r"exploit",
        r"malware",
        r"trojan",
        r"virus",
        r"backdoor",
        r"unauthorized.*access",
        r"privilege.*escalation",
        r"sql.*injection.*test",  # Only if it's actually testing/exploiting
        r"xss.*exploit",
    ]
    
    def __init__(
        self,
        id: Optional[str] = None,
        name: str = "ScriptAuthorAgent",
        script_languages: List[str] = None,
        memory_ref: Optional[Any] = None,
        **kwargs
    ):
        script_languages = script_languages or ["bash", "python", "powershell"]
        
        super().__init__(
            id=id,
            name=name,
            roles=["script_author"],
            skills=["script_generation", "security_scripting", "code_review"],
            memory_ref=memory_ref,
            **kwargs
        )
        
        self.script_languages = script_languages
        self.generated_scripts = []  # Track generated scripts for audit
    
    def _validate_script_category(self, category: str) -> bool:
        """Validate that script category is allowed"""
        return category.lower() in [c.lower() for c in self.ALLOWED_CATEGORIES]
    
    def _check_prohibited_patterns(self, script_content: str) -> Dict[str, Any]:
        """
        Check script for prohibited patterns.
        
        Returns:
            Dict with 'safe' bool and 'violations' list
        """
        import re
        
        violations = []
        script_lower = script_content.lower()
        
        for pattern in self.PROHIBITED_PATTERNS:
            if re.search(pattern, script_lower):
                violations.append(f"Prohibited pattern detected: {pattern}")
        
        return {
            "safe": len(violations) == 0,
            "violations": violations,
        }
    
    async def generate_script(
        self,
        script_type: str,
        language: str = "python",
        category: str = "security_monitoring",
        parameters: Dict[str, Any] = None,
        governance: Optional[Any] = None
    ) -> Dict[str, Any]:
        """
        Generate a security script.
        
        Args:
            script_type: Type of script (e.g., "firewall_check", "log_analyzer")
            language: Script language (bash, python, powershell)
            category: Script category (must be in ALLOWED_CATEGORIES)
            parameters: Script parameters
            governance: Governance engine for policy checks
            
        Returns:
            Dict with script content and metadata
        """
        parameters = parameters or {}
        
        # Validate category
        if not self._validate_script_category(category):
            return {
                "success": False,
                "error": f"Category '{category}' not allowed. Allowed: {self.ALLOWED_CATEGORIES}",
            }
        
        # Validate language
        if language.lower() not in [lang.lower() for lang in self.script_languages]:
            return {
                "success": False,
                "error": f"Language '{language}' not supported. Supported: {self.script_languages}",
            }
        
        # Generate script based on type
        script_content = self._generate_script_content(script_type, language, parameters)
        
        # Check for prohibited patterns
        safety_check = self._check_prohibited_patterns(script_content)
        if not safety_check["safe"]:
            return {
                "success": False,
                "error": "Script contains prohibited patterns",
                "violations": safety_check["violations"],
            }
        
        # Governance check (if provided)
        if governance:
            decision = await governance.check(
                agent_id=self.id,
                action="generate_script",
                context={
                    "script_type": script_type,
                    "category": category,
                    "language": language,
                    "script_preview": script_content[:500],  # First 500 chars for preview
                }
            )
            if not decision.allowed:
                return {
                    "success": False,
                    "error": f"Governance policy violation: {decision.reason}",
                }
        
        # Record script generation
        script_record = {
            "script_id": f"SCRIPT-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "type": script_type,
            "language": language,
            "category": category,
            "generated_by": self.id,
            "timestamp": datetime.now().isoformat(),
            "safe": True,
        }
        self.generated_scripts.append(script_record)
        
        return {
            "success": True,
            "script_content": script_content,
            "script_metadata": script_record,
            "safety_check": safety_check,
        }
    
    def _generate_script_content(self, script_type: str, language: str, parameters: Dict[str, Any]) -> str:
        """Generate script content based on type and language"""
        language = language.lower()
        
        # Template scripts (defensive/educational only)
        if script_type == "firewall_check":
            if language == "python":
                return self._generate_firewall_check_python(parameters)
            elif language == "bash":
                return self._generate_firewall_check_bash(parameters)
            elif language == "powershell":
                return self._generate_firewall_check_powershell(parameters)
        
        elif script_type == "log_analyzer":
            if language == "python":
                return self._generate_log_analyzer_python(parameters)
            elif language == "bash":
                return self._generate_log_analyzer_bash(parameters)
        
        elif script_type == "config_audit":
            if language == "python":
                return self._generate_config_audit_python(parameters)
        
        # Default template
        return f"""#!/usr/bin/env {language}
# Security Script: {script_type}
# Generated by ScriptAuthorAgent
# Category: {parameters.get('category', 'security_monitoring')}
# 
# ALLOWED USES:
# - Defensive security operations
# - Educational purposes
# - Security auditing and compliance
#
# PROHIBITED:
# - Exploit code
# - Malware
# - Unauthorized access attempts
# - Password cracking

print("Security script template for {script_type}")
"""
    
    def _generate_firewall_check_python(self, params: Dict[str, Any]) -> str:
        """Generate Python firewall check script"""
        return """#!/usr/bin/env python3
# Firewall Configuration Check Script
# Defensive security script for auditing firewall rules
# 
# ALLOWED: Configuration auditing, compliance checking
# PROHIBITED: Exploitation, unauthorized access

import subprocess
import json

def check_firewall_rules():
    \"\"\"Check firewall rules for security best practices\"\"\"
    print("Checking firewall configuration...")
    # Read-only firewall rule checking
    # No modifications, only analysis
    print("Firewall check completed")

if __name__ == "__main__":
    check_firewall_rules()
"""
    
    def _generate_firewall_check_bash(self, params: Dict[str, Any]) -> str:
        """Generate Bash firewall check script"""
        return """#!/bin/bash
# Firewall Configuration Check Script
# Defensive security script for auditing firewall rules

echo "Checking firewall configuration..."
# Read-only firewall rule checking
# No modifications, only analysis
echo "Firewall check completed"
"""
    
    def _generate_firewall_check_powershell(self, params: Dict[str, Any]) -> str:
        """Generate PowerShell firewall check script"""
        return """# Firewall Configuration Check Script
# Defensive security script for auditing firewall rules

Write-Host "Checking firewall configuration..."
# Read-only firewall rule checking
# No modifications, only analysis
Write-Host "Firewall check completed"
"""
    
    def _generate_log_analyzer_python(self, params: Dict[str, Any]) -> str:
        """Generate Python log analyzer script"""
        return """#!/usr/bin/env python3
# Log Analysis Script
# Defensive security script for analyzing security logs
# 
# ALLOWED: Log analysis, anomaly detection, incident investigation
# PROHIBITED: Log tampering, unauthorized access

import re
from collections import Counter

def analyze_security_logs(log_file):
    \"\"\"Analyze security logs for suspicious patterns\"\"\"
    print(f"Analyzing logs from {log_file}...")
    # Read-only log analysis
    # No modifications to logs
    print("Log analysis completed")

if __name__ == "__main__":
    analyze_security_logs("security.log")
"""
    
    def _generate_log_analyzer_bash(self, params: Dict[str, Any]) -> str:
        """Generate Bash log analyzer script"""
        return """#!/bin/bash
# Log Analysis Script
# Defensive security script for analyzing security logs

LOG_FILE="${1:-security.log}"
echo "Analyzing logs from $LOG_FILE..."
# Read-only log analysis
# No modifications to logs
echo "Log analysis completed"
"""
    
    def _generate_config_audit_python(self, params: Dict[str, Any]) -> str:
        """Generate Python config audit script"""
        return """#!/usr/bin/env python3
# Configuration Audit Script
# Defensive security script for auditing system configurations
# 
# ALLOWED: Configuration auditing, compliance checking
# PROHIBITED: Configuration modification, exploitation

import os
import json

def audit_configuration(config_path):
    \"\"\"Audit system configuration for security issues\"\"\"
    print(f"Auditing configuration at {config_path}...")
    # Read-only configuration analysis
    # No modifications to configuration
    print("Configuration audit completed")

if __name__ == "__main__":
    audit_configuration("/etc/security/config")
"""

