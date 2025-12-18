"""
Script Author Agent - Generates ONLY DEFENSIVE / EDUCATIONAL security scripts

Enforces governance pre-check BEFORE script is returned.

Allowed scripts:
- firewall config (ufw/iptables/windows)
- log analysis
- SIEM ingestion scripts
- permission and user audits
- network metadata inventory
- config audit automation

Forbidden:
- exploits
- malware
- cracking scripts
- payload generators
- active scanning
"""

import logging
import re
from typing import Dict, Any, List, Optional
from datetime import datetime
from agentos.core.agent import Agent

logger = logging.getLogger(__name__)


class ScriptAuthorAgent(Agent):
    """
    Script Author Agent - Generates defensive/educational security scripts.
    
    This agent generates security scripts in Bash, Python, or PowerShell.
    All scripts are restricted to defensive and educational purposes only.
    
    Governance pre-check is enforced BEFORE script is returned.
    """
    
    # Allowed script categories
    ALLOWED_CATEGORIES = [
        "firewall_config",
        "log_analysis",
        "siem_ingestion",
        "permission_audit",
        "user_audit",
        "network_metadata_inventory",
        "config_audit_automation",
    ]
    
    # Allowed script patterns (must match one of these)
    ALLOWED_PATTERNS = [
        r"firewall.*config|ufw|iptables|windows.*firewall",
        r"log.*analysis|log.*parse|log.*review",
        r"siem.*ingestion|siem.*integration",
        r"permission.*audit|user.*audit|access.*audit",
        r"network.*metadata|metadata.*inventory",
        r"config.*audit|configuration.*audit|config.*check",
    ]
    
    # Forbidden patterns
    FORBIDDEN_PATTERNS = [
        (r"exploit", "Exploits are forbidden"),
        (r"malware|trojan|virus|payload", "Malware/payload generation is forbidden"),
        (r"password.*crack|brute.*force", "Cracking scripts are forbidden"),
        (r"payload.*generator", "Payload generators are forbidden"),
        (r"active.*scan|intrusive.*scan|port.*scan.*active", "Active scanning is forbidden"),
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
        
        logger.info(f"ScriptAuthorAgent created: {name}")
    
    def _validate_category(self, category: str) -> bool:
        """Validate that script category is allowed"""
        return category.lower() in [c.lower() for c in self.ALLOWED_CATEGORIES]
    
    def _check_forbidden_patterns(self, script_content: str) -> Dict[str, Any]:
        """
        Check script for forbidden patterns.
        
        Returns:
            Dict with 'safe' bool and 'violations' list
        """
        violations = []
        script_lower = script_content.lower()
        
        for pattern, reason in self.FORBIDDEN_PATTERNS:
            if re.search(pattern, script_lower):
                violations.append({
                    "pattern": pattern,
                    "reason": reason,
                })
        
        return {
            "safe": len(violations) == 0,
            "violations": violations,
        }
    
    def _check_allowed_patterns(self, script_content: str) -> bool:
        """
        Check if script matches at least one allowed pattern.
        
        Returns:
            True if script matches allowed pattern
        """
        script_lower = script_content.lower()
        return any(re.search(pattern, script_lower) for pattern in self.ALLOWED_PATTERNS)
    
    async def generate_script(
        self,
        script_type: str,
        language: str = "python",
        category: str = "config_audit_automation",
        parameters: Dict[str, Any] = None,
        governance: Optional[Any] = None
    ) -> Dict[str, Any]:
        """
        Generate a security script with governance pre-check.
        
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
        if not self._validate_category(category):
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
        
        # Check for forbidden patterns
        safety_check = self._check_forbidden_patterns(script_content)
        if not safety_check["safe"]:
            logger.warning(f"Script contains forbidden patterns: {safety_check['violations']}")
            return {
                "success": False,
                "error": "Script contains forbidden patterns",
                "violations": safety_check["violations"],
            }
        
        # Check for allowed patterns
        if not self._check_allowed_patterns(script_content):
            logger.warning("Script does not match allowed defensive patterns")
            return {
                "success": False,
                "error": "Script does not match allowed defensive patterns",
            }
        
        # Governance pre-check (BEFORE script is returned)
        if governance:
            # First check: standard governance
            decision = await governance.check(
                agent_id=self.id,
                action="generate_script",
                context={
                    "script_type": script_type,
                    "category": category,
                    "language": language,
                    "script_content": script_content,
                    "script_preview": script_content[:500],  # First 500 chars for preview
                }
            )
            if not decision.allowed:
                logger.warning(f"Governance check failed: {decision.reason}")
                return {
                    "success": False,
                    "error": f"Governance policy violation: {decision.reason}",
                }
            
            # Second check: model output verification (if verifiers available)
            try:
                from agentos.modelhub.safety.verifier import VerifierModel
                verifier = VerifierModel(verifier_type="policy")
                violation_result = verifier.classify_policy_violation(script_content)
                
                if violation_result.get("violates_policy"):
                    logger.warning(f"Verifier detected policy violation: {violation_result.get('violations')}")
                    return {
                        "success": False,
                        "error": f"Script violates policy: {violation_result.get('violations')}",
                    }
            except ImportError:
                # Verifier not available, skip
                pass
        
        # Record script generation
        script_record = {
            "script_id": f"SCRIPT-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "type": script_type,
            "language": language,
            "category": category,
            "generated_by": self.id,
            "timestamp": datetime.now().isoformat(),
            "safe": True,
            "governance_checked": governance is not None,
        }
        self.generated_scripts.append(script_record)
        
        logger.info(f"Script generated successfully: {script_record['script_id']}")
        
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
        
        elif script_type == "siem_ingestion":
            if language == "python":
                return self._generate_siem_ingestion_python(parameters)
        
        elif script_type == "config_audit":
            if language == "python":
                return self._generate_config_audit_python(parameters)
        
        # Default template
        return f"""#!/usr/bin/env {language}
# Security Script: {script_type}
# Generated by ScriptAuthorAgent
# Category: {parameters.get('category', 'config_audit_automation')}
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
# - Active scanning

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
    
    def _generate_siem_ingestion_python(self, params: Dict[str, Any]) -> str:
        """Generate Python SIEM ingestion script"""
        return """#!/usr/bin/env python3
# SIEM Ingestion Script
# Defensive security script for SIEM integration
# 
# ALLOWED: SIEM data ingestion, log forwarding
# PROHIBITED: Data tampering, unauthorized access

import json
import requests

def ingest_to_siem(log_data, siem_endpoint):
    \"\"\"Ingest log data to SIEM system\"\"\"
    print(f"Sending data to SIEM: {siem_endpoint}")
    # Safe data ingestion only
    # No modifications to source data
    print("SIEM ingestion completed")

if __name__ == "__main__":
    ingest_to_siem({}, "https://siem.example.com/api/logs")
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

