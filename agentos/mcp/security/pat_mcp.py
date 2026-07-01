"""
Password Audit Tool MCP (PAT-MCP)

Provides safe password auditing capabilities:
- hash_type(): Identify password hash type
- hash_strength(): Benchmark hash strength (mathematical only)
- dictionary_strength_simulation(): Simulate dictionary attack strength (no real cracking)
- password_policy_eval(): Evaluate password policy
- ai_pattern_detector(): AI-based weak pattern detection

SAFETY: Mathematical evaluation only, NO real cracking.
"""

import logging
import re
from typing import Dict, Any, List
from agentos.mcp_connectors.base_mcp import BaseMCPConnector

logger = logging.getLogger(__name__)


class PasswordAuditToolMCP(BaseMCPConnector):
    """
    Password Audit Tool MCP - Safe password auditing.
    
    All operations are mathematical/simulated only.
    NO actual password cracking or brute-force attacks.
    """
    
    def __init__(self, endpoint: str = "pat://audit"):
        super().__init__(endpoint, "pat_mcp", "password_audit")
        self.skills = [
            {
                "id": "hash_type",
                "name": "hash_type",
                "description": "Identify password hash type (MD5, SHA-256, bcrypt, etc.)",
                "type": "tool",
                "inputs": {"hash": "string"},
                "outputs": {
                    "hash_type": "string",
                    "confidence": "float",
                    "algorithm": "string",
                },
                "latency_estimate": 0.1,
                "accuracy_estimate": 0.95,
                "data_sensitivity": "confidential",
                "cost_estimate": {"cost": 0.01},
            },
            {
                "id": "hash_strength",
                "name": "hash_strength",
                "description": "Benchmark hash strength (mathematical analysis only, no cracking)",
                "type": "tool",
                "inputs": {"hash": "string", "hash_type": "string"},
                "outputs": {
                    "strength_score": "float",
                    "resistance_to_brute_force": "string",
                    "estimated_crack_time": "string"
                },
                "latency_estimate": 0.2,
                "accuracy_estimate": 0.9,
                "data_sensitivity": "confidential",
                "cost_estimate": {"cost": 0.02},
            },
            {
                "id": "dictionary_strength_simulation",
                "name": "dictionary_strength_simulation",
                "description": "Simulate dictionary attack strength (no actual cracking)",
                "type": "tool",
                "inputs": {"hash": "string", "dictionary_size": "int"},
                "outputs": {
                    "vulnerable_to_dictionary": "bool",
                    "estimated_dictionary_match_probability": "float",
                },
                "latency_estimate": 0.3,
                "accuracy_estimate": 0.85,
                "data_sensitivity": "confidential",
                "cost_estimate": {"cost": 0.02},
            },
            {
                "id": "password_policy_eval",
                "name": "password_policy_eval",
                "description": "Evaluate password policy against NIST 800-63",
                "type": "tool",
                "inputs": {"policy": "dict"},
                "outputs": {
                    "compliance_score": "float",
                    "nist_compliant": "bool",
                    "violations": "list",
                },
                "latency_estimate": 0.5,
                "accuracy_estimate": 0.95,
                "data_sensitivity": "public",
                "cost_estimate": {"cost": 0.05},
            },
            {
                "id": "ai_pattern_detector",
                "name": "ai_pattern_detector",
                "description": "AI-based weak password pattern detection (analysis only)",
                "type": "tool",
                "inputs": {"password_samples": "list"},
                "outputs": {
                    "common_patterns": "list",
                    "weak_patterns_detected": "list",
                    "risk_level": "string",
                },
                "latency_estimate": 1.0,
                "accuracy_estimate": 0.9,
                "data_sensitivity": "confidential",
                "cost_estimate": {"cost": 0.1},
            },
        ]
    
    async def connect(self) -> bool:
        """Connect to PAT-MCP service"""
        self.status = "active"
        logger.info("PAT-MCP connected")
        return True
    
    async def disconnect(self):
        """Disconnect from PAT-MCP"""
        self.status = "inactive"
        logger.info("PAT-MCP disconnected")
    
    def _identify_hash_type(self, hash_value: str) -> Dict[str, Any]:
        """Identify hash type from hash value"""
        hash_value = hash_value.strip()
        length = len(hash_value)
        
        patterns = {
            "md5": (32, r"^[a-f0-9]{32}$", "MD5"),
            "sha1": (40, r"^[a-f0-9]{40}$", "SHA-1"),
            "sha256": (64, r"^[a-f0-9]{64}$", "SHA-256"),
            "sha512": (128, r"^[a-f0-9]{128}$", "SHA-512"),
            "bcrypt": (60, r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$", "bcrypt"),
            "argon2": (None, r"^\$argon2", "Argon2"),
            "pbkdf2": (None, r"^\$pbkdf2", "PBKDF2"),
        }
        
        for hash_type, (expected_len, pattern, algorithm) in patterns.items():
            if expected_len and length == expected_len:
                if re.match(pattern, hash_value, re.IGNORECASE):
                    return {
                        "hash_type": hash_type,
                        "algorithm": algorithm,
                        "confidence": 0.95,
                    }
            elif pattern and re.match(pattern, hash_value, re.IGNORECASE):
                return {
                    "hash_type": hash_type,
                    "algorithm": algorithm,
                    "confidence": 0.90,
                }
        
        return {
            "hash_type": "unknown",
            "algorithm": "Unknown",
            "confidence": 0.3,
        }
    
    def _benchmark_strength(self, hash_value: str, hash_type: str) -> Dict[str, Any]:
        """Benchmark hash strength (mathematical analysis only)"""
        strength_scores = {
            "md5": 0.2,
            "sha1": 0.3,
            "sha256": 0.5,
            "sha512": 0.6,
            "bcrypt": 0.9,
            "argon2": 0.95,
            "pbkdf2": 0.85,
        }
        
        strength_score = strength_scores.get(hash_type, 0.4)
        
        if hash_type in ["bcrypt", "argon2", "pbkdf2"]:
            brute_force_resistance = "High (slow by design)"
            crack_time = "Years to decades"
        elif hash_type in ["sha256", "sha512"]:
            brute_force_resistance = "Medium (fast but long output)"
            crack_time = "Days to months (with GPU clusters)"
        else:
            brute_force_resistance = "Low (fast and vulnerable)"
            crack_time = "Hours to days"
        
        return {
            "strength_score": strength_score,
            "resistance_to_brute_force": brute_force_resistance,
            "estimated_crack_time": crack_time,
        }
    
    def _simulate_dictionary_attack(self, hash_value: str, dictionary_size: int = 10000) -> Dict[str, Any]:
        """Simulate dictionary attack (no actual cracking)"""
        hash_type_info = self._identify_hash_type(hash_value)
        hash_type = hash_type_info.get("hash_type", "unknown")
        
        vulnerable = hash_type in ["md5", "sha1"]
        
        if hash_type in ["md5", "sha1"]:
            probability = 0.7
        elif hash_type in ["sha256", "sha512"]:
            probability = 0.3
        else:
            probability = 0.1
        
        return {
            "vulnerable_to_dictionary": vulnerable,
            "estimated_dictionary_match_probability": probability,
        }
    
    def _evaluate_policy(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate password policy against NIST 800-63"""
        violations = []
        compliance_score = 1.0
        
        min_length = policy.get("min_length", 0)
        if min_length < 8:
            violations.append("Minimum length should be at least 8 characters")
            compliance_score -= 0.2
        
        require_uppercase = policy.get("require_uppercase", False)
        require_lowercase = policy.get("require_lowercase", False)
        require_digits = policy.get("require_digits", False)
        
        if not (require_uppercase and require_lowercase):
            violations.append("Require both uppercase and lowercase characters")
        
        if not require_digits:
            violations.append("Require at least one digit")
        
        if not policy.get("password_history", 0):
            violations.append("Implement password history to prevent reuse")
        
        compliance_score = max(0.0, compliance_score - len(violations) * 0.1)
        nist_compliant = compliance_score >= 0.8 and min_length >= 8
        
        return {
            "compliance_score": compliance_score,
            "nist_compliant": nist_compliant,
            "violations": violations,
        }
    
    def _detect_weak_patterns(self, password_samples: List[str]) -> Dict[str, Any]:
        """Detect weak password patterns (AI-based analysis)"""
        if not password_samples:
            return {
                "common_patterns": [],
                "weak_patterns_detected": [],
                "risk_level": "unknown",
            }
        
        common_patterns = []
        weak_patterns = []
        
        keyboard_rows = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]
        
        for password in password_samples:
            password_lower = password.lower()
            
            # Check for sequential patterns
            for i in range(len(password) - 2):
                seq = password_lower[i:i+3]
                if seq in "abcdefghijklmnopqrstuvwxyz" or seq in "0123456789":
                    if "sequential_chars" not in weak_patterns:
                        weak_patterns.append("sequential_chars")
                        common_patterns.append("Sequential characters (abc, 123)")
                    break
            
            # Check for keyboard patterns
            for row in keyboard_rows:
                if row in password_lower or row[::-1] in password_lower:
                    if "keyboard_patterns" not in weak_patterns:
                        weak_patterns.append("keyboard_patterns")
                        common_patterns.append("Keyboard patterns (qwerty, asdf)")
                    break
            
            # Check for common words
            common_word_list = ["password", "admin", "welcome", "123456", "qwerty"]
            if any(word in password_lower for word in common_word_list):
                if "common_words" not in weak_patterns:
                    weak_patterns.append("common_words")
                    common_patterns.append("Common dictionary words")
        
        risk_score = len(weak_patterns)
        if risk_score >= 3:
            risk_level = "High"
        elif risk_score >= 2:
            risk_level = "Medium"
        elif risk_score >= 1:
            risk_level = "Low"
        else:
            risk_level = "Minimal"
        
        return {
            "common_patterns": common_patterns,
            "weak_patterns_detected": weak_patterns,
            "risk_level": risk_level,
        }
    
    async def call_skill(self, skill_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Call PAT-MCP skill"""
        try:
            logger.info(f"PAT-MCP skill called: {skill_name}")
            
            if skill_name == "hash_type":
                hash_value = params.get("hash", "")
                if not hash_value:
                    return {"success": False, "error": "Hash value required"}
                result = self._identify_hash_type(hash_value)
                return {"success": True, **result}
            
            elif skill_name == "hash_strength":
                hash_value = params.get("hash", "")
                hash_type = params.get("hash_type", "")
                if not hash_value:
                    return {"success": False, "error": "Hash value required"}
                if not hash_type:
                    hash_info = self._identify_hash_type(hash_value)
                    hash_type = hash_info.get("hash_type", "unknown")
                result = self._benchmark_strength(hash_value, hash_type)
                return {"success": True, **result}
            
            elif skill_name == "dictionary_strength_simulation":
                hash_value = params.get("hash", "")
                dictionary_size = params.get("dictionary_size", 10000)
                if not hash_value:
                    return {"success": False, "error": "Hash value required"}
                result = self._simulate_dictionary_attack(hash_value, dictionary_size)
                return {"success": True, **result}
            
            elif skill_name == "password_policy_eval":
                policy = params.get("policy", {})
                if not policy:
                    return {"success": False, "error": "Policy dictionary required"}
                result = self._evaluate_policy(policy)
                return {"success": True, **result}
            
            elif skill_name == "ai_pattern_detector":
                password_samples = params.get("password_samples", [])
                if not password_samples:
                    return {"success": False, "error": "Password samples list required"}
                result = self._detect_weak_patterns(password_samples)
                # Add safety_metadata to all results
                result["safety_metadata"] = {
                    "operation": "read_only",
                    "password_cracking": False,
                    "brute_force": False,
                    "compliance": "defensive_analysis_only",
                }
                return {"success": True, **result}
            
            else:
                return {"success": False, "error": f"Unknown skill: {skill_name}"}
        
        except Exception as e:
            logger.error(f"Error executing PAT-MCP skill {skill_name}: {e}")
            return {"success": False, "error": f"Error executing skill: {str(e)}"}

