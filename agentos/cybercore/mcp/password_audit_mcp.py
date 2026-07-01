"""
Password Audit MCP - Safe password policy auditing
NO password cracking - only policy evaluation and breach checks
"""

from typing import Dict, Any
from agentos.mcp_connectors.base_mcp import BaseMCPConnector
from agentos.cybercore.tools.hash_identifier import HashIdentifier
from agentos.cybercore.tools.password_entropy_estimator import PasswordEntropyEstimator
from agentos.cybercore.tools.breach_check_k_anonymity import BreachCheckKAnonymity
from agentos.cybercore.utils.validation import HashValidator, PolicyValidator


class PasswordAuditMCP(BaseMCPConnector):
    """
    Password Audit MCP - Safe password policy auditing.
    Identifies hash types, estimates entropy, performs breach checks using k-anonymity.
    NO password cracking or brute-force.
    """
    
    def __init__(self, endpoint: str = "password://audit"):
        super().__init__(endpoint, "password_audit_mcp", "password_audit")
        self.skills = [
            {
                "id": "identify_hash",
                "name": "identify_hash",
                "description": "Identify password hash type",
                "type": "tool",
                "inputs": {"hash": "string"},
                "outputs": {"hash_type": "string", "confidence": "float"},
                "latency_estimate": 0.1,
                "accuracy_estimate": 0.95,
                "data_sensitivity": "confidential",
                "cost_estimate": {"cost": 0.01},
            },
            {
                "id": "estimate_entropy",
                "name": "estimate_entropy",
                "description": "Estimate password entropy (mathematical only)",
                "type": "tool",
                "inputs": {"password": "string"},
                "outputs": {"entropy_bits": "float", "strength": "string"},
                "latency_estimate": 0.1,
                "accuracy_estimate": 0.9,
                "data_sensitivity": "confidential",
                "cost_estimate": {"cost": 0.01},
            },
            {
                "id": "check_breach",
                "name": "check_breach",
                "description": "Check password breach using k-anonymity (safe)",
                "type": "tool",
                "inputs": {"hash_prefix": "string"},
                "outputs": {"breached": "bool", "count": "int"},
                "latency_estimate": 1.0,
                "accuracy_estimate": 0.9,
                "data_sensitivity": "public",
                "cost_estimate": {"cost": 0.05},
            },
            {
                "id": "evaluate_policy",
                "name": "evaluate_policy",
                "description": "Evaluate password policy against NIST 800-63",
                "type": "tool",
                "inputs": {"policy": "dict", "password_hashes": "list"},
                "outputs": {"compliance_score": "float", "violations": "list"},
                "latency_estimate": 2.0,
                "accuracy_estimate": 0.95,
                "data_sensitivity": "confidential",
                "cost_estimate": {"cost": 0.1},
            },
        ]
    
    async def connect(self) -> bool:
        """Connect to password audit service"""
        self.status = "active"
        return True
    
    async def disconnect(self):
        """Disconnect"""
        self.status = "inactive"
    
    async def call_skill(self, skill_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Call password audit skill"""
        if skill_name == "identify_hash":
            hash_value = params.get("hash", "")
            
            # Safety check
            safety = HashValidator.is_safe_for_submission(hash_value)
            if not safety["safe"]:
                return {
                    "success": False,
                    "error": f"Hash validation failed: {safety['reason']}",
                }
            
            # Identify hash
            result = HashIdentifier.identify(hash_value)
            
            return {
                "success": True,
                "hash_type": result.get("hash_type"),
                "confidence": result.get("confidence", 0.0),
                "description": result.get("description"),
                "possible_types": result.get("possible_types", []),
            }
        
        elif skill_name == "estimate_entropy":
            password = params.get("password", "")
            
            # Estimate entropy
            entropy_result = PasswordEntropyEstimator.calculate_entropy(password)
            crack_time = PasswordEntropyEstimator.estimate_crack_time(entropy_result["entropy_bits"])
            
            return {
                "success": True,
                "entropy_bits": entropy_result["entropy_bits"],
                "strength": entropy_result["strength"],
                "estimated_crack_time": crack_time["readable"],
                "character_set_size": entropy_result["character_set_size"],
            }
        
        elif skill_name == "check_breach":
            hash_prefix = params.get("hash_prefix", "")
            
            # Validate prefix
            validation = BreachCheckKAnonymity.validate_prefix(hash_prefix)
            if not validation["valid"]:
                return {
                    "success": False,
                    "error": validation.get("reason", "Invalid prefix"),
                }
            
            # Check breach
            result = BreachCheckKAnonymity.check_breach(hash_prefix)
            
            return result
        
        elif skill_name == "evaluate_policy":
            policy = params.get("policy", {})
            password_hashes = params.get("password_hashes", [])
            
            # Safety: verify all are hashes
            for pwd_hash in password_hashes:
                safety = HashValidator.is_safe_for_submission(pwd_hash)
                if not safety["safe"]:
                    return {
                        "success": False,
                        "error": f"Invalid hash in list: {safety['reason']}",
                    }
            
            # Validate policy
            policy_validation = PolicyValidator.validate_password_policy(policy)
            
            # Analyze policy
            policy_analysis = PasswordEntropyEstimator.analyze_password_policy(policy)
            
            # Identify hash types
            hash_types = []
            for pwd_hash in password_hashes[:10]:  # Limit to avoid quota
                hash_id = HashIdentifier.identify(pwd_hash)
                hash_types.append(hash_id.get("hash_type", "unknown"))
            
            return {
                "success": True,
                "compliance_score": 1.0 if policy_validation["nist_compliant"] else 0.7,
                "violations": policy_validation["issues"],
                "recommendations": policy_validation["recommendations"],
                "policy_strength": policy_analysis["policy_strength"],
                "min_entropy_bits": policy_analysis["min_entropy_bits"],
                "hash_types_found": list(set(hash_types)),
            }
        
        return {"success": False, "error": f"Unknown skill: {skill_name}"}

