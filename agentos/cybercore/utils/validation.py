"""
Validation utilities for cybersecurity operations
"""

import re
from typing import Dict, Any, Optional, List


class HashValidator:
    """Validate and check hash safety rules"""
    
    # Common hash length patterns
    HASH_PATTERNS = {
        "md5": (32, 32, r"^[a-f0-9]{32}$", "MD5"),
        "sha1": (40, 40, r"^[a-f0-9]{40}$", "SHA-1"),
        "sha256": (64, 64, r"^[a-f0-9]{64}$", "SHA-256"),
        "sha512": (128, 128, r"^[a-f0-9]{128}$", "SHA-512"),
        "bcrypt": (60, 60, r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$", "bcrypt"),
        "pbkdf2": (64, 200, r"^\$pbkdf2[^$]+\$[./A-Za-z0-9]+$", "PBKDF2"),
        "argon2id": (97, 200, r"^\$argon2id\$[^$]+\$[./A-Za-z0-9]+$", "Argon2id"),
    }
    
    @staticmethod
    def is_valid_hash(hash_value: str) -> bool:
        """
        Check if a string is a valid hash format.
        
        Args:
            hash_value: Hash string to validate
            
        Returns:
            True if valid hash format
        """
        if not hash_value or not isinstance(hash_value, str):
            return False
        
        hash_lower = hash_value.lower()
        
        # Check against known patterns
        for hash_type, (min_len, max_len, pattern, _) in HashValidator.HASH_PATTERNS.items():
            if min_len <= len(hash_value) <= max_len:
                if re.match(pattern, hash_value, re.IGNORECASE):
                    return True
        
        return False
    
    @staticmethod
    def is_safe_for_submission(hash_value: str) -> Dict[str, Any]:
        """
        Check if hash is safe to submit (not cleartext).
        
        Args:
            hash_value: Hash to check
            
        Returns:
            Dict with safety status and reason
        """
        if not hash_value:
            return {
                "safe": False,
                "reason": "Empty hash value",
            }
        
        # Check if it looks like cleartext (too short, contains spaces, etc.)
        if len(hash_value) < 16:
            return {
                "safe": False,
                "reason": "Hash too short - may be cleartext",
            }
        
        if " " in hash_value or "\n" in hash_value:
            return {
                "safe": False,
                "reason": "Hash contains whitespace - may be cleartext",
            }
        
        # Check if it's a valid hash format
        if not HashValidator.is_valid_hash(hash_value):
            # Still might be safe if it's long enough
            if len(hash_value) >= 32:
                return {
                    "safe": True,
                    "reason": "Long hash-like string",
                }
            else:
                return {
                    "safe": False,
                    "reason": "Does not match known hash patterns",
                }
        
        return {
            "safe": True,
            "reason": "Valid hash format",
        }
    
    @staticmethod
    def validate_hash_prefix(prefix: str, min_length: int = 5) -> bool:
        """
        Validate hash prefix for k-anonymity.
        
        Args:
            prefix: Hash prefix
            min_length: Minimum prefix length
            
        Returns:
            True if valid prefix
        """
        if not prefix or len(prefix) < min_length:
            return False
        
        # Should be hexadecimal
        return bool(re.match(r"^[a-f0-9]+$", prefix.lower()))


class PolicyValidator:
    """Validate security policies"""
    
    @staticmethod
    def validate_password_policy(policy: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate password policy against NIST 800-63 guidelines.
        
        Args:
            policy: Policy configuration
            
        Returns:
            Validation result with recommendations
        """
        issues = []
        recommendations = []
        
        min_length = policy.get("min_length", 8)
        if min_length < 12:
            issues.append("Minimum length below NIST recommendation (12)")
            recommendations.append("Increase minimum length to at least 12 characters")
        
        if not policy.get("require_uppercase", False):
            recommendations.append("Consider requiring uppercase letters")
        
        if not policy.get("require_lowercase", False):
            recommendations.append("Consider requiring lowercase letters")
        
        if not policy.get("require_numbers", False):
            recommendations.append("Consider requiring numbers")
        
        if not policy.get("require_special", False):
            recommendations.append("Consider requiring special characters")
        
        # Check for common weak patterns
        if policy.get("allow_common_passwords", True):
            recommendations.append("Consider blocking common passwords")
        
        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "recommendations": recommendations,
            "nist_compliant": min_length >= 12 and len(issues) == 0,
        }


class InputValidator:
    """General input validation"""
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Validate IP address format"""
        pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        return bool(re.match(pattern, ip))
    
    @staticmethod
    def validate_domain(domain: str) -> bool:
        """Validate domain name format"""
        pattern = r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
        return bool(re.match(pattern, domain.lower()))
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate URL format"""
        pattern = r"^https?://[^\s/$.?#].[^\s]*$"
        return bool(re.match(pattern, url.lower()))
    
    @staticmethod
    def sanitize_input(value: str, max_length: int = 1000) -> str:
        """
        Sanitize input string.
        
        Args:
            value: Input value
            max_length: Maximum length
            
        Returns:
            Sanitized value
        """
        if not value:
            return ""
        
        # Truncate if too long
        if len(value) > max_length:
            value = value[:max_length]
        
        # Remove null bytes
        value = value.replace("\x00", "")
        
        # Remove control characters (except newline and tab)
        value = re.sub(r"[\x00-\x08\x0b-\x0c\x0e-\x1f]", "", value)
        
        return value

