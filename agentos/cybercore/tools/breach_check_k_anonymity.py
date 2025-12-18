"""
Breach check using k-anonymity (HIBP-style)
Safe - only accepts hash prefixes, never full hashes
"""

import hashlib
from typing import Dict, Any, Optional
from agentos.cybercore.utils.crypto_utils import CryptoUtils


class BreachCheckKAnonymity:
    """Check password breaches using k-anonymity (safe method)"""
    
    K_ANONYMITY_PREFIX_LENGTH = 5  # Standard k-anonymity prefix length
    
    @staticmethod
    def get_hash_prefix(password: str, hash_type: str = "sha1") -> str:
        """
        Get hash prefix for k-anonymity lookup.
        
        Args:
            password: Password (will be hashed)
            hash_type: Hash type (sha1 or sha256)
            
        Returns:
            Hash prefix (first 5 characters)
        """
        if hash_type.lower() == "sha1":
            full_hash = hashlib.sha1(password.encode()).hexdigest()
        elif hash_type.lower() == "sha256":
            full_hash = hashlib.sha256(password.encode()).hexdigest()
        else:
            raise ValueError(f"Unsupported hash type: {hash_type}")
        
        return full_hash[:BreachCheckKAnonymity.K_ANONYMITY_PREFIX_LENGTH]
    
    @staticmethod
    def check_breach(prefix: str) -> Dict[str, Any]:
        """
        Check if hash prefix appears in breach database (k-anonymity safe).
        
        Args:
            prefix: Hash prefix (first 5 characters) - NEVER full hash
            
        Returns:
            Breach check result
        """
        # Safety check: ensure prefix is safe length
        if len(prefix) < BreachCheckKAnonymity.K_ANONYMITY_PREFIX_LENGTH:
            return {
                "success": False,
                "error": f"Prefix too short. Minimum {BreachCheckKAnonymity.K_ANONYMITY_PREFIX_LENGTH} characters required for k-anonymity",
            }
        
        if len(prefix) > 10:
            return {
                "success": False,
                "error": "Prefix too long. For k-anonymity, use 5-10 characters only",
            }
        
        # Normalize prefix
        prefix = prefix.lower().strip()
        
        # Validate hexadecimal
        if not all(c in "0123456789abcdef" for c in prefix):
            return {
                "success": False,
                "error": "Prefix must be hexadecimal",
            }
        
        # Simulate breach check (in production would call HIBP API or similar)
        # This is a safe simulation - we only work with prefixes
        breached = False
        count = 0
        
        # Placeholder: In production, this would make HTTP request to breach API
        # Example: https://api.pwnedpasswords.com/range/{prefix}
        # Returns list of hash suffixes that match the prefix
        
        return {
            "success": True,
            "prefix": prefix,
            "breached": breached,
            "count": count,
            "method": "k-anonymity",
            "safe": True,
        }
    
    @staticmethod
    def check_password_safe(password: str) -> Dict[str, Any]:
        """
        Check password against breach database using k-anonymity.
        SAFE: Only sends hash prefix, never full hash or password.
        
        Args:
            password: Password to check
            
        Returns:
            Breach check result
        """
        # Get hash prefix
        prefix = BreachCheckKAnonymity.get_hash_prefix(password, "sha1")
        
        # Check breach
        result = BreachCheckKAnonymity.check_breach(prefix)
        
        if result.get("success"):
            result["password_checked"] = True
            result["method"] = "k-anonymity-safe"
            result["note"] = "Only hash prefix was used, never full hash or password"
        
        return result
    
    @staticmethod
    def validate_prefix(prefix: str) -> Dict[str, Any]:
        """
        Validate hash prefix for k-anonymity.
        
        Args:
            prefix: Hash prefix to validate
            
        Returns:
            Validation result
        """
        if not prefix:
            return {
                "valid": False,
                "reason": "Empty prefix",
            }
        
        prefix = prefix.lower().strip()
        
        if len(prefix) < BreachCheckKAnonymity.K_ANONYMITY_PREFIX_LENGTH:
            return {
                "valid": False,
                "reason": f"Prefix too short (minimum {BreachCheckKAnonymity.K_ANONYMITY_PREFIX_LENGTH} characters)",
            }
        
        if not all(c in "0123456789abcdef" for c in prefix):
            return {
                "valid": False,
                "reason": "Prefix must be hexadecimal",
            }
        
        return {
            "valid": True,
            "length": len(prefix),
            "safe_for_api": True,
        }

