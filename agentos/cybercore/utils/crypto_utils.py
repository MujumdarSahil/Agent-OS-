"""
Cryptographic utilities for safe hash operations
"""

import hashlib
import re
from typing import Dict, Any, Optional


class CryptoUtils:
    """Safe cryptographic utilities"""
    
    @staticmethod
    def get_hash_prefix(hash_value: str, prefix_length: int = 5) -> str:
        """
        Get hash prefix for k-anonymity (safe submission).
        
        Args:
            hash_value: Full hash
            prefix_length: Length of prefix (default 5 for k-anonymity)
            
        Returns:
            Hash prefix
        """
        if not hash_value:
            return ""
        
        # Ensure minimum length
        if prefix_length < 5:
            prefix_length = 5
        
        return hash_value.lower()[:prefix_length]
    
    @staticmethod
    def normalize_hash(hash_value: str) -> str:
        """
        Normalize hash to lowercase, remove whitespace.
        
        Args:
            hash_value: Hash to normalize
            
        Returns:
            Normalized hash
        """
        if not hash_value:
            return ""
        
        # Remove whitespace and convert to lowercase
        normalized = re.sub(r"\s+", "", hash_value).lower()
        
        return normalized
    
    @staticmethod
    def validate_hash_format(hash_value: str) -> Dict[str, Any]:
        """
        Validate hash format without revealing full hash.
        
        Args:
            hash_value: Hash to validate
            
        Returns:
            Validation result
        """
        if not hash_value:
            return {
                "valid": False,
                "reason": "Empty hash",
            }
        
        normalized = CryptoUtils.normalize_hash(hash_value)
        
        # Check length
        if len(normalized) < 16:
            return {
                "valid": False,
                "reason": "Hash too short",
            }
        
        # Check if hexadecimal
        if not re.match(r"^[a-f0-9]+$", normalized):
            return {
                "valid": False,
                "reason": "Invalid characters (not hexadecimal)",
            }
        
        return {
            "valid": True,
            "length": len(normalized),
        }
    
    @staticmethod
    def compute_sha1(text: str) -> str:
        """
        Compute SHA-1 hash (for k-anonymity breach checks).
        
        Args:
            text: Text to hash
            
        Returns:
            SHA-1 hash
        """
        return hashlib.sha1(text.encode()).hexdigest()
    
    @staticmethod
    def compute_sha256(text: str) -> str:
        """
        Compute SHA-256 hash.
        
        Args:
            text: Text to hash
            
        Returns:
            SHA-256 hash
        """
        return hashlib.sha256(text.encode()).hexdigest()
    
    @staticmethod
    def truncate_for_k_anonymity(hash_value: str, k: int = 5) -> str:
        """
        Truncate hash for k-anonymity (safe for external APIs).
        
        Args:
            hash_value: Full hash
            k: Number of prefix characters (default 5)
            
        Returns:
            Truncated hash prefix
        """
        normalized = CryptoUtils.normalize_hash(hash_value)
        return normalized[:max(k, 5)]  # Minimum 5 characters

