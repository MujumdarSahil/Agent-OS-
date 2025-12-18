"""
Hash identifier - Identify password hash types
Supports 20+ hash patterns
"""

import re
from typing import Dict, Any, Optional, List


class HashIdentifier:
    """Identify hash types from hash strings"""
    
    # Hash patterns: (name, pattern, length_range, description)
    HASH_PATTERNS = [
        ("MD5", r"^[a-f0-9]{32}$", (32, 32), "MD5 hash"),
        ("SHA1", r"^[a-f0-9]{40}$", (40, 40), "SHA-1 hash"),
        ("SHA256", r"^[a-f0-9]{64}$", (64, 64), "SHA-256 hash"),
        ("SHA512", r"^[a-f0-9]{128}$", (128, 128), "SHA-512 hash"),
        ("bcrypt", r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$", (60, 60), "bcrypt hash"),
        ("PBKDF2-SHA256", r"^\$pbkdf2-sha256\$[0-9]+\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+$", (64, 200), "PBKDF2-SHA256"),
        ("PBKDF2", r"^\$pbkdf2[^$]+\$[./A-Za-z0-9]+$", (64, 200), "PBKDF2 hash"),
        ("Argon2id", r"^\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+$", (97, 200), "Argon2id hash"),
        ("Argon2i", r"^\$argon2i\$v=\d+\$m=\d+,t=\d+,p=\d+\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+$", (97, 200), "Argon2i hash"),
        ("Argon2d", r"^\$argon2d\$v=\d+\$m=\d+,t=\d+,p=\d+\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+$", (97, 200), "Argon2d hash"),
        ("scrypt", r"^\$scrypt\$[^$]+\$[./A-Za-z0-9]+$", (64, 200), "scrypt hash"),
        ("NTLM", r"^[a-f0-9]{32}$", (32, 32), "NTLM hash (MD4-based)"),
        ("LM", r"^[a-f0-9]{32}$", (32, 32), "LM hash (weak)"),
        ("MySQL", r"^[a-f0-9]{40}$", (40, 40), "MySQL SHA1 hash"),
        ("PostgreSQL", r"^md5[a-f0-9]{32}$", (36, 36), "PostgreSQL MD5 hash"),
        ("Oracle", r"^[a-f0-9]{40}$", (40, 40), "Oracle hash"),
        ("Joomla", r"^[a-f0-9]{32}:[a-zA-Z0-9+/=]+$", (64, 200), "Joomla hash"),
        ("WordPress", r"^\$P\$[./A-Za-z0-9]{31}$", (34, 34), "WordPress hash"),
        ("Drupal", r"^\$S\$[./A-Za-z0-9]{52}$", (55, 55), "Drupal hash"),
        ("SHA-3-256", r"^[a-f0-9]{64}$", (64, 64), "SHA-3-256 hash"),
        ("SHA-3-512", r"^[a-f0-9]{128}$", (128, 128), "SHA-3-512 hash"),
        ("Blake2b", r"^[a-f0-9]{128}$", (128, 128), "Blake2b hash"),
    ]
    
    @staticmethod
    def identify(hash_value: str) -> Dict[str, Any]:
        """
        Identify hash type.
        
        Args:
            hash_value: Hash string to identify
            
        Returns:
            Identification result with hash type and confidence
        """
        if not hash_value:
            return {
                "hash_type": None,
                "confidence": 0.0,
                "description": "Empty hash",
                "possible_types": [],
            }
        
        hash_lower = hash_value.lower()
        hash_length = len(hash_value)
        
        matches = []
        
        for name, pattern, length_range, description in HashIdentifier.HASH_PATTERNS:
            min_len, max_len = length_range
            
            # Check length first
            if min_len <= hash_length <= max_len:
                # Check pattern
                if re.match(pattern, hash_value, re.IGNORECASE):
                    matches.append({
                        "hash_type": name,
                        "confidence": 1.0,
                        "description": description,
                        "length": hash_length,
                    })
        
        # If multiple matches, return the most specific
        if matches:
            # Prefer named hashes (bcrypt, PBKDF2, etc.) over generic hex
            named_matches = [m for m in matches if not m["hash_type"] in ["MD5", "SHA1", "SHA256", "SHA512"]]
            if named_matches:
                return named_matches[0]
            return matches[0]
        
        # No exact match - return possible types based on length
        possible_types = []
        for name, _, length_range, description in HashIdentifier.HASH_PATTERNS:
            min_len, max_len = length_range
            if min_len <= hash_length <= max_len:
                possible_types.append({
                    "hash_type": name,
                    "description": description,
                    "confidence": 0.5,  # Lower confidence
                })
        
        return {
            "hash_type": None,
            "confidence": 0.0,
            "description": "Unknown hash type",
            "possible_types": possible_types,
            "length": hash_length,
        }
    
    @staticmethod
    def identify_multiple(hashes: List[str]) -> List[Dict[str, Any]]:
        """
        Identify multiple hashes.
        
        Args:
            hashes: List of hash strings
            
        Returns:
            List of identification results
        """
        return [HashIdentifier.identify(h) for h in hashes]

