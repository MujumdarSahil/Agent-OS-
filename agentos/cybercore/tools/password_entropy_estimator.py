"""
Password entropy estimator - Calculate entropy bits and estimate guess complexity
Safe, mathematical only - NO actual cracking
"""

import math
import re
from typing import Dict, Any


class PasswordEntropyEstimator:
    """Estimate password entropy and cracking time"""
    
    @staticmethod
    def calculate_entropy(password: str) -> Dict[str, Any]:
        """
        Calculate password entropy (mathematical estimation only).
        
        Args:
            password: Password to analyze (for estimation purposes)
            
        Returns:
            Entropy analysis
        """
        if not password:
            return {
                "entropy_bits": 0.0,
                "character_set_size": 0,
                "length": 0,
                "strength": "very_weak",
            }
        
        length = len(password)
        
        # Determine character set
        has_lower = bool(re.search(r"[a-z]", password))
        has_upper = bool(re.search(r"[A-Z]", password))
        has_digits = bool(re.search(r"[0-9]", password))
        has_special = bool(re.search(r"[^a-zA-Z0-9]", password))
        
        # Calculate character set size
        charset_size = 0
        if has_lower:
            charset_size += 26
        if has_upper:
            charset_size += 26
        if has_digits:
            charset_size += 10
        if has_special:
            charset_size += 32  # Common special characters
        
        # Calculate entropy: log2(charset_size^length)
        if charset_size > 0:
            entropy_bits = length * math.log2(charset_size)
        else:
            entropy_bits = 0.0
        
        # Determine strength
        if entropy_bits < 28:
            strength = "very_weak"
        elif entropy_bits < 36:
            strength = "weak"
        elif entropy_bits < 60:
            strength = "moderate"
        elif entropy_bits < 80:
            strength = "strong"
        else:
            strength = "very_strong"
        
        return {
            "entropy_bits": round(entropy_bits, 2),
            "character_set_size": charset_size,
            "length": length,
            "has_lower": has_lower,
            "has_upper": has_upper,
            "has_digits": has_digits,
            "has_special": has_special,
            "strength": strength,
        }
    
    @staticmethod
    def estimate_crack_time(entropy_bits: float, guesses_per_second: float = 1e9) -> Dict[str, Any]:
        """
        Estimate time to crack password (mathematical simulation only).
        
        Args:
            entropy_bits: Entropy in bits
            guesses_per_second: Guesses per second (default 1 billion)
            
        Returns:
            Time estimation
        """
        if entropy_bits <= 0:
            return {
                "seconds": 0,
                "minutes": 0,
                "hours": 0,
                "days": 0,
                "years": 0,
                "readable": "Instant",
            }
        
        # Calculate total possible combinations
        total_combinations = 2 ** entropy_bits
        
        # Calculate time in seconds
        seconds = total_combinations / guesses_per_second
        
        # Convert to readable format
        minutes = seconds / 60
        hours = minutes / 60
        days = hours / 24
        years = days / 365.25
        
        # Format readable string
        if years >= 1:
            readable = f"{years:.2e} years"
        elif days >= 1:
            readable = f"{days:.2e} days"
        elif hours >= 1:
            readable = f"{hours:.2e} hours"
        elif minutes >= 1:
            readable = f"{minutes:.2e} minutes"
        else:
            readable = f"{seconds:.2e} seconds"
        
        return {
            "seconds": seconds,
            "minutes": minutes,
            "hours": hours,
            "days": days,
            "years": years,
            "readable": readable,
            "total_combinations": total_combinations,
            "guesses_per_second": guesses_per_second,
        }
    
    @staticmethod
    def analyze_password_policy(policy: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze password policy and estimate minimum entropy.
        
        Args:
            policy: Password policy configuration
            
        Returns:
            Policy analysis with entropy estimates
        """
        min_length = policy.get("min_length", 8)
        require_uppercase = policy.get("require_uppercase", False)
        require_lowercase = policy.get("require_lowercase", False)
        require_digits = policy.get("require_digits", False)
        require_special = policy.get("require_special", False)
        
        # Calculate minimum character set
        charset_size = 0
        if require_lowercase:
            charset_size += 26
        if require_uppercase:
            charset_size += 26
        if require_digits:
            charset_size += 10
        if require_special:
            charset_size += 32
        
        # If no requirements, assume lowercase only
        if charset_size == 0:
            charset_size = 26
        
        # Calculate minimum entropy
        min_entropy = min_length * math.log2(charset_size)
        
        # Estimate crack time
        crack_time = PasswordEntropyEstimator.estimate_crack_time(min_entropy)
        
        return {
            "min_length": min_length,
            "min_entropy_bits": round(min_entropy, 2),
            "character_set_size": charset_size,
            "estimated_crack_time": crack_time,
            "policy_strength": "strong" if min_entropy >= 60 else "moderate" if min_entropy >= 36 else "weak",
        }

