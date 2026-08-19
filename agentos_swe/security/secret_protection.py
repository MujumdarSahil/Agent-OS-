"""
SecretProtection - Secret redaction and credential protection for prompts, logs, patches, and PR descriptions (M6).
"""

import os
import re
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

SECRET_PATTERNS = [
    (re.compile(r"(ghp_[A-Za-z0-9_]{20,}|gho_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"(Bearer\s+)[A-Za-z0-9_\-\.]+", re.IGNORECASE), r"\1[REDACTED_BEARER_TOKEN]"),
    (re.compile(r"(token\s*=\s*['\"]?)[A-Za-z0-9_\-\.]+(repr|['\"]?)", re.IGNORECASE), r"\1[REDACTED_TOKEN]\2"),
    (re.compile(r"(password\s*=\s*['\"]?)[^\s'\"]+(['\"]?)", re.IGNORECASE), r"\1[REDACTED_PASSWORD]\2"),
    (re.compile(r"(secret\s*=\s*['\"]?)[^\s'\"]+(['\"]?)", re.IGNORECASE), r"\1[REDACTED_SECRET]\2"),
    (re.compile(r"(api_key\s*=\s*['\"]?)[^\s'\"]+(['\"]?)", re.IGNORECASE), r"\1[REDACTED_API_KEY]\2"),
    (re.compile(r"(sk-[A-Za-z0-9\-_]{20,})"), "[REDACTED_API_KEY]"),
]


class SecretProtection:
    """
    Sanitizes environment variables, prompts, patches, PR bodies, and logs.
    """

    @staticmethod
    def sanitize_text(text: str) -> str:
        if not text or not isinstance(text, str):
            return text

        sanitized = text
        for pattern, replacement in SECRET_PATTERNS:
            sanitized = pattern.sub(replacement, sanitized)

        return sanitized

    @staticmethod
    def sanitize_env(env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """
        Creates a clean environment dictionary stripping host API keys and tokens.
        """
        target_env = env.copy() if env else os.environ.copy()
        clean_env = {}

        sensitive_keys = {"key", "secret", "password", "token", "auth", "credential", "private", "passwd"}

        for k, v in target_env.items():
            k_lower = k.lower()
            if any(s in k_lower for s in sensitive_keys):
                continue
            clean_env[k] = v

        return clean_env
