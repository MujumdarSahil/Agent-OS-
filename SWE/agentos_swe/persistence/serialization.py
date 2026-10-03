"""
M28 Serialization & Secret Protection Module.

Provides safe JSON serialization, schema versioning, secret sanitization,
and fault-tolerant dictionary reconstruction for persistent operational state.
"""

import json
import logging
from typing import Dict, Any, Optional
from agentos_swe.security.secret_protection import SecretProtection

logger = logging.getLogger(__name__)

CURRENT_SCHEMA_VERSION = "1.0"


class PersistenceSerializer:
    """
    Handles safe serialization and deserialization of persistent records
    with secret sanitization and schema migration fallback.
    """

    @staticmethod
    def serialize(data: Dict[str, Any]) -> str:
        """
        Serializes dict to JSON string after redacting sensitive tokens/passwords.
        """
        try:
            sanitized_dict = PersistenceSerializer._sanitize_dict(data)
            sanitized_dict["_schema_version"] = CURRENT_SCHEMA_VERSION
            return json.dumps(sanitized_dict, default=str)
        except Exception as e:
            logger.error(f"Failed to serialize record: {e}")
            return json.dumps({"_schema_version": CURRENT_SCHEMA_VERSION, "error": "SERIALIZATION_FAILURE"})

    @staticmethod
    def deserialize(json_str: str) -> Dict[str, Any]:
        """
        Deserializes JSON string to dict safely.
        Returns a fallback empty schema dict on corrupt JSON.
        """
        if not json_str:
            return {"_schema_version": CURRENT_SCHEMA_VERSION}

        try:
            parsed = json.loads(json_str)
            if not isinstance(parsed, dict):
                return {"_schema_version": CURRENT_SCHEMA_VERSION}
            return parsed
        except Exception as e:
            logger.warning(f"Corrupted or invalid JSON record encountered: {e}")
            return {"_schema_version": CURRENT_SCHEMA_VERSION, "_corrupted": True}

    @staticmethod
    def _sanitize_dict(data: Any) -> Any:
        """Recursively redacts secrets from dict keys and string values."""
        if isinstance(data, dict):
            sanitized = {}
            for k, v in data.items():
                if any(sec in str(k).lower() for sec in ["token", "password", "secret", "api_key", "auth"]):
                    sanitized[k] = "[REDACTED_SECRET]"
                else:
                    sanitized[k] = PersistenceSerializer._sanitize_dict(v)
            return sanitized
        elif isinstance(data, list):
            return [PersistenceSerializer._sanitize_dict(item) for item in data]
        elif isinstance(data, str):
            return SecretProtection.sanitize_text(data)
        return data
