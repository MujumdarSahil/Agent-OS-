"""
Nonce / replay cache for webhook signatures.

Provides:
- InMemoryNonceCache for Standalone mode (with documented limitation: resets on restart).
- RedisNonceCache for Platform mode (shared across servers, persistent across restarts).
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, Optional, Protocol, runtime_checkable


@runtime_checkable
class NonceCache(Protocol):
    """Protocol for checking and registering request nonces / signatures."""

    async def check_and_set(self, key: str, ttl_s: int = 300) -> bool:
        """
        Check if the nonce/signature has been seen within the TTL window.
        Returns:
            True if key is fresh (not seen before, and now registered).
            False if key was already seen within the window (replay detected).
        """
        ...


class InMemoryNonceCache(NonceCache):
    """
    In-process nonce cache for standalone execution.

    Limitation:
        Resets on server restart. In Standalone mode, restarting the process clears
        the memory cache, allowing previously seen signatures within the 5-minute
        window to be re-evaluated if their timestamp remains valid.
        Use RedisNonceCache in production / Platform mode for persistent cross-restart
        and multi-server replay protection.
    """

    def __init__(self) -> None:
        self._seen: Dict[str, float] = {}  # key -> expiry timestamp (monotonic)
        self._lock = asyncio.Lock()

    async def check_and_set(self, key: str, ttl_s: int = 300) -> bool:
        async with self._lock:
            now = time.monotonic()
            # Prune expired keys
            expired = [k for k, exp in self._seen.items() if exp <= now]
            for k in expired:
                del self._seen[k]

            if key in self._seen and self._seen[key] > now:
                return False  # Replay detected

            self._seen[key] = now + float(ttl_s)
            return True


class RedisNonceCache(NonceCache):
    """
    Distributed Redis-backed nonce cache for Platform mode.
    Shared across multiple server instances and persistent across restarts.
    """

    def __init__(self, redis_client: Any) -> None:
        self._redis = redis_client

    async def check_and_set(self, key: str, ttl_s: int = 300) -> bool:
        redis_key = f"nonce:{key}"
        # SET key value EX ttl NX -> returns True only if key did not exist
        res = await self._redis.set(redis_key, "1", ex=ttl_s, nx=True)
        return bool(res)
