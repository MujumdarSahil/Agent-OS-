"""Login rate limit with exponential backoff (3.4), per IP + username and per IP.

After ``FREE_FAILURES`` failures for a key, the next attempt must wait 1 s, 2 s, 4 s, ... up to ``MAX_BACKOFF_S``.
A success clears the IP + username key (not the IP key: one good password must not unlock guessing others).
In memory, per process (documented gap for multi-process Platform mode). Keys idle for an hour are dropped and the
table is bounded, so it cannot grow without limit.
"""

from __future__ import annotations

import time
from typing import Callable

FREE_FAILURES = 5          # per IP + username
FREE_FAILURES_PER_IP = 20  # per IP, across usernames
MAX_BACKOFF_S = 900.0      # 15 min
IDLE_FORGET_S = 3600.0
MAX_KEYS = 10_000


class LoginLimiter:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._fails: dict[str, tuple[int, float]] = {}  # key -> (failures, last failure time)

    @staticmethod
    def _keys(ip: str, username: str) -> tuple[str, str]:
        return f"u:{ip}|{(username or '').strip().lower()[:128]}", f"i:{ip}"

    def _wait(self, key: str, free: int, now: float) -> float:
        n, last = self._fails.get(key, (0, 0.0))
        if n < free:
            return 0.0
        backoff = min(MAX_BACKOFF_S, 2.0 ** (n - free))
        return max(0.0, last + backoff - now)

    def retry_after(self, ip: str, username: str) -> float:
        """Seconds to wait before another attempt is allowed (0 = allowed now)."""
        now = self._clock()
        ku, ki = self._keys(ip, username)
        return max(self._wait(ku, FREE_FAILURES, now), self._wait(ki, FREE_FAILURES_PER_IP, now))

    def failure(self, ip: str, username: str) -> None:
        now = self._clock()
        self._prune(now)
        for key in self._keys(ip, username):
            n, _ = self._fails.get(key, (0, 0.0))
            self._fails[key] = (n + 1, now)

    def success(self, ip: str, username: str) -> None:
        self._fails.pop(self._keys(ip, username)[0], None)

    def _prune(self, now: float) -> None:
        if len(self._fails) < MAX_KEYS // 2:
            return
        for key, (_, last) in list(self._fails.items()):
            if now - last > IDLE_FORGET_S:
                del self._fails[key]
        while len(self._fails) >= MAX_KEYS:  # still full: drop the oldest
            del self._fails[min(self._fails, key=lambda k: self._fails[k][1])]
