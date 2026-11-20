"""Password hashing and rules for 3.4 user accounts (design: docs/evidence/3.4.md, "Password hashing").

scrypt from the Python standard library (no new dependency) with OWASP parameters N=2^17, r=8, p=1, a 16-byte
random salt and a 32-byte key. The encoded form carries its parameters (``scrypt$17$8$1$<salt>$<key>``), so they
can be raised later and old hashes still verify. There is deliberately no environment variable to lower the
cost; tests monkeypatch ``LOG_N``.

Passwords are never logged, stored in plain text, or echoed in error messages.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

LOG_N = 17  # N = 2^17 (OWASP); tests may lower this module constant, production cannot
R = 8
P = 1
SALT_BYTES = 16
KEY_BYTES = 32
MAX_LOG_N = 20  # refuse to verify hashes with absurd parameters (memory exhaustion via a tampered store)
MIN_LENGTH = 12
MAX_LENGTH = 256

# A small built-in list of very common passwords (compared case-insensitively). Short ones are already refused by
# the length rule; the list keeps the longer classics out.
COMMON_PASSWORDS = frozenset({
    "123456789012", "1234567890123", "12345678901234", "123456123456", "111111111111", "000000000000",
    "qwertyuiopas", "qwertyuiop123", "qwerty123456", "qwertyqwerty", "1q2w3e4r5t6y", "1qaz2wsx3edc",
    "zaq12wsxcde3", "asdfghjkl123", "asdfasdfasdf", "zxcvbnm12345", "password1234", "password12345",
    "password123!", "passwordpassword", "password1!2@", "p@ssw0rd1234", "p@ssword1234", "passw0rd1234",
    "letmein12345", "letmeinletmein", "welcome12345", "welcome123!!", "welcomewelcome", "iloveyou1234",
    "iloveyouiloveyou", "sunshine1234", "princess1234", "football1234", "baseball1234", "superman1234",
    "batman123456", "trustno1trustno1", "dragon123456", "monkey123456", "master123456", "shadow123456",
    "michael12345", "jennifer1234", "abc123abc123", "abcdefghijkl", "abcdef123456", "aaaaaaaaaaaa",
    "changeme1234", "changemenow!", "administrator", "administrator1", "admin1234567", "adminadmin12",
    "adminpassword", "rootpassword", "rootroot1234", "default12345", "defaultpassword", "secret123456",
    "secretsecret", "test12345678", "testtesttest", "testpassword", "guest1234567", "useruser1234",
    "agentos12345", "agentosadmin", "agentos-admin", "correcthorsebatterystaple", "starwars1234",
    "computer1234", "internet1234", "whatever1234", "qwerty12345678", "1234qwerasdf", "q1w2e3r4t5y6",
    "summer2024!!", "winter2024!!", "spring2024!!", "autumn2024!!", "summer2025!!", "winter2025!!",
    "summer2026!!", "winter2026!!", "january2026!", "company12345", "letmein!2345", "hello1234567",
    "helloworld12", "hellohello12", "loveyou12345", "freedom12345", "mustang12345", "access123456",
    "pokemon12345", "liverpool123", "chelsea12345", "arsenal12345", "samsung12345", "google123456",
})


class PasswordRuleError(ValueError):
    """The password does not meet the rules (message is safe to show; it never contains the password)."""


def check_password_rules(password: str, username: str | None = None) -> None:
    if not isinstance(password, str):
        raise PasswordRuleError("Password must be text")
    if len(password) < MIN_LENGTH:
        raise PasswordRuleError(f"Password must be at least {MIN_LENGTH} characters")
    if len(password) > MAX_LENGTH:
        raise PasswordRuleError(f"Password must be at most {MAX_LENGTH} characters")
    lowered = password.lower()
    if lowered in COMMON_PASSWORDS:
        raise PasswordRuleError("Password is too common; choose another")
    if username and lowered == username.lower():
        raise PasswordRuleError("Password must not be the username")


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _derive(password: str, salt: bytes, log_n: int, r: int, p: int) -> bytes:
    n = 1 << log_n
    maxmem = 128 * r * n * p + (32 << 20)  # what scrypt needs, plus headroom
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, maxmem=maxmem, dklen=KEY_BYTES)


def hash_password(password: str) -> str:
    salt = os.urandom(SALT_BYTES)
    key = _derive(password, salt, LOG_N, R, P)
    return f"scrypt${LOG_N}${R}${P}${_b64(salt)}${_b64(key)}"


def verify_password(password: str, encoded: str) -> bool:
    """Constant-time check; False for any malformed or out-of-range hash."""
    try:
        scheme, log_n, r, p, salt, key = encoded.split("$")
        log_n_i, r_i, p_i = int(log_n), int(r), int(p)
        if scheme != "scrypt" or not (1 <= log_n_i <= MAX_LOG_N) or not (1 <= r_i <= 32) or not (1 <= p_i <= 4):
            return False
        expected = _unb64(key)
        got = _derive(password if isinstance(password, str) else "", _unb64(salt), log_n_i, r_i, p_i)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(got, expected)


def needs_rehash(encoded: str) -> bool:
    try:
        scheme, log_n, r, p, _, _ = encoded.split("$")
        return scheme != "scrypt" or (int(log_n), int(r), int(p)) < (LOG_N, R, P)
    except ValueError:
        return True
