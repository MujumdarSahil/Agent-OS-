"""
Normalization routines and dedupe key generation for job opportunities.
"""

from __future__ import annotations

import hashlib
import re

LEGAL_SUFFIXES_REGEX = re.compile(
    r"\b(private\s+limited|pvt\s+ltd|private\s+ltd|pvt\s+limited|pvt|inc|ltd|llc|corp|corporation|gmbh|plc|limited)\b",
    re.IGNORECASE,
)

CITY_ALIASES = {
    r"\bbangalore\b": "bengaluru",
    r"\bbombay\b": "mumbai",
    r"\bcalcutta\b": "kolkata",
    r"\bmadras\b": "chennai",
}


def normalize_company(name: str) -> str:
    """
    Normalizes company names:
    - casefold
    - strip legal entity suffixes (inc, ltd, llc, pvt, private limited, etc.)
    - remove punctuation
    - collapse whitespace
    """
    if not name:
        return ""

    s = name.casefold()
    # Replace punctuation with spaces
    s = re.sub(r"[^\w\s]", " ", s)
    # Strip legal suffixes
    s = LEGAL_SUFFIXES_REGEX.sub(" ", s)
    # Collapse whitespace
    cleaned = re.sub(r"\s+", " ", s).strip()
    return cleaned if cleaned else name.casefold().strip()


def normalize_title(title: str) -> str:
    """
    Normalizes job titles:
    - casefold
    - remove punctuation
    - collapse whitespace
    """
    if not title:
        return ""

    s = title.casefold()
    s = re.sub(r"[^\w\s]", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def normalize_location(location: str) -> str:
    """
    Normalizes job locations:
    - casefold
    - canonicalize remote variants ('remote - india', 'india (remote)', 'remote, india' -> 'remote - india')
    - map city aliases ('bangalore' -> 'bengaluru', 'bombay' -> 'mumbai')
    - collapse whitespace
    """
    if not location:
        return ""

    s = location.casefold().strip()
    words = re.findall(r"\w+", s)
    word_set = set(words)

    # Check for remote location patterns
    if "remote" in word_set:
        other_words = [w for w in words if w != "remote"]
        if not other_words:
            return "remote"
        if "india" in word_set:
            return "remote - india"
        if "us" in word_set or "usa" in word_set or ("united" in word_set and "states" in word_set):
            return "remote - us"
        if "uk" in word_set or ("united" in word_set and "kingdom" in word_set):
            return "remote - uk"
        if "emea" in word_set:
            return "remote - emea"
        if "apac" in word_set:
            return "remote - apac"
        return f"remote - {' '.join(other_words)}"

    # City alias replacements
    cleaned = re.sub(r"[^\w\s]", " ", s)
    for pattern, replacement in CITY_ALIASES.items():
        cleaned = re.sub(pattern, replacement, cleaned)

    return re.sub(r"\s+", " ", cleaned).strip()


def compute_dedupe_key(company: str, title: str, location: str) -> str:
    """
    Computes a canonical SHA-256 deduplication key from company, title, and location.
    """
    norm_comp = normalize_company(company)
    norm_title = normalize_title(title)
    norm_loc = normalize_location(location)
    raw = f"{norm_comp}|{norm_title}|{norm_loc}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
