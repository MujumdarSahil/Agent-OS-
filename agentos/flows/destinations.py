"""4.1b Part 0: one shared check for every destination (email recipient, Slack channel, http host, allowlist entry).

AWIB (4.1) found that ``support@corp.lоcal`` (Cyrillic "о") looks identical to the real address on an approval card.
Every recipient/host check in AgentOS goes through this module:

- normalise to NFKC (full-width "ｃｏｒｐ" becomes "corp", which itself is a warning: the raw text was not plain);
- IDN domains are converted to punycode (the ``idna`` package if installed, else the stdlib codec);
- mixed scripts inside one label (Latin + Cyrillic, ...) and whole-label look-alikes (a Cyrillic-only label made only
  of letters that look Latin, e.g. "аре") are CONFUSABLE;
- a domain is internal / allowlisted only on an EXACT match after normalisation, and never when it is confusable.

A legitimate single-script non-English address (``josé@ejemplo.es``, ``用户@例子.中国``) is NOT confusable: it stays
deliverable, but it is non-ASCII, so cards show a warning and its ASCII form.

Built-in table only (Latin / Cyrillic / Greek letters that look Latin); not the full Unicode confusables data.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from typing import Any, Iterable

# Cyrillic and Greek letters that render like Latin letters (lower case; inputs are case-folded first).
CONFUSABLES: dict[str, str] = {
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "ё": "e", "һ": "h", "і": "i", "ї": "i", "ј": "j", "к": "k", "м": "m", "н": "h",
    "о": "o", "р": "p", "с": "c", "т": "t", "у": "y", "х": "x", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ӏ": "l",
    "ь": "b", "п": "n", "г": "r", "ц": "u", "ш": "w",
    # Greek
    "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u",
    "χ": "x", "γ": "y", "ω": "w", "μ": "u", "ϲ": "c", "ϳ": "j",
}
_COMMON = set("0123456789-._@+~!#$%&'*/=?^`{|}")


def _script(ch: str) -> str:
    if ch.isascii():
        return "LATIN" if ch.isalpha() else "COMMON"
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return "UNKNOWN"
    first = name.split(" ", 1)[0]
    if first in ("CJK", "HIRAGANA", "KATAKANA", "IDEOGRAPHIC"):
        return "HAN"  # one writing system for this check (Japanese mixes them legitimately)
    if first in ("COMBINING", "ZERO"):
        return "COMMON"
    return first


def _escape(s: str) -> str:
    return "".join(c if c.isascii() else f"\\u{ord(c):04x}" for c in s)


def _punycode_label(label: str) -> str:
    if label.isascii():
        return label
    try:
        import idna  # IDNA 2008 (transitive dependency of requests)

        return idna.encode(label, uts46=False).decode("ascii")
    except Exception:
        try:
            return label.encode("idna").decode("ascii")
        except Exception:
            return "xn--?" + _escape(label)


def _from_punycode(label: str) -> str:
    if not label.startswith("xn--"):
        return label
    try:
        import idna

        return idna.decode(label)
    except Exception:
        try:
            return label.encode("ascii").decode("idna")
        except Exception:
            return label


@dataclass
class DestinationInfo:
    raw: str
    normalized: str            # NFKC, case-folded, punycode labels decoded
    ascii_form: str            # what a mail server / DNS sees (punycode domain, escaped local part)
    non_ascii: bool = False
    nfkc_changed: bool = False
    mixed_script: bool = False
    confusable: bool = False
    scripts: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    @property
    def flagged(self) -> bool:
        """Show the look-alike warning (and need the extra confirmation on an approval card)."""
        return self.non_ascii or self.confusable


def _label_checks(label: str, info: DestinationInfo, where: str) -> None:
    letters = [c for c in label if _script(c) != "COMMON"]
    scripts = sorted({_script(c) for c in letters})
    for s in scripts:
        if s not in info.scripts:
            info.scripts.append(s)
    if len(scripts) > 1:
        info.mixed_script = info.confusable = True
        info.reasons.append(f"mixed scripts in the {where} ({', '.join(scripts)})")
        lookalikes = sorted({c for c in label if c in CONFUSABLES})
        if lookalikes:
            info.reasons.append("look-alike characters: " + ", ".join(
                f"{c} (U+{ord(c):04X}, looks like {CONFUSABLES[c]!r})" for c in lookalikes))
    elif scripts and scripts[0] in ("CYRILLIC", "GREEK") and all(c in CONFUSABLES for c in letters):
        info.confusable = True
        info.reasons.append(f"the {where} is written only with {scripts[0].title()} letters that look Latin")


def analyze(value: Any, kind: str = "email") -> DestinationInfo:
    """``kind``: "email" (local@domain), "host" (a host name) or "channel" (a name, no domain)."""
    raw = "" if value is None else str(value)
    stripped = raw.strip()
    nfkc = unicodedata.normalize("NFKC", stripped)
    info = DestinationInfo(raw=raw, normalized="", ascii_form="")
    info.nfkc_changed = nfkc != stripped
    if info.nfkc_changed:
        info.confusable = True
        info.reasons.append("compatibility characters (e.g. full-width) that normalise to different text")
    text = nfkc.casefold()
    if kind == "email" and "@" in text:
        local, domain = text.rsplit("@", 1)
    elif kind == "host":
        local, domain = "", text.rstrip(".")
    else:
        local, domain = text, ""
    raw_labels = domain.split(".") if domain else []
    labels = [_from_punycode(lbl) for lbl in raw_labels]
    if labels != raw_labels:
        info.reasons.append("the domain is IDN (punycode) encoded")
    decoded_domain = ".".join(labels)
    info.non_ascii = not stripped.isascii() or not decoded_domain.isascii()
    if local:
        _label_checks(local, info, "local part" if kind == "email" else "name")
    for lbl in labels:
        _label_checks(lbl, info, "domain")
    if info.non_ascii and not info.reasons:
        info.reasons.append("non-ASCII characters")
    ascii_domain = ".".join(_punycode_label(lbl) for lbl in labels)
    if kind == "email" and domain:
        info.normalized, info.ascii_form = f"{local}@{decoded_domain}", f"{_escape(local)}@{ascii_domain}"
    elif kind == "host":
        info.normalized, info.ascii_form = decoded_domain, ascii_domain
    else:
        info.normalized, info.ascii_form = local, _escape(local)
    return info


def is_confusable(value: Any, kind: str = "email") -> bool:
    return analyze(value, kind).confusable


def lookalike_warning(value: Any, kind: str = "email") -> dict[str, Any] | None:
    """Card data for a destination that needs the red warning, else None."""
    if not isinstance(value, str):
        return None
    info = analyze(value, kind)
    if not info.flagged:
        return None
    return {"value": value, "ascii_form": info.ascii_form, "confusable": info.confusable,
            "mixed_script": info.mixed_script, "reasons": info.reasons}


def canonical_host(host: Any) -> str | None:
    """Normalised host for exact matching (decoded IDN, NFKC, lower case), or None when confusable or empty."""
    if not isinstance(host, str) or not host.strip():
        return None
    info = analyze(host.strip().strip("[]").lstrip("@"), "host")
    return None if info.confusable or not info.normalized else info.normalized


def domain_matches(domain: Any, allowed: Iterable[str]) -> bool:
    """EXACT domain match after normalisation; never for a confusable domain (on either side)."""
    d = canonical_host(domain)
    if d is None:
        return False
    return any(canonical_host(str(e)) == d for e in allowed)


def email_domain_internal(email: Any, internal_domains: Iterable[str]) -> bool:
    """Internal only if the address has no look-alike characters anywhere and its domain matches exactly."""
    if not isinstance(email, str) or "@" not in email:
        return False
    if analyze(email, "email").confusable:
        return False
    return domain_matches(email.strip().rsplit("@", 1)[1], internal_domains)


def destination_kind(arg: str) -> str:
    if arg == "channel":
        return "channel"
    if arg in ("url", "host"):
        return "host"
    return "email"


def recipient_values(value: Any, _depth: int = 0) -> list[str]:
    """Every string a destination value carries (a str, a list, or a nested mapping such as ``{"payload": ...}``
    when a whole trigger payload is mapped into a recipient)."""
    if isinstance(value, str):
        return [value]
    if _depth > 4:
        return []
    if isinstance(value, (list, tuple, set)):
        return [s for v in value for s in recipient_values(v, _depth + 1)]
    if isinstance(value, dict):
        return [s for v in value.values() for s in recipient_values(v, _depth + 1)]
    return []
