"""Admin configuration read from ``<project>/agentos.config.yaml`` and environment variables (internal domains,
http allowlist, named allowlists, declassification flag, separation of duties, price overrides, notifications).

Moved from agentos_server/app.py in 4.2 so the CLI (``agentos test``) builds the SAME SecurityPolicy as the server
without importing the server package (core must not import agentos_server/fastapi). ``agentos_server.app`` still
exports every name for compatibility.
"""

from __future__ import annotations

import os
from typing import Any

INTERNAL_DOMAINS_ENV = "AGENTOS_INTERNAL_DOMAINS"


def load_internal_domains(project_path: str) -> set[str]:
    """Trusted internal email domains for the IFC SecurityPolicy (admin configuration).

    Precedence: the ``AGENTOS_INTERNAL_DOMAINS`` env var (comma-separated) if it is set, else
    ``security.internal_domains`` (a list) in ``<project>/agentos.config.yaml``, else empty.
    The default is empty: no recipient domain is trusted unless an admin configures it.
    """
    env_val = os.environ.get(INTERNAL_DOMAINS_ENV)
    if env_val is not None:
        return {d.strip().lower().lstrip("@") for d in env_val.split(",") if d.strip()}
    cfg_path = os.path.join(project_path, "agentos.config.yaml")
    if not os.path.isfile(cfg_path):
        return set()
    import yaml

    with open(cfg_path, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    domains = ((cfg.get("security") or {}) if isinstance(cfg, dict) else {}).get("internal_domains") or []
    if not isinstance(domains, list) or not all(isinstance(d, str) for d in domains):
        raise ValueError("agentos.config.yaml: security.internal_domains must be a list of domain strings")
    return {d.strip().lower().lstrip("@") for d in domains if d.strip()}


HTTP_ALLOWLIST_ENV = "AGENTOS_HTTP_ALLOWLIST"


def load_http_allowlist(project_path: str) -> list[str]:
    """Admin allowlist of internal hosts for the http_request node.

    Precedence: ``AGENTOS_HTTP_ALLOWLIST`` (comma-separated hosts, ``*.suffix`` or CIDRs) if set,
    else ``security.http_allowlist`` in ``<project>/agentos.config.yaml``, else empty.
    """
    env_val = os.environ.get(HTTP_ALLOWLIST_ENV)
    if env_val is not None:
        return sorted({e.strip().lower() for e in env_val.split(",") if e.strip()})
    cfg_path = os.path.join(project_path, "agentos.config.yaml")
    if not os.path.isfile(cfg_path):
        return []
    import yaml

    with open(cfg_path, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    entries = ((cfg.get("security") or {}) if isinstance(cfg, dict) else {}).get("http_allowlist") or []
    if not isinstance(entries, list) or not all(isinstance(e, str) for e in entries):
        raise ValueError("agentos.config.yaml: security.http_allowlist must be a list of host/CIDR strings")
    return sorted({e.strip().lower() for e in entries if e.strip()})


def load_notifications_config(project_path: str) -> dict[str, Any]:
    """3.3: ``notifications`` in agentos.config.yaml (admin): ``smtp_allowlist`` (hosts / CIDRs an SMTP relay may
    resolve to inside blocked ranges) and ``ui_base_url`` (links in alerts). Defaults: empty, http://127.0.0.1:8000."""
    cfg_path = os.path.join(project_path, "agentos.config.yaml")
    out: dict[str, Any] = {"smtp_allowlist": [], "ui_base_url": "http://127.0.0.1:8000"}
    if not os.path.isfile(cfg_path):
        return out
    import yaml

    with open(cfg_path, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    sec = (cfg.get("notifications") if isinstance(cfg, dict) else None) or {}
    if not isinstance(sec, dict):
        raise ValueError("agentos.config.yaml: notifications must be a mapping")
    allow = sec.get("smtp_allowlist") or []
    if not isinstance(allow, list) or not all(isinstance(e, str) for e in allow):
        raise ValueError("agentos.config.yaml: notifications.smtp_allowlist must be a list of host/CIDR strings")
    out["smtp_allowlist"] = sorted({e.strip().lower() for e in allow if e.strip()})
    base = sec.get("ui_base_url")
    if base is not None:
        if not isinstance(base, str) or not base.startswith(("http://", "https://")) or any(c in base for c in " \r\n"):
            raise ValueError("agentos.config.yaml: notifications.ui_base_url must be an http(s) URL")
        out["ui_base_url"] = base.rstrip("/")
    return out


def _security_section(project_path: str) -> dict[str, Any]:
    cfg_path = os.path.join(project_path, "agentos.config.yaml")
    if not os.path.isfile(cfg_path):
        return {}
    import yaml

    with open(cfg_path, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    sec = cfg.get("security") if isinstance(cfg, dict) else None
    return sec if isinstance(sec, dict) else {}


def load_allowlists(project_path: str) -> dict[str, list[str]]:
    """2.5b: named admin allowlists (``security.allowlists`` in agentos.config.yaml: name -> list of
    strings), used by validator ``allowlist_match`` and quarantined-extraction ``allowlist`` fields.
    Admin configuration only; a flow cannot add entries. Default: none."""
    raw = _security_section(project_path).get("allowlists") or {}
    if not isinstance(raw, dict) or not all(
        isinstance(k, str) and isinstance(v, list) and all(isinstance(e, str) for e in v) for k, v in raw.items()
    ):
        raise ValueError("agentos.config.yaml: security.allowlists must map names to lists of strings")
    return {k: [e.strip() for e in v if e.strip()] for k, v in raw.items()}


ALLOW_DECLASSIFIED_DESTRUCTIVE_ENV = "AGENTOS_ALLOW_DECLASSIFIED_FOR_DESTRUCTIVE"
# 2.5b draft names, still read (the new name wins when both are set)
ALLOW_EXTRACTION_DESTRUCTIVE_ENV = "AGENTOS_ALLOW_EXTRACTION_FOR_DESTRUCTIVE"


def load_allow_declassified_for_destructive(project_path: str) -> bool:
    """2.5b admin flag: may a DESTRUCTIVE sink be enabled solely by a declassified value (validator or quarantined
    extraction)? Default False. Precedence: ``AGENTOS_ALLOW_DECLASSIFIED_FOR_DESTRUCTIVE``, then the old
    ``AGENTOS_ALLOW_EXTRACTION_FOR_DESTRUCTIVE`` (exactly "1"/"true" enables), then
    ``security.allow_declassified_for_destructive``, then the old ``security.allow_extraction_for_destructive``."""
    for env_name in (ALLOW_DECLASSIFIED_DESTRUCTIVE_ENV, ALLOW_EXTRACTION_DESTRUCTIVE_ENV):
        env_val = os.environ.get(env_name)
        if env_val is not None:
            return env_val.strip().lower() in ("1", "true")
    sec = _security_section(project_path)
    for key in ("allow_declassified_for_destructive", "allow_extraction_for_destructive"):
        if key in sec:
            val = sec[key]
            if not isinstance(val, bool):
                raise ValueError(f"agentos.config.yaml: security.{key} must be true or false")
            return val
    return False


def load_separation_of_duties(project_path: str) -> bool:
    """3.4 admin flag ``security.separation_of_duties`` (default False): whoever published a flow version may not
    approve or reject runs of it."""
    val = _security_section(project_path).get("separation_of_duties", False)
    if not isinstance(val, bool):
        raise ValueError("agentos.config.yaml: security.separation_of_duties must be true or false")
    return val


# Deprecated 2.5b draft name of the loader.
load_allow_extraction_for_destructive = load_allow_declassified_for_destructive


def load_price_overrides(project_path: str) -> dict[str, Any]:
    """3.2: admin price overrides, ``usage.prices`` in agentos.config.yaml:
    {provider_or_model: {input_per_1m: float, output_per_1m: float}} (USD per 1M tokens)."""
    cfg_path = os.path.join(project_path, "agentos.config.yaml")
    if not os.path.isfile(cfg_path):
        return {}
    import yaml

    with open(cfg_path, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    prices = ((cfg.get("usage") or {}) if isinstance(cfg, dict) else {}).get("prices") or {}
    out: dict[str, Any] = {}
    if not isinstance(prices, dict):
        raise ValueError("agentos.config.yaml: usage.prices must map provider or model names to prices")
    for name, p in prices.items():
        if not (isinstance(p, dict) and all(isinstance(p.get(k), (int, float)) and p.get(k) >= 0
                                            for k in ("input_per_1m", "output_per_1m"))):
            raise ValueError(f"agentos.config.yaml: usage.prices[{name!r}] needs input_per_1m and output_per_1m >= 0")
        out[str(name)] = {"input_per_1m": float(p["input_per_1m"]), "output_per_1m": float(p["output_per_1m"])}
    return out
