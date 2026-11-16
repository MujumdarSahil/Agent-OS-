"""Facade for agentos_swe.repair"""
import warnings as _warnings

_warnings.warn(
    "agentos_swe.repair is a legacy compatibility facade; import agentos_swe.remediation.repair instead. "
    "It will be removed when SWE ships as a separate pack.",
    DeprecationWarning,
    stacklevel=2,
)

from agentos_swe.remediation.repair import *
