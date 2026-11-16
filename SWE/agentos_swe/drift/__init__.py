"""Facade for agentos_swe.drift"""
import warnings as _warnings

_warnings.warn(
    "agentos_swe.drift is a legacy compatibility facade; import agentos_swe.intelligence.drift instead. "
    "It will be removed when SWE ships as a separate pack.",
    DeprecationWarning,
    stacklevel=2,
)

from agentos_swe.intelligence.drift import *
