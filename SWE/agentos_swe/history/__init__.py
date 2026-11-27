"""Facade for agentos_swe.history"""
import warnings as _warnings

_warnings.warn(
    "agentos_swe.history is a legacy compatibility facade; import agentos_swe.intelligence.history instead. "
    "It will be removed when SWE ships as a separate pack.",
    DeprecationWarning,
    stacklevel=2,
)

from agentos_swe.intelligence.history import *
