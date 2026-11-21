"""Facade for agentos_swe.learning"""
import warnings as _warnings

_warnings.warn(
    "agentos_swe.learning is a legacy compatibility facade; import agentos_swe.intelligence.learning instead. "
    "It will be removed when SWE ships as a separate pack.",
    DeprecationWarning,
    stacklevel=2,
)

from agentos_swe.intelligence.learning import *
