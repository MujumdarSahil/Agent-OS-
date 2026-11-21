"""Facade for agentos_swe.knowledge"""
import warnings as _warnings

_warnings.warn(
    "agentos_swe.knowledge is a legacy compatibility facade; import agentos_swe.intelligence.knowledge instead. "
    "It will be removed when SWE ships as a separate pack.",
    DeprecationWarning,
    stacklevel=2,
)

from agentos_swe.intelligence.knowledge import *
