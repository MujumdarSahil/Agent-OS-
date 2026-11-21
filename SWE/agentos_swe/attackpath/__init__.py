"""Facade for agentos_swe.attackpath"""
import warnings as _warnings

_warnings.warn(
    "agentos_swe.attackpath is a legacy compatibility facade; import agentos_swe.intelligence.attackpath instead. "
    "It will be removed when SWE ships as a separate pack.",
    DeprecationWarning,
    stacklevel=2,
)

from agentos_swe.intelligence.attackpath import *
