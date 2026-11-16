"""Facade for agentos_swe.semantic"""
import warnings as _warnings

_warnings.warn(
    "agentos_swe.semantic is a legacy compatibility facade; import agentos_swe.analysis.semantic instead. "
    "It will be removed when SWE ships as a separate pack.",
    DeprecationWarning,
    stacklevel=2,
)

from agentos_swe.analysis.semantic import *
