"""Facade for agentos_swe.verification"""
import warnings as _warnings

_warnings.warn(
    "agentos_swe.verification is a legacy compatibility facade; import agentos_swe.analysis.verification instead. "
    "It will be removed when SWE ships as a separate pack.",
    DeprecationWarning,
    stacklevel=2,
)

from agentos_swe.analysis.verification import *
