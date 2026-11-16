"""Facade for agentos_swe.graph"""
import warnings as _warnings

_warnings.warn(
    "agentos_swe.graph is a legacy compatibility facade; import agentos_swe.analysis.graph instead. "
    "It will be removed when SWE ships as a separate pack.",
    DeprecationWarning,
    stacklevel=2,
)

from agentos_swe.analysis.graph import *
