"""Facade for agentos_swe.monitoring"""
import warnings as _warnings

_warnings.warn(
    "agentos_swe.monitoring is a legacy compatibility facade; import agentos_swe.operations.monitoring instead. "
    "It will be removed when SWE ships as a separate pack.",
    DeprecationWarning,
    stacklevel=2,
)

from agentos_swe.operations.monitoring import *
