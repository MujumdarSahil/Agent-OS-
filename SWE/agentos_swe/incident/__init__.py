"""Facade for agentos_swe.incident"""
import warnings as _warnings

_warnings.warn(
    "agentos_swe.incident is a legacy compatibility facade; import agentos_swe.operations.incident instead. "
    "It will be removed when SWE ships as a separate pack.",
    DeprecationWarning,
    stacklevel=2,
)

from agentos_swe.operations.incident import *
