"""Facade for agentos_swe.orchestration"""
import warnings as _warnings

_warnings.warn(
    "agentos_swe.orchestration is a legacy compatibility facade; import agentos_swe.operations.orchestration instead. "
    "It will be removed when SWE ships as a separate pack.",
    DeprecationWarning,
    stacklevel=2,
)

from agentos_swe.operations.orchestration import *
