"""Facade for agentos_swe.agents"""
import warnings as _warnings

_warnings.warn(
    "agentos_swe.agents is a legacy compatibility facade; import agentos_swe.core.agents instead. "
    "It will be removed when SWE ships as a separate pack.",
    DeprecationWarning,
    stacklevel=2,
)

from agentos_swe.core.agents import *
