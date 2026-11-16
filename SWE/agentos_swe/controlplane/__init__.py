"""Facade for agentos_swe.controlplane"""
import warnings as _warnings

_warnings.warn(
    "agentos_swe.controlplane is a legacy compatibility facade; import agentos_swe.operations.controlplane instead. "
    "It will be removed when SWE ships as a separate pack.",
    DeprecationWarning,
    stacklevel=2,
)

from agentos_swe.operations.controlplane import *
