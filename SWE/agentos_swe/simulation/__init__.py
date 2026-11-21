"""Facade for agentos_swe.simulation"""
import warnings as _warnings

_warnings.warn(
    "agentos_swe.simulation is a legacy compatibility facade; import agentos_swe.remediation.simulation instead. "
    "It will be removed when SWE ships as a separate pack.",
    DeprecationWarning,
    stacklevel=2,
)

from agentos_swe.remediation.simulation import *
