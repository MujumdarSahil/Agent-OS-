"""Facade for agentos_swe.correlation"""
import warnings as _warnings

_warnings.warn(
    "agentos_swe.correlation is a legacy compatibility facade; import agentos_swe.remediation.correlation instead. "
    "It will be removed when SWE ships as a separate pack.",
    DeprecationWarning,
    stacklevel=2,
)

from agentos_swe.remediation.correlation import *
