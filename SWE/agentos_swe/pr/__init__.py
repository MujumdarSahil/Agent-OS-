"""Facade for agentos_swe.pr"""
import warnings as _warnings

_warnings.warn(
    "agentos_swe.pr is a legacy compatibility facade; import agentos_swe.remediation.pr instead. "
    "It will be removed when SWE ships as a separate pack.",
    DeprecationWarning,
    stacklevel=2,
)

from agentos_swe.remediation.pr import *
