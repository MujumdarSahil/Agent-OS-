"""
Deprecated alias for the ``agentos_server`` package (moved in AgentOS 2.0, sub-milestone 1.1b).

Every ``agentos.server[.X]`` import resolves to the *same module object* as
``agentos_server[.X]``, so existing imports, monkeypatches and the uvicorn path
``agentos.server.app:create_app`` keep working. Nothing from ``agentos_server``
(or FastAPI) is imported until a submodule is actually requested.

Use ``agentos_server`` in new code. This shim will be removed no earlier than 2.1.
"""

import importlib
import importlib.abc
import importlib.util
import sys
import warnings

_OLD = __name__  # "agentos.server"
_NEW = "agentos_server"

warnings.warn(
    "agentos.server is deprecated; import from agentos_server instead.",
    DeprecationWarning,
    stacklevel=2,
)


class _AliasLoader(importlib.abc.Loader):
    def __init__(self, target: str):
        self._target = target

    def create_module(self, spec):
        # Return the real module; importlib registers it under the old name too.
        return importlib.import_module(self._target)

    def exec_module(self, module):
        pass  # already executed under its real name


class _AliasFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if not fullname.startswith(_OLD + "."):
            return None
        real_name = _NEW + fullname[len(_OLD):]
        real_spec = importlib.util.find_spec(real_name)
        if real_spec is None:
            return None
        return importlib.util.spec_from_loader(
            fullname,
            _AliasLoader(real_name),
            is_package=real_spec.submodule_search_locations is not None,
        )


if not any(isinstance(f, _AliasFinder) for f in sys.meta_path):
    sys.meta_path.insert(0, _AliasFinder())
