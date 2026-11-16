"""ModelHub training/performance are NOT AVAILABLE in 2.0: nothing may return success without work (rule 4)."""

import importlib
import inspect
import pkgutil

import pytest

import agentos.modelhub.performance as performance
import agentos.modelhub.training as training


def _classes():
    out = []
    for pkg in (training, performance):
        for info in pkgutil.iter_modules(pkg.__path__):
            mod = importlib.import_module(f"{pkg.__name__}.{info.name}")
            for obj in vars(mod).values():
                if inspect.isclass(obj) and obj.__module__ == mod.__name__:
                    out.append(obj)
    return out


CLASSES = _classes()


def test_all_classes_found():
    assert len(CLASSES) == 13


@pytest.mark.parametrize("cls", CLASSES, ids=lambda c: c.__name__)
def test_constructor_and_methods_raise(cls):
    with pytest.raises(NotImplementedError, match="not available in AgentOS 2.0"):
        cls()
    methods = [n for n, v in vars(cls).items() if not n.startswith("__") and isinstance(v, staticmethod)]
    assert methods, f"{cls.__name__} exposes no methods"
    for name in methods:
        with pytest.raises(NotImplementedError, match="docs/SPEC_2.0.md"):
            getattr(cls, name)("x")


def test_lora_apply_no_longer_reports_fake_success():
    from agentos.modelhub.training.lora_utils import LoRAUtils

    with pytest.raises(NotImplementedError):
        LoRAUtils.apply_lora_adapters("base", "adapter")
