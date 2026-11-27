"""4.1b: AgentDojo (https://github.com/ethz-spylab/agentdojo) with AgentOS as a defense. Benchmark only.

Needs the optional extra: pip install -e ".[benchmark]" (agentdojo==0.1.35). Never imported by the product.
"""

try:
    import agentdojo  # noqa: F401
except ImportError as err:  # pragma: no cover - depends on the optional extra
    raise ImportError('AgentDojo is not installed: pip install -e ".[benchmark]"') from err
