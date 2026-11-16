"""Queue interfaces and implementations for AgentOS flow execution."""

from agentos.queue.in_process import InProcessQueueBackend
from agentos.queue.ports import QueueBackend, QueueJob


def __getattr__(name: str):
    if name == "RedisQueueBackend":
        from agentos.queue.redis import RedisQueueBackend
        return RedisQueueBackend
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["QueueBackend", "QueueJob", "InProcessQueueBackend", "RedisQueueBackend"]
