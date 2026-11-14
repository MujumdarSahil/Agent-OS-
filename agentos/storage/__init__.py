"""
Storage ports and adapters (AgentOS 2.0, sub-milestone 1.2).

  ports.py    repository interfaces, no storage library imports
  models.py   stored entity models
  file/       Standalone backend: v1 YAML project layout + SQLite checkpoints
  mongo/      Platform backend: MongoDB via PyMongo async (extra: agentos[platform])
  factory.py  open_storage(): picks a backend from arguments or AGENTOS_STORAGE
"""

from agentos.storage.factory import open_storage
from agentos.storage.ports import ReadOnlyEntityError, Storage

__all__ = ["open_storage", "ReadOnlyEntityError", "Storage"]
