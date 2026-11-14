"""
Backend selection. Arguments win over environment variables:

  AGENTOS_STORAGE    file (default) | mongo
  AGENTOS_MONGO_URI  connection string (required for mongo)
  AGENTOS_MONGO_DB   database name (default "agentos")
  AGENTOS_VAULT_PATH Standalone vault file (default ~/.agentos/vault.json)

The Mongo adapter is imported only when selected, so Standalone installs do not
need pymongo.
"""

import os
from typing import Optional

from agentos.storage.ports import Storage


async def open_storage(
    project_path: Optional[str] = None,
    backend: Optional[str] = None,
    mongo_uri: Optional[str] = None,
    db_name: Optional[str] = None,
    vault_path: Optional[str] = None,
) -> Storage:
    backend = (backend or os.environ.get("AGENTOS_STORAGE") or "file").lower()

    if backend == "file":
        from agentos.storage.file import open_file_storage

        project_path = project_path or os.environ.get("AGENTOS_PROJECT") or os.getcwd()
        return open_file_storage(project_path, vault_path=vault_path)

    if backend == "mongo":
        uri = mongo_uri or os.environ.get("AGENTOS_MONGO_URI")
        if not uri:
            raise ValueError("Mongo storage selected but no URI given (set AGENTOS_MONGO_URI)")
        try:
            from agentos.storage.mongo import DEFAULT_DB, open_mongo_storage
        except ImportError as e:  # pragma: no cover - depends on installed extras
            raise ImportError("Mongo storage needs the 'platform' extra: pip install agentos[platform]") from e
        return await open_mongo_storage(uri, db_name or os.environ.get("AGENTOS_MONGO_DB") or DEFAULT_DB)

    raise ValueError(f"Unknown storage backend: {backend!r} (expected 'file' or 'mongo')")
