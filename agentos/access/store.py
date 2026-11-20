"""Document stores for 3.4 access (users, username claims, sessions, API tokens, settings).

File backend: ``<project>/.agentos/state/access_<name>.json`` (atomic writes, one lock per file; reuses the 3.3
FileDocs). Mongo backend: collections ``users``, ``usernames``, ``sessions``, ``api_tokens``, ``access_settings``
(reuses the 3.3 MongoDocs). Username uniqueness is a claim document keyed by the lower-case username, created with
``insert_if_absent`` (atomic in both backends), so two concurrent creates cannot both win.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


class AccessStore:
    def __init__(self, users: Any, usernames: Any, sessions: Any, tokens: Any, settings: Any) -> None:
        self.users = users
        self.usernames = usernames
        self.sessions = sessions
        self.tokens = tokens
        self.settings = settings


def access_store_for(storage: Any) -> AccessStore:
    if getattr(storage, "backend", "file") == "mongo":
        from agentos.storage.mongo.notify import MongoDocs

        db = storage.runs._c.database
        return AccessStore(MongoDocs(db.users), MongoDocs(db.usernames), MongoDocs(db.sessions),
                           MongoDocs(db.api_tokens), MongoDocs(db.access_settings))
    from agentos.notify.store import FileDocs

    base = Path(storage.location) / ".agentos" / "state"
    return AccessStore(FileDocs(base / "access_users.json"), FileDocs(base / "access_usernames.json"),
                       FileDocs(base / "access_sessions.json"), FileDocs(base / "access_tokens.json"),
                       FileDocs(base / "access_settings.json"))
