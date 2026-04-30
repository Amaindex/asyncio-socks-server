from __future__ import annotations

import json
from pathlib import Path

from asyncio_socks_server.addons.base import Addon


class FileAuth(Addon):
    """File-based username/password authentication.

    Reads a JSON file mapping usernames to passwords:
    {"user1": "pass1", "user2": "pass2"}
    """

    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._credentials: dict[str, str] = {}

    def _load(self) -> dict[str, str]:
        try:
            text = self._path.read_text(encoding="utf-8")
            return json.loads(text)
        except (OSError, json.JSONDecodeError):
            return {}

    async def on_auth(self, username: str, password: str) -> bool | None:
        if not self._credentials:
            self._credentials = self._load()
        if username in self._credentials:
            return self._credentials[username] == password
        return None
