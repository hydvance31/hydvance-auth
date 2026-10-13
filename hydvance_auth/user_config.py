"""One JSON configuration file per user and per application.

Files live under HYDVANCE_USER_CONFIG_DIR (a durable volume in production,
like LH2TankSizing's /data), named after the user's portal id, never their
e-mail: the id is a 32-hex-digit value checked before it touches the
filesystem, so no crafted value can escape the directory.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path

from .identity import Identity, app_slug

_ID = re.compile(r"^[0-9a-f]{32}$")
MAX_BYTES = 256 * 1024


class UserConfigStore:
    def __init__(self, slug: str | None = None, base_dir: str | os.PathLike | None = None):
        root = Path(base_dir or os.environ.get("HYDVANCE_USER_CONFIG_DIR", "user_configs"))
        self.dir = root / app_slug(slug)
        self.dir.mkdir(parents=True, exist_ok=True)

    def _path(self, me: Identity) -> Path:
        if not _ID.match(me.user_id):
            raise ValueError("Invalid user id.")
        return self.dir / f"{me.user_id}.json"

    def load(self, me: Identity) -> dict:
        path = self._path(me)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    def save(self, me: Identity, data: dict) -> None:
        raw = json.dumps(data, ensure_ascii=False, sort_keys=True)
        if len(raw.encode()) > MAX_BYTES:
            raise ValueError("Configuration too large.")
        path = self._path(me)
        # Write-then-rename: a crash mid-write never leaves a half file behind.
        fd, tmp = tempfile.mkstemp(dir=self.dir, suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(raw)
        os.replace(tmp, path)

    def clear(self, me: Identity) -> None:
        self._path(me).unlink(missing_ok=True)
