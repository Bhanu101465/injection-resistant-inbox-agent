"""
SQLite-backed LLM response cache.

Cache keys are SHA-256 hashes of the serialised (model, messages, tools,
temperature, reasoning_flag) tuple.  Each entry stores the raw
serialised LLMResponse JSON so the cache is independent of the model class.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from pathlib import Path

logger = logging.getLogger(__name__)

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS llm_cache (
    key        TEXT PRIMARY KEY,
    response   TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
)
"""


def _cache_key(
    model: str,
    messages: list[dict],
    tools: list[dict] | None,
    temperature: float,
    enable_reasoning: bool,
) -> str:
    """Return a deterministic SHA-256 hex key for a request."""
    payload = {
        "model": model,
        "messages": messages,
        "tools": tools or [],
        "temperature": temperature,
        "enable_reasoning": enable_reasoning,
    }
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


class LLMCache:
    """Disk-backed SQLite cache for LLM responses.

    Parameters
    ----------
    db_path:
        Path to the SQLite file.  Defaults to ``llm_cache.db`` in the
        current working directory.
    enabled:
        When *False* all ``get`` calls return ``None`` and ``set`` is a no-op.
        Pass ``enabled=False`` when ``--no-cache`` is supplied on the CLI.
    """

    def __init__(self, db_path: str | Path = "llm_cache.db", *, enabled: bool = True) -> None:
        self.enabled = enabled
        self._db_path = Path(db_path)
        if self.enabled:
            self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
            self._conn.execute(_CREATE_TABLE)
            self._conn.commit()
            logger.debug("LLM cache initialised at %s", self._db_path)

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def make_key(
        self,
        model: str,
        messages: list[dict],
        tools: list[dict] | None,
        temperature: float,
        enable_reasoning: bool,
    ) -> str:
        """Compute and return the cache key for a request."""
        return _cache_key(model, messages, tools, temperature, enable_reasoning)

    def get(self, key: str) -> str | None:
        """Return the cached JSON string for *key*, or ``None`` on miss."""
        if not self.enabled:
            return None
        row = self._conn.execute(
            "SELECT response FROM llm_cache WHERE key = ?", (key,)
        ).fetchone()
        if row:
            logger.debug("Cache HIT for key %.16s…", key)
            return row[0]
        logger.debug("Cache MISS for key %.16s…", key)
        return None

    def set(self, key: str, response_json: str) -> None:
        """Store *response_json* under *key*."""
        if not self.enabled:
            return
        self._conn.execute(
            "INSERT OR REPLACE INTO llm_cache (key, response) VALUES (?, ?)",
            (key, response_json),
        )
        self._conn.commit()

    def clear(self) -> int:
        """Delete all cached entries; return the number of rows removed."""
        if not self.enabled:
            return 0
        cur = self._conn.execute("DELETE FROM llm_cache")
        self._conn.commit()
        count = cur.rowcount
        logger.info("Cache cleared (%d entries removed)", count)
        return count

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        if self.enabled:
            self._conn.close()
