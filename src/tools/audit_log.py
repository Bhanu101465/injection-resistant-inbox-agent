"""
JSONL audit logger — every tool call is appended here.

Each line: {"timestamp": ..., "tool": ..., "args": ..., "email_id": ...}
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


class AuditLogger:
    """Append-only JSONL logger for tool calls.

    Parameters
    ----------
    log_path:
        Path to the ``.jsonl`` audit file.  Defaults to ``AUDIT_LOG_PATH``
        env var or ``audit.jsonl`` in the current working directory.
    enabled:
        Set to ``False`` to disable logging (useful in unit tests that want
        to inspect calls through MockInbox instead).
    """

    def __init__(
        self,
        log_path: str | Path | None = None,
        *,
        enabled: bool = True,
    ) -> None:
        self.enabled = enabled
        if log_path is None:
            log_path = os.environ.get("AUDIT_LOG_PATH", "audit.jsonl")
        self._path = Path(log_path)

    def log(
        self,
        tool: str,
        args: dict,
        email_id: str | None = None,
    ) -> None:
        """Append a JSONL entry to the audit log.

        Parameters
        ----------
        tool:     Name of the tool that was called.
        args:     Keyword arguments passed to the tool.
        email_id: ID of the email that triggered the tool call.
        """
        if not self.enabled:
            return

        entry = {
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "tool": tool,
            "args": args,
            "email_id": email_id,
        }
        try:
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError as exc:
            logger.error("Audit log write failed: %s", exc)

    def read_all(self) -> list[dict]:
        """Return all logged entries as a list of dicts (for testing)."""
        if not self._path.exists():
            return []
        entries = []
        with self._path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        return entries

    def clear(self) -> None:
        """Truncate the audit log (useful between test runs)."""
        if self._path.exists():
            self._path.write_text("", encoding="utf-8")
