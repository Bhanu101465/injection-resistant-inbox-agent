"""
Mock inbox — in-memory email store loaded from JSON files.

Supports all operations needed by the inbox agent tools:
read, search, mark-read, reply, forward, delete.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from src.models.email import Email

logger = logging.getLogger(__name__)


class MockInbox:
    """In-memory email store backed by JSON files on disk.

    Parameters
    ----------
    directories:
        One or more directories to load ``*.json`` email files from.
        Files that fail to parse are skipped with a warning.
    """

    def __init__(self, *directories: str | Path) -> None:
        self._emails: dict[str, Email] = {}
        self._sent: list[dict] = []   # records of reply/forward actions
        self._deleted: list[str] = []  # ids of deleted emails

        for directory in directories:
            self._load_directory(Path(directory))

        logger.info("MockInbox loaded %d emails", len(self._emails))

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _load_directory(self, directory: Path) -> None:
        if not directory.exists():
            logger.warning("Inbox directory not found: %s", directory)
            return
        for json_file in sorted(directory.glob("*.json")):
            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
                email = Email.model_validate(data)
                self._emails[email.id] = email
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to load %s: %s", json_file.name, exc)

    # ------------------------------------------------------------------
    # Read operations
    # ------------------------------------------------------------------

    def get(self, email_id: str) -> Email | None:
        """Return the Email with the given id, or ``None`` if not found."""
        return self._emails.get(email_id)

    def list_all(self) -> list[Email]:
        """Return all emails (including read) ordered by timestamp descending."""
        return sorted(
            self._emails.values(),
            key=lambda e: e.timestamp,
            reverse=True,
        )

    def list_unread(self) -> list[Email]:
        """Return only unread emails, ordered by timestamp descending."""
        return [e for e in self.list_all() if not e.is_read]

    def search(self, query: str) -> list[Email]:
        """Keyword search over subject + body_text (case-insensitive)."""
        q = query.lower()
        return [
            e
            for e in self.list_all()
            if q in e.subject.lower()
            or q in e.body_text.lower()
            or q in (e.from_ or "").lower()
        ]

    # ------------------------------------------------------------------
    # Mutating operations
    # ------------------------------------------------------------------

    def mark_read(self, email_id: str) -> bool:
        """Mark an email as read. Returns True if found."""
        email = self._emails.get(email_id)
        if email is None:
            return False
        self._emails[email_id] = email.model_copy(update={"is_read": True})
        return True

    def delete(self, email_id: str) -> bool:
        """Remove an email. Returns True if it existed."""
        if email_id in self._emails:
            del self._emails[email_id]
            self._deleted.append(email_id)
            logger.debug("Deleted email %s", email_id)
            return True
        return False

    def record_reply(self, email_id: str, to: str, body: str) -> None:
        """Record a reply action (does not actually send email)."""
        self._sent.append({"action": "reply", "email_id": email_id, "to": to, "body": body})

    def record_forward(
        self, email_id: str, to: str, comment: str = ""
    ) -> None:
        """Record a forward action (does not actually send email)."""
        self._sent.append(
            {"action": "forward", "email_id": email_id, "to": to, "comment": comment}
        )

    def add(self, email: Email) -> None:
        """Add or overwrite an email (useful in tests)."""
        self._emails[email.id] = email

    # ------------------------------------------------------------------
    # State accessors (for testing / eval)
    # ------------------------------------------------------------------

    @property
    def sent_actions(self) -> list[dict]:
        """All recorded reply / forward actions."""
        return list(self._sent)

    @property
    def deleted_ids(self) -> list[str]:
        """IDs of emails that have been deleted."""
        return list(self._deleted)

    def __len__(self) -> int:
        return len(self._emails)

    def __repr__(self) -> str:
        return f"MockInbox({len(self._emails)} emails)"
