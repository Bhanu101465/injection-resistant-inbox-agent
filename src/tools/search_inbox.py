"""search_inbox tool — keyword search over the inbox."""

from __future__ import annotations

from src.inbox.mock_inbox import MockInbox
from src.tools.audit_log import AuditLogger


def search_inbox(
    inbox: MockInbox,
    logger: AuditLogger,
    query: str,
    email_id: str | None = None,
) -> list[dict]:
    """Search the inbox for emails matching *query*.

    Parameters
    ----------
    inbox:    The MockInbox to search.
    logger:   AuditLogger to record this tool call.
    query:    Keyword or phrase to search for.
    email_id: Optional — the email that triggered this tool call (for audit).

    Returns
    -------
    list[dict]
        Summaries of matching emails: id, from, subject, timestamp, is_read.
    """
    logger.log("search_inbox", {"query": query}, email_id=email_id)

    matches = inbox.search(query)
    return [
        {
            "id": e.id,
            "from": e.from_,
            "subject": e.subject,
            "timestamp": e.timestamp.isoformat(),
            "is_read": e.is_read,
        }
        for e in matches
    ]
