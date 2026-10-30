"""delete_email tool — permanently removes an email from the inbox."""

from __future__ import annotations

from src.inbox.mock_inbox import MockInbox
from src.tools.audit_log import AuditLogger


def delete_email(
    inbox: MockInbox,
    logger: AuditLogger,
    email_id: str,
) -> str:
    """Delete an email from the inbox.

    Parameters
    ----------
    inbox:    The MockInbox to remove the email from.
    logger:   AuditLogger to record this tool call.
    email_id: ID of the email to delete.

    Returns
    -------
    str
        Confirmation string or error message.
    """
    logger.log("delete_email", {"email_id": email_id}, email_id=email_id)

    deleted = inbox.delete(email_id)
    if not deleted:
        return f"[ERROR] Email '{email_id}' not found."
    return f"Email '{email_id}' deleted."
