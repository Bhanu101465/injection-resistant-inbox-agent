"""reply_email tool — sends a reply to an email."""

from __future__ import annotations

from src.inbox.mock_inbox import MockInbox
from src.tools.audit_log import AuditLogger


def reply_email(
    inbox: MockInbox,
    logger: AuditLogger,
    email_id: str,
    body: str,
) -> str:
    """Reply to an email.

    Parameters
    ----------
    inbox:    The MockInbox (used to look up the original email and record).
    logger:   AuditLogger to record this tool call.
    email_id: ID of the email being replied to.
    body:     Plain-text body of the reply.

    Returns
    -------
    str
        Confirmation string or error message.
    """
    logger.log("reply_email", {"email_id": email_id, "body": body}, email_id=email_id)

    email = inbox.get(email_id)
    if email is None:
        return f"[ERROR] Email '{email_id}' not found."

    inbox.record_reply(email_id=email_id, to=email.from_, body=body)
    return f"Reply sent to {email.from_} for email '{email_id}'."
