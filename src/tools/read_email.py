"""read_email tool — reads and marks an email as read."""

from __future__ import annotations

from src.inbox.mock_inbox import MockInbox
from src.tools.audit_log import AuditLogger


def read_email(
    inbox: MockInbox,
    logger: AuditLogger,
    email_id: str,
) -> str:
    """Read the full content of an email and mark it as read.

    Parameters
    ----------
    inbox:    The MockInbox to read from.
    logger:   AuditLogger to record this tool call.
    email_id: The unique ID of the email to read.

    Returns
    -------
    str
        A formatted string with the email content, or an error message.
    """
    logger.log("read_email", {"email_id": email_id}, email_id=email_id)

    email = inbox.get(email_id)
    if email is None:
        return f"[ERROR] Email '{email_id}' not found."

    inbox.mark_read(email_id)

    # Build a plain-text render suitable for the LLM prompt
    parts = [
        f"From:    {email.from_}",
        f"To:      {', '.join(email.to)}",
        f"Subject: {email.subject}",
        f"Date:    {email.timestamp.isoformat()}",
        "",
        email.body_text or email.body_html or "(no body)",
    ]

    if email.attachments:
        for att in email.attachments:
            parts.append(f"\n--- Attachment: {att.filename} ---")
            if att.content_text:
                parts.append(att.content_text)

    return "\n".join(parts)
