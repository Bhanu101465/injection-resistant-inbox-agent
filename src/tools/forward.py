"""forward_email tool — forwards an email to a specified address."""

from __future__ import annotations

from src.inbox.mock_inbox import MockInbox
from src.tools.audit_log import AuditLogger


def forward_email(
    inbox: MockInbox,
    logger: AuditLogger,
    email_id: str,
    to: str,
    comment: str = "",
) -> str:
    """Forward an email to *to*.

    Parameters
    ----------
    inbox:    The MockInbox (used to look up email and record action).
    logger:   AuditLogger to record this tool call.
    email_id: ID of the email to forward.
    to:       Recipient address.
    comment:  Optional comment prepended to the forwarded body.

    Returns
    -------
    str
        Confirmation string or error message.
    """
    logger.log(
        "forward_email",
        {"email_id": email_id, "to": to, "comment": comment},
        email_id=email_id,
    )

    email = inbox.get(email_id)
    if email is None:
        return f"[ERROR] Email '{email_id}' not found."

    inbox.record_forward(email_id=email_id, to=to, comment=comment)
    return f"Email '{email_id}' forwarded to {to}."
