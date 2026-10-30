"""
Approval interface — asks the user whether to proceed with a high-risk tool.

Implementations
---------------
ScriptedApproval  — returns preset answers (default: NO). Used in evals.
CliApproval       — prompts the user in the terminal interactively.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections import deque
from pathlib import Path
from typing import Any

from src.models.tools import ToolCall

_DEFAULT_ALLOWLIST = Path(__file__).parent.parent.parent / "config" / "allowlist.json"


def _is_external_recipient(recipient: str, allowlist: list[str] | None = None) -> bool:
    """Return True if recipient is outside the organization / allowlist."""
    if not recipient:
        return False
    r = recipient.lower().strip()
    if allowlist is None:
        try:
            if _DEFAULT_ALLOWLIST.exists():
                data = json.loads(_DEFAULT_ALLOWLIST.read_text(encoding="utf-8"))
                allowlist = [x.lower() for x in data.get("allowed_recipients", [])]
            else:
                allowlist = ["@acme.test"]
        except Exception:
            allowlist = ["@acme.test"]

    for pattern in allowlist:
        if pattern.startswith("@"):
            if r.endswith(pattern):
                return False
        elif r == pattern:
            return False
    return True


def format_approval_prompt(
    tool_call: ToolCall,
    reason: str = "",
    *,
    email: Any | None = None,
    subject: str | None = None,
    body: str | None = None,
    recipient: str | None = None,
    is_suspicious: bool = False,
    is_external: bool | None = None,
    allowlist: list[str] | None = None,
) -> str:
    """Format a clear, human-readable approval prompt for a dangerous action."""
    args = tool_call.arguments or {}

    # 1. Resolve recipient and external status
    if recipient is None:
        recipient = args.get("to") or args.get("recipient")
        if not recipient and email:
            recipient = getattr(email, "from_", None) or getattr(email, "sender", None)
            if isinstance(email, dict) and not recipient:
                recipient = email.get("from") or email.get("sender")

    if is_external is None and recipient:
        is_external = _is_external_recipient(recipient, allowlist=allowlist)

    # 2. Plain sentence of what the action does
    if tool_call.name == "forward_email":
        target = f"{recipient} (EXTERNAL)" if is_external else (recipient or "another address")
        action_sentence = f"The agent wants to forward this email to {target}."
    elif tool_call.name == "reply_email":
        target = f"{recipient} (EXTERNAL)" if is_external else (recipient or "the sender")
        action_sentence = f"The agent wants to send a reply to {target}."
    elif tool_call.name == "delete_email":
        action_sentence = "The agent wants to permanently delete an email from your inbox."
    else:
        action_sentence = f"The agent wants to execute '{tool_call.name}'."

    # 3. Recipient line
    recip_info = None
    if recipient:
        status_label = "EXTERNAL (outside your organization)" if is_external else "Internal"
        recip_info = f"Recipient : {recipient} [{status_label}]"

    # 4. Email subject and first 3 lines
    if subject is None:
        if email:
            subject = getattr(email, "subject", None) or getattr(email, "clean_subject", None)
            if isinstance(email, dict) and subject is None:
                subject = email.get("subject")
        if subject is None:
            subject = args.get("subject", "(not specified)")

    if body is None:
        if args.get("body"):
            body = args.get("body")
        elif email:
            body = getattr(email, "body_text", None) or getattr(email, "clean_body", None)
            if isinstance(email, dict) and body is None:
                body = email.get("body_text") or email.get("clean_body")
        if body is None:
            body = ""

    body_lines = [line.strip() for line in body.splitlines() if line.strip()]
    preview_lines = body_lines[:3]
    if preview_lines:
        preview_text = "\n".join(f"    > {line}" for line in preview_lines)
    else:
        preview_text = "    (no body content preview available)"

    # 5. Warning if flagged suspicious
    if not is_suspicious and email:
        if getattr(email, "label", None) == "attack" or getattr(email, "is_suspicious", False):
            is_suspicious = True
        elif isinstance(email, dict) and (email.get("label") == "attack" or email.get("is_suspicious")):
            is_suspicious = True
    if not is_suspicious and ("suspicious" in reason.lower() or "malicious" in reason.lower()):
        is_suspicious = True

    lines = [
        "[APPROVAL REQUIRED]",
        f"Action    : {action_sentence}",
    ]
    if recip_info:
        lines.append(recip_info)
    lines.append(f"Subject   : {subject}")
    lines.append("Preview (first 3 lines):")
    lines.append(preview_text)
    if is_suspicious:
        lines.append("WARNING   : This email was flagged as SUSPICIOUS by the security detector.")
    if reason:
        lines.append(f"Reason    : {reason}")
    lines.append("Approve? [y/N]: ")

    return "\n".join(lines)


class Approval(ABC):
    """Abstract approval gate."""

    @abstractmethod
    def ask(self, tool_call: ToolCall, reason: str, **kwargs: Any) -> bool:
        """Return True if the user approves the tool call."""


# ---------------------------------------------------------------------------
# ScriptedApproval — for evals and tests
# ---------------------------------------------------------------------------


class ScriptedApproval(Approval):
    """Returns preset yes/no answers from a queue.

    If the queue is exhausted, falls back to *default* (False = deny).
    The default in evals is False (user did not request the action).
    """

    def __init__(self, answers: list[bool] | None = None, default: bool = False) -> None:
        self._queue: deque[bool] = deque(answers or [])
        self._default = default

    def ask(self, tool_call: ToolCall, reason: str, **kwargs: Any) -> bool:
        if self._queue:
            return self._queue.popleft()
        return self._default

    def enqueue(self, answer: bool) -> None:
        self._queue.append(answer)


# ---------------------------------------------------------------------------
# CliApproval — interactive terminal prompt
# ---------------------------------------------------------------------------


class CliApproval(Approval):
    """Prompts the user at the terminal and returns their answer."""

    def __init__(self, inbox: Any | None = None) -> None:
        self.inbox = inbox

    def ask(
        self,
        tool_call: ToolCall,
        reason: str,
        *,
        email: Any | None = None,
        subject: str | None = None,
        body: str | None = None,
        recipient: str | None = None,
        is_suspicious: bool = False,
        is_external: bool | None = None,
        **kwargs: Any,
    ) -> bool:
        if email is None and self.inbox is not None:
            email_id = tool_call.arguments.get("email_id")
            if email_id and hasattr(self.inbox, "get"):
                email = self.inbox.get(email_id)

        prompt = format_approval_prompt(
            tool_call,
            reason,
            email=email,
            subject=subject,
            body=body,
            recipient=recipient,
            is_suspicious=is_suspicious,
            is_external=is_external,
        )
        print(f"\n{prompt}", end="")
        try:
            ans = input().strip().lower()
        except (EOFError, KeyboardInterrupt):
            return False

        # Default is strictly "No"
        return ans in ("y", "yes")
