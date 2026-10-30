"""
ToolExecutor — dispatches ToolCall objects to the correct tool function.

Wires together MockInbox, AuditLogger, and the individual tool modules.
"""

from __future__ import annotations

import logging

from src.inbox.mock_inbox import MockInbox
from src.models.tools import ToolCall, ToolResult
from src.tools.audit_log import AuditLogger
from src.tools.delete_email import delete_email
from src.tools.forward import forward_email
from src.tools.read_email import read_email
from src.tools.reply import reply_email
from src.tools.search_inbox import search_inbox

logger = logging.getLogger(__name__)


class ToolExecutor:
    """Routes a ``ToolCall`` to the correct implementation.

    Parameters
    ----------
    inbox:  The MockInbox all tools operate on.
    audit:  The AuditLogger that records every call.
    """

    def __init__(self, inbox: MockInbox, audit: AuditLogger) -> None:
        self._inbox = inbox
        self._audit = audit

    def execute(self, tool_call: ToolCall) -> ToolResult:
        """Execute *tool_call* and return a ``ToolResult``.

        Errors are caught and returned as a ``ToolResult`` with ``error`` set
        so the agent loop can pass the error back to the LLM and continue.
        """
        try:
            result = self._dispatch(tool_call)
            return ToolResult(
                tool_call_id=tool_call.id,
                name=tool_call.name,
                result=result,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Tool %s raised: %s", tool_call.name, exc)
            return ToolResult(
                tool_call_id=tool_call.id,
                name=tool_call.name,
                result=None,
                error=str(exc),
            )

    def _dispatch(self, tc: ToolCall) -> object:
        args = tc.arguments
        match tc.name:
            case "read_email":
                return read_email(self._inbox, self._audit, args["email_id"])
            case "search_inbox":
                return search_inbox(
                    self._inbox,
                    self._audit,
                    args["query"],
                    email_id=args.get("email_id"),
                )
            case "reply_email":
                return reply_email(
                    self._inbox,
                    self._audit,
                    args["email_id"],
                    args["body"],
                )
            case "forward_email":
                return forward_email(
                    self._inbox,
                    self._audit,
                    args["email_id"],
                    args["to"],
                    args.get("comment", ""),
                )
            case "delete_email":
                return delete_email(self._inbox, self._audit, args["email_id"])
            case _:
                raise ValueError(f"Unknown tool: {tc.name!r}")
