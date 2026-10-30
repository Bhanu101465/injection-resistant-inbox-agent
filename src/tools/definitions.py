"""
Tool definitions — one ToolDefinition per callable tool.

``ALL_TOOLS`` is the canonical registry; ``get_tool_schemas()`` converts it
to the OpenAI-format ``tools`` list for injection into LLM calls.
"""

from __future__ import annotations

from pydantic import BaseModel


class ToolDefinition(BaseModel):
    """Schema for a single callable tool."""

    name: str
    description: str
    parameters: dict  # JSON Schema object
    risk_level: str = "low"
    """Risk classification: 'low' for read-only operations, 'high' for
    operations that mutate external state (send, delete, forward)."""
    


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------

ALL_TOOLS: list[ToolDefinition] = [
    ToolDefinition(
        name="read_email",
        description=(
            "Read the full content of an email by its ID and mark it as read. "
            "Returns the email subject, sender, body, and attachment text."
        ),
        parameters={
            "type": "object",
            "properties": {
                "email_id": {
                    "type": "string",
                    "description": "The unique ID of the email to read.",
                }
            },
            "required": ["email_id"],
        },
        risk_level="low",
    ),
    ToolDefinition(
        name="search_inbox",
        description=(
            "Search the inbox for emails matching a keyword query. "
            "Searches across subject, sender, and body text. "
            "Returns a list of matching email summaries."
        ),
        parameters={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Keyword or phrase to search for.",
                }
            },
            "required": ["query"],
        },
        risk_level="low",
    ),
    ToolDefinition(
        name="reply_email",
        description=(
            "Send a reply to an email. "
            "The reply will be sent from the user's address to the original sender."
        ),
        parameters={
            "type": "object",
            "properties": {
                "email_id": {
                    "type": "string",
                    "description": "ID of the email to reply to.",
                },
                "body": {
                    "type": "string",
                    "description": "Plain-text body of the reply.",
                },
            },
            "required": ["email_id", "body"],
        },
        risk_level="high",
    ),
    ToolDefinition(
        name="forward_email",
        description=(
            "Forward an email to one or more recipients. "
            "Optionally include a comment prepended to the forwarded body."
        ),
        parameters={
            "type": "object",
            "properties": {
                "email_id": {
                    "type": "string",
                    "description": "ID of the email to forward.",
                },
                "to": {
                    "type": "string",
                    "description": "Recipient email address to forward to.",
                },
                "comment": {
                    "type": "string",
                    "description": "Optional comment to prepend.",
                    "default": "",
                },
            },
            "required": ["email_id", "to"],
        },
        risk_level="high",
    ),
    ToolDefinition(
        name="delete_email",
        description=(
            "Permanently delete an email from the inbox by its ID. "
            "This action cannot be undone."
        ),
        parameters={
            "type": "object",
            "properties": {
                "email_id": {
                    "type": "string",
                    "description": "ID of the email to delete.",
                }
            },
            "required": ["email_id"],
        },
        risk_level="high",
    ),
]

# Lookup by name for the executor
TOOL_BY_NAME: dict[str, ToolDefinition] = {t.name: t for t in ALL_TOOLS}


def get_tool_schemas() -> list[dict]:
    """Return the OpenAI-compatible ``tools`` list for all registered tools."""
    return [
        {
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.parameters,
            },
        }
        for tool in ALL_TOOLS
    ]
