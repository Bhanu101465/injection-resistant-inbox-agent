"""Pydantic models for LLM tool calls and results."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ToolCall(BaseModel):
    """A tool invocation requested by the LLM."""

    id: str = Field(..., description="Unique tool-call ID (from LLM response)")
    name: str = Field(..., description="Tool/function name to invoke")
    arguments: dict[str, Any] = Field(
        default_factory=dict, description="Parsed JSON arguments for the tool"
    )


class ToolResult(BaseModel):
    """The result returned after executing a ToolCall."""

    tool_call_id: str = Field(..., description="Matches ToolCall.id")
    name: str = Field(..., description="Tool name that was executed")
    result: Any = Field(default=None, description="Return value from the tool")
    error: str | None = Field(
        default=None, description="Error message if the tool raised an exception"
    )
