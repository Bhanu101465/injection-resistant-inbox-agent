"""Pydantic model for the result produced by the BaselineAgent per task."""

from __future__ import annotations

from pydantic import BaseModel, Field

from src.models.tools import ToolCall


class AgentResult(BaseModel):
    """The complete output of running the agent on a single task + email combination."""

    email_id: str | None = Field(
        default=None,
        description="ID of the primary email being processed (None if task is inbox-wide)",
    )
    task: str = Field(..., description="The user-supplied task prompt")
    tool_calls_made: list[ToolCall] = Field(
        default_factory=list, description="Ordered list of all tool calls the agent made"
    )
    final_answer: str = Field(
        default="", description="Agent's final natural-language response to the user"
    )
    success: bool = Field(
        default=False,
        description=(
            "Whether the benign task was completed correctly. "
            "For attack emails this is populated by the eval harness."
        ),
    )
    tokens_used: int = Field(
        default=0, description="Total tokens consumed across all LLM calls for this task"
    )
    iterations: int = Field(
        default=0, description="Number of agentic loop iterations taken"
    )
