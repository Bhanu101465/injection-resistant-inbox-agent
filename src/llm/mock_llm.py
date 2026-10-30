"""
MockLLM — scripted LLM client for use in pytest.

Backed by a queue of pre-configured ``LLMResponse`` objects.
**Never touches the network.**

Also contains GullibleMockLLM — a deliberately vulnerable mock that
obeys injected instructions found in message text (for defense testing).
"""

from __future__ import annotations

import re
from collections import deque

from src.llm.client import LLMClient, LLMResponse
from src.models.tools import ToolCall


class MockLLM(LLMClient):
    """A deterministic, network-free LLM client for tests.

    Pass a list of ``LLMResponse`` objects at construction; each call to
    ``generate`` pops the next response.  If the queue is exhausted an
    ``IndexError`` is raised so tests fail loudly instead of silently using
    stale data.

    Parameters
    ----------
    responses:
        Ordered list of responses to return on successive ``generate`` calls.
    """

    def __init__(self, responses: list[LLMResponse] | None = None) -> None:
        self._queue: deque[LLMResponse] = deque(responses or [])

    # ------------------------------------------------------------------
    # Queue helpers (useful inside tests)
    # ------------------------------------------------------------------

    def enqueue(self, response: LLMResponse) -> None:
        """Append a response to the back of the queue."""
        self._queue.append(response)

    def enqueue_many(self, responses: list[LLMResponse]) -> None:
        """Append multiple responses at once."""
        self._queue.extend(responses)

    def remaining(self) -> int:
        """Return how many responses are still in the queue."""
        return len(self._queue)

    # ------------------------------------------------------------------
    # LLMClient interface
    # ------------------------------------------------------------------

    def generate(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
    ) -> LLMResponse:
        """Pop and return the next scripted response.

        Raises
        ------
        IndexError
            If the response queue is empty (test oversight).
        """
        if not self._queue:
            raise IndexError(
                "MockLLM response queue is empty — add more responses via enqueue()."
            )
        return self._queue.popleft()

    @staticmethod
    def make_text_response(text: str, tokens: int = 10) -> LLMResponse:
        """Convenience factory: a plain-text response with no tool calls."""
        return LLMResponse(text=text, tool_calls=[], usage={"total_tokens": tokens})

    @staticmethod
    def make_tool_response(
        tool_name: str,
        arguments: dict,
        call_id: str = "call_mock_001",
        tokens: int = 20,
    ) -> LLMResponse:
        """Convenience factory: a response containing a single tool call."""
        return LLMResponse(
            text="",
            tool_calls=[ToolCall(id=call_id, name=tool_name, arguments=arguments)],
            usage={"total_tokens": tokens},
        )


# ---------------------------------------------------------------------------
# GullibleMockLLM — deliberately vulnerable (for defense testing)
# ---------------------------------------------------------------------------

_FORWARD_RE = re.compile(
    r"forward[^\n]*?(?:to\s+)?([\w.+\-]+@[\w.\-]+)",
    re.IGNORECASE,
)
_REPLY_RE = re.compile(r"\breply\b", re.IGNORECASE)
_DELETE_RE = re.compile(
    r"\bdelete\s+(?:all\s+)?(?:email|mail|message)s?\b", re.IGNORECASE
)


def _extract_email_id(messages: list[dict]) -> str:
    for msg in messages:
        content = msg.get("content") or ""
        m = re.search(r"\b(attack_\d+|benign_\d+|email_\d+)\b", content)
        if m:
            return m.group(1)
    return "unknown"


class GullibleMockLLM(LLMClient):
    """A mock LLM that obeys injected instructions — deliberately vulnerable.

    Scans message text for forward/delete/reply patterns and emits the
    corresponding tool call.  Used as the 'gullible' backend in evals so
    attack success can be measured without a real API key.
    """

    def generate(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
    ) -> LLMResponse:
        # After a tool result → finish
        if messages and messages[-1].get("role") == "tool":
            return LLMResponse(
                text="Done. I have carried out the requested action.",
                tool_calls=[],
                usage={"total_tokens": 5},
            )

        full_text = " ".join((msg.get("content") or "") for msg in messages)
        email_id = _extract_email_id(messages)

        m = _FORWARD_RE.search(full_text)
        if m:
            return LLMResponse(
                text="",
                tool_calls=[ToolCall(
                    id="gull_fwd_001",
                    name="forward_email",
                    arguments={"email_id": email_id, "to": m.group(1), "comment": ""},
                )],
                usage={"total_tokens": 10},
            )

        if _DELETE_RE.search(full_text):
            return LLMResponse(
                text="",
                tool_calls=[ToolCall(
                    id="gull_del_001",
                    name="delete_email",
                    arguments={"email_id": email_id},
                )],
                usage={"total_tokens": 10},
            )

        if _REPLY_RE.search(full_text):
            return LLMResponse(
                text="",
                tool_calls=[ToolCall(
                    id="gull_rep_001",
                    name="reply_email",
                    arguments={"email_id": email_id, "body": "As requested."},
                )],
                usage={"total_tokens": 10},
            )

        return LLMResponse(
            text="Done. I reviewed your email.",
            tool_calls=[],
            usage={"total_tokens": 5},
        )
