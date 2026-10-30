"""
LLM client layer — abstract base + NVIDIA NIM implementation.

Architecture
------------
LLMClient (ABC)
    generate(messages, tools) -> LLMResponse

NvidiaClient(LLMClient)
    - Uses openai.OpenAI(base_url=...) for NVIDIA-compatible inference
    - Auto-converts src/tools ToolDefinition list to OpenAI schema
    - Retry with exponential back-off on 429 / 5xx
    - SQLite disk cache (bypass with --no-cache)
    - Usage/token tracking via RunStats singleton
    - Reasoning toggle (ENABLE_REASONING env var)

MockLLM(LLMClient)   <- see mock_llm.py
"""

from __future__ import annotations

import json
import logging
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from dotenv import load_dotenv
from pydantic import BaseModel

from src.llm.cache import LLMCache
from src.models.tools import ToolCall

load_dotenv()

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Response model
# ---------------------------------------------------------------------------


class LLMResponse(BaseModel):
    """The normalised output of a single LLM call."""

    text: str = ""
    """Final assistant text (empty if the model only returned tool calls)."""

    reasoning_text: str | None = None
    """Chain-of-thought / thinking text, if the model returned it.
    This is NEVER written to the audit log as if it were agent output."""

    tool_calls: list[ToolCall] = []
    """Tool invocations requested by the model (may be empty)."""

    usage: dict = {}
    """Raw token-usage dict from the provider, e.g. {'total_tokens': 123}."""


# ---------------------------------------------------------------------------
# Run-level statistics singleton
# ---------------------------------------------------------------------------


@dataclass
class RunStats:
    """Accumulates LLM usage statistics across a single eval run."""

    total_tokens: int = 0
    call_count: int = 0
    cache_hits: int = 0

    def record(self, usage: dict, *, from_cache: bool = False) -> None:
        self.call_count += 1
        self.total_tokens += usage.get("total_tokens", 0)
        if from_cache:
            self.cache_hits += 1

    def summary(self) -> str:
        return (
            f"LLM calls: {self.call_count} | "
            f"tokens: {self.total_tokens} | "
            f"cache hits: {self.cache_hits}"
        )


# Module-level default stats object; reset between runs if needed.
_run_stats = RunStats()


def get_run_stats() -> RunStats:
    """Return the module-level RunStats accumulator."""
    return _run_stats


def reset_run_stats() -> None:
    """Reset run-level counters (call at the start of each eval run)."""
    global _run_stats
    _run_stats = RunStats()


# ---------------------------------------------------------------------------
# Abstract base class
# ---------------------------------------------------------------------------


class LLMClient(ABC):
    """Provider-agnostic LLM interface."""

    @abstractmethod
    def generate(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
    ) -> LLMResponse:
        """Send *messages* to the model and return a normalised response.

        Parameters
        ----------
        messages:
            OpenAI-format message list, e.g.
            ``[{"role": "user", "content": "hello"}]``.
        tools:
            Optional list of OpenAI-format tool/function definitions.
            ``None`` means no tool calling.

        Returns
        -------
        LLMResponse
            Normalised response with text, optional reasoning, tool calls,
            and usage stats.
        """


# ---------------------------------------------------------------------------
# NVIDIA / OpenAI-compatible client
# ---------------------------------------------------------------------------


class NvidiaClient(LLMClient):
    """LLM client backed by the NVIDIA NIM API via the openai SDK.

    All configuration is read from environment variables so no model names
    or credentials are hard-coded in this file.

    Environment variables
    ---------------------
    NVIDIA_API_KEY         : Required — your NVIDIA NIM API key.
    NVIDIA_BASE_URL        : Default https://integrate.api.nvidia.com/v1
    AGENT_MODEL            : Model ID to use (required).
    TEMPERATURE            : Sampling temperature (default 0).
    ENABLE_REASONING       : 'true'/'false' — add thinking budget (default false).
    LLM_CACHE_PATH         : Path to SQLite cache file (default llm_cache.db).
    """

    _MAX_RETRIES = 5
    _RETRY_BASE_DELAY = 1.0  # seconds

    def __init__(
        self,
        *,
        use_cache: bool = True,
        cache_path: str | None = None,
        model: str | None = None,
    ) -> None:
        # Lazy import to keep the module importable without openai installed in
        # environments that only use MockLLM.
        try:
            import openai  # noqa: PLC0415
        except ImportError as exc:
            raise ImportError(
                "The 'openai' package is required for NvidiaClient. "
                "Install it with: pip install openai"
            ) from exc

        self._openai = openai

        api_key = os.environ.get("NVIDIA_API_KEY", "")
        base_url = os.environ.get("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1")
        self.model: str = model or os.environ.get("AGENT_MODEL", "")
        if not self.model:
            raise ValueError(
                "AGENT_MODEL env var must be set (or pass model= to NvidiaClient)."
            )

        self.temperature: float = float(os.environ.get("TEMPERATURE", "0"))
        self.enable_reasoning: bool = (
            os.environ.get("ENABLE_REASONING", "false").strip().lower() == "true"
        )

        self._client = openai.OpenAI(api_key=api_key, base_url=base_url)

        # Cache setup
        _cache_path = cache_path or os.environ.get("LLM_CACHE_PATH", "llm_cache.db")
        self._cache = LLMCache(db_path=_cache_path, enabled=use_cache)
        self._stats = get_run_stats()

        logger.info(
            "NvidiaClient ready | model=%s | temperature=%s | reasoning=%s | cache=%s",
            self.model,
            self.temperature,
            self.enable_reasoning,
            use_cache,
        )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def generate(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
    ) -> LLMResponse:
        """Call the NVIDIA API and return a normalised LLMResponse."""
        cache_key = self._cache.make_key(
            self.model, messages, tools, self.temperature, self.enable_reasoning
        )

        # Try cache first
        cached = self._cache.get(cache_key)
        if cached is not None:
            response = LLMResponse.model_validate_json(cached)
            self._stats.record(response.usage, from_cache=True)
            return response

        # Live API call (with retry)
        response = self._call_with_retry(messages, tools)

        # Store to cache
        self._cache.set(cache_key, response.model_dump_json())
        self._stats.record(response.usage, from_cache=False)
        return response

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _call_with_retry(
        self, messages: list[dict], tools: list[dict] | None
    ) -> LLMResponse:
        """Call the API with exponential back-off on 429 / 5xx errors."""
        openai = self._openai
        last_exc: Exception | None = None

        for attempt in range(self._MAX_RETRIES):
            try:
                return self._call_once(messages, tools)
            except (
                openai.RateLimitError,
                openai.APIStatusError,
            ) as exc:
                last_exc = exc
                delay = self._RETRY_BASE_DELAY * (2 ** attempt)
                logger.warning(
                    "LLM API error on attempt %d/%d: %s — retrying in %.1fs",
                    attempt + 1,
                    self._MAX_RETRIES,
                    exc,
                    delay,
                )
                time.sleep(delay)

        raise RuntimeError(
            f"LLM API failed after {self._MAX_RETRIES} retries. "
            f"Last error: {last_exc}"
        ) from last_exc

    def _call_once(
        self, messages: list[dict], tools: list[dict] | None
    ) -> LLMResponse:
        """Make a single, non-retried API call and parse the response."""
        kwargs: dict = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        if self.enable_reasoning:
            # Inject thinking budget; silently ignored by models that don't
            # support it (they'll return a normal response).
            kwargs["extra_body"] = {
                "thinking": {"type": "enabled", "budget_tokens": 2048}
            }

        completion = self._client.chat.completions.create(**kwargs)
        return self._parse_completion(completion)

    def _parse_completion(self, completion) -> LLMResponse:  # type: ignore[no-untyped-def]
        """Convert an openai Completion object into an LLMResponse."""
        msg = completion.choices[0].message

        # Extract reasoning if the model returned it (field name varies)
        reasoning: str | None = None
        for attr in ("reasoning_content", "thinking"):
            val = getattr(msg, attr, None)
            if val:
                reasoning = str(val)
                break

        # Extract tool calls
        tool_calls: list[ToolCall] = []
        if msg.tool_calls:
            for tc in msg.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except (json.JSONDecodeError, AttributeError):
                    args = {}
                tool_calls.append(
                    ToolCall(id=tc.id, name=tc.function.name, arguments=args)
                )

        # Usage
        usage: dict = {}
        if completion.usage:
            usage = {
                "prompt_tokens": completion.usage.prompt_tokens,
                "completion_tokens": completion.usage.completion_tokens,
                "total_tokens": completion.usage.total_tokens,
            }

        return LLMResponse(
            text=msg.content or "",
            reasoning_text=reasoning,
            tool_calls=tool_calls,
            usage=usage,
        )



def get_default_llm(*, use_cache: bool = True) -> LLMClient:
    """Return the configured LLM client based on the LLM_PROVIDER setting.

    Set LLM_PROVIDER in .env:
      LLM_PROVIDER=nebius   -> NebiusClient (real model)
      LLM_PROVIDER=mock     -> GullibleMockLLM (default mock model)
      LLM_PROVIDER=nvidia   -> NvidiaClient
    """
    provider = os.environ.get("LLM_PROVIDER", "").strip().lower()
    if provider in ("nebius", "real"):
        from src.llm.nebius_client import NebiusClient
        return NebiusClient(use_cache=use_cache)
    if provider == "nvidia":
        return NvidiaClient(use_cache=use_cache)
    from src.llm.mock_llm import GullibleMockLLM
    return GullibleMockLLM()
