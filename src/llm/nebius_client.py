"""
Nebius Token Factory LLM client.

Uses the OpenAI Python SDK targeting https://api.tokenfactory.nebius.com/v1/.
Reads NEBIUS_API_KEY and NEBIUS_MODEL_ID from environment (.env).
Supports OpenAI-compatible function calling (tools), timeout, and 2 retries.
Never prints or logs the API key.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from src.llm.cache import LLMCache
from src.llm.client import LLMClient, LLMResponse, get_run_stats
from src.models.tools import ToolCall

_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(_ROOT / ".env", override=False)

logger = logging.getLogger(__name__)

_DEFAULT_BASE_URL = "https://api.tokenfactory.nebius.com/v1/"
_DEFAULT_TIMEOUT = 30.0
_MAX_RETRIES = 2
_RETRY_BASE_DELAY = 1.0


class NebiusClient(LLMClient):
    """LLM client backed by the Nebius Token Factory API.

    Environment variables
    ---------------------
    NEBIUS_API_KEY   : Required — Nebius API token (never printed or logged).
    NEBIUS_MODEL_ID  : Model identifier (e.g. nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B).
    NEBIUS_BASE_URL  : Base URL (default: https://api.tokenfactory.nebius.com/v1/).
    NEBIUS_TIMEOUT   : Request timeout in seconds (default: 30.0).
    TEMPERATURE      : Sampling temperature (default: 0).
    LLM_CACHE_PATH   : Path to SQLite cache file (default: llm_cache.db).
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
        timeout: float | None = None,
        temperature: float | None = None,
        use_cache: bool = True,
        cache_path: str | None = None,
        openai_client: Any | None = None,
    ) -> None:
        try:
            import openai
        except ImportError as exc:
            raise ImportError(
                "The 'openai' package is required for NebiusClient. "
                "Install it with: pip install openai"
            ) from exc

        self._openai = openai

        raw_key = api_key or os.environ.get("NEBIUS_API_KEY", "")
        self._api_key = raw_key.strip().strip("'\"") if raw_key else ""
        if not self._api_key:
            raise ValueError(
                "NEBIUS_API_KEY must be set in your .env file or passed to NebiusClient."
            )

        raw_model = model or os.environ.get("NEBIUS_MODEL_ID", "")
        self.model = raw_model.strip().strip("'\"") if raw_model else ""
        if not self.model:
            raise ValueError(
                "NEBIUS_MODEL_ID must be set in your .env file or passed to NebiusClient."
            )

        self.base_url = (
            base_url or os.environ.get("NEBIUS_BASE_URL") or _DEFAULT_BASE_URL
        ).rstrip("/") + "/"

        self.timeout = (
            timeout
            if timeout is not None
            else float(os.environ.get("NEBIUS_TIMEOUT", _DEFAULT_TIMEOUT))
        )

        self.temperature = (
            temperature
            if temperature is not None
            else float(os.environ.get("TEMPERATURE", "0"))
        )

        # Allow passing mock client for tests without real API calls
        if openai_client is not None:
            self._client = openai_client
        else:
            self._client = openai.OpenAI(
                api_key=self._api_key,
                base_url=self.base_url,
                timeout=self.timeout,
            )

        _cache_path = cache_path or os.environ.get("LLM_CACHE_PATH", "llm_cache.db")
        self._cache = LLMCache(db_path=_cache_path, enabled=use_cache)
        self._stats = get_run_stats()

        logger.info(
            "NebiusClient initialized | model=%s | base_url=%s | timeout=%.1fs | cache=%s",
            self.model,
            self.base_url,
            self.timeout,
            use_cache,
        )

    def __repr__(self) -> str:
        # Crucial: NEVER display or expose the API key
        return f"<NebiusClient model={self.model!r} base_url={self.base_url!r}>"

    def generate(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
    ) -> LLMResponse:
        """Call Nebius Token Factory and return a normalised LLMResponse."""
        cache_key = self._cache.make_key(
            self.model, messages, tools, self.temperature, False
        )

        cached = self._cache.get(cache_key)
        if cached is not None:
            response = LLMResponse.model_validate_json(cached)
            self._stats.record(response.usage, from_cache=True)
            return response

        response = self._call_with_retry(messages, tools)

        self._cache.set(cache_key, response.model_dump_json())
        self._stats.record(response.usage, from_cache=False)
        return response

    def _call_with_retry(
        self, messages: list[dict], tools: list[dict] | None
    ) -> LLMResponse:
        """Call Nebius API with timeout and 2 retries."""
        openai = self._openai
        retry_errors = (
            openai.RateLimitError,
            openai.APIConnectionError,
            openai.APITimeoutError,
            openai.APIStatusError,
        )

        last_exc: Exception | None = None
        for attempt in range(_MAX_RETRIES + 1):
            try:
                return self._call_once(messages, tools)
            except retry_errors as exc:
                last_exc = exc
                if attempt < _MAX_RETRIES:
                    delay = _RETRY_BASE_DELAY * (2 ** attempt)
                    logger.warning(
                        "Nebius API attempt %d/%d failed: %s. Retrying in %.1fs...",
                        attempt + 1,
                        _MAX_RETRIES + 1,
                        type(exc).__name__,
                        delay,
                    )
                    time.sleep(delay)

        raise RuntimeError(
            f"Nebius API failed after {_MAX_RETRIES} retries. "
            f"Last error: {type(last_exc).__name__}: {last_exc}"
        ) from last_exc

    def _call_once(
        self, messages: list[dict], tools: list[dict] | None
    ) -> LLMResponse:
        kwargs: dict = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "timeout": self.timeout,
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        completion = self._client.chat.completions.create(**kwargs)
        return self._parse_completion(completion)

    def _parse_completion(self, completion: Any) -> LLMResponse:
        msg = completion.choices[0].message

        tool_calls: list[ToolCall] = []
        if getattr(msg, "tool_calls", None):
            for tc in msg.tool_calls:
                fn = getattr(tc, "function", None)
                fn_name = getattr(fn, "name", "")
                raw_args = getattr(fn, "arguments", "{}")
                try:
                    args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
                except Exception:
                    args = {}
                tool_calls.append(
                    ToolCall(id=getattr(tc, "id", "call_1"), name=fn_name, arguments=args)
                )

        usage: dict = {}
        if getattr(completion, "usage", None):
            usage = {
                "prompt_tokens": getattr(completion.usage, "prompt_tokens", 0),
                "completion_tokens": getattr(completion.usage, "completion_tokens", 0),
                "total_tokens": getattr(completion.usage, "total_tokens", 0),
            }

        return LLMResponse(
            text=getattr(msg, "content", "") or "",
            tool_calls=tool_calls,
            usage=usage,
        )

