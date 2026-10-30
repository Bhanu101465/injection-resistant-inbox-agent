"""Tests for NvidiaClient retry logic using a mocked openai.OpenAI."""

from __future__ import annotations

from unittest.mock import MagicMock, patch, call

import pytest


class _FakeRateLimitError(Exception):
    """Simulates openai.RateLimitError (a thin stand-in)."""


class _FakeAPIStatusError(Exception):
    """Simulates openai.APIStatusError."""


class TestNvidiaClientRetry:
    """Verify that _call_with_retry retries on rate-limit errors then succeeds."""

    def _make_client(self):
        """Construct a NvidiaClient with env vars patched so no real key is needed."""
        import os

        env_patch = {
            "NVIDIA_API_KEY": "fake-key",
            "NVIDIA_BASE_URL": "https://fake.example.com/v1",
            "AGENT_MODEL": "test-model",
            "TEMPERATURE": "0",
            "ENABLE_REASONING": "false",
        }
        with patch.dict(os.environ, env_patch):
            # Patch openai so NvidiaClient.__init__ doesn't actually connect
            with patch("src.llm.client.LLMCache"):
                with patch("openai.OpenAI"):
                    from src.llm.client import NvidiaClient

                    client = NvidiaClient(use_cache=False)
        return client

    def test_retry_then_success(self):
        """Mock _call_once to fail twice then succeed; verify 3 total calls."""
        client = self._make_client()

        from src.llm.client import LLMResponse

        success_response = LLMResponse(text="done", tool_calls=[], usage={"total_tokens": 5})

        call_count = 0

        def _call_once_side_effect(messages, tools):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise _FakeRateLimitError("rate limited")
            return success_response

        # Patch the exception types so the retry catches our fake errors
        with patch.object(client, "_call_once", side_effect=_call_once_side_effect):
            # Temporarily set the openai attribute so isinstance checks work
            import types

            fake_openai = types.SimpleNamespace(
                RateLimitError=_FakeRateLimitError,
                APIStatusError=_FakeAPIStatusError,
            )
            client._openai = fake_openai

            # Also patch time.sleep to avoid actually waiting
            with patch("src.llm.client.time.sleep"):
                result = client._call_with_retry(
                    messages=[{"role": "user", "content": "hi"}],
                    tools=None,
                )

        assert call_count == 3
        assert result.text == "done"

    def test_all_retries_exhausted_raises(self):
        """If all attempts fail, RuntimeError must be raised."""
        client = self._make_client()

        import types

        fake_openai = types.SimpleNamespace(
            RateLimitError=_FakeRateLimitError,
            APIStatusError=_FakeAPIStatusError,
        )
        client._openai = fake_openai

        def _always_fail(messages, tools):
            raise _FakeRateLimitError("still rate limited")

        with patch.object(client, "_call_once", side_effect=_always_fail):
            with patch("src.llm.client.time.sleep"):
                with pytest.raises(RuntimeError, match="failed after"):
                    client._call_with_retry(
                        messages=[{"role": "user", "content": "hi"}],
                        tools=None,
                    )
