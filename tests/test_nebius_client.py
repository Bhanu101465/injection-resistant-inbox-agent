"""Tests for NebiusClient using fake mocked responses (no real API calls)."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest
from openai import APIConnectionError, RateLimitError

from src.llm.client import get_default_llm
from src.llm.nebius_client import NebiusClient
from src.models.tools import ToolCall


def _make_fake_completion(content="Hello from fake Nebius!", tool_calls=None):
    choice = MagicMock()
    choice.message.content = content
    choice.message.tool_calls = tool_calls

    usage = MagicMock()
    usage.prompt_tokens = 10
    usage.completion_tokens = 5
    usage.total_tokens = 15

    completion = MagicMock()
    completion.choices = [choice]
    completion.usage = usage
    return completion


class TestNebiusClient:
    def test_init_reads_from_env_or_params(self, monkeypatch):
        monkeypatch.setenv("NEBIUS_API_KEY", "test-secret-key-12345")
        monkeypatch.setenv("NEBIUS_MODEL_ID", "nvidia/test-model")
        with patch("openai.OpenAI"):
            client = NebiusClient(use_cache=False)
            assert client.model == "nvidia/test-model"
            assert client.base_url == "https://api.tokenfactory.nebius.com/v1/"
            assert client.timeout == 30.0

    def test_init_raises_without_api_key(self, monkeypatch):
        monkeypatch.delenv("NEBIUS_API_KEY", raising=False)
        monkeypatch.setenv("NEBIUS_MODEL_ID", "nvidia/test-model")
        with pytest.raises(ValueError, match="NEBIUS_API_KEY must be set"):
            NebiusClient(api_key="", use_cache=False)

    def test_init_raises_without_model_id(self, monkeypatch):
        monkeypatch.setenv("NEBIUS_API_KEY", "test-key")
        monkeypatch.delenv("NEBIUS_MODEL_ID", raising=False)
        with pytest.raises(ValueError, match="NEBIUS_MODEL_ID must be set"):
            NebiusClient(model="", use_cache=False)

    def test_api_key_never_printed_or_in_repr(self, monkeypatch):
        secret = "secret-token-xyz-987"
        monkeypatch.setenv("NEBIUS_API_KEY", secret)
        monkeypatch.setenv("NEBIUS_MODEL_ID", "nvidia/test-model")
        with patch("openai.OpenAI"):
            client = NebiusClient(use_cache=False)
            assert secret not in repr(client)
            assert secret not in str(client)

    def test_fake_text_response_and_usage(self):
        mock_openai = MagicMock()
        mock_openai.chat.completions.create.return_value = _make_fake_completion("Test response")

        client = NebiusClient(
            api_key="key",
            model="test-model",
            use_cache=False,
            openai_client=mock_openai,
        )

        response = client.generate([{"role": "user", "content": "Hi"}])
        assert response.text == "Test response"
        assert response.tool_calls == []
        assert response.usage["total_tokens"] == 15

    def test_fake_tool_calls_parsed_correctly(self):
        mock_tc = MagicMock()
        mock_tc.id = "call_99"
        mock_tc.function.name = "forward_email"
        mock_tc.function.arguments = '{"email_id": "em_1", "to": "alice@acme.test"}'

        mock_openai = MagicMock()
        mock_openai.chat.completions.create.return_value = _make_fake_completion(
            content="", tool_calls=[mock_tc]
        )

        client = NebiusClient(
            api_key="key",
            model="test-model",
            use_cache=False,
            openai_client=mock_openai,
        )

        tools = [
            {
                "type": "function",
                "function": {
                    "name": "forward_email",
                    "description": "Forward an email",
                    "parameters": {"type": "object"},
                },
            }
        ]

        response = client.generate([{"role": "user", "content": "Forward email 1"}], tools=tools)
        assert len(response.tool_calls) == 1
        tc = response.tool_calls[0]
        assert tc.id == "call_99"
        assert tc.name == "forward_email"
        assert tc.arguments == {"email_id": "em_1", "to": "alice@acme.test"}

    def test_timeout_and_tools_passed_to_openai_create(self):
        mock_openai = MagicMock()
        mock_openai.chat.completions.create.return_value = _make_fake_completion("OK")

        client = NebiusClient(
            api_key="key",
            model="test-model",
            timeout=45.0,
            use_cache=False,
            openai_client=mock_openai,
        )

        tools = [{"type": "function", "function": {"name": "search_inbox"}}]
        client.generate([{"role": "user", "content": "search"}], tools=tools)

        mock_openai.chat.completions.create.assert_called_once()
        _, kwargs = mock_openai.chat.completions.create.call_args
        assert kwargs["timeout"] == 45.0
        assert kwargs["tools"] == tools
        assert kwargs["tool_choice"] == "auto"

    def test_two_retries_then_success(self):
        mock_openai = MagicMock()
        fake_rate_limit = RateLimitError(
            message="Rate limit reached", response=MagicMock(status_code=429), body=None
        )
        fake_conn_error = APIConnectionError(request=MagicMock())

        success_completion = _make_fake_completion("Recovered after 2 retries")

        mock_openai.chat.completions.create.side_effect = [
            fake_rate_limit,
            fake_conn_error,
            success_completion,
        ]

        client = NebiusClient(
            api_key="key",
            model="test-model",
            use_cache=False,
            openai_client=mock_openai,
        )

        with patch("time.sleep"):
            res = client.generate([{"role": "user", "content": "ping"}])

        assert res.text == "Recovered after 2 retries"
        assert mock_openai.chat.completions.create.call_count == 3

    def test_retries_exhausted_raises_runtime_error(self):
        mock_openai = MagicMock()
        fake_rate_limit = RateLimitError(
            message="Rate limit", response=MagicMock(status_code=429), body=None
        )
        mock_openai.chat.completions.create.side_effect = fake_rate_limit

        client = NebiusClient(
            api_key="key",
            model="test-model",
            use_cache=False,
            openai_client=mock_openai,
        )

        with patch("time.sleep"):
            with pytest.raises(RuntimeError, match="Nebius API failed after 2 retries"):
                client.generate([{"role": "user", "content": "ping"}])

        assert mock_openai.chat.completions.create.call_count == 3

    def test_switch_between_mock_and_real_with_one_setting(self, monkeypatch):
        # 1. Setting LLM_PROVIDER=mock -> returns GullibleMockLLM
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        mock_llm = get_default_llm()
        from src.llm.mock_llm import GullibleMockLLM
        assert isinstance(mock_llm, GullibleMockLLM)

        # 2. Setting LLM_PROVIDER=nebius -> returns NebiusClient
        monkeypatch.setenv("LLM_PROVIDER", "nebius")
        monkeypatch.setenv("NEBIUS_API_KEY", "key")
        monkeypatch.setenv("NEBIUS_MODEL_ID", "test-model")
        with patch("openai.OpenAI"):
            real_llm = get_default_llm(use_cache=False)
            assert isinstance(real_llm, NebiusClient)

