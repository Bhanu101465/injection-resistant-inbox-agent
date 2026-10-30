"""Tests for LLMCache: set/get round-trip, collision, and clear."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.llm.cache import LLMCache


@pytest.fixture()
def cache(tmp_path: Path) -> LLMCache:
    return LLMCache(db_path=tmp_path / "test_cache.db", enabled=True)


@pytest.fixture()
def disabled_cache(tmp_path: Path) -> LLMCache:
    return LLMCache(db_path=tmp_path / "noop.db", enabled=False)


class TestLLMCache:
    def test_set_and_get_roundtrip(self, cache: LLMCache):
        cache.set("key1", '{"text": "hello"}')
        result = cache.get("key1")
        assert result == '{"text": "hello"}'

    def test_miss_returns_none(self, cache: LLMCache):
        assert cache.get("nonexistent_key") is None

    def test_key_collision_returns_cached(self, cache: LLMCache):
        cache.set("key2", "first_value")
        cache.set("key2", "second_value")  # REPLACE
        result = cache.get("key2")
        assert result == "second_value"

    def test_clear_invalidates(self, cache: LLMCache):
        cache.set("key3", "some_data")
        removed = cache.clear()
        assert removed >= 1
        assert cache.get("key3") is None

    def test_disabled_get_always_none(self, disabled_cache: LLMCache):
        # Even if we try to set, it should be a no-op
        disabled_cache.set("k", "v")
        assert disabled_cache.get("k") is None

    def test_disabled_clear_returns_zero(self, disabled_cache: LLMCache):
        count = disabled_cache.clear()
        assert count == 0

    def test_make_key_is_deterministic(self, cache: LLMCache):
        messages = [{"role": "user", "content": "hello"}]
        k1 = cache.make_key("model-x", messages, None, 0.0, False)
        k2 = cache.make_key("model-x", messages, None, 0.0, False)
        assert k1 == k2

    def test_make_key_differs_on_model(self, cache: LLMCache):
        messages = [{"role": "user", "content": "hello"}]
        k1 = cache.make_key("model-a", messages, None, 0.0, False)
        k2 = cache.make_key("model-b", messages, None, 0.0, False)
        assert k1 != k2
