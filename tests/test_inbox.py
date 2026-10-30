"""Tests for MockInbox operations."""

from __future__ import annotations

import pytest

from src.inbox.mock_inbox import MockInbox
from src.models.email import Email


class TestMockInbox:
    def test_list_all(self, mock_inbox: MockInbox):
        emails = mock_inbox.list_all()
        assert len(emails) == 1
        assert emails[0].id == "test_001"

    def test_list_unread(self, mock_inbox: MockInbox):
        unread = mock_inbox.list_unread()
        assert len(unread) == 1

    def test_mark_read_removes_from_unread(self, mock_inbox: MockInbox):
        mock_inbox.mark_read("test_001")
        assert mock_inbox.list_unread() == []

    def test_get_existing(self, mock_inbox: MockInbox):
        email = mock_inbox.get("test_001")
        assert email is not None
        assert email.subject == "Hello"

    def test_get_missing_returns_none(self, mock_inbox: MockInbox):
        assert mock_inbox.get("does_not_exist") is None

    def test_delete(self, mock_inbox: MockInbox):
        mock_inbox.delete("test_001")
        assert mock_inbox.get("test_001") is None
        assert mock_inbox.list_all() == []

    def test_delete_missing_is_noop(self, mock_inbox: MockInbox):
        mock_inbox.delete("nonexistent")  # should not raise
        assert len(mock_inbox.list_all()) == 1

    def test_search_hit(self, mock_inbox: MockInbox):
        results = mock_inbox.search("Hello")
        assert len(results) >= 1

    def test_search_miss(self, mock_inbox: MockInbox):
        results = mock_inbox.search("zzz_nonexistent_query")
        assert results == []

    def test_add_email(self, mock_inbox: MockInbox, make_email):
        new_email = make_email(eid="test_002", subject="New email")
        mock_inbox.add(new_email)
        assert len(mock_inbox.list_all()) == 2

    def test_multiple_unread(self, make_email):
        inbox = MockInbox()
        for i in range(3):
            inbox.add(make_email(eid=f"e{i}"))
        assert len(inbox.list_unread()) == 3
        inbox.mark_read("e0")
        assert len(inbox.list_unread()) == 2
