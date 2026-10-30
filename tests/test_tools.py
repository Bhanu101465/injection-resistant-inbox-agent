"""Tests for individual tool functions: read_email, search_inbox, reply, forward, delete."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.inbox.mock_inbox import MockInbox
from src.tools.audit_log import AuditLogger
from src.tools.delete_email import delete_email
from src.tools.forward import forward_email
from src.tools.read_email import read_email
from src.tools.reply import reply_email
from src.tools.search_inbox import search_inbox


class TestReadEmail:
    def test_marks_read(self, mock_inbox: MockInbox, audit_logger: AuditLogger):
        read_email(mock_inbox, audit_logger, "test_001")
        assert mock_inbox.get("test_001").is_read is True  # type: ignore

    def test_returns_content(self, mock_inbox: MockInbox, audit_logger: AuditLogger):
        result = read_email(mock_inbox, audit_logger, "test_001")
        assert "Hello" in result  # subject appears in output

    def test_audit_entry_created(self, mock_inbox: MockInbox, audit_logger: AuditLogger):
        read_email(mock_inbox, audit_logger, "test_001")
        entries = audit_logger.read_all()
        assert len(entries) == 1
        assert entries[0]["tool"] == "read_email"

    def test_missing_email_returns_error(self, mock_inbox: MockInbox, audit_logger: AuditLogger):
        result = read_email(mock_inbox, audit_logger, "nonexistent")
        assert "not found" in result.lower() or "error" in result.lower()


class TestSearchInbox:
    def test_hit(self, mock_inbox: MockInbox, audit_logger: AuditLogger):
        results = search_inbox(mock_inbox, audit_logger, "Hello")
        assert isinstance(results, list)
        assert len(results) >= 1

    def test_miss(self, mock_inbox: MockInbox, audit_logger: AuditLogger):
        results = search_inbox(mock_inbox, audit_logger, "zzz_no_match")
        assert results == []

    def test_audit_entry(self, mock_inbox: MockInbox, audit_logger: AuditLogger):
        search_inbox(mock_inbox, audit_logger, "test")
        entries = audit_logger.read_all()
        assert any(e["tool"] == "search_inbox" for e in entries)


class TestReplyEmail:
    def test_reply_logged(self, mock_inbox: MockInbox, audit_logger: AuditLogger):
        result = reply_email(mock_inbox, audit_logger, "test_001", "Thanks!")
        assert isinstance(result, str)
        entries = audit_logger.read_all()
        assert any(e["tool"] == "reply_email" for e in entries)

    def test_reply_args_in_log(self, mock_inbox: MockInbox, audit_logger: AuditLogger):
        reply_email(mock_inbox, audit_logger, "test_001", "Hello back")
        entries = audit_logger.read_all()
        reply_entries = [e for e in entries if e["tool"] == "reply_email"]
        assert len(reply_entries) == 1
        assert reply_entries[0]["args"].get("email_id") == "test_001"


class TestForwardEmail:
    def test_forward_logged(self, mock_inbox: MockInbox, audit_logger: AuditLogger):
        result = forward_email(mock_inbox, audit_logger, "test_001", "bob@acme.test")
        assert isinstance(result, str)
        entries = audit_logger.read_all()
        assert any(e["tool"] == "forward_email" for e in entries)

    def test_forward_to_in_log(self, mock_inbox: MockInbox, audit_logger: AuditLogger):
        forward_email(mock_inbox, audit_logger, "test_001", "target@example.com", comment="FYI")
        entries = audit_logger.read_all()
        fwd = [e for e in entries if e["tool"] == "forward_email"][0]
        assert fwd["args"]["to"] == "target@example.com"


class TestDeleteEmail:
    def test_delete_removes_email(self, mock_inbox: MockInbox, audit_logger: AuditLogger):
        delete_email(mock_inbox, audit_logger, "test_001")
        assert mock_inbox.get("test_001") is None

    def test_delete_logged(self, mock_inbox: MockInbox, audit_logger: AuditLogger):
        delete_email(mock_inbox, audit_logger, "test_001")
        entries = audit_logger.read_all()
        assert any(e["tool"] == "delete_email" for e in entries)
