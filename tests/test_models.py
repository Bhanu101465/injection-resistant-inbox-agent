"""Tests for Pydantic data models: Email, Attachment, ToolCall, AgentResult."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.models.email import Attachment, Email, ExtractedEmail
from src.models.tools import ToolCall, ToolResult
from src.models.agent import AgentResult


# ---------------------------------------------------------------------------
# Attachment
# ---------------------------------------------------------------------------


class TestAttachment:
    def test_basic_construction(self):
        att = Attachment(filename="report.pdf", content_type="application/pdf")
        assert att.filename == "report.pdf"
        assert att.content_text == ""

    def test_with_content(self):
        att = Attachment(
            filename="notes.txt",
            content_type="text/plain",
            content_text="Some extracted text",
        )
        assert att.content_text == "Some extracted text"

    def test_missing_filename_raises(self):
        with pytest.raises(ValidationError):
            Attachment(content_type="text/plain")  # type: ignore


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------


class TestEmail:
    def test_valid_email(self, sample_email: Email):
        assert sample_email.id == "test_001"
        assert sample_email.label == "benign"
        assert sample_email.category is None
        assert sample_email.attacker_goal is None

    def test_alias_from(self, make_email):
        """The 'from' alias must work (JSON key is 'from', Python attr is 'from_')."""
        email = make_email(from_="bob@acme.test")
        assert email.from_ == "bob@acme.test"

    def test_defaults(self, sample_email: Email):
        assert sample_email.is_read is False
        assert sample_email.attachments == []
        assert sample_email.cc == []

    def test_taint_field_defaults(self, sample_email: Email):
        """New architecture-prep fields should have sensible defaults."""
        assert sample_email.source_trust == "unknown"
        assert sample_email.provenance == []

    def test_taint_field_explicit(self, make_email):
        email = make_email()
        email_with_taint = email.model_copy(
            update={"source_trust": "untrusted", "provenance": ["smtp:mta.example.com"]}
        )
        assert email_with_taint.source_trust == "untrusted"
        assert "smtp:mta.example.com" in email_with_taint.provenance

    def test_invalid_label_not_rejected(self, make_email):
        """Label is a free-form string — any value is accepted."""
        email = make_email()
        assert email.label == "benign"

    def test_missing_required_id(self):
        with pytest.raises(ValidationError):
            Email.model_validate({
                "from": "x@x.test",
                "subject": "Hi",
                "timestamp": "2026-01-01T00:00:00Z",
            })


# ---------------------------------------------------------------------------
# ExtractedEmail
# ---------------------------------------------------------------------------


class TestExtractedEmail:
    def test_minimal_construction(self):
        ex = ExtractedEmail(email_id="test_001")
        assert ex.email_id == "test_001"
        assert ex.plain_text == ""
        assert ex.source_trust == "unknown"
        assert ex.provenance == []

    def test_full_construction(self):
        ex = ExtractedEmail(
            email_id="test_002",
            subject="Invoice Q4",
            sender="finance@acme.test",
            recipients=["user@acme.test"],
            plain_text="Please find attached the invoice.",
            html_snippet="<p>Please find attached...</p>",
            attachment_texts=["Invoice total: $5,000"],
            source_trust="trusted",
            provenance=["smtp:mta.acme.test", "inbox:mock"],
        )
        assert ex.sender == "finance@acme.test"
        assert ex.source_trust == "trusted"
        assert len(ex.attachment_texts) == 1

    def test_missing_email_id_raises(self):
        with pytest.raises(ValidationError):
            ExtractedEmail()  # type: ignore


# ---------------------------------------------------------------------------
# ToolCall / ToolResult
# ---------------------------------------------------------------------------


class TestToolCall:
    def test_basic(self):
        tc = ToolCall(id="call_001", name="read_email", arguments={"email_id": "e1"})
        assert tc.name == "read_email"
        assert tc.arguments["email_id"] == "e1"

    def test_empty_arguments_default(self):
        tc = ToolCall(id="call_002", name="search_inbox")
        assert tc.arguments == {}

    def test_missing_required_fields(self):
        with pytest.raises(ValidationError):
            ToolCall(arguments={})  # type: ignore


class TestToolResult:
    def test_success(self):
        tr = ToolResult(tool_call_id="call_001", name="read_email", result="Email body")
        assert tr.error is None
        assert tr.result == "Email body"

    def test_error(self):
        tr = ToolResult(tool_call_id="call_001", name="delete_email", error="Not found")
        assert tr.error == "Not found"


# ---------------------------------------------------------------------------
# AgentResult
# ---------------------------------------------------------------------------


class TestAgentResult:
    def test_basic(self):
        ar = AgentResult(task="Summarise inbox")
        assert ar.task == "Summarise inbox"
        assert ar.success is False
        assert ar.tool_calls_made == []

    def test_with_tool_calls(self):
        tc = ToolCall(id="c1", name="read_email", arguments={"email_id": "e1"})
        ar = AgentResult(task="Read email", tool_calls_made=[tc], success=True, tokens_used=42)
        assert len(ar.tool_calls_made) == 1
        assert ar.tokens_used == 42
