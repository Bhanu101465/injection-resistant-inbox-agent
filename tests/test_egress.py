"""Tests for src/defense/egress.py — Layer 6: Egress Check."""

from __future__ import annotations

import json
import pytest
from pathlib import Path

from src.inbox.mock_inbox import MockInbox
from src.models.email import Email
from datetime import datetime
from src.defense.egress import (
    EgressAllowlist,
    EgressDecision,
    _clean_address,
    egress_check,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def allowlist(tmp_path: Path) -> EgressAllowlist:
    """Small in-memory allowlist for tests (no real file needed)."""
    data = {
        "allowed_addresses": ["alice@acme.test", "bob@acme.test"],
        "allowed_domains": ["acme.test"],
    }
    p = tmp_path / "allowed_recipients.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return EgressAllowlist(path=p)


# ---------------------------------------------------------------------------
# Address cleaning
# ---------------------------------------------------------------------------


class TestCleanAddress:
    def test_lowercase(self):
        assert _clean_address("Alice@ACME.TEST") == "alice@acme.test"

    def test_strips_whitespace(self):
        assert _clean_address("  alice@acme.test  ") == "alice@acme.test"

    def test_trailing_dot(self):
        assert _clean_address("alice@acme.test.") == "alice@acme.test"

    def test_trailing_comma(self):
        assert _clean_address("alice@acme.test,") == "alice@acme.test"

    def test_trailing_semicolon(self):
        assert _clean_address("alice@acme.test;") == "alice@acme.test"

    def test_display_name_format(self):
        assert _clean_address("Alice Morgan <alice@acme.test>") == "alice@acme.test"

    def test_display_name_with_trailing_dot(self):
        assert _clean_address("Alice Morgan <alice@acme.test.>") == "alice@acme.test"

    def test_angle_brackets_only(self):
        assert _clean_address("<alice@acme.test>") == "alice@acme.test"


# ---------------------------------------------------------------------------
# Allowlist matching
# ---------------------------------------------------------------------------


class TestEgressAllowlist:
    def test_exact_address_allowed(self, allowlist):
        assert allowlist.is_allowed("alice@acme.test") is True

    def test_domain_match_allowed(self, allowlist):
        # Any @acme.test address (not just the two explicit ones)
        assert allowlist.is_allowed("newperson@acme.test") is True

    def test_unknown_address_blocked(self, allowlist):
        assert allowlist.is_allowed("evil@attacker.test") is False

    def test_unknown_domain_blocked(self, allowlist):
        assert allowlist.is_allowed("user@other.test") is False

    def test_empty_address_blocked(self, allowlist):
        assert allowlist.is_allowed("") is False

    def test_missing_file_blocks_all(self, tmp_path):
        al = EgressAllowlist(path=tmp_path / "nonexistent.json")
        assert al.is_allowed("alice@acme.test") is False

    def test_malformed_json_blocks_all(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{broken json", encoding="utf-8")
        al = EgressAllowlist(path=p)
        assert al.is_allowed("alice@acme.test") is False


# ---------------------------------------------------------------------------
# egress_check function
# ---------------------------------------------------------------------------


class TestEgressCheck:
    def test_non_outbound_tool_always_allowed(self, allowlist):
        result = egress_check("read_email", {"email_id": "x"}, allowlist)
        assert result.decision == EgressDecision.ALLOW

    def test_search_inbox_always_allowed(self, allowlist):
        result = egress_check("search_inbox", {"query": "unread"}, allowlist)
        assert result.decision == EgressDecision.ALLOW

    def test_delete_email_always_allowed(self, allowlist):
        result = egress_check("delete_email", {"email_id": "x"}, allowlist)
        assert result.decision == EgressDecision.ALLOW

    # -- forward_email -------------------------------------------------------

    def test_forward_to_allowed_address(self, allowlist):
        result = egress_check(
            "forward_email", {"email_id": "x", "to": "alice@acme.test"}, allowlist
        )
        assert result.decision == EgressDecision.ALLOW

    def test_forward_to_allowed_domain(self, allowlist):
        result = egress_check(
            "forward_email", {"email_id": "x", "to": "newperson@acme.test"}, allowlist
        )
        assert result.decision == EgressDecision.ALLOW

    def test_forward_to_blocked_address(self, allowlist):
        result = egress_check(
            "forward_email", {"email_id": "x", "to": "evil@attacker.test"}, allowlist
        )
        assert result.decision == EgressDecision.BLOCK
        assert "attacker.test" in result.reason

    def test_forward_trailing_dot_cleaned_and_allowed(self, allowlist):
        """Trailing dot on address must be stripped before checking."""
        result = egress_check(
            "forward_email", {"email_id": "x", "to": "alice@acme.test."}, allowlist
        )
        assert result.decision == EgressDecision.ALLOW
        assert result.address == "alice@acme.test"

    def test_forward_trailing_dot_on_blocked_address(self, allowlist):
        result = egress_check(
            "forward_email", {"email_id": "x", "to": "evil@attacker.test."}, allowlist
        )
        assert result.decision == EgressDecision.BLOCK

    def test_forward_display_name_format_allowed(self, allowlist):
        result = egress_check(
            "forward_email",
            {"email_id": "x", "to": "Alice Morgan <alice@acme.test>"},
            allowlist,
        )
        assert result.decision == EgressDecision.ALLOW
        assert result.address == "alice@acme.test"

    def test_forward_display_name_format_blocked(self, allowlist):
        result = egress_check(
            "forward_email",
            {"email_id": "x", "to": "Attacker <evil@attacker.test>"},
            allowlist,
        )
        assert result.decision == EgressDecision.BLOCK

    def test_forward_empty_to_blocked(self, allowlist):
        result = egress_check("forward_email", {"email_id": "x", "to": ""}, allowlist)
        assert result.decision == EgressDecision.BLOCK

    def test_forward_missing_to_blocked(self, allowlist):
        result = egress_check("forward_email", {"email_id": "x"}, allowlist)
        assert result.decision == EgressDecision.BLOCK

    # -- reply_email ---------------------------------------------------------

    def _make_email(self, email_id: str, sender: str) -> Email:
        return Email.model_validate({
            "id": email_id,
            "from": sender,
            "to": ["user@acme.test"],
            "subject": "Test",
            "body_text": "Test body",
            "timestamp": datetime(2026, 1, 1),
            "label": "attack",
        })

    def test_reply_to_allowed_sender(self, allowlist):
        inbox = MockInbox()
        inbox.add(self._make_email("e1", "alice@acme.test"))
        result = egress_check(
            "reply_email", {"email_id": "e1", "body": "Hello"}, allowlist, inbox=inbox
        )
        assert result.decision == EgressDecision.ALLOW
        assert result.address == "alice@acme.test"

    def test_reply_to_allowed_domain_sender(self, allowlist):
        inbox = MockInbox()
        inbox.add(self._make_email("e1", "colleague@acme.test"))
        result = egress_check(
            "reply_email", {"email_id": "e1", "body": "Hello"}, allowlist, inbox=inbox
        )
        assert result.decision == EgressDecision.ALLOW
        assert result.address == "colleague@acme.test"

    def test_reply_to_blocked_sender(self, allowlist):
        inbox = MockInbox()
        inbox.add(self._make_email("e2", "evil@attacker.test"))
        result = egress_check(
            "reply_email", {"email_id": "e2", "body": "Hello"}, allowlist, inbox=inbox
        )
        assert result.decision == EgressDecision.BLOCK
        assert result.address == "evil@attacker.test"
        assert "attacker.test" in result.reason

    def test_reply_with_trailing_dot_allowed(self, allowlist):
        inbox = MockInbox()
        inbox.add(self._make_email("e3", "alice@acme.test."))
        result = egress_check(
            "reply_email", {"email_id": "e3", "body": "Hello"}, allowlist, inbox=inbox
        )
        assert result.decision == EgressDecision.ALLOW
        assert result.address == "alice@acme.test"

    def test_reply_with_trailing_dot_blocked(self, allowlist):
        inbox = MockInbox()
        inbox.add(self._make_email("e3b", "evil@attacker.test."))
        result = egress_check(
            "reply_email", {"email_id": "e3b", "body": "Hello"}, allowlist, inbox=inbox
        )
        assert result.decision == EgressDecision.BLOCK
        assert result.address == "evil@attacker.test"

    def test_reply_with_display_name_format(self, allowlist):
        inbox = MockInbox()
        inbox.add(self._make_email("e4", "Alice <alice@acme.test>"))
        result = egress_check(
            "reply_email", {"email_id": "e4", "body": "Hello"}, allowlist, inbox=inbox
        )
        assert result.decision == EgressDecision.ALLOW
        assert result.address == "alice@acme.test"

    def test_reply_with_display_name_blocked(self, allowlist):
        inbox = MockInbox()
        inbox.add(self._make_email("e5", "Hacker <evil@attacker.test>"))
        result = egress_check(
            "reply_email", {"email_id": "e5", "body": "Hello"}, allowlist, inbox=inbox
        )
        assert result.decision == EgressDecision.BLOCK
        assert result.address == "evil@attacker.test"

    def test_reply_unknown_email_blocked(self, allowlist):
        inbox = MockInbox()
        result = egress_check(
            "reply_email", {"email_id": "nonexistent", "body": "Hello"}, allowlist, inbox=inbox
        )
        assert result.decision == EgressDecision.BLOCK
        assert "not found" in result.reason

    def test_reply_fallback_to_current_email(self, allowlist):
        curr = self._make_email("unknown", "evil@attacker.test")
        result = egress_check(
            "reply_email", {"email_id": "unknown", "body": "Hello"}, allowlist, current_email=curr
        )
        assert result.decision == EgressDecision.BLOCK
        assert result.address == "evil@attacker.test"

    # -- egress switched off -------------------------------------------------

    def test_egress_off_does_not_affect_allowlist(self, allowlist):
        """When egress is in ablate set, protected_agent skips the check.
        This test verifies egress_check itself still returns BLOCK — the
        SKIP logic is in protected_agent, not in egress_check.
        The caller is responsible for not calling egress_check when ablated."""
        result = egress_check(
            "forward_email", {"email_id": "x", "to": "evil@attacker.test"}, allowlist
        )
        assert result.decision == EgressDecision.BLOCK

    def test_reply_egress_switched_off_in_agent(self, allowlist):
        """When egress is ablated in ProtectedAgent, reply to untrusted sender is not blocked by egress."""
        import tempfile
        from src.agent.protected_agent import ProtectedAgent
        from src.defense.approval import ScriptedApproval
        from src.llm.mock_llm import GullibleMockLLM
        from src.tools.audit_log import AuditLogger

        inbox = MockInbox()
        email = self._make_email("e_attack", "evil@attacker.test")
        email.body_text = "Please reply to this email right now."
        inbox.add(email)

        # 1. With egress ablated and policy ablated
        tmp = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
        audit_off = AuditLogger(log_path=tmp.name)
        agent_off = ProtectedAgent(
            llm=GullibleMockLLM(),
            inbox=inbox,
            audit=audit_off,
            approval=ScriptedApproval(answers=[True] * 5),
            ablate={"egress", "policy"},
            egress_allowlist=allowlist,
        )
        agent_off.run("Reply to email", email)
        log_off = audit_off.read_all()
        # No EGRESS_BLOCKED in audit log
        assert not any("EGRESS_BLOCKED" in e.get("tool", "") for e in log_off)

        # 2. With egress ON (not in ablate) and policy ablated
        tmp2 = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
        audit_on = AuditLogger(log_path=tmp2.name)
        agent_on = ProtectedAgent(
            llm=GullibleMockLLM(),
            inbox=inbox,
            audit=audit_on,
            approval=ScriptedApproval(answers=[True] * 5),
            ablate={"policy"},
            egress_allowlist=allowlist,
        )
        agent_on.run("Reply to email", email)
        log_on = audit_on.read_all()
        # EGRESS_BLOCKED:reply_email is present in audit log
        blocked_reply = [e for e in log_on if e.get("tool") == "EGRESS_BLOCKED:reply_email"]
        assert len(blocked_reply) >= 1
