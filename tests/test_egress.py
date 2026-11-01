"""Tests for src/defense/egress.py — Layer 6: Egress Check."""

from __future__ import annotations

import json
import pytest
from pathlib import Path

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

    def test_reply_email_allowed(self, allowlist):
        """reply_email is allowed by egress (destination resolved at send time)."""
        result = egress_check(
            "reply_email", {"email_id": "x", "body": "Hello"}, allowlist
        )
        assert result.decision == EgressDecision.ALLOW

    # -- egress switched off -------------------------------------------------

    def test_egress_off_does_not_affect_allowlist(self, allowlist):
        """When egress is in ablate set, protected_agent skips the check.
        This test verifies egress_check itself still returns BLOCK — the
        SKIP logic is in protected_agent, not in egress_check.
        The caller is responsible for not calling egress_check when ablated."""
        result = egress_check(
            "forward_email", {"email_id": "x", "to": "evil@attacker.test"}, allowlist
        )
        # Function itself still returns BLOCK — caller decides to skip it
        assert result.decision == EgressDecision.BLOCK
