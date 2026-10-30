"""Tests for PolicyEngine."""

from __future__ import annotations

import tempfile

import pytest

from src.defense.policy import Decision, PolicyEngine
from src.models.tools import ToolCall
from src.tools.audit_log import AuditLogger


def _engine() -> tuple[PolicyEngine, AuditLogger]:
    tmp = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
    audit = AuditLogger(log_path=tmp.name)
    engine = PolicyEngine(audit)
    return engine, audit


def _tc(name: str, args: dict) -> ToolCall:
    return ToolCall(id="t1", name=name, arguments=args)


class TestPolicyEngine:
    def test_low_risk_tool_allowed(self):
        eng, _ = _engine()
        pd = eng.decide(_tc("read_email", {"email_id": "x"}))
        assert pd.decision == Decision.ALLOW

    def test_high_risk_forward_requires_ask(self):
        eng, _ = _engine()
        pd = eng.decide(_tc("forward_email", {"email_id": "x", "to": "alice@acme.test"}))
        assert pd.decision == Decision.ASK

    def test_high_risk_delete_requires_ask(self):
        eng, _ = _engine()
        pd = eng.decide(_tc("delete_email", {"email_id": "x"}))
        assert pd.decision == Decision.ASK

    def test_high_risk_reply_requires_ask(self):
        eng, _ = _engine()
        pd = eng.decide(_tc("reply_email", {"email_id": "x", "body": "hi"}))
        assert pd.decision == Decision.ASK

    def test_malicious_session_denies_high_risk(self):
        eng, _ = _engine()
        pd = eng.decide(
            _tc("delete_email", {"email_id": "x"}),
            session_malicious=True,
        )
        assert pd.decision == Decision.DENY

    def test_malicious_session_allows_low_risk(self):
        eng, _ = _engine()
        pd = eng.decide(
            _tc("read_email", {"email_id": "x"}),
            session_malicious=True,
        )
        assert pd.decision == Decision.ALLOW

    def test_tainted_arg_denied(self):
        eng, _ = _engine()
        tainted = {"evil@attacker.test"}
        pd = eng.decide(
            _tc("forward_email", {"email_id": "x", "to": "evil@attacker.test"}),
            tainted_values=tainted,
        )
        assert pd.decision == Decision.DENY

    def test_allowlist_blocks_external_recipient(self):
        eng, _ = _engine()
        # forward to a domain not in allowlist.json
        pd = eng.decide(
            _tc("forward_email", {"email_id": "x", "to": "evil@attacker.test"}),
        )
        assert pd.decision == Decision.DENY

    def test_allowlist_permits_internal_recipient(self):
        eng, _ = _engine()
        # @acme.test is in allowlist → should get ASK (high-risk, not DENY)
        pd = eng.decide(
            _tc("forward_email", {"email_id": "x", "to": "bob@acme.test"}),
        )
        assert pd.decision == Decision.ASK

    def test_reason_present(self):
        eng, _ = _engine()
        pd = eng.decide(_tc("read_email", {"email_id": "x"}))
        assert pd.reason != ""

    def test_decision_logged_to_audit(self):
        eng, audit = _engine()
        eng.decide(_tc("read_email", {"email_id": "x"}))
        log = audit.read_all()
        assert len(log) == 1
        assert "policy:" in log[0]["tool"]
