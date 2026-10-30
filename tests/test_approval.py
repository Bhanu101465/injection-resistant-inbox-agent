"""Tests for ScriptedApproval and CliApproval interfaces."""

from __future__ import annotations

from unittest.mock import patch

from src.defense.approval import CliApproval, ScriptedApproval, format_approval_prompt
from src.models.tools import ToolCall


def _tc(name="forward_email", **kwargs) -> ToolCall:
    args = {"email_id": "x", "to": "a@b.com"}
    args.update(kwargs)
    return ToolCall(id="t1", name=name, arguments=args)


class TestScriptedApproval:
    def test_default_is_false(self):
        ap = ScriptedApproval()
        assert ap.ask(_tc(), "reason") is False

    def test_preset_yes(self):
        ap = ScriptedApproval(answers=[True])
        assert ap.ask(_tc(), "reason") is True

    def test_preset_no(self):
        ap = ScriptedApproval(answers=[False])
        assert ap.ask(_tc(), "reason") is False

    def test_queue_exhausted_falls_back_to_default(self):
        ap = ScriptedApproval(answers=[True], default=False)
        ap.ask(_tc(), "first")   # consumes the True
        assert ap.ask(_tc(), "second") is False  # falls back

    def test_enqueue(self):
        ap = ScriptedApproval()
        ap.enqueue(True)
        assert ap.ask(_tc(), "r") is True

    def test_multiple_preset(self):
        ap = ScriptedApproval(answers=[True, False, True])
        assert ap.ask(_tc(), "r") is True
        assert ap.ask(_tc(), "r") is False
        assert ap.ask(_tc(), "r") is True


class TestApprovalPromptFormatting:
    def test_action_sentence_forward_and_external_recipient(self):
        tc = _tc("forward_email", to="evil@attacker.test")
        prompt = format_approval_prompt(tc, reason="policy check")
        assert "The agent wants to forward this email to evil@attacker.test (EXTERNAL)." in prompt
        assert "Recipient : evil@attacker.test [EXTERNAL (outside your organization)]" in prompt

    def test_action_sentence_reply_and_internal_recipient(self):
        tc = _tc("reply_email", to="alice@acme.test")
        prompt = format_approval_prompt(tc, reason="user confirm")
        assert "The agent wants to send a reply to alice@acme.test." in prompt
        assert "Recipient : alice@acme.test [Internal]" in prompt

    def test_action_sentence_delete(self):
        tc = ToolCall(id="t2", name="delete_email", arguments={"email_id": "msg_01"})
        prompt = format_approval_prompt(tc, reason="destructive")
        assert "The agent wants to permanently delete an email from your inbox." in prompt

    def test_subject_and_first_three_lines_preview(self):
        tc = _tc("forward_email", to="colleague@acme.test")
        body_content = "Line 1: Confidential report.\nLine 2: Project status.\nLine 3: Key metrics.\nLine 4: Extra data.\nLine 5: Footer."
        prompt = format_approval_prompt(
            tc,
            reason="check",
            subject="Q3 Executive Review",
            body=body_content,
        )
        assert "Subject   : Q3 Executive Review" in prompt
        assert "> Line 1: Confidential report." in prompt
        assert "> Line 2: Project status." in prompt
        assert "> Line 3: Key metrics." in prompt
        assert "Line 4: Extra data." not in prompt

    def test_warning_present_when_flagged_suspicious(self):
        tc = _tc("forward_email", to="evil@attacker.test")
        prompt = format_approval_prompt(tc, reason="high risk", is_suspicious=True)
        assert "WARNING   : This email was flagged as SUSPICIOUS by the security detector." in prompt

    def test_warning_absent_when_benign(self):
        tc = _tc("forward_email", to="alice@acme.test")
        prompt = format_approval_prompt(tc, reason="high risk", is_suspicious=False)
        assert "WARNING" not in prompt

    def test_cli_approval_default_answer_is_no(self):
        cli = CliApproval()
        tc = _tc()
        # Empty string / hitting Enter defaults to No
        with patch("builtins.input", return_value=""):
            assert cli.ask(tc, "confirm") is False

        # Explicit 'n' or 'no' returns False
        with patch("builtins.input", return_value="n"):
            assert cli.ask(tc, "confirm") is False
        with patch("builtins.input", return_value="no"):
            assert cli.ask(tc, "confirm") is False

        # Random keystroke returns False
        with patch("builtins.input", return_value="anything_else"):
            assert cli.ask(tc, "confirm") is False

        # 'y' or 'yes' returns True
        with patch("builtins.input", return_value="y"):
            assert cli.ask(tc, "confirm") is True
        with patch("builtins.input", return_value="yes"):
            assert cli.ask(tc, "confirm") is True
