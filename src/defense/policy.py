"""
Policy Engine — decides allow / ask / deny for every tool call.

Rules (in priority order):
1. If session is in malicious-lockdown: only low-risk tools are allowed.
2. forward_email / reply_email / delete_email always require "ask".
3. Any argument value tainted from untrusted email → deny (unless approved).
4. forward_email / reply_email to a recipient not in the allowlist → deny.
5. Low-risk tools → allow.

Every decision is recorded to the audit log.
"""

from __future__ import annotations

import json
import logging
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from src.models.tools import ToolCall
from src.tools.audit_log import AuditLogger
from src.tools.definitions import TOOL_BY_NAME

logger = logging.getLogger(__name__)

_DEFAULT_ALLOWLIST = Path(__file__).parent.parent.parent / "config" / "allowlist.json"

# ---------------------------------------------------------------------------
# Output model
# ---------------------------------------------------------------------------


class Decision(str, Enum):
    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"


class PolicyDecision(BaseModel):
    decision: Decision
    reason: str
    tool_name: str
    tool_args: dict[str, Any] = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_HIGH_RISK = {"forward_email", "reply_email", "delete_email"}


def _load_allowlist(path: Path) -> list[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return [r.lower() for r in data.get("allowed_recipients", [])]
    except Exception as exc:
        logger.warning("Could not load allowlist from %s: %s", path, exc)
        return []


def _recipient_allowed(recipient: str, allowlist: list[str]) -> bool:
    """Return True if *recipient* matches any allowlist entry (suffix match)."""
    r = recipient.lower()
    for pattern in allowlist:
        if pattern.startswith("@"):
            if r.endswith(pattern):
                return True
        elif r == pattern:
            return True
    return False


def _looks_tainted(value: str, tainted_values: set[str]) -> bool:
    """True if *value* appears in the tainted value set."""
    return value in tainted_values


# ---------------------------------------------------------------------------
# PolicyEngine
# ---------------------------------------------------------------------------


class PolicyEngine:
    """Evaluates tool calls against policy rules.

    Parameters
    ----------
    audit:           AuditLogger for recording decisions.
    allowlist_path:  JSON file listing allowed forward/reply recipients.
    """

    def __init__(
        self,
        audit: AuditLogger,
        allowlist_path: Path = _DEFAULT_ALLOWLIST,
    ) -> None:
        self._audit = audit
        self._allowlist = _load_allowlist(allowlist_path)

    def decide(
        self,
        tool_call: ToolCall,
        *,
        session_malicious: bool = False,
        tainted_values: set[str] | None = None,
        approved_calls: set[str] | None = None,
    ) -> PolicyDecision:
        """Return a PolicyDecision for *tool_call*.

        Parameters
        ----------
        tool_call:         The proposed tool invocation.
        session_malicious: True if the current email was classified malicious.
        tainted_values:    Set of string values extracted from untrusted email.
        approved_calls:    Set of tool names the user has already approved.
        """
        tainted_values = tainted_values or set()
        approved_calls = approved_calls or set()

        tool_def = TOOL_BY_NAME.get(tool_call.name)
        risk = tool_def.risk_level if tool_def else "high"
        name = tool_call.name
        args = tool_call.arguments

        # ── Rule 1: malicious lockdown ───────────────────────────────────────
        if session_malicious and risk != "low":
            decision = PolicyDecision(
                decision=Decision.DENY,
                reason="Session locked to low-risk tools: email classified malicious",
                tool_name=name,
                tool_args=args,
            )
            self._log(decision)
            return decision

        # ── Rule 3: taint check ──────────────────────────────────────────────
        if name not in approved_calls:
            for arg_val in args.values():
                if isinstance(arg_val, str) and _looks_tainted(arg_val, tainted_values):
                    decision = PolicyDecision(
                        decision=Decision.DENY,
                        reason=f"Argument value came from untrusted email content (tainted)",
                        tool_name=name,
                        tool_args=args,
                    )
                    self._log(decision)
                    return decision

        # ── Rule 4: allowlist for forward / reply ────────────────────────────
        if name == "forward_email":
            recipient = args.get("to", "")
            if recipient and not _recipient_allowed(recipient, self._allowlist):
                decision = PolicyDecision(
                    decision=Decision.DENY,
                    reason=f"Forward recipient '{recipient}' not in allowlist",
                    tool_name=name,
                    tool_args=args,
                )
                self._log(decision)
                return decision

        # ── Rule 2: high-risk → always ask ──────────────────────────────────
        if name in _HIGH_RISK:
            decision = PolicyDecision(
                decision=Decision.ASK,
                reason=f"High-risk tool '{name}' requires user approval",
                tool_name=name,
                tool_args=args,
            )
            self._log(decision)
            return decision

        # ── Default: allow ───────────────────────────────────────────────────
        decision = PolicyDecision(
            decision=Decision.ALLOW,
            reason=f"Low-risk tool '{name}' auto-approved",
            tool_name=name,
            tool_args=args,
        )
        self._log(decision)
        return decision

    def _log(self, d: PolicyDecision) -> None:
        self._audit.log(
            tool=f"policy:{d.decision.value}",
            args={"tool": d.tool_name, "reason": d.reason, "args": d.tool_args},
        )
