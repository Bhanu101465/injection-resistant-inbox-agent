"""
EgressCheck — Layer 6.

Before forward_email or reply_email executes, check that the destination
address is in the approved allowlist (config/allowed_recipients.json).

Address cleaning (applied before every check):
  - Lowercase + strip whitespace
  - Parse "Name <addr>" display-name format
  - Strip a trailing punctuation character (.,;:!?)

Decision: ALLOW or BLOCK with a plain-English reason.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)

# Default allowlist path (relative to this file's package root)
_DEFAULT_ALLOWLIST = (
    Path(__file__).resolve().parents[2] / "config" / "allowed_recipients.json"
)

# Matches "Display Name <user@domain.test>" or just "<user@domain.test>"
_DISPLAY_NAME_RE = re.compile(r"<([^>]+)>")


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


class EgressDecision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"


@dataclass(frozen=True)
class EgressResult:
    decision: EgressDecision
    address: str        # cleaned address that was checked
    reason: str


# ---------------------------------------------------------------------------
# Address cleaning
# ---------------------------------------------------------------------------


def _clean_address(raw: str) -> str:
    """Normalise a raw recipient string to a plain lowercase email address.

    Handles:
    - Leading/trailing whitespace
    - Display-name format:  "Alice <alice@acme.test>"  →  "alice@acme.test"
    - Trailing punctuation: "alice@acme.test."          →  "alice@acme.test"
    """
    addr = raw.strip()

    # Extract from display-name format
    m = _DISPLAY_NAME_RE.search(addr)
    if m:
        addr = m.group(1).strip()

    # Strip one trailing punctuation character
    addr = addr.rstrip(".,;:!? \t")

    return addr.lower()


# ---------------------------------------------------------------------------
# Allowlist loader
# ---------------------------------------------------------------------------


class EgressAllowlist:
    """Loads and caches the allowlist from a JSON file.

    Parameters
    ----------
    path:
        Path to the JSON allowlist file.  Falls back to
        ``config/allowed_recipients.json`` relative to the project root.
    """

    def __init__(self, path: str | Path | None = None) -> None:
        p = Path(path) if path else _DEFAULT_ALLOWLIST
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except FileNotFoundError:
            logger.warning("Egress allowlist not found at %s — blocking all outbound.", p)
            data = {}
        except json.JSONDecodeError as exc:
            logger.error("Egress allowlist JSON error: %s — blocking all outbound.", exc)
            data = {}

        self._addresses: frozenset[str] = frozenset(
            a.lower().strip() for a in data.get("allowed_addresses", [])
        )
        self._domains: frozenset[str] = frozenset(
            d.lower().strip().lstrip("@") for d in data.get("allowed_domains", [])
        )

    def is_allowed(self, cleaned_addr: str) -> bool:
        """Return True if *cleaned_addr* matches any address or domain rule."""
        if cleaned_addr in self._addresses:
            return True
        if "@" in cleaned_addr:
            domain = cleaned_addr.split("@", 1)[1]
            if domain in self._domains:
                return True
        return False


# ---------------------------------------------------------------------------
# Public check function
# ---------------------------------------------------------------------------


def egress_check(
    tool_name: str,
    arguments: dict,
    allowlist: EgressAllowlist,
) -> EgressResult:
    """Check whether an outbound tool call is permitted.

    Only ``forward_email`` and ``reply_email`` have an outbound destination;
    all other tools are allowed unconditionally.

    Parameters
    ----------
    tool_name:
        Name of the tool the agent wants to call.
    arguments:
        Tool arguments dict (as sent to the LLM tool schema).
    allowlist:
        Loaded ``EgressAllowlist`` instance.

    Returns
    -------
    EgressResult
        Decision (ALLOW / BLOCK) plus the cleaned address and reason.
    """
    OUTBOUND_TOOLS = {
        "forward_email": "to",
        "reply_email": "email_id",   # reply destination is the original sender — no explicit addr
    }

    if tool_name not in OUTBOUND_TOOLS:
        return EgressResult(
            decision=EgressDecision.ALLOW,
            address="",
            reason="Tool does not send outbound email.",
        )

    # forward_email has an explicit "to" address we can check
    if tool_name == "forward_email":
        raw_to = arguments.get("to", "")
        addr = _clean_address(raw_to)
        if not addr:
            return EgressResult(
                decision=EgressDecision.BLOCK,
                address=addr,
                reason="forward_email called with empty 'to' address.",
            )
        if allowlist.is_allowed(addr):
            return EgressResult(
                decision=EgressDecision.ALLOW,
                address=addr,
                reason=f"Destination '{addr}' is in the egress allowlist.",
            )
        return EgressResult(
            decision=EgressDecision.BLOCK,
            address=addr,
            reason=(
                f"Destination '{addr}' is NOT in the egress allowlist. "
                "Add it to config/allowed_recipients.json to permit this action."
            ),
        )

    # reply_email — the reply goes to the original sender of the email.
    # We do not have that address here without looking up the inbox, so we
    # ALLOW it and rely on the policy engine + approval gate upstream.
    # Operators who need strict reply egress should add the sender address
    # check at the executor level.
    return EgressResult(
        decision=EgressDecision.ALLOW,
        address="",
        reason="reply_email destination resolved at send time; allowed by egress.",
    )
