"""
Extractor — converts a SanitizedEmail into an ExtractedEmail.

Design notes
------------
- Free-text fields coming from email content are considered TAINTED.
  The caller (ProtectedAgent) must not trust them as instructions.
- Strict length limits prevent oversized payloads reaching the LLM.
- Extra / unexpected fields are dropped (strict=True on model_validate).

Extension point
---------------
To add an LLM-based extractor, subclass Extractor and implement process().
The RuleExtractor below is a pure-Python fallback with no network calls.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod

from src.defense.sanitizer import SanitizedEmail
from src.models.email import ExtractedEmail
from src.models.pipeline import Stage, StageContext

# Field length limits (chars)
_MAX_SUBJECT = 200
_MAX_BODY = 4_000
_MAX_ATTACHMENT = 1_000
_MAX_SUMMARY_SENTENCES = 3


def _first_sentences(text: str, n: int) -> str:
    """Return first *n* sentences of *text*."""
    sentences = re.split(r"(?<=[.!?])\s+", text.strip())
    return " ".join(sentences[:n])


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class Extractor(Stage[SanitizedEmail, ExtractedEmail], ABC):
    """Abstract extractor: SanitizedEmail → ExtractedEmail."""

    # LLM-based extractor slot — override this method in a subclass that
    # calls an LLM to extract structured fields, then build ExtractedEmail.
    # The LLM must be called with taint-safe prompting (label email content
    # as UNTRUSTED DATA in the prompt).

    @abstractmethod
    def process(self, input: SanitizedEmail, ctx: StageContext) -> ExtractedEmail:
        ...


# ---------------------------------------------------------------------------
# RuleExtractor — no LLM
# ---------------------------------------------------------------------------


class RuleExtractor(Extractor):
    """Extracts structured fields from a SanitizedEmail using simple rules.

    No network or LLM calls.  Free-text outputs are marked tainted via the
    provenance list on the returned ExtractedEmail.
    """

    @property
    def name(self) -> str:
        return "rule_extractor"

    def process(self, input: SanitizedEmail, ctx: StageContext) -> ExtractedEmail:
        # Subject — truncate only
        subject = input.clean_subject[:_MAX_SUBJECT]

        # Body summary — first N sentences, then truncate
        summary = _first_sentences(input.clean_body, _MAX_SUMMARY_SENTENCES)
        plain_text = summary[:_MAX_BODY]

        # Attachment texts — truncate each
        att_texts = [t[:_MAX_ATTACHMENT] for t in input.clean_attachment_texts]

        # HTML snippet — not available from sanitized email; leave empty
        html_snippet = ""

        # Propagate taint: all free-text fields came from untrusted email
        provenance = list(ctx.flags.get("provenance", [])) + [
            f"rule_extractor:{input.email_id}:tainted"
        ]
        ctx.flags["tainted_fields"] = {"subject", "plain_text", "attachment_texts"}

        return ExtractedEmail(
            email_id=input.email_id,
            subject=subject,
            sender=ctx.flags.get("sender", ""),
            recipients=ctx.flags.get("recipients", []),
            plain_text=plain_text,
            html_snippet=html_snippet,
            attachment_texts=att_texts,
            source_trust=ctx.flags.get("source_trust", "untrusted"),
            provenance=provenance,
        )


# Convenience
def extract(sanitized: SanitizedEmail, ctx: StageContext | None = None) -> ExtractedEmail:
    if ctx is None:
        ctx = StageContext()
    return RuleExtractor().process(sanitized, ctx)
