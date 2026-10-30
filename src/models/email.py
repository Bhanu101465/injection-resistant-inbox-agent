"""Pydantic models for Email, Attachment, and ExtractedEmail."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class Attachment(BaseModel):
    """An email attachment with extracted text content."""

    filename: str = Field(..., description="Attachment filename")
    content_type: str = Field(..., description="MIME type, e.g. 'application/pdf'")
    content_text: str = Field(
        default="", description="Extracted plain-text representation of the attachment"
    )


class Email(BaseModel):
    """A single email message stored in the MockInbox."""

    id: str = Field(..., description="Unique email identifier")
    from_: str = Field(..., alias="from", description="Sender email address")
    to: list[str] = Field(default_factory=list, description="Primary recipients")
    cc: list[str] = Field(default_factory=list, description="CC recipients")
    subject: str = Field(..., description="Email subject line")
    body_html: str = Field(default="", description="HTML body (may contain hidden payloads)")
    body_text: str = Field(default="", description="Plain-text body")
    attachments: list[Attachment] = Field(
        default_factory=list, description="File attachments"
    )
    timestamp: datetime = Field(..., description="When the email was received")
    is_read: bool = Field(default=False, description="Whether the email has been read")

    # Corpus metadata — populated for both benign and attack emails
    label: str = Field(
        default="benign",
        description="'benign' or 'attack'",
    )
    category: str | None = Field(
        default=None,
        description=(
            "Attack category, e.g. 'direct_override', 'exfil_forward_reply', etc. "
            "None for benign emails."
        ),
    )
    attacker_goal: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Machine-checkable condition describing what a successful attack achieves. "
            "Example: {\"action\": \"forward\", \"to\": \"evil@attacker.test\"}. "
            "None for benign emails."
        ),
    )

    # ------------------------------------------------------------------
    # Taint / provenance fields (architecture-prep)
    # ------------------------------------------------------------------

    source_trust: Literal["trusted", "untrusted", "unknown"] = Field(
        default="unknown",
        description=(
            "Taint label for the email origin. 'trusted' = internal/known-good "
            "sender; 'untrusted' = external / unverified; 'unknown' = default."
        ),
    )
    provenance: list[str] = Field(
        default_factory=list,
        description=(
            "Ordered chain of processing steps or sources that produced/modified "
            "this email record, e.g. ['smtp:mta.acme.test', 'inbox:mock']."
        ),
    )

    model_config = {"populate_by_name": True}


# ---------------------------------------------------------------------------
# ExtractedEmail — structured parsed representation for pipeline stages
# ---------------------------------------------------------------------------


class ExtractedEmail(BaseModel):
    """Structured view of an email after content extraction.

    Produced by an extraction stage in the pipeline; downstream stages
    operate on this model rather than the raw ``Email``.
    """

    email_id: str = Field(..., description="Source email ID")
    subject: str = Field(default="", description="Cleaned subject line")
    sender: str = Field(default="", description="Normalised sender address")
    recipients: list[str] = Field(default_factory=list, description="All To + CC recipients")
    plain_text: str = Field(default="", description="Extracted plain-text body")
    html_snippet: str = Field(
        default="",
        description="First 2 000 chars of body_html for heuristic analysis",
    )
    attachment_texts: list[str] = Field(
        default_factory=list,
        description="Concatenated text extracted from each attachment",
    )
    source_trust: Literal["trusted", "untrusted", "unknown"] = Field(
        default="unknown",
        description="Propagated taint label from the source Email",
    )
    provenance: list[str] = Field(
        default_factory=list,
        description="Provenance chain inherited (and possibly extended) from source Email",
    )
