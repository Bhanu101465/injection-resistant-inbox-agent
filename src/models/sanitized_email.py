"""Data models produced by the Sanitizer stage."""

from __future__ import annotations

from pydantic import BaseModel, Field


class Finding(BaseModel):
    """A single suspicious item found during sanitisation."""

    type: str = Field(..., description="Category, e.g. 'hidden_text', 'base64_blob'")
    sample: str = Field(default="", description="Short excerpt (≤120 chars)")


class SanitizedEmail(BaseModel):
    """Output of the Sanitizer stage: cleaned text plus a list of findings."""

    email_id: str
    clean_subject: str = ""
    clean_body: str = ""
    clean_attachment_texts: list[str] = Field(default_factory=list)
    alt_texts: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
