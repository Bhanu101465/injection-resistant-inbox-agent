"""
Sanitizer stage — strips injection-friendly content from an Email.

No LLM or network calls.  Pure text transformations + heuristics.
"""

from __future__ import annotations

import base64
import codecs
import re
import unicodedata

from bs4 import BeautifulSoup, Comment

from src.models.email import Email
from src.models.pipeline import Stage, StageContext
from src.models.sanitized_email import Finding, SanitizedEmail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ZERO_WIDTH = re.compile(
    r"[\u00ad\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\ufeff]"
)

# Suspicious phrase patterns (used later by detector too, but kept here for
# finding generation during sanitisation)
_OVERRIDE_RE = re.compile(
    r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)",
    re.IGNORECASE,
)

# base64-looking blob: ≥40 base64 chars with possible whitespace
_B64_RE = re.compile(r"(?:[A-Za-z0-9+/\s]{40,}={0,2})")

# rot13 heuristic: word of ≥8 letters with no common English letters (q-z-heavy pattern)
# We use a simpler proxy: detect "==\n" endings typical of b64 padding
_B64_STRICT_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


def _snippet(text: str, maxlen: int = 120) -> str:
    text = text.strip()
    return text[:maxlen] + ("…" if len(text) > maxlen else "")


def _looks_base64(blob: str) -> bool:
    clean = re.sub(r"\s+", "", blob)
    if len(clean) < 40:
        return False
    try:
        decoded = base64.b64decode(clean + "==", validate=False)
        # If decoded text is mostly printable ascii it's suspicious
        printable = sum(0x20 <= b < 0x7F for b in decoded)
        return printable / max(len(decoded), 1) > 0.7
    except Exception:
        return False


def _looks_rot13(blob: str) -> bool:
    """Very rough: try rot13 decoding and check if result has common words."""
    try:
        decoded = codecs.decode(blob, "rot_13")
        return bool(_OVERRIDE_RE.search(decoded))
    except Exception:
        return False


# CSS / inline style patterns that hide content
_HIDDEN_STYLE_RE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|"
    r"font-size\s*:\s*0|opacity\s*:\s*0|"
    r"color\s*:\s*(white|#fff(?:fff)?|rgb\s*\(\s*255\s*,\s*255\s*,\s*255\s*\))",
    re.IGNORECASE,
)

_OFFSCREEN_RE = re.compile(
    r"(?:left|top|margin(?:-left|-top)?)\s*:\s*-\d{3,}",
    re.IGNORECASE,
)


def _style_hidden(tag) -> bool:
    style = tag.get("style", "")
    return bool(_HIDDEN_STYLE_RE.search(style) or _OFFSCREEN_RE.search(style))


# ---------------------------------------------------------------------------
# Core sanitisation functions
# ---------------------------------------------------------------------------


def _clean_html(html: str, findings: list[Finding]) -> str:
    """Convert HTML → plain text, stripping all hidden/invisible content."""
    soup = BeautifulSoup(html, "html.parser")

    # Remove HTML comments
    for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
        findings.append(Finding(type="html_comment", sample=_snippet(str(comment))))
        comment.extract()

    # Remove hidden elements
    for tag in soup.find_all(True):
        if _style_hidden(tag):
            findings.append(Finding(type="hidden_text", sample=_snippet(tag.get_text())))
            tag.decompose()
            continue
        # font-size:0 or tiny via attribute (rare but seen in attacks)
        size_attr = tag.get("size", "")
        if str(size_attr) == "0":
            findings.append(Finding(type="hidden_text", sample=_snippet(tag.get_text())))
            tag.decompose()

    return soup.get_text(separator=" ", strip=True)


def _clean_text(text: str, findings: list[Finding]) -> str:
    """Normalise plain text: remove zero-width chars, normalise Unicode."""
    # Remove zero-width / invisible chars
    cleaned, n = _ZERO_WIDTH.subn("", text)
    if n:
        findings.append(Finding(type="zero_width_chars", sample=f"{n} removed"))

    # NFKC normalisation (folds homoglyphs, ligatures, etc.)
    cleaned = unicodedata.normalize("NFKC", cleaned)
    return cleaned


def _scan_blobs(text: str, findings: list[Finding]) -> None:
    """Detect base64 or rot13-encoded payloads; record findings."""
    for m in _B64_STRICT_RE.finditer(text):
        blob = m.group(0)
        if _looks_base64(blob):
            findings.append(Finding(type="base64_blob", sample=_snippet(blob)))
        elif _looks_rot13(blob):
            findings.append(Finding(type="rot13_blob", sample=_snippet(blob)))


def _sanitize_field(raw_html: str, raw_text: str, findings: list[Finding]) -> str:
    """Produce a clean plain-text string from an email field."""
    if raw_html:
        text = _clean_html(raw_html, findings)
    else:
        text = raw_text
    text = _clean_text(text, findings)
    _scan_blobs(text, findings)
    return text


# ---------------------------------------------------------------------------
# Stage implementation
# ---------------------------------------------------------------------------


class Sanitizer(Stage[Email, SanitizedEmail]):
    """Pipeline stage that sanitises a raw Email into a SanitizedEmail."""

    @property
    def name(self) -> str:
        return "sanitizer"

    def process(self, input: Email, ctx: StageContext) -> SanitizedEmail:
        findings: list[Finding] = []

        clean_body = _sanitize_field(input.body_html, input.body_text, findings)
        clean_subject = _clean_text(input.subject, findings)
        _scan_blobs(clean_subject, findings)

        alt_texts: list[str] = []
        if input.body_html and input.body_text:
            cleaned_text = _clean_text(input.body_text, findings)
            _scan_blobs(cleaned_text, findings)
            alt_texts.append(cleaned_text)

            html_words = set(re.findall(r"\b[a-zA-Z]{3,}\b", clean_body.lower()))
            text_words = set(re.findall(r"\b[a-zA-Z]{3,}\b", cleaned_text.lower()))
            missing_words = text_words - html_words
            if len(missing_words) >= 6:
                findings.append(Finding(
                    type="parts_mismatch",
                    sample=_snippet(" ".join(sorted(missing_words))),
                ))

        clean_attachments = []
        for att in input.attachments:
            cleaned = _sanitize_field("", att.content_text, findings)
            clean_attachments.append(cleaned)

        ctx.flags["sanitizer_findings"] = len(findings)

        return SanitizedEmail(
            email_id=input.id,
            clean_subject=clean_subject,
            clean_body=clean_body,
            clean_attachment_texts=clean_attachments,
            alt_texts=alt_texts,
            findings=findings,
        )


# Convenience function for direct use without a pipeline
def sanitize(email: Email) -> SanitizedEmail:
    return Sanitizer().process(email, StageContext())
