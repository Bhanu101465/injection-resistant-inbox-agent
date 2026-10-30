"""Tests for RuleExtractor."""

from __future__ import annotations

from src.defense.extractor import RuleExtractor
from src.models.pipeline import StageContext
from src.models.sanitized_email import SanitizedEmail


def _san(body="Hello world.", subject="Test subject", email_id="e1") -> SanitizedEmail:
    return SanitizedEmail(email_id=email_id, clean_subject=subject, clean_body=body)


class TestRuleExtractor:
    def test_basic_extraction(self):
        ex = RuleExtractor()
        result = ex.process(_san(), StageContext())
        assert result.email_id == "e1"
        assert result.subject == "Test subject"

    def test_body_truncated(self):
        ex = RuleExtractor()
        long_body = "word " * 2000
        san = _san(body=long_body)
        result = ex.process(san, StageContext())
        assert len(result.plain_text) <= 4000

    def test_subject_truncated(self):
        ex = RuleExtractor()
        long_subject = "X" * 500
        san = _san(subject=long_subject)
        result = ex.process(san, StageContext())
        assert len(result.subject) <= 200

    def test_taint_provenance_added(self):
        ex = RuleExtractor()
        result = ex.process(_san(), StageContext())
        assert any("tainted" in p for p in result.provenance)

    def test_source_trust_propagated(self):
        ex = RuleExtractor()
        ctx = StageContext()
        ctx.flags["source_trust"] = "untrusted"
        result = ex.process(_san(), ctx)
        assert result.source_trust == "untrusted"

    def test_sender_from_context(self):
        ex = RuleExtractor()
        ctx = StageContext()
        ctx.flags["sender"] = "alice@acme.test"
        result = ex.process(_san(), ctx)
        assert result.sender == "alice@acme.test"

    def test_first_sentences_summary(self):
        ex = RuleExtractor()
        body = "Sentence one. Sentence two. Sentence three. Sentence four."
        result = ex.process(_san(body=body), StageContext())
        # Should include first 3 sentences but not necessarily all 4
        assert "Sentence one" in result.plain_text
        assert "Sentence four" not in result.plain_text

    def test_attachment_texts_truncated(self):
        ex = RuleExtractor()
        san = SanitizedEmail(
            email_id="e1",
            clean_subject="s",
            clean_body="b",
            clean_attachment_texts=["x" * 2000],
        )
        result = ex.process(san, StageContext())
        assert len(result.attachment_texts[0]) <= 1000
