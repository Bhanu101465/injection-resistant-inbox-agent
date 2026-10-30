"""
Injection Detector — two-tier, no network calls.

Tier 1: hand-crafted rule patterns.
Tier 2: TF-IDF + LogisticRegression loaded from models/detector.joblib.
         Falls back gracefully if the model file is missing.

The detector only FLAGS; it never decides to block or take an action.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any

from src.defense.sanitizer import SanitizedEmail
from src.models.detection import DetectionResult, Verdict
from src.models.pipeline import Stage, StageContext

logger = logging.getLogger(__name__)

_MODEL_PATH = Path(__file__).parent.parent.parent / "models" / "detector.joblib"

# ---------------------------------------------------------------------------
# Tier-1 rules
# ---------------------------------------------------------------------------

_RULES: list[tuple[str, re.Pattern]] = [
    ("override_instruction", re.compile(
        r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)|"
        r"disregard\s+(all\s+)?(preceding|previous|prior|above)\s+(prompts?|guidelines?|instructions?|rules?)",
        re.IGNORECASE,
    )),
    ("ai_targeting", re.compile(
        r"\b(you\s+are\s+(now\s+)?(an?\s+)?ai|as\s+an?\s+(ai|assistant|language\s+model)|"
        r"your\s+(new\s+)?instructions?|system\s+prompt|"
        r"dear\s+(ai|assistant|bot|agent))\b",
        re.IGNORECASE,
    )),
    ("tool_abuse_forward", re.compile(
        r"\b(forward|send|relay|redirect)\s+(all\s+)?(email|message|mail)s?\b",
        re.IGNORECASE,
    )),
    ("tool_abuse_delete", re.compile(
        r"\b(delete|remove|purge|erase|wipe|expunge)\s+(all\s+|every\s+)?(email|message|mail)s?\b",
        re.IGNORECASE,
    )),
    ("tool_abuse_reply", re.compile(
        r"\bauto[-\s]?reply\b|\breply\s+to\s+(all|every|each|unread)\b",
        re.IGNORECASE,
    )),
    ("urgent_authority", re.compile(
        r"\b(immediately|urgent(ly)?|right\s+now|without\s+(delay|hesitation)|"
        r"do\s+not\s+(inform|tell|notify|warn)\s+the\s+user|"
        r"admin\s+mode|override\s+mode|debug\s+mode|priority\s+override|system\s+override|stop\s+current\s+task)\b",
        re.IGNORECASE,
    )),
    ("data_url", re.compile(
        r"https?://[^\s]*\?[^\s]*(password|token|secret|key|auth|cred|dump|inbox|payload)[^\s]*",
        re.IGNORECASE,
    )),
    ("exfil_address", re.compile(
        r"\b[A-Za-z0-9._%+\-]+@(?:attacker|evil|exfil|steal|harvest)\.[a-z]+\b",
        re.IGNORECASE,
    )),
    ("role_hijack", re.compile(
        r"\b(you\s+are\s+now|act\s+as|pretend\s+(you\s+are|to\s+be)|"
        r"roleplay\s+as|simulate\s+being|from\s+now\s+on\s+you)\b",
        re.IGNORECASE,
    )),
    ("reply_embed_url", re.compile(
        r"\b(reply|respond|response)\b[^\.\n]{0,100}\b(include|append|embed|attach|insert|contain)\b[^\.\n]{0,100}\b(link|url|pixel|webhook|beacon|endpoint|code)\b|"
        r"\b(include|append|embed|attach|insert|contain)\b[^\.\n]{0,100}\b(link|url|pixel|webhook|beacon|endpoint)\b[^\.\n]{0,100}\b(reply|respond|response)\b",
        re.IGNORECASE,
    )),
    ("summary_exfil", re.compile(
        r"\b(reply|respond|send|forward|dispatch|provide)\b[^\.\n]{0,100}\b(summary|copy|transcript|record|archive)s?\b[^\.\n]{0,100}\b(recent|all|past|inbox|unread|executive|client)\b[^\.\n]{0,100}\b(email|message|mail|correspondence)s?\b|"
        r"\b(reply|respond|send|forward|dispatch|provide)\b[^\.\n]{0,100}\b(recent|all|past|unread)\b[^\.\n]{0,100}\b(email|message|mail|correspondence)s?\b[^\.\n]{0,100}\b(summary|copy|transcript|archive)\b",
        re.IGNORECASE,
    )),
    ("decode_execute", re.compile(
        r"\bdecode\b[^\.\n]{0,80}\b(base64|rot13|hex|cipher|binary|payload)\b[^\.\n]{0,80}\b(follow|execute|run|carry\s+out|obey|apply)\b|"
        r"\b(follow|execute|run|carry\s+out|obey)\b[^\.\n]{0,80}\bdecode\b[^\.\n]{0,80}\b(base64|rot13|hex|cipher)\b|"
        r"\bdecode\s+(this\s+)?(base64|rot13|hex|payload|string)\b",
        re.IGNORECASE,
    )),
    ("forward_link", re.compile(
        r"\b(forward|send|relay|share)\b[^\.\n]{0,80}\b(this|the)\s+(link|url|endpoint|webhook)\b[^\.\n]{0,80}\b(assistant|ai|agent|bot)\b|"
        r"\b(forward|send|relay)\s+(this\s+link|the\s+link)\s+to\s+(the\s+)?(assistant|ai|agent|bot)\b",
        re.IGNORECASE,
    )),
]


def _run_rules(text: str) -> list[str]:
    """Return list of rule IDs that fired on *text*."""
    fired = []
    for rule_id, pattern in _RULES:
        if pattern.search(text):
            fired.append(rule_id)
    return fired


# ---------------------------------------------------------------------------
# Tier-2 ML model
# ---------------------------------------------------------------------------

_pipeline_cache: Any = None  # lazy load


def _load_model():
    global _pipeline_cache
    if _pipeline_cache is not None:
        return _pipeline_cache
    if not _MODEL_PATH.exists():
        return None
    try:
        import joblib  # noqa: PLC0415
        _pipeline_cache = joblib.load(_MODEL_PATH)
        return _pipeline_cache
    except Exception as exc:
        logger.warning("Could not load detector model: %s", exc)
        return None


def _ml_score(text: str) -> float:
    """Return probability [0,1] of being an attack. Returns 0.0 if no model."""
    model = _load_model()
    if model is None:
        return 0.0
    try:
        prob = model.predict_proba([text])[0]
        # class order: model.classes_ = [0, 1] where 1 = attack
        classes = list(model.classes_)
        attack_idx = classes.index(1) if 1 in classes else -1
        return float(prob[attack_idx]) if attack_idx >= 0 else 0.0
    except Exception as exc:
        logger.warning("ML scoring failed: %s", exc)
        return 0.0


# ---------------------------------------------------------------------------
# Score combination
# ---------------------------------------------------------------------------

def _combine(rule_hits: list[str], ml_prob: float, n_sanitizer_findings: int) -> float:
    """Combine rule hits + ML into a single [0,1] score."""
    # Each rule hit contributes 0.25, capped at 0.75
    rule_score = min(len(rule_hits) * 0.25, 0.75)
    # Sanitizer findings add a small bonus
    finding_bonus = min(n_sanitizer_findings * 0.05, 0.20)
    # Weighted average with ML
    combined = 0.5 * rule_score + 0.3 * ml_prob + 0.2 * min(finding_bonus + rule_score, 1.0)
    return round(min(combined, 1.0), 4)


def _verdict(score: float) -> Verdict:
    if score >= 0.65:
        return Verdict.MALICIOUS
    if score >= 0.30:
        return Verdict.SUSPICIOUS
    return Verdict.BENIGN


# ---------------------------------------------------------------------------
# Stage implementation
# ---------------------------------------------------------------------------

class InjectionDetector(Stage[SanitizedEmail, DetectionResult]):
    """Pipeline stage that scores a SanitizedEmail for injection attacks."""

    @property
    def name(self) -> str:
        return "injection_detector"

    def process(self, input: SanitizedEmail, ctx: StageContext) -> DetectionResult:
        alt_texts = getattr(input, "alt_texts", [])
        full_text = " ".join(
            [input.clean_subject, input.clean_body] + list(alt_texts) + input.clean_attachment_texts
        )

        rule_hits = _run_rules(full_text)
        ml_prob = _ml_score(full_text)
        n_findings = len(input.findings)
        score = _combine(rule_hits, ml_prob, n_findings)
        verdict = _verdict(score)

        # Strong sanitizer signals: hidden_text, html_comment, base64_blob, parts_mismatch, zero_width
        strong_types = {
            "hidden_text", "html_comment", "base64_blob", "parts_mismatch",
            "zero_width", "zero_width_chars"
        }
        strong_findings = [
            f for f in input.findings
            if f.type in strong_types or any(t in f.type for t in ("zero_width", "hidden_text", "html_comment", "base64_blob", "parts_mismatch"))
        ]

        strong_reasons = []
        if strong_findings and rule_hits:
            verdict = Verdict.MALICIOUS
            score = max(score, 0.85)
            s_names = ", ".join(sorted({f.type for f in strong_findings}))
            strong_reasons.append(f"Strong finding ({s_names}) + rule hit -> MALICIOUS")
        elif strong_findings:
            if verdict == Verdict.BENIGN:
                verdict = Verdict.SUSPICIOUS
                score = max(score, 0.50)
            s_names = ", ".join(sorted({f.type for f in strong_findings}))
            strong_reasons.append(f"Strong finding ({s_names}) -> SUSPICIOUS")

        reasons = []
        if strong_reasons:
            reasons.extend(strong_reasons)
        if rule_hits:
            reasons.append(f"Rules fired: {', '.join(rule_hits)}")
        if ml_prob > 0.4:
            reasons.append(f"ML score: {ml_prob:.2f}")
        if n_findings and not strong_reasons:
            finding_types = [f.type for f in input.findings]
            reasons.append(f"Sanitizer findings: {', '.join(finding_types)}")
        if not reasons:
            reasons.append("No threat signals detected")

        ctx.flags["detection_score"] = score
        ctx.flags["detection_verdict"] = verdict.value

        return DetectionResult(
            stage_name=self.name,
            verdict=verdict,
            confidence=score,
            reason="; ".join(reasons),
            indicators={
                "rule_hits": rule_hits,
                "ml_prob": ml_prob,
                "sanitizer_findings": n_findings,
            },
            email_id=input.email_id,
        )


# Convenience function
def detect(sanitized: SanitizedEmail) -> DetectionResult:
    return InjectionDetector().process(sanitized, StageContext())
