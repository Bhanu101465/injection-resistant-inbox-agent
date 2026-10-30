"""Tests for architecture-prep models: DetectionResult, Pipeline/Stage, and tool risk_level."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.models.detection import DetectionResult, Verdict
from src.models.pipeline import Pipeline, Stage, StageContext
from src.tools.definitions import ALL_TOOLS, TOOL_BY_NAME, ToolDefinition


# ---------------------------------------------------------------------------
# DetectionResult
# ---------------------------------------------------------------------------


class TestDetectionResult:
    def test_benign_verdict(self):
        dr = DetectionResult(
            stage_name="keyword_detector",
            verdict=Verdict.BENIGN,
            email_id="e1",
        )
        assert dr.verdict == Verdict.BENIGN
        assert dr.is_threat is False

    def test_malicious_is_threat(self):
        dr = DetectionResult(
            stage_name="keyword_detector",
            verdict=Verdict.MALICIOUS,
            confidence=0.95,
            reason="Found injection pattern",
            indicators={"pattern": "IGNORE ALL INSTRUCTIONS"},
            email_id="e2",
        )
        assert dr.is_threat is True
        assert dr.confidence == pytest.approx(0.95)

    def test_suspicious_is_threat(self):
        dr = DetectionResult(
            stage_name="heuristic",
            verdict=Verdict.SUSPICIOUS,
            email_id="e3",
        )
        assert dr.is_threat is True

    def test_uncertain_is_not_threat(self):
        dr = DetectionResult(
            stage_name="llm_judge",
            verdict=Verdict.UNCERTAIN,
            email_id="e4",
        )
        assert dr.is_threat is False

    def test_confidence_bounds(self):
        with pytest.raises(ValidationError):
            DetectionResult(stage_name="x", verdict=Verdict.BENIGN, confidence=1.5)
        with pytest.raises(ValidationError):
            DetectionResult(stage_name="x", verdict=Verdict.BENIGN, confidence=-0.1)

    def test_missing_required_fields(self):
        with pytest.raises(ValidationError):
            DetectionResult(stage_name="x")  # missing verdict
        with pytest.raises(ValidationError):
            DetectionResult(verdict=Verdict.BENIGN)  # missing stage_name


# ---------------------------------------------------------------------------
# Stage / Pipeline
# ---------------------------------------------------------------------------


class _UpperStage(Stage[str, str]):
    """Test stage: converts string to uppercase."""

    @property
    def name(self) -> str:
        return "upper"

    def process(self, input: str, ctx: StageContext) -> str:
        ctx.flags["uppercased"] = True
        return input.upper()


class _AppendStage(Stage[str, str]):
    """Test stage: appends a suffix."""

    def __init__(self, suffix: str) -> None:
        self._suffix = suffix

    @property
    def name(self) -> str:
        return f"append_{self._suffix}"

    def process(self, input: str, ctx: StageContext) -> str:
        return input + self._suffix


class TestStageContext:
    def test_defaults(self):
        ctx = StageContext()
        assert ctx.flags == {}
        assert ctx.trace == []

    def test_flag_mutation(self):
        ctx = StageContext()
        ctx.flags["key"] = 42
        assert ctx.flags["key"] == 42


class TestPipeline:
    def test_single_stage(self):
        pipeline = Pipeline([_UpperStage()])
        ctx = StageContext()
        result = pipeline.run("hello", ctx)
        assert result == "HELLO"
        assert ctx.trace == ["upper"]

    def test_multi_stage(self):
        pipeline = Pipeline([_UpperStage(), _AppendStage("!")])
        result = pipeline.run("world")
        assert result == "WORLD!"

    def test_context_propagates_flags(self):
        pipeline = Pipeline([_UpperStage()])
        ctx = StageContext()
        pipeline.run("test", ctx)
        assert ctx.flags.get("uppercased") is True

    def test_trace_accumulates(self):
        pipeline = Pipeline([_UpperStage(), _AppendStage("_suffix")])
        ctx = StageContext()
        pipeline.run("x", ctx)
        assert ctx.trace == ["upper", "append__suffix"]

    def test_fresh_context_if_none_provided(self):
        pipeline = Pipeline([_UpperStage()])
        result = pipeline.run("abc")  # no ctx passed
        assert result == "ABC"

    def test_stages_property(self):
        stages = [_UpperStage(), _AppendStage("x")]
        pipeline = Pipeline(stages)
        assert len(pipeline.stages) == 2


# ---------------------------------------------------------------------------
# Tool risk_level in registry
# ---------------------------------------------------------------------------


class TestToolRiskLevels:
    def test_all_tools_have_risk_level(self):
        for t in ALL_TOOLS:
            assert t.risk_level in ("low", "high"), (
                f"Tool '{t.name}' has invalid risk_level: {t.risk_level!r}"
            )

    def test_read_email_is_low_risk(self):
        assert TOOL_BY_NAME["read_email"].risk_level == "low"

    def test_search_inbox_is_low_risk(self):
        assert TOOL_BY_NAME["search_inbox"].risk_level == "low"

    def test_reply_email_is_high_risk(self):
        assert TOOL_BY_NAME["reply_email"].risk_level == "high"

    def test_forward_email_is_high_risk(self):
        assert TOOL_BY_NAME["forward_email"].risk_level == "high"

    def test_delete_email_is_high_risk(self):
        assert TOOL_BY_NAME["delete_email"].risk_level == "high"

    def test_risk_level_default_is_low(self):
        td = ToolDefinition(name="custom", description="x", parameters={})
        assert td.risk_level == "low"
