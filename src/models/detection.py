"""
DetectionResult model (architecture-prep).

Represents the output of a detection stage in the pipeline.  No detection
logic is implemented here — this file is a data-model definition only.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    """High-level classification of a detection stage's decision."""

    BENIGN = "benign"
    """The content appears safe / non-malicious."""

    SUSPICIOUS = "suspicious"
    """The content shows signals worth flagging but is not conclusively an attack."""

    MALICIOUS = "malicious"
    """The content is classified as an active injection / attack attempt."""

    UNCERTAIN = "uncertain"
    """The detector could not reach a confident verdict (e.g. quota exceeded)."""


class DetectionResult(BaseModel):
    """The output produced by a detection stage.

    A single stage may populate this model; multiple stages can each produce
    their own ``DetectionResult`` and they can be aggregated downstream.

    Fields
    ------
    stage_name   : Name of the detector that generated this result.
    verdict      : High-level verdict (see ``Verdict`` enum).
    confidence   : Float in [0, 1]; 1.0 = fully confident.
    reason       : Human-readable explanation of the verdict.
    indicators   : Structured evidence (patterns, scores, matched rules, etc.).
    email_id     : ID of the email that was evaluated.
    """

    stage_name: str = Field(..., description="Name of the detection stage")
    verdict: Verdict = Field(..., description="High-level classification verdict")
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Detector confidence in the verdict (0.0–1.0)",
    )
    reason: str = Field(
        default="",
        description="Human-readable explanation of why this verdict was reached",
    )
    indicators: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Machine-readable evidence, e.g. matched regex patterns, "
            "perplexity scores, or rule IDs that fired."
        ),
    )
    email_id: str = Field(
        default="",
        description="ID of the source email that was evaluated",
    )

    @property
    def is_threat(self) -> bool:
        """Return True if the verdict indicates a likely or certain attack."""
        return self.verdict in (Verdict.SUSPICIOUS, Verdict.MALICIOUS)
