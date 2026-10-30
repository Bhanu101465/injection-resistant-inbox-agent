"""
# DEMO ONLY — local use on 127.0.0.1 only — no login, no auth.
FastAPI application for the Injection-Resistant Inbox Agent.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from src.defense.detector import InjectionDetector
from src.defense.sanitizer import Sanitizer
from src.models.detection import Verdict
from src.models.email import Email
from src.models.pipeline import StageContext

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_ROOT = Path(__file__).resolve().parents[2]
_EMAILS_DIR = _ROOT / "data" / "emails"
_TASKS_FILE = _ROOT / "data" / "tasks.json"
_STATIC_DIR = Path(__file__).resolve().parent / "static"

# ---------------------------------------------------------------------------
# Startup: load all emails and tasks once
# ---------------------------------------------------------------------------

_emails: dict[str, Email] = {}
_tasks: list[dict] = []


def _load_all() -> None:
    for p in sorted(_EMAILS_DIR.rglob("*.json")):
        try:
            email = Email.model_validate_json(p.read_text(encoding="utf-8"))
            _emails[email.id] = email
        except Exception:
            pass
    _tasks.extend(json.loads(_TASKS_FILE.read_text(encoding="utf-8")))


_load_all()

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Inbox Agent API",
    description="Injection-Resistant Inbox Agent — demo only, local only.",
    version="0.2.0",
)

# Serve static files (index.html) at /static, but we'll also add a root route
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


# ---------------------------------------------------------------------------
# Pydantic response models
# ---------------------------------------------------------------------------

class EmailSummary(BaseModel):
    id: str
    from_: str = Field(alias="from")
    subject: str
    label: str
    category: str | None

    model_config = {"populate_by_name": True}


class RunRequest(BaseModel):
    email_id: str
    task: str
    llm: str = Field(default="gullible", pattern="^(gullible|mock|nvidia)$")
    mode: str = Field(default="protected", pattern="^(baseline|protected)$")
    auto_approve: bool = False
    ablate: list[str] = Field(default_factory=list)


class DetectorInfo(BaseModel):
    verdict: str
    score: float
    reason: str


class RunResult(BaseModel):
    mode: str
    final_answer: str
    tool_calls: list[dict[str, Any]]
    audit_entries: list[dict[str, Any]]
    tokens_used: int
    attack_succeeded: bool
    detector: DetectorInfo


class CompareResult(BaseModel):
    email_id: str
    task: str
    baseline: RunResult
    protected: RunResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _detector_verdict(email: Email) -> DetectorInfo:
    ctx = StageContext(email_id=email.id)
    sanitized = Sanitizer().process(email, ctx)
    detection = InjectionDetector().process(sanitized, ctx)
    return DetectorInfo(
        verdict=detection.verdict.value,
        score=detection.confidence,
        reason=detection.reason,
    )


def _run_and_wrap(
    email: Email,
    task: str,
    llm: str,
    mode: str,
    auto_approve: bool,
    ablate: list[str],
    detector: DetectorInfo,
) -> RunResult:
    from src.api.runner import run_one  # local import keeps startup fast

    result = run_one(
        email=email,
        task=task,
        llm_name=llm,
        mode=mode,
        auto_approve=auto_approve,
        ablate=ablate,
    )
    return RunResult(
        mode=mode,
        final_answer=result["final_answer"],
        tool_calls=result["tool_calls"],
        audit_entries=result["audit_entries"],
        tokens_used=result["tokens_used"],
        attack_succeeded=result["attack_succeeded"],
        detector=detector,
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(str(_STATIC_DIR / "index.html"))


@app.get("/health", tags=["meta"])
def health() -> dict:
    """Health check endpoint."""
    return {"status": "ok", "emails_loaded": len(_emails), "tasks_loaded": len(_tasks)}


@app.get("/emails", response_model=list[EmailSummary], tags=["data"])
def list_emails() -> list[EmailSummary]:
    """Return a summary of every loaded email."""
    return [
        EmailSummary(
            id=e.id,
            **{"from": e.from_},
            subject=e.subject,
            label=e.label,
            category=e.category,
        )
        for e in _emails.values()
    ]


@app.get("/emails/{email_id}", response_model=Email, tags=["data"])
def get_email(email_id: str) -> Email:
    """Return the full email object. 404 if not found."""
    email = _emails.get(email_id)
    if email is None:
        raise HTTPException(status_code=404, detail=f"Email '{email_id}' not found.")
    return email


@app.get("/tasks", tags=["data"])
def list_tasks() -> list[dict]:
    """Return all tasks from data/tasks.json."""
    return _tasks


@app.post("/run", response_model=RunResult, tags=["agent"])
def run_single(req: RunRequest) -> RunResult:
    """Run the agent on one email in baseline or protected mode."""
    if req.llm == "nvidia" and not os.environ.get("NVIDIA_API_KEY"):
        raise HTTPException(
            status_code=400,
            detail=(
                "llm='nvidia' requires the NVIDIA_API_KEY environment variable to be set. "
                "Either set the key or choose llm='gullible' or llm='mock'."
            ),
        )
    email = _emails.get(req.email_id)
    if email is None:
        raise HTTPException(status_code=404, detail=f"Email '{req.email_id}' not found.")

    detector = _detector_verdict(email)
    return _run_and_wrap(
        email=email,
        task=req.task,
        llm=req.llm,
        mode=req.mode,
        auto_approve=req.auto_approve,
        ablate=req.ablate,
        detector=detector,
    )


@app.post("/compare", response_model=CompareResult, tags=["agent"])
def compare(req: RunRequest) -> CompareResult:
    """Run baseline AND protected mode; return both results side-by-side."""
    if req.llm == "nvidia" and not os.environ.get("NVIDIA_API_KEY"):
        raise HTTPException(
            status_code=400,
            detail=(
                "llm='nvidia' requires the NVIDIA_API_KEY environment variable to be set. "
                "Either set the key or choose llm='gullible' or llm='mock'."
            ),
        )
    email = _emails.get(req.email_id)
    if email is None:
        raise HTTPException(status_code=404, detail=f"Email '{req.email_id}' not found.")

    detector = _detector_verdict(email)

    baseline = _run_and_wrap(
        email=email,
        task=req.task,
        llm=req.llm,
        mode="baseline",
        auto_approve=req.auto_approve,
        ablate=[],           # baseline never ablates
        detector=detector,
    )
    protected = _run_and_wrap(
        email=email,
        task=req.task,
        llm=req.llm,
        mode="protected",
        auto_approve=req.auto_approve,
        ablate=req.ablate,
        detector=detector,
    )
    return CompareResult(
        email_id=req.email_id,
        task=req.task,
        baseline=baseline,
        protected=protected,
    )
