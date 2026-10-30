"""
tests/test_api.py — FastAPI endpoint tests using TestClient.

LLM: gullible (no network needed).
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from src.api.app import app, _emails

client = TestClient(app)


# ---------------------------------------------------------------------------
# /health
# ---------------------------------------------------------------------------

def test_health():
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"


# ---------------------------------------------------------------------------
# /emails
# ---------------------------------------------------------------------------

def test_emails_returns_65():
    res = client.get("/emails")
    assert res.status_code == 200
    assert len(res.json()) == 65


def test_emails_unknown_returns_404():
    res = client.get("/emails/does_not_exist_xyz")
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# nvidia without key → 400
# ---------------------------------------------------------------------------

def test_nvidia_without_key_returns_400(monkeypatch):
    # Make sure NVIDIA_API_KEY is absent
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)

    # Pick any email
    first_id = next(iter(_emails))
    payload = {
        "email_id": first_id,
        "task": "Summarize this email.",
        "llm": "nvidia",
        "mode": "protected",
        "auto_approve": False,
        "ablate": [],
    }
    res = client.post("/run", json=payload)
    assert res.status_code == 400
    assert "NVIDIA_API_KEY" in res.json()["detail"]


# ---------------------------------------------------------------------------
# /compare: attack email — baseline succeeds, protected blocks
# ---------------------------------------------------------------------------

def test_compare_attack_blocked():
    """
    Find an attack email where the gullible baseline succeeds,
    then assert the protected run blocks it.
    """
    attack_emails = [e for e in _emails.values() if e.label == "attack"]
    assert attack_emails, "No attack emails found in data/emails"

    task = "Summarize this email."
    found = False

    for email in attack_emails:
        payload = {
            "email_id": email.id,
            "task": task,
            "llm": "gullible",
            "mode": "protected",
            "auto_approve": False,
            "ablate": [],
        }
        res = client.post("/compare", json=payload)
        assert res.status_code == 200, f"Unexpected status {res.status_code}: {res.text}"
        data = res.json()

        if data["baseline"]["attack_succeeded"] and not data["protected"]["attack_succeeded"]:
            found = True
            break

    assert found, (
        "Could not find a single attack email where baseline succeeded AND "
        "protected blocked it. Check eval results — defenses may be misconfigured."
    )
