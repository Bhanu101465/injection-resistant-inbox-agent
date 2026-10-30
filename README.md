# Injection-Resistant Inbox Agent

A research project that shows how an AI email assistant can be tricked into doing harmful things (forwarding, replying, or deleting emails) through **prompt injection attacks** — and how to stop it.

---

## What It Does

An email agent reads your inbox and runs tasks for you. The problem: a malicious email can hide instructions that trick the agent into calling risky tools. This project builds a **defense pipeline** in front of the agent to catch and block those attacks before they succeed.

---

## Defense Layers

```
Incoming Email
      │
      ▼
 1. Sanitizer      — strips hidden HTML, invisible text, and suspicious content
      │
      ▼
 2. Detector       — classifies the email as benign or malicious (ML + rules)
      │
      ▼
 3. Extractor      — separates trusted data (subject, sender) from untrusted body text;
                     marks attacker-controlled values as "tainted"
      │
      ▼
 4. Policy Engine  — checks every tool call the model wants to make; blocks any call
                     that uses tainted values or violates allowed actions
      │
      ▼
 5. Approval Gate  — asks the user (or a scripted policy) before executing high-risk
                     tools (forward, reply, delete); default answer is No
      │
      ▼
    Agent          — only sees sanitized data; blocked calls never reach the inbox
```

---

## Setup

```bash
cd inbox-agent
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -e .[dev]
```

Copy `.env.example` to `.env` and fill in your API key:

```
NEBIUS_API_KEY=your_key_here
NEBIUS_MODEL_ID=nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B
```

---

## Run the Web Demo

```bash
cd inbox-agent
uvicorn src.api.app:app --reload --host 127.0.0.1 --port 8000
```

Then open **http://127.0.0.1:8000** in your browser.

> The demo runs locally only. There is no login or auth — do not expose it to the internet.

---

## Run the Tests

```bash
cd inbox-agent
pytest tests --ignore=tests/test_api.py
```

`test_api.py` is excluded because it starts a live server that conflicts with pytest's event loop.

---

## Evaluation Results

See **[REAL_MODEL_RESULTS.md](REAL_MODEL_RESULTS.md)** for the full results of running 90 real model runs (45 weak + 45 strong) across all three protection modes.

**Short answer:**
- No protection → attack worked in **13 of 15** strong-attack runs.
- Policy only → **0 of 15** attacks worked.
- Full protection → **0 of 15** attacks worked.

Known issue: the demo badge can show "attack blocked" on Baseline when the
model copies a trailing dot in the attacker address (e.g. attacker.test.).
The tool calls and audit log shown on the page are correct.