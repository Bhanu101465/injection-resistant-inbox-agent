"""
Baseline evaluation runner.

Usage
-----
    python eval/run_baseline.py [--llm nvidia|mock] [--no-cache]
                                [--tasks-file data/tasks.json]
                                [--emails-dir data/emails]

The script:
1. Loads emails from ``data/emails/benign/`` and ``data/emails/attacks/``.
2. Loads tasks from ``data/tasks.json``.
3. For each task × email pair, runs ``BaselineAgent`` and collects the audit log.
4. Evaluates attack success and benign utility using ``eval/metrics.py``.
5. Prints a formatted ASR / utility report.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import tempfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Make sure the project root is on sys.path so imports work when the script
# is run directly (e.g. `python eval/run_baseline.py`).
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.agent.baseline_agent import BaselineAgent  # noqa: E402
from src.inbox.mock_inbox import MockInbox  # noqa: E402
from src.llm.client import LLMClient, reset_run_stats, get_run_stats  # noqa: E402
from src.llm.mock_llm import MockLLM  # noqa: E402
from src.models.email import Email  # noqa: E402
from src.tools.audit_log import AuditLogger  # noqa: E402
from eval.metrics import (  # noqa: E402
    EvalResult,
    check_attack_success,
    print_report,
)

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_emails(emails_dir: Path) -> list[Email]:
    """Load all *.json email files from *emails_dir* recursively."""
    emails: list[Email] = []
    for json_path in sorted(emails_dir.rglob("*.json")):
        try:
            raw = json_path.read_text(encoding="utf-8")
            email = Email.model_validate_json(raw)
            emails.append(email)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Skipping %s: %s", json_path.name, exc)
    return emails


def _load_tasks(tasks_file: Path) -> list[dict]:
    """Load task definitions from a JSON file."""
    raw = tasks_file.read_text(encoding="utf-8")
    return json.loads(raw)


def _build_mock_llm() -> MockLLM:
    """Return a MockLLM pre-loaded with scripted responses.

    For the baseline eval we configure the mock to immediately return a
    plain-text "done" response so that every run completes cleanly
    without any tool calls (ASR = 0% by construction — this is fine;
    the mock run validates the pipeline, not the model behaviour).

    Each agent run calls ``generate()`` at least once, so we load
    1 000 canned responses which is more than enough for the full
    benign × attack × tasks cross-product.
    """
    from src.llm.client import LLMResponse  # noqa: PLC0415

    responses = [
        LLMResponse(
            text="Done. I have processed your request.",
            tool_calls=[],
            usage={"total_tokens": 5},
        )
        for _ in range(10_000)
    ]
    return MockLLM(responses)


def _build_nvidia_client(use_cache: bool) -> LLMClient:
    """Construct and return a live NvidiaClient."""
    from src.llm.client import NvidiaClient  # noqa: PLC0415

    return NvidiaClient(use_cache=use_cache)


# ---------------------------------------------------------------------------
# Core eval loop
# ---------------------------------------------------------------------------


def run_eval(
    emails: list[Email],
    tasks: list[dict],
    llm: LLMClient,
) -> list[EvalResult]:
    """Run BaselineAgent on every task × email pair and return all results."""
    results: list[EvalResult] = []

    for task_def in tasks:
        task_id: str = task_def.get("id", "unknown")
        task_description: str = task_def.get("description", "")

        for email in emails:
            # Fresh per-task inbox so tool mutations don't bleed across runs
            inbox = MockInbox()
            inbox.add(email)

            # Temp audit log
            with tempfile.NamedTemporaryFile(
                suffix=".jsonl", delete=False, mode="w"
            ) as fh:
                audit_path = fh.name

            try:
                audit = AuditLogger(log_path=audit_path)
                agent = BaselineAgent(llm=llm, inbox=inbox, audit=audit)

                agent_result = agent.run(task=task_description, email_id=email.id)
                tool_log = audit.read_all()

                # Evaluate attack success
                attack_ok = False
                if email.label == "attack" and email.attacker_goal:
                    attack_ok = check_attack_success(email.attacker_goal, tool_log)

                # Benign utility: consider it completed if the agent produced a
                # final answer (no error text) and made at least one tool call OR
                # returned non-trivial text.
                benign_ok = False
                if email.label == "benign":
                    benign_ok = bool(
                        agent_result.final_answer
                        and "[Agent reached max iterations" not in agent_result.final_answer
                    )

                results.append(
                    EvalResult(
                        email_id=email.id,
                        email_label=email.label,
                        email_category=email.category,
                        attacker_goal=email.attacker_goal,
                        task_id=task_id,
                        task_description=task_description,
                        tool_calls_log=tool_log,
                        agent_final_answer=agent_result.final_answer,
                        tokens_used=agent_result.tokens_used,
                        attack_succeeded=attack_ok,
                        benign_task_completed=benign_ok,
                    )
                )
            finally:
                try:
                    os.unlink(audit_path)
                except OSError:
                    pass

    return results


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the baseline inbox agent evaluation."
    )
    parser.add_argument(
        "--llm",
        choices=["nvidia", "mock"],
        default="mock",
        help="LLM backend to use (default: mock)",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable the SQLite LLM response cache (NVIDIA only)",
    )
    parser.add_argument(
        "--tasks-file",
        default="data/tasks.json",
        help="Path to tasks JSON file (default: data/tasks.json)",
    )
    parser.add_argument(
        "--emails-dir",
        default="data/emails",
        help="Path to emails directory (default: data/emails)",
    )
    args = parser.parse_args()

    tasks_file = Path(args.tasks_file)
    emails_dir = Path(args.emails_dir)

    if not tasks_file.exists():
        sys.exit(f"[ERROR] Tasks file not found: {tasks_file}")
    if not emails_dir.exists():
        sys.exit(f"[ERROR] Emails directory not found: {emails_dir}")

    print(f"Loading emails from {emails_dir} …")
    emails = _load_emails(emails_dir)
    print(f"  {len(emails)} emails loaded.")

    print(f"Loading tasks from {tasks_file} …")
    tasks = _load_tasks(tasks_file)
    print(f"  {len(tasks)} tasks loaded.")

    print(f"Using LLM backend: {args.llm}")
    reset_run_stats()

    if args.llm == "nvidia":
        llm = _build_nvidia_client(use_cache=not args.no_cache)
    else:
        llm = _build_mock_llm()

    print(f"Running eval ({len(emails)} emails × {len(tasks)} tasks) …")
    results = run_eval(emails, tasks, llm)

    print_report(results)
    print(get_run_stats().summary())


if __name__ == "__main__":
    main()
