"""
Protected-agent evaluation runner.

Usage
-----
    python eval/run_protected.py --llm gullible|mock|nvidia [--no-cache]
                                 [--ablate sanitizer|detector|extractor|policy]

Runs the same emails × tasks as run_baseline.py, then prints a side-by-side
table: baseline ASR vs protected ASR, and utility for both.

--ablate can be specified multiple times to disable layers one at a time.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import tempfile
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.agent.baseline_agent import BaselineAgent
from src.agent.protected_agent import ProtectedAgent
from src.defense.approval import ScriptedApproval
from src.inbox.mock_inbox import MockInbox
from src.llm.client import LLMClient, LLMResponse, reset_run_stats, get_run_stats
from src.llm.mock_llm import GullibleMockLLM, MockLLM
from src.models.email import Email
from src.tools.audit_log import AuditLogger
from eval.metrics import (
    EvalResult,
    check_attack_success,
    compute_asr,
    compute_overall_asr,
    compute_utility,
)

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def _load_emails(emails_dir: Path) -> list[Email]:
    emails = []
    for p in sorted(emails_dir.rglob("*.json")):
        try:
            emails.append(Email.model_validate_json(p.read_text(encoding="utf-8")))
        except Exception as exc:
            logger.warning("Skipping %s: %s", p.name, exc)
    return emails


def _load_tasks(tasks_file: Path) -> list[dict]:
    return json.loads(tasks_file.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# LLM builders
# ---------------------------------------------------------------------------

def _build_llm(name: str, use_cache: bool = True) -> LLMClient:
    provider = os.environ.get("LLM_PROVIDER", "").strip().lower()
    if name == "nebius" or (name == "gullible" and provider in ("nebius", "real")):
        from src.llm.nebius_client import NebiusClient
        return NebiusClient(use_cache=use_cache)
    if name == "gullible":
        return GullibleMockLLM()
    if name == "mock":
        return MockLLM(
            [LLMResponse(text="Done.", tool_calls=[], usage={"total_tokens": 5})]
            * 10_000
        )
    from src.llm.client import NvidiaClient
    return NvidiaClient(use_cache=use_cache)


# ---------------------------------------------------------------------------
# Eval loops
# ---------------------------------------------------------------------------

def _run_eval_result(
    email: Email,
    task_def: dict,
    llm: LLMClient,
    agent_mode: str,
    ablate: set[str],
) -> EvalResult:
    task_id = task_def.get("id", "?")
    task_desc = task_def.get("description", "")
    inbox = MockInbox()
    inbox.add(email)

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False, mode="w") as fh:
        audit_path = fh.name
    try:
        audit = AuditLogger(log_path=audit_path)
        if agent_mode == "baseline":
            agent = BaselineAgent(llm=llm, inbox=inbox, audit=audit)
            result = agent.run(task=task_desc, email_id=email.id)
        else:
            agent = ProtectedAgent(
                llm=llm,
                inbox=inbox,
                audit=audit,
                approval=ScriptedApproval(default=False),
                ablate=ablate,
            )
            result = agent.run(task=task_desc, email=email)

        tool_log = audit.read_all()

        attack_ok = False
        if email.label == "attack" and email.attacker_goal:
            attack_ok = check_attack_success(email.attacker_goal, tool_log)

        benign_ok = False
        if email.label == "benign":
            benign_ok = bool(
                result.final_answer
                and "[Agent reached max iterations" not in result.final_answer
            )

        return EvalResult(
            email_id=email.id,
            email_label=email.label,
            email_category=email.category,
            attacker_goal=email.attacker_goal,
            task_id=task_id,
            task_description=task_desc,
            tool_calls_log=tool_log,
            agent_final_answer=result.final_answer,
            tokens_used=result.tokens_used,
            attack_succeeded=attack_ok,
            benign_task_completed=benign_ok,
        )
    finally:
        try:
            os.unlink(audit_path)
        except OSError:
            pass


def run_eval(
    emails: list[Email],
    tasks: list[dict],
    llm_factory,          # callable() -> LLMClient (fresh per mode)
    agent_mode: str,
    ablate: set[str],
) -> list[EvalResult]:
    results = []
    for task_def in tasks:
        llm = llm_factory()          # fresh LLM for each task (avoids queue depletion)
        for email in emails:
            results.append(_run_eval_result(email, task_def, llm, agent_mode, ablate))
    return results


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _print_table(
    baseline: list[EvalResult],
    protected: list[EvalResult],
    ablate: set[str],
) -> None:
    b_cat = compute_asr(baseline)
    p_cat = compute_asr(protected)
    all_cats = sorted(set(b_cat) | set(p_cat))

    ablate_str = ", ".join(sorted(ablate)) if ablate else "none"
    print("\n" + "=" * 78)
    print(f"  PROTECTION EVAL  |  Ablated layers: {ablate_str}")
    print("=" * 78)
    print(
        f"  {'Category':<28} "
        f"{'Base ASR':>9} {'Prot ASR':>9} "
        f"{'Base Util':>10} {'Prot Util':>10}"
    )
    print("-" * 78)

    for cat in all_cats:
        bm = b_cat.get(cat)
        pm = p_cat.get(cat)
        b_asr = f"{bm.asr:.0%}" if bm else "  N/A"
        p_asr = f"{pm.asr:.0%}" if pm else "  N/A"
        print(f"  {cat:<28} {b_asr:>9} {p_asr:>9}  {'':>9} {'':>9}")

    print("-" * 78)
    b_overall = compute_overall_asr(baseline)
    p_overall = compute_overall_asr(protected)
    b_util = compute_utility(baseline)
    p_util = compute_utility(protected)
    print(
        f"  {'OVERALL':<28} "
        f"{b_overall:>8.0%} {p_overall:>9.0%} "
        f"{b_util:>10.0%} {p_util:>10.0%}"
    )
    print("=" * 78 + "\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Run the protected-agent evaluation.")
    parser.add_argument(
        "--llm", choices=["gullible", "mock", "nvidia", "nebius"], default="gullible"
    )
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--tasks-file", default="data/tasks.json")
    parser.add_argument("--emails-dir", default="data/emails")
    parser.add_argument(
        "--ablate",
        choices=["sanitizer", "detector", "extractor", "policy"],
        action="append",
        default=[],
        help="Disable a defense layer (can be repeated)",
    )
    args = parser.parse_args()

    tasks_file = Path(args.tasks_file)
    emails_dir = Path(args.emails_dir)
    if not tasks_file.exists():
        sys.exit(f"[ERROR] Tasks file not found: {tasks_file}")
    if not emails_dir.exists():
        sys.exit(f"[ERROR] Emails dir not found: {emails_dir}")

    ablate: set[str] = set(args.ablate)

    print(f"Loading emails…")
    emails = _load_emails(emails_dir)
    print(f"  {len(emails)} emails loaded.")
    print(f"Loading tasks…")
    tasks = _load_tasks(tasks_file)
    print(f"  {len(tasks)} tasks loaded.")

    use_cache = not args.no_cache
    llm_name = args.llm

    def llm_factory():
        return _build_llm(llm_name, use_cache)

    total = len(emails) * len(tasks)
    print(f"\nRunning BASELINE ({total} runs)…")
    reset_run_stats()
    baseline_results = run_eval(emails, tasks, llm_factory, "baseline", set())

    print(f"Running PROTECTED ({total} runs, ablate={ablate or 'none'})…")
    reset_run_stats()
    protected_results = run_eval(emails, tasks, llm_factory, "protected", ablate)

    _print_table(baseline_results, protected_results, ablate)


if __name__ == "__main__":
    main()
