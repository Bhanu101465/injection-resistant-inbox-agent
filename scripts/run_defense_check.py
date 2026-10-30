"""
Defense check report: detection rate per attack category + false alarm rate.

Uses only emails in the test split (same logic as train_detector.py).
No LLM or network calls.

Usage:
    python scripts/run_defense_check.py
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from src.defense.sanitizer import sanitize
from src.defense.detector import detect
from src.models.email import Email


def _load_test_emails():
    """Return only the test-split emails (same criterion as train_detector.py)."""
    emails = []
    for path in sorted((ROOT / "data" / "emails").rglob("*.json")):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        last_digit = next((c for c in reversed(data["id"]) if c.isdigit()), "0")
        if int(last_digit) % 5 == 0:
            emails.append(Email.model_validate(data))
    return emails


def main():
    emails = _load_test_emails()
    if not emails:
        print("No test-split emails found.")
        sys.exit(1)

    # Category → (total, detected)
    attack_stats: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    # Benign: (total, alarmed)
    benign_total = 0
    benign_alarmed = 0

    for email in emails:
        san = sanitize(email)
        result = detect(san)
        flagged = result.verdict.value in ("suspicious", "malicious")

        if email.label == "attack":
            cat = email.category or "unknown"
            attack_stats[cat][0] += 1
            if flagged:
                attack_stats[cat][1] += 1
        else:
            benign_total += 1
            if flagged:
                benign_alarmed += 1

    print("=" * 60)
    print("DEFENSE CHECK REPORT  (test split only)")
    print("=" * 60)

    print(f"\n{'Category':<35} {'Total':>6} {'Detected':>9} {'Rate':>7}")
    print("-" * 60)
    all_total = 0
    all_detected = 0
    for cat in sorted(attack_stats):
        total, detected = attack_stats[cat]
        rate = detected / total if total else 0.0
        print(f"  {cat:<33} {total:>6} {detected:>9} {rate:>6.0%}")
        all_total += total
        all_detected += detected

    overall = all_detected / all_total if all_total else 0.0
    print("-" * 60)
    print(f"  {'OVERALL ATTACK DETECTION':<33} {all_total:>6} {all_detected:>9} {overall:>6.0%}")

    print(f"\n  False alarm rate (benign emails flagged): "
          f"{benign_alarmed}/{benign_total} = "
          f"{benign_alarmed/benign_total:.0%}" if benign_total else "  No benign test emails.")

    print("=" * 60)


if __name__ == "__main__":
    main()
