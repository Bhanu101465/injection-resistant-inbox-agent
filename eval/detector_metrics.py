"""Detector scorecard: precision, recall and false-alarm rate.

Put this file in the inbox-agent/eval folder and run it:
    python eval/detector_metrics.py

No AI model and no API key needed. It runs the sanitizer and the detector
on every email in data/emails and writes DETECTOR_REPORT.md.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Use the project's .venv Python automatically, whatever terminal you use.
_venv = ROOT / ".venv" / "Scripts" / "python.exe"
if not _venv.exists():
    _venv = ROOT / ".venv" / "bin" / "python"
if _venv.exists() and Path(sys.executable).resolve() != _venv.resolve():
    sys.exit(subprocess.call([str(_venv), str(Path(__file__).resolve())] + sys.argv[1:]))

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def rate(num: int, den: int) -> str:
    return "n/a" if den == 0 else f"{100 * num / den:.0f}%"


def score(rows: list[dict], flagged_key: str) -> dict:
    tp = sum(1 for r in rows if r["label"] == "attack" and r[flagged_key])
    fn = sum(1 for r in rows if r["label"] == "attack" and not r[flagged_key])
    fp = sum(1 for r in rows if r["label"] != "attack" and r[flagged_key])
    tn = sum(1 for r in rows if r["label"] != "attack" and not r[flagged_key])
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "recall": rate(tp, tp + fn),
            "precision": rate(tp, tp + fp),
            "fpr": rate(fp, fp + tn)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Detector scorecard")
    parser.add_argument("--emails-dir", default="data/emails", help="Directory containing email JSONs")
    parser.add_argument("--output", default=None, help="Output markdown report file name or path")
    args = parser.parse_args()

    from src.defense.detector import InjectionDetector
    from src.defense.sanitizer import Sanitizer
    from src.models.detection import Verdict
    from src.models.email import Email
    from src.models.pipeline import StageContext

    emails_dir = Path(args.emails_dir)
    if not emails_dir.is_absolute():
        emails_dir = ROOT / emails_dir

    emails = []
    for p in sorted(emails_dir.rglob("*.json")):
        try:
            emails.append(Email.model_validate_json(p.read_text(encoding="utf-8")))
        except Exception as exc:
            print(f"Skipping {p.name}: {exc}")
    print(f"{len(emails)} emails loaded from {emails_dir}. Running the detector ...")

    rows = []
    for email in emails:
        ctx = StageContext(email_id=email.id)
        sanitized = Sanitizer().process(email, ctx)
        det = InjectionDetector().process(sanitized, ctx)
        rows.append({
            "id": email.id,
            "label": email.label,
            "category": email.category or "-",
            "verdict": det.verdict,
            "any_warning": det.verdict in (Verdict.SUSPICIOUS, Verdict.MALICIOUS),
            "malicious": det.verdict == Verdict.MALICIOUS,
            "score": det.confidence,
            "reason": det.reason,
        })

    loose = score(rows, "any_warning")
    strict = score(rows, "malicious")
    n_attack = loose["tp"] + loose["fn"]
    n_benign = loose["fp"] + loose["tn"]
    ml_file = ROOT / "models" / "detector.joblib"

    out = []
    a = out.append
    a("# Detector Scorecard\n")
    a(f"Emails checked: **{len(rows)}** ({n_attack} attack emails, {n_benign} normal emails).\n")
    a("## The numbers\n")
    a("| When does the detector count as 'caught'? | Attacks caught | False alarms on normal emails | Precision |")
    a("|---|---|---|---|")
    a(f"| Any warning (suspicious or malicious) | {loose['recall']} ({loose['tp']}/{n_attack}) "
      f"| {loose['fpr']} ({loose['fp']}/{n_benign}) | {loose['precision']} |")
    a(f"| Malicious only (this is what locks the agent) | {strict['recall']} ({strict['tp']}/{n_attack}) "
      f"| {strict['fpr']} ({strict['fp']}/{n_benign}) | {strict['precision']} |")
    a("")
    a("- **Attacks caught** = recall. Higher is better.")
    a("- **False alarms** = normal emails wrongly flagged. Lower is better.")
    a("- **Precision** = of all emails flagged, how many were real attacks.\n")

    a("## Attacks caught, by type (any warning)\n")
    a("| Attack type | Caught |")
    a("|---|---|")
    cats = sorted({r["category"] for r in rows if r["label"] == "attack"})
    for cat in cats:
        group = [r for r in rows if r["label"] == "attack" and r["category"] == cat]
        hit = sum(1 for r in group if r["any_warning"])
        a(f"| {cat} | {rate(hit, len(group))} ({hit}/{len(group)}) |")
    a("")

    missed = [r for r in rows if r["label"] == "attack" and not r["any_warning"]]
    a(f"## Attacks the detector missed ({len(missed)})\n")
    if missed:
        a("| Email | Type | Score |")
        a("|---|---|---|")
        for r in missed:
            a(f"| {r['id']} | {r['category']} | {r['score']} |")
    else:
        a("None.")
    a("")

    alarms = [r for r in rows if r["label"] != "attack" and r["any_warning"]]
    a(f"## False alarms on normal emails ({len(alarms)})\n")
    if alarms:
        a("| Email | Score | Why |")
        a("|---|---|---|")
        for r in alarms:
            a(f"| {r['id']} | {r['score']} | {r['reason']} |")
    else:
        a("None.")
    a("")

    a("## Good to know\n")
    a("- The machine-learning part of the detector file: "
      + ("**found**." if ml_file.exists() else
         "**not found** (`models/detector.joblib`). The detector uses only its rules, "
         "so it can miss attacks that use different words."))
    a("- The detector only raises a flag. The rules checker (policy) decides what is blocked.")
    a("")

    report = "\n".join(out)
    out_file = Path(args.output) if args.output else (ROOT / "DETECTOR_REPORT.md")
    if not out_file.is_absolute():
        out_file = ROOT / out_file
    out_file.write_text(report, encoding="utf-8")
    print("\n".join(out[:12]))
    print(f"\nFull report: {out_file}")


if __name__ == "__main__":
    main()
