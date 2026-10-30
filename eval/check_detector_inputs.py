"""Why did the detector miss some attacks?

Put this file in the inbox-agent/eval folder and run it:
    python eval/check_detector_inputs.py

It looks at every attack the detector missed and checks two things:
  - would the detector's rules fire on the ORIGINAL email text?
  - do they fire on the CLEANED text (what the detector really reads)?

Result is saved in DETECTOR_DEBUG.txt. It changes nothing in your project.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

_venv = ROOT / ".venv" / "Scripts" / "python.exe"
if not _venv.exists():
    _venv = ROOT / ".venv" / "bin" / "python"
if _venv.exists() and Path(sys.executable).resolve() != _venv.resolve():
    sys.exit(subprocess.call([str(_venv), str(Path(__file__).resolve())] + sys.argv[1:]))

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def short(text: str, n: int = 140) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= n else text[:n] + " ..."


def main() -> None:
    from src.defense.detector import InjectionDetector, _run_rules
    from src.defense.sanitizer import Sanitizer
    from src.models.detection import Verdict
    from src.models.email import Email
    from src.models.pipeline import StageContext

    emails = []
    for p in sorted((ROOT / "data" / "emails").rglob("*.json")):
        try:
            emails.append(Email.model_validate_json(p.read_text(encoding="utf-8")))
        except Exception as exc:
            print(f"Skipping {p.name}: {exc}")

    hidden_by_cleaner = []   # rules fire on original text, not on cleaned text
    rule_gap = []            # rules fire on neither
    score_too_low = []       # rules fire on cleaned text, but score still too low
    lines = []

    for email in emails:
        if email.label != "attack":
            continue
        ctx = StageContext(email_id=email.id)
        sanitized = Sanitizer().process(email, ctx)
        det = InjectionDetector().process(sanitized, ctx)
        if det.verdict in (Verdict.SUSPICIOUS, Verdict.MALICIOUS):
            continue  # caught, not interesting here

        raw_text = " ".join(
            [email.subject or "", email.body_text or "", email.body_html or ""]
            + [a.content_text or "" for a in email.attachments]
        )
        clean_text = " ".join(
            [sanitized.clean_subject, sanitized.clean_body] + list(sanitized.clean_attachment_texts)
        )
        raw_rules = _run_rules(raw_text)
        clean_rules = _run_rules(clean_text)
        findings = [f.type for f in sanitized.findings]

        if clean_rules:
            score_too_low.append(email.id)
            why = "rules fired on cleaned text, but the score stayed too low"
        elif raw_rules:
            hidden_by_cleaner.append(email.id)
            why = "rules WOULD fire on the original text, but the cleaner removed those words first"
        else:
            rule_gap.append(email.id)
            why = "no rule fires on either version (the rules do not know this wording)"

        lines += [
            f"{email.id}  ({email.category})  score {det.confidence}",
            f"  why missed        : {why}",
            f"  rules on original : {', '.join(raw_rules) or 'none'}",
            f"  rules on cleaned  : {', '.join(clean_rules) or 'none'}",
            f"  cleaner removed   : {', '.join(findings) or 'nothing reported'}",
            f"  cleaned text      : {short(sanitized.clean_body)}",
            "",
        ]

    total = len(hidden_by_cleaner) + len(rule_gap) + len(score_too_low)
    summary = [
        "DETECTOR DEBUG",
        f"Attacks the detector missed: {total}",
        "",
        f"- Cleaner removed the words before the detector read them : {len(hidden_by_cleaner)}  {hidden_by_cleaner}",
        f"- Rules do not know this wording                          : {len(rule_gap)}  {rule_gap}",
        f"- Rules fired but score stayed too low                     : {len(score_too_low)}  {score_too_low}",
        "",
        "----- details -----",
        "",
    ]
    report = "\n".join(summary + lines)
    (ROOT / "DETECTOR_DEBUG.txt").write_text(report, encoding="utf-8")
    print("\n".join(summary[:7]))
    print(f"Full details: {ROOT / 'DETECTOR_DEBUG.txt'}")
    print("Attach DETECTOR_DEBUG.txt here.")


if __name__ == "__main__":
    main()
