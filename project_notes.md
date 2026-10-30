PROJECT NOTES (read first, then wait for my next step)

Project: injection-resistant inbox agent, folder inbox-agent.
Flow: raw email -> sanitizer -> detector -> extractor (rules, no AI yet)
-> agent -> policy engine + approval -> tools -> audit log.
Layer 6 (egress check) is planned, NOT built.

BUILD PHASES
1 Scaffold, mock inbox, weak agent, attack emails: DONE
2 Sanitizer + detector (rules + ML): DONE
3 Policy, approval, extractor, protected agent, GullibleMockLLM,
  eval/run_protected.py with --ablate: DONE
4 Eval and ablations: mostly done (detector scorecard done)
5 FastAPI service, simple UI, optional Gmail: NOT STARTED

STATUS
- 153 tests pass.
- Fake gullible AI results: no protection 48% of attacks work,
  all defenses on 0%. Policy is the most important layer.
  Sanitizer and extractor back it up. Detector never changed a result
  (approval always says NO, and "malicious" label is rare).
- eval/run_everything.py runs every defense combination and writes
  FINAL_RESULTS.md.
- eval/detector_metrics.py wrote DETECTOR_REPORT.md: detector catches
  22 of 40 attacks (55%), 0 of 25 false alarms; "malicious" only 1 of 40.
  Missed: direct_override 0/5, encoded_payload 0/5, exfil_url 0/5,
  hidden_text 3/5, header_payload 4/5.

OPEN ISSUES
- Detector gives low scores to emails whose ORIGINAL text matches its
  rules (attack_001, 016, 031, 037). Probably the sanitizer removes the
  text before the detector reads it. Not confirmed yet.
- attack_011 (exfil_url): no detector rule matches its wording.
- GullibleMockLLM cannot do the URL attack, so exfil_url shows 0%
  even with no protection.
- Egress check not installed yet (postponed).
- No NVIDIA API key yet, so no real-model runs. No .env file.

RULES
- Do not change code until I give you a step. Do one step, then stop.
- Do not rewrite existing files unless the step says so.
- No plan documents. Keep code short.
- Ask me if anything is unclear. Do not assume.
- Use simple words with me. I am new to this kind of tool.pP