"""Run the protected-agent test with each defense turned off, one by one.

Put this file in the inbox-agent/eval folder.
Run from the inbox-agent folder:
    python eval/run_all_ablations.py

It saves everything to ablation_results.txt
"""
import subprocess
import sys

RUNS = [
    ("all defenses ON", []),
    ("sanitizer OFF", ["--ablate", "sanitizer"]),
    ("detector OFF", ["--ablate", "detector"]),
    ("extractor OFF", ["--ablate", "extractor"]),
    ("policy OFF", ["--ablate", "policy"]),
    ("ALL FOUR OFF", ["--ablate", "sanitizer", "--ablate", "detector",
                      "--ablate", "extractor", "--ablate", "policy"]),
]

summary = []
full_text = []

for name, extra in RUNS:
    print(f"Running: {name} ...")
    cmd = [sys.executable, "eval/run_protected.py", "--llm", "gullible"] + extra
    result = subprocess.run(cmd, capture_output=True, text=True)
    output = result.stdout + result.stderr
    full_text.append(f"##### {name} #####\n{output}\n")

    overall = [line.strip() for line in output.splitlines() if "OVERALL" in line]
    line = overall[0] if overall else "no result (see ablation_results.txt)"
    summary.append(f"{name:18} -> {line}")

with open("ablation_results.txt", "w", encoding="utf-8") as f:
    f.write("SUMMARY (Base ASR, Prot ASR, Base Util, Prot Util)\n")
    f.write("\n".join(summary))
    f.write("\n\n")
    f.write("\n".join(full_text))

print("\n=== SUMMARY ===")
print("\n".join(summary))
print("\nFull details saved in ablation_results.txt")
