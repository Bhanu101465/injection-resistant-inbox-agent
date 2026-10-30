"""Run EVERY test for the inbox agent and write a final results report.

Put this file anywhere inside the inbox-agent folder (eval folder is best).
Run it:
    python eval/run_everything.py

It makes two files inside inbox-agent:
    FINAL_RESULTS.md      <- the report, in simple words
    raw_outputs.txt       <- every full output, in case something looks odd
"""
import itertools
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = HERE if os.path.exists(os.path.join(HERE, "eval")) else os.path.dirname(HERE)

# Use the .venv Python if it exists, so the right terminal does not matter.
VENV_PY = os.path.join(ROOT, ".venv", "Scripts", "python.exe")
if not os.path.exists(VENV_PY):
    VENV_PY = os.path.join(ROOT, ".venv", "bin", "python")
PY = VENV_PY if os.path.exists(VENV_PY) else sys.executable

RUN_PROTECTED = os.path.join(ROOT, "eval", "run_protected.py")
RUN_BASELINE = os.path.join(ROOT, "eval", "run_baseline.py")
LAYERS = ["sanitizer", "detector", "extractor", "policy"]

raw = []


def run(cmd, timeout=900):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT,
                           timeout=timeout)
        return r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return "TIMEOUT"


def pct(token):
    return int(token.rstrip("%"))


def parse(output):
    overall, cats = None, {}
    for line in output.splitlines():
        parts = line.split()
        if not parts:
            continue
        pcts = [p for p in parts if p.endswith("%") and p[:-1].isdigit()]
        if parts[0] == "OVERALL" and len(pcts) >= 4:
            overall = [pct(p) for p in pcts[:4]]
        elif (len(pcts) >= 2 and parts[0].replace("_", "").isalpha()
              and parts[0] not in ("Category", "OVERALL")):
            cats[parts[0]] = (pct(pcts[0]), pct(pcts[1]))
    return overall, cats


# ---------------------------------------------------------------- run tests
print("1/4  Checking the code tests (pytest) ...")
t0 = time.time()
pytest_out = run([PY, "-m", "pytest", "-q", "-p", "no:cacheprovider"], timeout=900)
raw.append("##### pytest #####\n" + pytest_out)
pytest_last = [l for l in pytest_out.strip().splitlines() if l.strip()][-1:] or ["no result"]

print("2/4  Scoring the agent with NO protection ...")
base_out = run([PY, RUN_BASELINE, "--llm", "mock"])
raw.append("##### baseline (mock) #####\n" + base_out)

print("3/4  Scoring with every mix of defenses turned off (16 runs) ...")
combos = [()]
for size in (1, 2, 3, 4):
    combos.extend(itertools.combinations(LAYERS, size))

results = {}
for combo in combos:
    name = "all defenses ON" if not combo else " + ".join(combo) + " OFF"
    print(f"     {name}")
    cmd = [PY, RUN_PROTECTED, "--llm", "gullible"]
    for layer in combo:
        cmd += ["--ablate", layer]
    out = run(cmd)
    raw.append(f"##### {name} #####\n{out}")
    overall, cats = parse(out)
    results[combo] = (name, overall, cats)

print("4/4  Writing the report ...")

# ---------------------------------------------------------------- analysis
all_on = results[()][1]
all_off = results[tuple(LAYERS)][1]
ok = all_on is not None and all_off is not None

base_asr = all_on[0] if ok else None
prot_on = all_on[1] if ok else None
prot_off = all_off[1] if ok else None

singles = []
for layer in LAYERS:
    o = results[(layer,)][1]
    if o:
        singles.append((layer, o[1]))

matter_alone = [(l, v) for l, v in singles if ok and v > prot_on]
no_change_alone = [l for l, v in singles if ok and v <= prot_on]

# smallest groups that let attacks through
minimal = []
for size in (1, 2, 3, 4):
    for combo in itertools.combinations(LAYERS, size):
        o = results[combo][1]
        if not (ok and o and o[1] > prot_on):
            continue
        if any(set(m) <= set(combo) for m in minimal):
            continue
        minimal.append(combo)

never_changes = []
for layer in LAYERS:
    others = [l for l in LAYERS if l != layer]
    changed = False
    for size in range(0, 4):
        for c in itertools.combinations(others, size):
            without = tuple(l for l in LAYERS if l in c)
            with_off = tuple(l for l in LAYERS if l in set(c) | {layer})
            o1, o2 = results[without][1], results[with_off][1]
            if o1 and o2 and o1[1] != o2[1]:
                changed = True
    if not changed:
        never_changes.append(layer)

helps_when_policy_off = []
for layer in LAYERS:
    if layer == "policy":
        continue
    o1 = results[("policy",)][1]
    o2 = results[tuple(l for l in LAYERS if l in ("policy", layer))][1]
    if o1 and o2 and o2[1] > o1[1]:
        helps_when_policy_off.append((layer, o1[1], o2[1]))

utils = [r[1][3] for r in results.values() if r[1]]
util_text = (f"{min(utils)}% to {max(utils)}%" if utils else "unknown")

lines = []
a = lines.append
a("# Final Results: Injection-Resistant Inbox Agent\n")
a("_Test AI used: a fake 'gullible' AI that always follows attack emails. "
  "No real model was used._\n")
a("## The short story\n")
if ok:
    a(f"- With **no protection**, **{base_asr}%** of attacks worked.")
    a(f"- With **all defenses on**, **{prot_on}%** of attacks worked.")
    a(f"- With **all four defenses off**, **{prot_off}%** of attacks worked.")
a(f"- Normal email work stayed at **{util_text}** in every test.")
a(f"- Code checks: `{pytest_last[0].strip()}`\n")

a("## Turning off ONE defense\n")
a("| Defense turned off | Attacks that worked |")
a("|---|---|")
for layer, v in singles:
    a(f"| {layer} | {v}% |")
a("")
if matter_alone:
    names = ", ".join(l for l, _ in matter_alone)
    a(f"- Needed on its own: **{names}**. When it is off, attacks get through.")
if no_change_alone:
    a(f"- No change when off alone: **{', '.join(no_change_alone)}**. "
      "Other layers cover for them.\n")

a("## Turning off MANY defenses\n")
a("| Defenses turned off | Attacks that worked | Normal work |")
a("|---|---|---|")
for combo in combos:
    name, o, _ = results[combo]
    if o:
        a(f"| {name} | {o[1]}% | {o[3]}% |")
a("")

a("## Do the backup layers help?\n")
if helps_when_policy_off:
    a("When the rules checker (policy) is already off, turning off one more layer:\n")
    for layer, before, after in helps_when_policy_off:
        a(f"- **{layer}**: attacks go from {before}% to {after}%")
    a("")
if never_changes:
    a(f"- **Never changed the result in any test: {', '.join(never_changes)}.** "
      "With this fake AI it did not help. It may matter with a real model.\n")

a("## Smallest groups that let attacks through\n")
if minimal:
    for m in minimal:
        a(f"- {' + '.join(m)}")
    a("")
    a("Turn off any of these groups and some attacks work.\n")
else:
    a("- No group of defenses let attacks through.\n")

a("## Attack types: before and after\n")
a("| Attack type | No protection | All defenses on | All four off |")
a("|---|---|---|---|")
cats_on = results[()][2]
cats_off = results[tuple(LAYERS)][2]
for cat in cats_on:
    b, p = cats_on[cat]
    p_off = cats_off.get(cat, ("?", "?"))[1]
    a(f"| {cat} | {b}% | {p}% | {p_off}% |")
a("")

a("## Things to be careful about\n")
a("- The test AI is fake and always follows attacks. A real model may behave "
  "differently. Real proof needs a real model later.")
a("- The `exfil_url` attack shows 0% even with no protection, "
  "so it was not really tested.")
if ok and prot_off is not None and prot_off < base_asr:
    a(f"- With all four defenses off, attacks drop from {base_asr}% to "
      f"{prot_off}%. Something else in the protected agent also blocks some "
      "attacks (maybe the approval step). Worth checking in the code.")
a("")

with open(os.path.join(ROOT, "FINAL_RESULTS.md"), "w", encoding="utf-8") as f:
    f.write("\n".join(lines))
with open(os.path.join(ROOT, "raw_outputs.txt"), "w", encoding="utf-8") as f:
    f.write("\n\n".join(raw))

print(f"\nDone in {int(time.time() - t0)} seconds.")
print("Report:  " + os.path.join(ROOT, "FINAL_RESULTS.md"))
print("Details: " + os.path.join(ROOT, "raw_outputs.txt"))
print("\n".join(lines[:12]))
