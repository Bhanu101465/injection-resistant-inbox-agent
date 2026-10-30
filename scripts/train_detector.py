"""
Train a TF-IDF + LogisticRegression injection detector.

Usage:
    python scripts/train_detector.py

Reads all emails from data/emails/, splits by email id (deterministic),
trains on 80% and tests on 20%, then saves models/detector.joblib.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.pipeline import Pipeline

# ---------------------------------------------------------------------------
# Load emails
# ---------------------------------------------------------------------------

def _load_emails():
    rows = []
    for path in sorted((ROOT / "data" / "emails").rglob("*.json")):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        label = 1 if data.get("label") == "attack" else 0
        text = " ".join([
            data.get("subject", ""),
            data.get("body_text", ""),
            data.get("body_html", ""),
        ])
        rows.append((data["id"], text, label))
    return rows


def _split(rows):
    """Deterministic split by email id: ids ending in odd digit → test."""
    train, test = [], []
    for eid, text, label in rows:
        # use last char of id digit as split key
        last_digit = next((c for c in reversed(eid) if c.isdigit()), "0")
        if int(last_digit) % 5 == 0:
            test.append((eid, text, label))
        else:
            train.append((eid, text, label))
    return train, test


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    rows = _load_emails()
    if len(rows) < 4:
        print("Not enough emails to train; aborting.")
        sys.exit(1)

    train, test = _split(rows)
    print(f"Train: {len(train)} | Test: {len(test)}")

    X_train = [r[1] for r in train]
    y_train = [r[2] for r in train]
    X_test  = [r[1] for r in test]
    y_test  = [r[2] for r in test]

    model = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=10_000,
            sublinear_tf=True,
        )),
        ("clf", LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            C=1.0,
        )),
    ])

    model.fit(X_train, y_train)

    print("\n=== Test-set report ===")
    preds = model.predict(X_test)
    print(classification_report(y_test, preds, target_names=["benign", "attack"], zero_division=0))

    out = ROOT / "models" / "detector.joblib"
    out.parent.mkdir(exist_ok=True)
    joblib.dump(model, out)
    print(f"Model saved → {out}")


if __name__ == "__main__":
    main()
