import os
import pickle
from pathlib import Path

import pandas as pd

from src.url_security.url_analyzer import FEATURE_COLUMNS

MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "phishing_url_model.pkl"


def load_model():
    if not MODEL_PATH.exists():
        return None
    with open(MODEL_PATH, "rb") as f:
        return pickle.load(f)


def predict(features: dict):
    model = load_model()
    if model is None:
        return 50.0, 0.5
    row = pd.DataFrame([[features[c] for c in FEATURE_COLUMNS]], columns=FEATURE_COLUMNS)
    probability = float(model.predict_proba(row)[0][1])
    return round(probability * 100, 2), probability


def build_result(analysis: dict):
    ml_score, _ = predict(analysis["features"])
    heuristic = float(analysis["heuristic_points"])
    # ML is the primary signal; deterministic checks provide a transparent
    # second signal. This keeps the result explainable rather than pretending
    # every signal came from the model.
    final_score = round(min(100.0, 0.60 * ml_score + 0.40 * heuristic), 1)

    # Safety-oriented guardrails for obvious patterns. These do not replace the
    # model; they prevent a low model score from hiding a strong deterministic
    # phishing signal in a user-facing security tool.
    risky_count = len(analysis["reasons"])
    if analysis["is_ip"] or "@" in analysis["url"] or any("Embedded username/password" in r[0] for r in analysis["reasons"]):
        final_score = max(final_score, 82.0)
    if analysis["suspicious_keywords"] and analysis["scheme"] != "https":
        final_score = max(final_score, 75.0)
    if risky_count >= 4:
        final_score = max(final_score, 72.0)
    if not analysis["is_ip"] and analysis["dns_ok"] and analysis["ssl_ok"] and risky_count == 0:
        final_score = min(final_score, 20.0)

    if final_score >= 80:
        level = "Critical"
        label = "Likely Phishing"
    elif final_score >= 60:
        level = "High"
        label = "Suspicious"
    elif final_score >= 35:
        level = "Medium"
        label = "Needs Caution"
    else:
        level = "Low"
        label = "Likely Safe"
    return {
        "ml_score": ml_score,
        "heuristic_score": round(heuristic, 1),
        "risk_score": final_score,
        "risk_level": level,
        "prediction": label,
        "reasons": [r[0] for r in analysis["reasons"]],
        "positive_signals": analysis["positive_signals"],
    }
