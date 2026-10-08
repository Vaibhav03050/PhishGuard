"""Train the live URL model from the bundled UCI phishing feature dataset."""
import json
import pickle
from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from sklearn.model_selection import train_test_split

FEATURES = [
    "having_IP_Address", "URL_Length", "Shortining_Service", "having_At_Symbol",
    "double_slash_redirecting", "Prefix_Suffix", "having_Sub_Domain", "SSLfinal_State",
    "Domain_registeration_length", "port", "HTTPS_token", "Abnormal_URL",
    "age_of_domain", "DNSRecord"
]

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "notebook implementation" / "phising.csv"
MODEL_DIR = ROOT / "models"
MODEL_DIR.mkdir(exist_ok=True)


def main():
    df = pd.read_csv(DATA)
    X = df[FEATURES]
    y = (df["Result"] == -1).astype(int)  # 1 = phishing, 0 = legitimate
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=42
    )
    model = RandomForestClassifier(
        n_estimators=400,
        max_depth=12,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)
    pred = model.predict(X_test)
    prob = model.predict_proba(X_test)[:, 1]
    metrics = {
        "model": "RandomForestClassifier",
        "dataset_rows": len(df),
        "features": FEATURES,
        "accuracy": round(accuracy_score(y_test, pred), 4),
        "precision": round(precision_score(y_test, pred), 4),
        "recall": round(recall_score(y_test, pred), 4),
        "f1": round(f1_score(y_test, pred), 4),
        "roc_auc": round(roc_auc_score(y_test, prob), 4),
    }
    with open(MODEL_DIR / "phishing_url_model.pkl", "wb") as f:
        pickle.dump(model, f)
    (MODEL_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2))
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
