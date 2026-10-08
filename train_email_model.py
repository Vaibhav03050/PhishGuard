
import json
import os
import re
import zipfile
from pathlib import Path

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

SOURCE_FILES = [
    "CEAS_08.csv", "Enron.csv", "Ling.csv",
    "SpamAssasin.csv", "phishing_email.csv"
]

def load_sources(zip_path):
    rows = []
    with zipfile.ZipFile(zip_path) as z:
        names = set(z.namelist())
        for name in SOURCE_FILES:
            if name not in names:
                continue
            with z.open(name) as f:
                df = pd.read_csv(f, low_memory=False)
            if name == "phishing_email.csv":
                text = df["text_combined"].fillna("").astype(str)
            else:
                cols = [c for c in ["sender", "receiver", "subject", "body"] if c in df.columns]
                text = df[cols].fillna("").astype(str).agg(" ".join, axis=1)
            part = pd.DataFrame({
                "text": text.str.replace(r"\s+", " ", regex=True).str.strip(),
                "label": pd.to_numeric(df["label"], errors="coerce").fillna(0).astype(int),
                "source": name,
            })
            part = part[part.text.str.len() > 10]
            if len(part) > 20000:
                from sklearn.model_selection import train_test_split
                part, _ = train_test_split(
                    part, test_size=len(part) - 20000,
                    stratify=part["label"] if part["label"].nunique() > 1 else None,
                    random_state=42
                )
            rows.append(part)
    data = pd.concat(rows, ignore_index=True)
    data["normalized"] = data.text.str.lower().str.replace(r"\W+", " ", regex=True).str.strip()
    return data.drop_duplicates("normalized").drop(columns="normalized").reset_index(drop=True)

def train(zip_path, output_dir="models"):
    data = load_sources(zip_path)
    vectorizer = TfidfVectorizer(
        lowercase=True, strip_accents="unicode", sublinear_tf=True,
        ngram_range=(1, 1), min_df=3, max_features=15000
    )
    X = vectorizer.fit_transform(data.text)
    model = LogisticRegression(
        max_iter=350, C=2.0, class_weight="balanced", solver="liblinear"
    )
    model.fit(X, data.label)

    os.makedirs(output_dir, exist_ok=True)
    import pickle
    with open(Path(output_dir) / "email_phishing_model.pkl", "wb") as f:
        pickle.dump({"vectorizer": vectorizer, "model": model,
                     "thresholds": {"medium": 0.40, "high": 0.70}}, f,
                    protocol=pickle.HIGHEST_PROTOCOL)

    print(f"Training rows: {len(data)}")
    print(f"Positive: {int(data.label.sum())}")
    print(f"Negative: {int((data.label == 0).sum())}")
    print("Saved models/email_phishing_model.pkl")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Train the PhishGuard email model.")
    parser.add_argument("dataset_zip", help="Path to the email dataset ZIP")
    args = parser.parse_args()
    train(args.dataset_zip)
