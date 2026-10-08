
import html
import pickle
import re
from pathlib import Path
from urllib.parse import urlparse

MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "email_phishing_model.pkl"
URL_RE = re.compile(r'(?i)\b(?:https?://|www\.)[^\s<>"\']+')
URGENCY = {
    "urgent", "immediately", "action required", "act now", "within 24 hours",
    "suspended", "blocked", "expire", "expires", "final notice", "warning",
    "verify now", "respond immediately"
}
CREDENTIALS = {
    "verify your account", "confirm your identity", "reset your password",
    "login", "sign in", "password", "credential", "authenticate", "kyc",
    "otp", "one time password", "security code"
}
FINANCIAL = {
    "bank", "upi", "payment", "refund", "invoice", "loan", "credit card",
    "debit card", "wallet", "transaction", "tax", "wire transfer"
}

_model_bundle = None

def load_email_model():
    global _model_bundle
    if _model_bundle is None:
        if not MODEL_PATH.exists():
            return None
        with open(MODEL_PATH, "rb") as f:
            _model_bundle = pickle.load(f)
    return _model_bundle

def extract_urls(text):
    found = []
    for raw in URL_RE.findall(text or ""):
        url = raw.rstrip(".,;:!?)]}>\"'")
        if url.lower().startswith("www."):
            url = "https://" + url
        if url not in found:
            found.append(url)
    return found

def _sender_domain(sender):
    m = re.search(r'[\w.+-]+@([\w.-]+\.[A-Za-z]{2,})', sender or "")
    return m.group(1).lower() if m else ""

def _link_domains(urls):
    domains = []
    for u in urls:
        try:
            host = urlparse(u).hostname
            if host:
                domains.append(host.lower().rstrip("."))
        except Exception:
            pass
    return sorted(set(domains))

def analyze_email(sender="", subject="", body="", receiver=""):
    sender = sender or ""
    subject = subject or ""
    body = body or ""
    receiver = receiver or ""
    combined = " ".join([sender, subject, body])
    urls = extract_urls(combined)

    bundle = load_email_model()
    if bundle is None:
        email_score = 50.0
    else:
        text = re.sub(r"\s+", " ", combined).strip()
        x = bundle["vectorizer"].transform([text])
        email_score = round(float(bundle["model"].predict_proba(x)[0][1]) * 100, 2)

    lower = combined.lower()
    matched_urgency = sorted(k for k in URGENCY if k in lower)
    matched_credentials = sorted(k for k in CREDENTIALS if k in lower)
    matched_financial = sorted(k for k in FINANCIAL if k in lower)

    sender_domain = _sender_domain(sender)
    link_domains = _link_domains(urls)
    domain_mismatch = bool(sender_domain and link_domains and
                           not any(d == sender_domain or d.endswith("." + sender_domain)
                                   for d in link_domains))

    reasons = []
    if matched_urgency:
        reasons.append("Urgency or account-pressure language detected")
    if matched_credentials:
        reasons.append("Credential or identity-verification language detected")
    if matched_financial:
        reasons.append("Financial or payment-related language detected")
    if domain_mismatch:
        reasons.append("Sender domain does not match the linked domain")
    if len(urls) >= 3:
        reasons.append("Multiple external links detected")
    if any(urlparse(u).scheme.lower() == "http" for u in urls):
        reasons.append("One or more links use an unsecured HTTP connection")

    # Transparent, small rule adjustment. The model remains the main signal.
    rule_score = min(100, len(reasons) * 8)
    url_max_score = 0.0

    if email_score >= 70:
        level, prediction = "High", "Likely Phishing"
    elif email_score >= 40:
        level, prediction = "Medium", "Needs Caution"
    else:
        level, prediction = "Low", "Likely Safe"

    return {
        "sender": sender,
        "receiver": receiver,
        "subject": subject,
        "urls": urls,
        "sender_domain": sender_domain,
        "link_domains": link_domains,
        "domain_mismatch": domain_mismatch,
        "email_score": email_score,
        "rule_score": rule_score,
        "risk_score": email_score,
        "risk_level": level,
        "prediction": prediction,
        "reasons": reasons,
        "matched_urgency": matched_urgency,
        "matched_credentials": matched_credentials,
        "matched_financial": matched_financial,
    }
