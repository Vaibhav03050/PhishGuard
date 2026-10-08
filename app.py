
from flask import Flask, jsonify, render_template, request, make_response
import csv
import io
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.exception import CustomException
from src.logger import logging as lg
from src.url_security.url_analyzer import analyze_url
from src.url_security.risk_engine import build_result
from src.url_security.history import recent_scans, save_scan
from src.email_security.email_analyzer import analyze_email

app = Flask(__name__)

@app.after_request
def add_cors_headers(response):
    # Required by the optional browser extension. The API does not store
    # credentials, so it can safely expose these scan endpoints.
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response

@app.route("/")
def home():
    return render_template("prediction.html", history=recent_scans())

@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "PhishGuard"})

def _scan_url_payload(raw_url):
    analysis = analyze_url(raw_url)
    result = build_result(analysis)
    result.update({
        "url": analysis["url"],
        "hostname": analysis["hostname"],
        "scheme": analysis["scheme"],
        "port": analysis["port"],
        "subdomain_count": analysis["subdomain_count"],
        "dns_ok": analysis["dns_ok"],
        "dns_message": analysis["dns_message"],
        "dns_status": analysis.get("dns_status", "unknown"),
        "ssl_ok": analysis["ssl_ok"],
        "ssl_status": analysis.get("ssl_status", "unknown"),
        "ssl_expiry": analysis["ssl_expiry"],
        "suspicious_keywords": analysis["suspicious_keywords"],
        "features": analysis["features"],
        "checked_at": analysis["checked_at"],
    })
    return analysis, result

@app.route("/scan", methods=["POST", "OPTIONS"])
def scan():
    if request.method == "OPTIONS":
        return ("", 204)
    try:
        payload = request.get_json(silent=True) or {}
        raw_url = payload.get("url") or request.form.get("url")
        analysis, result = _scan_url_payload(raw_url)
        save_scan(analysis["url"], result["prediction"], result["risk_score"],
                  result["risk_level"], analysis["checked_at"])
        lg.info("URL scan completed: %s", analysis["hostname"])
        return jsonify(result)
    except Exception as e:
        lg.exception("URL scan failed")
        return jsonify({"error": str(e)}), 400

@app.route("/scan-email", methods=["POST", "OPTIONS"])
def scan_email():
    if request.method == "OPTIONS":
        return ("", 204)
    try:
        payload = request.get_json(silent=True) or {}
        if request.files.get("file"):
            raw = request.files["file"].read().decode("utf-8-sig", errors="replace")
            email_text = raw
        else:
            email_text = payload.get("email") or request.form.get("email") or ""
        sender = payload.get("sender") or request.form.get("sender") or ""
        subject = payload.get("subject") or request.form.get("subject") or ""
        receiver = payload.get("receiver") or request.form.get("receiver") or ""

        if not email_text.strip() and not any([sender, subject]):
            return jsonify({"error": "Enter an email message or provide email fields."}), 400

        result = analyze_email(sender, subject, email_text, receiver)
        url_results = []

        # Limit URL lookups so one email cannot create a large number of
        # outbound network requests.
        urls = result["urls"][:5]
        if urls:
            with ThreadPoolExecutor(max_workers=min(4, len(urls))) as pool:
                futures = {pool.submit(_scan_url_payload, u): u for u in urls}
                for future in as_completed(futures):
                    u = futures[future]
                    try:
                        analysis, scan_result = future.result()
                        url_results.append({
                            "url": analysis["url"],
                            "prediction": scan_result["prediction"],
                            "risk_score": scan_result["risk_score"],
                            "risk_level": scan_result["risk_level"],
                            "reasons": scan_result["reasons"][:4],
                        })
                    except Exception as exc:
                        url_results.append({
                            "url": u, "prediction": "Could not scan",
                            "risk_score": None, "risk_level": "Unavailable",
                            "reasons": [str(exc)]
                        })

        max_url_score = max(
            [float(x["risk_score"]) for x in url_results if x["risk_score"] is not None],
            default=0.0
        )
        # Email content is the primary signal; linked URL analysis adds context.
        final_score = round(0.70 * float(result["email_score"]) + 0.30 * max_url_score, 1) if url_results else float(result["email_score"])
        if result["domain_mismatch"]:
            final_score = max(final_score, 65.0)
        final_score = min(100.0, final_score)

        if final_score >= 70:
            level, prediction = "High", "Likely Phishing"
        elif final_score >= 40:
            level, prediction = "Medium", "Needs Caution"
        else:
            level, prediction = "Low", "Likely Safe"

        reasons = list(result["reasons"])
        if max_url_score >= 70:
            reasons.append("A linked URL was rated high risk")
        elif max_url_score >= 40:
            reasons.append("A linked URL needs additional caution")

        return jsonify({
            "prediction": prediction,
            "risk_level": level,
            "risk_score": final_score,
            "email_score": result["email_score"],
            "url_max_score": max_url_score,
            "urls_found": len(result["urls"]),
            "urls_scanned": len(url_results),
            "reasons": reasons,
            "url_results": url_results,
            "sender": result["sender"],
            "subject": result["subject"],
            "sender_domain": result["sender_domain"],
            "link_domains": result["link_domains"],
            "checked_at": __import__("datetime").datetime.utcnow().isoformat() + "Z"
        })
    except Exception as e:
        lg.exception("Email scan failed")
        return jsonify({"error": str(e)}), 400

@app.route("/predict", methods=["GET", "POST"])
def predict():
    if request.method == "GET":
        return render_template("prediction.html", history=recent_scans())
    return scan()

@app.route("/scan-batch", methods=["POST"])
def scan_batch():
    try:
        uploaded = request.files.get("file")
        if not uploaded:
            return jsonify({"error": "Upload a CSV file with a 'url' column."}), 400
        text = uploaded.read().decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames or "url" not in [x.strip().lower() for x in reader.fieldnames]:
            return jsonify({"error": "CSV must contain a 'url' column."}), 400
        url_col = next(x for x in reader.fieldnames if x.strip().lower() == "url")
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["url", "prediction", "risk_score", "risk_level"])
        writer.writeheader()
        for row in reader:
            url = row.get(url_col, "")
            try:
                analysis, result = _scan_url_payload(url)
                writer.writerow({"url": analysis["url"], "prediction": result["prediction"],
                                 "risk_score": result["risk_score"], "risk_level": result["risk_level"]})
                save_scan(analysis["url"], result["prediction"], result["risk_score"],
                          result["risk_level"], analysis["checked_at"])
            except Exception:
                writer.writerow({"url": url, "prediction": "Invalid URL", "risk_score": "", "risk_level": ""})
        response = app.response_class(output.getvalue(), mimetype="text/csv")
        response.headers["Content-Disposition"] = "attachment; filename=phishing_scan_results.csv"
        return response
    except Exception as e:
        raise CustomException(e, sys)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
