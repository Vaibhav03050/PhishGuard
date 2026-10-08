import concurrent.futures
import ipaddress
import re
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse

try:
    import dns.resolver
    import dns.exception
except Exception:  # pragma: no cover
    dns = None

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "lnkd.in", "rebrand.ly"
}
SUSPICIOUS_KEYWORDS = {
    "login", "signin", "verify", "verification", "account", "secure", "update",
    "password", "bank", "wallet", "confirm", "authenticate", "payment", "invoice",
    "recover", "unlock", "support", "security", "credential", "session",
    "kyc", "upi", "card", "otp", "loan", "refund", "transaction"
}

FEATURE_COLUMNS = [
    "having_IP_Address", "URL_Length", "Shortining_Service", "having_At_Symbol",
    "double_slash_redirecting", "Prefix_Suffix", "having_Sub_Domain", "SSLfinal_State",
    "Domain_registeration_length", "port", "HTTPS_token", "Abnormal_URL",
    "age_of_domain", "DNSRecord"
]


def _is_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _normalize_url(value: str) -> str:
    value = (value or "").strip()
    if not value:
        raise ValueError("URL cannot be empty")
    if not re.match(r"^https?://", value, re.I):
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Please enter a valid HTTP/HTTPS URL with a domain name")
    # Reject malformed hostnames that urlparse can technically accept.
    if any(ch.isspace() for ch in parsed.hostname):
        raise ValueError("The URL contains an invalid hostname")
    return value


def _dns_check(hostname: str):
    """Return (ok, message, status) with a hard DNS lifetime."""
    try:
        if dns is not None:
            resolver = dns.resolver.Resolver(configure=True)
            resolver.timeout = 0.7
            resolver.lifetime = 1.0
            resolver.resolve(hostname, "A")
            return True, "DNS record resolved", "resolved"

        # Fallback: gethostbyname uses the process socket timeout.
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(1.0)
        try:
            socket.gethostbyname(hostname)
        finally:
            socket.setdefaulttimeout(old_timeout)
        return True, "DNS record resolved", "resolved"
    except Exception as exc:
        name = exc.__class__.__name__.lower()
        if "timeout" in name or "timeouterror" in name:
            return False, "DNS check timed out; scan continued", "unavailable"
        if dns is not None and isinstance(exc, getattr(dns.resolver, "NXDOMAIN", ())):
            return False, "Domain does not have a DNS record", "unresolved"
        return False, "DNS record could not be resolved", "unresolved"


def _ssl_check(hostname: str, port: int = 443):
    """Validate TLS with a short timeout; never make the whole scan depend on it."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=1.5) as sock:
            sock.settimeout(1.5)
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expires = cert.get("notAfter")
                return True, expires, "valid"
    except ssl.SSLCertVerificationError:
        return False, None, "invalid"
    except ssl.SSLError:
        return False, None, "invalid"
    except (socket.timeout, TimeoutError):
        return False, None, "unavailable"
    except OSError:
        return False, None, "unavailable"
    except Exception:
        return False, None, "unavailable"


def _live_checks(hostname: str, scheme: str, port: int, ip_based: bool):
    """Run DNS/TLS checks concurrently with a hard overall response budget."""
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)
    futures = {"dns": executor.submit(_dns_check, hostname)}
    if scheme == "https" and not ip_based:
        futures["ssl"] = executor.submit(_ssl_check, hostname, port or 443)

    try:
        done, _ = concurrent.futures.wait(
            list(futures.values()), timeout=2.5
        )
        dns_future = futures["dns"]
        if dns_future in done:
            dns_ok, dns_message, dns_status = dns_future.result()
        else:
            dns_ok, dns_message, dns_status = False, "DNS check timed out; scan continued", "unavailable"

        if "ssl" in futures:
            ssl_future = futures["ssl"]
            if ssl_future in done:
                ssl_ok, ssl_expiry, ssl_status = ssl_future.result()
            else:
                ssl_ok, ssl_expiry, ssl_status = False, None, "unavailable"
        else:
            ssl_ok, ssl_expiry, ssl_status = False, None, "not_checked"
    except Exception:
        dns_ok, dns_message, dns_status = False, "DNS check unavailable; scan continued", "unavailable"
        ssl_ok, ssl_expiry, ssl_status = False, None, "unavailable"
    finally:
        # Do not keep a slow network lookup on the request path.
        executor.shutdown(wait=False, cancel_futures=True)

    return dns_ok, dns_message, dns_status, ssl_ok, ssl_expiry, ssl_status


def analyze_url(raw_url: str) -> dict:
    url = _normalize_url(raw_url)
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    path = parsed.path or ""
    port = parsed.port
    domain_parts = hostname.split(".") if hostname else []
    subdomain_count = max(0, len(domain_parts) - 2)
    ip_based = _is_ip(hostname)
    path_query = (parsed.path + "?" + (parsed.query or "")).lower()
    suspicious_keywords = sorted({
        k for k in SUSPICIOUS_KEYWORDS
        if k in path_query or (k in hostname and (hostname.startswith(k + "-") or hostname.endswith("-" + k)))
    })
    has_non_default_port = port not in (None, 80, 443)

    dns_ok, dns_message, dns_status, ssl_ok, ssl_expiry, ssl_status = _live_checks(
        hostname, parsed.scheme.lower(), port or (443 if parsed.scheme.lower() == "https" else 80), ip_based
    )

    url_len = len(url)
    # UCI feature encoding: short URLs are 1, medium are 0, long are -1.
    if url_len < 54:
        url_length_feature = 1
    elif url_len <= 75:
        url_length_feature = 0
    else:
        url_length_feature = -1

    shortener = any(hostname == s or hostname.endswith("." + s) for s in SHORTENERS)
    at_symbol = "@" in url
    double_slash_redirect = "//" in url.split("://", 1)[-1]
    prefix_suffix = "-" in hostname
    if subdomain_count == 0:
        subdomain_feature = -1
    elif subdomain_count <= 2:
        subdomain_feature = 0
    else:
        subdomain_feature = 1

    # Unknown live signals are kept neutral rather than treated as phishing.
    # UCI encoding: valid TLS = 1, invalid TLS = -1, unknown/unavailable = 0.
    if ssl_ok:
        ssl_feature = 1
    elif ssl_status == "invalid":
        ssl_feature = -1
    else:
        ssl_feature = 0
    https_token_suspicious = "https" in hostname
    abnormal = ip_based or bool(parsed.username) or bool(parsed.password) or any(c in hostname for c in ["_", "\\"])
    registration_length = 0
    age_of_domain = 0

    # The bundled ML model was trained on binary live-signal values. If a
    # hosting environment blocks outbound DNS/TLS, feeding 0 for both signals
    # can produce an artificially extreme probability. For model inference only,
    # use the safest URL-derived baseline when the live check is unavailable;
    # the UI still reports the live check as unavailable.
    model_ssl_feature = ssl_feature
    if ssl_status == "unavailable":
        model_ssl_feature = 1 if parsed.scheme.lower() == "https" else -1
    model_dns_feature = 1 if dns_ok else (-1 if dns_status == "unresolved" else 1)

    features = {
        "having_IP_Address": 1 if ip_based else -1,
        "URL_Length": url_length_feature,
        "Shortining_Service": 1 if shortener else -1,
        "having_At_Symbol": 1 if at_symbol else -1,
        "double_slash_redirecting": 1 if double_slash_redirect else -1,
        "Prefix_Suffix": 1 if prefix_suffix else -1,
        "having_Sub_Domain": subdomain_feature,
        "SSLfinal_State": model_ssl_feature,
        "Domain_registeration_length": registration_length,
        "port": 1 if has_non_default_port else -1,
        "HTTPS_token": 1 if https_token_suspicious else -1,
        "Abnormal_URL": 1 if abnormal else -1,
        "age_of_domain": age_of_domain,
        "DNSRecord": model_dns_feature,
    }

    reasons = []
    positive = []
    if ip_based:
        reasons.append(("IP address used instead of a domain", 22))
    if url_len > 75:
        reasons.append(("Unusually long URL", 12))
    if shortener:
        reasons.append(("URL shortening service detected", 15))
    if at_symbol:
        reasons.append(("@ symbol can obscure the real destination", 20))
    if double_slash_redirect:
        reasons.append(("Extra // redirect pattern in the URL", 10))
    if prefix_suffix:
        reasons.append(("Hyphen-heavy domain structure", 10))
    if subdomain_count >= 3:
        reasons.append(("Multiple nested subdomains", 12))
    if parsed.scheme.lower() != "https":
        reasons.append(("Connection is not using HTTPS", 18))
    elif ssl_status == "invalid":
        reasons.append(("HTTPS certificate could not be validated", 8))
    elif ssl_status == "valid":
        positive.append("HTTPS certificate validated")
    elif ssl_status == "unavailable":
        positive.append("SSL check unavailable; it was not used as a phishing signal")
    if has_non_default_port:
        reasons.append((f"Non-standard port detected ({port})", 10))
    if https_token_suspicious:
        reasons.append(("The word 'https' appears inside the hostname", 12))
    if suspicious_keywords:
        reasons.append(("Sensitive/phishing-related keyword(s): " + ", ".join(suspicious_keywords[:5]), 14))
    if dns_status == "unresolved":
        reasons.append(("Domain does not currently resolve in DNS", 15))
    elif dns_status == "resolved":
        positive.append("Domain resolves in DNS")
    else:
        positive.append("DNS check unavailable; it was not used as a phishing signal")
    if parsed.username or parsed.password:
        reasons.append(("Embedded username/password information in URL", 18))

    heuristic_points = min(100, sum(points for _, points in reasons))
    return {
        "url": url,
        "hostname": hostname,
        "scheme": parsed.scheme.lower(),
        "path": path,
        "port": port or (443 if parsed.scheme.lower() == "https" else 80),
        "subdomain_count": subdomain_count,
        "is_ip": ip_based,
        "dns_ok": dns_ok,
        "dns_status": dns_status,
        "dns_message": dns_message,
        "ssl_ok": ssl_ok,
        "ssl_status": ssl_status,
        "ssl_expiry": ssl_expiry,
        "suspicious_keywords": suspicious_keywords,
        "features": features,
        "feature_columns": FEATURE_COLUMNS,
        "reasons": reasons,
        "positive_signals": positive,
        "heuristic_points": heuristic_points,
        "checked_at": datetime.utcnow().isoformat() + "Z",
    }
