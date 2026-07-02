# phishing-url-detector
"""
Phishing URL Detector
----------------------
A beginner-friendly web security project that analyzes a URL for common
phishing red flags and returns a risk score.

This is a RULE-BASED detector (not machine learning) so it's easy to
understand, explain, and extend. Great first "web security" project.
"""

from flask import Flask, render_template, request
from urllib.parse import urlparse
import re

app = Flask(__name__)

# Common URL shorteners that phishers often abuse to hide the real destination
SUSPICIOUS_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly"
]

# Words phishers commonly stuff into fake URLs to look legitimate
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "update", "secure", "banking",
    "confirm", "signin", "password", "billing"
]


def is_ip_address(host: str) -> bool:
    """Check if the hostname is a raw IP address instead of a domain name."""
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    return bool(re.match(pattern, host))


def analyze_url(url: str) -> dict:
    """
    Run a series of checks on the URL and return a dict with:
    - score: 0-100 risk score (higher = more suspicious)
    - findings: list of (flag_triggered: bool, message: str) tuples
    """
    findings = []
    score = 0

    # Make sure the URL has a scheme so urlparse works correctly
    parse_target = url if "://" in url else "http://" + url
    parsed = urlparse(parse_target)
    host = parsed.hostname or ""

    # 1. Uses HTTP instead of HTTPS
    if parsed.scheme == "http":
        findings.append((True, "Uses insecure HTTP instead of HTTPS"))
        score += 15
    else:
        findings.append((False, "Uses HTTPS"))

    # 2. Hostname is a raw IP address
    if is_ip_address(host):
        findings.append((True, "Uses an IP address instead of a domain name"))
        score += 25
    else:
        findings.append((False, "Uses a proper domain name"))

    # 3. Contains "@" symbol (browsers ignore everything before @)
    if "@" in url:
        findings.append((True, "Contains '@' symbol (can hide the real destination)"))
        score += 20
    else:
        findings.append((False, "No '@' symbol trick detected"))

    # 4. Excessive subdomains (e.g. paypal.com.verify.fake-site.com)
    subdomain_count = host.count(".") - 1 if host else 0
    if subdomain_count > 3:
        findings.append((True, f"Excessive subdomains ({subdomain_count} found)"))
        score += 15
    else:
        findings.append((False, "Normal number of subdomains"))

    # 5. Very long URL (phishing links are often long to hide the true domain)
    if len(url) > 75:
        findings.append((True, f"Unusually long URL ({len(url)} characters)"))
        score += 10
    else:
        findings.append((False, "Reasonable URL length"))

    # 6. Excessive hyphens in domain (e.g. paypal-secure-login.com)
    if host.count("-") >= 2:
        findings.append((True, "Multiple hyphens in domain name"))
        score += 10
    else:
        findings.append((False, "No excessive hyphens in domain"))

    # 7. Known URL shortener
    if any(shortener in host for shortener in SUSPICIOUS_SHORTENERS):
        findings.append((True, "Uses a URL shortener (hides real destination)"))
        score += 15
    else:
        findings.append((False, "Not a known URL shortener"))

    # 8. Suspicious keywords in the URL
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url.lower()]
    if found_keywords:
        findings.append((True, f"Contains suspicious keyword(s): {', '.join(found_keywords)}"))
        score += 10
    else:
        findings.append((False, "No suspicious keywords found"))

    score = min(score, 100)

    if score >= 60:
        risk_level = "High Risk"
    elif score >= 30:
        risk_level = "Medium Risk"
    else:
        risk_level = "Low Risk"

    return {"score": score, "risk_level": risk_level, "findings": findings, "url": url}


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if url:
            result = analyze_url(url)
    return render_template("index.html", result=result)


if __name__ == "__main__":
    app.run(debug=True)
