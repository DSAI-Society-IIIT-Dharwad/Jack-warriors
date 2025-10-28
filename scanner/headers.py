# scanner/headers.py
import requests

HEADERS = {"User-Agent": "VulnScanner/1.0 (+educational-testing)"}
REQUIRED_HEADERS = [
    ("Content-Security-Policy", "CSP"),
    ("X-Frame-Options", "Clickjacking protection"),
    ("X-XSS-Protection", "XSS filter (legacy)"),
    ("Strict-Transport-Security", "HSTS"),
    ("Referrer-Policy", "Referrer policy"),
]

def analyze(target_url, timeout=8):
    findings = []
    try:
        r = requests.get(target_url, headers=HEADERS, timeout=timeout, verify=True)
    except requests.exceptions.RequestException:
        return findings

    present = r.headers
    missing = []
    for header, desc in REQUIRED_HEADERS:
        if header not in present:
            missing.append(header)

    if missing:
        findings.append({
            "vulnerability": "Missing Security Headers",
            "type": "headers",
            "payload": "",
            "evidence": f"Missing headers: {', '.join(missing)}",
            "url": target_url,
            "confidence": 60,
            "severity": "Medium"
        })

    # check insecure header values heuristics
    # CSP too permissive? simple check if CSP contains '*'
    csp = present.get("Content-Security-Policy", "")
    if csp and "*" in csp:
        findings.append({
            "vulnerability": "Permissive Content-Security-Policy",
            "type": "headers",
            "payload": "",
            "evidence": f"CSP contains wildcard '*' -> {csp}",
            "url": target_url,
            "confidence": 70,
            "severity": "High"
        })

    # check for missing secure cookie attributes in set-cookie header (best-effort)
    sc = present.get("Set-Cookie", "")
    if sc and ("HttpOnly" not in sc or "Secure" not in sc):
        findings.append({
            "vulnerability": "Insecure cookie attributes",
            "type": "headers",
            "payload": "",
            "evidence": f"Set-Cookie lacks Secure/HttpOnly flags: {sc}",
            "url": target_url,
            "confidence": 60,
            "severity": "Medium"
        })

    return findings
