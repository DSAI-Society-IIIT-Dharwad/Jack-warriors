# scanner/csrf_scanner.py
import requests
from bs4 import BeautifulSoup
import urllib.parse

HEADERS = {"User-Agent": "VulnScanner/1.0 (+educational-testing)"}

def _ensure_request(url, timeout=8):
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout, verify=True)
        return r.text if r is not None else ""
    except requests.exceptions.RequestException:
        return ""

def analyze(target_url, timeout=8):
    """
    Detects forms that use POST but have no obvious CSRF token input.
    This is heuristic-based.
    """
    findings = []
    html = _ensure_request(target_url, timeout=timeout)
    if not html:
        return findings

    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")
    for form in forms:
        method = (form.get("method") or "get").lower()
        if method != "post":
            continue
        # look for hidden inputs with token-like names
        inputs = form.find_all("input")
        token_found = False
        token_names = ["csrf", "token", "authenticity_token", "xsrf", "_csrf"]
        for inp in inputs:
            t = inp.get("type", "").lower()
            name = (inp.get("name") or "").lower()
            if t == "hidden" and any(x in name for x in token_names):
                token_found = True
                break
        action = form.get("action") or target_url
        if not token_found:
            findings.append({
                "vulnerability": "Possible Missing CSRF Protection",
                "type": "csrf",
                "payload": "",
                "evidence": f"POST form with no CSRF-like hidden inputs. action={action}",
                "url": target_url,
                "confidence": 70,
                "severity": "High"
            })
    return findings
