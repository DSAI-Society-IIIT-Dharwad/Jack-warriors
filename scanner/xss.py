# scanner/xss_scanner.py
import requests
import urllib.parse
import time

HEADERS = {"User-Agent": "VulnScanner/1.0 (+educational-testing)"}
DEFAULT_TIMEOUT = 8

# Simple reflected XSS payloads (start small; expand later)
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
]

def _ensure_param(url):
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    if qs:
        return url
    sep = '&' if parsed.query else '?'
    return url + sep + "q=test"

def _inject(url, value):
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    if not qs:
        new_qs = [("q", value)]
    else:
        # replace first param value
        new_qs = [(qs[0][0], value)] + qs[1:]
    new_query = urllib.parse.urlencode(new_qs, doseq=True)
    return parsed._replace(query=new_query).geturl()

def _safe_get(url, timeout=DEFAULT_TIMEOUT):
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout, verify=True)
        return r
    except requests.exceptions.RequestException:
        return None

def analyze(target_url, timeout=DEFAULT_TIMEOUT):
    """
    Returns list of findings:
    { "payload": ..., "evidence": ..., "detail": injected_url, "confidence": 0-100, "type": "reflected" }
    """
    findings = []
    target = _ensure_param(target_url)

    # baseline fetch
    normal_url = _inject(target, "test123")
    normal_resp = _safe_get(normal_url, timeout=timeout)
    normal_text = normal_resp.text if normal_resp is not None else ""
    normal_len = len(normal_text)

    for payload in XSS_PAYLOADS:
        test_url = _inject(target, payload)
        resp = _safe_get(test_url, timeout=timeout)
        if resp is None:
            continue
        text = resp.text

        # 1) Direct reflection: payload appears verbatim in response
        if payload in text:
            # ensure it's not just echoed as harmless (some sites always reflect)
            confidence = 60
            # if script tag appears, higher confidence
            if "<script" in payload or "onerror" in payload or "svg" in payload:
                confidence = 85
            findings.append({
                "payload": payload,
                "type": "reflected",
                "evidence": "Payload reflected verbatim in response",
                "detail": test_url,
                "confidence": confidence
            })
            continue

        # 2) Heuristic: significant length change + presence of parts of payload (like 'alert(1)')
        if "alert(1)" in text or "onerror" in text or "svg" in text:
            findings.append({
                "payload": payload,
                "type": "reflected",
                "evidence": "Partial payload content found (e.g., alert/onerror/svg)",
                "detail": test_url,
                "confidence": 65
            })
            continue

        # 3) Compare lengths — big change could indicate processing/reflection
        if abs(len(text) - normal_len) > max(200, normal_len * 0.2):
            findings.append({
                "payload": payload,
                "type": "reflected",
                "evidence": "Large response size difference vs baseline (possible reflection)",
                "detail": test_url,
                "confidence": 35
            })

    return findings

# quick run
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python xss_scanner.py <target_url>")
        sys.exit(1)
    out = analyze(sys.argv[1])
    if not out:
        print("[+] No reflected XSS detected.")
    else:
        for f in out:
            print(f"[!] Payload: {f['payload']} | Confidence: {f['confidence']}%")
            print(f"    Evidence: {f['evidence']}")
            print(f"    URL: {f['detail']}")
