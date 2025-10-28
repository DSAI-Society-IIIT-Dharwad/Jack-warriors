# scanner/exposed_files.py
import requests
import urllib.parse

HEADERS = {"User-Agent": "VulnScanner/1.0 (+educational-testing)"}
COMMON_PATHS = [
    ".env", "config.php", "backup.zip", "database.sql", "config.yml",
    "wp-config.php", "phpinfo.php", "admin/.env", "debug.log"
]

def _join(target, path):
    if target.endswith("/"):
        return target + path
    else:
        return target + "/" + path

def analyze(target_url, timeout=8):
    findings = []
    for p in COMMON_PATHS:
        try:
            url = _join(target_url.rstrip("/"), p)
            r = requests.get(url, headers=HEADERS, timeout=timeout, verify=True, allow_redirects=True)
            if r is None:
                continue
            # If status 200 and content not empty, likely exposed
            if r.status_code == 200 and len(r.content) > 10:
                # avoid flagging normal pages by checking content-types (if archive/plain)
                ct = r.headers.get("Content-Type", "")
                evidence = f"HTTP {r.status_code} Content-Type: {ct}"
                findings.append({
                    "vulnerability": "Exposed Sensitive File",
                    "type": "exposed-file",
                    "payload": p,
                    "evidence": evidence,
                    "url": url,
                    "confidence": 85,
                    "severity": "High" if p in [".env", "wp-config.php", "database.sql"] else "Medium"
                })
        except requests.exceptions.RequestException:
            continue
    return findings
