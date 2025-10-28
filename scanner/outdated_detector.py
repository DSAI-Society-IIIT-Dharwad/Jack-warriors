# scanner/outdated_detector.py
import requests
from bs4 import BeautifulSoup
import re

HEADERS = {"User-Agent": "VulnScanner/1.0 (+educational-testing)"}

# Heuristic: flag jQuery 1.x or 2.x as outdated; flag older bootstrap 3.x as medium
def analyze(target_url, timeout=8):
    findings = []
    try:
        r = requests.get(target_url, headers=HEADERS, timeout=timeout, verify=True)
        html = r.text
    except requests.exceptions.RequestException:
        return findings

    soup = BeautifulSoup(html, "html.parser")
    scripts = soup.find_all("script", src=True)
    for s in scripts:
        src = s.get("src")
        # jQuery detection
        m = re.search(r"jquery(?:\.min)?\.js(?:\?ver=([\d\.]+))?|jquery-([\d\.]+)(?:\.min)?\.js", src or "", re.I)
        if m:
            ver = (m.group(1) or m.group(2) or "").strip()
            if ver:
                major = ver.split(".")[0]
                try:
                    maj = int(major)
                except:
                    maj = 99
                if maj <= 2:
                    findings.append({
                        "vulnerability": "Outdated jQuery detected",
                        "type": "outdated-js",
                        "payload": ver,
                        "evidence": f"jQuery version {ver} found in {src}",
                        "url": target_url,
                        "confidence": 80,
                        "severity": "High"
                    })
                elif maj == 3:
                    findings.append({
                        "vulnerability": "Old jQuery (3.x) detected",
                        "type": "outdated-js",
                        "payload": ver,
                        "evidence": f"jQuery version {ver} found in {src}",
                        "url": target_url,
                        "confidence": 50,
                        "severity": "Medium"
                    })
        # bootstrap detection
        m2 = re.search(r"bootstrap(?:\.min)?\.js(?:\?ver=([\d\.]+))?|bootstrap-([\d\.]+)(?:\.min)?\.js", src or "", re.I)
        if m2:
            ver = (m2.group(1) or m2.group(2) or "").strip()
            if ver:
                major = ver.split(".")[0]
                try:
                    maj = int(major)
                except:
                    maj = 99
                if maj <= 3:
                    findings.append({
                        "vulnerability": "Outdated Bootstrap detected",
                        "type": "outdated-js",
                        "payload": ver,
                        "evidence": f"Bootstrap version {ver} found in {src}",
                        "url": target_url,
                        "confidence": 65,
                        "severity": "Medium"
                    })
    return findings
