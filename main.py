# main.py
import sys
from scanner.sql_injection import analyze as sqli_analyze
from scanner.xss import analyze as xss_analyze
from scanner.headers import analyze as headers_analyze
from scanner.exposed_files import analyze as exposed_analyze
from scanner.csrf_scanner import analyze as csrf_analyze
from scanner.outdated_detector import analyze as outdated_analyze
from utils.report_generator import generate_report

def severity_from_conf(conf):
    return "High" if conf >= 80 else "Medium" if conf >= 50 else "Low"

def normalize_findings(raw_list):
    normalized = []
    for f in raw_list:
        # expected to include keys like vulnerability, type, evidence, url, confidence
        nf = {
            "vulnerability": f.get("vulnerability", "Unknown"),
            "type": f.get("type", ""),
            "payload": f.get("payload", ""),
            "evidence": f.get("evidence", ""),
            "url": f.get("url", ""),
            "confidence": f.get("confidence", 50),
            "severity": f.get("severity") or severity_from_conf(f.get("confidence", 50))
        }
        normalized.append(nf)
    return normalized

def main():
    if len(sys.argv) < 2:
        print("Usage: py main.py <target_url>")
        print("Example: py main.py http://testphp.vulnweb.com/")
        sys.exit(1)

    target = sys.argv[1].strip()
    print(f"\n🔍 Starting vulnerability scan for: {target}\n")

    findings = []

    # Run each scanner, extend findings
    scanners = [
        ("SQL Injection", sqli_analyze),
        ("Reflected XSS", xss_analyze),
        ("Headers", headers_analyze),
        ("Exposed Files", exposed_analyze),
        ("CSRF", csrf_analyze),
        ("Outdated Components", outdated_analyze),
    ]

    for name, func in scanners:
        print(f"[*] Running {name} scanner...")
        try:
            raw = func(target)
            if raw:
                normalized = normalize_findings(raw)
                findings.extend(normalized)
                print(f"    -> {len(normalized)} findings from {name}")
            else:
                print("    -> No findings")
        except Exception as e:
            print(f"    -> Scanner {name} crashed: {e}")

    if findings:
        print(f"\n[!] {len(findings)} potential issues found. Generating report...")
        generate_report(target, findings, filename="report.pdf")
        print("📄 Report created: report.pdf")
    else:
        print("\n✅ No significant vulnerabilities detected.")

if __name__ == "__main__":
    main()
