# main.py
import sys
import argparse
from scanner.sql_injection import analyze as sqli_analyze
from scanner.xss_scanner import analyze as xss_analyze
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
        nf = {
            "name": f.get("vulnerability", f.get("name", "Unknown")),
            "type": f.get("type", ""),
            "payload": f.get("payload", ""),
            "description": f.get("evidence", ""),
            "url": f.get("url", ""),
            "confidence": f.get("confidence", 50),
            "severity": f.get("severity") or severity_from_conf(f.get("confidence", 50)),
            "recommendation": f.get("recommendation", "")
        }
        normalized.append(nf)
    return normalized

def run_scanners(target):
    findings = []
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
    return findings

def main():
    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner")
    parser.add_argument("target", nargs="?", help="Target URL (e.g. http://example.com/page.php?id=1)")
    parser.add_argument("--team", default="Team CyberShield", help="Team name for report")
    parser.add_argument("--logo", default=None, help="Path to team logo for report (optional)")
    args = parser.parse_args()

    if not args.target:
        # interactive prompt if no positional provided
        args.target = input("Enter target URL (e.g., http://testphp.vulnweb.com/): ").strip()
        if not args.target:
            print("No target provided. Exiting.")
            sys.exit(1)

    target = args.target
    print(f"\n🔍 Starting vulnerability scan for: {target}\n")

    findings = run_scanners(target)

    if findings:
        print(f"\n[!] {len(findings)} potential issues found. Generating report...")
        # generate_report(results, output_file="scan_report.pdf", team_name="Team...", logo_path=...)
        generate_report(findings, output_file="scan_report.pdf", team_name=args.team, logo_path=args.logo)
        print("📄 Report created: scan_report.pdf")
    else:
        # still produce a clean report indicating no findings
        print("\n✅ No significant vulnerabilities detected. Generating clean report...")
        generate_report([], output_file="scan_report.pdf", team_name=args.team, logo_path=args.logo)
        print("📄 Report created: scan_report.pdf")

if __name__ == "__main__":
    main()
