import sys
import concurrent.futures
import requests
from utils.report_generator import generate_report
from scanner.sql_injection import analyze as sqli_analyze
from scanner.xss_scanner import analyze as xss_analyze

def scan_url(url):
    """Runs all scanners for a single URL and returns combined results."""
    results = []
    try:
        results.extend(sqli_analyze(url))
        results.extend(xss_analyze(url))
    except Exception as e:
        print(f"[!] Error scanning {url}: {e}")
    return results

def main():
    if len(sys.argv) < 2:
        print("Usage: py main.py <target_url>")
        print("Example: py main.py http://testphp.vulnweb.com/")
        return

    target = sys.argv[1]

    # Example: you can later load multiple URLs from a list or file
    urls_to_scan = [target]

    print(f"🔍 Starting concurrent scan on {len(urls_to_scan)} URL(s)...\n")

    all_results = []

    # ⚡ Run scans in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_url = {executor.submit(scan_url, url): url for url in urls_to_scan}
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                results = future.result()
                all_results.extend(results)
                print(f"✅ Completed scan for: {url}")
            except Exception as e:
                print(f"❌ Error scanning {url}: {e}")

    if all_results:
        print(f"\n🛡 Scan complete — found {len(all_results)} potential vulnerabilities.")
        generate_report(all_results, team_name="Team Jack Warriors")
    else:
        print("✅ No significant vulnerabilities detected.")

if __name__ == "__main__":
    main()
