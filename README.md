## Web Vulnerability Scanner

Simple, educational web vulnerability scanner with a CLI and a Streamlit-based UI.

### Features
- SQL Injection (heuristics)
- Reflected XSS (payload-based)
- Security headers checks
- Common exposed files
- CSRF token heuristic
- Outdated JS libraries (jQuery/Bootstrap patterns)
- PDF report generation

### Setup
1. Use Python 3.9+
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Run (CLI)
```bash
python main.py https://example.com
```

### Run (UI)
```bash
streamlit run ui.py
```

Enter a target URL, select scanners, run, view findings, and download a PDF report.

### Notes
This tool is for educational/testing purposes. Findings are heuristic and should be manually verified before action.


