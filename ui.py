import streamlit as st
import tempfile
import json
import os
from datetime import datetime
from typing import List, Dict

from scanner.sql_injection import analyze as sqli_analyze
from scanner.xss import analyze as xss_analyze
from scanner.headers import analyze as headers_analyze
from scanner.exposed_files import analyze as exposed_analyze
from scanner.csrf_scanner import analyze as csrf_analyze
from scanner.outdated_detector import analyze as outdated_analyze
from utils.report_generator import generate_report
from utils.recommendations import get_recommendations, is_ai_available


def severity_from_conf(conf: int) -> str:
    return "High" if conf >= 80 else "Medium" if conf >= 50 else "Low"


def normalize_findings(raw_list: List[Dict]) -> List[Dict]:
    normalized: List[Dict] = []
    for f in raw_list:
        nf = {
            "vulnerability": f.get("vulnerability", "Unknown"),
            "type": f.get("type", ""),
            "payload": f.get("payload", ""),
            "evidence": f.get("evidence", ""),
            "url": f.get("url", f.get("detail", "")),
            "confidence": f.get("confidence", 50),
            "severity": f.get("severity") or severity_from_conf(f.get("confidence", 50)),
        }
        normalized.append(nf)
    return normalized


st.set_page_config(page_title="Web Vulnerability Scanner", page_icon="🔍", layout="wide")
st.markdown('<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" integrity="sha512-SJm1Uo9bB4I4t5Qk8Cw6W6j3yS0S5u7hW4WzqJv1Rk8XvCe0nF2q8+8n0ri6bV+ZlF2YVop0G2w9Rr3i8kq7uw==" crossorigin="anonymous" referrerpolicy="no-referrer"/>', unsafe_allow_html=True)

# --- Global styling (fonts, background, components) ---
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&family=Poppins:wght@600;700&display=swap');

    :root { --brand: #7C3AED; --brand2: #00D4FF; }

    html, body, [data-testid="stAppViewContainer"] {
      background:
        radial-gradient(1200px circle at 10% 10%, rgba(12,20,36,0.9) 0%, rgba(10,18,30,0.85) 40%, rgba(8,14,24,0.9) 100%),
        linear-gradient(180deg, rgba(0,0,0,0.35), rgba(0,0,0,0.35)),
        repeating-linear-gradient(0deg, rgba(0,212,255,0.14) 0px, rgba(0,212,255,0.14) 1px, transparent 1px, transparent 42px),
        repeating-linear-gradient(90deg, rgba(0,212,255,0.14) 0px, rgba(0,212,255,0.14) 1px, transparent 1px, transparent 42px) !important;
      color: #e5e7eb !important;
      font-family: 'Inter', sans-serif;
      font-size: 14px;
      background-attachment: fixed, fixed, fixed, fixed;
    }
    /* animated subtle grid overlay */
    [data-testid="stAppViewContainer"]::before {
      content: "";
      position: fixed; inset: 0; pointer-events: none; opacity: .18;
      background:
        repeating-linear-gradient(0deg, rgba(0,180,216,.18) 0px, rgba(0,180,216,.18) 1px, transparent 1px, transparent 38px),
        repeating-linear-gradient(90deg, rgba(0,180,216,.18) 0px, rgba(0,180,216,.18) 1px, transparent 1px, transparent 38px);
      animation: gridScroll 40s linear infinite;
    }
    @keyframes gridScroll { 0% { background-position: 0 0, 0 0; } 100% { background-position: 200px 0, 0 200px; } }
    [data-testid="stHeader"] { background: transparent; }
    [data-testid="stSidebar"] {
      background: linear-gradient(180deg, rgba(17,24,39,0.95), rgba(31,41,55,0.9));
      border-right: 1px solid rgba(255,255,255,0.06);
    }
    h1, h2, h3, .stMarkdown h1, .stMarkdown h2, .stMarkdown h3 {
      font-family: 'Poppins', sans-serif !important;
      letter-spacing: .2px;
      margin: 0.2rem 0 0.6rem 0;
    }
    h1 { font-size: 1.25rem; }
    h2 { font-size: 1.05rem; }
    h3 { font-size: .95rem; }
    .stButton>button {
      background: linear-gradient(90deg, var(--brand), var(--brand2));
      color: #fff; border: 0; border-radius: 10px; padding: .4rem .7rem; font-size: .85rem;
      box-shadow: 0 4px 16px rgba(124,58,237,.28);
      transition: transform .15s ease, box-shadow .2s ease;
    }
    .stButton>button:hover { transform: translateY(-1px) scale(1.01); box-shadow: 0 10px 28px rgba(0,212,255,.3); }
    .stButton>button:active { transform: translateY(0); }

    .fade-in { animation: fadeIn .6s ease 1; }
    @keyframes fadeIn { from {opacity:0; transform: translateY(6px);} to {opacity:1; transform: translateY(0);} }

    .pulse-success { border-radius: 12px; padding: .6rem .8rem; background: rgba(16,185,129,.15); border: 1px solid rgba(16,185,129,.35);
                     box-shadow: 0 0 0 0 rgba(16,185,129,.55); animation: pulseGlow 2s ease-out 2; }
    @keyframes pulseGlow { 0% { box-shadow: 0 0 0 0 rgba(16,185,129,.55);} 70% { box-shadow: 0 0 0 12px rgba(16,185,129,0);} 100% { box-shadow: 0 0 0 0 rgba(16,185,129,0);} }

    .card { background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.06);
            border-radius: 14px; padding: .8rem 1rem; backdrop-filter: blur(6px); font-size: .92rem; }

    /* Top header bar */
    .topbar { position: sticky; top: 0; z-index: 1000;
              background: linear-gradient(180deg, rgba(11,18,32,0.92), rgba(11,18,32,0.88));
              backdrop-filter: blur(8px);
              border-bottom: 1px solid rgba(255,255,255,0.06);
              padding: .4rem .6rem .3rem .6rem; margin: 0 0 .6rem 0; }
    .topbar h1 { margin: 0; font-size: 1rem; }
    .topbar .subtitle { margin: 0; font-size: .8rem; color: #a3a3a3; }

    /* Make topbar nav look like text links (no boxes) */
    .topbar .stButton>button {
      background: transparent !important;
      border: 0 !important;
      border-radius: 0 !important;
      box-shadow: none !important;
      padding: .2rem .4rem !important;
      color: #e5e7eb !important;
      font-weight: 600;
    }
    .topbar .stButton>button:hover {
      background: transparent !important;
      text-decoration: underline;
      box-shadow: none !important;
      transform: none !important;
    }

    /* Sidebar styling */
    .sidebar-brand { display:flex; align-items:center; gap:.5rem; margin:.4rem 0 .8rem 0; }
    .sidebar-brand .logo { font-size:1rem }
    .sidebar-link { display:flex; align-items:center; gap:.5rem; padding:.35rem .3rem; border-radius:8px; color:#e5e7eb; text-decoration:none }
    .sidebar-link:hover { background: rgba(255,255,255,.06) }
    .badge { display:inline-block; padding:.05rem .4rem; border-radius:9999px; font-size:.72rem; font-weight:600 }
    .badge.high { background:#991b1b33; color:#f87171; border:1px solid #991b1b77 }
    .badge.medium { background:#92400e33; color:#fbbf24; border:1px solid #92400e77 }
    .badge.low { background:#065f4633; color:#34d399; border:1px solid #065f4677 }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("Web Vulnerability Scanner")
st.caption("Educational, heuristic-only checks. Use only on systems you’re authorized to test.")
# Professional header bar with navigation
def render_topbar(active_step: int):
    st.markdown('<div class="topbar"></div>', unsafe_allow_html=True)
    wrap = st.container()
    with wrap:
        c_logo, c_spacer = st.columns([0.9, 0.1])
        with c_logo:
            st.markdown(
                """
                <div style="display:flex;align-items:center;gap:.5rem" class="fade-in">
                  <div style="font-size:1rem">🛡</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        # Top bar buttons removed to avoid duplication with sidebar


# Lottie helper
def lottie(url: str, height: int = 180):
    st.components.v1.html(
        f"""
        <script src="https://unpkg.com/@lottiefiles/lottie-player@latest/dist/lottie-player.js"></script>
        <lottie-player src="{url}" background="transparent" speed="1"
          style="width:100%;height:{height}px;margin:0 auto" loop autoplay></lottie-player>
        """,
        height=height,
        scrolling=False,
    )

# Stepper helper
def render_stepper(current_step: int):
    st.markdown(
        f"""
        <div style="display:flex;gap:12px;align-items:center;margin:8px 0 18px 0" class="fade-in">
          <div style="display:flex;align-items:center;gap:12px">
            <div style="width:30px;height:30px;border-radius:50%;display:grid;place-items:center;border:2px solid #7C3AED;background:{'#7C3AED' if current_step>=1 else 'transparent'};color:#fff">1</div>
            <div style="height:2px;width:60px;background:{'#7C3AED' if current_step>=2 else 'rgba(255,255,255,0.15)'}"></div>
            <div style="width:30px;height:30px;border-radius:50%;display:grid;place-items:center;border:2px solid #7C3AED;background:{'#7C3AED' if current_step>=2 else 'transparent'};color:#fff">2</div>
            <div style="height:2px;width:60px;background:{'#7C3AED' if current_step>=3 else 'rgba(255,255,255,0.15)'}"></div>
            <div style="width:30px;height:30px;border-radius:50%;display:grid;place-items:center;border:2px solid #7C3AED;background:{'#7C3AED' if current_step>=3 else 'transparent'};color:#fff">3</div>
            <div style="height:2px;width:60px;background:{'#7C3AED' if current_step>=4 else 'rgba(255,255,255,0.15)'}"></div>
            <div style="width:30px;height:30px;border-radius:50%;display:grid;place-items:center;border:2px solid #7C3AED;background:{'#7C3AED' if current_step>=4 else 'transparent'};color:#fff">4</div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

# Findings renderer
def render_findings_table(findings: List[Dict]):
    if not findings:
        return
    try:
        import pandas as pd
        from streamlit import column_config as cc
    except Exception:
        st.dataframe(findings, width='stretch')
        return
    df = pd.DataFrame(findings)
    # Ensure columns
    wanted = ["vulnerability", "type", "severity", "confidence", "evidence", "payload", "url"]
    for c in wanted:
        if c not in df.columns:
            df[c] = ""
    # Severity emoji labels for clarity
    def _sev_label(s):
        s = str(s or "").capitalize()
        return "🔴 High" if s.startswith("High") else ("🟠 Medium" if s.startswith("Medium") else ("🟢 Low" if s.startswith("Low") else s))
    try:
        df["severity"] = df["severity"].apply(_sev_label)
    except Exception:
        pass
    # Shorten long evidence for readability (UI-only)
    try:
        df["evidence"] = df["evidence"].astype(str).apply(lambda s: (s[:140] + "…") if len(s) > 140 else s)
    except Exception:
        pass

    st.data_editor(
        df[wanted],
        hide_index=True,
        disabled=True,
        width='stretch',
        column_config={
            "vulnerability": cc.TextColumn("Vulnerability", help="Detected issue name"),
            "type": cc.TextColumn("Type"),
            "severity": cc.TextColumn("Severity"),
            "confidence": cc.ProgressColumn("Confidence", min_value=0, max_value=100, format="%d%%"),
            "evidence": cc.TextColumn("Evidence", help="Short evidence; see full details in PDF"),
            "payload": cc.TextColumn("Payload"),
            "url": cc.LinkColumn("URL"),
        },
    )

def render_severity_metrics(findings: List[Dict]):
    if not findings:
        return
    high = sum(1 for f in findings if (f.get("severity") or "").lower().startswith("high"))
    med = sum(1 for f in findings if (f.get("severity") or "").lower().startswith("medium"))
    low = sum(1 for f in findings if (f.get("severity") or "").lower().startswith("low"))
    total = len(findings)
    c1, c2, c3, c4 = st.columns(4)
    with c1: st.metric("Total Findings", total)
    with c2: st.metric("High", high, help="High severity issues", delta=f"{int(high/total*100) if total else 0}%")
    with c3: st.metric("Medium", med, help="Medium severity issues", delta=f"{int(med/total*100) if total else 0}%")
    with c4: st.metric("Low", low, help="Low severity issues", delta=f"{int(low/total*100) if total else 0}%")

def render_summary_cards(findings: List[Dict]):
    if not findings:
        return
    high = sum(1 for f in findings if (f.get("severity") or "").lower().startswith("high"))
    med = sum(1 for f in findings if (f.get("severity") or "").lower().startswith("medium"))
    low = sum(1 for f in findings if (f.get("severity") or "").lower().startswith("low"))
    total = len(findings)
    # simple security score heuristic
    score_raw = max(0, 100 - (high*25 + med*12 + low*4))
    grade = "A" if score_raw >= 90 else "B" if score_raw >= 80 else "C" if score_raw >= 70 else "D" if score_raw >= 60 else "E" if score_raw >= 50 else "F"
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1: st.metric("Total", total)
    with col2: st.metric("High", high)
    with col3: st.metric("Medium", med)
    with col4: st.metric("Low", low)
    with col5: st.metric("Security Score", grade)


def render_analytics_charts(findings: List[Dict]):
    if not findings:
        st.info("No data to visualize. Run a scan first.")
        return
    try:
        import pandas as pd
        import plotly.graph_objects as go
    except Exception:
        st.warning("Analytics requires plotly; please install requirements.")
        return
    df = pd.DataFrame(findings)
    # Normalize columns
    for col in ["severity", "type", "url", "confidence"]:
        if col not in df.columns:
            df[col] = ""

    # Map to high-level categories
    def map_category(row):
        vul = (row.get("vulnerability") or "").lower()
        typ = (row.get("type") or "").lower()
        if "sql" in vul or typ in {"error-based", "time-based"}:
            return "SQL Injection"
        if "xss" in vul or typ == "reflected":
            return "XSS"
        if "header" in vul or typ == "headers":
            return "Security Headers"
        if typ == "exposed-file" or "exposed" in vul:
            return "Exposed Files"
        if "csrf" in vul or typ == "csrf":
            return "CSRF"
        if "outdated" in vul or typ == "outdated-js":
            return "Outdated Components"
        return "Other"

    df["category"] = df.apply(map_category, axis=1)

    # Severity donut
    sev_counts = df.groupby("severity", dropna=False).size().reset_index(name="count")
    pie = go.Figure(data=[go.Pie(labels=sev_counts["severity"], values=sev_counts["count"], hole=.55)])
    pie.update_layout(height=260, margin=dict(l=0,r=0,t=0,b=0))

    # Category bar
    cat_counts = df.groupby("category", dropna=False).size().reset_index(name="count").sort_values("count", ascending=False)
    bar = go.Figure(data=[go.Bar(y=cat_counts["category"], x=cat_counts["count"], orientation='h')])
    bar.update_layout(height=260, margin=dict(l=0,r=0,t=0,b=0))

    # Confidence histogram
    hist = go.Figure(data=[go.Histogram(x=df["confidence"], xbins=dict(size=10))])
    hist.update_layout(height=260, margin=dict(l=0,r=0,t=0,b=0), xaxis_title="Confidence (%)", yaxis_title="Count")

    # Radar chart: severity weight by category
    cat_pivot = df.pivot_table(index="category", columns="severity", aggfunc="size", fill_value=0)
    cats = list(cat_pivot.index)
    def series(sev):
        return [int(cat_pivot.get(sev, pd.Series([0]*len(cats), index=cats)).loc[c]) for c in cats]
    radar = go.Figure()
    for sev, color in [("High", "#ef4444"), ("Medium", "#f59e0b"), ("Low", "#10b981")]:
        radar.add_trace(go.Scatterpolar(r=series(sev), theta=cats, fill='toself', name=sev, line_color=color))
    radar.update_layout(height=320, margin=dict(l=0,r=0,t=0,b=0), polar=dict(radialaxis=dict(visible=True)))

    c1, c2 = st.columns([1, 1])
    with c1:
        st.subheader("Vulnerabilities by Severity")
        st.plotly_chart(pie, use_container_width=True)
    with c2:
        st.subheader("Vulnerabilities by Category")
        st.plotly_chart(bar, use_container_width=True)

    c3, c4 = st.columns([1, 1])
    with c3:
        st.subheader("Confidence Histogram")
        st.plotly_chart(hist, use_container_width=True)
    with c4:
        st.subheader("Top URLs")
        st.dataframe(df.groupby("url").size().reset_index(name="count").sort_values("count", ascending=False).head(10), use_container_width=True)

    # Historical trends
    st.subheader("Vulnerabilities Over Time")
    history = load_scan_history()
    if not history:
        st.info("No scan history yet. Run scans to build history.")
    else:
        try:
            import pandas as pd
            import plotly.express as px
            hdf = pd.DataFrame(history)
            hdf["time"] = pd.to_datetime(hdf["time"])  # parse ISO
            # Long format for metrics
            long = hdf.melt(id_vars=["time", "target"], value_vars=["total", "high"], var_name="metric", value_name="count")
            fig = px.line(long, x="time", y="count", color="metric", markers=True, title=None)
            fig.update_layout(height=280, margin=dict(l=0,r=0,t=0,b=0), xaxis_title="Time", yaxis_title="Findings")
            st.plotly_chart(fig, use_container_width=True)
        except Exception:
            st.warning("Unable to render history chart.")

HISTORY_PATH = os.path.join(os.path.dirname(__file__), "scan_history.json")

def append_scan_history(target_url: str, findings: List[Dict]):
    try:
        history = []
        if os.path.exists(HISTORY_PATH):
            with open(HISTORY_PATH, "r", encoding="utf-8") as f:
                history = json.load(f) or []
        high = sum(1 for f in findings if (f.get("severity") or "").lower().startswith("high"))
        med = sum(1 for f in findings if (f.get("severity") or "").lower().startswith("medium"))
        low = sum(1 for f in findings if (f.get("severity") or "").lower().startswith("low"))
        rec = {
            "time": datetime.utcnow().isoformat(),
            "target": target_url,
            "total": len(findings),
            "high": high,
            "medium": med,
            "low": low,
        }
        history.append(rec)
        with open(HISTORY_PATH, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2)
    except Exception:
        pass

def load_scan_history():
    try:
        if not os.path.exists(HISTORY_PATH):
            return []
        with open(HISTORY_PATH, "r", encoding="utf-8") as f:
            return json.load(f) or []
    except Exception:
        return []

# --- Session state ---
if "step" not in st.session_state:
    st.session_state.step = 1
if "target" not in st.session_state:
    st.session_state.target = "http://testphp.vulnweb.com/"
if "findings" not in st.session_state:
    st.session_state.findings = []
if "scanned" not in st.session_state:
    st.session_state.scanned = False
if "show_about" not in st.session_state:
    st.session_state.show_about = False
if "theme_light" not in st.session_state:
    st.session_state.theme_light = False
if "intensity" not in st.session_state:
    st.session_state.intensity = "Standard"
if "animated_bg" not in st.session_state:
    st.session_state.animated_bg = True
if "confetti_enabled" not in st.session_state:
    st.session_state.confetti_enabled = True

# keep scanner selections across reruns
for k, default in [
    ("use_sqli", True),
    ("use_xss", True),
    ("use_headers", True),
    ("use_exposed", True),
    ("use_csrf", True),
    ("use_outdated", True),
]:
    if k not in st.session_state:
        st.session_state[k] = default


def run_selected_scanners(url: str) -> List[Dict]:
    findings: List[Dict] = []
    scanners = []
    if st.session_state.use_sqli:
        scanners.append(("SQL Injection", sqli_analyze))
    if st.session_state.use_xss:
        scanners.append(("Reflected XSS", xss_analyze))
    if st.session_state.use_headers:
        scanners.append(("Headers", headers_analyze))
    if st.session_state.use_exposed:
        scanners.append(("Exposed Files", exposed_analyze))
    if st.session_state.use_csrf:
        scanners.append(("CSRF", csrf_analyze))
    if st.session_state.use_outdated:
        scanners.append(("Outdated Components", outdated_analyze))

    progress = st.progress(0)
    status = st.empty()
    total = max(1, len(scanners))
    # timeout by intensity
    intensity = st.session_state.get("intensity", "Standard")
    timeout = 8 if intensity == "Standard" else (5 if intensity == "Fast" else 12)

    def step_label(scan_name: str) -> str:
        n = scan_name.lower()
        if "sql" in n:
            return "Now checking for SQL Injection…"
        if "xss" in n:
            return "Testing for reflected XSS…"
        if "header" in n:
            return "Analyzing security headers…"
        if "exposed" in n:
            return "Testing for exposed files…"
        if "csrf" in n:
            return "Checking CSRF protections…"
        if "outdated" in n:
            return "Scanning for outdated components…"
        return f"Running {scan_name}…"

    for idx, (name, func) in enumerate(scanners, start=1):
        try:
            status.text(f"🔍 {step_label(name)}")
            try:
                raw = func(url, timeout=timeout)
            except TypeError:
                raw = func(url)
            if raw:
                normalized = normalize_findings(raw)
                findings.extend(normalized)
                status.text(f"✅ {name} — {len(normalized)} findings")
            else:
                status.text(f"✅ {name} — no findings")
        except Exception as e:
            status.text(f"❌ {name} — error: {e}")
        progress.progress(min(idx / total, 1.0))

    return findings


# Render header bar across all pages
render_topbar(st.session_state.step)
# Sidebar navigation and theme toggle
with st.sidebar:
    st.markdown('<div class="sidebar-brand"><span class="logo">🛡</span><span><b>WVS</b></span></div>', unsafe_allow_html=True)
    if st.button("🏠 Dashboard", use_container_width=True):
        st.session_state.step = 1
    if st.button("🧪 Scan", use_container_width=True):
        st.session_state.step = 2
    if st.button("📄 Report", use_container_width=True):
        st.session_state.step = 3
    if st.button("📈 Analytics", use_container_width=True):
        st.session_state.step = 4
    if st.button("⚙ Settings", use_container_width=True):
        st.session_state.step = 5
    st.divider()
    st.session_state.theme_light = st.toggle("Light theme", value=st.session_state.theme_light)
    if st.session_state.theme_light:
        st.markdown(
            """
            <style>
            html, body, [data-testid='stAppViewContainer']{
              color:#0f172a !important;
            }
            [data-testid='stAppViewContainer']{ background:
              radial-gradient(1200px circle at 10% 10%, #f1f5f9 0%, #e2e8f0 45%, #e5edf7 100%) !important;}
            .topbar{ background: linear-gradient(180deg, rgba(241,245,249,0.9), rgba(226,232,240,0.85)); border-bottom:1px solid rgba(0,0,0,.08) }
            .topbar .stButton>button{ color:#0f172a !important }
            </style>
            """,
            unsafe_allow_html=True,
        )
    if not st.session_state.get("animated_bg", True):
        st.markdown(
            """
            <style>
            [data-testid='stAppViewContainer']::before{ display:none !important }
            </style>
            """,
            unsafe_allow_html=True,
        )

# --- Simple 3-step flow ---

if st.session_state.step == 1:
    st.header("Target URL", divider="rainbow")
    lottie("https://assets9.lottiefiles.com/packages/lf20_8wREpI.json", height=160)
    st.session_state.target = st.text_input(
        "Website URL",
        value=st.session_state.target,
        placeholder="https://example.com",
        help="Include the scheme (http/https). Example: https://testphp.vulnweb.com/",
    )
    st.markdown('<div class="card fade-in">Enter the homepage of the site. Run scans only with explicit permission.</div>', unsafe_allow_html=True)
    cols = st.columns([1, 1])
    with cols[1]:
        if st.button("Next →", type="primary"):
            if not st.session_state.target.strip():
                st.error("Please enter a target URL.")
            else:
                st.session_state.step = 2

elif st.session_state.step == 2:
    st.header("Scan", divider="rainbow")
    lottie("https://assets7.lottiefiles.com/packages/lf20_x62chJ.json", height=140)
    st.write("Select checks to run, then click Run Scan.")
    st.markdown(
        '<div class="card" style="margin:.3rem 0 .7rem 0">'
        '<i class="fa-solid fa-database" title="SQL Injection"></i> SQLi · '
        '<i class="fa-solid fa-code" title="Reflected XSS"></i> XSS · '
        '<i class="fa-solid fa-shield-halved" title="Security Headers"></i> Headers · '
        '<i class="fa-solid fa-file-shield" title="Exposed Files"></i> Exposed · '
        '<i class="fa-solid fa-user-shield" title="CSRF"></i> CSRF · '
        '<i class="fa-solid fa-sitemap" title="Outdated Libraries"></i> Outdated'
        '</div>',
        unsafe_allow_html=True,
    )

    c1, c2, c3 = st.columns(3)
    with c1:
        st.session_state.use_sqli = st.checkbox("SQL Injection", value=st.session_state.use_sqli, help="Attempts error/time-based payloads on the first query parameter.")
        st.session_state.use_xss = st.checkbox("Reflected XSS", value=st.session_state.use_xss, help="Checks reflected output and script injection indicators.")
    with c2:
        st.session_state.use_headers = st.checkbox("Security Headers", value=st.session_state.use_headers, help="Looks for missing or weak security headers.")
        st.session_state.use_exposed = st.checkbox("Exposed Files", value=st.session_state.use_exposed, help="Probes common sensitive paths like .env, backups, configs.")
    with c3:
        st.session_state.use_csrf = st.checkbox("CSRF Heuristic", value=st.session_state.use_csrf, help="Flags POST forms without CSRF tokens.")
        st.session_state.use_outdated = st.checkbox("Outdated Components", value=st.session_state.use_outdated, help="Detects older jQuery/Bootstrap versions.")

    st.session_state.intensity = st.select_slider("Scan intensity", options=["Fast", "Standard", "Thorough"], value=st.session_state.intensity, help="Higher intensity tries more payloads and may take longer.")

    if st.button("Scan Now", type="primary"):
        if not st.session_state.target.strip():
            st.error("Please enter a target URL in Step 1.")
        else:
            st.session_state.findings = run_selected_scanners(st.session_state.target.strip())
            st.session_state.scanned = True
            if st.session_state.findings:
                st.success(f"Scan completed: {len(st.session_state.findings)} potential issues found.")
                # Confetti + pulse banner
                st.markdown('<div class="pulse-success">Scan complete — results below.</div>', unsafe_allow_html=True)
                try:
                    st.components.v1.html(
                        """
                        <script src=\"https://cdn.jsdelivr.net/npm/canvas-confetti@1.9.3/dist/confetti.browser.min.js\"></script>
                        <script>
                          (function(){
                            var duration = 1200; var end = Date.now() + duration;
                            (function frame(){
                              confetti({ particleCount: 60, spread: 60, startVelocity: 42, origin: { y: 0.25 }, colors: ['#22c55e','#86efac','#10b981'] });
                              if (Date.now() < end) requestAnimationFrame(frame);
                            })();
                          })();
                        </script>
                        """,
                        height=0,
                    )
                except Exception:
                    pass
                append_scan_history(st.session_state.target.strip(), st.session_state.findings)
            else:
                st.info("Scan completed: No issues detected by the selected checks.")

    if st.session_state.scanned and st.session_state.findings:
        render_summary_cards(st.session_state.findings)
        render_severity_metrics(st.session_state.findings)
        render_findings_table(st.session_state.findings)

    colb, coln = st.columns([1, 1])
    with colb:
        if st.button("← Back"):
            st.session_state.step = 1
    with coln:
        if st.button("Next → Report", disabled=not st.session_state.scanned):
            st.session_state.step = 3
    if st.session_state.scanned:
        if st.button("View Analytics →", type="secondary"):
            st.session_state.step = 4

elif st.session_state.step == 3:
    st.header("Report", divider="rainbow")
    lottie("https://assets2.lottiefiles.com/private_files/lf30_editor_7mpspf8d.json", height=140)
    if not st.session_state.scanned:
        st.warning("Please complete the scan in Step 2 first.")
    else:
        st.subheader("Findings")
        render_severity_metrics(st.session_state.findings)
        render_findings_table(st.session_state.findings)

        if st.button("Generate PDF Report"):
            with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
                generate_report(st.session_state.target.strip(), st.session_state.findings, filename=tmp.name)
                tmp.flush()
                tmp.seek(0)
                st.session_state.report_bytes = tmp.read()
        if "report_bytes" in st.session_state:
            st.download_button(
                label="Download report.pdf",
                data=st.session_state.report_bytes,
                file_name="report.pdf",
                mime="application/pdf",
            )

        st.subheader("AI Recommendations (Optional)")
        enable_ai = st.checkbox("Enable AI-based recommendations", value=is_ai_available(), help="Requires an OpenAI API key set in the environment.")
        if enable_ai:
            if st.button("Suggest Fixes"):
                with st.spinner("Generating suggestions…"):
                    recos = get_recommendations(st.session_state.findings)
                    # persist in session
                    st.session_state.recommendations = recos
        if "recommendations" in st.session_state:
            try:
                import pandas as pd
                from streamlit import column_config as cc
                rows = []
                for f, r in zip(st.session_state.findings, st.session_state.recommendations):
                    rows.append({
                        "vulnerability": f.get("vulnerability", ""),
                        "url": f.get("url", ""),
                        "recommendation": r,
                    })
                df = pd.DataFrame(rows)
                st.data_editor(
                    df,
                    hide_index=True,
                    disabled=True,
                    width='stretch',
                    column_config={
                        "vulnerability": cc.TextColumn("Vulnerability"),
                        "url": cc.LinkColumn("URL"),
                        "recommendation": cc.TextColumn("Recommendation"),
                    },
                )
            except Exception:
                for f, r in zip(st.session_state.findings, st.session_state.recommendations):
                    st.markdown(f"- **{f.get('vulnerability','')}**: {r}")

    colb, colr = st.columns([1, 1])
    with colb:
        if st.button("← Back to Scan"):
            st.session_state.step = 2
    with colr:
        if st.button("Next → Analytics", disabled=not st.session_state.scanned):
            st.session_state.step = 4

elif st.session_state.step == 4:
    st.header("Analytics", divider="rainbow")
    lottie("https://assets9.lottiefiles.com/packages/lf20_uekp8bxh.json", height=140)
    if not st.session_state.scanned:
        st.warning("Please run a scan first.")
    else:
        render_analytics_charts(st.session_state.findings)

    colb, colr = st.columns([1, 1])
    with colb:
        if st.button("← Back to Report"):
            st.session_state.step = 3
    with colr:
        if st.button("Restart Wizard"):
            st.session_state.step = 1
            st.session_state.scanned = False
            st.session_state.findings = []
            if "report_bytes" in st.session_state:
                del st.session_state["report_bytes"]

elif st.session_state.step == 5:
    st.header("Settings", divider="rainbow")
    st.markdown("Configure UI and scan preferences.")
    st.session_state.confetti_enabled = st.toggle("Celebration confetti on success", value=st.session_state.confetti_enabled)
    st.session_state.animated_bg = st.toggle("Animated background grid", value=st.session_state.animated_bg)
    st.session_state.intensity = st.select_slider("Default scan intensity", options=["Fast", "Standard", "Thorough"], value=st.session_state.intensity)
    if not st.session_state.animated_bg:
        st.markdown("""
        <style>
        [data-testid='stAppViewContainer']::before{ display:none !important }
        </style>
        """, unsafe_allow_html=True)


