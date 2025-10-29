import os
import json
from typing import List, Dict


def _heuristic_recommendation(f: Dict) -> str:
    vul = (f.get("vulnerability") or "").lower()
    typ = (f.get("type") or "").lower()

    if "sql" in vul or typ in {"error-based", "time-based"}:
        return (
            "Use parameterized queries/prepared statements and input validation; avoid string concatenation. "
            "Adopt ORM query builders, enforce least-privileged DB accounts, and add WAF rules for SQLi.")

    if "xss" in vul or typ == "reflected":
        return (
            "HTML-encode untrusted output by context; sanitize inputs. Set a strict Content-Security-Policy, "
            "and mark cookies HttpOnly and Secure. Avoid dangerous event handlers in templates.")

    if "header" in vul or typ == "headers":
        return (
            "Add security headers: Content-Security-Policy (no wildcards), X-Frame-Options=DENY/ SAMEORIGIN, "
            "Strict-Transport-Security, Referrer-Policy, X-Content-Type-Options, and Permissions-Policy.")

    if typ == "exposed-file" or "exposed" in vul:
        return (
            "Remove sensitive files from web root; restrict access via server config; disable directory listing; "
            "store secrets in environment/secret manager, not in versioned files.")

    if "csrf" in vul or typ == "csrf":
        return (
            "Include anti-CSRF tokens in state-changing POST forms, verify Origin/Referer, enable SameSite=strict/lax "
            "cookies, and require re-authentication for critical actions.")

    if "outdated" in vul or typ == "outdated-js":
        return (
            "Upgrade outdated libraries (e.g., jQuery 3.7+; Bootstrap 5+), run SCA (OWASP Dependency-Track, pip-audit), "
            "and enable automated dependency updates.")

    return (
        "Review input handling, output encoding, authentication/session settings, and server configuration; "
        "apply principle of least privilege and keep components up to date.")


def is_ai_available() -> bool:
    try:
        from openai import OpenAI  # type: ignore
        return bool(os.getenv("OPENAI_API_KEY"))
    except Exception:
        return False


def _openai_recommend(findings: List[Dict]) -> List[str]:
    """Return per-finding recommendations using OpenAI if configured. Fallback to heuristics on any error."""
    try:
        from openai import OpenAI  # type: ignore
    except Exception:
        return [_heuristic_recommendation(f) for f in findings]

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return [_heuristic_recommendation(f) for f in findings]

    client = OpenAI()

    # Limit to first N items to keep prompt reasonable
    max_items = 12
    subset = findings[:max_items]
    prompt_items = [
        {
            "vulnerability": f.get("vulnerability", ""),
            "type": f.get("type", ""),
            "severity": f.get("severity", ""),
            "confidence": f.get("confidence", ""),
            "url": f.get("url", ""),
            "evidence": (f.get("evidence") or "")[:160],
        }
        for f in subset
    ]
    system_msg = (
        "You are an application security expert. Provide concise, high-impact remediation steps for each finding. "
        "Return a JSON array of strings; each string is the recommendation for the corresponding finding in order."
    )
    user_msg = (
        "Provide pragmatic fix recommendations for each finding. "
        "Keep each item under 240 characters, action-oriented, and security best-practice aligned.\n\n"
        f"Findings: {json.dumps(prompt_items)}"
    )

    try:
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_msg},
                {"role": "user", "content": user_msg},
            ],
            temperature=0.2,
        )
        content = resp.choices[0].message.content or "[]"
        recos = json.loads(content)
        if isinstance(recos, list) and all(isinstance(x, str) for x in recos):
            # Map back to full findings length
            out = [_heuristic_recommendation(f) for f in findings]
            for i, r in enumerate(recos):
                if i < len(out):
                    out[i] = r
            return out
    except Exception:
        pass

    return [_heuristic_recommendation(f) for f in findings]


def get_recommendations(findings: List[Dict]) -> List[str]:
    """Return per-finding recommendation strings, aligned with input order."""
    if not findings:
        return []
    if is_ai_available():
        return _openai_recommend(findings)
    return [_heuristic_recommendation(f) for f in findings]


