"""Production verification routing plus professional Core email presentation."""
import os
import secrets
import json
import urllib.request
import urllib.error

import app as core_app
import app_gate7 as gate7
from email_branding import render_email

app = gate7.app


def verification_base_url() -> str:
    override = os.getenv("PUBLIC_VERIFY_BASE_URL", "").strip().rstrip("/")
    if override:
        return override
    railway_domain = os.getenv("RAILWAY_PUBLIC_DOMAIN", "").strip().strip("/")
    if railway_domain:
        return f"https://{railway_domain}"
    return core_app.PUBLIC_APP_URL


def send_professional_email(to: str, subject: str, text: str, *, html: str | None = None) -> bool:
    """Send multipart-compatible Resend payload with professional HTML plus text fallback."""
    api_key = os.getenv("RESEND_API_KEY") or os.getenv("SMTP_PASSWORD")
    sender = os.getenv("SMTP_FROM")
    if not api_key or not sender:
        return False
    payload = {"from": sender, "to": [to], "subject": subject, "text": text}
    if html:
        payload["html"] = html
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json", "User-Agent": "Zorvian-Core/0.9.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return getattr(resp, "status", 200) in (200, 201)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500]
        raise RuntimeError(f"Resend HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Resend HTTPS connection failed: {exc.reason}") from exc


def issue_email_verification_fixed(uid: str, email: str):
    raw = secrets.token_urlsafe(32)
    c = core_app.db()
    c.execute("INSERT INTO email_verifications VALUES (?,?,?,?,?,?)", (str(__import__("uuid").uuid4()), uid, core_app.hash_token(raw), core_app.future(hours=24), None, core_app.now()))
    c.commit(); c.close()
    verify_url = f"{verification_base_url()}/auth/verify-email-link?token={raw}"
    text = f"Verify your Zorvian account:\n\n{verify_url}\n\nThis secure link expires in 24 hours."
    html = render_email(
        title="Verify your Zorvian account",
        body="Welcome to Zorvian. Please confirm your email address to activate secure access to your workspace.\nThis secure verification link expires in 24 hours.",
        client_name="ZORVIAN",
        cta_label="VERIFY EMAIL ADDRESS",
        cta_url=verify_url,
        preheader="Confirm your email address to activate your Zorvian workspace.",
    )
    delivered = send_professional_email(email, "Verify your Zorvian account", text, html=html)
    return raw, delivered


# Preserve the proven verification destination while upgrading presentation.
core_app.issue_email_verification = issue_email_verification_fixed
gate7.issue_email_verification = issue_email_verification_fixed
