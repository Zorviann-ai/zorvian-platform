"""Gate 8 compatibility layer for production email verification links.

Verification emails must terminate on the live FastAPI service because that
service owns the email_verifications table. Railway exposes the deployed
service hostname through RAILWAY_PUBLIC_DOMAIN, so production links can verify
directly instead of returning to a static frontend that cannot consume the
token.
"""
import os
import secrets

import app as core_app
import app_gate7 as gate7

app = gate7.app


def verification_base_url() -> str:
    override = os.getenv("PUBLIC_VERIFY_BASE_URL", "").strip().rstrip("/")
    if override:
        return override

    railway_domain = os.getenv("RAILWAY_PUBLIC_DOMAIN", "").strip().strip("/")
    if railway_domain:
        return f"https://{railway_domain}"

    return core_app.PUBLIC_APP_URL


def issue_email_verification_fixed(uid: str, email: str):
    raw = secrets.token_urlsafe(32)
    c = core_app.db()
    c.execute(
        "INSERT INTO email_verifications VALUES (?,?,?,?,?,?)",
        (
            str(__import__("uuid").uuid4()),
            uid,
            core_app.hash_token(raw),
            core_app.future(hours=24),
            None,
            core_app.now(),
        ),
    )
    c.commit()
    c.close()

    verify_url = (
        f"{verification_base_url()}/auth/verify-email-link?token={raw}"
    )
    delivered = core_app.send_email(
        email,
        "Verify your Zorvian account",
        "Verify your Zorvian account:\n\n"
        f"{verify_url}\n\n"
        "This link expires in 24 hours.",
    )
    return raw, delivered


# Registration lives in app.py and resend lives in app_gate7.py. Patch both
# module globals so every newly issued verification email targets the service
# that owns and validates the verification token.
core_app.issue_email_verification = issue_email_verification_fixed
gate7.issue_email_verification = issue_email_verification_fixed
