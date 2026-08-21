"""Gate 8 compatibility layer for production email verification links.

The public Zorvian site is a static frontend. Verification links therefore
return to the frontend root with a query token, where the browser posts the
token to Core. This avoids sending users to a non-existent /auth path on the
static web host.
"""
import secrets

import app as core_app
import app_gate7 as gate7

app = gate7.app


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

    verify_url = f"{core_app.PUBLIC_APP_URL}/?verify={raw}"
    delivered = core_app.send_email(
        email,
        "Verify your Zorvian account",
        "Verify your Zorvian account:\n\n"
        f"{verify_url}\n\n"
        "This link expires in 24 hours.",
    )
    return raw, delivered


# Registration lives in app.py and resend lives in app_gate7.py. Patch both
# module globals so every newly issued verification email uses the frontend
# verification route.
core_app.issue_email_verification = issue_email_verification_fixed
gate7.issue_email_verification = issue_email_verification_fixed
