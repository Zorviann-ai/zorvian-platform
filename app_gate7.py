"""Gate 7 controlled-pilot security additions.

Adds an email-verified MFA recovery path without weakening normal MFA login.
"""
import secrets
import uuid

from fastapi import Request
from pydantic import BaseModel

from app_gate6 import app
from app import (
    PUBLIC_APP_URL,
    db,
    future,
    hash_token,
    norm_email,
    now,
    privacy_hash,
    rate_limit,
    security_event,
    send_email,
)


class MFARecoveryRequestIn(BaseModel):
    email: str


class MFARecoverIn(BaseModel):
    token: str


def _ensure_mfa_recovery_table():
    c = db()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS mfa_recovery_tokens(
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            token_hash TEXT UNIQUE NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    c.commit()
    c.close()


_ensure_mfa_recovery_table()


@app.post("/auth/mfa/recovery-request")
def mfa_recovery_request(d: MFARecoveryRequestIn, request: Request):
    email = norm_email(d.email)
    rate_limit("mfa-recovery:" + privacy_hash(email), 3, 3600)

    c = db()
    u = c.execute(
        "SELECT * FROM users WHERE email=? AND status='active'",
        (email,),
    ).fetchone()

    if u and int(u["mfa_enabled"] or 0) == 1:
        raw = secrets.token_urlsafe(32)
        c.execute(
            "INSERT INTO mfa_recovery_tokens VALUES (?,?,?,?,?,?)",
            (
                str(uuid.uuid4()),
                u["id"],
                hash_token(raw),
                future(minutes=30),
                None,
                now(),
            ),
        )
        c.commit()
        send_email(
            email,
            "Recover your Zorvian Guardian MFA",
            "A request was made to recover Guardian MFA on your Zorvian account.\n\n"
            f"Continue securely:\n\n{PUBLIC_APP_URL}/?mfa_recover={raw}\n\n"
            "This one-time link expires in 30 minutes. If you did not request this, ignore this email.",
        )
        security_event(
            "mfa_recovery_requested",
            "warning",
            u["tenant_id"],
            u["id"],
            "one-time recovery email issued",
            request,
        )

    c.close()
    return {"status": "If the account is eligible, recovery instructions have been sent."}


@app.post("/auth/mfa/recover")
def mfa_recover(d: MFARecoverIn, request: Request):
    c = db()
    r = c.execute(
        "SELECT * FROM mfa_recovery_tokens WHERE token_hash=? AND used_at IS NULL AND expires_at>?",
        (hash_token(d.token), now()),
    ).fetchone()
    if not r:
        c.close()
        from fastapi import HTTPException
        raise HTTPException(400, "MFA recovery link is invalid or expired")

    u = c.execute("SELECT * FROM users WHERE id=?", (r["user_id"],)).fetchone()
    if not u:
        c.close()
        from fastapi import HTTPException
        raise HTTPException(400, "MFA recovery link is invalid or expired")

    c.execute(
        "UPDATE users SET mfa_enabled=0,mfa_secret=NULL WHERE id=?",
        (u["id"],),
    )
    c.execute(
        "UPDATE mfa_recovery_tokens SET used_at=? WHERE id=?",
        (now(), r["id"]),
    )
    c.execute(
        "UPDATE secure_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL",
        (now(), u["id"]),
    )
    c.commit()
    c.close()

    security_event(
        "mfa_recovered",
        "warning",
        u["tenant_id"],
        u["id"],
        "MFA disabled by one-time email recovery; sessions revoked",
        request,
    )
    return {"status": "mfa_recovered", "message": "Guardian MFA has been reset. Sign in and set up MFA again."}
