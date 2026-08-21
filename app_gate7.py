"""Gate 7 controlled-pilot security additions.

Adds an email-verified MFA recovery path and a hardened MFA enrollment verifier
without weakening normal MFA login.
"""
import hmac
import re
import secrets
import time
import uuid

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel

from app_gate6 import app
from app import (
    PUBLIC_APP_URL,
    current_user,
    db,
    future,
    hash_token,
    norm_email,
    now,
    privacy_hash,
    rate_limit,
    security_event,
    send_email,
    totp_code,
)


class MFARecoveryRequestIn(BaseModel):
    email: str


class MFARecoverIn(BaseModel):
    token: str


class MFAEnableV2In(BaseModel):
    code: str


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
        raise HTTPException(400, "MFA recovery link is invalid or expired")

    u = c.execute("SELECT * FROM users WHERE id=?", (r["user_id"],)).fetchone()
    if not u:
        c.close()
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


@app.post("/auth/mfa/enable-v2")
def mfa_enable_v2(d: MFAEnableV2In, request: Request, u=Depends(current_user)):
    """Enrollment-only TOTP verifier with controlled clock-skew tolerance.

    Normal login continues to use the stricter verifier in app.py. This wider
    enrollment window prevents a phone/server clock mismatch from blocking setup.
    """
    code = str(d.code).strip()
    if not re.fullmatch(r"\d{6}", code):
        raise HTTPException(422, "Enter a 6-digit authenticator code")

    rate_limit("mfa-enable:" + u["id"], 10, 600)
    c = db()
    r = c.execute("SELECT mfa_secret FROM users WHERE id=?", (u["id"],)).fetchone()
    if not r or not r["mfa_secret"]:
        c.close()
        raise HTTPException(409, "Start MFA setup again to create a fresh authenticator secret")

    secret = r["mfa_secret"]
    ts = int(time.time())
    matched_offset = None
    for step in range(-5, 6):
        if hmac.compare_digest(totp_code(secret, ts + step * 30), code):
            matched_offset = step
            break

    if matched_offset is None:
        c.close()
        security_event(
            "mfa_enrollment_failed",
            "warning",
            u["tenant_id"],
            u["id"],
            "authenticator code did not match enrollment secret",
            request,
        )
        raise HTTPException(400, "That code does not match this QR setup. Delete any old Zorvian entry in the authenticator, scan the current QR once, then use the code shown for that new Zorvian entry.")

    c.execute("UPDATE users SET mfa_enabled=1 WHERE id=?", (u["id"],))
    c.commit()
    c.close()
    security_event(
        "mfa_enabled",
        "info",
        u["tenant_id"],
        u["id"],
        f"TOTP enabled via Gate 7 enrollment verifier; clock_offset_steps={matched_offset}",
        request,
    )
    return {"status": "mfa_enabled", "clock_offset_seconds": matched_offset * 30}
