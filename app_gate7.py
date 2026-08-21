"""Gate 7 controlled-pilot security additions.

Adds email-verified MFA recovery, a one-time MFA enrollment transaction, and a
safe verification-email resend path for pilot accounts. Normal MFA login
remains enforced by app.py.
"""
import base64
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
    issue_email_verification,
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


class MFAEnableV3In(BaseModel):
    enrollment_id: str
    code: str


class ResendVerificationIn(BaseModel):
    email: str


def _ensure_gate7_tables():
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
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS mfa_enrollments(
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            secret TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    c.commit()
    c.close()


_ensure_gate7_tables()


@app.post("/auth/resend-verification")
def resend_verification(d: ResendVerificationIn, request: Request):
    """Issue a fresh one-time verification email for an unverified account.

    The response does not reveal whether an email address is registered. A
    verified account is left untouched. Failed provider delivery is surfaced as
    503 so the pilot UI does not falsely claim that an email was sent.
    """
    email = norm_email(d.email)
    rate_limit("verify-resend:" + privacy_hash(email), 4, 3600)
    c = db()
    u = c.execute(
        "SELECT * FROM users WHERE email=? AND status='active'",
        (email,),
    ).fetchone()
    if not u:
        c.close()
        return {"status": "If the account exists and is unverified, a fresh verification email has been sent."}
    if int(u["email_verified"] or 0) == 1:
        c.close()
        return {"status": "already_verified", "message": "This account is already verified. You can sign in."}

    # Invalidate earlier unused links so only the newest verification email is active.
    c.execute(
        "UPDATE email_verifications SET used_at=? WHERE user_id=? AND used_at IS NULL",
        (now(), u["id"]),
    )
    c.commit()
    c.close()

    try:
        _raw, delivered = issue_email_verification(u["id"], email)
    except Exception as exc:
        security_event(
            "verification_email_failed",
            "error",
            u["tenant_id"],
            u["id"],
            f"provider_error={type(exc).__name__}",
            request,
        )
        raise HTTPException(503, "Verification email could not be sent right now. Try again shortly.") from exc

    if not delivered:
        security_event(
            "verification_email_failed",
            "error",
            u["tenant_id"],
            u["id"],
            "email provider not configured",
            request,
        )
        raise HTTPException(503, "Verification email service is not configured.")

    security_event(
        "verification_email_resent",
        "info",
        u["tenant_id"],
        u["id"],
        "fresh verification link issued",
        request,
    )
    return {"status": "verification_sent", "message": "A fresh verification email has been sent. Check Inbox and Spam/Junk."}


@app.post("/auth/mfa/recovery-request")
def mfa_recovery_request(d: MFARecoveryRequestIn, request: Request):
    email = norm_email(d.email)
    rate_limit("mfa-recovery:" + privacy_hash(email), 3, 3600)
    c = db()
    u = c.execute("SELECT * FROM users WHERE email=? AND status='active'", (email,)).fetchone()
    if u and int(u["mfa_enabled"] or 0) == 1:
        raw = secrets.token_urlsafe(32)
        c.execute(
            "INSERT INTO mfa_recovery_tokens VALUES (?,?,?,?,?,?)",
            (str(uuid.uuid4()), u["id"], hash_token(raw), future(minutes=30), None, now()),
        )
        c.commit()
        send_email(
            email,
            "Recover your Zorvian Guardian MFA",
            "A request was made to recover Guardian MFA on your Zorvian account.\n\n"
            f"Continue securely:\n\n{PUBLIC_APP_URL}/?mfa_recover={raw}\n\n"
            "This one-time link expires in 30 minutes. If you did not request this, ignore this email.",
        )
        security_event("mfa_recovery_requested", "warning", u["tenant_id"], u["id"], "one-time recovery email issued", request)
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
    c.execute("UPDATE users SET mfa_enabled=0,mfa_secret=NULL WHERE id=?", (u["id"],))
    c.execute("UPDATE mfa_recovery_tokens SET used_at=? WHERE id=?", (now(), r["id"]))
    c.execute("UPDATE secure_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL", (now(), u["id"]))
    c.execute("DELETE FROM mfa_enrollments WHERE user_id=?", (u["id"],))
    c.commit()
    c.close()
    security_event("mfa_recovered", "warning", u["tenant_id"], u["id"], "MFA disabled by one-time email recovery; sessions revoked", request)
    return {"status": "mfa_recovered", "message": "Guardian MFA has been reset. Sign in and set up MFA again."}


@app.post("/auth/mfa/setup-v2")
def mfa_setup_v2(request: Request, u=Depends(current_user)):
    """Create one immutable enrollment transaction.

    The user's live MFA secret is not changed until the code is verified. This
    prevents double-clicks, reloads or another setup request from making the QR
    on screen differ from the secret being checked.
    """
    rate_limit("mfa-setup:" + u["id"], 10, 600)
    secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
    enrollment_id = str(uuid.uuid4())
    expires_at = future(minutes=10)
    c = db()
    c.execute("DELETE FROM mfa_enrollments WHERE user_id=?", (u["id"],))
    c.execute(
        "INSERT INTO mfa_enrollments VALUES (?,?,?,?,?,?)",
        (enrollment_id, u["id"], secret, expires_at, None, now()),
    )
    c.commit()
    c.close()
    uri = (
        f"otpauth://totp/Zorvian%20Guardian:{u['email']}"
        f"?secret={secret}&issuer=Zorvian%20Guardian&algorithm=SHA1&digits=6&period=30"
    )
    security_event("mfa_setup_started", "info", u["tenant_id"], u["id"], "one-time enrollment created", request)
    return {
        "enrollment_id": enrollment_id,
        "secret": secret,
        "otpauth_uri": uri,
        "expires_at": expires_at,
        "server_unix_time": int(time.time()),
    }


@app.post("/auth/mfa/enable-v3")
def mfa_enable_v3(d: MFAEnableV3In, request: Request, u=Depends(current_user)):
    code = str(d.code).strip()
    if not re.fullmatch(r"\d{6}", code):
        raise HTTPException(422, "Enter a 6-digit authenticator code")
    rate_limit("mfa-enable:" + u["id"], 12, 600)
    c = db()
    r = c.execute(
        "SELECT * FROM mfa_enrollments WHERE id=? AND user_id=? AND used_at IS NULL AND expires_at>?",
        (d.enrollment_id, u["id"], now()),
    ).fetchone()
    if not r:
        c.close()
        raise HTTPException(409, "This QR setup has expired or been replaced. Click Set Up MFA once and scan the new QR.")
    secret = r["secret"]
    ts = int(time.time())
    matched_offset = None
    # Enrollment only: tolerate up to +/-10 minutes to diagnose device clock skew.
    for step in range(-20, 21):
        if hmac.compare_digest(totp_code(secret, ts + step * 30), code):
            matched_offset = step
            break
    if matched_offset is None:
        c.close()
        security_event("mfa_enrollment_failed", "warning", u["tenant_id"], u["id"], "code did not match bound enrollment secret", request)
        raise HTTPException(400, "The authenticator code does not match this exact QR enrollment. Remove previous Zorvian entries, click Set Up MFA once, scan that QR once, and use the new Zorvian code.")
    c.execute("UPDATE users SET mfa_secret=?,mfa_enabled=1 WHERE id=?", (secret, u["id"]))
    c.execute("UPDATE mfa_enrollments SET used_at=? WHERE id=?", (now(), r["id"]))
    c.commit()
    c.close()
    security_event("mfa_enabled", "info", u["tenant_id"], u["id"], f"TOTP enabled; enrollment_offset_steps={matched_offset}", request)
    return {"status": "mfa_enabled", "clock_offset_seconds": matched_offset * 30}


# Compatibility endpoint retained for v13/v14 clients during rollout.
@app.post("/auth/mfa/enable-v2")
def mfa_enable_v2(d: MFAEnableV2In, request: Request, u=Depends(current_user)):
    raise HTTPException(409, "Refresh Zorvian and use the latest MFA setup flow.")
