"""Gate 7 operational email layer.

Adds professional tenant-branded outbound mail, secure inbound Resend webhook
handling, tenant/thread routing, contact association, audit records and truthful
mailbox status reporting. External status is reported connected only when both
outbound and inbound provider configuration are present.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import urllib.error
import urllib.request
import uuid
from email.utils import parseaddr

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field

import app as core_app
from app_gate8 import app
from email_branding import render_email


class MailboxActivateIn(BaseModel):
    display_name: str | None = Field(default=None, max_length=120)


class MailSendIn(BaseModel):
    to: str
    subject: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=20000)
    contact_id: str | None = None
    thread_id: str | None = None


def _ensure_email_tables():
    c = core_app.db()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS mailbox_settings(
            tenant_id TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            inbound_address TEXT UNIQUE,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS email_threads(
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            contact_id TEXT,
            route_token TEXT UNIQUE NOT NULL,
            subject TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS email_messages(
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            thread_id TEXT,
            direction TEXT NOT NULL,
            provider_id TEXT UNIQUE,
            message_id TEXT,
            contact_id TEXT,
            from_addr TEXT NOT NULL,
            to_addr TEXT NOT NULL,
            subject TEXT,
            text_body TEXT,
            html_body TEXT,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS email_events(
            id TEXT PRIMARY KEY,
            tenant_id TEXT,
            message_id TEXT,
            provider_event_id TEXT UNIQUE,
            event_type TEXT NOT NULL,
            detail_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """
    )
    c.commit()
    c.close()


_ensure_email_tables()


def _api_key():
    return os.getenv("RESEND_API_KEY") or os.getenv("SMTP_PASSWORD") or ""


def _sender_email():
    return parseaddr(os.getenv("SMTP_FROM", ""))[1]


def _inbound_domain():
    return os.getenv("RESEND_INBOUND_DOMAIN", "").strip().lower().lstrip("@")


def _mailbox_capabilities():
    outbound = bool(_api_key() and _sender_email())
    inbound = bool(_api_key() and _inbound_domain() and os.getenv("RESEND_WEBHOOK_SECRET", "").strip())
    return outbound, inbound


def _set_integration_status(tenant_id: str, status: str, config: dict):
    c = core_app.db()
    row = c.execute("SELECT id FROM integrations WHERE tenant_id=? AND provider='email'", (tenant_id,)).fetchone()
    if row:
        c.execute("UPDATE integrations SET status=?,config_json=? WHERE id=?", (status, json.dumps(config), row["id"]))
    else:
        c.execute("INSERT INTO integrations VALUES (?,?,?,?,?,?)", (str(uuid.uuid4()), tenant_id, "email", status, json.dumps(config), core_app.now()))
    c.commit()
    c.close()


def _tenant(u):
    c = core_app.db()
    row = c.execute("SELECT * FROM tenants WHERE id=?", (u["tenant_id"],)).fetchone()
    c.close()
    if not row:
        raise HTTPException(404, "Workspace not found")
    return dict(row)


def _safe_alias(slug: str):
    alias = re.sub(r"[^a-z0-9-]+", "-", (slug or "workspace").lower()).strip("-")[:48]
    return alias or "workspace"


def _route_token():
    return secrets.token_urlsafe(12).replace("_", "").replace("-", "").lower()[:20]


def _find_contact(c, tenant_id: str, address: str):
    return c.execute(
        "SELECT * FROM contacts WHERE tenant_id=? AND lower(contact) LIKE ? ORDER BY created_at DESC LIMIT 1",
        (tenant_id, f"%{address.lower()}%"),
    ).fetchone()


def _audit_system(c, tenant_id: str, event: str, detail: str, severity="info"):
    c.execute(
        "INSERT INTO audit VALUES (?,?,?,?,?,?,?)",
        (str(uuid.uuid4()), tenant_id, None, event, detail[:1000], severity, core_app.now()),
    )


def _resend_json(method: str, path: str, payload: dict | None = None, extra_headers: dict | None = None):
    key = _api_key()
    if not key:
        raise HTTPException(503, "Email provider is not configured")
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "User-Agent": "Zorvian-Core/0.9.0",
    }
    headers.update(extra_headers or {})
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(f"https://api.resend.com{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode("utf-8", "replace")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500]
        raise HTTPException(502, f"Email provider error ({exc.code})") from RuntimeError(detail)
    except urllib.error.URLError as exc:
        raise HTTPException(503, "Email provider could not be reached") from exc


def _verify_resend_webhook(raw: bytes, request: Request):
    secret = os.getenv("RESEND_WEBHOOK_SECRET", "").strip()
    if not secret:
        raise HTTPException(503, "Inbound email webhook is not configured")
    svix_id = request.headers.get("svix-id", "")
    svix_ts = request.headers.get("svix-timestamp", "")
    svix_sig = request.headers.get("svix-signature", "")
    if not svix_id or not svix_ts or not svix_sig:
        raise HTTPException(400, "Invalid webhook signature")
    try:
        timestamp = int(svix_ts)
    except ValueError:
        raise HTTPException(400, "Invalid webhook timestamp")
    if abs(int(time.time()) - timestamp) > 300:
        raise HTTPException(400, "Expired webhook signature")
    encoded = secret.removeprefix("whsec_")
    encoded += "=" * ((4 - len(encoded) % 4) % 4)
    try:
        key = base64.b64decode(encoded)
    except Exception as exc:
        raise HTTPException(503, "Webhook signing secret is invalid") from exc
    signed = f"{svix_id}.{svix_ts}.".encode() + raw
    expected = base64.b64encode(hmac.new(key, signed, hashlib.sha256).digest()).decode()
    candidates = [part.split(",", 1)[1] for part in svix_sig.split() if part.startswith("v1,")]
    if not any(hmac.compare_digest(expected, candidate) for candidate in candidates):
        raise HTTPException(400, "Invalid webhook signature")


@app.post("/mailbox/activate")
def mailbox_activate(d: MailboxActivateIn, u=Depends(core_app.current_user)):
    core_app.require(u, "admin")
    tenant = _tenant(u)
    outbound, inbound = _mailbox_capabilities()
    display = (d.display_name or tenant.get("name") or "Zorvian Client").strip()
    address = None
    if _inbound_domain():
        address = f"{_safe_alias(tenant.get('slug') or tenant['id'][:10])}@{_inbound_domain()}"
    status = "connected" if outbound and inbound else ("outbound_only" if outbound else "not_connected")
    c = core_app.db()
    row = c.execute("SELECT tenant_id FROM mailbox_settings WHERE tenant_id=?", (u["tenant_id"],)).fetchone()
    if row:
        c.execute(
            "UPDATE mailbox_settings SET display_name=?,inbound_address=?,status=?,updated_at=? WHERE tenant_id=?",
            (display, address, status, core_app.now(), u["tenant_id"]),
        )
    else:
        c.execute(
            "INSERT INTO mailbox_settings VALUES (?,?,?,?,?,?)",
            (u["tenant_id"], display, address, status, core_app.now(), core_app.now()),
        )
    _audit_system(c, u["tenant_id"], "mailbox_configured", f"status={status}; inbound={address or 'not configured'}")
    c.commit()
    c.close()
    _set_integration_status(
        u["tenant_id"],
        status,
        {"inbound_address": address, "professional_html": True, "tenant_routing": bool(address)},
    )
    return {
        "status": status,
        "display_name": display,
        "inbound_address": address,
        "outbound_ready": outbound,
        "inbound_ready": inbound,
    }


@app.get("/mailbox/status")
def mailbox_status(u=Depends(core_app.current_user)):
    outbound, inbound = _mailbox_capabilities()
    c = core_app.db()
    row = c.execute("SELECT * FROM mailbox_settings WHERE tenant_id=?", (u["tenant_id"],)).fetchone()
    counts = c.execute(
        "SELECT direction,COUNT(*) c FROM email_messages WHERE tenant_id=? GROUP BY direction",
        (u["tenant_id"],),
    ).fetchall()
    c.close()
    return {
        "status": row["status"] if row else "not_connected",
        "display_name": row["display_name"] if row else None,
        "inbound_address": row["inbound_address"] if row else None,
        "outbound_ready": outbound,
        "inbound_ready": inbound,
        "messages": {r["direction"]: r["c"] for r in counts},
    }


@app.get("/mailbox/messages")
def mailbox_messages(limit: int = 50, u=Depends(core_app.current_user)):
    limit = max(1, min(100, limit))
    c = core_app.db()
    rows = c.execute(
        "SELECT id,thread_id,direction,contact_id,from_addr,to_addr,subject,text_body,status,created_at FROM email_messages WHERE tenant_id=? ORDER BY created_at DESC LIMIT ?",
        (u["tenant_id"], limit),
    ).fetchall()
    c.close()
    return [dict(r) for r in rows]


@app.post("/mailbox/send")
def mailbox_send(d: MailSendIn, u=Depends(core_app.current_user)):
    core_app.require(u, "write")
    recipient = core_app.norm_email(d.to)
    tenant = _tenant(u)
    outbound, inbound = _mailbox_capabilities()
    if not outbound:
        raise HTTPException(503, "Outbound email is not configured")
    c = core_app.db()
    setting = c.execute("SELECT * FROM mailbox_settings WHERE tenant_id=?", (u["tenant_id"],)).fetchone()
    display = (setting["display_name"] if setting else tenant.get("name")) or "Zorvian Client"
    contact = None
    if d.contact_id:
        contact = c.execute(
            "SELECT * FROM contacts WHERE id=? AND tenant_id=?", (d.contact_id, u["tenant_id"])
        ).fetchone()
    if not contact:
        contact = _find_contact(c, u["tenant_id"], recipient)
    if d.thread_id:
        thread = c.execute(
            "SELECT * FROM email_threads WHERE id=? AND tenant_id=?", (d.thread_id, u["tenant_id"])
        ).fetchone()
        if not thread:
            c.close()
            raise HTTPException(404, "Email thread not found")
        thread_id = thread["id"]
        token = str(thread["route_token"]).lower()
    else:
        thread_id = str(uuid.uuid4())
        token = _route_token()
        c.execute(
            "INSERT INTO email_threads VALUES (?,?,?,?,?,?,?)",
            (thread_id, u["tenant_id"], contact["id"] if contact else None, token, d.subject, core_app.now(), core_app.now()),
        )
    reply_to = f"reply+{token}@{_inbound_domain()}" if inbound else None
    sender_addr = _sender_email()
    from_value = f"{display} <{sender_addr}>"
    html = render_email(title=d.subject, body=d.body, client_name=display, preheader=d.body[:120])
    payload = {"from": from_value, "to": [recipient], "subject": d.subject, "text": d.body, "html": html}
    if reply_to:
        payload["reply_to"] = reply_to
    provider = _resend_json(
        "POST",
        "/emails",
        payload,
        {
            "Idempotency-Key": f"zorvian/{u['tenant_id']}/{thread_id}/{hashlib.sha256((recipient+d.subject+d.body).encode()).hexdigest()[:18]}"
        },
    )
    provider_id = provider.get("id")
    mid = str(uuid.uuid4())
    c.execute(
        "INSERT INTO email_messages VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            mid,
            u["tenant_id"],
            thread_id,
            "outbound",
            provider_id,
            None,
            contact["id"] if contact else None,
            sender_addr,
            recipient,
            d.subject,
            d.body,
            html,
            "sent",
            core_app.now(),
        ),
    )
    c.execute("UPDATE email_threads SET updated_at=? WHERE id=?", (core_app.now(), thread_id))
    _audit_system(c, u["tenant_id"], "email_sent", f"to={recipient}; subject={d.subject}; provider_id={provider_id}")
    c.commit()
    c.close()
    return {
        "id": mid,
        "thread_id": thread_id,
        "provider_id": provider_id,
        "status": "sent",
        "reply_to": reply_to,
        "professional_html": True,
    }


@app.post("/webhooks/resend")
async def resend_webhook(request: Request):
    raw = await request.body()
    _verify_resend_webhook(raw, request)
    try:
        event = json.loads(raw)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid webhook payload")
    event_type = str(event.get("type") or "")
    data = event.get("data") or {}
    event_key = request.headers.get("svix-id") or str(uuid.uuid4())
    c = core_app.db()
    if c.execute("SELECT id FROM email_events WHERE provider_event_id=?", (event_key,)).fetchone():
        c.close()
        return {"status": "duplicate_ignored"}
    if event_type != "email.received":
        provider_id = data.get("email_id")
        msg = c.execute("SELECT * FROM email_messages WHERE provider_id=?", (provider_id,)).fetchone() if provider_id else None
        tenant_id = msg["tenant_id"] if msg else None
        if msg:
            c.execute("UPDATE email_messages SET status=? WHERE id=?", (event_type.removeprefix("email."), msg["id"]))
        c.execute(
            "INSERT INTO email_events VALUES (?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), tenant_id, msg["id"] if msg else None, event_key, event_type, json.dumps(data)[:8000], core_app.now()),
        )
        c.commit()
        c.close()
        return {"status": "recorded"}
    provider_id = data.get("email_id")
    if not provider_id:
        c.close()
        raise HTTPException(400, "Missing inbound email id")
    full = _resend_json("GET", f"/emails/receiving/{provider_id}")
    recipients = full.get("to") or data.get("to") or []
    recipients = [recipients] if isinstance(recipients, str) else recipients
    thread = None
    setting = None
    for recipient in recipients:
        address = parseaddr(recipient)[1].lower()
        local = address.split("@", 1)[0]
        if local.startswith("reply+"):
            token = local.split("+", 1)[1].lower()
            thread = c.execute("SELECT * FROM email_threads WHERE lower(route_token)=?", (token,)).fetchone()
            if thread:
                break
        setting = c.execute("SELECT * FROM mailbox_settings WHERE lower(inbound_address)=?", (address,)).fetchone()
        if setting:
            break
    tenant_id = thread["tenant_id"] if thread else (setting["tenant_id"] if setting else None)
    if not tenant_id:
        c.execute(
            "INSERT INTO email_events VALUES (?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), None, None, event_key, event_type, json.dumps(data)[:8000], core_app.now()),
        )
        c.commit()
        c.close()
        return {"status": "unrouted"}
    from_raw = full.get("from") or data.get("from") or ""
    sender_name, sender_addr = parseaddr(from_raw)
    sender_addr = sender_addr.lower()
    contact = _find_contact(c, tenant_id, sender_addr) if sender_addr else None
    text = full.get("text") or ""
    html = full.get("html") or ""
    subject = full.get("subject") or data.get("subject") or "(no subject)"
    if not contact and sender_addr:
        cid = str(uuid.uuid4())
        c.execute(
            "INSERT INTO contacts VALUES (?,?,?,?,?,?,?,?)",
            (cid, tenant_id, sender_name or sender_addr, sender_addr, subject, "Inbound Email", core_app.score(subject + " " + text), core_app.now()),
        )
        contact = c.execute("SELECT * FROM contacts WHERE id=?", (cid,)).fetchone()
    if not thread:
        thread_id = str(uuid.uuid4())
        token = _route_token()
        c.execute(
            "INSERT INTO email_threads VALUES (?,?,?,?,?,?,?)",
            (thread_id, tenant_id, contact["id"] if contact else None, token, subject, core_app.now(), core_app.now()),
        )
    else:
        thread_id = thread["id"]
    msg_id = str(uuid.uuid4())
    to_addr = ", ".join(parseaddr(x)[1] or x for x in recipients)
    c.execute(
        "INSERT OR IGNORE INTO email_messages VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            msg_id,
            tenant_id,
            thread_id,
            "inbound",
            provider_id,
            full.get("message_id") or data.get("message_id"),
            contact["id"] if contact else None,
            sender_addr,
            to_addr,
            subject,
            text,
            html,
            "received",
            core_app.now(),
        ),
    )
    c.execute(
        "INSERT INTO email_events VALUES (?,?,?,?,?,?,?)",
        (str(uuid.uuid4()), tenant_id, msg_id, event_key, event_type, json.dumps(data)[:8000], core_app.now()),
    )
    c.execute(
        "UPDATE email_threads SET contact_id=COALESCE(contact_id,?),updated_at=? WHERE id=?",
        (contact["id"] if contact else None, core_app.now(), thread_id),
    )
    _audit_system(c, tenant_id, "email_received", f"from={sender_addr}; subject={subject}; provider_id={provider_id}")
    c.commit()
    c.close()
    return {
        "status": "received",
        "tenant_id": tenant_id,
        "thread_id": thread_id,
        "contact_id": contact["id"] if contact else None,
    }
