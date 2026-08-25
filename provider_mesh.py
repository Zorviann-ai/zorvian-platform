"""Provider-neutral server-side execution mesh for Zorvian Core.

Credentials remain server-side. Consequential operations require an approved
Core approval record bound to the authenticated tenant.
"""
import datetime
import json
import os
import uuid
from typing import Any
import httpx

PROVIDERS = {
    "ai": {"primary": "openai", "env": ["OPENAI_API_KEY"]},
    "voice": {"primary": "twilio", "env": ["TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN"]},
    "messaging": {"primary": "twilio", "env": ["TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN"]},
    "email": {"primary": "resend", "env": ["RESEND_API_KEY"]},
    "travel_flights": {"primary": "duffel", "env": ["DUFFEL_ACCESS_TOKEN"]},
    "travel_stays": {"primary": "duffel", "env": ["DUFFEL_ACCESS_TOKEN"]},
    "routing": {"primary": "here", "env": ["HERE_API_KEY"]},
    "video": {"primary": "heygen", "env": ["HEYGEN_API_KEY"]},
    "audio": {"primary": "elevenlabs", "env": ["ELEVENLABS_API_KEY"]},
    "social": {"primary": "native_platform_apis", "env": []},
    "documents": {"primary": "openai", "env": ["OPENAI_API_KEY"]},
}

MUTATING_OPS = {"book", "purchase", "send", "publish", "call", "reserve", "cancel", "submit", "create_order", "create_booking", "render", "generate_final"}


def now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def ensure_tables(c) -> None:
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS provider_approvals(
            id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, user_id TEXT NOT NULL,
            action TEXT NOT NULL, payload TEXT NOT NULL, status TEXT NOT NULL,
            requested_at TEXT NOT NULL, approved_at TEXT, approved_by TEXT
        );
        CREATE TABLE IF NOT EXISTS provider_jobs(
            id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, user_id TEXT NOT NULL,
            service TEXT NOT NULL, provider TEXT NOT NULL, status TEXT NOT NULL,
            request TEXT NOT NULL, response TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        """
    )
    c.commit()


def provider_status() -> dict[str, Any]:
    return {name: {"primary": p["primary"], "configured": all(os.getenv(k) for k in p["env"]) if p["env"] else True} for name, p in PROVIDERS.items()}


def needs_approval(operation: str) -> bool:
    return operation.lower() in MUTATING_OPS


def request_approval(c, tenant_id: str, user_id: str, action: str, payload: dict[str, Any]) -> str:
    ensure_tables(c)
    aid = str(uuid.uuid4())
    c.execute("INSERT INTO provider_approvals VALUES (?,?,?,?,?,?,?,?,?)", (aid, tenant_id, user_id, action, json.dumps(payload), "pending", now(), None, None))
    c.commit()
    return aid


def approve(c, tenant_id: str, approval_id: str, approved_by: str) -> bool:
    ensure_tables(c)
    row = c.execute("SELECT id FROM provider_approvals WHERE id=? AND tenant_id=? AND status='pending'", (approval_id, tenant_id)).fetchone()
    if not row:
        return False
    c.execute("UPDATE provider_approvals SET status='approved',approved_at=?,approved_by=? WHERE id=?", (now(), approved_by, approval_id))
    c.commit()
    return True


def approval_ok(c, tenant_id: str, approval_id: str | None, action: str) -> bool:
    if not approval_id:
        return False
    ensure_tables(c)
    row = c.execute("SELECT id FROM provider_approvals WHERE id=? AND tenant_id=? AND status='approved' AND action=?", (approval_id, tenant_id, action)).fetchone()
    return bool(row)


async def call_provider(service: str, operation: str, payload: dict[str, Any]) -> dict[str, Any]:
    if service == "routing" and operation == "route" and os.getenv("HERE_API_KEY"):
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.get("https://router.hereapi.com/v8/routes", params={**payload, "apikey": os.getenv("HERE_API_KEY")})
            r.raise_for_status(); return r.json()
    if service == "email" and operation == "send" and os.getenv("RESEND_API_KEY"):
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.post("https://api.resend.com/emails", headers={"Authorization": f"Bearer {os.getenv('RESEND_API_KEY')}", "Content-Type": "application/json"}, json=payload)
            r.raise_for_status(); return r.json()
    if service == "video" and operation in {"render", "generate_final"} and os.getenv("HEYGEN_API_KEY"):
        async with httpx.AsyncClient(timeout=60) as client:
            r = await client.post("https://api.heygen.com/v2/video/generate", headers={"X-Api-Key": os.getenv("HEYGEN_API_KEY"), "Content-Type": "application/json"}, json=payload)
            r.raise_for_status(); return r.json()
    if service == "audio" and operation in {"voices", "list_voices"} and os.getenv("ELEVENLABS_API_KEY"):
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.get("https://api.elevenlabs.io/v1/voices", headers={"xi-api-key": os.getenv("ELEVENLABS_API_KEY")})
            r.raise_for_status(); return r.json()
    return {"status": "connector_ready", "live_call_made": False, "service": service, "operation": operation, "provider": PROVIDERS[service]["primary"], "reason": "Credential or mapped operation not configured", "payload_received": payload}
