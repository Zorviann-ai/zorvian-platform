"""Phase 3 Stage 1 — live-execution foundations with every gate default-deny.

Live submit is never entered through this module's public API helpers.
Shadow performs validation only and does not consume tickets or call providers.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import uuid
from datetime import timedelta
from typing import Any
from urllib.parse import urlparse

from intelligence.execution import load_ticket, _iso, _now, _parse_iso
from intelligence.execution_adapters import (
    AdapterDenied,
    destination_hash,
    get_adapter,
    load_plan,
    payload_hash,
    validate_plan_bound_approval,
    _append_evidence,
    _record_control_event,
    _update_plan_status,
)
from intelligence.execution_providers import ClosedProvider, ProviderDenied, get_provider
from intelligence.execution_providers_webhook import (
    InProcessWebhookSink,
    NullResolver,
    ResolverPort,
    SandboxRequest,
    StaticResolver,
    WebhookSandboxProvider,
    DestinationDenied,
    validate_hardened_webhook_destination,
)
from intelligence.execution_receipts import record_receipt

LIVE_ENV_SWITCH = "ZORVIAN_EXTERNAL_EXECUTION"
CONFIRMATION_TTL_SECONDS = int(os.getenv("ZORVIAN_CONFIRMATION_TTL_SECONDS", "600"))

ALLOWED_TRANSITIONS = {
    "PREPARED": {"SHADOW_COMPLETE"},
    "SHADOW_COMPLETE": {"SUBMITTING"},
    "SUBMITTING": {"EXECUTED", "FAILED", "UNCERTAIN", "CANCEL_REQUESTED"},
    "CANCEL_REQUESTED": {"CANCELLED", "EXECUTED_AFTER_CANCEL_REQUEST"},
    "UNCERTAIN": {"EXECUTED", "FAILED", "MANUAL_RESOLUTION_REQUIRED"},
}

LIVE_STATES = {
    "SUBMITTING",
    "EXECUTED",
    "FAILED",
    "UNCERTAIN",
    "CANCEL_REQUESTED",
    "CANCELLED",
    "EXECUTED_AFTER_CANCEL_REQUEST",
    "MANUAL_RESOLUTION_REQUIRED",
}

BLOCKED_HOSTS = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "metadata.google.com",
    "instance-data",
    "metadata.aws.internal",
}

BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
    ipaddress.ip_network("2001:db8::/32"),
]


class LiveDenied(AdapterDenied):
    pass


def ensure_phase3_schema(c: sqlite3.Connection) -> None:
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS execution_attempts(
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            plan_id TEXT NOT NULL,
            ticket_id TEXT NOT NULL,
            adapter_id TEXT NOT NULL,
            idempotency_key TEXT NOT NULL,
            state TEXT NOT NULL,
            provider_ref TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(tenant_id, idempotency_key)
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS execution_receipts(
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            attempt_id TEXT NOT NULL,
            classification TEXT NOT NULL,
            payload_hash TEXT,
            destination_hash TEXT,
            recorded_at TEXT NOT NULL,
            extra_json TEXT NOT NULL DEFAULT '{}'
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS execution_live_grants(
            tenant_id TEXT NOT NULL,
            adapter_id TEXT NOT NULL,
            action TEXT NOT NULL DEFAULT '*',
            env TEXT NOT NULL DEFAULT 'prod',
            enabled INTEGER NOT NULL DEFAULT 0,
            created_by TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(tenant_id, adapter_id, action, env)
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS execution_destination_allowlist(
            tenant_id TEXT NOT NULL,
            adapter_id TEXT NOT NULL,
            destination_hash TEXT NOT NULL,
            label TEXT,
            created_at TEXT NOT NULL,
            PRIMARY KEY(tenant_id, adapter_id, destination_hash)
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS execution_kill_switches(
            id TEXT PRIMARY KEY,
            scope TEXT NOT NULL,
            tenant_id TEXT,
            adapter_id TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            reason TEXT,
            updated_at TEXT NOT NULL
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS execution_shadow_runs(
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            plan_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            result TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS execution_confirmation_tokens(
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            plan_id TEXT NOT NULL,
            approval_hash TEXT,
            idempotency_key TEXT,
            token_hash TEXT NOT NULL UNIQUE,
            expires_at TEXT NOT NULL,
            consumed_at TEXT,
            revoked_at TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS execution_resolution_records(
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            plan_id TEXT NOT NULL,
            destination_hash TEXT NOT NULL,
            hostname TEXT NOT NULL,
            addresses TEXT NOT NULL DEFAULT '[]',
            record_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS execution_phase3_audit(
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            event TEXT NOT NULL,
            subject_id TEXT,
            detail_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
        )
        """
    )


def apply_phase3_disablement(c: sqlite3.Connection) -> None:
    """Rollback helper: disable live capability, keep evidence tables."""
    now = _iso()
    c.execute("UPDATE execution_live_grants SET enabled=0, updated_at=?", (now,))
    existing = c.execute(
        "SELECT id FROM execution_kill_switches WHERE scope='global' AND tenant_id IS NULL"
    ).fetchone()
    if existing:
        c.execute(
            "UPDATE execution_kill_switches SET enabled=1, reason=?, updated_at=? WHERE id=?",
            ("phase3_rollback_disablement", now, existing["id"]),
        )
    else:
        c.execute(
            """INSERT INTO execution_kill_switches(id,scope,tenant_id,adapter_id,enabled,reason,updated_at)
               VALUES (?,?,?,?,?,?,?)""",
            (str(uuid.uuid4()), "global", None, None, 1, "phase3_rollback_disablement", now),
        )
    _audit(c, tenant_id="system", actor_id="system", event="phase3_functionality_disabled", subject_id=None, detail={"reason": "rollback"})


def _audit(c: sqlite3.Connection, *, tenant_id: str, actor_id: str, event: str, subject_id: str | None, detail: dict[str, Any] | None = None) -> None:
    safe = {k: v for k, v in (detail or {}).items() if k not in {"token", "secret", "password", "authorization", "destination"}}
    c.execute(
        """INSERT INTO execution_phase3_audit(id,tenant_id,actor_id,event,subject_id,detail_json,created_at)
           VALUES (?,?,?,?,?,?,?)""",
        (str(uuid.uuid4()), tenant_id, actor_id, event, subject_id, json.dumps(safe), _iso()),
    )


def process_live_switch_enabled() -> bool:
    value = (os.getenv(LIVE_ENV_SWITCH) or "off").strip().lower()
    return value in {"pilot", "on", "live", "1", "true"}


def assert_external_disabled_public() -> dict[str, Any]:
    return {"external_execution_enabled": False}


def transition_plan_status(current: str, target: str) -> str:
    allowed = ALLOWED_TRANSITIONS.get(current, set())
    if target not in allowed:
        raise LiveDenied(f"invalid state transition {current} -> {target}")
    return target


def assert_not_live_api_transition(target: str) -> None:
    if target in LIVE_STATES or target == "SUBMITTING":
        raise LiveDenied("Stage 1 APIs cannot enter live execution states")


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_confirmation_token(
    c: sqlite3.Connection,
    *,
    tenant_id: str,
    user_id: str,
    plan_id: str,
    approval_hash: str | None,
    idempotency_key: str | None,
    ttl_seconds: int | None = None,
) -> str:
    """Library-only issuer. Not exposed as an HTTP endpoint in Stage 1."""
    ensure_phase3_schema(c)
    token = secrets.token_urlsafe(32)
    token_h = hash_token(token)
    now = _now()
    expires = now + timedelta(seconds=ttl_seconds or CONFIRMATION_TTL_SECONDS)
    c.execute(
        """INSERT INTO execution_confirmation_tokens(
            id,tenant_id,user_id,plan_id,approval_hash,idempotency_key,token_hash,expires_at,created_at
        ) VALUES (?,?,?,?,?,?,?,?,?)""",
        (str(uuid.uuid4()), tenant_id, user_id, plan_id, approval_hash, idempotency_key, token_h, _iso(expires), _iso(now)),
    )
    _audit(c, tenant_id=tenant_id, actor_id=user_id, event="confirmation_token_issued", subject_id=plan_id, detail={"token_hash_prefix": token_h[:8]})
    return token


def revoke_confirmation_token(c: sqlite3.Connection, *, tenant_id: str, token_hash: str, actor_id: str) -> None:
    cur = c.execute(
        """UPDATE execution_confirmation_tokens SET revoked_at=?
           WHERE tenant_id=? AND token_hash=? AND revoked_at IS NULL""",
        (_iso(), tenant_id, token_hash),
    )
    if cur.rowcount != 1:
        raise LiveDenied("confirmation token cannot be revoked")
    _audit(c, tenant_id=tenant_id, actor_id=actor_id, event="confirmation_token_revoked", subject_id=token_hash[:8], detail={})


def consume_confirmation_token(
    c: sqlite3.Connection,
    *,
    tenant_id: str,
    user_id: str,
    plan_id: str,
    approval_hash: str | None,
    idempotency_key: str | None,
    token: str,
) -> None:
    token_h = hash_token(token)
    now = _iso()
    cur = c.execute(
        """UPDATE execution_confirmation_tokens
           SET consumed_at=?
           WHERE tenant_id=? AND user_id=? AND plan_id=? AND token_hash=?
             AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at>?
             AND IFNULL(approval_hash,'')=IFNULL(?, '')
             AND IFNULL(idempotency_key,'')=IFNULL(?, '')""",
        (now, tenant_id, user_id, plan_id, token_h, now, approval_hash, idempotency_key),
    )
    if cur.rowcount != 1:
        row = c.execute(
            "SELECT * FROM execution_confirmation_tokens WHERE tenant_id=? AND token_hash=?",
            (tenant_id, token_h),
        ).fetchone()
        if row is None:
            raise LiveDenied("confirmation token not found")
        if row["revoked_at"]:
            raise LiveDenied("confirmation token revoked")
        if row["consumed_at"]:
            raise LiveDenied("confirmation token replay blocked")
        expires = _parse_iso(row["expires_at"])
        if expires and _now() > expires:
            raise LiveDenied("confirmation token expired")
        raise LiveDenied("confirmation token binding mismatch")
    _audit(c, tenant_id=tenant_id, actor_id=user_id, event="confirmation_token_consumed", subject_id=plan_id, detail={"token_hash_prefix": token_h[:8]})


def set_kill_switch(
    c: sqlite3.Connection,
    *,
    scope: str,
    enabled: bool,
    reason: str,
    actor_id: str,
    tenant_id: str | None = None,
    adapter_id: str | None = None,
) -> None:
    now = _iso()
    row_id = str(uuid.uuid4())
    c.execute(
        """INSERT INTO execution_kill_switches(id,scope,tenant_id,adapter_id,enabled,reason,updated_at)
           VALUES (?,?,?,?,?,?,?)""",
        (row_id, scope, tenant_id, adapter_id, 1 if enabled else 0, reason, now),
    )
    _audit(
        c,
        tenant_id=tenant_id or "system",
        actor_id=actor_id,
        event="kill_switch_changed",
        subject_id=row_id,
        detail={"scope": scope, "enabled": enabled, "adapter_id": adapter_id},
    )


def add_destination_allowlist(
    c: sqlite3.Connection,
    *,
    tenant_id: str,
    adapter_id: str,
    destination: str,
    label: str = "",
) -> None:
    c.execute(
        """INSERT OR REPLACE INTO execution_destination_allowlist(tenant_id,adapter_id,destination_hash,label,created_at)
           VALUES (?,?,?,?,?)""",
        (tenant_id, adapter_id, destination_hash(destination), label, _iso()),
    )


def grant_live(
    c: sqlite3.Connection,
    *,
    tenant_id: str,
    adapter_id: str,
    action: str,
    env: str,
    actor_id: str,
    enabled: bool = False,
) -> None:
    now = _iso()
    c.execute(
        """INSERT INTO execution_live_grants(tenant_id,adapter_id,action,env,enabled,created_by,created_at,updated_at)
           VALUES (?,?,?,?,?,?,?,?)
           ON CONFLICT(tenant_id,adapter_id,action,env) DO UPDATE SET enabled=excluded.enabled, updated_at=excluded.updated_at""",
        (tenant_id, adapter_id, action, env, 1 if enabled else 0, actor_id, now, now),
    )
    _audit(c, tenant_id=tenant_id, actor_id=actor_id, event="live_grant_changed", subject_id=adapter_id, detail={"enabled": enabled, "action": action})


def _global_kill_active(c: sqlite3.Connection) -> bool:
    row = c.execute(
        """SELECT enabled FROM execution_kill_switches
           WHERE scope='global' AND enabled=1
           ORDER BY updated_at DESC LIMIT 1"""
    ).fetchone()
    return bool(row and row["enabled"])


def _tenant_kill_active(c: sqlite3.Connection, tenant_id: str, adapter_id: str) -> bool:
    row = c.execute(
        """SELECT enabled FROM execution_kill_switches
           WHERE enabled=1 AND scope IN ('tenant','tenant_adapter')
             AND tenant_id=? AND (adapter_id IS NULL OR adapter_id=?)
           ORDER BY updated_at DESC LIMIT 1""",
        (tenant_id, adapter_id),
    ).fetchone()
    return bool(row and row["enabled"])


def _grant_enabled(c: sqlite3.Connection, tenant_id: str, adapter_id: str, action: str, env: str) -> bool:
    row = c.execute(
        """SELECT enabled FROM execution_live_grants
           WHERE tenant_id=? AND adapter_id=? AND enabled=1
             AND action IN (?, '*') AND env IN (?, '*')
           LIMIT 1""",
        (tenant_id, adapter_id, action, env),
    ).fetchone()
    return bool(row and row["enabled"])


def evaluate_live_gates(
    c: sqlite3.Connection,
    *,
    tenant_id: str,
    adapter_id: str,
    action: str,
    env: str = "prod",
) -> None:
    adapter = get_adapter(adapter_id)
    raw = os.getenv(LIVE_ENV_SWITCH)
    if raw is None or str(raw).strip() == "":
        raise LiveDenied("process external-execution switch is missing")
    if process_live_switch_enabled() is not True:
        raise LiveDenied("process external-execution switch is off")
    if _global_kill_active(c):
        raise LiveDenied("global kill switch is active")
    if _tenant_kill_active(c, tenant_id, adapter_id):
        raise LiveDenied("tenant kill switch is active")
    if not _grant_enabled(c, tenant_id, adapter_id, action, env):
        raise LiveDenied("tenant live grant is missing or disabled")
    if not adapter.live_execution_supported:
        raise LiveDenied("adapter live support flag is disabled")
    if adapter.external:
        raise LiveDenied("External execution disabled in Controlled Execution Gateway Phase 3 Stage 1")


def _host_blocked(host: str) -> bool:
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return True
    if host in BLOCKED_HOSTS or host.endswith(".localhost") or host.endswith(".local"):
        return True
    if host == "metadata" or host.endswith(".internal"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(ip in net for net in BLOCKED_NETWORKS)


def validate_webhook_destination_stage1(destination: str | None, allowed_hashes: list[str]) -> str:
    value = (destination or "").strip()
    if not value:
        raise LiveDenied("destination is required")
    parsed = urlparse(value)
    if parsed.scheme != "https":
        raise LiveDenied("webhook destination must be HTTPS")
    if parsed.username or parsed.password:
        raise LiveDenied("webhook destination must not include credentials")
    if parsed.port == 80:
        raise LiveDenied("webhook destination must not use plaintext ports")
    host = (parsed.hostname or "").lower()
    if not host or _host_blocked(host):
        raise LiveDenied("webhook destination is not publicly allowable")
    dest_h = destination_hash(value)
    if not allowed_hashes or dest_h not in allowed_hashes:
        raise LiveDenied("destination is not allowlisted for this tenant adapter")
    return value


def _allowlisted_hashes(c: sqlite3.Connection, tenant_id: str, adapter_id: str) -> list[str]:
    rows = c.execute(
        "SELECT destination_hash FROM execution_destination_allowlist WHERE tenant_id=? AND adapter_id=?",
        (tenant_id, adapter_id),
    ).fetchall()
    return [r["destination_hash"] for r in rows]


def _require_role(role: str | None) -> None:
    if role not in {"owner", "write", "execution_live", "admin"}:
        raise LiveDenied("role is not authorised for execution gateway actions")


def _guardian_ok(ticket) -> None:
    if not ticket.guardian_assessment_id:
        raise LiveDenied("Guardian assessment missing")
    if ticket.execution_state not in {"AUTHORISED", "CONSUMED"}:
        raise LiveDenied("ticket is not authorised for shadow or live paths")


def shadow_execution_plan(
    c: sqlite3.Connection,
    *,
    tenant_id: str,
    user_id: str,
    plan_id: str,
    role: str = "write",
    payload: dict[str, Any] | None = None,
    destination: str | None = None,
    resource_id: str | None = None,
    resource_hash: str | None = None,
    payload_tenant_id: str | None = None,
) -> dict[str, Any]:
    ensure_phase3_schema(c)
    if payload_tenant_id and payload_tenant_id != tenant_id:
        raise LiveDenied("Tenant identity cannot be supplied by the client payload")
    _require_role(role)
    plan = load_plan(c, plan_id, tenant_id)
    if plan is None:
        raise LiveDenied("execution plan not found")
    if plan["requesting_user_id"] != user_id:
        raise LiveDenied("execution plan does not belong to this user")
    if plan["tenant_id"] != tenant_id:
        raise LiveDenied("tenant mismatch")
    adapter = get_adapter(plan["adapter_id"])
    if _global_kill_active(c):
        raise LiveDenied("global kill switch is active")
    if _tenant_kill_active(c, tenant_id, plan["adapter_id"]):
        raise LiveDenied("tenant kill switch is active")
    ticket = load_ticket(c, plan["execution_ticket_id"], tenant_id)
    if ticket is None:
        raise LiveDenied("execution ticket not found for this tenant")
    if ticket.requesting_user_id != user_id:
        raise LiveDenied("execution ticket does not belong to this user")
    _guardian_ok(ticket)
    if adapter.requires_human_approval or plan.get("approval_hash") or plan.get("approval_binding_id"):
        validate_plan_bound_approval(c, plan)
    if payload is not None and payload_hash(payload) != plan["payload_hash"]:
        raise LiveDenied("payload change blocked")
    if destination is not None and destination_hash(destination) != plan.get("destination_hash"):
        raise LiveDenied("destination change blocked")
    if resource_id is not None and resource_id != plan.get("resource_id"):
        raise LiveDenied("resource change blocked")
    if resource_hash is not None and resource_hash != plan.get("resource_hash"):
        raise LiveDenied("resource hash mismatch")
    allowed = _allowlisted_hashes(c, tenant_id, plan["adapter_id"])
    if adapter.requires_destination:
        dest_value = destination or plan.get("destination")
        if adapter.adapter_type == "webhook":
            host_allow = []
            if dest_value:
                from urllib.parse import urlsplit
                host = urlsplit(dest_value).hostname
                if host:
                    host_allow = [host]
            validate_hardened_webhook_destination(
                dest_value,
                allowed_hosts=host_allow,
                resolver=NullResolver(),
                plan_id=plan_id,
            )
            if not allowed or destination_hash(dest_value or "") not in allowed:
                raise LiveDenied("destination is not allowlisted for this tenant adapter")
        else:
            if not allowed or destination_hash(dest_value or "") not in allowed:
                raise LiveDenied("destination is not allowlisted for this tenant adapter")
    provider = get_provider(adapter)
    preview = provider.shadow(plan)
    if plan["status"] == "PREPARED":
        transition_plan_status(plan["status"], "SHADOW_COMPLETE")
        _append_evidence(plan, "execution_shadow_completed")
        _update_plan_status(c, plan_id, tenant_id, "SHADOW_COMPLETE", plan.get("evidence_chain") or [])
        plan["status"] = "SHADOW_COMPLETE"
    elif plan["status"] == "SHADOW_COMPLETE":
        _append_evidence(plan, "execution_shadow_repeated")
        _update_plan_status(c, plan_id, tenant_id, "SHADOW_COMPLETE", plan.get("evidence_chain") or [])
    else:
        raise LiveDenied(f"invalid state transition {plan['status']} -> SHADOW_COMPLETE")
    run_id = str(uuid.uuid4())
    c.execute(
        """INSERT INTO execution_shadow_runs(id,tenant_id,plan_id,user_id,result,created_at)
           VALUES (?,?,?,?,?,?)""",
        (run_id, tenant_id, plan_id, user_id, "shadow_complete", _iso()),
    )
    _audit(c, tenant_id=tenant_id, actor_id=user_id, event="execution_shadow_completed", subject_id=plan_id, detail={"run_id": run_id})
    _record_control_event(c, tenant_id=tenant_id, user_id=user_id, action="execution_shadow_completed", result="shadow", extra={"plan_id": plan_id})
    ticket_after = load_ticket(c, plan["execution_ticket_id"], tenant_id)
    return {
        "shadow": {
            "mode": preview.mode,
            "adapter_id": preview.adapter_id,
            "execution_allowed": False,
            "reason": preview.reason,
            "destination_hash": preview.destination_hash,
            "payload_hash": preview.payload_hash,
        },
        "plan_status": plan["status"],
        "ticket_state": None if ticket_after is None else ticket_after.execution_state,
        "external_execution_enabled": False,
        "shadow_run_id": run_id,
    }


def request_live_execution(*_args: Any, **_kwargs: Any) -> None:
    raise LiveDenied("Stage 1 APIs cannot enter live execution states")


def submit_live(*_args: Any, **_kwargs: Any) -> None:
    raise LiveDenied("External execution disabled in Controlled Execution Gateway Phase 3 Stage 1")


def operator_status(c: sqlite3.Connection, *, tenant_id: str | None = None) -> dict[str, Any]:
    ensure_phase3_schema(c)
    params: list[Any] = []
    tenant_sql = ""
    if tenant_id:
        tenant_sql = " AND tenant_id=?"
        params.append(tenant_id)
    uncertain = c.execute(
        f"SELECT id, tenant_id, plan_id, state, updated_at FROM execution_attempts WHERE state='UNCERTAIN'{tenant_sql}",
        params,
    ).fetchall()
    stuck = c.execute(
        f"SELECT id, tenant_id, plan_id, state, updated_at FROM execution_attempts WHERE state IN ('SUBMITTING','CANCEL_REQUESTED'){tenant_sql}",
        params,
    ).fetchall()
    kills = c.execute(
        "SELECT id, scope, tenant_id, adapter_id, enabled, reason, updated_at FROM execution_kill_switches WHERE enabled=1"
    ).fetchall()
    denials = c.execute(
        """SELECT event, COUNT(*) AS n FROM execution_phase3_audit
           WHERE event LIKE '%denied%' OR event LIKE '%blocked%'
           GROUP BY event"""
    ).fetchall()
    return {
        "uncertain_attempts": [dict(r) for r in uncertain],
        "stuck_attempts": [dict(r) for r in stuck],
        "open_circuit_breakers": [],
        "active_kill_switches": [dict(r) for r in kills],
        "repeated_execution_denials": [dict(r) for r in denials],
        "external_execution_enabled": False,
        "process_switch": os.getenv(LIVE_ENV_SWITCH) or "missing",
    }


def record_denied(c: sqlite3.Connection, *, tenant_id: str, actor_id: str, reason: str, plan_id: str | None = None) -> None:
    _audit(c, tenant_id=tenant_id, actor_id=actor_id, event="execution_live_denied", subject_id=plan_id, detail={"reason": reason})


def persist_resolution(c: sqlite3.Connection, *, tenant_id: str, record) -> None:
    ensure_phase3_schema(c)
    c.execute(
        """INSERT INTO execution_resolution_records(
            id,tenant_id,plan_id,destination_hash,hostname,addresses,record_hash,created_at
        ) VALUES (?,?,?,?,?,?,?,?)""",
        (
            record.record_id,
            tenant_id,
            record.plan_id,
            record.destination_hash,
            record.hostname,
            json.dumps(list(record.addresses)),
            record.record_hash,
            record.created_at,
        ),
    )


def shadow_webhook_sandbox(
    c: sqlite3.Connection,
    *,
    tenant_id: str,
    user_id: str,
    plan_id: str,
    role: str = "write",
    payload: dict | None = None,
    destination: str | None = None,
    allowed_hosts: list[str] | None = None,
    resolver: ResolverPort | None = None,
    sink: InProcessWebhookSink | None = None,
    headers: dict[str, str] | None = None,
) -> dict:
    """Stage 2 shadow + in-process sandbox construction. Never submits live."""
    base = shadow_execution_plan(
        c,
        tenant_id=tenant_id,
        user_id=user_id,
        plan_id=plan_id,
        role=role,
        payload=payload,
        destination=destination,
    )
    plan = load_plan(c, plan_id, tenant_id)
    if plan is None:
        raise LiveDenied("execution plan not found")
    adapter = get_adapter(plan["adapter_id"])
    if adapter.adapter_id != "webhook.post":
        raise LiveDenied("webhook sandbox requires webhook.post")
    dest_value = destination or plan.get("destination")
    if payload is not None:
        body = payload
    else:
        raw = plan.get("payload_canonical") or "{}"
        body = json.loads(raw) if isinstance(raw, str) else (raw or {})
    provider = WebhookSandboxProvider(adapter, transport=sink, resolver=resolver or NullResolver(), production_mode=False)
    plan_view = dict(plan)
    plan_view["id"] = plan.get("execution_plan_id") or plan.get("id")
    request = provider.build_sandbox_request(
        plan=plan_view,
        payload=body,
        destination=dest_value,
        allowed_hosts=allowed_hosts or [],
        headers=headers,
    )
    _, resolution = validate_hardened_webhook_destination(
        dest_value,
        allowed_hosts=allowed_hosts or [],
        resolver=resolver or NullResolver(),
        plan_id=plan_id,
    )
    persist_resolution(c, tenant_id=tenant_id, record=resolution)
    recorded = provider.record_sandbox(request) if sink is not None else None
    ticket_after = load_ticket(c, plan["execution_ticket_id"], tenant_id)
    public = {
        "plan_id": request.plan_id,
        "tenant_id": request.tenant_id,
        "adapter_id": request.adapter_id,
        "action": request.action,
        "destination_hash": request.destination_hash,
        "payload_hash": request.payload_hash,
        "resource_hash": request.resource_hash,
        "approval_hash": request.approval_hash,
        "idempotency_key": request.idempotency_key,
        "masked_destination": request.masked_destination,
        "redacted_headers": request.redacted_headers,
        "resolution_record_hash": request.resolution_record_hash,
        "created_at": request.created_at,
        "expires_at": request.expires_at,
    }
    banned = ("secret", "authorization", "token", "password")
    blob = json.dumps(public)
    if any(word in blob.lower() and "idempotency" not in blob.lower() for word in ("bearer ", "basic ")):
        raise LiveDenied("sandbox output leaked credentials")
    return {
        **base,
        "sandbox_request": public,
        "sandbox_receipt": recorded,
        "ticket_state": None if ticket_after is None else ticket_after.execution_state,
        "external_execution_enabled": False,
    }
