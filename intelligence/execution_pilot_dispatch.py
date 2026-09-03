"""Phase 3 Stage 4F — sealed one-shot production-pilot dispatch and closeout.

Merge, import, bootstrap, preflight and tests never activate a tenant,
install a secret, or send a webhook. There is no public HTTP dispatch route.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import uuid
from typing import Any

from intelligence.execution import _iso, _now, _parse_iso
from intelligence.execution_adapters import get_adapter
from intelligence.execution_live import _global_kill_active, _tenant_kill_active
from intelligence.execution_pilot_activation import (
    ACTIVATION_ENV,
    ActivationDenied,
    PlatformPrincipal,
    _require_principal,
    load_offline_platform_principal,
    suspend_pilot,
)
from intelligence.execution_pilot_ceremony import (
    CeremonyDenied,
    _redact,
    read_confirmation_handoff,
    write_confirmation_handoff,
)
from intelligence.execution_pilot_ops import ACTION, ADAPTER_ID, _ops_audit
from intelligence.execution_pilot_reconciliation import record_reconciliation
from intelligence.execution_production_webhook import (
    PILOT_SECRET_ENV,
    ProductionPilotDenied,
    ProductionUncertain,
    circuit_open,
    submit_production_pilot,
)
from intelligence.execution_providers import ClosedProvider, get_provider
from intelligence.guardian import GUARDIAN_POLICY_VERSION, guardian_policy_hash

CONFIRM_TTL_MINUTES = 10


class DispatchDenied(ActivationDenied):
    """Fail-closed Stage 4F dispatch denial."""


def ensure_stage4f_schema(c: sqlite3.Connection) -> None:
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS execution_pilot_dispatch_approvals(
            approval_id TEXT PRIMARY KEY,
            pilot_id TEXT NOT NULL,
            activation_id TEXT NOT NULL,
            ceremony_receipt_id TEXT NOT NULL,
            plan_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            role TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            context_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked_at TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS execution_pilot_dispatch_confirmations(
            confirmation_id TEXT PRIMARY KEY,
            pilot_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            plan_id TEXT NOT NULL,
            activation_id TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            context_hash TEXT NOT NULL,
            owner_actor_id TEXT NOT NULL,
            security_actor_id TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            consumed_at TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS execution_pilot_dispatch_receipts(
            receipt_id TEXT PRIMARY KEY,
            pilot_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            activation_id TEXT,
            plan_id TEXT,
            attempt_id TEXT,
            owner_actor_id TEXT,
            security_actor_id TEXT,
            status TEXT NOT NULL,
            mode TEXT NOT NULL,
            detail_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    c.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_dispatch_active_role
        ON execution_pilot_dispatch_approvals(pilot_id, plan_id, role)
        WHERE revoked_at IS NULL
        """
    )
    c.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_dispatch_active_actor
        ON execution_pilot_dispatch_approvals(pilot_id, plan_id, actor_id)
        WHERE revoked_at IS NULL
        """
    )


def _commit_dispatch(c: sqlite3.Connection) -> None:
    c.commit()


def _assert_no_caller_substitutes(**kwargs: Any) -> None:
    banned = {
        "tenant_id", "destination", "destination_hash", "manifest_hash",
        "adapter_id", "action", "signing_key_id", "policy_version", "policy_hash",
        "guardian_assessment_id", "guardian_context_hash", "window_minutes",
        "max_successes", "max_concurrent",
    }
    present = [key for key in banned if key in kwargs and kwargs[key] is not None]
    if present:
        raise DispatchDenied("caller may not supply binding substitutes")


def _require_distinct_principals(owner: PlatformPrincipal, security: PlatformPrincipal) -> None:
    _require_principal(owner, "platform_owner")
    _require_principal(security, "security_operator")
    if owner.actor_id == security.actor_id:
        raise DispatchDenied("platform owner and security operator must be different actors")


def _hash_confirmation(token: str, context_hash: str) -> str:
    return hashlib.sha256(f"{token}:{context_hash}".encode("utf-8")).hexdigest()


def _context_binding(
    bundle: dict[str, Any],
    *,
    owner_actor_id: str | None = None,
    security_actor_id: str | None = None,
) -> str:
    payload = {
        "pilot_id": bundle["pilot_id"],
        "activation_id": bundle["activation_id"],
        "ceremony_receipt_id": bundle["ceremony_receipt_id"],
        "plan_id": bundle["plan_id"],
        "tenant_id": bundle["tenant_id"],
        "adapter_id": ADAPTER_ID,
        "action": ACTION,
        "payload_hash": bundle["payload_hash"],
        "destination_hash": bundle["destination_hash"],
        "manifest_hash": bundle["manifest_hash"],
        "guardian_assessment_id": bundle["guardian_assessment_id"],
        "guardian_context_hash": bundle["guardian_context_hash"],
        "policy_version": bundle["policy_version"],
        "policy_hash": bundle["policy_hash"],
        "signing_key_id": bundle["signing_key_id"],
        "owner_actor_id": owner_actor_id or bundle.get("owner_actor_id"),
        "security_actor_id": security_actor_id or bundle.get("security_actor_id"),
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def load_dispatch_bundle(
    c: sqlite3.Connection,
    *,
    pilot_id: str,
    plan_id: str,
) -> dict[str, Any]:
    prep = c.execute(
        "SELECT * FROM execution_pilot_preparations WHERE pilot_id=?", (pilot_id,)
    ).fetchone()
    if prep is None:
        raise DispatchDenied("pilot preparation not found")
    act = c.execute(
        "SELECT * FROM execution_pilot_activations WHERE pilot_id=? AND tenant_id=?",
        (pilot_id, prep["tenant_id"]),
    ).fetchone()
    if act is None:
        raise DispatchDenied("activation not found")
    if act["status"] != "ACTIVE":
        raise DispatchDenied("activation is not ACTIVE")
    receipt = c.execute(
        """SELECT r.* FROM execution_pilot_ceremony_receipts r
           WHERE r.pilot_id=? AND r.tenant_id=? AND r.activation_id=?
             AND r.mode='execute' AND r.status='ACTIVE'""",
        (pilot_id, prep["tenant_id"], act["activation_id"]),
    ).fetchone()
    if receipt is None:
        raise DispatchDenied("ceremony receipt not found for current ACTIVE activation")
    plan = c.execute(
        "SELECT * FROM execution_plans WHERE id=? AND tenant_id=?",
        (plan_id, prep["tenant_id"]),
    ).fetchone()
    if plan is None:
        raise DispatchDenied("execution plan not found")
    if plan["adapter_id"] != ADAPTER_ID:
        raise DispatchDenied("plan adapter mismatch")
    if (plan["destination_hash"] or "") != prep["destination_hash"]:
        raise DispatchDenied("plan destination hash mismatch")
    if (plan["payload_hash"] or "") == "":
        raise DispatchDenied("plan payload hash missing")
    grant = c.execute(
        "SELECT enabled FROM execution_live_grants WHERE tenant_id=? AND adapter_id=? AND action=? AND env=?",
        (prep["tenant_id"], ADAPTER_ID, ACTION, ACTIVATION_ENV),
    ).fetchone()
    allow = c.execute(
        "SELECT COUNT(*) AS n FROM execution_destination_allowlist WHERE tenant_id=? AND adapter_id=? AND destination_hash=?",
        (prep["tenant_id"], ADAPTER_ID, prep["destination_hash"]),
    ).fetchone()["n"]
    if grant is None or not grant["enabled"]:
        raise DispatchDenied("exact live grant is missing")
    if allow != 1:
        raise DispatchDenied("exact allowlist row is missing")
    expires = _parse_iso(act["expires_at"])
    if expires is None or expires <= _now():
        raise DispatchDenied("activation is expired")
    if _global_kill_active(c) or _tenant_kill_active(c, prep["tenant_id"], ADAPTER_ID):
        raise DispatchDenied("kill switch is active")
    if circuit_open(c, prep["tenant_id"], ADAPTER_ID):
        raise DispatchDenied("circuit breaker is open")
    stored_pv = act["policy_version"] if "policy_version" in act.keys() else None
    stored_ph = act["policy_hash"] if "policy_hash" in act.keys() else None
    if stored_pv != GUARDIAN_POLICY_VERSION or stored_ph != guardian_policy_hash():
        raise DispatchDenied("stored policy does not match current authority")
    return {
        "prep": prep,
        "activation": act,
        "ceremony": receipt,
        "plan": plan,
        "pilot_id": pilot_id,
        "activation_id": act["activation_id"],
        "ceremony_receipt_id": receipt["receipt_id"],
        "plan_id": plan_id,
        "tenant_id": prep["tenant_id"],
        "payload_hash": plan["payload_hash"],
        "destination_hash": prep["destination_hash"],
        "manifest_hash": prep["manifest_hash"],
        "guardian_context_hash": act["guardian_context_hash"],
        "guardian_assessment_id": act["guardian_assessment_id"],
        "policy_version": stored_pv,
        "policy_hash": stored_ph,
        "signing_key_id": prep["signing_key_id"],
        "plan_user_id": plan["requesting_user_id"],
    }


def _require_fresh_approvals(c: sqlite3.Connection, bundle: dict[str, Any], context_hash: str) -> None:
    rows = c.execute(
        """SELECT * FROM execution_pilot_dispatch_approvals
           WHERE pilot_id=? AND plan_id=? AND revoked_at IS NULL""",
        (bundle["pilot_id"], bundle["plan_id"]),
    ).fetchall()
    roles = {}
    for row in rows:
        expires = _parse_iso(row["expires_at"])
        if expires is None or expires <= _now():
            raise DispatchDenied("dispatch approval is expired")
        if row["context_hash"] != context_hash:
            raise DispatchDenied("dispatch approval is not bound to current evidence")
        if row["activation_id"] != bundle["activation_id"] or row["ceremony_receipt_id"] != bundle["ceremony_receipt_id"]:
            raise DispatchDenied("dispatch approval binding mismatch")
        if row["role"] in roles:
            raise DispatchDenied("duplicate active approval role")
        roles[row["role"]] = row["actor_id"]
    if "platform_owner" not in roles or "security_operator" not in roles:
        raise DispatchDenied("two distinct dispatch approvals are required")
    if roles["platform_owner"] == roles["security_operator"]:
        raise DispatchDenied("platform owner and security operator must be different actors")
    if len(set(roles.values())) != len(roles):
        raise DispatchDenied("each actor may hold only one active approval")
    return roles


def record_dispatch_approval(
    c: sqlite3.Connection,
    *,
    pilot_id: str,
    plan_id: str,
    principal: PlatformPrincipal,
) -> dict[str, Any]:
    _require_principal(principal)
    if c.in_transaction:
        raise DispatchDenied("open transaction exists")
    bundle = load_dispatch_bundle(c, pilot_id=pilot_id, plan_id=plan_id)
    context_hash = _context_binding(bundle, owner_actor_id=None, security_actor_id=None)
    from datetime import timedelta
    expires_at = _iso(_now() + timedelta(minutes=CONFIRM_TTL_MINUTES))
    c.execute("BEGIN IMMEDIATE")
    try:
        c.execute(
            """INSERT INTO execution_pilot_dispatch_approvals(
                approval_id,pilot_id,activation_id,ceremony_receipt_id,plan_id,tenant_id,
                role,actor_id,context_hash,expires_at,revoked_at,created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,NULL,?)""",
            (
                str(uuid.uuid4()), pilot_id, bundle["activation_id"], bundle["ceremony_receipt_id"],
                plan_id, bundle["tenant_id"], principal.role, principal.actor_id, context_hash,
                expires_at, _iso(),
            ),
        )
        c.commit()
    except sqlite3.IntegrityError as exc:
        try:
            c.rollback()
        except sqlite3.Error:
            pass
        raise DispatchDenied("active approval already exists for this role or actor") from exc
    except Exception:
        try:
            c.rollback()
        except sqlite3.Error:
            pass
        raise
    return {"ok": True, "role": principal.role, "expires_at": expires_at, "activation_permitted": False}


def preflight_dispatch(
    c: sqlite3.Connection,
    *,
    pilot_id: str,
    plan_id: str,
    owner: PlatformPrincipal,
    security: PlatformPrincipal,
) -> dict[str, Any]:
    _require_distinct_principals(owner, security)
    if c.in_transaction:
        raise DispatchDenied("open transaction exists")
    bundle = load_dispatch_bundle(c, pilot_id=pilot_id, plan_id=plan_id)
    return _redact({
        "mode": "preflight",
        "ok": True,
        "pilot_id": pilot_id,
        "plan_id": plan_id,
        "tenant_id": bundle["tenant_id"],
        "activation_id": bundle["activation_id"],
        "ceremony_receipt_id": bundle["ceremony_receipt_id"],
        "manifest_hash": bundle["manifest_hash"],
        "destination_hash": bundle["destination_hash"],
        "payload_hash": bundle["payload_hash"],
        "guardian_context_hash": bundle["guardian_context_hash"],
        "policy_hash": bundle["policy_hash"],
        "signing_key_id": bundle["signing_key_id"],
        "activation_permitted": False,
        "webhook_submitted": False,
        "activated": False,
        "production_provider": type(get_provider(get_adapter(ADAPTER_ID))).__name__,
    })


def issue_dispatch_confirmation(
    c: sqlite3.Connection,
    *,
    pilot_id: str,
    plan_id: str,
    owner: PlatformPrincipal,
    security: PlatformPrincipal,
) -> dict[str, Any]:
    _require_distinct_principals(owner, security)
    if c.in_transaction:
        raise DispatchDenied("open transaction exists")
    bundle = load_dispatch_bundle(c, pilot_id=pilot_id, plan_id=plan_id)
    evidence_hash = _context_binding(bundle, owner_actor_id=None, security_actor_id=None)
    roles = _require_fresh_approvals(c, bundle, evidence_hash)
    if owner.actor_id != roles["platform_owner"] or security.actor_id != roles["security_operator"]:
        raise DispatchDenied("confirmation issuers must match stored approvers")
    context_hash = _context_binding(
        bundle, owner_actor_id=owner.actor_id, security_actor_id=security.actor_id
    )
    token = secrets.token_urlsafe(32)
    token_hash = _hash_confirmation(token, context_hash)
    confirmation_id = str(uuid.uuid4())
    from datetime import timedelta
    expires_at = _iso(_now() + timedelta(minutes=CONFIRM_TTL_MINUTES))
    try:
        c.execute("BEGIN IMMEDIATE")
        c.execute(
            """INSERT INTO execution_pilot_dispatch_confirmations(
                confirmation_id,pilot_id,tenant_id,plan_id,activation_id,token_hash,context_hash,
                owner_actor_id,security_actor_id,expires_at,consumed_at,created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,NULL,?)""",
            (
                confirmation_id, pilot_id, bundle["tenant_id"], plan_id, bundle["activation_id"],
                token_hash, context_hash, owner.actor_id, security.actor_id, expires_at, _iso(),
            ),
        )
        _ops_audit(
            c, tenant_id=bundle["tenant_id"], actor_id=owner.actor_id,
            event="pilot_dispatch_confirmation_issued", pilot_id=pilot_id,
            detail={"confirmation_id": confirmation_id},
        )
        c.commit()
    except Exception:
        try:
            c.rollback()
        except sqlite3.Error:
            pass
        raise
    return {
        "confirmation_id": confirmation_id,
        "confirmation_token": token,
        "expires_at": expires_at,
        "activated": False,
        "webhook_submitted": False,
    }


def _consume_confirmation(
    c: sqlite3.Connection,
    *,
    token: str,
    bundle: dict[str, Any],
    owner: PlatformPrincipal,
    security: PlatformPrincipal,
) -> str:
    context_hash = _context_binding(
        bundle, owner_actor_id=owner.actor_id, security_actor_id=security.actor_id
    )
    digest = _hash_confirmation(token, context_hash)
    row = c.execute(
        "SELECT * FROM execution_pilot_dispatch_confirmations WHERE token_hash=? AND pilot_id=? AND plan_id=?",
        (digest, bundle["pilot_id"], bundle["plan_id"]),
    ).fetchone()
    if row is None:
        raise DispatchDenied("dispatch confirmation is invalid")
    if row["consumed_at"]:
        raise DispatchDenied("dispatch confirmation has already been consumed")
    expires = _parse_iso(row["expires_at"])
    if expires is None or expires <= _now():
        raise DispatchDenied("dispatch confirmation is expired")
    if row["context_hash"] != context_hash:
        raise DispatchDenied("dispatch confirmation is not bound to current evidence")
    if row["owner_actor_id"] != owner.actor_id or row["security_actor_id"] != security.actor_id:
        raise DispatchDenied("confirmation actors do not match stored approvers")
    marked = c.execute(
        """UPDATE execution_pilot_dispatch_confirmations
           SET consumed_at=? WHERE confirmation_id=? AND consumed_at IS NULL""",
        (_iso(), row["confirmation_id"]),
    ).rowcount
    if marked != 1:
        raise DispatchDenied("dispatch confirmation could not be consumed")
    return row["confirmation_id"]


def _close_authority(c: sqlite3.Connection, bundle: dict[str, Any], status: str) -> None:
    now = _iso()
    c.execute(
        "UPDATE execution_live_grants SET enabled=0, updated_at=? WHERE tenant_id=? AND adapter_id=? AND action=? AND env=?",
        (now, bundle["tenant_id"], ADAPTER_ID, ACTION, ACTIVATION_ENV),
    )
    c.execute(
        "DELETE FROM execution_destination_allowlist WHERE tenant_id=? AND adapter_id=? AND destination_hash=?",
        (bundle["tenant_id"], ADAPTER_ID, bundle["destination_hash"]),
    )
    c.execute(
        "UPDATE execution_pilot_activations SET status=? WHERE activation_id=? AND status='ACTIVE'",
        (status, bundle["activation_id"]),
    )


def execute_once(
    c: sqlite3.Connection,
    *,
    pilot_id: str,
    plan_id: str,
    owner: PlatformPrincipal,
    security: PlatformPrincipal,
    confirmation_token: str,
    plan_confirmation_token: str,
    transport: Any | None = None,
    resolver: Any | None = None,
    _commit_claim=None,
    **rejected: Any,
) -> dict[str, Any]:
    """Claim quota and close authority, then make exactly one production submit call."""
    _assert_no_caller_substitutes(**rejected)
    _require_distinct_principals(owner, security)
    if not (confirmation_token or "").strip() or confirmation_token.strip().lower() in {"yes", "y", "true", "1", "confirm"}:
        raise DispatchDenied("a random single-use dispatch confirmation is required")
    if c.in_transaction:
        raise DispatchDenied("open transaction exists")
    replay = _authorised_replay(c, pilot_id=pilot_id, plan_id=plan_id, owner=owner, security=security)
    if replay is not None:
        return replay
    bundle = load_dispatch_bundle(c, pilot_id=pilot_id, plan_id=plan_id)
    evidence_hash = _context_binding(bundle, owner_actor_id=None, security_actor_id=None)
    roles = _require_fresh_approvals(c, bundle, evidence_hash)
    if owner.actor_id != roles["platform_owner"] or security.actor_id != roles["security_operator"]:
        raise DispatchDenied("executing principals must match stored approvers")

    consumed: dict[str, str] = {}

    def after_claim_writes() -> None:
        live_roles = _require_fresh_approvals(c, bundle, evidence_hash)
        if owner.actor_id != live_roles["platform_owner"] or security.actor_id != live_roles["security_operator"]:
            raise DispatchDenied("dispatch approvals changed before claim")
        consumed["confirmation_id"] = _consume_confirmation(
            c, token=confirmation_token, bundle=bundle, owner=owner, security=security
        )
        _close_authority(c, bundle, "SUBMITTING")
        _ops_audit(
            c, tenant_id=bundle["tenant_id"], actor_id=owner.actor_id,
            event="pilot_dispatch_claimed", pilot_id=pilot_id,
            detail={"plan_id": plan_id, "activation_id": bundle["activation_id"]},
        )

    try:
        result = submit_production_pilot(
            c,
            tenant_id=bundle["tenant_id"],
            user_id=bundle["plan_user_id"],
            plan_id=plan_id,
            confirmation_token=plan_confirmation_token,
            role="owner",
            transport=transport,
            resolver=resolver,
            _after_claim_writes=after_claim_writes,
            _commit_claim=_commit_claim or _commit_dispatch,
        )
    except (ProductionPilotDenied, ProductionUncertain, ActivationDenied, CeremonyDenied) as exc:
        raise DispatchDenied(str(exc)) from exc

    state = result.get("state")
    if result.get("idempotent_replay"):
        return _redact({**result, "provider_calls": 0, "webhook_submitted": False, "activated": False})

    close_status = {
        "EXECUTED": "COMPLETED",
        "EXECUTED_AFTER_CANCEL_REQUEST": "COMPLETED",
        "FAILED": "FAILED",
        "UNCERTAIN": "UNCERTAIN",
    }.get(state, "SUSPENDED")
    if c.in_transaction:
        c.rollback()
    try:
        c.execute("BEGIN IMMEDIATE")
        _close_authority(c, bundle, close_status)
        detail = _redact({
            "receipt_id": str(uuid.uuid4()),
            "mode": "execute-once",
            "pilot_id": pilot_id,
            "plan_id": plan_id,
            "tenant_id": bundle["tenant_id"],
            "activation_id": bundle["activation_id"],
            "attempt_id": result.get("attempt_id"),
            "confirmation_id": consumed.get("confirmation_id"),
            "status": close_status,
            "state": state,
            "provider_calls": 0 if result.get("idempotent_replay") else 1,
            "webhook_submitted": False,
            "activated": False,
        })
        c.execute(
            """INSERT INTO execution_pilot_dispatch_receipts(
                receipt_id,pilot_id,tenant_id,activation_id,plan_id,attempt_id,
                owner_actor_id,security_actor_id,status,mode,detail_json,created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                detail["receipt_id"], pilot_id, bundle["tenant_id"], bundle["activation_id"],
                plan_id, result.get("attempt_id"), owner.actor_id, security.actor_id,
                close_status, "execute-once", json.dumps(detail), _iso(),
            ),
        )
        c.commit()
    except Exception:
        try:
            c.rollback()
        except sqlite3.Error:
            pass
        raise
    out = dict(result)
    out.update(detail)
    out["provider_calls"] = 0 if result.get("idempotent_replay") else 1
    return _redact(out)


def _authorised_replay(
    c: sqlite3.Connection,
    *,
    pilot_id: str,
    plan_id: str,
    owner: PlatformPrincipal,
    security: PlatformPrincipal,
) -> dict[str, Any] | None:
    prep = c.execute("SELECT * FROM execution_pilot_preparations WHERE pilot_id=?", (pilot_id,)).fetchone()
    if prep is None:
        raise DispatchDenied("pilot preparation not found")
    act = c.execute(
        "SELECT * FROM execution_pilot_activations WHERE pilot_id=? AND tenant_id=?",
        (pilot_id, prep["tenant_id"]),
    ).fetchone()
    if act is None:
        raise DispatchDenied("activation not found")
    plan = c.execute(
        "SELECT * FROM execution_plans WHERE id=? AND tenant_id=?",
        (plan_id, prep["tenant_id"]),
    ).fetchone()
    if plan is None:
        raise DispatchDenied("execution plan not found")
    receipt = c.execute(
        """SELECT * FROM execution_pilot_dispatch_receipts
           WHERE pilot_id=? AND tenant_id=? AND plan_id=? AND activation_id=? AND mode='execute-once'
           ORDER BY created_at DESC LIMIT 1""",
        (pilot_id, prep["tenant_id"], plan_id, act["activation_id"]),
    ).fetchone()
    if receipt is None:
        return None
    if receipt["owner_actor_id"] != owner.actor_id or receipt["security_actor_id"] != security.actor_id:
        raise DispatchDenied("replay is not bound to the original authorised principals")
    attempt = c.execute(
        "SELECT * FROM execution_attempts WHERE id=? AND tenant_id=? AND plan_id=?",
        (receipt["attempt_id"], prep["tenant_id"], plan_id),
    ).fetchone()
    if attempt is None:
        raise DispatchDenied("original dispatch attempt is missing")
    return _redact({
        "attempt_id": attempt["id"],
        "state": attempt["state"],
        "idempotent_replay": True,
        "receipt_id": receipt["receipt_id"],
        "pilot_id": pilot_id,
        "plan_id": plan_id,
        "activation_id": act["activation_id"],
        "provider_calls": 0,
        "webhook_submitted": False,
        "activated": False,
    })


def dispatch_status(
    c: sqlite3.Connection,
    *,
    pilot_id: str,
    plan_id: str,
    principal: PlatformPrincipal,
) -> dict[str, Any]:
    _require_principal(principal)
    if c.in_transaction:
        raise DispatchDenied("open transaction exists")
    prep = c.execute("SELECT * FROM execution_pilot_preparations WHERE pilot_id=?", (pilot_id,)).fetchone()
    if prep is None:
        raise DispatchDenied("pilot preparation not found")
    act = c.execute(
        "SELECT status, activation_id, tenant_id FROM execution_pilot_activations WHERE pilot_id=? AND tenant_id=?",
        (pilot_id, prep["tenant_id"]),
    ).fetchone()
    plan = c.execute(
        "SELECT id FROM execution_plans WHERE id=? AND tenant_id=?",
        (plan_id, prep["tenant_id"]),
    ).fetchone()
    if plan is None:
        raise DispatchDenied("execution plan is not bound to this pilot tenant")
    attempt = None
    if act is not None:
        attempt = c.execute(
            "SELECT id, state FROM execution_attempts WHERE tenant_id=? AND plan_id=?",
            (prep["tenant_id"], plan_id),
        ).fetchone()
    grant = c.execute(
        "SELECT enabled FROM execution_live_grants WHERE tenant_id=? AND enabled=1",
        (prep["tenant_id"],),
    ).fetchone()
    return _redact({
        "mode": "status",
        "pilot_id": pilot_id,
        "plan_id": plan_id,
        "activation_status": act["status"] if act else "absent",
        "activation_id": act["activation_id"] if act else None,
        "attempt_id": attempt["id"] if attempt else None,
        "attempt_state": attempt["state"] if attempt else None,
        "grant_enabled": bool(grant),
        "activation_permitted": False,
        "webhook_submitted": False,
        "production_provider": type(get_provider(get_adapter(ADAPTER_ID))).__name__,
    })


def closeout_dispatch(
    c: sqlite3.Connection,
    *,
    pilot_id: str,
    plan_id: str,
    principal: PlatformPrincipal,
    decision: str | None = None,
) -> dict[str, Any]:
    _require_principal(principal)
    act = c.execute("SELECT * FROM execution_pilot_activations WHERE pilot_id=?", (pilot_id,)).fetchone()
    if act is None:
        raise DispatchDenied("activation not found")
    attempt = c.execute("SELECT * FROM execution_attempts WHERE plan_id=?", (plan_id,)).fetchone()
    if attempt is not None and attempt["state"] == "UNCERTAIN":
        if not decision:
            raise DispatchDenied("UNCERTAIN closeout requires reconciliation decision")
        record_reconciliation(
            c, principal=principal, tenant_id=act["tenant_id"],
            attempt_id=attempt["id"], decision=decision,
        )
    else:
        suspend_pilot(c, pilot_id=pilot_id, principal=principal, reason="stage4f-closeout")
    return dispatch_status(c, pilot_id=pilot_id, plan_id=plan_id, principal=principal)


def abort_dispatch(
    c: sqlite3.Connection,
    *,
    pilot_id: str,
    principal: PlatformPrincipal,
    reason: str = "operator-abort",
) -> dict[str, Any]:
    _require_principal(principal)
    out = suspend_pilot(c, pilot_id=pilot_id, principal=principal, reason=reason)
    out["aborted"] = True
    out["webhook_submitted"] = False
    out["evidence_preserved"] = True
    return _redact(out)


def dispatch_default_off() -> dict[str, Any]:
    return {
        "production_provider": type(get_provider(get_adapter(ADAPTER_ID))).__name__,
        "external_execution": bool((os.getenv(PILOT_SECRET_ENV) and False) or (os.getenv("ZORVIAN_EXTERNAL_EXECUTION") or "").strip()),
        "activated": False,
        "webhook_submitted": False,
        "closed_provider": isinstance(get_provider(get_adapter(ADAPTER_ID)), ClosedProvider),
    }
