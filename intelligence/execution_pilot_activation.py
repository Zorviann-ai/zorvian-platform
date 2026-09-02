"""Phase 3 Stage 4C1 — activation control plane. Switched off by default.

Merge and bootstrap never activate a tenant. There is no HTTP activation route.
Platform authority is resolved only from protected offline operator configuration.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from intelligence.execution import _iso, _now, _parse_iso
from intelligence.execution_adapters import get_adapter
from intelligence.execution_live import (
    _global_kill_active,
    _grant_enabled,
    _tenant_kill_active,
    set_kill_switch,
)
from intelligence.execution_pilot_ops import (
    ACTION,
    ADAPTER_ID,
    PLATFORM_ROLES,
    PilotOpsDenied,
    _ops_audit,
    lookup_guardian_evidence,
)
from intelligence.execution_production_webhook import PILOT_KEY_ID_ENV, PILOT_SECRET_ENV, circuit_open
from intelligence.execution_providers import get_provider
from intelligence.guardian import (
    GUARDIAN_POLICY_VERSION,
    PILOT_PURPOSE,
    canonical_context_hash,
    canonical_pilot_context,
    guardian_policy_hash,
    load_guardian_assessment,
)

MAX_WINDOW_MINUTES = 30
MAX_SUCCESSES = 1
MAX_CONCURRENT = 1
MAX_RETRIES = 0
CHALLENGE_TTL_MINUTES = 10
ACTIVATION_ENV = "prod"
OWNER_IDS_ENV = "ZORVIAN_PLATFORM_OWNER_IDS"
SECURITY_IDS_ENV = "ZORVIAN_SECURITY_OPERATOR_IDS"


class ActivationDenied(PilotOpsDenied):
    """Stage 4C1 activation ceremony denied."""


@dataclass(frozen=True)
class PlatformPrincipal:
    actor_id: str
    role: str
    source: str = "offline_operator"


def _begin_immediate(c: sqlite3.Connection) -> None:
    c.execute("BEGIN IMMEDIATE")


def _commit_activation_claim(c: sqlite3.Connection) -> None:
    c.execute("COMMIT")


def _rollback_quietly(c: sqlite3.Connection) -> None:
    try:
        c.execute("ROLLBACK")
    except sqlite3.Error:
        try:
            c.rollback()
        except sqlite3.Error:
            pass


def load_offline_platform_principal(*, actor_id: str, requested_role: str) -> PlatformPrincipal:
    actor = (actor_id or "").strip()
    role = (requested_role or "").strip()
    if not actor or role not in PLATFORM_ROLES:
        raise ActivationDenied("platform principal is not approved")
    owners = {x.strip() for x in (os.getenv(OWNER_IDS_ENV) or "").split(",") if x.strip()}
    secs = {x.strip() for x in (os.getenv(SECURITY_IDS_ENV) or "").split(",") if x.strip()}
    if role == "platform_owner":
        if actor not in owners:
            raise ActivationDenied("actor is not an approved platform_owner")
        return PlatformPrincipal(actor_id=actor, role="platform_owner")
    if actor not in secs:
        raise ActivationDenied("actor is not an approved security_operator")
    return PlatformPrincipal(actor_id=actor, role="security_operator")


def _require_principal(principal: PlatformPrincipal, expected_role: str | None = None) -> None:
    if not isinstance(principal, PlatformPrincipal):
        raise ActivationDenied("trusted PlatformPrincipal is required")
    if principal.source != "offline_operator" or principal.role not in PLATFORM_ROLES:
        raise ActivationDenied("platform principal is not trusted")
    approved = load_offline_platform_principal(actor_id=principal.actor_id, requested_role=principal.role)
    if approved.actor_id != principal.actor_id or approved.role != principal.role:
        raise ActivationDenied("platform principal does not match approved configuration")
    if expected_role and principal.role != expected_role:
        raise ActivationDenied(f"platform principal must be {expected_role}")


def _hash_nonce(nonce: str) -> str:
    return hashlib.sha256((nonce or "").encode("utf-8")).hexdigest()


def _secret_configured(signing_key_id: str) -> bool:
    env_key = (os.getenv(PILOT_KEY_ID_ENV) or "").strip()
    secret = os.getenv(PILOT_SECRET_ENV) or ""
    return bool(env_key and env_key == signing_key_id and secret.strip())


def ensure_stage4c1_schema(c: sqlite3.Connection) -> None:
    """Controlled bootstrap only. Do not call from preflight or activate."""
    from intelligence.execution_pilot_ops import ensure_stage4b_schema
    ensure_stage4b_schema(c)
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS execution_pilot_platform_approvals(
            id TEXT PRIMARY KEY,
            pilot_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            role TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            decision TEXT NOT NULL,
            note TEXT,
            manifest_hash TEXT NOT NULL,
            guardian_context_hash TEXT NOT NULL,
            policy_hash TEXT NOT NULL,
            evidence_expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    for stmt in (
        "ALTER TABLE execution_pilot_platform_approvals ADD COLUMN manifest_hash TEXT",
        "ALTER TABLE execution_pilot_platform_approvals ADD COLUMN guardian_context_hash TEXT",
        "ALTER TABLE execution_pilot_platform_approvals ADD COLUMN policy_hash TEXT",
        "ALTER TABLE execution_pilot_platform_approvals ADD COLUMN evidence_expires_at TEXT",
    ):
        try:
            c.execute(stmt)
        except sqlite3.OperationalError:
            pass
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_pilot_platform_approval_role ON execution_pilot_platform_approvals(pilot_id, role)")
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_pilot_platform_approval_actor ON execution_pilot_platform_approvals(pilot_id, actor_id)")
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS execution_pilot_activation_challenges(
            challenge_id TEXT PRIMARY KEY,
            pilot_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            nonce_hash TEXT NOT NULL UNIQUE,
            manifest_hash TEXT NOT NULL,
            guardian_context_hash TEXT NOT NULL,
            owner_actor_id TEXT NOT NULL,
            security_actor_id TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            consumed_at TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    try:
        c.execute("ALTER TABLE execution_pilot_activation_challenges ADD COLUMN guardian_context_hash TEXT")
    except sqlite3.OperationalError:
        pass
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS execution_pilot_activations(
            activation_id TEXT PRIMARY KEY,
            pilot_id TEXT NOT NULL UNIQUE,
            tenant_id TEXT NOT NULL,
            adapter_id TEXT NOT NULL,
            destination_hash TEXT NOT NULL,
            manifest_hash TEXT NOT NULL,
            signing_key_id TEXT NOT NULL,
            platform_owner_id TEXT NOT NULL,
            security_operator_id TEXT NOT NULL,
            challenge_id TEXT NOT NULL,
            activated_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            max_successes INTEGER NOT NULL,
            max_concurrent INTEGER NOT NULL,
            max_retries INTEGER NOT NULL,
            successes_claimed INTEGER NOT NULL DEFAULT 0,
            concurrent_claimed INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    for stmt in (
        "ALTER TABLE execution_pilot_activations ADD COLUMN successes_claimed INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE execution_pilot_activations ADD COLUMN concurrent_claimed INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE execution_pilot_activations ADD COLUMN guardian_assessment_id TEXT",
        "ALTER TABLE execution_pilot_activations ADD COLUMN guardian_context_hash TEXT",
        "ALTER TABLE execution_pilot_activations ADD COLUMN policy_version TEXT",
        "ALTER TABLE execution_pilot_activations ADD COLUMN policy_hash TEXT",
    ):
        try:
            c.execute(stmt)
        except sqlite3.OperationalError:
            pass
    c.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS ux_one_active_pilot_per_tenant_adapter
        ON execution_pilot_activations(tenant_id, adapter_id)
        WHERE status='ACTIVE'
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS execution_pilot_preflight_audit(
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            pilot_id TEXT,
            event TEXT NOT NULL,
            detail_json TEXT,
            created_at TEXT NOT NULL
        )
        """
    )


def down_migrate_stage4c1(c: sqlite3.Connection) -> None:
    now = _iso()
    c.execute("UPDATE execution_live_grants SET enabled=0, updated_at=? WHERE adapter_id=?", (now, ADAPTER_ID))
    c.execute("DELETE FROM execution_destination_allowlist WHERE adapter_id=?", (ADAPTER_ID,))
    set_kill_switch(c, scope="global", enabled=True, reason="stage4c1-down", actor_id="system")
    tenants = c.execute("SELECT DISTINCT tenant_id FROM execution_pilot_preparations").fetchall()
    for row in tenants:
        set_kill_switch(
            c,
            scope="tenant_adapter",
            enabled=True,
            reason="stage4c1-down",
            actor_id="system",
            tenant_id=row["tenant_id"],
            adapter_id=ADAPTER_ID,
        )
    c.execute(
        """UPDATE execution_pilot_preparations
           SET status=CASE WHEN status='ACTIVE' THEN 'SUSPENDED' ELSE status END, updated_at=?
           WHERE adapter_id=?""",
        (now, ADAPTER_ID),
    )
    c.execute("UPDATE execution_pilot_activations SET status='SUSPENDED' WHERE status='ACTIVE'")


def _load_prep_any(c: sqlite3.Connection, pilot_id: str):
    row = c.execute("SELECT * FROM execution_pilot_preparations WHERE pilot_id=?", (pilot_id,)).fetchone()
    if row is None:
        raise ActivationDenied("pilot preparation not found")
    return row


def _read_current_hashes(c: sqlite3.Connection, pilot_id: str) -> dict[str, Any]:
    prep = _load_prep_any(c, pilot_id)
    bind = c.execute(
        """SELECT * FROM execution_pilot_guardian_bindings
           WHERE pilot_id=? AND tenant_id=? ORDER BY created_at DESC LIMIT 1""",
        (pilot_id, prep["tenant_id"]),
    ).fetchone()
    assessment = dict(load_guardian_assessment(c, bind["guardian_assessment_id"])) if bind else {}
    expected = canonical_pilot_context(
        {
            "purpose": PILOT_PURPOSE,
            "pilot_id": pilot_id,
            "tenant_id": prep["tenant_id"],
            "requesting_user_id": prep["proposer_id"],
            "adapter_id": ADAPTER_ID,
            "action": ACTION,
            "destination_hash": prep["destination_hash"],
            "manifest_hash": prep["manifest_hash"],
            "policy_version": GUARDIAN_POLICY_VERSION,
            "policy_hash": guardian_policy_hash(),
            "consequential_action": True,
            "expiry": assessment.get("expires_at"),
        }
    )
    return {
        "prep": prep,
        "tenant_id": prep["tenant_id"],
        "assessment": assessment,
        "bind": bind,
        "context_hash": canonical_context_hash(expected),
        "policy_hash": guardian_policy_hash(),
        "expires_at": assessment.get("expires_at"),
    }


def _verify_manifest_readonly(prep) -> None:
    from intelligence.execution_pilot_ops import _canonical_manifest
    payload = json.loads(prep["manifest_json"])
    _, digest = _canonical_manifest(payload)
    if digest != prep["manifest_hash"]:
        raise ActivationDenied("manifest hash mismatch")
    if payload.get("adapter_id") != ADAPTER_ID:
        raise ActivationDenied("manifest adapter must be webhook.post")
    if payload.get("status") not in {"PREPARED"}:
        raise ActivationDenied("manifest status is not PREPARED")


def _current_evidence(c: sqlite3.Connection, pilot_id: str) -> dict[str, Any]:
    snap = _read_current_hashes(c, pilot_id)
    prep = snap["prep"]
    if prep["adapter_id"] != ADAPTER_ID or prep["action"] != ACTION:
        raise ActivationDenied("adapter/action is not webhook.post/post_webhook")
    _verify_manifest_readonly(prep)
    if not prep["approver_id"] or prep["approver_id"] == prep["proposer_id"]:
        raise ActivationDenied("two-person tenant approval is incomplete")
    if snap["bind"] is None:
        raise ActivationDenied("guardian binding is missing")
    assessment = snap["assessment"]
    if not assessment:
        raise ActivationDenied("guardian assessment is missing")
    expires = _parse_iso(assessment.get("expires_at"))
    if expires is None or expires <= _now():
        raise ActivationDenied("guardian assessment is expired")
    if str(assessment.get("decision") or "").upper() != "ALLOW" or not assessment.get("execution_allowed") or not assessment.get("consequential_action"):
        raise ActivationDenied("guardian assessment is not a consequential ALLOW")
    if (assessment.get("context_hash") or "") != snap["context_hash"]:
        raise ActivationDenied("guardian context hash does not match stored pilot")
    if (assessment.get("requesting_user_id") or "") != prep["proposer_id"]:
        raise ActivationDenied("guardian requesting user does not match proposer")
    lookup = lookup_guardian_evidence(
        c,
        pilot_id=pilot_id,
        tenant_id=snap["tenant_id"],
        destination_hash_value=prep["destination_hash"],
        manifest_hash=prep["manifest_hash"],
    )
    if lookup["status"] != "PASS":
        raise ActivationDenied(f"guardian readiness {lookup['status']}")
    return snap


def _invalidate_stale_approvals(c: sqlite3.Connection, pilot_id: str, snap: dict[str, Any]) -> int:
    cur = c.execute(
        """DELETE FROM execution_pilot_platform_approvals
           WHERE pilot_id=? AND (
             COALESCE(manifest_hash,'') != ?
             OR COALESCE(guardian_context_hash,'') != ?
             OR COALESCE(policy_hash,'') != ?
           )""",
        (pilot_id, snap["prep"]["manifest_hash"], snap["context_hash"], snap["policy_hash"]),
    )
    return cur.rowcount


def record_platform_approval(
    c: sqlite3.Connection,
    *,
    pilot_id: str,
    principal: PlatformPrincipal,
    note: str = "",
) -> dict[str, Any]:
    _require_principal(principal)
    if c.in_transaction:
        raise ActivationDenied("open transaction exists")
    try:
        _begin_immediate(c)
        snap = _read_current_hashes(c, pilot_id)
        _invalidate_stale_approvals(c, pilot_id, snap)
        try:
            evidence = _current_evidence(c, pilot_id)
        except ActivationDenied:
            _commit_activation_claim(c)
            raise
        if principal.actor_id in {evidence["prep"]["proposer_id"], evidence["prep"]["approver_id"]}:
            raise ActivationDenied("tenant proposer/approver cannot supply a platform approval")
        c.execute(
            """INSERT INTO execution_pilot_platform_approvals(
                id,pilot_id,tenant_id,role,actor_id,decision,note,
                manifest_hash,guardian_context_hash,policy_hash,evidence_expires_at,created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                str(uuid.uuid4()), pilot_id, evidence["tenant_id"], principal.role, principal.actor_id,
                "approve", note, evidence["prep"]["manifest_hash"], evidence["context_hash"],
                evidence["policy_hash"], evidence["expires_at"], _iso(),
            ),
        )
        _ops_audit(
            c, tenant_id=evidence["tenant_id"], actor_id=principal.actor_id,
            event="pilot_platform_approved", pilot_id=pilot_id, detail={"role": principal.role},
        )
        _commit_activation_claim(c)
    except sqlite3.IntegrityError as exc:
        _rollback_quietly(c)
        raise ActivationDenied("platform approval uniqueness conflict") from exc
    except Exception:
        _rollback_quietly(c)
        raise
    return {"ok": True, "pilot_id": pilot_id, "role": principal.role, "activated": False}


def _platform_approvals_readonly(c: sqlite3.Connection, pilot_id: str, snap: dict[str, Any]) -> dict[str, str]:
    rows = c.execute(
        """SELECT role, actor_id FROM execution_pilot_platform_approvals
           WHERE pilot_id=? AND decision='approve'
             AND COALESCE(manifest_hash,'')=? AND COALESCE(guardian_context_hash,'')=? AND COALESCE(policy_hash,'')=?""",
        (pilot_id, snap["prep"]["manifest_hash"], snap["context_hash"], snap["policy_hash"]),
    ).fetchall()
    return {r["role"]: r["actor_id"] for r in rows}


def _revalidate_for_ceremony(c: sqlite3.Connection, pilot_id: str) -> dict[str, Any]:
    evidence = _current_evidence(c, pilot_id)
    prep = evidence["prep"]
    if prep["status"] not in {"PREPARED", "ACTIVE"}:
        raise ActivationDenied(f"pilot status {prep['status']} cannot be activated")
    if not _secret_configured(prep["signing_key_id"]):
        raise ActivationDenied("signing secret is not configured for the stored key id")
    if _global_kill_active(c) or _tenant_kill_active(c, evidence["tenant_id"], ADAPTER_ID):
        raise ActivationDenied("kill switch is active")
    if circuit_open(c, evidence["tenant_id"], ADAPTER_ID):
        raise ActivationDenied("circuit is open")
    approvals = _platform_approvals_readonly(c, pilot_id, evidence)
    owner_id = approvals.get("platform_owner")
    security_id = approvals.get("security_operator")
    if not owner_id or not security_id:
        raise ActivationDenied("both platform_owner and security_operator approvals are required")
    if owner_id == security_id:
        raise ActivationDenied("platform approvals must be from different actors")
    evidence["owner_id"] = owner_id
    evidence["security_id"] = security_id
    return evidence


def issue_activation_challenge(
    c: sqlite3.Connection,
    *,
    pilot_id: str,
    owner: PlatformPrincipal,
    security: PlatformPrincipal,
) -> dict[str, Any]:
    _require_principal(owner, "platform_owner")
    _require_principal(security, "security_operator")
    if owner.actor_id == security.actor_id:
        raise ActivationDenied("challenge approvers must be different actors")
    if c.in_transaction:
        raise ActivationDenied("open transaction exists")
    try:
        _begin_immediate(c)
        evidence = _revalidate_for_ceremony(c, pilot_id)
        if evidence["owner_id"] != owner.actor_id or evidence["security_id"] != security.actor_id:
            raise ActivationDenied("challenge actors do not match recorded platform approvals")
        nonce = secrets.token_urlsafe(32)
        challenge_id = str(uuid.uuid4())
        expires = _iso(_now() + timedelta(minutes=CHALLENGE_TTL_MINUTES))
        c.execute(
            """INSERT INTO execution_pilot_activation_challenges(
                challenge_id,pilot_id,tenant_id,nonce_hash,manifest_hash,guardian_context_hash,
                owner_actor_id,security_actor_id,expires_at,consumed_at,created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,NULL,?)""",
            (
                challenge_id, pilot_id, evidence["tenant_id"], _hash_nonce(nonce),
                evidence["prep"]["manifest_hash"], evidence["context_hash"],
                owner.actor_id, security.actor_id, expires, _iso(),
            ),
        )
        _ops_audit(
            c, tenant_id=evidence["tenant_id"], actor_id=owner.actor_id,
            event="pilot_activation_challenge_issued", pilot_id=pilot_id,
            detail={"challenge_id": challenge_id},
        )
        _commit_activation_claim(c)
    except Exception:
        _rollback_quietly(c)
        raise
    return {
        "challenge_id": challenge_id,
        "nonce": nonce,
        "expires_at": expires,
        "activated": False,
        "external_execution_enabled": False,
    }


def _consume_challenge(c: sqlite3.Connection, *, pilot_id: str, nonce: str, evidence: dict[str, Any]) -> str:
    digest = _hash_nonce(nonce)
    row = c.execute(
        "SELECT * FROM execution_pilot_activation_challenges WHERE nonce_hash=? AND pilot_id=?",
        (digest, pilot_id),
    ).fetchone()
    if row is None:
        raise ActivationDenied("activation challenge is invalid")
    if row["consumed_at"]:
        raise ActivationDenied("activation challenge has already been consumed")
    expires = _parse_iso(row["expires_at"])
    if expires is None or expires <= _now():
        raise ActivationDenied("activation challenge is expired")
    if row["manifest_hash"] != evidence["prep"]["manifest_hash"]:
        raise ActivationDenied("activation challenge manifest hash mismatch")
    if (row["guardian_context_hash"] or "") != evidence["context_hash"]:
        raise ActivationDenied("activation challenge guardian context mismatch")
    if row["owner_actor_id"] != evidence["owner_id"] or row["security_actor_id"] != evidence["security_id"]:
        raise ActivationDenied("activation challenge actor mismatch")
    cur = c.execute(
        """UPDATE execution_pilot_activation_challenges SET consumed_at=?
           WHERE challenge_id=? AND consumed_at IS NULL""",
        (_iso(), row["challenge_id"]),
    )
    if cur.rowcount != 1:
        raise ActivationDenied("activation challenge consume raced")
    return row["challenge_id"]


def _same_ceremony_duplicate(c: sqlite3.Connection, *, existing, nonce: str, principal: PlatformPrincipal, evidence: dict[str, Any]) -> bool:
    digest = _hash_nonce(nonce)
    row = c.execute(
        """SELECT * FROM execution_pilot_activation_challenges
           WHERE challenge_id=? AND nonce_hash=? AND pilot_id=?""",
        (existing["challenge_id"], digest, existing["pilot_id"]),
    ).fetchone()
    if row is None:
        return False
    if principal.actor_id not in {existing["platform_owner_id"], existing["security_operator_id"]}:
        return False
    if existing["manifest_hash"] != evidence["prep"]["manifest_hash"]:
        return False
    if existing["destination_hash"] != evidence["prep"]["destination_hash"]:
        return False
    return True


def activate_pilot(
    c: sqlite3.Connection,
    *,
    pilot_id: str,
    principal: PlatformPrincipal,
    challenge_nonce: str,
    window_minutes: int = MAX_WINDOW_MINUTES,
    max_successes: int = MAX_SUCCESSES,
    max_concurrent: int = MAX_CONCURRENT,
    max_retries: int = MAX_RETRIES,
) -> dict[str, Any]:
    _require_principal(principal)
    if window_minutes > MAX_WINDOW_MINUTES or window_minutes < 1:
        raise ActivationDenied("activation window exceeds hard limit")
    if max_successes > MAX_SUCCESSES or max_successes < 1:
        raise ActivationDenied("success quota exceeds hard limit")
    if max_concurrent > MAX_CONCURRENT or max_concurrent < 1:
        raise ActivationDenied("concurrency exceeds hard limit")
    if max_retries != MAX_RETRIES:
        raise ActivationDenied("retries are not permitted")
    if c.in_transaction:
        raise ActivationDenied("open transaction exists")

    provider_calls = {"count": 0}
    try:
        _begin_immediate(c)
        evidence = _revalidate_for_ceremony(c, pilot_id)
        if principal.actor_id not in {evidence["owner_id"], evidence["security_id"]}:
            raise ActivationDenied("principal is not a recorded platform approver")
        existing = c.execute("SELECT * FROM execution_pilot_activations WHERE pilot_id=?", (pilot_id,)).fetchone()
        if existing is not None:
            if not _same_ceremony_duplicate(c, existing=existing, nonce=challenge_nonce, principal=principal, evidence=evidence):
                raise ActivationDenied("activation already exists for a different ceremony")
            _commit_activation_claim(c)
            out = _public_activation(dict(existing), duplicate=True)
            out["provider_calls"] = 0
            return out
        prep = evidence["prep"]
        challenge_id = _consume_challenge(c, pilot_id=pilot_id, nonce=challenge_nonce, evidence=evidence)
        now = _now()
        activated_at = _iso(now)
        expires_at = _iso(now + timedelta(minutes=window_minutes))
        activation_id = str(uuid.uuid4())
        c.execute(
            """INSERT OR IGNORE INTO execution_destination_allowlist(tenant_id,adapter_id,destination_hash,label,created_at)
               VALUES (?,?,?,?,?)""",
            (prep["tenant_id"], ADAPTER_ID, prep["destination_hash"], "stage4c1-pilot", activated_at),
        )
        c.execute(
            """INSERT INTO execution_live_grants(tenant_id,adapter_id,action,env,enabled,created_by,created_at,updated_at)
               VALUES (?,?,?,?,?,?,?,?)
               ON CONFLICT(tenant_id,adapter_id,action,env) DO UPDATE SET enabled=1, updated_at=excluded.updated_at""",
            (prep["tenant_id"], ADAPTER_ID, ACTION, ACTIVATION_ENV, 1, principal.actor_id, activated_at, activated_at),
        )
        marked = c.execute(
            """UPDATE execution_pilot_preparations
               SET status='ACTIVE', updated_at=? WHERE pilot_id=? AND tenant_id=? AND status='PREPARED'""",
            (activated_at, pilot_id, prep["tenant_id"]),
        ).rowcount
        if marked != 1:
            raise ActivationDenied("pilot could not be marked ACTIVE")
        c.execute(
            """INSERT INTO execution_pilot_activations(
                activation_id,pilot_id,tenant_id,adapter_id,destination_hash,manifest_hash,
                signing_key_id,platform_owner_id,security_operator_id,challenge_id,
                activated_at,expires_at,max_successes,max_concurrent,max_retries,
                successes_claimed,concurrent_claimed,status,created_at,
                guardian_assessment_id,guardian_context_hash,policy_version,policy_hash
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                activation_id, pilot_id, prep["tenant_id"], ADAPTER_ID, prep["destination_hash"],
                prep["manifest_hash"], prep["signing_key_id"], evidence["owner_id"], evidence["security_id"],
                challenge_id, activated_at, expires_at, max_successes, max_concurrent, max_retries,
                0, 0, "ACTIVE", activated_at,
                (evidence.get("assessment") or {}).get("guardian_assessment_id"),
                evidence.get("context_hash"),
                GUARDIAN_POLICY_VERSION,
                evidence.get("policy_hash") or guardian_policy_hash(),
            ),
        )
        _ops_audit(
            c, tenant_id=prep["tenant_id"], actor_id=principal.actor_id, event="pilot_activated",
            pilot_id=pilot_id, detail={"activation_id": activation_id, "provider_calls": 0},
        )
        _commit_activation_claim(c)
    except sqlite3.IntegrityError as exc:
        _rollback_quietly(c)
        raise ActivationDenied("only one ACTIVE pilot is permitted per tenant and adapter") from exc
    except Exception:
        _rollback_quietly(c)
        raise

    row = c.execute("SELECT * FROM execution_pilot_activations WHERE activation_id=?", (activation_id,)).fetchone()
    out = _public_activation(dict(row), duplicate=False)
    out["provider_calls"] = provider_calls["count"]
    out["production_provider"] = type(get_provider(get_adapter(ADAPTER_ID))).__name__
    return out


def _public_activation(row: dict[str, Any], *, duplicate: bool) -> dict[str, Any]:
    return {
        "activation_id": row["activation_id"],
        "pilot_id": row["pilot_id"],
        "tenant_id": row["tenant_id"],
        "status": row["status"],
        "activated_at": row["activated_at"],
        "expires_at": row["expires_at"],
        "max_successes": row["max_successes"],
        "max_concurrent": row["max_concurrent"],
        "max_retries": row["max_retries"],
        "duplicate": duplicate,
        "destination": None,
        "signing_secret": None,
        "nonce": None,
        "external_execution_enabled": False,
    }


def _close_activation(c: sqlite3.Connection, row, reason: str) -> None:
    now = _iso()
    c.execute(
        "UPDATE execution_live_grants SET enabled=0, updated_at=? WHERE tenant_id=? AND adapter_id=? AND action=? AND env=?",
        (now, row["tenant_id"], ADAPTER_ID, ACTION, ACTIVATION_ENV),
    )
    c.execute(
        "DELETE FROM execution_destination_allowlist WHERE tenant_id=? AND adapter_id=? AND destination_hash=?",
        (row["tenant_id"], ADAPTER_ID, row["destination_hash"]),
    )
    status = "EXPIRED" if reason == "expired" else "QUOTA_EXHAUSTED" if reason == "quota" else "SUSPENDED"
    c.execute("UPDATE execution_pilot_activations SET status=? WHERE activation_id=?", (status, row["activation_id"]))


def _rows_or_deny(c: sqlite3.Connection, *, tenant_id: str, adapter_id: str):
    try:
        return c.execute(
            "SELECT * FROM execution_pilot_activations WHERE tenant_id=? AND adapter_id=?",
            (tenant_id, adapter_id),
        ).fetchall()
    except sqlite3.Error as exc:
        raise ActivationDenied("activation table unreadable") from exc


def _match_activation(rows, *, pilot_id=None, destination_hash=None, manifest_hash=None, signing_key_id=None, exact=False):
    if not rows:
        raise ActivationDenied("activation record is missing")
    active = [r for r in rows if r["status"] == "ACTIVE"]
    if not active:
        raise ActivationDenied("no ACTIVE activation")
    if len(active) > 1:
        raise ActivationDenied("ambiguous multiple ACTIVE activations")
    if exact or any(v is not None for v in (pilot_id, destination_hash, manifest_hash, signing_key_id)):
        matched = []
        for row in active:
            if pilot_id is not None and row["pilot_id"] != pilot_id:
                continue
            if destination_hash is not None and row["destination_hash"] != destination_hash:
                continue
            if manifest_hash is not None and row["manifest_hash"] != manifest_hash:
                continue
            if signing_key_id is not None and row["signing_key_id"] != signing_key_id:
                continue
            matched.append(row)
        if not matched:
            raise ActivationDenied("activation does not match stored pilot context")
        return matched[0]
    return active[0]


def _assert_activation_live(c: sqlite3.Connection, row, *, action: str) -> None:
    if action != ACTION:
        raise ActivationDenied("activation action mismatch")
    if row["adapter_id"] != ADAPTER_ID:
        raise ActivationDenied("activation adapter mismatch")
    expires = _parse_iso(row["expires_at"])
    if expires is None or expires <= _now():
        _close_activation(c, row, "expired")
        raise ActivationDenied("activation window has expired")
    if int(row["successes_claimed"] or 0) >= int(row["max_successes"] or MAX_SUCCESSES):
        _close_activation(c, row, "quota")
        raise ActivationDenied("activation success quota is exhausted")
    if _global_kill_active(c) or _tenant_kill_active(c, row["tenant_id"], row["adapter_id"]):
        raise ActivationDenied("kill switch is active")
    if circuit_open(c, row["tenant_id"], row["adapter_id"]):
        raise ActivationDenied("circuit is open")
    if not _grant_enabled(c, row["tenant_id"], row["adapter_id"], ACTION, ACTIVATION_ENV):
        raise ActivationDenied("corresponding live grant is missing or disabled")
    allow = c.execute(
        """SELECT 1 FROM execution_destination_allowlist
           WHERE tenant_id=? AND adapter_id=? AND destination_hash=?""",
        (row["tenant_id"], row["adapter_id"], row["destination_hash"]),
    ).fetchone()
    if allow is None:
        raise ActivationDenied("corresponding destination allowlist entry is missing")
    evidence = lookup_guardian_evidence(
        c,
        pilot_id=row["pilot_id"],
        tenant_id=row["tenant_id"],
        destination_hash_value=row["destination_hash"],
        manifest_hash=row["manifest_hash"],
    )
    if evidence["status"] != "PASS":
        raise ActivationDenied(f"guardian evidence {evidence['status']}")
    bind = c.execute(
        """SELECT guardian_assessment_id FROM execution_pilot_guardian_bindings
           WHERE pilot_id=? AND tenant_id=? ORDER BY created_at DESC LIMIT 1""",
        (row["pilot_id"], row["tenant_id"]),
    ).fetchone()
    stored_gid = row["guardian_assessment_id"] if "guardian_assessment_id" in row.keys() else None
    stored_ctx = row["guardian_context_hash"] if "guardian_context_hash" in row.keys() else None
    if stored_gid and bind and bind["guardian_assessment_id"] != stored_gid:
        raise ActivationDenied("guardian assessment id mismatch")
    if stored_ctx:
        assessment = load_guardian_assessment(c, bind["guardian_assessment_id"]) if bind else None
        if assessment is None or (dict(assessment).get("context_hash") or "") != stored_ctx:
            raise ActivationDenied("guardian context hash mismatch")
    if row["policy_version"] if "policy_version" in row.keys() else None:
        if row["policy_version"] not in {None, "", GUARDIAN_POLICY_VERSION}:
            raise ActivationDenied("guardian policy version mismatch")
    if row["policy_hash"] if "policy_hash" in row.keys() else None:
        if row["policy_hash"] not in {None, "", guardian_policy_hash()}:
            raise ActivationDenied("guardian policy hash mismatch")


def enforce_activation_for_runtime(
    c: sqlite3.Connection,
    *,
    tenant_id: str,
    adapter_id: str,
    action: str,
    pilot_id: str | None = None,
    destination_hash: str | None = None,
    manifest_hash: str | None = None,
    signing_key_id: str | None = None,
    exact: bool = False,
) -> dict[str, Any]:
    rows = _rows_or_deny(c, tenant_id=tenant_id, adapter_id=adapter_id)
    row = _match_activation(
        rows,
        pilot_id=pilot_id,
        destination_hash=destination_hash,
        manifest_hash=manifest_hash,
        signing_key_id=signing_key_id,
        exact=exact,
    )
    _assert_activation_live(c, row, action=action)
    return dict(row)


def claim_activation_success(
    c: sqlite3.Connection,
    *,
    tenant_id: str,
    adapter_id: str,
    action: str = ACTION,
    pilot_id: str | None = None,
    destination_hash: str | None = None,
    manifest_hash: str | None = None,
    signing_key_id: str | None = None,
    exact: bool = False,
) -> str:
    owned = False
    if not c.in_transaction:
        _begin_immediate(c)
        owned = True
    try:
        rows = _rows_or_deny(c, tenant_id=tenant_id, adapter_id=adapter_id)
        row = _match_activation(
            rows,
            pilot_id=pilot_id,
            destination_hash=destination_hash,
            manifest_hash=manifest_hash,
            signing_key_id=signing_key_id,
            exact=exact,
        )
        _assert_activation_live(c, row, action=action)
        cur = c.execute(
            """UPDATE execution_pilot_activations
               SET successes_claimed = successes_claimed + 1
               WHERE activation_id=? AND status='ACTIVE' AND successes_claimed < max_successes""",
            (row["activation_id"],),
        )
        if cur.rowcount != 1:
            if owned:
                _commit_activation_claim(c)
            raise ActivationDenied("activation success quota is exhausted")
        updated = c.execute("SELECT * FROM execution_pilot_activations WHERE activation_id=?", (row["activation_id"],)).fetchone()
        if int(updated["successes_claimed"]) >= int(updated["max_successes"]):
            c.execute(
                "UPDATE execution_pilot_activations SET status='QUOTA_EXHAUSTED' WHERE activation_id=?",
                (updated["activation_id"],),
            )
            grant_cur = c.execute(
                "UPDATE execution_live_grants SET enabled=0, updated_at=? WHERE tenant_id=? AND adapter_id=? AND action=? AND env=?",
                (_iso(), updated["tenant_id"], ADAPTER_ID, ACTION, ACTIVATION_ENV),
            )
            allow_cur = c.execute(
                "DELETE FROM execution_destination_allowlist WHERE tenant_id=? AND adapter_id=? AND destination_hash=?",
                (updated["tenant_id"], ADAPTER_ID, updated["destination_hash"]),
            )
            if grant_cur.rowcount < 1 or allow_cur.rowcount < 1:
                raise ActivationDenied("quota claim could not close grant and allowlist")
        if owned:
            _commit_activation_claim(c)
        return row["activation_id"]
    except ActivationDenied:
        if owned and c.in_transaction:
            try:
                _commit_activation_claim(c)
            except sqlite3.Error:
                _rollback_quietly(c)
        raise
    except Exception:
        if owned:
            _rollback_quietly(c)
        raise


def _suspend_pilot_locked(
    c: sqlite3.Connection,
    *,
    pilot_id: str,
    principal: PlatformPrincipal,
    reason: str,
) -> dict[str, Any]:
    """Apply suspension inside an already-open writer transaction."""
    _require_principal(principal)
    prep = _load_prep_any(c, pilot_id)
    stored_tenant = prep["tenant_id"]
    actor = principal.actor_id
    set_kill_switch(
        c, scope="tenant_adapter", enabled=True, reason=reason, actor_id=actor,
        tenant_id=stored_tenant, adapter_id=ADAPTER_ID,
    )
    c.execute(
        """UPDATE execution_live_grants SET enabled=0, updated_at=?
           WHERE tenant_id=? AND adapter_id=? AND action=? AND env=?""",
        (_iso(), stored_tenant, ADAPTER_ID, ACTION, ACTIVATION_ENV),
    )
    c.execute(
        """DELETE FROM execution_destination_allowlist
           WHERE tenant_id=? AND adapter_id=? AND destination_hash=?""",
        (stored_tenant, ADAPTER_ID, prep["destination_hash"]),
    )
    marked = c.execute(
        """UPDATE execution_pilot_preparations
           SET status='SUSPENDED', last_denial=?, updated_at=? WHERE pilot_id=?""",
        (reason, _iso(), pilot_id),
    ).rowcount
    if marked < 1:
        raise ActivationDenied("pilot preparation could not be suspended")
    c.execute("UPDATE execution_pilot_activations SET status='SUSPENDED' WHERE pilot_id=?", (pilot_id,))
    grant = c.execute(
        "SELECT enabled FROM execution_live_grants WHERE tenant_id=? AND adapter_id=? AND action=? AND env=?",
        (stored_tenant, ADAPTER_ID, ACTION, ACTIVATION_ENV),
    ).fetchone()
    allow = c.execute(
        "SELECT 1 FROM execution_destination_allowlist WHERE tenant_id=? AND adapter_id=? AND destination_hash=?",
        (stored_tenant, ADAPTER_ID, prep["destination_hash"]),
    ).fetchone()
    act = c.execute("SELECT status FROM execution_pilot_activations WHERE pilot_id=?", (pilot_id,)).fetchone()
    if grant is None or grant["enabled"] != 0 or allow is not None or act is None or act["status"] != "SUSPENDED":
        raise ActivationDenied("suspension could not close the exact pilot controls")
    _ops_audit(c, tenant_id=stored_tenant, actor_id=actor, event="pilot_suspended", pilot_id=pilot_id, detail={"reason": reason})
    return {"pilot_id": pilot_id, "status": "SUSPENDED", "external_execution_enabled": False, "evidence_preserved": True, "tenant_id": stored_tenant}


def suspend_pilot(
    c: sqlite3.Connection,
    *,
    pilot_id: str,
    principal: PlatformPrincipal,
    reason: str,
) -> dict[str, Any]:
    _require_principal(principal)
    if c.in_transaction:
        raise ActivationDenied("open transaction exists")
    try:
        _begin_immediate(c)
        out = _suspend_pilot_locked(c, pilot_id=pilot_id, principal=principal, reason=reason)
        _commit_activation_claim(c)
    except Exception:
        _rollback_quietly(c)
        raise
    return out


def preflight_activation(
    c: sqlite3.Connection,
    *,
    pilot_id: str,
    principal: PlatformPrincipal,
) -> dict[str, Any]:
    """SELECT-only except exactly one append-only preflight audit INSERT."""
    _require_principal(principal)
    try:
        evidence = _revalidate_for_ceremony(c, pilot_id)
        ok = True
        detail = "evidence complete"
        tenant_id = evidence["tenant_id"]
    except ActivationDenied as exc:
        ok = False
        detail = str(exc)
        try:
            tenant_id = _load_prep_any(c, pilot_id)["tenant_id"]
        except ActivationDenied:
            tenant_id = "unknown"
    c.execute(
        """INSERT INTO execution_pilot_preflight_audit(
            id,tenant_id,actor_id,pilot_id,event,detail_json,created_at
        ) VALUES (?,?,?,?,?,?,?)""",
        (str(uuid.uuid4()), tenant_id, principal.actor_id, pilot_id, "preflight", json.dumps({"ok": ok, "detail": detail}), _iso()),
    )
    return {
        "ok": ok,
        "detail": detail,
        "activated": False,
        "activation_permitted": False,
        "external_execution_enabled": False,
        "http_post": False,
    }


def classify_activation_state(c: sqlite3.Connection, *, tenant_id: str, pilot_id: str | None) -> str:
    if _global_kill_active(c) or (pilot_id and _tenant_kill_active(c, tenant_id, ADAPTER_ID)):
        return "killed"
    if not pilot_id:
        return "default_closed"
    act = c.execute("SELECT * FROM execution_pilot_activations WHERE pilot_id=?", (pilot_id,)).fetchone()
    if act and act["status"] == "SUSPENDED":
        return "suspended"
    if act and act["status"] == "EXPIRED":
        return "expired"
    if act and act["status"] == "QUOTA_EXHAUSTED":
        return "quota_exhausted"
    if act and act["status"] == "ACTIVE":
        expires = _parse_iso(act["expires_at"])
        if expires and expires <= _now():
            return "expired"
        if int(act["successes_claimed"] or 0) >= int(act["max_successes"] or 1):
            return "quota_exhausted"
        return "active"
    try:
        _revalidate_for_ceremony(c, pilot_id)
        return "ready_for_activation"
    except ActivationDenied as exc:
        msg = str(exc)
        if "platform_owner" in msg or "security_operator" in msg or "platform approvals" in msg:
            return "awaiting_platform_approvals"
        return "gates_incomplete"


def assert_no_http_activation_route() -> dict[str, Any]:
    from pathlib import Path
    src = Path("app_gate5.py").read_text()
    return {
        "stage4c_activation_route": "/api/execution/pilot/activate" in src or "/activate" in src,
        "external_execution_enabled": False,
    }
