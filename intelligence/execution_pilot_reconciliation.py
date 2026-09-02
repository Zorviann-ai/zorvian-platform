"""Phase 3 Stage 4C2 — production pilot reconciliation and observability.

Default production remains ClosedProvider. No public activation or reconcile route.
Reconciliation never calls a provider and never writes secrets.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from typing import Any

from intelligence.execution import _iso, _now, _parse_iso
from intelligence.execution_live import _global_kill_active, _grant_enabled, _tenant_kill_active
from intelligence.execution_pilot_activation import (
    ACTION,
    ACTIVATION_ENV,
    ADAPTER_ID,
    ActivationDenied,
    PlatformPrincipal,
    _close_activation,
    _require_principal,
    claim_activation_success,
    enforce_activation_for_runtime,
)
from intelligence.execution_pilot_ops import _ops_audit, lookup_guardian_evidence
from intelligence.execution_production_webhook import circuit_open, recover_stale_production
from intelligence.guardian import (
    GUARDIAN_POLICY_VERSION,
    guardian_policy_hash,
    load_guardian_assessment,
)


RECONCILE_DECISIONS = {"confirmed-success", "confirmed-failure", "unresolved"}


class ReconciliationDenied(ActivationDenied):
    """Stage 4C2 reconciliation or observability denied."""


def ensure_stage4c2_schema(c: sqlite3.Connection) -> None:
    """Controlled bootstrap only. Observability must not call this."""
    from intelligence.execution_pilot_activation import ensure_stage4c1_schema
    ensure_stage4c1_schema(c)
    for stmt in (
        "ALTER TABLE execution_pilot_activations ADD COLUMN guardian_assessment_id TEXT",
        "ALTER TABLE execution_pilot_activations ADD COLUMN guardian_context_hash TEXT",
        "ALTER TABLE execution_pilot_activations ADD COLUMN policy_version TEXT",
        "ALTER TABLE execution_pilot_activations ADD COLUMN policy_hash TEXT",
        "ALTER TABLE execution_attempts ADD COLUMN activation_id TEXT",
        "ALTER TABLE execution_attempts ADD COLUMN pilot_id TEXT",
        "ALTER TABLE execution_pilot_attempts ADD COLUMN activation_id TEXT",
        "ALTER TABLE execution_pilot_attempts ADD COLUMN pilot_id TEXT",
    ):
        try:
            c.execute(stmt)
        except sqlite3.OperationalError:
            pass
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS execution_pilot_reconciliations(
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            attempt_id TEXT NOT NULL,
            pilot_id TEXT,
            actor_id TEXT NOT NULL,
            role TEXT NOT NULL,
            decision TEXT NOT NULL,
            note TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS execution_pilot_closure_audit(
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            pilot_id TEXT,
            event TEXT NOT NULL,
            detail_json TEXT,
            created_at TEXT NOT NULL
        )
        """
    )


def _audit_closure(c: sqlite3.Connection, *, tenant_id: str, pilot_id: str | None, event: str, detail: dict[str, Any]) -> None:
    c.execute(
        """INSERT INTO execution_pilot_closure_audit(id,tenant_id,pilot_id,event,detail_json,created_at)
           VALUES (?,?,?,?,?,?)""",
        (str(uuid.uuid4()), tenant_id, pilot_id, event, json.dumps(detail, sort_keys=True), _iso()),
    )


def bind_stored_guardian_to_activation(c: sqlite3.Connection, activation_id: str, evidence: dict[str, Any]) -> None:
    assessment = evidence.get("assessment") or {}
    c.execute(
        """UPDATE execution_pilot_activations
           SET guardian_assessment_id=?, guardian_context_hash=?, policy_version=?, policy_hash=?
           WHERE activation_id=?""",
        (
            assessment.get("guardian_assessment_id"),
            evidence.get("context_hash"),
            GUARDIAN_POLICY_VERSION,
            evidence.get("policy_hash") or guardian_policy_hash(),
            activation_id,
        ),
    )


def require_exact_activation_binding(
    c: sqlite3.Connection,
    *,
    tenant_id: str,
    adapter_id: str,
    action: str,
    pilot_id: str,
    destination_hash: str,
    manifest_hash: str,
    signing_key_id: str,
    guardian_assessment_id: str | None = None,
    guardian_context_hash: str | None = None,
    policy_version: str | None = None,
    policy_hash: str | None = None,
) -> dict[str, Any]:
    """Fail closed unless the stored ACTIVE activation matches every stored field."""
    row = enforce_activation_for_runtime(
        c,
        tenant_id=tenant_id,
        adapter_id=adapter_id,
        action=action,
        pilot_id=pilot_id,
        destination_hash=destination_hash,
        manifest_hash=manifest_hash,
        signing_key_id=signing_key_id,
        exact=True,
    )
    bind = c.execute(
        """SELECT * FROM execution_pilot_guardian_bindings
           WHERE pilot_id=? AND tenant_id=? ORDER BY created_at DESC LIMIT 1""",
        (pilot_id, tenant_id),
    ).fetchone()
    if bind is None:
        raise ActivationDenied("guardian binding is missing")
    assessment = load_guardian_assessment(c, bind["guardian_assessment_id"])
    if assessment is None:
        raise ActivationDenied("guardian assessment is missing")
    assessment = dict(assessment)
    stored_gid = row.get("guardian_assessment_id") or bind["guardian_assessment_id"]
    stored_ctx = row.get("guardian_context_hash") or assessment.get("context_hash")
    stored_pv = row.get("policy_version") or assessment.get("policy_version") or GUARDIAN_POLICY_VERSION
    stored_ph = row.get("policy_hash") or assessment.get("policy_hash") or guardian_policy_hash()
    if guardian_assessment_id and guardian_assessment_id != stored_gid:
        raise ActivationDenied("guardian assessment id mismatch")
    if guardian_context_hash and guardian_context_hash != stored_ctx:
        raise ActivationDenied("guardian context hash mismatch")
    if policy_version and policy_version != stored_pv:
        raise ActivationDenied("guardian policy version mismatch")
    if policy_hash and policy_hash != stored_ph:
        raise ActivationDenied("guardian policy hash mismatch")
    if bind["guardian_assessment_id"] != stored_gid:
        raise ActivationDenied("guardian assessment id mismatch")
    if (assessment.get("context_hash") or "") != (stored_ctx or ""):
        raise ActivationDenied("guardian context hash mismatch")
    lookup = lookup_guardian_evidence(
        c,
        pilot_id=pilot_id,
        tenant_id=tenant_id,
        destination_hash_value=destination_hash,
        manifest_hash=manifest_hash,
    )
    if lookup["status"] != "PASS":
        raise ActivationDenied(f"guardian evidence {lookup['status']}")
    row["guardian_assessment_id"] = stored_gid
    row["guardian_context_hash"] = stored_ctx
    row["policy_version"] = stored_pv
    row["policy_hash"] = stored_ph
    return row


def list_uncertain_attempts(
    c: sqlite3.Connection,
    *,
    principal: PlatformPrincipal,
    tenant_id: str | None = None,
    pilot_id: str | None = None,
    activation_id: str | None = None,
) -> list[dict[str, Any]]:
    _require_principal(principal)
    sql = "SELECT id, tenant_id, plan_id, adapter_id, state, updated_at, pilot_id, activation_id FROM execution_attempts WHERE state='UNCERTAIN'"
    params: list[Any] = []
    if tenant_id:
        sql += " AND tenant_id=?"
        params.append(tenant_id)
    if pilot_id:
        sql += " AND pilot_id=?"
        params.append(pilot_id)
    if activation_id:
        sql += " AND activation_id=?"
        params.append(activation_id)
    sql += " ORDER BY updated_at DESC"
    out = []
    for row in c.execute(sql, params).fetchall():
        out.append({
            "attempt_id": row["id"],
            "tenant_id": row["tenant_id"],
            "plan_id": row["plan_id"],
            "adapter_id": row["adapter_id"],
            "state": row["state"],
            "updated_at": row["updated_at"],
            "destination": None,
            "signing_secret": None,
            "external_execution_enabled": False,
        })
    return out


def inspect_attempt_redacted(c: sqlite3.Connection, *, principal: PlatformPrincipal, tenant_id: str, attempt_id: str) -> dict[str, Any]:
    _require_principal(principal)
    attempt = c.execute(
        "SELECT id, tenant_id, plan_id, adapter_id, state, idempotency_key, updated_at FROM execution_attempts WHERE id=? AND tenant_id=?",
        (attempt_id, tenant_id),
    ).fetchone()
    if attempt is None:
        raise ReconciliationDenied("attempt not found")
    receipts = c.execute(
        "SELECT classification, recorded_at FROM execution_receipts WHERE attempt_id=? AND tenant_id=? ORDER BY recorded_at",
        (attempt_id, tenant_id),
    ).fetchall()
    recon = c.execute(
        "SELECT decision, actor_id, role, created_at FROM execution_pilot_reconciliations WHERE attempt_id=? ORDER BY created_at",
        (attempt_id,),
    ).fetchall()
    return {
        "attempt_id": attempt["id"],
        "tenant_id": attempt["tenant_id"],
        "adapter_id": attempt["adapter_id"],
        "state": attempt["state"],
        "idempotency_fingerprint": (attempt["idempotency_key"] or "")[:12],
        "updated_at": attempt["updated_at"],
        "receipts": [{"classification": r["classification"], "recorded_at": r["recorded_at"]} for r in receipts],
        "reconciliations": [dict(r) for r in recon],
        "destination": None,
        "payload": None,
        "signing_secret": None,
        "confirmation_token": None,
        "authorization": None,
        "external_execution_enabled": False,
    }


def record_reconciliation(
    c: sqlite3.Connection,
    *,
    principal: PlatformPrincipal,
    tenant_id: str,
    attempt_id: str,
    decision: str,
    note: str = "",
    suspend: bool = False,
) -> dict[str, Any]:
    from intelligence.execution_pilot_activation import (
        _begin_immediate,
        _commit_activation_claim,
        _rollback_quietly,
        _suspend_pilot_locked,
    )
    _require_principal(principal)
    if decision not in RECONCILE_DECISIONS:
        raise ReconciliationDenied("reconciliation decision is invalid")
    if c.in_transaction:
        raise ReconciliationDenied("open transaction exists")
    try:
        _begin_immediate(c)
        attempt = c.execute(
            "SELECT * FROM execution_attempts WHERE id=? AND tenant_id=?",
            (attempt_id, tenant_id),
        ).fetchone()
        if attempt is None:
            raise ReconciliationDenied("attempt not found")
        if attempt["state"] != "UNCERTAIN":
            raise ReconciliationDenied("reconciliation is only allowed for UNCERTAIN attempts")
        extra = c.execute(
            "SELECT pilot_id, activation_id FROM execution_pilot_attempts WHERE attempt_id=? AND tenant_id=?",
            (attempt_id, tenant_id),
        ).fetchone()
        pilot_id = attempt["pilot_id"] if "pilot_id" in attempt.keys() else None
        activation_id = attempt["activation_id"] if "activation_id" in attempt.keys() else None
        if extra:
            if extra["pilot_id"] and pilot_id and extra["pilot_id"] != pilot_id:
                raise ReconciliationDenied("attempt pilot binding mismatch")
            if extra["activation_id"] and activation_id and extra["activation_id"] != activation_id:
                raise ReconciliationDenied("attempt activation binding mismatch")
            pilot_id = pilot_id or extra["pilot_id"]
            activation_id = activation_id or extra["activation_id"]
        if not pilot_id or not activation_id:
            raise ReconciliationDenied("attempt is not bound to an activation")
        row = c.execute(
            "SELECT * FROM execution_pilot_activations WHERE activation_id=? AND pilot_id=? AND tenant_id=?",
            (activation_id, pilot_id, tenant_id),
        ).fetchone()
        if row is None:
            raise ReconciliationDenied("bound activation was not found")
        terminal = {"confirmed-success": "RECONCILED_SUCCESS", "confirmed-failure": "RECONCILED_FAILURE"}.get(decision)
        c.execute(
            """INSERT INTO execution_pilot_reconciliations(
                id,tenant_id,attempt_id,pilot_id,actor_id,role,decision,note,created_at
            ) VALUES (?,?,?,?,?,?,?,?,?)""",
            (str(uuid.uuid4()), tenant_id, attempt_id, pilot_id, principal.actor_id, principal.role, decision, note, _iso()),
        )
        if terminal:
            marked = c.execute(
                "UPDATE execution_attempts SET state=?, updated_at=? WHERE id=? AND tenant_id=? AND state='UNCERTAIN'",
                (terminal, _iso(), attempt_id, tenant_id),
            ).rowcount
            if marked != 1:
                raise ReconciliationDenied("attempt classification could not be applied")
        _suspend_pilot_locked(c, pilot_id=pilot_id, principal=principal, reason=f"reconcile:{decision}")
        grant = c.execute(
            "SELECT enabled FROM execution_live_grants WHERE tenant_id=? AND adapter_id=? AND action=? AND env=?",
            (tenant_id, ADAPTER_ID, ACTION, ACTIVATION_ENV),
        ).fetchone()
        allow = c.execute(
            "SELECT 1 FROM execution_destination_allowlist WHERE tenant_id=? AND adapter_id=? AND destination_hash=?",
            (tenant_id, ADAPTER_ID, row["destination_hash"]),
        ).fetchone()
        act = c.execute("SELECT status FROM execution_pilot_activations WHERE activation_id=?", (activation_id,)).fetchone()
        if grant is None or grant["enabled"] != 0 or allow is not None or act["status"] != "SUSPENDED":
            raise ReconciliationDenied("reconciliation could not close the exact pilot controls")
        _ops_audit(
            c, tenant_id=tenant_id, actor_id=principal.actor_id, event="pilot_reconciled",
            pilot_id=pilot_id, detail={"attempt_id": attempt_id, "decision": decision},
        )
        _audit_closure(c, tenant_id=tenant_id, pilot_id=pilot_id, event="reconcile", detail={"decision": decision, "attempt_id": attempt_id})
        _commit_activation_claim(c)
    except Exception:
        _rollback_quietly(c)
        raise
    return {
        "ok": True,
        "attempt_id": attempt_id,
        "decision": decision,
        "provider_calls": 0,
        "external_execution_enabled": False,
        "http_post": False,
    }


def observe_pilot_runtime(
    c: sqlite3.Connection,
    *,
    principal: PlatformPrincipal,
    tenant_id: str,
    pilot_id: str | None = None,
    activation_id: str | None = None,
) -> dict[str, Any]:
    """SELECT-only operational view. Must not install schema."""
    _require_principal(principal)
    act_sql = "SELECT * FROM execution_pilot_activations WHERE tenant_id=?"
    act_params: list[Any] = [tenant_id]
    if pilot_id:
        act_sql += " AND pilot_id=?"
        act_params.append(pilot_id)
    if activation_id:
        act_sql += " AND activation_id=?"
        act_params.append(activation_id)
    if not pilot_id and not activation_id:
        act_sql += " AND adapter_id=?"
        act_params.append(ADAPTER_ID)
    act_sql += " ORDER BY created_at DESC LIMIT 1"
    act = c.execute(act_sql, act_params).fetchone()
    dest_hash = act["destination_hash"] if act else None
    grant = c.execute(
        "SELECT enabled FROM execution_live_grants WHERE tenant_id=? AND adapter_id=? AND action=? AND env=?",
        (tenant_id, ADAPTER_ID, ACTION, ACTIVATION_ENV),
    ).fetchone()
    if dest_hash:
        allow_n = c.execute(
            "SELECT COUNT(*) AS n FROM execution_destination_allowlist WHERE tenant_id=? AND adapter_id=? AND destination_hash=?",
            (tenant_id, ADAPTER_ID, dest_hash),
        ).fetchone()["n"]
    else:
        allow_n = 0
    bound_pilot = pilot_id or (act["pilot_id"] if act else None)
    bound_act = activation_id or (act["activation_id"] if act else None)
    uncertain_sql = "SELECT COUNT(*) AS n FROM execution_attempts WHERE tenant_id=? AND state='UNCERTAIN'"
    uncertain_params: list[Any] = [tenant_id]
    if bound_pilot:
        uncertain_sql += " AND pilot_id=?"
        uncertain_params.append(bound_pilot)
    if bound_act:
        uncertain_sql += " AND activation_id=?"
        uncertain_params.append(bound_act)
    uncertain_n = c.execute(uncertain_sql, uncertain_params).fetchone()["n"]
    join_sql = """
        SELECT a.id, a.state, a.updated_at, a.pilot_id, a.activation_id, p.provider_submitted
        FROM execution_attempts a
        LEFT JOIN execution_pilot_attempts p
          ON p.attempt_id = a.id AND p.tenant_id = a.tenant_id
        WHERE a.tenant_id=?
    """
    join_params: list[Any] = [tenant_id]
    if bound_pilot:
        join_sql += " AND a.pilot_id=?"
        join_params.append(bound_pilot)
    if bound_act:
        join_sql += " AND a.activation_id=?"
        join_params.append(bound_act)
    join_sql += " ORDER BY a.updated_at DESC LIMIT 1"
    attempt = c.execute(join_sql, join_params).fetchone()
    recon = None
    receipt = None
    if attempt:
        recon_sql = "SELECT decision, created_at FROM execution_pilot_reconciliations WHERE attempt_id=?"
        recon_params: list[Any] = [attempt["id"]]
        if bound_pilot:
            recon_sql += " AND pilot_id=?"
            recon_params.append(bound_pilot)
        recon_sql += " ORDER BY created_at DESC LIMIT 1"
        recon = c.execute(recon_sql, recon_params).fetchone()
        receipt = c.execute(
            "SELECT classification FROM execution_receipts WHERE attempt_id=? AND tenant_id=? ORDER BY recorded_at DESC LIMIT 1",
            (attempt["id"], tenant_id),
        ).fetchone()
    return {
        "tenant_id": tenant_id,
        "pilot_id": act["pilot_id"] if act else bound_pilot,
        "activation_id": act["activation_id"] if act else bound_act,
        "activation_status": act["status"] if act else "absent",
        "expires_at": act["expires_at"] if act else None,
        "quota": {
            "successes_claimed": int(act["successes_claimed"]) if act else 0,
            "max_successes": int(act["max_successes"]) if act else 1,
        },
        "grant_enabled": bool(grant and grant["enabled"]),
        "allowlist_entries": int(allow_n),
        "circuit_open": circuit_open(c, tenant_id, ADAPTER_ID),
        "kill_switch": _global_kill_active(c) or _tenant_kill_active(c, tenant_id, ADAPTER_ID),
        "attempt_id": attempt["id"] if attempt else None,
        "attempt_state": attempt["state"] if attempt else None,
        "provider_submitted": bool(attempt["provider_submitted"]) if attempt and attempt["provider_submitted"] is not None else False,
        "bound_pilot_id": (attempt["pilot_id"] if attempt else bound_pilot),
        "bound_activation_id": (attempt["activation_id"] if attempt else bound_act),
        "receipt_classification": receipt["classification"] if receipt else None,
        "outstanding_uncertain": int(uncertain_n),
        "reconciliation_status": recon["decision"] if recon else None,
        "destination": None,
        "signing_secret": None,
        "external_execution_enabled": False,
    }


def maintain_pilot_runtime(c: sqlite3.Connection) -> dict[str, Any]:
    """Idempotent closure. No provider I/O. Safe to repeat."""
    from intelligence.execution_pilot_activation import _begin_immediate, _commit_activation_claim, _rollback_quietly
    if c.in_transaction:
        raise ReconciliationDenied("open transaction exists")
    _begin_immediate(c)
    closed = 0
    recovered: list[str] = []
    try:
        recovered = recover_stale_production(c, commit=False, install_schema=False)
        rows = c.execute("SELECT * FROM execution_pilot_activations").fetchall()
        for row in rows:
            expires = _parse_iso(row["expires_at"])
            stale = row["status"] == "ACTIVE" and expires is not None and expires <= _now()
            inconsistent = False
            if row["status"] == "ACTIVE":
                lookup = lookup_guardian_evidence(
                    c,
                    pilot_id=row["pilot_id"],
                    tenant_id=row["tenant_id"],
                    destination_hash_value=row["destination_hash"],
                    manifest_hash=row["manifest_hash"],
                )
                inconsistent = lookup["status"] != "PASS"
            if stale or inconsistent:
                _close_activation(c, row, "expired" if stale else "suspended")
                if inconsistent:
                    c.execute("UPDATE execution_pilot_activations SET status='SUSPENDED' WHERE activation_id=?", (row["activation_id"],))
                    c.execute(
                        "UPDATE execution_pilot_preparations SET status='SUSPENDED', updated_at=? WHERE pilot_id=?",
                        (_iso(), row["pilot_id"]),
                    )
                _audit_closure(
                    c,
                    tenant_id=row["tenant_id"],
                    pilot_id=row["pilot_id"],
                    event="maintain_close",
                    detail={"stale": stale, "inconsistent": inconsistent},
                )
                closed += 1
        _commit_activation_claim(c)
        return {
            "closed": closed,
            "stale_attempts": recovered,
            "provider_calls": 0,
            "external_execution_enabled": False,
        }
    except Exception:
        _rollback_quietly(c)
        raise


def assert_no_public_4c2_routes() -> dict[str, Any]:
    from pathlib import Path
    src = Path("app_gate5.py").read_text()
    return {
        "activate_route": "/api/execution/pilot/activate" in src or "/activate" in src,
        "reconcile_route": "/reconcile" in src,
        "external_execution_enabled": False,
    }


# Re-export claim for tests that drive the 4C2 claim path explicitly.
claim_one_shot = claim_activation_success
