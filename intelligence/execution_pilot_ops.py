"""Phase 3 Stage 4B — pilot preparation, readiness, shutdown. Not activation.

Default production execution remains off. This module never inserts a live
grant, allowlist row or signing secret, and never sends network traffic.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from datetime import timedelta
from typing import Any

from intelligence.execution import _iso, _now, _parse_iso
from urllib.parse import urlsplit

from intelligence.execution_adapters import destination_hash
from intelligence.execution_live import (
    LIVE_ENV_SWITCH,
    LiveDenied,
    _audit,
    _global_kill_active,
    _grant_enabled,
    _require_role,
    _tenant_kill_active,
    ensure_phase3_schema,
    set_kill_switch,
)
from intelligence.execution_production_webhook import (
    PILOT_FLAG,
    PILOT_HOST_SUFFIX_ENV,
    PILOT_KEY_ID_ENV,
    PILOT_SECRET_ENV,
    PILOT_TENANT_ENV,
    circuit_open,
    ensure_stage4a_schema,
)
from intelligence.execution_providers import ClosedProvider, get_provider
from intelligence.execution_adapters import get_adapter
from intelligence.execution_receipts import list_receipts_for_attempt, public_receipt

ADAPTER_ID = "webhook.post"
ACTION = "post_webhook"
ALLOWED_STATUSES = {"PREPARED", "EXPIRED", "REVOKED", "SUSPENDED"}
OPERATOR_ROLES = {"owner", "admin"}
PLATFORM_ROLES = {"platform_owner", "security_operator"}
POLICY_VERSION = "phase3-stage4b-v1"


class PilotOpsDenied(LiveDenied):
    """Stage 4B preparation or inspection denied."""


def _result(name: str, status: str, detail: str) -> dict[str, str]:
    if status not in {"PASS", "FAIL", "UNKNOWN"}:
        status = "UNKNOWN"
    return {"name": name, "status": status, "detail": detail}


def ensure_stage4b_schema(c: sqlite3.Connection) -> None:
    from intelligence.guardian import ensure_guardian_schema
    ensure_stage4a_schema(c)
    ensure_phase3_schema(c)
    ensure_guardian_schema(c)
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS execution_pilot_preparations(
            pilot_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            adapter_id TEXT NOT NULL,
            action TEXT NOT NULL,
            destination_hash TEXT NOT NULL,
            hostname_suffix TEXT NOT NULL,
            signing_key_id TEXT NOT NULL,
            reason TEXT,
            change_ref TEXT,
            max_requests INTEGER NOT NULL,
            max_exposure TEXT,
            rate_ceiling INTEGER,
            circuit_threshold INTEGER,
            not_before TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            proposer_id TEXT NOT NULL,
            approver_id TEXT,
            status TEXT NOT NULL,
            rollback_ref TEXT,
            manifest_json TEXT NOT NULL,
            manifest_hash TEXT NOT NULL,
            last_denial TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS execution_pilot_approvals(
            id TEXT PRIMARY KEY,
            pilot_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            role TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            decision TEXT NOT NULL,
            note TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS execution_pilot_ops_audit(
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            event TEXT NOT NULL,
            pilot_id TEXT,
            detail_json TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS execution_pilot_guardian_bindings(
            binding_id TEXT PRIMARY KEY,
            guardian_assessment_id TEXT NOT NULL,
            pilot_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            adapter_id TEXT NOT NULL,
            destination_hash TEXT NOT NULL,
            manifest_hash TEXT NOT NULL,
            policy_version TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )



def bind_pilot_to_guardian_assessment(
    c: sqlite3.Connection,
    *,
    guardian_assessment_id: str,
    pilot_id: str,
    actor_id: str,
    tenant_id: str | None = None,
    **kwargs: Any,
) -> str:
    from intelligence.guardian import (
        GUARDIAN_POLICY_VERSION,
        PILOT_PURPOSE,
        canonical_context_hash,
        canonical_pilot_context,
        guardian_policy_hash,
        load_guardian_assessment,
    )
    banned = {k for k in kwargs if k in {"destination_hash_value", "destination_hash", "manifest_hash", "manifest_hash_value"}}
    if banned:
        raise PilotOpsDenied("caller cannot supply replacement destination or manifest hashes")
    if kwargs:
        raise PilotOpsDenied("unexpected bind arguments: " + ", ".join(sorted(kwargs)))

    prep = c.execute("SELECT * FROM execution_pilot_preparations WHERE pilot_id=?", (pilot_id,)).fetchone()
    if prep is None:
        raise PilotOpsDenied("pilot preparation not found")
    if tenant_id is not None and prep["tenant_id"] != tenant_id:
        raise PilotOpsDenied("pilot preparation not found for this tenant")
    tenant_id = prep["tenant_id"]
    dest_h = prep["destination_hash"]
    man_h = prep["manifest_hash"]

    row = load_guardian_assessment(c, guardian_assessment_id)
    if row is None:
        raise PilotOpsDenied("guardian assessment does not exist")
    assessment = dict(row)
    if assessment["tenant_id"] != tenant_id:
        raise PilotOpsDenied("guardian assessment tenant mismatch")
    proposer_id = prep["proposer_id"]
    if (assessment.get("requesting_user_id") or "") != proposer_id:
        raise PilotOpsDenied("guardian assessment requesting user does not match pilot proposer")
    if str(assessment.get("decision") or "").upper() != "ALLOW":
        raise PilotOpsDenied("guardian assessment decision is not ALLOW")
    if not assessment.get("execution_allowed"):
        raise PilotOpsDenied("execution_allowed is not true")
    if not assessment.get("consequential_action"):
        raise PilotOpsDenied("consequential_action is not true")
    if (assessment.get("action") or "") != ACTION:
        raise PilotOpsDenied("guardian assessment action is not post_webhook")
    if (assessment.get("adapter_id") or "") != ADAPTER_ID:
        raise PilotOpsDenied("guardian assessment adapter is not webhook.post")
    if (assessment.get("purpose") or "") != PILOT_PURPOSE:
        raise PilotOpsDenied("guardian assessment purpose is not production_webhook_pilot")
    if (assessment.get("pilot_id") or "") != pilot_id:
        raise PilotOpsDenied("guardian assessment pilot_id does not match stored manifest")
    if (assessment.get("destination_hash") or "") != dest_h:
        raise PilotOpsDenied("guardian assessment destination hash does not match stored manifest")
    if (assessment.get("manifest_hash") or "") != man_h:
        raise PilotOpsDenied("guardian assessment manifest hash does not match stored manifest")
    if (assessment.get("policy_version") or "") != GUARDIAN_POLICY_VERSION:
        raise PilotOpsDenied("guardian policy version mismatch")
    if (assessment.get("policy_hash") or "") != guardian_policy_hash(assessment.get("policy_version")):
        raise PilotOpsDenied("guardian policy hash mismatch")
    expires = _parse_iso(assessment.get("expires_at"))
    if expires is None or expires <= _now():
        raise PilotOpsDenied("guardian assessment is expired")

    expected = canonical_pilot_context(
        {
            "purpose": PILOT_PURPOSE,
            "pilot_id": pilot_id,
            "tenant_id": tenant_id,
            "requesting_user_id": proposer_id,
            "adapter_id": ADAPTER_ID,
            "action": ACTION,
            "destination_hash": dest_h,
            "manifest_hash": man_h,
            "policy_version": GUARDIAN_POLICY_VERSION,
            "policy_hash": guardian_policy_hash(),
            "consequential_action": True,
            "expiry": assessment.get("expires_at"),
        }
    )
    expected_hash = canonical_context_hash(expected)
    if (assessment.get("context_hash") or "") != expected_hash:
        raise PilotOpsDenied("assessment context hash does not match the canonical current manifest context")

    binding_id = str(uuid.uuid4())
    c.execute(
        """INSERT INTO execution_pilot_guardian_bindings(
            binding_id,guardian_assessment_id,pilot_id,tenant_id,adapter_id,
            destination_hash,manifest_hash,policy_version,actor_id,created_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (
            binding_id,
            guardian_assessment_id,
            pilot_id,
            tenant_id,
            ADAPTER_ID,
            dest_h,
            man_h,
            GUARDIAN_POLICY_VERSION,
            actor_id,
            _iso(),
        ),
    )
    return binding_id


def lookup_guardian_evidence(
    c: sqlite3.Connection,
    *,
    pilot_id: str | None,
    tenant_id: str,
    destination_hash_value: str | None,
    manifest_hash: str | None,
) -> dict[str, str]:
    from intelligence.guardian import (
        GUARDIAN_POLICY_VERSION,
        PILOT_PURPOSE,
        canonical_context_hash,
        canonical_pilot_context,
        guardian_policy_hash,
        load_guardian_assessment,
    )
    if not pilot_id:
        return _result("guardian_approval", "FAIL", "guardian evidence is not bound")
    try:
        prep = c.execute(
            "SELECT * FROM execution_pilot_preparations WHERE pilot_id=? AND tenant_id=?",
            (pilot_id, tenant_id),
        ).fetchone()
    except sqlite3.Error:
        return _result("guardian_approval", "UNKNOWN", "pilot preparation unreadable")
    if prep is None:
        return _result("guardian_approval", "FAIL", "pilot preparation is missing")
    dest_h = prep["destination_hash"]
    man_h = prep["manifest_hash"]
    proposer_id = prep["proposer_id"]
    if destination_hash_value and destination_hash_value != dest_h:
        return _result("guardian_approval", "FAIL", "destination hash does not match stored manifest")
    if manifest_hash and manifest_hash != man_h:
        return _result("guardian_approval", "FAIL", "manifest hash does not match stored manifest")
    try:
        bind = c.execute(
            """SELECT * FROM execution_pilot_guardian_bindings
               WHERE pilot_id=? AND tenant_id=? AND adapter_id=?
               ORDER BY created_at DESC LIMIT 1""",
            (pilot_id, tenant_id, ADAPTER_ID),
        ).fetchone()
    except sqlite3.Error:
        return _result("guardian_approval", "UNKNOWN", "guardian binding table unreadable")
    if bind is None:
        return _result("guardian_approval", "FAIL", "guardian evidence is missing")
    if bind["destination_hash"] != dest_h or bind["manifest_hash"] != man_h:
        return _result("guardian_approval", "FAIL", "guardian evidence binding mismatch")
    if bind["policy_version"] != GUARDIAN_POLICY_VERSION:
        return _result("guardian_approval", "FAIL", "guardian policy version mismatch")
    try:
        assessment = load_guardian_assessment(c, bind["guardian_assessment_id"])
    except sqlite3.Error:
        return _result("guardian_approval", "UNKNOWN", "guardian assessment unreadable")
    if assessment is None:
        return _result("guardian_approval", "FAIL", "guardian assessment is missing")
    assessment = dict(assessment)
    if assessment.get("tenant_id") != tenant_id:
        return _result("guardian_approval", "FAIL", "guardian assessment tenant mismatch")
    if (assessment.get("requesting_user_id") or "") != proposer_id:
        return _result("guardian_approval", "FAIL", "guardian assessment requesting user does not match pilot proposer")
    if (assessment.get("pilot_id") or "") != pilot_id:
        return _result("guardian_approval", "FAIL", "guardian assessment pilot_id mismatch")
    if (assessment.get("purpose") or "") != PILOT_PURPOSE:
        return _result("guardian_approval", "FAIL", "guardian assessment purpose mismatch")
    if (assessment.get("action") or "") != ACTION:
        return _result("guardian_approval", "FAIL", "guardian assessment action mismatch")
    if (assessment.get("adapter_id") or "") != ADAPTER_ID:
        return _result("guardian_approval", "FAIL", "guardian assessment adapter mismatch")
    if (assessment.get("destination_hash") or "") != dest_h:
        return _result("guardian_approval", "FAIL", "guardian assessment destination hash mismatch")
    if (assessment.get("manifest_hash") or "") != man_h:
        return _result("guardian_approval", "FAIL", "guardian assessment manifest hash mismatch")
    if (assessment.get("policy_version") or "") != GUARDIAN_POLICY_VERSION:
        return _result("guardian_approval", "FAIL", "guardian policy version mismatch")
    expected_policy_hash = guardian_policy_hash(assessment.get("policy_version"))
    if (assessment.get("policy_hash") or "") != expected_policy_hash:
        return _result("guardian_approval", "FAIL", "guardian policy hash mismatch")
    if not assessment.get("consequential_action"):
        return _result("guardian_approval", "FAIL", "consequential_action is not true")
    if not assessment.get("execution_allowed"):
        return _result("guardian_approval", "FAIL", "execution_allowed is not true")
    expires = _parse_iso(assessment.get("expires_at"))
    if expires is None:
        return _result("guardian_approval", "UNKNOWN", "guardian expiry unreadable")
    if expires <= _now():
        return _result("guardian_approval", "FAIL", "guardian evidence is expired")
    decision = str(assessment.get("decision") or "").upper()
    if decision == "DENY":
        return _result("guardian_approval", "FAIL", "guardian assessment is DENY")
    if decision != "ALLOW":
        return _result("guardian_approval", "UNKNOWN", f"guardian decision {assessment.get('decision')}")
    expected = canonical_pilot_context(
        {
            "purpose": PILOT_PURPOSE,
            "pilot_id": pilot_id,
            "tenant_id": tenant_id,
            "requesting_user_id": proposer_id,
            "adapter_id": ADAPTER_ID,
            "action": ACTION,
            "destination_hash": dest_h,
            "manifest_hash": man_h,
            "policy_version": GUARDIAN_POLICY_VERSION,
            "policy_hash": expected_policy_hash,
            "consequential_action": True,
            "expiry": assessment.get("expires_at"),
        }
    )
    expected_hash = canonical_context_hash(expected)
    stored_hash = assessment.get("context_hash") or ""
    if not stored_hash:
        return _result("guardian_approval", "FAIL", "guardian context hash is missing")
    if stored_hash != expected_hash:
        return _result("guardian_approval", "FAIL", "guardian context hash does not match stored pilot context")
    return _result("guardian_approval", "PASS", assessment["guardian_assessment_id"])


def canonical_pilot_destination(destination: str, declared_suffix: str) -> str:
    raw = (destination or "").strip()
    parts = urlsplit(raw)
    if parts.scheme != "https" or not parts.netloc:
        raise PilotOpsDenied("destination must be a valid https URL")
    if parts.username or parts.password:
        raise PilotOpsDenied("destination must not contain userinfo")
    if parts.query or parts.fragment:
        raise PilotOpsDenied("query strings and fragments are rejected")
    if parts.port not in (None, 443):
        raise PilotOpsDenied("destination port must be 443")
    host = parts.hostname
    if not host:
        raise PilotOpsDenied("destination hostname is required")
    try:
        ascii_host = host.encode("idna").decode("ascii").lower().rstrip(".")
        suffix_ascii = declared_suffix.strip().encode("idna").decode("ascii").lower().rstrip(".")
    except (UnicodeError, AttributeError) as exc:
        raise PilotOpsDenied("destination hostname is not a valid IDNA name") from exc
    if not suffix_ascii:
        raise PilotOpsDenied("hostname suffix is required")
    if ascii_host != suffix_ascii and not ascii_host.endswith("." + suffix_ascii):
        raise PilotOpsDenied("destination hostname is not bound to the platform-owned suffix")
    configured = (os.getenv(PILOT_HOST_SUFFIX_ENV) or "").strip()
    if configured:
        try:
            cfg = configured.encode("idna").decode("ascii").lower().rstrip(".")
        except UnicodeError as exc:
            raise PilotOpsDenied("configured hostname suffix is invalid") from exc
        if suffix_ascii != cfg:
            raise PilotOpsDenied("declared suffix does not match configured platform-owned suffix")
    path = parts.path or "/"
    return f"https://{ascii_host}{path}"


def classify_provider_state(c: sqlite3.Connection, tenant_id: str) -> dict[str, Any]:
    if _global_kill_active(c) or _tenant_kill_active(c, tenant_id, ADAPTER_ID):
        state = "killed"
    else:
        switch = (os.getenv(LIVE_ENV_SWITCH) or "").strip().lower()
        flag = (os.getenv(PILOT_FLAG) or "").strip().lower()
        tenant = (os.getenv(PILOT_TENANT_ENV) or "").strip()
        suffix = (os.getenv(PILOT_HOST_SUFFIX_ENV) or "").strip()
        key_id = (os.getenv(PILOT_KEY_ID_ENV) or "").strip()
        secret = os.getenv(PILOT_SECRET_ENV) or ""
        grant = _grant_enabled(c, tenant_id, ADAPTER_ID, ACTION, "prod")
        complete = (
            switch == "pilot"
            and flag in {"1", "true", "on", "yes"}
            and tenant == tenant_id
            and bool(suffix and key_id and len(secret) >= 16)
            and grant
        )
        if not switch and not flag and not tenant and not suffix and not key_id and not secret and not grant:
            state = "default_closed"
        elif complete:
            state = "selectable_but_not_activated"
        elif switch or flag or tenant or suffix or key_id or secret or grant:
            state = "gates_incomplete"
        else:
            state = "unknown"
    provider = get_provider(get_adapter(ADAPTER_ID), connection=c, tenant_id=tenant_id)
    return {
        "provider_state": state,
        "production_provider": type(provider).__name__,
        "production_execution_selectable": state == "selectable_but_not_activated",
        "external_execution_enabled": False,
    }


def _ops_audit(c: sqlite3.Connection, *, tenant_id: str, actor_id: str, event: str, pilot_id: str | None, detail: dict[str, Any] | None = None) -> None:
    safe = {k: v for k, v in (detail or {}).items() if k not in {"secret", "token", "password", "authorization", "destination"}}
    c.execute(
        """INSERT INTO execution_pilot_ops_audit(id,tenant_id,actor_id,event,pilot_id,detail_json,created_at)
           VALUES (?,?,?,?,?,?,?)""",
        (str(uuid.uuid4()), tenant_id, actor_id, event, pilot_id, json.dumps(safe), _iso()),
    )
    _audit(c, tenant_id=tenant_id, actor_id=actor_id, event=event, subject_id=pilot_id, detail=safe)


def _secret_present() -> tuple[str, str]:
    secret = os.getenv(PILOT_SECRET_ENV) or ""
    if not secret:
        return "FAIL", "signing secret is absent"
    if len(secret) < 16:
        return "FAIL", "signing secret is too weak"
    return "PASS", "signing secret present and meets minimum length"


def assess_pilot_readiness(
    c: sqlite3.Connection,
    *,
    tenant_id: str,
    destination_hash_value: str | None = None,
    hostname_suffix: str | None = None,
    signing_key_id: str | None = None,
    pilot_id: str | None = None,
    manifest_hash: str | None = None,
) -> dict[str, Any]:
    """Read-only. Never mutates env, grants, allowlists, tickets, schema or network."""
    checks: list[dict[str, str]] = []
    env_mode = (os.getenv("ZORVIAN_EXECUTION_ENV") or os.getenv("APP_ENV") or "").strip().lower()
    if env_mode == "production":
        checks.append(_result("production_environment", "PASS", "production"))
    elif env_mode:
        checks.append(_result("production_environment", "FAIL", f"env={env_mode}"))
    else:
        checks.append(_result("production_environment", "FAIL", "production environment is not set"))

    switch = (os.getenv(LIVE_ENV_SWITCH) or "off").strip().lower()
    checks.append(_result("process_switch", "PASS" if switch == "pilot" else "FAIL", f"ZORVIAN_EXTERNAL_EXECUTION={switch or 'unset'}"))

    flag = (os.getenv(PILOT_FLAG) or "").strip().lower()
    checks.append(_result("pilot_feature_flag", "PASS" if flag in {"1", "true", "on", "yes"} else "FAIL", f"{PILOT_FLAG}={flag or 'unset'}"))

    configured_tenant = (os.getenv(PILOT_TENANT_ENV) or "").strip()
    if not configured_tenant:
        checks.append(_result("pilot_tenant_configured", "FAIL", "pilot tenant is not configured"))
    elif configured_tenant != tenant_id:
        checks.append(_result("pilot_tenant_configured", "FAIL", "configured tenant does not match request tenant"))
    else:
        checks.append(_result("pilot_tenant_configured", "PASS", "tenant matches"))

    suffix = (os.getenv(PILOT_HOST_SUFFIX_ENV) or "").strip().lower()
    if not suffix:
        checks.append(_result("hostname_suffix", "FAIL", "hostname suffix is not configured"))
    elif hostname_suffix and hostname_suffix.lower() != suffix:
        checks.append(_result("hostname_suffix", "FAIL", "suffix mismatch"))
    else:
        checks.append(_result("hostname_suffix", "PASS", "suffix configured"))

    key_id = (os.getenv(PILOT_KEY_ID_ENV) or "").strip()
    if not key_id:
        checks.append(_result("signing_key_id", "FAIL", "signing key id is not configured"))
    elif signing_key_id and signing_key_id != key_id:
        checks.append(_result("signing_key_id", "FAIL", "key id mismatch"))
    else:
        checks.append(_result("signing_key_id", "PASS", "key id configured"))

    secret_status, secret_detail = _secret_present()
    checks.append(_result("signing_secret_presence", secret_status, secret_detail if secret_status == "FAIL" else "present"))
    checks.append(_result("signing_secret_strength", secret_status, secret_detail))

    grant = _grant_enabled(c, tenant_id, ADAPTER_ID, ACTION, "prod")
    checks.append(_result("active_db_live_grant", "PASS" if grant else "FAIL", "grant enabled" if grant else "no enabled grant"))

    if destination_hash_value:
        row = c.execute(
            """SELECT 1 FROM execution_destination_allowlist
               WHERE tenant_id=? AND adapter_id=? AND destination_hash=?""",
            (tenant_id, ADAPTER_ID, destination_hash_value),
        ).fetchone()
        checks.append(_result("destination_allowlist", "PASS" if row else "FAIL", "exact hash present" if row else "exact destination hash is not allowlisted"))
    else:
        checks.append(_result("destination_allowlist", "FAIL", "destination hash was not supplied"))

    checks.append(
        lookup_guardian_evidence(
            c,
            pilot_id=pilot_id,
            tenant_id=tenant_id,
            destination_hash_value=destination_hash_value,
            manifest_hash=manifest_hash,
        )
    )

    checks.append(_result("global_kill_switch", "FAIL" if _global_kill_active(c) else "PASS", "active" if _global_kill_active(c) else "inactive"))
    tenant_kill = _tenant_kill_active(c, tenant_id, ADAPTER_ID)
    checks.append(_result("tenant_adapter_kill_switch", "FAIL" if tenant_kill else "PASS", "active" if tenant_kill else "inactive"))

    try:
        open_circuit = circuit_open(c, tenant_id, ADAPTER_ID)
        checks.append(_result("circuit_state", "FAIL" if open_circuit else "PASS", "open" if open_circuit else "closed"))
    except Exception:
        checks.append(_result("circuit_state", "UNKNOWN", "circuit table unreadable"))

    checks.append(_result("rate_limits", "PASS", "hard ceilings remain 5/2/1"))

    uncertain = c.execute(
        "SELECT COUNT(*) AS n FROM execution_attempts WHERE tenant_id=? AND state='UNCERTAIN'",
        (tenant_id,),
    ).fetchone()
    checks.append(_result("outstanding_uncertain_attempts", "FAIL" if uncertain and uncertain["n"] else "PASS", str(uncertain["n"] if uncertain else 0)))

    submitting = c.execute(
        "SELECT COUNT(*) AS n FROM execution_attempts WHERE tenant_id=? AND state='SUBMITTING'",
        (tenant_id,),
    ).fetchone()
    checks.append(_result("unresolved_submitting_attempts", "FAIL" if submitting and submitting["n"] else "PASS", str(submitting["n"] if submitting else 0)))

    checks.append(_result("emergency_rollback_readiness", "PASS", "kill switches and suspend path available"))

    statuses = {item["status"] for item in checks}
    overall = "FAIL"
    if "UNKNOWN" in statuses:
        overall = "UNKNOWN"
    if "FAIL" in statuses:
        overall = "FAIL"
    if statuses == {"PASS"}:
        overall = "PASS"
    state = classify_provider_state(c, tenant_id)
    return {
        "overall": overall,
        "checks": checks,
        "external_execution_enabled": False,
        "production_provider": state["production_provider"],
        "provider_state": state["provider_state"],
        "activation_permitted": False,
        "network_calls": 0,
    }


def _canonical_manifest(payload: dict[str, Any]) -> tuple[str, str]:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return body, hashlib.sha256(body.encode("utf-8")).hexdigest()


def propose_pilot(
    c: sqlite3.Connection,
    *,
    tenant_id: str,
    proposer_id: str,
    role: str,
    destination: str,
    hostname_suffix: str,
    signing_key_id: str,
    reason: str,
    change_ref: str,
    max_requests: int,
    max_exposure: str,
    not_before: str | None = None,
    expires_at: str | None = None,
    rate_ceiling: int = 5,
    circuit_threshold: int = 5,
    rollback_ref: str = "CONTROLLED_EXECUTION_GATEWAY_PHASE3_STAGE4B_RUNBOOK.md#shutdown",
) -> dict[str, Any]:
    ensure_stage4b_schema(c)
    _require_role(role)
    if role not in OPERATOR_ROLES:
        raise PilotOpsDenied("role is not authorised for pilot preparation")
    canonical = canonical_pilot_destination(destination, hostname_suffix)
    dest_h = destination_hash(canonical)
    now = _now()
    start = not_before or _iso(now)
    expiry = expires_at or _iso(now + timedelta(hours=24))
    expires = _parse_iso(expiry)
    if expires and expires <= now:
        raise PilotOpsDenied("preparation expiry must be in the future")
    if max_requests < 1 or max_requests > 5:
        raise PilotOpsDenied("maximum requests must be between 1 and 5")
    pilot_id = str(uuid.uuid4())
    manifest = {
        "pilot_id": pilot_id,
        "tenant_id": tenant_id,
        "adapter_id": ADAPTER_ID,
        "action": ACTION,
        "destination_hash": dest_h,
        "hostname_suffix": hostname_suffix,
        "signing_key_id": signing_key_id,
        "permitted_action": ACTION,
        "not_before": start,
        "expires_at": expiry,
        "maximum_requests": max_requests,
        "rate_ceilings": {"tenant_per_hour": rate_ceiling, "user_per_hour": 2, "in_flight": 1},
        "circuit_thresholds": {"open_after": circuit_threshold},
        "rollback_procedure_reference": rollback_ref,
        "proposer": proposer_id,
        "approver": None,
        "status": "PREPARED",
    }
    body, digest = _canonical_manifest(manifest)
    c.execute(
        """INSERT INTO execution_pilot_preparations(
            pilot_id,tenant_id,adapter_id,action,destination_hash,hostname_suffix,signing_key_id,
            reason,change_ref,max_requests,max_exposure,rate_ceiling,circuit_threshold,not_before,expires_at,
            proposer_id,approver_id,status,rollback_ref,manifest_json,manifest_hash,last_denial,created_at,updated_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            pilot_id, tenant_id, ADAPTER_ID, ACTION, dest_h, hostname_suffix, signing_key_id,
            reason, change_ref, max_requests, max_exposure, rate_ceiling, circuit_threshold, start, expiry,
            proposer_id, None, "PREPARED", rollback_ref, body, digest, None, _iso(), _iso(),
        ),
    )
    c.execute(
        """INSERT INTO execution_pilot_approvals(id,pilot_id,tenant_id,role,actor_id,decision,note,created_at)
           VALUES (?,?,?,?,?,?,?,?)""",
        (str(uuid.uuid4()), pilot_id, tenant_id, "proposer", proposer_id, "proposed", reason, _iso()),
    )
    _ops_audit(c, tenant_id=tenant_id, actor_id=proposer_id, event="pilot_proposed", pilot_id=pilot_id, detail={"manifest_hash": digest})
    return public_manifest(c, tenant_id=tenant_id, pilot_id=pilot_id)


def approve_pilot(
    c: sqlite3.Connection,
    *,
    tenant_id: str,
    pilot_id: str,
    approver_id: str,
    role: str,
    note: str = "",
) -> dict[str, Any]:
    ensure_stage4b_schema(c)
    _require_role(role)
    if role not in OPERATOR_ROLES:
        raise PilotOpsDenied("role is not authorised for pilot approval")
    row = _load_prep(c, tenant_id, pilot_id)
    if row["proposer_id"] == approver_id:
        raise PilotOpsDenied("same user cannot propose and approve")
    expire_if_needed(c, row)
    row = _load_prep(c, tenant_id, pilot_id)
    if row["status"] != "PREPARED":
        raise PilotOpsDenied(f"pilot status {row['status']} cannot be approved")
    if row["approver_id"]:
        raise PilotOpsDenied("pilot already has an approver")
    manifest = json.loads(row["manifest_json"])
    manifest["approver"] = approver_id
    body, digest = _canonical_manifest(manifest)
    c.execute(
        """UPDATE execution_pilot_preparations
           SET approver_id=?, manifest_json=?, manifest_hash=?, updated_at=?
           WHERE pilot_id=? AND tenant_id=? AND status='PREPARED'""",
        (approver_id, body, digest, _iso(), pilot_id, tenant_id),
    )
    c.execute(
        """INSERT INTO execution_pilot_approvals(id,pilot_id,tenant_id,role,actor_id,decision,note,created_at)
           VALUES (?,?,?,?,?,?,?,?)""",
        (str(uuid.uuid4()), pilot_id, tenant_id, "approver", approver_id, "approved", note, _iso()),
    )
    _ops_audit(c, tenant_id=tenant_id, actor_id=approver_id, event="pilot_approved", pilot_id=pilot_id, detail={"manifest_hash": digest})
    return public_manifest(c, tenant_id=tenant_id, pilot_id=pilot_id)


def _load_prep(c: sqlite3.Connection, tenant_id: str, pilot_id: str):
    row = c.execute(
        "SELECT * FROM execution_pilot_preparations WHERE pilot_id=? AND tenant_id=?",
        (pilot_id, tenant_id),
    ).fetchone()
    if row is None:
        raise PilotOpsDenied("pilot preparation not found for this tenant")
    return row


def expire_if_needed(c: sqlite3.Connection, row) -> None:
    expires = _parse_iso(row["expires_at"])
    if expires and _now() > expires and row["status"] == "PREPARED":
        c.execute(
            "UPDATE execution_pilot_preparations SET status='EXPIRED', updated_at=? WHERE pilot_id=?",
            (_iso(), row["pilot_id"]),
        )


def public_manifest(c: sqlite3.Connection, *, tenant_id: str, pilot_id: str) -> dict[str, Any]:
    row = _load_prep(c, tenant_id, pilot_id)
    status = row["status"]
    expires = _parse_iso(row["expires_at"])
    if expires and _now() > expires and status == "PREPARED":
        status = "EXPIRED"
    manifest = json.loads(row["manifest_json"])
    if manifest.get("status") == "ACTIVE":
        raise PilotOpsDenied("ACTIVE status is forbidden in Stage 4B")
    return {
        "pilot_id": row["pilot_id"],
        "tenant_id": row["tenant_id"],
        "adapter_id": row["adapter_id"],
        "status": status,
        "destination_hash": row["destination_hash"],
        "hostname_suffix": row["hostname_suffix"],
        "signing_key_id": row["signing_key_id"],
        "proposer": row["proposer_id"],
        "approver": row["approver_id"],
        "not_before": row["not_before"],
        "expires_at": row["expires_at"],
        "maximum_requests": row["max_requests"],
        "manifest_hash": row["manifest_hash"],
        "reason": row["reason"],
        "change_ref": row["change_ref"],
        "rollback_ref": row["rollback_ref"],
        "external_execution_enabled": False,
        "active": False,
    }


def verify_manifest_integrity(c: sqlite3.Connection, *, tenant_id: str, pilot_id: str) -> dict[str, Any]:
    row = _load_prep(c, tenant_id, pilot_id)
    payload = json.loads(row["manifest_json"])
    _, digest = _canonical_manifest(payload)
    if digest != row["manifest_hash"]:
        raise PilotOpsDenied("manifest hash mismatch")
    if payload.get("tenant_id") != tenant_id:
        raise PilotOpsDenied("manifest tenant mismatch")
    if payload.get("adapter_id") != ADAPTER_ID:
        raise PilotOpsDenied("manifest adapter must be webhook.post")
    if payload.get("status") not in {"PREPARED"}:
        raise PilotOpsDenied("manifest status is not PREPARED")
    return {"ok": True, "manifest_hash": digest}


def activation_precheck(
    c: sqlite3.Connection,
    *,
    tenant_id: str,
    pilot_id: str,
    destination_hash_value: str | None = None,
    signing_key_id: str | None = None,
    hostname_suffix: str | None = None,
) -> dict[str, Any]:
    ensure_stage4b_schema(c)
    row = _load_prep(c, tenant_id, pilot_id)
    expire_if_needed(c, row)
    row = _load_prep(c, tenant_id, pilot_id)
    if row["status"] != "PREPARED":
        raise PilotOpsDenied(f"precheck denied: status {row['status']}")
    verify_manifest_integrity(c, tenant_id=tenant_id, pilot_id=pilot_id)
    if not row["approver_id"] or row["approver_id"] == row["proposer_id"]:
        raise PilotOpsDenied("two-person approval is incomplete")
    if destination_hash_value and destination_hash_value != row["destination_hash"]:
        raise PilotOpsDenied("destination hash mismatch")
    if signing_key_id and signing_key_id != row["signing_key_id"]:
        raise PilotOpsDenied("signing key id mismatch")
    if hostname_suffix and hostname_suffix != row["hostname_suffix"]:
        raise PilotOpsDenied("hostname suffix mismatch")
    readiness = assess_pilot_readiness(
        c,
        tenant_id=tenant_id,
        destination_hash_value=row["destination_hash"],
        hostname_suffix=row["hostname_suffix"],
        signing_key_id=row["signing_key_id"],
        pilot_id=pilot_id,
        manifest_hash=row["manifest_hash"],
    )
    if readiness["overall"] != "PASS":
        raise PilotOpsDenied(f"readiness is {readiness['overall']}")
    return {
        "ok": True,
        "pilot_id": pilot_id,
        "status": "PREPARED",
        "activated": False,
        "external_execution_enabled": False,
        "readiness": readiness["overall"],
    }


def emergency_global_shutdown(
    c: sqlite3.Connection,
    *,
    actor_id: str,
    role: str,
    reason: str,
) -> None:
    if role not in PLATFORM_ROLES:
        raise PilotOpsDenied("global kill switch requires a platform operator")
    set_kill_switch(c, scope="global", enabled=True, reason=reason, actor_id=actor_id)


def emergency_shutdown(
    c: sqlite3.Connection,
    *,
    tenant_id: str,
    actor_id: str,
    role: str,
    reason: str,
    pilot_id: str | None = None,
) -> dict[str, Any]:
    ensure_stage4b_schema(c)
    _require_role(role)
    if role not in OPERATOR_ROLES:
        raise PilotOpsDenied("role is not authorised for emergency shutdown")
    set_kill_switch(c, scope="tenant_adapter", enabled=True, reason=reason, actor_id=actor_id, tenant_id=tenant_id, adapter_id=ADAPTER_ID)
    if pilot_id:
        c.execute(
            """UPDATE execution_pilot_preparations
               SET status='SUSPENDED', last_denial=?, updated_at=?
               WHERE pilot_id=? AND tenant_id=? AND status='PREPARED'""",
            (reason, _iso(), pilot_id, tenant_id),
        )
        c.execute(
            """INSERT INTO execution_pilot_approvals(id,pilot_id,tenant_id,role,actor_id,decision,note,created_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (str(uuid.uuid4()), pilot_id, tenant_id, "shutdown", actor_id, "revoked", reason, _iso()),
        )
    else:
        c.execute(
            """UPDATE execution_pilot_preparations
               SET status='SUSPENDED', last_denial=?, updated_at=?
               WHERE tenant_id=? AND status='PREPARED'""",
            (reason, _iso(), tenant_id),
        )
    _ops_audit(c, tenant_id=tenant_id, actor_id=actor_id, event="pilot_emergency_shutdown", pilot_id=pilot_id, detail={"reason": reason})
    return shutdown_status(c, tenant_id=tenant_id)


def shutdown_status(c: sqlite3.Connection, *, tenant_id: str) -> dict[str, Any]:
    ensure_stage4b_schema(c)
    prepared = c.execute(
        "SELECT COUNT(*) AS n FROM execution_pilot_preparations WHERE tenant_id=? AND status='PREPARED'",
        (tenant_id,),
    ).fetchone()["n"]
    attempts = c.execute("SELECT COUNT(*) AS n FROM execution_attempts WHERE tenant_id=?", (tenant_id,)).fetchone()["n"]
    receipts = c.execute("SELECT COUNT(*) AS n FROM execution_receipts WHERE tenant_id=?", (tenant_id,)).fetchone()["n"]
    effective = _tenant_kill_active(c, tenant_id, ADAPTER_ID) and prepared == 0
    return {
        "shutdown_effective": bool(effective),
        "global_kill_active": _global_kill_active(c),
        "tenant_adapter_kill_active": _tenant_kill_active(c, tenant_id, ADAPTER_ID),
        "prepared_remaining": prepared,
        "attempts_preserved": attempts,
        "receipts_preserved": receipts,
        "new_claims_blocked": True,
        "external_execution_enabled": False,
        "production_provider": type(get_provider(get_adapter(ADAPTER_ID))).__name__,
    }


def claims_blocked(c: sqlite3.Connection, tenant_id: str) -> bool:
    return _global_kill_active(c) or _tenant_kill_active(c, tenant_id, ADAPTER_ID)


def observability(
    c: sqlite3.Connection,
    *,
    tenant_id: str,
    pilot_id: str | None = None,
) -> dict[str, Any]:
    ensure_stage4b_schema(c)
    readiness = assess_pilot_readiness(c, tenant_id=tenant_id, pilot_id=pilot_id)
    kill = {
        "global": _global_kill_active(c),
        "tenant_adapter": _tenant_kill_active(c, tenant_id, ADAPTER_ID),
    }
    circuit = circuit_open(c, tenant_id, ADAPTER_ID)
    rate = c.execute(
        "SELECT COALESCE(SUM(tenant_count),0) AS used FROM execution_pilot_rate WHERE tenant_id=?",
        (tenant_id,),
    ).fetchone()
    used = int(rate["used"] if rate else 0)
    uncertain = c.execute(
        "SELECT id,state,updated_at FROM execution_attempts WHERE tenant_id=? AND state='UNCERTAIN'",
        (tenant_id,),
    ).fetchall()
    submitting = c.execute(
        "SELECT id,state,updated_at FROM execution_attempts WHERE tenant_id=? AND state='SUBMITTING'",
        (tenant_id,),
    ).fetchall()
    receipts = []
    last_denial = None
    manifest = None
    if pilot_id:
        row = _load_prep(c, tenant_id, pilot_id)
        last_denial = row["last_denial"]
        manifest = public_manifest(c, tenant_id=tenant_id, pilot_id=pilot_id)
        for attempt in c.execute("SELECT id FROM execution_attempts WHERE tenant_id=?", (tenant_id,)).fetchall():
            receipts.extend([public_receipt(r) for r in list_receipts_for_attempt(c, attempt["id"], tenant_id)])
    state = classify_provider_state(c, tenant_id)
    return {
        "readiness_overall": readiness["overall"],
        "checks": readiness["checks"],
        "manifest": manifest,
        "kill_switches": kill,
        "circuit_open": circuit,
        "request_count": used,
        "remaining_allowance": max(5 - used, 0),
        "uncertain_attempts": [{"attempt_id": r["id"], "state": r["state"]} for r in uncertain],
        "submitting_attempts": [{"attempt_id": r["id"], "state": r["state"]} for r in submitting],
        "receipts": receipts,
        "last_denial_reason": last_denial,
        "production_execution_selectable": state["production_execution_selectable"],
        "production_provider": state["production_provider"],
        "provider_state": state["provider_state"],
        "external_execution_enabled": False,
        "destination": None,
        "signing_secret": None,
    }


def invoke_closing(factory, fn):
    c = factory()
    try:
        return fn(c)
    finally:
        c.close()


def assert_no_activation_route() -> dict[str, Any]:
    return {
        "stage4c_activation_route": False,
        "prepared_can_become_active": False,
        "external_execution_enabled": False,
    }
