"""Phase 3 Stage 4D — operational readiness, offline drills and redacted evidence.

Merge and bootstrap activate nothing. No public routes. ClosedProvider remains default.
"""
from __future__ import annotations

import os
import sqlite3
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from intelligence.execution import _iso, _now, _parse_iso
from intelligence.execution_adapters import get_adapter
from intelligence.execution_live import LIVE_ENV_SWITCH, _global_kill_active, _tenant_kill_active
from intelligence.execution_pilot_activation import (
    ACTION,
    ACTIVATION_ENV,
    ADAPTER_ID,
    ActivationDenied,
    PlatformPrincipal,
    _require_principal,
    assert_no_http_activation_route,
    suspend_pilot,
)
from intelligence.execution_pilot_ops import emergency_global_shutdown, emergency_shutdown, lookup_guardian_evidence
from intelligence.execution_pilot_reconciliation import (
    ReconciliationDenied,
    assert_no_public_4c2_routes,
    maintain_pilot_runtime,
    record_reconciliation,
)
from intelligence.execution_production_webhook import PILOT_FLAG, PILOT_KEY_ID_ENV, circuit_open, select_production_provider
from intelligence.execution_providers import ClosedProvider, get_provider
from intelligence.guardian import GUARDIAN_POLICY_VERSION, guardian_policy_hash


DRILL_TENANT_PREFIX = "drill-"
DRILL_HOSTS = {"hooks.drill.invalid", "sink.drill.invalid"}
RAILWAY_PATH_MARKERS = ("/data/", "/mnt/", "/var/lib/", "/app/data")


class ReadinessDenied(ActivationDenied):
    """Stage 4D readiness or drill denied."""


def _check(name: str, status: str, detail: str) -> dict[str, str]:
    return {"name": name, "status": status, "detail": detail}


def _mask_host(host: str | None) -> str | None:
    if not host:
        return None
    if "." in host:
        return "*." + host.split(".", 1)[1]
    return "***"


def _canonical_drill_host(destination: str) -> str:
    raw = (destination or "").strip()
    parts = urlsplit(raw)
    if parts.scheme != "https" or not parts.netloc:
        raise ReadinessDenied("drill destination must be https")
    if parts.username or parts.password:
        raise ReadinessDenied("drill destination must not contain userinfo")
    if parts.query or parts.fragment:
        raise ReadinessDenied("drill destination must not contain query or fragment")
    if parts.port not in (None, 443):
        raise ReadinessDenied("drill destination port must be 443")
    host = (parts.hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
    if host not in DRILL_HOSTS:
        raise ReadinessDenied("drill destination hostname is not a permitted synthetic host")
    return host


def _same_file(path_a: str, path_b: str) -> bool:
    try:
        a = Path(path_a).resolve()
        b = Path(path_b).resolve()
    except OSError:
        return os.path.normpath(path_a) == os.path.normpath(path_b)
    if a == b:
        return True
    try:
        sa, sb = a.stat(), b.stat()
        return (sa.st_dev, sa.st_ino) == (sb.st_dev, sb.st_ino)
    except OSError:
        return False


def connection_db_path(c: sqlite3.Connection) -> str | None:
    row = c.execute("PRAGMA database_list").fetchone()
    if row is None:
        return None
    return row["file"] if "file" in row.keys() else row[2]


def assert_drill_environment(
    *,
    db_path: str,
    tenant_id: str,
    destination: str,
    connection: sqlite3.Connection | None = None,
    allow_memory: bool = False,
) -> None:
    raw_env = os.getenv("ZORVIAN_ENV")
    if raw_env is None or not str(raw_env).strip():
        raise ReadinessDenied("drill requires explicit ZORVIAN_ENV")
    env = str(raw_env).strip().lower()
    if env not in {"test", "ci"}:
        raise ReadinessDenied("drill refuses this environment")
    if (os.getenv("ZORVIAN_EXTERNAL_EXECUTION") or "").strip():
        raise ReadinessDenied("drill refuses an enabled external-execution switch")
    if (os.getenv("STAGE4D_DRILL") or "").strip().lower() not in {"1", "true", "yes", "on"}:
        raise ReadinessDenied("explicit drill flag is required")
    if not (tenant_id or "").startswith(DRILL_TENANT_PREFIX):
        raise ReadinessDenied("drill requires a synthetic drill tenant")
    _canonical_drill_host(destination)
    if not db_path:
        raise ReadinessDenied("empty/unknown database identity")
    if db_path == ":memory:":
        if not allow_memory:
            raise ReadinessDenied(":memory: is not a permitted drill database")
        return
    resolved = str(Path(db_path).resolve())
    configured = (os.getenv("SQLITE_PATH") or "").strip()
    if configured:
        if _same_file(resolved, configured) or _same_file(db_path, configured):
            raise ReadinessDenied("drill refuses the configured production database")
    if any(marker in resolved for marker in RAILWAY_PATH_MARKERS):
        raise ReadinessDenied("drill refuses a persistent production data path")
    if connection is not None:
        listed = connection_db_path(connection) or ""
        if listed and not _same_file(listed, resolved):
            raise ReadinessDenied("connection path mismatch")


def _process_gate_status(*, for_activation: bool) -> dict[str, str]:
    switch = (os.getenv(LIVE_ENV_SWITCH) or "").strip().lower()
    flag = (os.getenv(PILOT_FLAG) or "").strip().lower()
    if for_activation:
        if not switch or not flag:
            return _check("process_switches", "NOT_READY", "required switches absent")
        if switch != "pilot" or flag not in {"1", "true", "on", "yes"}:
            return _check("process_switches", "FAIL", "unexpected or partial configuration")
        return _check("process_switches", "FAIL", "activation_permitted remains false")
    if switch or flag:
        return _check("process_switches", "FAIL", "unexpected process configuration")
    return _check("process_switches", "PASS", "absent")


def render_stage4d_readiness(
    c: sqlite3.Connection,
    *,
    principal: PlatformPrincipal,
    tenant_id: str,
    pilot_id: str,
) -> dict[str, Any]:
    """SELECT-only redacted readiness. Never installs schema or mutates env."""
    _require_principal(principal)
    checks: list[dict[str, str]] = []
    prep = c.execute(
        "SELECT * FROM execution_pilot_preparations WHERE pilot_id=? AND tenant_id=?",
        (pilot_id, tenant_id),
    ).fetchone()
    if prep is None:
        checks.append(_check("preparation", "FAIL", "pilot preparation not found"))
        return _payload(tenant_id, pilot_id, None, checks)

    checks.append(_check("preparation", "PASS" if prep["status"] in {"PREPARED", "ACTIVE", "SUSPENDED"} else "FAIL", prep["status"]))
    checks.append(_check("manifest_hash", "PASS" if prep["manifest_hash"] else "FAIL", "present" if prep["manifest_hash"] else "missing"))
    checks.append(_check("adapter", "PASS" if prep["adapter_id"] == ADAPTER_ID and prep["action"] == ACTION else "FAIL", prep["adapter_id"]))
    checks.append(_check("destination_masked", "PASS", _mask_host(prep["hostname_suffix"]) or "absent"))

    evidence = lookup_guardian_evidence(
        c,
        pilot_id=pilot_id,
        tenant_id=tenant_id,
        destination_hash_value=prep["destination_hash"],
        manifest_hash=prep["manifest_hash"],
    )
    checks.append(_check("guardian", evidence["status"], evidence.get("detail") or evidence["status"]))
    bind = c.execute(
        "SELECT * FROM execution_pilot_guardian_bindings WHERE pilot_id=? AND tenant_id=? ORDER BY created_at DESC LIMIT 1",
        (pilot_id, tenant_id),
    ).fetchone()
    assessment = None
    if bind:
        assessment = c.execute(
            "SELECT * FROM guardian_assessments WHERE guardian_assessment_id=?",
            (bind["guardian_assessment_id"],),
        ).fetchone()
    stored_policy = assessment["policy_version"] if assessment and "policy_version" in assessment.keys() else None
    stored_hash = assessment["policy_hash"] if assessment and "policy_hash" in assessment.keys() else None
    stored_ctx = assessment["context_hash"] if assessment and "context_hash" in assessment.keys() else None
    if stored_policy != GUARDIAN_POLICY_VERSION or stored_hash != guardian_policy_hash() or not stored_ctx:
        checks.append(_check("policy_match", "FAIL", "stored policy or context does not match current authority"))
    else:
        checks.append(_check("policy_match", "PASS", "stored policy matches"))

    approvals = c.execute(
        "SELECT role, actor_id, created_at FROM execution_pilot_platform_approvals WHERE pilot_id=?",
        (pilot_id,),
    ).fetchall()
    roles = {row["role"] for row in approvals}
    checks.append(_check("platform_owner_approval", "PASS" if "platform_owner" in roles else "FAIL", str(len(approvals))))
    checks.append(_check("security_operator_approval", "PASS" if "security_operator" in roles else "FAIL", str(len(approvals))))
    stale = False
    for row in approvals:
        created = _parse_iso(row["created_at"])
        if created is None or created < _now() - timedelta(hours=24):
            stale = True
    checks.append(_check("approval_freshness", "FAIL" if stale or not approvals else "PASS", "stale" if stale else "fresh"))

    act = c.execute(
        "SELECT * FROM execution_pilot_activations WHERE pilot_id=? AND tenant_id=?",
        (pilot_id, tenant_id),
    ).fetchone()
    challenge = c.execute(
        """SELECT * FROM execution_pilot_activation_challenges
           WHERE pilot_id=? AND tenant_id=? ORDER BY created_at DESC LIMIT 1""",
        (pilot_id, tenant_id),
    ).fetchone()
    checks.append(_classify_challenge(challenge, prep, assessment, approvals, act=act))
    checks.extend(_classify_activation(c, act, prep, assessment, tenant_id))

    active_n = c.execute(
        "SELECT COUNT(*) AS n FROM execution_pilot_activations WHERE tenant_id=? AND adapter_id=? AND status='ACTIVE'",
        (tenant_id, ADAPTER_ID),
    ).fetchone()["n"]
    checks.append(_check("ambiguous_activation", "FAIL" if active_n > 1 else "PASS", str(active_n)))
    checks.append(_check("kill_switch", "FAIL" if _global_kill_active(c) or _tenant_kill_active(c, tenant_id, ADAPTER_ID) else "PASS", "clear"))
    checks.append(_check("circuit", "FAIL" if circuit_open(c, tenant_id, ADAPTER_ID) else "PASS", "closed"))
    uncertain = c.execute(
        "SELECT COUNT(*) AS n FROM execution_attempts WHERE tenant_id=? AND pilot_id=? AND state='UNCERTAIN'",
        (tenant_id, pilot_id),
    ).fetchone()["n"]
    checks.append(_check("uncertain_attempts", "UNKNOWN" if uncertain else "PASS", str(uncertain)))
    checks.append(_process_gate_status(for_activation=True))
    checks.append(_check("external_execution_enabled", "PASS", "false"))
    failed = any(item["status"] in {"FAIL", "NOT_READY"} for item in checks)
    return _payload(tenant_id, pilot_id, prep, checks, overall="FAIL" if failed else "UNKNOWN")


def _classify_challenge(challenge, prep, assessment, approvals, act=None) -> dict[str, str]:
    if challenge is None:
        return _check("challenge", "FAIL", "absent")
    if challenge["manifest_hash"] != prep["manifest_hash"]:
        return _check("challenge", "FAIL", "manifest mismatch")
    def _present(value) -> bool:
        return value is not None and str(value).strip() != ""

    ctx = assessment["context_hash"] if assessment and "context_hash" in assessment.keys() else None
    stored_ctx = challenge["guardian_context_hash"] if "guardian_context_hash" in challenge.keys() else None
    if not _present(stored_ctx) or not _present(ctx) or stored_ctx != ctx:
        return _check("challenge", "FAIL", "context mismatch")
    actors = {row["actor_id"] for row in approvals}
    if challenge["owner_actor_id"] not in actors or challenge["security_actor_id"] not in actors:
        return _check("challenge", "FAIL", "approver mismatch")
    expires = _parse_iso(challenge["expires_at"])
    expired = expires is None or expires <= _now()
    status = act["status"] if act else None
    if status in {"SUSPENDED", "EXPIRED", "QUOTA_EXHAUSTED"}:
        return _check("challenge", "FAIL", "activation-not-ready")
    if status == "ACTIVE":
        if expired:
            return _check("challenge", "FAIL", "expired")
        if not challenge["consumed_at"]:
            return _check("challenge", "FAIL", "active-requires-consumed-challenge")
        act_cid = act["challenge_id"] if "challenge_id" in act.keys() else None
        chal_id = challenge["challenge_id"] if "challenge_id" in challenge.keys() else None
        if not _present(act_cid) or not _present(chal_id) or act_cid != chal_id:
            return _check("challenge", "FAIL", "unbound")
        return _check("challenge", "PASS", "consumed-once")
    if expired:
        return _check("challenge", "FAIL", "expired")
    if challenge["consumed_at"]:
        return _check("challenge", "FAIL", "consumed-before-activation")
    return _check("challenge", "PASS", "valid-open")


def _classify_activation(c, act, prep, assessment, tenant_id) -> list[dict[str, str]]:
    out = []
    grant = c.execute(
        "SELECT enabled FROM execution_live_grants WHERE tenant_id=? AND adapter_id=? AND action=? AND env=?",
        (tenant_id, ADAPTER_ID, ACTION, ACTIVATION_ENV),
    ).fetchone()
    allow = c.execute(
        "SELECT COUNT(*) AS n FROM execution_destination_allowlist WHERE tenant_id=? AND adapter_id=? AND destination_hash=?",
        (tenant_id, ADAPTER_ID, prep["destination_hash"]),
    ).fetchone()["n"]
    if act is None:
        out.append(_check("activation", "FAIL", "absent"))
        out.append(_check("orphan_grant", "FAIL" if grant and grant["enabled"] else "PASS", "none"))
        out.append(_check("orphan_allowlist", "FAIL" if allow else "PASS", str(allow)))
        return out
    if act["status"] != "ACTIVE":
        out.append(_check("activation", "FAIL", act["status"]))
    else:
        expires = _parse_iso(act["expires_at"])
        exhausted = int(act["successes_claimed"] or 0) >= int(act["max_successes"] or 1)
        match = (
            act["tenant_id"] == tenant_id
            and act["pilot_id"] == prep["pilot_id"]
            and act["adapter_id"] == ADAPTER_ID
            and act["destination_hash"] == prep["destination_hash"]
            and act["manifest_hash"] == prep["manifest_hash"]
            and act["signing_key_id"] == prep["signing_key_id"]
        )
        gctx = assessment["context_hash"] if assessment and "context_hash" in assessment.keys() else None
        gid = assessment["guardian_assessment_id"] if assessment else None
        stored_ctx = act["guardian_context_hash"] if "guardian_context_hash" in act.keys() else None
        stored_gid = act["guardian_assessment_id"] if "guardian_assessment_id" in act.keys() else None
        stored_pv = act["policy_version"] if "policy_version" in act.keys() else None
        stored_ph = act["policy_hash"] if "policy_hash" in act.keys() else None
        def _present(value) -> bool:
            return value is not None and str(value).strip() != ""

        policy_ok = (
            _present(stored_gid) and stored_gid == gid
            and _present(stored_ctx) and stored_ctx == gctx
            and _present(stored_pv) and stored_pv == GUARDIAN_POLICY_VERSION
            and _present(stored_ph) and stored_ph == guardian_policy_hash()
            and _present(gid) and _present(gctx)
        )
        if expires is None or expires <= _now():
            out.append(_check("activation", "FAIL", "expired"))
        elif exhausted:
            out.append(_check("activation", "FAIL", "quota-exhausted"))
        elif not match or not policy_ok:
            out.append(_check("activation", "FAIL", "binding mismatch"))
        else:
            out.append(_check("activation", "PASS", "ACTIVE"))
    if act["status"] == "ACTIVE":
        out.append(_check("grant_matches_activation", "PASS" if grant and grant["enabled"] else "FAIL", "enabled" if grant and grant["enabled"] else "missing"))
        out.append(_check("allowlist_matches_activation", "PASS" if allow else "FAIL", str(allow)))
    else:
        out.append(_check("orphan_grant", "FAIL" if grant and grant["enabled"] else "PASS", "closed"))
        out.append(_check("orphan_allowlist", "FAIL" if allow else "PASS", str(allow)))
    return out


def _payload(tenant_id, pilot_id, prep, checks, overall: str = "FAIL") -> dict[str, Any]:
    return {
        "tenant_id": tenant_id,
        "pilot_id": pilot_id,
        "preparation_status": prep["status"] if prep else "absent",
        "manifest_hash": prep["manifest_hash"] if prep else None,
        "destination": _mask_host(prep["hostname_suffix"]) if prep else None,
        "checks": checks,
        "overall": overall,
        "activation_permitted": False,
        "external_execution_enabled": False,
        "signing_secret": None,
        "confirmation_token": None,
        "authorization": None,
        "payload": None,
    }


def verify_deployment_default_off(c: sqlite3.Connection | None = None) -> dict[str, Any]:
    adapter = get_adapter("webhook.post")
    provider = get_provider(adapter)
    routes = {**assert_no_http_activation_route(), **assert_no_public_4c2_routes()}
    checks = [
        _check("closed_provider", "PASS" if isinstance(provider, ClosedProvider) else "FAIL", type(provider).__name__),
        _check("external_switch", "PASS" if not (os.getenv("ZORVIAN_EXTERNAL_EXECUTION") or "").strip() else "FAIL", "absent"),
        _process_gate_status(for_activation=False),
        _check("no_activate_route", "PASS" if not routes.get("activate_route") else "FAIL", "absent"),
        _check("no_reconcile_route", "PASS" if not routes.get("reconcile_route") else "FAIL", "absent"),
    ]
    if c is not None:
        active = c.execute("SELECT COUNT(*) AS n FROM execution_pilot_activations WHERE status='ACTIVE'").fetchone()["n"]
        enabled_grants = c.execute("SELECT COUNT(*) AS n FROM execution_live_grants WHERE enabled=1").fetchone()["n"]
        allow = c.execute("SELECT COUNT(*) AS n FROM execution_destination_allowlist").fetchone()["n"]
        if active > 1:
            checks.append(_check("ambiguous_activation", "FAIL", str(active)))
        elif enabled_grants and active != 1:
            checks.append(_check("enabled_grants", "FAIL", "grant without exact ACTIVE activation"))
        elif allow and active != 1:
            checks.append(_check("allowlist_rows", "FAIL", "allowlist without exact ACTIVE activation"))
        else:
            checks.append(_check("active_activations", "PASS" if active == 0 else "FAIL", str(active)))
            checks.append(_check("enabled_grants", "PASS" if enabled_grants == 0 else "FAIL", str(enabled_grants)))
            checks.append(_check("allowlist_rows", "PASS" if allow == 0 else "FAIL", str(allow)))
        tenants = {row["tenant_id"] for row in c.execute("SELECT tenant_id FROM execution_pilot_activations WHERE status='ACTIVE'").fetchall()}
        tenants.update(row["tenant_id"] for row in c.execute("SELECT tenant_id FROM execution_live_grants WHERE enabled=1").fetchall())
        selectable_ok = True
        detail = "closed"
        for tenant in tenants or {"anyone"}:
            selectable = select_production_provider(adapter, connection=c, tenant_id=tenant)
            if not isinstance(selectable, ClosedProvider):
                selectable_ok = False
                detail = f"{tenant}:{type(selectable).__name__}"
                break
        checks.append(_check("selectable_provider", "PASS" if selectable_ok else "FAIL", detail))
    failed = any(item["status"] == "FAIL" for item in checks)
    return {
        "ok": not failed,
        "overall": "FAIL" if failed else "PASS",
        "checks": checks,
        "provider": type(provider).__name__,
        "external_execution_enabled": False,
        "activation_permitted": False,
        "signing_secret": None,
    }


def require_tenant_operator(c: sqlite3.Connection, *, tenant_id: str, actor_id: str, pilot_id: str | None = None) -> str:
    """Authority comes from persisted owner/admin approval rows only."""
    sql = """SELECT role FROM execution_pilot_approvals
             WHERE tenant_id=? AND actor_id=? AND role IN ('owner','admin') AND decision='approved'"""
    params: list[Any] = [tenant_id, actor_id]
    if pilot_id:
        sql += " AND pilot_id=?"
        params.append(pilot_id)
    row = c.execute(sql + " ORDER BY created_at DESC LIMIT 1", params).fetchone()
    if row is None:
        raise ReadinessDenied("actor is not a persisted tenant owner or admin")
    return row["role"]


def run_emergency_shutdown_drill(
    c: sqlite3.Connection,
    *,
    principal: PlatformPrincipal,
    tenant_principal_id: str,
    tenant_id: str,
    other_tenant_id: str,
    pilot_id: str,
    destination: str,
    db_path: str,
) -> dict[str, Any]:
    assert_drill_environment(db_path=db_path, tenant_id=tenant_id, destination=destination, connection=c)
    _require_principal(principal)
    tenant_role = require_tenant_operator(c, tenant_id=tenant_id, actor_id=tenant_principal_id, pilot_id=pilot_id)
    global_before = _global_kill_active(c)
    other_before = c.execute("SELECT COUNT(*) AS n FROM execution_kill_switches WHERE tenant_id=?", (other_tenant_id,)).fetchone()["n"]
    emergency_shutdown(
        c, tenant_id=tenant_id, actor_id=tenant_principal_id, role=tenant_role,
        reason="stage4d-tenant-drill", pilot_id=pilot_id,
    )
    if c.in_transaction:
        c.commit()
    other_after = c.execute("SELECT COUNT(*) AS n FROM execution_kill_switches WHERE tenant_id=?", (other_tenant_id,)).fetchone()["n"]
    global_after_tenant = _global_kill_active(c)
    platform = suspend_pilot(c, pilot_id=pilot_id, principal=principal, reason="stage4d-platform-suspend")
    try:
        require_tenant_operator(c, tenant_id=tenant_id, actor_id=principal.actor_id, pilot_id=pilot_id)
        impersonated = True
    except ReadinessDenied:
        impersonated = False
    try:
        emergency_global_shutdown(c, actor_id=tenant_principal_id, role="owner", reason="should-fail")
        global_denied = False
    except Exception:
        global_denied = True
    return {
        "tenant_role": tenant_role,
        "platform_status": platform["status"],
        "tenant_isolated": other_after == other_before,
        "global_unchanged_by_tenant": global_before == global_after_tenant,
        "platform_cannot_impersonate_tenant": not impersonated,
        "tenant_cannot_global_shutdown": global_denied,
        "external_execution_enabled": False,
    }


def run_uncertain_reconciliation_drill(
    c: sqlite3.Connection,
    *,
    principal: PlatformPrincipal,
    unauthorized,
    tenant_id: str,
    other_tenant_id: str,
    pilot_id: str,
    destination: str,
    db_path: str,
    submit,
) -> dict[str, Any]:
    assert_drill_environment(db_path=db_path, tenant_id=tenant_id, destination=destination, connection=c)
    _require_principal(principal)
    first = submit()
    replay = submit()
    if first.get("state") != "UNCERTAIN":
        raise ReadinessDenied(f"expected UNCERTAIN, got {first.get('state')}")
    if not replay.get("idempotent_replay"):
        raise ReadinessDenied("replay did not remain idempotent")
    attempt = c.execute(
        "SELECT * FROM execution_attempts WHERE id=? AND tenant_id=?",
        (first["attempt_id"], tenant_id),
    ).fetchone()
    if attempt is None or attempt["pilot_id"] != pilot_id:
        raise ReadinessDenied("attempt is not bound to the exact pilot")
    with _expect_denied():
        record_reconciliation(c, principal=unauthorized, tenant_id=tenant_id, attempt_id=first["attempt_id"], decision="confirmed-failure")
    with _expect_denied():
        record_reconciliation(c, principal=principal, tenant_id=other_tenant_id, attempt_id=first["attempt_id"], decision="confirmed-failure")
    before = c.execute("SELECT COUNT(*) AS n FROM execution_pilot_reconciliations WHERE attempt_id=?", (first["attempt_id"],)).fetchone()["n"]
    rec = record_reconciliation(c, principal=principal, tenant_id=tenant_id, attempt_id=first["attempt_id"], decision="confirmed-failure")
    after = c.execute("SELECT COUNT(*) AS n FROM execution_pilot_reconciliations WHERE attempt_id=?", (first["attempt_id"],)).fetchone()["n"]
    act = c.execute("SELECT status FROM execution_pilot_activations WHERE pilot_id=?", (pilot_id,)).fetchone()
    grant = c.execute("SELECT enabled FROM execution_live_grants WHERE tenant_id=?", (tenant_id,)).fetchone()
    allow = c.execute("SELECT COUNT(*) AS n FROM execution_destination_allowlist WHERE tenant_id=?", (tenant_id,)).fetchone()["n"]
    return {
        "state": first["state"],
        "idempotent_replay": True,
        "append_only": after == before + 1,
        "suspended": act["status"] == "SUSPENDED",
        "grant_closed": grant is None or grant["enabled"] == 0,
        "allowlist_closed": allow == 0,
        "bound_pilot_id": attempt["pilot_id"],
        "provider_calls_reported_by_submit": rec.get("provider_calls", 0),
        "external_execution_enabled": False,
    }


def run_expiry_maintenance_drill(
    c: sqlite3.Connection,
    *,
    tenant_id: str,
    pilot_id: str,
    destination: str,
    db_path: str,
) -> dict[str, Any]:
    assert_drill_environment(db_path=db_path, tenant_id=tenant_id, destination=destination, connection=c)
    c.execute("UPDATE execution_pilot_activations SET expires_at=? WHERE pilot_id=?", (_iso(_now() - timedelta(minutes=1)), pilot_id))
    now = _iso(_now() - timedelta(minutes=5))
    c.execute(
        """INSERT INTO execution_attempts(id,tenant_id,plan_id,ticket_id,adapter_id,idempotency_key,state,provider_ref,created_at,updated_at,activation_id,pilot_id)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        ("stale-sub", tenant_id, "plan", "tix", ADAPTER_ID, "idem-stale", "SUBMITTING", None, now, now, None, pilot_id),
    )
    if c.in_transaction:
        c.commit()
    first = maintain_pilot_runtime(c)
    second = maintain_pilot_runtime(c)
    status = c.execute("SELECT status FROM execution_pilot_activations WHERE pilot_id=?", (pilot_id,)).fetchone()["status"]
    stale = c.execute("SELECT state FROM execution_attempts WHERE id='stale-sub'").fetchone()["state"]
    return {
        "first_closed": first.get("closed", 0),
        "second_closed": second.get("closed", 0),
        "status": status,
        "stale_state": stale,
        "idempotent": second.get("closed", 0) == 0 or status in {"EXPIRED", "SUSPENDED"},
        "external_execution_enabled": False,
    }


def _expect_denied():
    class _Guard:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            if exc_type is None:
                raise ReadinessDenied("expected denial")
            if issubclass(exc_type, (ActivationDenied, ReconciliationDenied, ReadinessDenied)):
                return True
            return False
    return _Guard()


def export_redacted_evidence(
    c: sqlite3.Connection,
    *,
    principal: PlatformPrincipal,
    tenant_id: str,
    pilot_id: str,
    base_commit: str,
) -> dict[str, Any]:
    _require_principal(principal)
    readiness = render_stage4d_readiness(c, principal=principal, tenant_id=tenant_id, pilot_id=pilot_id)
    prep = c.execute(
        "SELECT pilot_id, status, manifest_hash, destination_hash, adapter_id, created_at FROM execution_pilot_preparations WHERE pilot_id=? AND tenant_id=?",
        (pilot_id, tenant_id),
    ).fetchone()
    act = c.execute(
        "SELECT activation_id, status, expires_at, successes_claimed, guardian_assessment_id, guardian_context_hash FROM execution_pilot_activations WHERE pilot_id=? AND tenant_id=?",
        (pilot_id, tenant_id),
    ).fetchone()
    bind = c.execute(
        "SELECT guardian_assessment_id FROM execution_pilot_guardian_bindings WHERE pilot_id=? AND tenant_id=?",
        (pilot_id, tenant_id),
    ).fetchone()
    approvals = c.execute(
        "SELECT role, created_at FROM execution_pilot_platform_approvals WHERE pilot_id=?",
        (pilot_id,),
    ).fetchall()
    attempts = c.execute(
        "SELECT id, state, activation_id, pilot_id FROM execution_attempts WHERE tenant_id=? AND pilot_id=?",
        (tenant_id, pilot_id),
    ).fetchall()
    recon = c.execute(
        "SELECT decision, created_at FROM execution_pilot_reconciliations WHERE tenant_id=? AND pilot_id=?",
        (tenant_id, pilot_id),
    ).fetchall()
    audits = c.execute(
        "SELECT event, created_at FROM execution_pilot_ops_audit WHERE tenant_id=? AND (pilot_id=? OR pilot_id IS NULL)",
        (tenant_id, pilot_id),
    ).fetchall()
    closure = c.execute(
        "SELECT event, created_at FROM execution_pilot_closure_audit WHERE tenant_id=? AND (pilot_id=? OR pilot_id IS NULL)",
        (tenant_id, pilot_id),
    ).fetchall()
    return {
        "base_commit": base_commit,
        "generated_at": _iso(),
        "pilot_id": pilot_id,
        "tenant_id": tenant_id,
        "manifest_hash": prep["manifest_hash"] if prep else None,
        "destination_hash": prep["destination_hash"] if prep else None,
        "guardian_assessment_id": (act["guardian_assessment_id"] if act else None) or (bind["guardian_assessment_id"] if bind else None),
        "guardian_context_hash": act["guardian_context_hash"] if act else None,
        "activation_id": act["activation_id"] if act else None,
        "approvals": [dict(row) for row in approvals],
        "activation_status": act["status"] if act else "absent",
        "readiness_checks": readiness["checks"],
        "readiness": readiness["overall"],
        "attempts": [{"attempt_id": row["id"], "state": row["state"]} for row in attempts],
        "reconciliations": [dict(row) for row in recon],
        "shutdown_audit": [dict(row) for row in audits],
        "maintenance_audit": [dict(row) for row in closure],
        "destination": readiness["destination"],
        "signing_secret": None,
        "confirmation_token": None,
        "payload": None,
        "authorization": None,
        "external_execution_enabled": False,
        "activation_permitted": False,
    }
