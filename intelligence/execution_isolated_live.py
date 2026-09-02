"""Phase 3 Stage 3 — isolated-CI webhook live lifecycle.

Internal-only. Production get_provider stays ClosedProvider. External
execution remains disabled. No public live endpoint.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from datetime import timedelta
from typing import Any
from urllib.parse import urlsplit

from intelligence.execution import (
    consume_execution_ticket,
    load_ticket,
    _iso,
    _now,
    _parse_iso,
)
from intelligence.execution_adapters import (
    destination_hash,
    get_adapter,
    load_plan,
    payload_hash,
    validate_plan_bound_approval,
    _append_evidence,
    _record_control_event,
    _update_plan_status,
)
from intelligence.execution_ci_sink import (
    DEFAULT_TIMEOUT_SECONDS,
    ISOLATED_CI_HOSTNAME,
    ISOLATED_CI_PINNED_IP,
    IsolatedCiDenied,
    IsolatedCiUncertain,
    IsolatedTlsResponse,
    ScriptedTransport,
    isolated_tls_post,
)
from intelligence.execution_live import (
    ALLOWED_TRANSITIONS,
    LIVE_STATES,
    LiveDenied,
    consume_confirmation_token,
    ensure_phase3_schema,
    persist_resolution,
    process_live_switch_enabled,
    transition_plan_status,
    _audit,
    _global_kill_active,
    _guardian_ok,
    _require_role,
    _tenant_kill_active,
)
from intelligence.execution_providers import ClosedProvider, ProviderDenied, get_provider
from intelligence.execution_providers_webhook import (
    DestinationDenied,
    IsolatedWebhookProvider,
    NullResolver,
    classify_ip,
    validate_hardened_webhook_destination,
)
from intelligence.execution_receipts import record_receipt


ISOLATED_ENV_SWITCH = "ZORVIAN_ISOLATED_CI_EXECUTION"
CIRCUIT_FAILURE_THRESHOLD = 5
RATE_LIMIT_PER_WINDOW = 20
RATE_WINDOW_SECONDS = 60
MAX_IN_FLIGHT = 1
STALE_SUBMITTING_SECONDS = 30

_process_lock = threading.Lock()


class IsolatedLiveDenied(LiveDenied):
    pass


def isolated_ci_enabled() -> bool:
    value = (os.getenv(ISOLATED_ENV_SWITCH) or "").strip().lower()
    return value in {"1", "true", "on", "isolated", "ci"}


def ensure_isolated_schema(c: sqlite3.Connection) -> None:
    ensure_phase3_schema(c)
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS execution_isolated_attempts(
            attempt_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            plan_id TEXT NOT NULL,
            ticket_id TEXT NOT NULL,
            idempotency_key TEXT NOT NULL,
            provider_submitted INTEGER NOT NULL DEFAULT 0,
            submit_count INTEGER NOT NULL DEFAULT 0,
            last_http_status INTEGER,
            cancel_requested INTEGER NOT NULL DEFAULT 0,
            pinned_ip TEXT,
            hostname TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(tenant_id, idempotency_key)
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS execution_circuit_breakers(
            tenant_id TEXT NOT NULL,
            adapter_id TEXT NOT NULL,
            failures INTEGER NOT NULL DEFAULT 0,
            open INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(tenant_id, adapter_id)
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS execution_rate_windows(
            tenant_id TEXT NOT NULL,
            adapter_id TEXT NOT NULL,
            window_start TEXT NOT NULL,
            count INTEGER NOT NULL DEFAULT 0,
            in_flight INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(tenant_id, adapter_id)
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS execution_isolated_grants(
            tenant_id TEXT NOT NULL,
            adapter_id TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            PRIMARY KEY(tenant_id, adapter_id)
        )
        """
    )


def grant_isolated_ci(c: sqlite3.Connection, *, tenant_id: str, adapter_id: str = "webhook.post") -> None:
    ensure_isolated_schema(c)
    c.execute(
        """INSERT INTO execution_isolated_grants(tenant_id,adapter_id,enabled,created_at)
           VALUES (?,?,1,?)
           ON CONFLICT(tenant_id,adapter_id) DO UPDATE SET enabled=1""",
        (tenant_id, adapter_id, _iso()),
    )


def _isolated_grant(c: sqlite3.Connection, tenant_id: str, adapter_id: str) -> bool:
    row = c.execute(
        "SELECT enabled FROM execution_isolated_grants WHERE tenant_id=? AND adapter_id=? AND enabled=1",
        (tenant_id, adapter_id),
    ).fetchone()
    return bool(row and row["enabled"])


def evaluate_isolated_gates(
    c: sqlite3.Connection,
    *,
    tenant_id: str,
    adapter_id: str,
) -> None:
    if process_live_switch_enabled():
        raise IsolatedLiveDenied("production external execution switch must remain off for isolated CI")
    if not isolated_ci_enabled():
        raise IsolatedLiveDenied("isolated CI execution switch is off")
    if _global_kill_active(c):
        raise IsolatedLiveDenied("global kill switch is active")
    if _tenant_kill_active(c, tenant_id, adapter_id):
        raise IsolatedLiveDenied("tenant kill switch is active")
    if adapter_id != "webhook.post":
        raise IsolatedLiveDenied("Stage 3 isolated live is webhook.post only")
    if not _isolated_grant(c, tenant_id, adapter_id):
        raise IsolatedLiveDenied("isolated CI grant is missing")
    breaker = c.execute(
        "SELECT open FROM execution_circuit_breakers WHERE tenant_id=? AND adapter_id=?",
        (tenant_id, adapter_id),
    ).fetchone()
    if breaker and breaker["open"]:
        raise IsolatedLiveDenied("circuit breaker is open")


def _assert_isolated_destination(destination: str) -> tuple[str, str]:
    parts = urlsplit(destination)
    host = (parts.hostname or "").lower()
    if parts.scheme != "https":
        raise DestinationDenied("isolated destination must be HTTPS")
    if host != ISOLATED_CI_HOSTNAME:
        raise DestinationDenied("isolated destination hostname is not the CI sink")
    if parts.port not in (None, 443) and parts.port != parts.port:
        raise DestinationDenied("isolated destination port is invalid")
    return host, ISOLATED_CI_PINNED_IP


def _record_failure(c: sqlite3.Connection, tenant_id: str, adapter_id: str) -> None:
    now = _iso()
    row = c.execute(
        "SELECT failures, open FROM execution_circuit_breakers WHERE tenant_id=? AND adapter_id=?",
        (tenant_id, adapter_id),
    ).fetchone()
    failures = int(row["failures"]) + 1 if row else 1
    opened = 1 if failures >= CIRCUIT_FAILURE_THRESHOLD else 0
    c.execute(
        """INSERT INTO execution_circuit_breakers(tenant_id,adapter_id,failures,open,updated_at)
           VALUES (?,?,?,?,?)
           ON CONFLICT(tenant_id,adapter_id) DO UPDATE SET
             failures=excluded.failures, open=excluded.open, updated_at=excluded.updated_at""",
        (tenant_id, adapter_id, failures, opened, now),
    )


def _clear_in_flight(c: sqlite3.Connection, tenant_id: str, adapter_id: str) -> None:
    c.execute(
        """UPDATE execution_rate_windows SET in_flight=MAX(in_flight-1,0)
           WHERE tenant_id=? AND adapter_id=?""",
        (tenant_id, adapter_id),
    )


def _claim_rate_and_concurrency(c: sqlite3.Connection, tenant_id: str, adapter_id: str) -> None:
    now = _now()
    row = c.execute(
        "SELECT window_start, count, in_flight FROM execution_rate_windows WHERE tenant_id=? AND adapter_id=?",
        (tenant_id, adapter_id),
    ).fetchone()
    if row is None:
        c.execute(
            """INSERT INTO execution_rate_windows(tenant_id,adapter_id,window_start,count,in_flight)
               VALUES (?,?,?,?,?)""",
            (tenant_id, adapter_id, _iso(now), 1, 1),
        )
        return
    started = _parse_iso(row["window_start"]) or now
    count = int(row["count"])
    in_flight = int(row["in_flight"])
    if now - started > timedelta(seconds=RATE_WINDOW_SECONDS):
        count = 0
        started = now
    if count >= RATE_LIMIT_PER_WINDOW:
        raise IsolatedLiveDenied("isolated CI rate limit exceeded")
    if in_flight >= MAX_IN_FLIGHT:
        raise IsolatedLiveDenied("isolated CI concurrency limit exceeded")
    c.execute(
        """UPDATE execution_rate_windows
           SET window_start=?, count=?, in_flight=?
           WHERE tenant_id=? AND adapter_id=?""",
        (_iso(started), count + 1, in_flight + 1, tenant_id, adapter_id),
    )


def _insert_attempt(
    c: sqlite3.Connection,
    *,
    tenant_id: str,
    plan: dict[str, Any],
    ticket_id: str,
    idempotency_key: str,
    hostname: str,
    pinned_ip: str,
) -> str:
    now = _iso()
    attempt_id = str(uuid.uuid4())
    c.execute(
        """INSERT INTO execution_attempts(
            id,tenant_id,plan_id,ticket_id,adapter_id,idempotency_key,state,provider_ref,created_at,updated_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (
            attempt_id,
            tenant_id,
            plan["execution_plan_id"],
            ticket_id,
            plan["adapter_id"],
            idempotency_key,
            "SUBMITTING",
            None,
            now,
            now,
        ),
    )
    c.execute(
        """INSERT INTO execution_isolated_attempts(
            attempt_id,tenant_id,plan_id,ticket_id,idempotency_key,provider_submitted,submit_count,
            last_http_status,cancel_requested,pinned_ip,hostname,created_at,updated_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            attempt_id,
            tenant_id,
            plan["execution_plan_id"],
            ticket_id,
            idempotency_key,
            0,
            0,
            None,
            0,
            pinned_ip,
            hostname,
            now,
            now,
        ),
    )
    return attempt_id


def _load_isolated(c: sqlite3.Connection, attempt_id: str) -> dict[str, Any] | None:
    row = c.execute(
        "SELECT * FROM execution_isolated_attempts WHERE attempt_id=?",
        (attempt_id,),
    ).fetchone()
    return dict(row) if row else None


def _load_attempt_by_key(c: sqlite3.Connection, tenant_id: str, idempotency_key: str) -> dict[str, Any] | None:
    row = c.execute(
        "SELECT * FROM execution_attempts WHERE tenant_id=? AND idempotency_key=?",
        (tenant_id, idempotency_key),
    ).fetchone()
    return dict(row) if row else None


def _set_attempt_state(c: sqlite3.Connection, attempt_id: str, tenant_id: str, state: str) -> None:
    c.execute(
        "UPDATE execution_attempts SET state=?, updated_at=? WHERE id=? AND tenant_id=?",
        (state, _iso(), attempt_id, tenant_id),
    )


def _mark_submitted(c: sqlite3.Connection, attempt_id: str) -> int:
    cur = c.execute(
        """UPDATE execution_isolated_attempts
           SET provider_submitted=1, submit_count=submit_count+1, updated_at=?
           WHERE attempt_id=? AND provider_submitted=0""",
        (_iso(), attempt_id),
    )
    return cur.rowcount


def classify_http_outcome(status: int) -> str:
    if 200 <= status < 300:
        return "EXECUTED"
    if 400 <= status < 500:
        return "FAILED"
    return "UNCERTAIN"


def recover_stale_submitting(
    c: sqlite3.Connection,
    *,
    tenant_id: str | None = None,
    older_than_seconds: int = STALE_SUBMITTING_SECONDS,
) -> list[str]:
    """Crash/stale SUBMITTING recovery. Never resubmits to the provider."""
    ensure_isolated_schema(c)
    cutoff = _now() - timedelta(seconds=older_than_seconds)
    params: list[Any] = [_iso(cutoff)]
    sql = "SELECT * FROM execution_attempts WHERE state='SUBMITTING' AND updated_at<=?"
    if tenant_id:
        sql += " AND tenant_id=?"
        params.append(tenant_id)
    rows = c.execute(sql, params).fetchall()
    recovered = []
    for row in rows:
        nxt = transition_plan_status("SUBMITTING", "UNCERTAIN")
        _set_attempt_state(c, row["id"], row["tenant_id"], nxt)
        plan = load_plan(c, row["plan_id"], row["tenant_id"])
        if plan and plan.get("status") in {"SUBMITTING", "SHADOW_COMPLETE"}:
            try:
                if plan["status"] == "SHADOW_COMPLETE":
                    transition_plan_status("SHADOW_COMPLETE", "SUBMITTING")
                transition_plan_status("SUBMITTING", "UNCERTAIN")
                _update_plan_status(c, row["plan_id"], row["tenant_id"], "UNCERTAIN", plan.get("evidence_chain") or [])
            except LiveDenied:
                pass
        record_receipt(
            c,
            tenant_id=row["tenant_id"],
            attempt_id=row["id"],
            classification="uncertain_stale_recovery",
            extra={"resubmitted": False},
        )
        _audit(
            c,
            tenant_id=row["tenant_id"],
            actor_id="system",
            event="isolated_stale_submitting_recovered",
            subject_id=row["id"],
            detail={"resubmitted": False},
        )
        recovered.append(row["id"])
    return recovered


def request_isolated_cancel(
    c: sqlite3.Connection,
    *,
    tenant_id: str,
    attempt_id: str,
    actor_id: str,
) -> dict[str, Any]:
    ensure_isolated_schema(c)
    attempt = c.execute(
        "SELECT * FROM execution_attempts WHERE id=? AND tenant_id=?",
        (attempt_id, tenant_id),
    ).fetchone()
    if attempt is None:
        raise IsolatedLiveDenied("attempt not found")
    state = attempt["state"]
    if state == "EXECUTED":
        transition_plan_status("EXECUTED", "EXECUTED") if False else None
        _set_attempt_state(c, attempt_id, tenant_id, "EXECUTED_AFTER_CANCEL_REQUEST")
        c.execute(
            "UPDATE execution_isolated_attempts SET cancel_requested=1, updated_at=? WHERE attempt_id=?",
            (_iso(), attempt_id),
        )
        return {"state": "EXECUTED_AFTER_CANCEL_REQUEST", "attempt_id": attempt_id}
    if state == "SUBMITTING":
        transition_plan_status("SUBMITTING", "CANCEL_REQUESTED")
        _set_attempt_state(c, attempt_id, tenant_id, "CANCEL_REQUESTED")
        c.execute(
            "UPDATE execution_isolated_attempts SET cancel_requested=1, updated_at=? WHERE attempt_id=?",
            (_iso(), attempt_id),
        )
        return {"state": "CANCEL_REQUESTED", "attempt_id": attempt_id}
    if state == "CANCEL_REQUESTED":
        return {"state": "CANCEL_REQUESTED", "attempt_id": attempt_id}
    raise IsolatedLiveDenied(f"cannot cancel from {state}")


def _finalise_success_after_cancel(c: sqlite3.Connection, attempt_id: str, tenant_id: str) -> str:
    _set_attempt_state(c, attempt_id, tenant_id, "EXECUTED_AFTER_CANCEL_REQUEST")
    return "EXECUTED_AFTER_CANCEL_REQUEST"


def submit_isolated_live(
    c: sqlite3.Connection,
    *,
    tenant_id: str,
    user_id: str,
    plan_id: str,
    confirmation_token: str,
    role: str = "write",
    destination: str | None = None,
    payload: dict[str, Any] | None = None,
    transport: Any | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    sink_port: int | None = None,
    ca_file: str | None = None,
) -> dict[str, Any]:
    """Atomic isolated-CI live submit. Production path remains closed."""
    ensure_isolated_schema(c)
    _require_role(role)
    if get_provider(get_adapter("webhook.post")).__class__ is not ClosedProvider:
        raise IsolatedLiveDenied("production get_provider must remain ClosedProvider")

    plan = load_plan(c, plan_id, tenant_id)
    if plan is None:
        raise IsolatedLiveDenied("execution plan not found")
    if plan["requesting_user_id"] != user_id:
        raise IsolatedLiveDenied("execution plan does not belong to this user")
    evaluate_isolated_gates(c, tenant_id=tenant_id, adapter_id=plan["adapter_id"])
    ticket = load_ticket(c, plan["execution_ticket_id"], tenant_id)
    if ticket is None:
        raise IsolatedLiveDenied("execution ticket not found")
    _guardian_ok(ticket)
    if plan.get("approval_hash") or plan.get("approval_binding_id"):
        validate_plan_bound_approval(c, plan)
    dest_value = destination or plan.get("destination")
    hostname, pinned_ip = _assert_isolated_destination(dest_value)
    if payload is not None and payload_hash(payload) != plan["payload_hash"]:
        raise IsolatedLiveDenied("payload change blocked")
    if destination is not None and destination_hash(destination) != plan.get("destination_hash"):
        raise IsolatedLiveDenied("destination change blocked")

    if payload is not None:
        body_obj = payload
    else:
        raw = plan.get("payload_canonical") or "{}"
        body_obj = json.loads(raw) if isinstance(raw, str) else (raw or {})
    body = json.dumps(body_obj, sort_keys=True, separators=(",", ":"), default=str)
    idem = plan.get("idempotency_key") or f"{plan_id}:{plan['payload_hash']}:{plan.get('destination_hash')}"

    existing = _load_attempt_by_key(c, tenant_id, idem)
    if existing is not None:
        iso = _load_isolated(c, existing["id"])
        return {
            "attempt_id": existing["id"],
            "state": existing["state"],
            "idempotent_replay": True,
            "provider_submitted": bool(iso and iso["provider_submitted"]),
            "external_execution_enabled": False,
        }

    # BEGIN IMMEDIATE atomic claim: token + ticket + attempt + limits.
    try:
        c.execute("BEGIN IMMEDIATE")
    except sqlite3.OperationalError:
        # already in a transaction
        pass

    evaluate_isolated_gates(c, tenant_id=tenant_id, adapter_id=plan["adapter_id"])
    _claim_rate_and_concurrency(c, tenant_id, plan["adapter_id"])
    consume_confirmation_token(
        c,
        tenant_id=tenant_id,
        user_id=user_id,
        plan_id=plan_id,
        approval_hash=plan.get("approval_hash"),
        idempotency_key=plan.get("idempotency_key"),
        token=confirmation_token,
    )
    consumed = consume_execution_ticket(
        connection=c,
        ticket_id=plan["execution_ticket_id"],
        tenant_id=tenant_id,
        user_id=user_id,
        exact_action=plan["action"],
        resource_id=plan.get("resource_id"),
        resource_hash=plan.get("resource_hash"),
        commit=False,
    )
    if consumed.execution_state != "CONSUMED":
        raise IsolatedLiveDenied(f"ticket was not consumed: {consumed.execution_state}")

    current_status = plan["status"]
    if current_status == "PREPARED":
        raise IsolatedLiveDenied("shadow must complete before isolated live submit")
    if current_status == "SHADOW_COMPLETE":
        transition_plan_status("SHADOW_COMPLETE", "SUBMITTING")
        _append_evidence(plan, "isolated_ci_submitting")
        _update_plan_status(c, plan_id, tenant_id, "SUBMITTING", plan.get("evidence_chain") or [])
    elif current_status != "SUBMITTING":
        raise IsolatedLiveDenied(f"invalid state for isolated submit: {current_status}")

    try:
        attempt_id = _insert_attempt(
            c,
            tenant_id=tenant_id,
            plan=plan,
            ticket_id=plan["execution_ticket_id"],
            idempotency_key=idem,
            hostname=hostname,
            pinned_ip=pinned_ip,
        )
    except sqlite3.IntegrityError:
        c.rollback()
        existing = _load_attempt_by_key(c, tenant_id, idem)
        if existing is None:
            raise IsolatedLiveDenied("idempotency conflict")
        return {
            "attempt_id": existing["id"],
            "state": existing["state"],
            "idempotent_replay": True,
            "external_execution_enabled": False,
        }

    try:
        c.commit()
    except sqlite3.OperationalError:
        pass

    isolated = IsolatedWebhookProvider(get_adapter("webhook.post"), production_mode=False)
    isolated.preview({"destination_hash": plan.get("destination_hash"), "payload_hash": plan.get("payload_hash")})

    marked = _mark_submitted(c, attempt_id)
    try:
        c.commit()
    except sqlite3.OperationalError:
        pass
    if marked != 1:
        existing = _load_attempt_by_key(c, tenant_id, idem)
        return {
            "attempt_id": attempt_id,
            "state": existing["state"] if existing else "SUBMITTING",
            "idempotent_replay": True,
            "provider_submitted": True,
            "external_execution_enabled": False,
        }

    outcome_state = "UNCERTAIN"
    http_status = None
    classification = "uncertain"
    extra: dict[str, Any] = {"pinned_ip": pinned_ip, "hostname": hostname}
    try:
        if transport is not None:
            response = transport.post(body=body, idempotency_key=idem, timeout=timeout)
        else:
            if sink_port is None or ca_file is None:
                raise IsolatedCiUncertain("hermetic TLS sink binding missing")
            response = isolated_tls_post(
                pinned_ip=pinned_ip,
                port=sink_port,
                hostname=hostname,
                path="/isolated",
                body=body,
                idempotency_key=idem,
                ca_file=ca_file,
                timeout=timeout,
            )
        if not isinstance(response, IsolatedTlsResponse):
            raise IsolatedCiUncertain("transport returned no TLS response")
        http_status = response.status
        outcome_state = classify_http_outcome(response.status)
        classification = {
            "EXECUTED": "isolated_ci_executed",
            "FAILED": "isolated_ci_failed",
            "UNCERTAIN": "isolated_ci_uncertain",
        }[outcome_state]
        extra["http_status"] = response.status
        extra["verified_hostname"] = response.verified_hostname
    except IsolatedCiDenied as exc:
        if isinstance(exc, IsolatedCiUncertain):
            outcome_state = "UNCERTAIN"
            classification = "isolated_ci_uncertain"
        else:
            outcome_state = "FAILED"
            classification = "isolated_ci_denied"
        extra["error"] = str(exc)
    except IsolatedLiveDenied:
        raise
    except Exception as exc:
        outcome_state = "UNCERTAIN"
        classification = "isolated_ci_uncertain"
        extra["error"] = str(exc)

    iso_row = _load_isolated(c, attempt_id)
    cancel_requested = bool(iso_row and iso_row.get("cancel_requested"))
    current_attempt = _load_attempt_by_key(c, tenant_id, idem)
    if current_attempt and current_attempt["state"] == "CANCEL_REQUESTED" and outcome_state == "EXECUTED":
        outcome_state = _finalise_success_after_cancel(c, attempt_id, tenant_id)
        classification = "isolated_ci_executed_after_cancel"
    elif cancel_requested and outcome_state == "EXECUTED":
        outcome_state = _finalise_success_after_cancel(c, attempt_id, tenant_id)
        classification = "isolated_ci_executed_after_cancel"
    else:
        if current_attempt and current_attempt["state"] == "SUBMITTING":
            transition_plan_status("SUBMITTING", outcome_state if outcome_state in ALLOWED_TRANSITIONS["SUBMITTING"] else "UNCERTAIN")
        if outcome_state not in {"EXECUTED_AFTER_CANCEL_REQUEST"}:
            _set_attempt_state(c, attempt_id, tenant_id, outcome_state)
        plan_now = load_plan(c, plan_id, tenant_id)
        if plan_now and plan_now.get("status") == "SUBMITTING" and outcome_state in LIVE_STATES:
            try:
                transition_plan_status("SUBMITTING", outcome_state if outcome_state in ALLOWED_TRANSITIONS["SUBMITTING"] else "UNCERTAIN")
                _update_plan_status(c, plan_id, tenant_id, outcome_state, plan_now.get("evidence_chain") or [])
            except LiveDenied:
                if outcome_state == "EXECUTED_AFTER_CANCEL_REQUEST":
                    _update_plan_status(c, plan_id, tenant_id, "EXECUTED_AFTER_CANCEL_REQUEST", plan_now.get("evidence_chain") or [])

    if outcome_state in {"FAILED", "UNCERTAIN"}:
        _record_failure(c, tenant_id, plan["adapter_id"])
    _clear_in_flight(c, tenant_id, plan["adapter_id"])
    record_receipt(
        c,
        tenant_id=tenant_id,
        attempt_id=attempt_id,
        classification=classification,
        payload_hash=plan.get("payload_hash"),
        destination_hash=plan.get("destination_hash"),
        extra=extra,
    )
    _audit(
        c,
        tenant_id=tenant_id,
        actor_id=user_id,
        event="isolated_ci_submit_completed",
        subject_id=attempt_id,
        detail={"state": outcome_state, "http_status": http_status},
    )
    _record_control_event(
        c,
        tenant_id=tenant_id,
        user_id=user_id,
        action="isolated_ci_submit",
        result=outcome_state,
        extra={"attempt_id": attempt_id},
    )
    try:
        c.commit()
    except sqlite3.OperationalError:
        pass

    ticket_after = load_ticket(c, plan["execution_ticket_id"], tenant_id)
    return {
        "attempt_id": attempt_id,
        "state": outcome_state,
        "http_status": http_status,
        "idempotent_replay": False,
        "provider_submitted": True,
        "ticket_state": None if ticket_after is None else ticket_after.execution_state,
        "external_execution_enabled": False,
        "receipt_classification": classification,
    }


def production_live_still_closed() -> dict[str, Any]:
    from intelligence.execution_live import submit_live

    try:
        submit_live()
        closed = False
    except LiveDenied:
        closed = True
    adapter = get_adapter("webhook.post")
    provider = get_provider(adapter, mode="production")
    return {
        "submit_live_closed": closed,
        "provider_is_closed": isinstance(provider, ClosedProvider),
        "adapter_live_supported": adapter.live_execution_supported,
        "external_execution_enabled": False,
    }
