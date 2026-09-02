"""Phase 3 Stage 4A — production webhook pilot capability, switched off.

No grant, destination, secret or external request is created by import or
deployment. Default production configuration cannot execute.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import socket
import sqlite3
import ssl
import time
import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Callable
from urllib.parse import parse_qsl, urlsplit

from intelligence.execution import consume_execution_ticket, load_ticket, _iso, _now, _parse_iso
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
from intelligence.execution_live import (
    ALLOWED_TRANSITIONS,
    LIVE_ENV_SWITCH,
    LiveDenied,
    consume_confirmation_token,
    ensure_phase3_schema,
    persist_resolution,
    transition_plan_status,
    _audit,
    _global_kill_active,
    _grant_enabled,
    _guardian_ok,
    _require_role,
    _tenant_kill_active,
)
from intelligence.execution_providers import Attempt, ClosedProvider, DryRunPreview, ProviderDenied, Receipt, ShadowResult
from intelligence.execution_providers_webhook import (
    BLOCKED_HOSTS,
    DestinationDenied,
    ResolverPort,
    classify_ip,
    record_resolution,
    sha256_text,
    validate_hardened_webhook_destination,
)
from intelligence.execution_receipts import list_receipts_for_attempt, public_receipt, record_receipt


PILOT_FLAG = "ZORVIAN_WEBHOOK_PILOT_ENABLED"
PILOT_TENANT_ENV = "ZORVIAN_WEBHOOK_PILOT_TENANT_ID"
PILOT_HOST_SUFFIX_ENV = "ZORVIAN_WEBHOOK_PILOT_HOST_SUFFIX"
PILOT_SECRET_ENV = "ZORVIAN_WEBHOOK_PILOT_SIGNING_SECRET"
PILOT_NEXT_SECRET_ENV = "ZORVIAN_WEBHOOK_PILOT_SIGNING_SECRET_NEXT"
PILOT_KEY_ID_ENV = "ZORVIAN_WEBHOOK_PILOT_KEY_ID"
PILOT_NEXT_KEY_ID_ENV = "ZORVIAN_WEBHOOK_PILOT_KEY_ID_NEXT"

HARD_MAX_TENANT_PER_HOUR = 5
HARD_MAX_USER_PER_HOUR = 2
HARD_MAX_IN_FLIGHT = 1
HARD_MAX_PAYLOAD = 32 * 1024
HARD_MAX_RESPONSE_EVIDENCE = 8 * 1024
HARD_MAX_URL = 2048
CIRCUIT_THRESHOLD = 5
CIRCUIT_WINDOW_SECONDS = 600
CIRCUIT_OPEN_SECONDS = 1800
CONNECT_TIMEOUT = 3.0
TOTAL_TIMEOUT = 8.0


class ProductionPilotDenied(LiveDenied):
    pass


class ProductionUncertain(ProductionPilotDenied):
    pass


def _ceil(name: str, hard: int) -> int:
    raw = os.getenv(name)
    if not raw:
        return hard
    try:
        value = int(raw)
    except ValueError:
        return hard
    return max(0, min(value, hard))


def process_is_pilot() -> bool:
    return (os.getenv(LIVE_ENV_SWITCH) or "").strip().lower() == "pilot"


def pilot_flag_enabled() -> bool:
    return (os.getenv(PILOT_FLAG) or "").strip().lower() in {"1", "true", "yes", "on"}


def env_is_production() -> bool:
    return (os.getenv("ZORVIAN_ENV") or "prod").strip().lower() in {"prod", "production"}


def configured_pilot_tenant() -> str:
    return (os.getenv(PILOT_TENANT_ENV) or "").strip()


def configured_host_suffix() -> str:
    return (os.getenv(PILOT_HOST_SUFFIX_ENV) or "").strip().lower().lstrip(".")


def signing_key_id() -> str:
    return (os.getenv(PILOT_KEY_ID_ENV) or "").strip()


def load_signing_secret(key_id: str | None = None) -> str:
    wanted = (key_id or signing_key_id()).strip()
    current_id = signing_key_id()
    nxt = (os.getenv(PILOT_NEXT_KEY_ID_ENV) or "").strip()
    if wanted and wanted == nxt:
        secret = os.getenv(PILOT_NEXT_SECRET_ENV) or ""
    elif wanted and current_id and wanted != current_id and wanted != nxt:
        raise ProductionPilotDenied("unknown signing key id")
    else:
        secret = os.getenv(PILOT_SECRET_ENV) or ""
    if not secret:
        raise ProductionPilotDenied("signing secret is absent")
    if len(secret) < 16:
        raise ProductionPilotDenied("signing secret is too weak")
    return secret


def ensure_stage4a_schema(c: sqlite3.Connection) -> None:
    ensure_phase3_schema(c)
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS execution_pilot_attempts(
            attempt_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            plan_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            idempotency_key TEXT NOT NULL,
            provider_submitted INTEGER NOT NULL DEFAULT 0,
            submit_count INTEGER NOT NULL DEFAULT 0,
            cancel_requested INTEGER NOT NULL DEFAULT 0,
            resolution_hash TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(tenant_id, idempotency_key)
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS execution_pilot_rate(
            tenant_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            window_start TEXT NOT NULL,
            tenant_count INTEGER NOT NULL DEFAULT 0,
            user_count INTEGER NOT NULL DEFAULT 0,
            in_flight INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(tenant_id, user_id)
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS execution_pilot_circuit(
            tenant_id TEXT NOT NULL,
            adapter_id TEXT NOT NULL,
            failures INTEGER NOT NULL DEFAULT 0,
            window_start TEXT NOT NULL,
            opened_at TEXT,
            PRIMARY KEY(tenant_id, adapter_id)
        )
        """
    )


def circuit_open(c: sqlite3.Connection, tenant_id: str, adapter_id: str) -> bool:
    row = c.execute(
        "SELECT opened_at FROM execution_pilot_circuit WHERE tenant_id=? AND adapter_id=?",
        (tenant_id, adapter_id),
    ).fetchone()
    if not row or not row["opened_at"]:
        return False
    opened = _parse_iso(row["opened_at"])
    if opened is None:
        return False
    return _now() < opened + timedelta(seconds=CIRCUIT_OPEN_SECONDS)


def record_circuit_failure(c: sqlite3.Connection, tenant_id: str, adapter_id: str) -> None:
    now = _now()
    row = c.execute(
        "SELECT * FROM execution_pilot_circuit WHERE tenant_id=? AND adapter_id=?",
        (tenant_id, adapter_id),
    ).fetchone()
    if row is None:
        c.execute(
            """INSERT INTO execution_pilot_circuit(tenant_id,adapter_id,failures,window_start,opened_at)
               VALUES (?,?,?,?,?)""",
            (tenant_id, adapter_id, 1, _iso(now), None),
        )
        return
    started = _parse_iso(row["window_start"]) or now
    failures = int(row["failures"])
    if now - started > timedelta(seconds=CIRCUIT_WINDOW_SECONDS):
        failures = 0
        started = now
    failures += 1
    opened = _iso(now) if failures >= CIRCUIT_THRESHOLD else row["opened_at"]
    c.execute(
        """UPDATE execution_pilot_circuit SET failures=?, window_start=?, opened_at=?
           WHERE tenant_id=? AND adapter_id=?""",
        (failures, _iso(started), opened, tenant_id, adapter_id),
    )
    if opened and failures >= CIRCUIT_THRESHOLD:
        _audit(c, tenant_id=tenant_id, actor_id="system", event="pilot_circuit_opened", subject_id=adapter_id, detail={"failures": failures})


def destination_suffix_ok(destination: str) -> bool:
    suffix = configured_host_suffix()
    if not suffix:
        return False
    host = (urlsplit(destination).hostname or "").lower()
    return host == suffix or host.endswith("." + suffix)


def validate_pilot_destination(destination: str | None, *, allowed_hashes: list[str], resolver: ResolverPort | None, plan_id: str) -> tuple[str, Any]:
    value = (destination or "").strip()
    if not value:
        raise ProductionPilotDenied("destination is required")
    if len(value) > HARD_MAX_URL:
        raise ProductionPilotDenied("destination exceeds maximum length")
    parts = urlsplit(value)
    if parts.query or parts.fragment:
        raise ProductionPilotDenied("query strings and fragments are rejected")
    dest, resolution = validate_hardened_webhook_destination(
        value,
        allowed_hosts=[],
        resolver=resolver,
        allow_non_443=False,
        plan_id=plan_id,
    )
    if not destination_suffix_ok(dest):
        raise ProductionPilotDenied("destination host is not the platform-owned suffix")
    dest_h = destination_hash(dest)
    if not allowed_hashes or dest_h not in allowed_hashes:
        raise ProductionPilotDenied("empty destination allowlist denies")
    return dest, resolution


def evaluate_pilot_process_gates() -> None:
    if not process_is_pilot():
        raise ProductionPilotDenied("process switch is not pilot")
    if not pilot_flag_enabled():
        raise ProductionPilotDenied("webhook pilot flag is off")
    if not env_is_production():
        raise ProductionPilotDenied("environment is not production")
    if not configured_pilot_tenant():
        raise ProductionPilotDenied("pilot tenant identifier is not configured")
    if not configured_host_suffix():
        raise ProductionPilotDenied("platform-owned host suffix is not configured")
    if not signing_key_id():
        raise ProductionPilotDenied("signing key id is absent")
    load_signing_secret()


def evaluate_pilot_runtime_gates(
    c: sqlite3.Connection,
    *,
    tenant_id: str,
    adapter_id: str,
    action: str,
) -> None:
    evaluate_pilot_process_gates()
    if tenant_id != configured_pilot_tenant():
        raise ProductionPilotDenied("tenant is not the configured pilot tenant")
    if adapter_id != "webhook.post":
        raise ProductionPilotDenied("only webhook.post may pilot")
    if _global_kill_active(c):
        raise ProductionPilotDenied("global kill switch is active")
    if _tenant_kill_active(c, tenant_id, adapter_id):
        raise ProductionPilotDenied("tenant kill switch is active")
    if not _grant_enabled(c, tenant_id, adapter_id, action, "prod"):
        raise ProductionPilotDenied("tenant live grant is missing or disabled")
    if circuit_open(c, tenant_id, adapter_id):
        raise ProductionPilotDenied("circuit breaker is open")


def select_production_provider(adapter, *, connection: sqlite3.Connection | None = None, tenant_id: str | None = None):
    """Default remains ClosedProvider. Pilot provider only when every gate passes."""
    try:
        if connection is None or tenant_id is None:
            raise ProductionPilotDenied("provider selection missing tenant context")
        evaluate_pilot_runtime_gates(
            connection,
            tenant_id=tenant_id,
            adapter_id=adapter.adapter_id,
            action="post_webhook",
        )
    except ProductionPilotDenied:
        return ClosedProvider(adapter)
    return ProductionWebhookProvider(adapter)


def build_signed_headers(*, body: str, idempotency_key: str, key_id: str | None = None) -> dict[str, str]:
    kid = key_id or signing_key_id()
    secret = load_signing_secret(kid)
    ts = str(int(time.time()))
    nonce = secrets.token_hex(16)
    body_h = sha256_text(body)
    material = f"{ts}.{nonce}.{idempotency_key}.{body_h}".encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), material, hashlib.sha256).hexdigest()
    return {
        "Content-Type": "application/json",
        "Idempotency-Key": idempotency_key,
        "X-Zorvian-Timestamp": ts,
        "X-Zorvian-Nonce": nonce,
        "X-Zorvian-Body-SHA256": body_h,
        "X-Zorvian-Key-Id": kid,
        "X-Zorvian-Signature": f"v1={sig}",
    }


def verify_signature(headers: dict[str, str], body: str, idempotency_key: str) -> bool:
    kid = headers.get("X-Zorvian-Key-Id") or ""
    secret = load_signing_secret(kid)
    ts = headers.get("X-Zorvian-Timestamp") or ""
    nonce = headers.get("X-Zorvian-Nonce") or ""
    body_h = headers.get("X-Zorvian-Body-SHA256") or ""
    sig = (headers.get("X-Zorvian-Signature") or "").removeprefix("v1=")
    expected = hmac.new(
        secret.encode("utf-8"),
        f"{ts}.{nonce}.{idempotency_key}.{sha256_text(body)}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(sig, expected) and body_h == sha256_text(body)


@dataclass
class ProductionTlsResponse:
    status: int
    body: bytes
    headers: dict[str, str]


class ScriptedProductionTransport:
    def __init__(self, outcomes: list[Any] | None = None):
        self.outcomes = list(outcomes or [])
        self.calls: list[dict[str, Any]] = []

    def post(self, **kwargs: Any) -> ProductionTlsResponse:
        self.calls.append(kwargs)
        if not self.outcomes:
            return ProductionTlsResponse(200, b'{"ok":true}', {})
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        if isinstance(outcome, ProductionTlsResponse):
            return outcome
        if isinstance(outcome, int):
            return ProductionTlsResponse(outcome, b"{}", {})
        raise ProductionPilotDenied("unknown scripted outcome")


class SystemResolver:
    def resolve(self, hostname: str) -> list[str]:
        try:
            infos = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise ProductionPilotDenied(f"DNS resolution failed: {exc}") from exc
        addresses = []
        for info in infos:
            addr = info[4][0]
            addresses.append(addr)
        if not addresses:
            raise ProductionPilotDenied("DNS returned no addresses")
        for item in addresses:
            classify_ip(item)
        return addresses


def production_tls_post(
    *,
    pinned_ip: str,
    hostname: str,
    path: str,
    body: str,
    headers: dict[str, str],
    timeout: float = TOTAL_TIMEOUT,
    ca_file: str | None = None,
    port: int = 443,
) -> ProductionTlsResponse:
    classify_ip(pinned_ip)
    saved = {}
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        if key in os.environ:
            saved[key] = os.environ.pop(key)
    try:
        ctx = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        sock = socket.create_connection((pinned_ip, port), timeout=min(timeout, CONNECT_TIMEOUT))
        try:
            ssock = ctx.wrap_socket(sock, server_hostname=hostname)
        except ssl.SSLError as exc:
            sock.close()
            raise ProductionPilotDenied(f"TLS verification failed: {exc}") from exc
        header_lines = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
        req = f"POST {path or '/'} HTTP/1.1\r\nHost: {hostname}\r\n{header_lines}Content-Length: {len(body.encode())}\r\nConnection: close\r\n\r\n{body}"
        try:
            ssock.settimeout(timeout)
            ssock.sendall(req.encode("utf-8"))
            chunks = []
            total = 0
            while True:
                block = ssock.recv(65536)
                if not block:
                    break
                total += len(block)
                if total > HARD_MAX_RESPONSE_EVIDENCE + 4096:
                    raise ProductionUncertain("response oversized")
                chunks.append(block)
            raw = b"".join(chunks)
        except TimeoutError as exc:
            raise ProductionUncertain("timeout") from exc
        except OSError as exc:
            raise ProductionUncertain(f"transport reset: {exc}") from exc
        finally:
            try:
                ssock.close()
            except Exception:
                pass
    finally:
        os.environ.update(saved)
    if not raw:
        raise ProductionUncertain("empty response")
    header_blob, _, rest = raw.partition(b"\r\n\r\n")
    lines = header_blob.split(b"\r\n")
    try:
        status = int(lines[0].decode("latin1").split()[1])
    except Exception as exc:
        raise ProductionUncertain("malformed HTTP status") from exc
    parsed = {}
    for line in lines[1:]:
        if b":" in line:
            name, value = line.split(b":", 1)
            parsed[name.decode("latin1").lower()] = value.decode("latin1").strip()
    if status in {301, 302, 303, 307, 308} or "location" in parsed:
        raise ProductionPilotDenied("redirects are rejected")
    if len(rest) > HARD_MAX_RESPONSE_EVIDENCE:
        raise ProductionUncertain("response body exceeds evidence limit")
    return ProductionTlsResponse(status, rest, parsed)


class ProductionWebhookProvider:
    def __init__(self, adapter, *, transport=None, resolver: ResolverPort | None = None):
        if adapter.adapter_id != "webhook.post":
            raise ProviderDenied("ProductionWebhookProvider is webhook.post only")
        self.adapter = adapter
        self.adapter_id = adapter.adapter_id
        self.adapter_type = adapter.adapter_type
        self.transport = transport
        self.resolver = resolver

    def preview(self, plan: dict[str, Any]) -> DryRunPreview:
        return DryRunPreview("dry_run", self.adapter_id, False, "Stage 4A pilot preview; default production remains closed", plan.get("destination_hash"), plan.get("payload_hash"))

    def shadow(self, plan: dict[str, Any]) -> ShadowResult:
        return ShadowResult("shadow", self.adapter_id, False, "Stage 4A shadow only", plan.get("destination_hash"), plan.get("payload_hash"))

    def submit(self, plan: dict[str, Any], idempotency_key: str, timeout: float) -> Attempt:
        raise ProviderDenied("use submit_production_pilot; ProductionWebhookProvider.submit is not a free path")

    def fetch_receipt(self, provider_ref: str) -> Receipt:
        return Receipt(provider_ref, provider_ref, "read_only_reconcile", provider_ref)

    def cancel(self, provider_ref: str) -> Any:
        raise ProviderDenied("cancel is mediated by request_production_cancel")


def _allowlisted(c: sqlite3.Connection, tenant_id: str, adapter_id: str) -> list[str]:
    rows = c.execute(
        "SELECT destination_hash FROM execution_destination_allowlist WHERE tenant_id=? AND adapter_id=?",
        (tenant_id, adapter_id),
    ).fetchall()
    return [r["destination_hash"] for r in rows]


def _claim_limits(c: sqlite3.Connection, tenant_id: str, user_id: str) -> None:
    now = _now()
    row = c.execute(
        "SELECT * FROM execution_pilot_rate WHERE tenant_id=? AND user_id=?",
        (tenant_id, user_id),
    ).fetchone()
    tenant_cap = _ceil("ZORVIAN_WEBHOOK_PILOT_TENANT_PER_HOUR", HARD_MAX_TENANT_PER_HOUR)
    user_cap = _ceil("ZORVIAN_WEBHOOK_PILOT_USER_PER_HOUR", HARD_MAX_USER_PER_HOUR)
    if row is None:
        c.execute(
            """INSERT INTO execution_pilot_rate(tenant_id,user_id,window_start,tenant_count,user_count,in_flight)
               VALUES (?,?,?,?,?,?)""",
            (tenant_id, user_id, _iso(now), 1, 1, 1),
        )
        return
    started = _parse_iso(row["window_start"]) or now
    tcount, ucount, inflight = int(row["tenant_count"]), int(row["user_count"]), int(row["in_flight"])
    if now - started > timedelta(hours=1):
        tcount = ucount = 0
        started = now
    tenant_total = c.execute(
        "SELECT COALESCE(SUM(tenant_count),0) AS n FROM execution_pilot_rate WHERE tenant_id=?",
        (tenant_id,),
    ).fetchone()["n"]
    if tenant_total >= tenant_cap or tcount >= tenant_cap:
        raise ProductionPilotDenied("tenant hourly rate limit exceeded")
    if ucount >= user_cap:
        raise ProductionPilotDenied("user hourly rate limit exceeded")
    if inflight >= HARD_MAX_IN_FLIGHT:
        raise ProductionPilotDenied("concurrency limit exceeded")
    c.execute(
        """UPDATE execution_pilot_rate SET window_start=?, tenant_count=?, user_count=?, in_flight=?
           WHERE tenant_id=? AND user_id=?""",
        (_iso(started), tcount + 1, ucount + 1, inflight + 1, tenant_id, user_id),
    )


def classify_outcome(status: int) -> str:
    if 200 <= status < 300:
        return "EXECUTED"
    if 400 <= status < 500:
        return "FAILED"
    return "UNCERTAIN"


def recover_stale_production(c: sqlite3.Connection, *, tenant_id: str | None = None, older_than_seconds: int = 30) -> list[str]:
    ensure_stage4a_schema(c)
    cutoff = _iso(_now() - timedelta(seconds=older_than_seconds))
    sql = "SELECT * FROM execution_attempts WHERE state='SUBMITTING' AND updated_at<=?"
    params: list[Any] = [cutoff]
    if tenant_id:
        sql += " AND tenant_id=?"
        params.append(tenant_id)
    recovered = []
    for row in c.execute(sql, params).fetchall():
        c.execute("UPDATE execution_attempts SET state='UNCERTAIN', updated_at=? WHERE id=?", (_iso(), row["id"]))
        record_receipt(c, tenant_id=row["tenant_id"], attempt_id=row["id"], classification="uncertain_stale_recovery", extra={"resubmitted": False})
        recovered.append(row["id"])
    return recovered


def request_production_cancel(c: sqlite3.Connection, *, tenant_id: str, attempt_id: str) -> dict[str, Any]:
    attempt = c.execute("SELECT * FROM execution_attempts WHERE id=? AND tenant_id=?", (attempt_id, tenant_id)).fetchone()
    if attempt is None:
        raise ProductionPilotDenied("attempt not found")
    if attempt["state"] == "EXECUTED":
        c.execute("UPDATE execution_attempts SET state=?, updated_at=? WHERE id=?", ("EXECUTED_AFTER_CANCEL_REQUEST", _iso(), attempt_id))
        return {"state": "EXECUTED_AFTER_CANCEL_REQUEST", "attempt_id": attempt_id}
    if attempt["state"] == "SUBMITTING":
        transition_plan_status("SUBMITTING", "CANCEL_REQUESTED")
        c.execute("UPDATE execution_attempts SET state=?, updated_at=? WHERE id=?", ("CANCEL_REQUESTED", _iso(), attempt_id))
        c.execute("UPDATE execution_pilot_attempts SET cancel_requested=1 WHERE attempt_id=?", (attempt_id,))
        return {"state": "CANCEL_REQUESTED", "attempt_id": attempt_id}
    return {"state": attempt["state"], "attempt_id": attempt_id}


def _in_transaction(c: sqlite3.Connection) -> bool:
    try:
        return bool(c.in_transaction)
    except Exception:
        return False


def _rollback_quietly(c: sqlite3.Connection) -> None:
    try:
        c.rollback()
    except sqlite3.Error:
        pass


def begin_immediate_or_deny(c: sqlite3.Connection) -> None:
    if _in_transaction(c):
        raise ProductionPilotDenied("unexpected open transaction before BEGIN IMMEDIATE")
    try:
        c.execute("BEGIN IMMEDIATE")
    except sqlite3.Error as exc:
        _rollback_quietly(c)
        raise ProductionPilotDenied(f"BEGIN IMMEDIATE failed: {exc}") from exc


def commit_claim_or_deny(c: sqlite3.Connection) -> None:
    try:
        c.commit()
    except sqlite3.Error as exc:
        _rollback_quietly(c)
        raise ProductionPilotDenied(f"pre-I/O commit failed: {exc}") from exc
    if _in_transaction(c):
        _rollback_quietly(c)
        raise ProductionPilotDenied("pre-I/O commit did not complete")


def request_target(destination: str) -> str:
    parts = urlsplit(destination)
    if parts.query or parts.fragment:
        raise ProductionPilotDenied("query strings and fragments are rejected")
    return parts.path or "/"


def public_attempt(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "attempt_id": row.get("id") or row.get("attempt_id"),
        "state": row.get("state"),
        "adapter_id": row.get("adapter_id"),
        "updated_at": row.get("updated_at"),
    }


def submit_production_pilot(
    c: sqlite3.Connection,
    *,
    tenant_id: str,
    user_id: str,
    plan_id: str,
    confirmation_token: str,
    role: str = "owner",
    payload: dict[str, Any] | None = None,
    destination: str | None = None,
    transport=None,
    resolver: ResolverPort | None = None,
    tls_port: int | None = None,
    ca_file: str | None = None,
    _after_claim_writes: Callable[[], None] | None = None,
    _commit_claim: Callable[[sqlite3.Connection], None] | None = None,
) -> dict[str, Any]:
    caller_tx = _in_transaction(c)
    ensure_stage4a_schema(c)
    if not caller_tx and _in_transaction(c):
        try:
            c.commit()
        except sqlite3.Error as exc:
            _rollback_quietly(c)
            raise ProductionPilotDenied(f"schema persist commit failed: {exc}") from exc
    _require_role(role)
    plan = load_plan(c, plan_id, tenant_id)
    if plan is None:
        raise ProductionPilotDenied("execution plan not found")
    if plan["requesting_user_id"] != user_id:
        raise ProductionPilotDenied("execution plan does not belong to this user")
    evaluate_pilot_runtime_gates(c, tenant_id=tenant_id, adapter_id=plan["adapter_id"], action=plan["action"])
    ticket = load_ticket(c, plan["execution_ticket_id"], tenant_id)
    if ticket is None:
        raise ProductionPilotDenied("execution ticket not found")
    _guardian_ok(ticket)
    validate_plan_bound_approval(c, plan)
    dest_value = destination or plan.get("destination")
    if payload is not None and payload_hash(payload) != plan["payload_hash"]:
        raise ProductionPilotDenied("payload change blocked")
    if destination is not None and destination_hash(destination) != plan.get("destination_hash"):
        raise ProductionPilotDenied("destination change blocked")
    raw = plan.get("payload_canonical") or "{}"
    body_obj = payload if payload is not None else (json.loads(raw) if isinstance(raw, str) else raw or {})
    body = json.dumps(body_obj, sort_keys=True, separators=(",", ":"), default=str)
    if len(body.encode("utf-8")) > HARD_MAX_PAYLOAD:
        raise ProductionPilotDenied("payload exceeds 32KB")
    resolver = resolver or SystemResolver()
    dest, resolution = validate_pilot_destination(dest_value, allowed_hashes=_allowlisted(c, tenant_id, plan["adapter_id"]), resolver=resolver, plan_id=plan_id)
    caller_tx = _in_transaction(c)
    persist_resolution(c, tenant_id=tenant_id, record=resolution)
    if not caller_tx and _in_transaction(c):
        try:
            c.commit()
        except sqlite3.Error as exc:
            _rollback_quietly(c)
            raise ProductionPilotDenied(f"resolution persist commit failed: {exc}") from exc
    dest2, resolution2 = validate_pilot_destination(dest_value, allowed_hashes=_allowlisted(c, tenant_id, plan["adapter_id"]), resolver=resolver, plan_id=plan_id)
    if set(resolution.addresses) != set(resolution2.addresses):
        raise DestinationDenied("DNS_REBINDING_DENIED")
    if not resolution2.addresses:
        raise ProductionPilotDenied("resolved address set is empty")
    pinned_ip = resolution2.addresses[0]
    classify_ip(pinned_ip)
    idem = plan.get("idempotency_key") or f"{plan_id}:{plan['payload_hash']}"
    existing = c.execute("SELECT * FROM execution_attempts WHERE tenant_id=? AND idempotency_key=?", (tenant_id, idem)).fetchone()
    if existing is not None:
        return {
            "attempt_id": existing["id"],
            "state": existing["state"],
            "idempotent_replay": True,
            "external_execution_enabled": False,
            "provider_submitted": True,
        }

    request_path = request_target(dest)
    attempt_id = str(uuid.uuid4())
    try:
        begin_immediate_or_deny(c)
        evaluate_pilot_runtime_gates(c, tenant_id=tenant_id, adapter_id=plan["adapter_id"], action=plan["action"])
        _claim_limits(c, tenant_id, user_id)
        try:
            consume_confirmation_token(
                c,
                tenant_id=tenant_id,
                user_id=user_id,
                plan_id=plan_id,
                approval_hash=plan.get("approval_hash"),
                idempotency_key=plan.get("idempotency_key"),
                token=confirmation_token,
            )
        except LiveDenied as exc:
            _rollback_quietly(c)
            row = c.execute(
                "SELECT * FROM execution_attempts WHERE tenant_id=? AND idempotency_key=?",
                (tenant_id, idem),
            ).fetchone()
            if row is not None:
                return {
                    "attempt_id": row["id"],
                    "state": row["state"],
                    "idempotent_replay": True,
                    "external_execution_enabled": False,
                    "provider_submitted": True,
                }
            raise ProductionPilotDenied(str(exc)) from exc
        # Do not call consume_execution_ticket() inside this transaction: its
        # ensure_execution_schema() DDL would implicitly commit the claim.
        ticket_row = c.execute(
            "SELECT * FROM execution_tickets WHERE id=? AND tenant_id=?",
            (plan["execution_ticket_id"], tenant_id),
        ).fetchone()
        if ticket_row is None:
            raise ProductionPilotDenied("execution ticket not found")
        if ticket_row["requesting_user_id"] != user_id:
            raise ProductionPilotDenied("execution ticket does not belong to this user")
        if ticket_row["execution_state"] == "CONSUMED":
            _rollback_quietly(c)
            row = c.execute(
                "SELECT * FROM execution_attempts WHERE tenant_id=? AND idempotency_key=?",
                (tenant_id, idem),
            ).fetchone()
            if row is not None:
                return {
                    "attempt_id": row["id"],
                    "state": row["state"],
                    "idempotent_replay": True,
                    "external_execution_enabled": False,
                    "provider_submitted": True,
                }
            raise ProductionPilotDenied("ticket was not consumed: CONSUMED")
        marked_ticket = c.execute(
            """UPDATE execution_tickets
               SET execution_state='CONSUMED', executed_at=?
               WHERE id=? AND tenant_id=? AND execution_state='AUTHORISED'""",
            (_iso(), plan["execution_ticket_id"], tenant_id),
        ).rowcount
        if marked_ticket != 1:
            raise ProductionPilotDenied("ticket was not consumed: " + str(ticket_row["execution_state"]))
        if plan["status"] != "SHADOW_COMPLETE":
            raise ProductionPilotDenied("shadow must complete before production pilot submit")
        transition_plan_status("SHADOW_COMPLETE", "SUBMITTING")
        _append_evidence(plan, "production_pilot_submitting")
        _update_plan_status(c, plan_id, tenant_id, "SUBMITTING", plan.get("evidence_chain") or [])
        now = _iso()
        try:
            c.execute(
                """INSERT INTO execution_attempts(id,tenant_id,plan_id,ticket_id,adapter_id,idempotency_key,state,provider_ref,created_at,updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (attempt_id, tenant_id, plan_id, plan["execution_ticket_id"], plan["adapter_id"], idem, "SUBMITTING", None, now, now),
            )
            c.execute(
                """INSERT INTO execution_pilot_attempts(attempt_id,tenant_id,plan_id,user_id,idempotency_key,provider_submitted,submit_count,cancel_requested,resolution_hash,created_at,updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (attempt_id, tenant_id, plan_id, user_id, idem, 1, 1, 0, resolution2.record_hash, now, now),
            )
        except sqlite3.IntegrityError:
            _rollback_quietly(c)
            row = c.execute(
                "SELECT * FROM execution_attempts WHERE tenant_id=? AND idempotency_key=?",
                (tenant_id, idem),
            ).fetchone()
            if row is None:
                raise ProductionPilotDenied("duplicate claim lost and no existing attempt was found")
            return {
                "attempt_id": row["id"],
                "state": row["state"],
                "idempotent_replay": True,
                "external_execution_enabled": False,
                "provider_submitted": True,
            }
        _audit(c, tenant_id=tenant_id, actor_id=user_id, event="pilot_submit_claimed", subject_id=attempt_id, detail={"resolution_hash": resolution2.record_hash})
        if _after_claim_writes is not None:
            _after_claim_writes()
        if _commit_claim is not None:
            _commit_claim(c)
        else:
            commit_claim_or_deny(c)
    except ProductionPilotDenied:
        _rollback_quietly(c)
        raise
    except (LiveDenied, DestinationDenied, AdapterDenied) as exc:
        _rollback_quietly(c)
        raise ProductionPilotDenied(str(exc)) from exc
    except sqlite3.Error as exc:
        _rollback_quietly(c)
        raise ProductionPilotDenied(f"claim transaction failed: {exc}") from exc
    except Exception:
        _rollback_quietly(c)
        raise

    if _in_transaction(c):
        _rollback_quietly(c)
        raise ProductionPilotDenied("open transaction remained after claim commit")

    headers = build_signed_headers(body=body, idempotency_key=idem)
    outcome = "UNCERTAIN"
    classification = "isolated_ci_uncertain"
    extra = {"hostname": urlsplit(dest).hostname, "pinned_ip_present": True, "key_id": headers["X-Zorvian-Key-Id"]}
    http_status = None
    try:
        if transport is not None:
            response = transport.post(body=body, headers=headers, pinned_ip=pinned_ip, hostname=urlsplit(dest).hostname, path=request_path)
        else:
            response = production_tls_post(
                pinned_ip=pinned_ip,
                hostname=urlsplit(dest).hostname or "",
                path=request_path,
                body=body,
                headers=headers,
                ca_file=ca_file,
                port=tls_port or 443,
            )
        http_status = response.status
        outcome = classify_outcome(response.status)
        classification = {
            "EXECUTED": "production_pilot_executed",
            "FAILED": "production_pilot_failed",
            "UNCERTAIN": "production_pilot_uncertain",
        }[outcome]
        extra["http_status"] = response.status
        extra["evidence_bytes"] = min(len(response.body), HARD_MAX_RESPONSE_EVIDENCE)
    except ProductionUncertain as exc:
        outcome, classification, extra["error"] = "UNCERTAIN", "production_pilot_uncertain", str(exc)
    except ProductionPilotDenied as exc:
        if "redirect" in str(exc).lower() or "TLS" in str(exc):
            outcome, classification = "FAILED", "production_pilot_denied"
        else:
            outcome, classification = "FAILED", "production_pilot_denied"
        extra["error"] = str(exc)
    except Exception as exc:
        outcome, classification, extra["error"] = "UNCERTAIN", "production_pilot_uncertain", type(exc).__name__

    current = c.execute("SELECT state FROM execution_attempts WHERE id=?", (attempt_id,)).fetchone()
    if current and current["state"] == "CANCEL_REQUESTED" and outcome == "EXECUTED":
        outcome, classification = "EXECUTED_AFTER_CANCEL_REQUEST", "production_pilot_executed_after_cancel"
    if outcome in {"FAILED", "UNCERTAIN"}:
        record_circuit_failure(c, tenant_id, plan["adapter_id"])
    c.execute("UPDATE execution_pilot_rate SET in_flight=MAX(in_flight-1,0) WHERE tenant_id=? AND user_id=?", (tenant_id, user_id))
    if outcome != "EXECUTED_AFTER_CANCEL_REQUEST" and current and current["state"] == "SUBMITTING":
        c.execute("UPDATE execution_attempts SET state=?, updated_at=? WHERE id=?", (outcome, _iso(), attempt_id))
        try:
            if outcome in ALLOWED_TRANSITIONS.get("SUBMITTING", set()):
                _update_plan_status(c, plan_id, tenant_id, outcome, plan.get("evidence_chain") or [])
        except LiveDenied:
            pass
    elif outcome == "EXECUTED_AFTER_CANCEL_REQUEST":
        c.execute("UPDATE execution_attempts SET state=?, updated_at=? WHERE id=?", (outcome, _iso(), attempt_id))
    record_receipt(
        c,
        tenant_id=tenant_id,
        attempt_id=attempt_id,
        classification=classification,
        payload_hash=plan.get("payload_hash"),
        destination_hash=plan.get("destination_hash"),
        extra=extra,
    )
    _audit(c, tenant_id=tenant_id, actor_id=user_id, event="pilot_submit_completed", subject_id=attempt_id, detail={"state": outcome, "http_status": http_status})
    _record_control_event(c, tenant_id=tenant_id, user_id=user_id, action="production_pilot_submit", result=outcome, extra={"attempt_id": attempt_id})
    try:
        c.commit()
    except sqlite3.Error as exc:
        extra["post_io_commit_error"] = type(exc).__name__
    ticket_after = load_ticket(c, plan["execution_ticket_id"], tenant_id)
    return {
        "attempt_id": attempt_id,
        "state": outcome,
        "http_status": http_status,
        "idempotent_replay": False,
        "provider_submitted": True,
        "ticket_state": None if ticket_after is None else ticket_after.execution_state,
        "external_execution_enabled": False,
        "exactly_once": False,
    }
