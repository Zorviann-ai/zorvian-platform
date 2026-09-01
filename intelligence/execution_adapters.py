"""Controlled Execution Gateway Phase 2 — adapters, plans and dry-run.

External side effects remain disabled. Plans bind ticket + payload + destination
+ resource hashes. Unknown adapters fail closed. Default tenant policy is DENY.
"""
from __future__ import annotations

import hashlib
import os
import ipaddress
import json
import re
import sqlite3
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

from intelligence.execution import consume_execution_ticket, load_ticket, _iso, _now, _parse_iso

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
E164_RE = re.compile(r"^\+[1-9]\d{7,14}$")
RISK_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
PLAN_TTL_MINUTES = 15
BLOCKED_WEBHOOK_HOSTS = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "metadata.google.com",
    "instance-data",
}
PRIVATE_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


class AdapterDenied(PermissionError):
    pass


@dataclass(frozen=True)
class ExecutionAdapter:
    adapter_id: str
    name: str
    adapter_type: str
    version: str
    enabled: bool
    external: bool
    supported_execution_types: tuple[str, ...]
    supported_actions: tuple[str, ...]
    risk_class: str
    requires_destination: bool
    requires_resource_hash: bool
    requires_human_approval: bool
    dry_run_supported: bool
    live_execution_supported: bool
    tenant_allowlist: tuple[str, ...] = ()
    configuration_reference: str = ""


def _builtin_adapters() -> dict[str, ExecutionAdapter]:
    return {
        "internal.record_transition": ExecutionAdapter(
            adapter_id="internal.record_transition",
            name="Internal record transition",
            adapter_type="internal",
            version="1",
            enabled=True,
            external=False,
            supported_execution_types=("internal_release", "other", "configuration_change"),
            supported_actions=("internal_status_transition", "internal_record_note"),
            risk_class="low",
            requires_destination=False,
            requires_resource_hash=False,
            requires_human_approval=False,
            dry_run_supported=True,
            live_execution_supported=True,
            configuration_reference="internal",
        ),
        "email.send": ExecutionAdapter(
            adapter_id="email.send",
            name="Email send",
            adapter_type="email",
            version="1",
            enabled=True,
            external=True,
            supported_execution_types=("external_communication",),
            supported_actions=("send_email", "email"),
            risk_class="medium",
            requires_destination=True,
            requires_resource_hash=False,
            requires_human_approval=True,
            dry_run_supported=True,
            live_execution_supported=False,
            configuration_reference="email",
        ),
        "sms.send": ExecutionAdapter(
            adapter_id="sms.send",
            name="SMS send",
            adapter_type="sms",
            version="1",
            enabled=True,
            external=True,
            supported_execution_types=("external_communication",),
            supported_actions=("send_sms", "sms"),
            risk_class="medium",
            requires_destination=True,
            requires_resource_hash=False,
            requires_human_approval=True,
            dry_run_supported=True,
            live_execution_supported=False,
            configuration_reference="sms",
        ),
        "webhook.post": ExecutionAdapter(
            adapter_id="webhook.post",
            name="Webhook post",
            adapter_type="webhook",
            version="1",
            enabled=True,
            external=True,
            supported_execution_types=("external_communication", "publication", "other"),
            supported_actions=("webhook", "post_webhook"),
            risk_class="high",
            requires_destination=True,
            requires_resource_hash=False,
            requires_human_approval=True,
            dry_run_supported=True,
            live_execution_supported=False,
            configuration_reference="webhook",
        ),
        "document_release.release": ExecutionAdapter(
            adapter_id="document_release.release",
            name="Document release adapter",
            adapter_type="document_release",
            version="1",
            enabled=True,
            external=True,
            supported_execution_types=("document_release",),
            supported_actions=("release_letter", "release_document", "release"),
            risk_class="medium",
            requires_destination=True,
            requires_resource_hash=True,
            requires_human_approval=True,
            dry_run_supported=True,
            live_execution_supported=False,
            configuration_reference="document_release",
        ),
        "publication.publish": ExecutionAdapter(
            adapter_id="publication.publish",
            name="Publication adapter",
            adapter_type="publication",
            version="1",
            enabled=True,
            external=True,
            supported_execution_types=("publication",),
            supported_actions=("publish", "campaign"),
            risk_class="high",
            requires_destination=True,
            requires_resource_hash=False,
            requires_human_approval=True,
            dry_run_supported=True,
            live_execution_supported=False,
            configuration_reference="publication",
        ),
    }


ADAPTERS = _builtin_adapters()


def get_adapter(adapter_id: str) -> ExecutionAdapter:
    adapter = ADAPTERS.get(adapter_id)
    if adapter is None or not adapter.enabled:
        raise AdapterDenied("unknown or disabled adapter")
    return adapter


def canonical_payload(payload: dict[str, Any] | None) -> str:
    return json.dumps(payload or {}, sort_keys=True, separators=(",", ":"), default=str)


def sha256_text(value: str) -> str:
    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()


def payload_hash(payload: dict[str, Any] | None) -> str:
    return sha256_text(canonical_payload(payload))


def destination_hash(destination: str | None) -> str | None:
    if destination is None or destination == "":
        return None
    return sha256_text(destination.strip().lower())


def mask_destination(destination: str | None, adapter_type: str) -> str | None:
    if not destination:
        return None
    if adapter_type == "email" and "@" in destination:
        name, _, domain = destination.partition("@")
        return (name[:1] + "***@" + domain.lower()) if name else "***@" + domain.lower()
    if adapter_type == "sms":
        return destination[:3] + "****" + destination[-2:]
    if adapter_type == "webhook":
        parsed = urlparse(destination)
        return f"{parsed.scheme}://{parsed.hostname}/***"
    if len(destination) <= 4:
        return "***"
    return destination[:2] + "***"


def _is_private_host(host: str) -> bool:
    host = (host or "").strip().lower().rstrip(".")
    if host in BLOCKED_WEBHOOK_HOSTS or host.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(ip in net for net in PRIVATE_NETWORKS)


def validate_destination(adapter: ExecutionAdapter, destination: str | None, allowed: list[str], env: str = "test") -> str:
    if not adapter.requires_destination:
        return destination or ""
    value = (destination or "").strip()
    if not value:
        raise AdapterDenied("destination is required")
    kind = adapter.adapter_type
    if kind == "email":
        value = value.lower()
        if not EMAIL_RE.match(value) or len(value) > 254:
            raise AdapterDenied("invalid email destination")
        if env != "test" and value.endswith(("@example.com", "@example.test", "@example.org")):
            raise AdapterDenied("invalid email destination")
    elif kind == "sms":
        compact = value.replace(" ", "")
        if not E164_RE.match(compact):
            raise AdapterDenied("invalid SMS destination")
        value = compact
    elif kind == "webhook":
        parsed = urlparse(value)
        if parsed.scheme != "https":
            raise AdapterDenied("webhook destination must be HTTPS")
        host = (parsed.hostname or "").lower()
        if not host:
            raise AdapterDenied("invalid webhook destination")
        if _is_private_host(host):
            raise AdapterDenied("webhook destination is not publicly allowable")
        if parsed.username or parsed.password:
            raise AdapterDenied("webhook destination must not include credentials")
        allowed_hosts = {item.lower() for item in allowed if "://" not in item}
        allowed_urls = {item.lower().rstrip("/") for item in allowed}
        if allowed and host not in allowed_hosts and value.lower().rstrip("/") not in allowed_urls:
            raise AdapterDenied("webhook hostname is not allowlisted")
    if allowed and kind in {"email", "sms"} and value.lower() not in {item.lower() for item in allowed}:
        raise AdapterDenied("destination is not allowlisted for this tenant adapter")
    return value


def ensure_adapter_schema(c: sqlite3.Connection) -> None:
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS execution_adapter_policy(
            tenant_id TEXT NOT NULL,
            adapter_id TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 0,
            allowed_actions TEXT NOT NULL DEFAULT '[]',
            allowed_destinations TEXT NOT NULL DEFAULT '[]',
            max_risk_level TEXT NOT NULL DEFAULT 'low',
            requires_human_approval INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(tenant_id, adapter_id)
        );
        CREATE TABLE IF NOT EXISTS execution_plans(
            id TEXT PRIMARY KEY,
            execution_ticket_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            requesting_user_id TEXT NOT NULL,
            adapter_id TEXT NOT NULL,
            adapter_type TEXT NOT NULL,
            action TEXT NOT NULL,
            execution_type TEXT NOT NULL,
            resource_type TEXT,
            resource_id TEXT,
            resource_hash TEXT,
            destination TEXT,
            destination_hash TEXT,
            payload_hash TEXT NOT NULL,
            payload_canonical TEXT NOT NULL,
            payload_schema_version TEXT NOT NULL DEFAULT '1',
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            mode TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            approval_refs TEXT,
            constitutional_decision_id TEXT,
            evidence_chain TEXT,
            status TEXT NOT NULL,
            UNIQUE(tenant_id, execution_ticket_id, adapter_id, payload_hash, destination_hash)
        );
        CREATE TABLE IF NOT EXISTS execution_internal_effects(
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            plan_id TEXT NOT NULL,
            action TEXT NOT NULL,
            resource_id TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS execution_approval_bindings(
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            execution_ticket_id TEXT NOT NULL,
            action TEXT NOT NULL,
            adapter_id TEXT NOT NULL,
            resource_id TEXT,
            resource_hash TEXT,
            destination_hash TEXT,
            payload_hash TEXT NOT NULL,
            state TEXT NOT NULL,
            approved_at TEXT NOT NULL,
            expires_at TEXT,
            revoked_at TEXT,
            approval_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS control_events (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            workflow TEXT NOT NULL,
            action TEXT NOT NULL,
            purpose TEXT NOT NULL,
            data_classes TEXT NOT NULL,
            jurisdiction_rules TEXT NOT NULL,
            layer_results TEXT NOT NULL,
            document_id TEXT,
            document_hash TEXT,
            approved_hash TEXT,
            model_id TEXT,
            model_provider TEXT,
            model_version TEXT,
            produced_by TEXT,
            approval_ref TEXT,
            destination_hash TEXT,
            result TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            payload_json TEXT NOT NULL DEFAULT '{}'
        );
        """
    )
    existing = {row[1] for row in c.execute("PRAGMA table_info(execution_plans)").fetchall()}
    if "approval_binding_id" not in existing:
        c.execute("ALTER TABLE execution_plans ADD COLUMN approval_binding_id TEXT")
    if "approval_hash" not in existing:
        c.execute("ALTER TABLE execution_plans ADD COLUMN approval_hash TEXT")


def enable_adapter_policy(
    c: sqlite3.Connection,
    *,
    tenant_id: str,
    adapter_id: str,
    allowed_actions: list[str] | None = None,
    allowed_destinations: list[str] | None = None,
    max_risk_level: str = "critical",
    requires_human_approval: bool = False,
) -> None:
    ensure_adapter_schema(c)
    now = _iso()
    c.execute(
        """INSERT INTO execution_adapter_policy(
            tenant_id,adapter_id,enabled,allowed_actions,allowed_destinations,max_risk_level,requires_human_approval,created_at,updated_at
        ) VALUES (?,?,?,?,?,?,?,?,?)
        ON CONFLICT(tenant_id, adapter_id) DO UPDATE SET
            enabled=excluded.enabled,
            allowed_actions=excluded.allowed_actions,
            allowed_destinations=excluded.allowed_destinations,
            max_risk_level=excluded.max_risk_level,
            requires_human_approval=excluded.requires_human_approval,
            updated_at=excluded.updated_at
        """,
        (
            tenant_id,
            adapter_id,
            1,
            json.dumps(allowed_actions or []),
            json.dumps(allowed_destinations or []),
            max_risk_level,
            1 if requires_human_approval else 0,
            now,
            now,
        ),
    )



def approval_binding_hash(*, tenant_id, ticket_id, action, adapter_id, resource_id, resource_hash, destination_hash, payload_hash) -> str:
    blob = canonical_payload({
        "tenant_id": tenant_id,
        "execution_ticket_id": ticket_id,
        "action": action,
        "adapter_id": adapter_id,
        "resource_id": resource_id,
        "resource_hash": resource_hash,
        "destination_hash": destination_hash,
        "payload_hash": payload_hash,
    })
    return sha256_text(blob)


def record_approval_binding(
    c: sqlite3.Connection,
    *,
    tenant_id: str,
    ticket_id: str,
    action: str,
    adapter_id: str,
    payload_hash_value: str,
    destination_hash_value: str | None = None,
    resource_id: str | None = None,
    resource_hash: str | None = None,
    expires_at: str | None = None,
    state: str = "approved",
    revoked_at: str | None = None,
) -> dict[str, Any]:
    ensure_adapter_schema(c)
    approval_id = str(uuid.uuid4())
    digest = approval_binding_hash(
        tenant_id=tenant_id,
        ticket_id=ticket_id,
        action=action,
        adapter_id=adapter_id,
        resource_id=resource_id,
        resource_hash=resource_hash,
        destination_hash=destination_hash_value,
        payload_hash=payload_hash_value,
    )
    c.execute(
        """INSERT INTO execution_approval_bindings(
            id,tenant_id,execution_ticket_id,action,adapter_id,resource_id,resource_hash,destination_hash,
            payload_hash,state,approved_at,expires_at,revoked_at,approval_hash
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            approval_id, tenant_id, ticket_id, action, adapter_id, resource_id, resource_hash,
            destination_hash_value, payload_hash_value, state, _iso(), expires_at, revoked_at, digest,
        ),
    )
    return {"id": approval_id, "approval_hash": digest, "state": state}


def load_valid_approval(
    c: sqlite3.Connection,
    *,
    tenant_id: str,
    ticket_id: str,
    action: str,
    adapter_id: str,
    payload_hash_value: str,
    destination_hash_value: str | None,
    resource_id: str | None,
    resource_hash: str | None,
) -> dict[str, Any]:
    rows = c.execute(
        """SELECT * FROM execution_approval_bindings
           WHERE tenant_id=? AND execution_ticket_id=? AND adapter_id=? AND action=? AND state='approved'""",
        (tenant_id, ticket_id, adapter_id, action),
    ).fetchall()
    expected = approval_binding_hash(
        tenant_id=tenant_id,
        ticket_id=ticket_id,
        action=action,
        adapter_id=adapter_id,
        resource_id=resource_id,
        resource_hash=resource_hash,
        destination_hash=destination_hash_value,
        payload_hash=payload_hash_value,
    )
    now = _now()
    for row in rows:
        item = dict(row)
        if item.get("revoked_at"):
            continue
        expires = _parse_iso(item.get("expires_at"))
        if expires and now > expires:
            continue
        if item.get("approval_hash") != expected:
            continue
        if item.get("payload_hash") != payload_hash_value:
            continue
        if (item.get("destination_hash") or None) != (destination_hash_value or None):
            continue
        if (item.get("resource_hash") or None) != (resource_hash or None):
            continue
        return item
    raise AdapterDenied("human approval binding missing or mismatched")


def validate_plan_bound_approval(c: sqlite3.Connection, plan: dict[str, Any]) -> dict[str, Any]:
    binding_id = plan.get("approval_binding_id")
    stored_hash = plan.get("approval_hash")
    if not binding_id or not stored_hash:
        raise AdapterDenied("plan has no bound approval")
    row = c.execute(
        "SELECT * FROM execution_approval_bindings WHERE id=?",
        (binding_id,),
    ).fetchone()
    if row is None:
        raise AdapterDenied("plan-bound approval is missing")
    item = dict(row)
    if item["id"] != binding_id:
        raise AdapterDenied("approval binding mismatch")
    if item.get("tenant_id") != plan["tenant_id"]:
        raise AdapterDenied("approval tenant mismatch")
    if item.get("execution_ticket_id") != plan["execution_ticket_id"]:
        raise AdapterDenied("approval ticket mismatch")
    if item.get("action") != plan["action"]:
        raise AdapterDenied("approval action mismatch")
    if item.get("adapter_id") != plan["adapter_id"]:
        raise AdapterDenied("approval adapter mismatch")
    if (item.get("resource_id") or None) != (plan.get("resource_id") or None):
        raise AdapterDenied("approval resource mismatch")
    if (item.get("resource_hash") or None) != (plan.get("resource_hash") or None):
        raise AdapterDenied("approval resource hash mismatch")
    if (item.get("destination_hash") or None) != (plan.get("destination_hash") or None):
        raise AdapterDenied("approval destination hash mismatch")
    if item.get("payload_hash") != plan["payload_hash"]:
        raise AdapterDenied("approval payload hash mismatch")
    if item.get("state") != "approved" or item.get("revoked_at"):
        raise AdapterDenied("approval revoked")
    expires = _parse_iso(item.get("expires_at"))
    if expires and _now() > expires:
        raise AdapterDenied("approval expired")
    expected = approval_binding_hash(
        tenant_id=plan["tenant_id"],
        ticket_id=plan["execution_ticket_id"],
        action=plan["action"],
        adapter_id=plan["adapter_id"],
        resource_id=plan.get("resource_id"),
        resource_hash=plan.get("resource_hash"),
        destination_hash=plan.get("destination_hash"),
        payload_hash=plan["payload_hash"],
    )
    if item.get("approval_hash") != stored_hash or expected != stored_hash or item.get("approval_hash") != expected:
        raise AdapterDenied("approval hash mismatch")
    return item



def _record_control_event(c: sqlite3.Connection, *, tenant_id: str, user_id: str, action: str, result: str, extra: dict[str, Any] | None = None) -> None:
    if os.getenv("CONTROL_PLANE_FAIL_WRITE") == "1":
        raise AdapterDenied("evidence write failed")
    event = {
        "id": str(uuid.uuid4()),
        "tenant_id": tenant_id,
        "actor_id": user_id,
        "workflow": "controlled_execution",
        "action": action,
        "purpose": "execution_gateway_phase2",
        "data_classes": ["internal"],
        "jurisdiction_rules": [],
        "layer_results": {"execution_gateway": {"result": result}},
        "document_id": None,
        "document_hash": None,
        "approved_hash": None,
        "model_id": None,
        "model_provider": None,
        "model_version": None,
        "produced_by": None,
        "approval_ref": None,
        "destination_hash": None,
        "result": result,
        "created_at": _iso(),
        "payload_json": json.dumps(extra or {}, sort_keys=True),
    }
    try:
        from control_plane import persist_event
        persist_event(c, event)
        return
    except AdapterDenied:
        raise
    except Exception:
        prev_row = c.execute(
            "SELECT event_hash FROM control_events WHERE tenant_id=? ORDER BY created_at DESC, id DESC LIMIT 1",
            (tenant_id,),
        ).fetchone()
        prev = prev_row["event_hash"] if prev_row else "genesis"
        body = {
            "id": event["id"], "tenant_id": event["tenant_id"], "actor_id": event["actor_id"],
            "workflow": event["workflow"], "action": event["action"], "purpose": event["purpose"],
            "data_classes": event["data_classes"], "jurisdiction_rules": event["jurisdiction_rules"],
            "layer_results": event["layer_results"], "document_id": None, "document_hash": None,
            "approved_hash": None, "model_id": None, "model_provider": None, "model_version": None,
            "produced_by": None, "approval_ref": None, "destination_hash": None, "result": event["result"],
            "prev_hash": prev, "created_at": event["created_at"], "payload_json": event["payload_json"],
        }
        event_hash = sha256_text(json.dumps(body, sort_keys=True, default=str))
        c.execute(
            """INSERT INTO control_events(
                id,tenant_id,actor_id,workflow,action,purpose,data_classes,jurisdiction_rules,layer_results,
                document_id,document_hash,approved_hash,model_id,model_provider,model_version,produced_by,
                approval_ref,destination_hash,result,prev_hash,event_hash,created_at,payload_json
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                body["id"], body["tenant_id"], body["actor_id"], body["workflow"], body["action"], body["purpose"],
                json.dumps(body["data_classes"]), json.dumps(body["jurisdiction_rules"]), json.dumps(body["layer_results"]),
                None, None, None, None, None, None, None, None, None, body["result"], prev, event_hash,
                body["created_at"], body["payload_json"],
            ),
        )


def _require_policy(c: sqlite3.Connection, *, tenant_id: str, adapter: ExecutionAdapter, action: str, risk_level: str, destination: str | None) -> dict[str, Any]:
    policy = _policy(c, tenant_id, adapter.adapter_id)
    if not policy or not policy.get("enabled"):
        raise AdapterDenied("tenant adapter policy denies this adapter")
    allowed_actions = json.loads(policy.get("allowed_actions") or "[]")
    if allowed_actions and action not in allowed_actions:
        raise AdapterDenied("unsupported action for adapter")
    if RISK_RANK.get(risk_level, 0) > RISK_RANK.get(policy.get("max_risk_level") or "low", 0):
        raise AdapterDenied("ticket risk exceeds tenant adapter policy")
    allowed_destinations = json.loads(policy.get("allowed_destinations") or "[]")
    if destination and allowed_destinations:
        dest_ok = destination.lower() in {item.lower() for item in allowed_destinations}
        host = ""
        if "://" in destination:
            host = (urlparse(destination).hostname or "").lower()
        host_ok = host in {item.lower() for item in allowed_destinations}
        if not dest_ok and not host_ok:
            raise AdapterDenied("destination is not allowlisted for this tenant adapter")
    return policy


def _policy(c: sqlite3.Connection, tenant_id: str, adapter_id: str) -> dict[str, Any] | None:
    row = c.execute(
        "SELECT * FROM execution_adapter_policy WHERE tenant_id=? AND adapter_id=?",
        (tenant_id, adapter_id),
    ).fetchone()
    return dict(row) if row else None


def _append_evidence(plan: dict[str, Any], event: str, **fields: Any) -> None:
    chain = list(plan.get("evidence_chain") or [])
    chain.append({"event": event, "at": _iso(), **fields})
    plan["evidence_chain"] = chain


def _row_to_plan(row: sqlite3.Row | dict) -> dict[str, Any]:
    d = dict(row)
    d["execution_plan_id"] = d.get("id") or d.get("execution_plan_id")
    d["approval_refs"] = json.loads(d.get("approval_refs") or "[]")
    d["evidence_chain"] = json.loads(d.get("evidence_chain") or "[]")
    return d


def load_plan(c: sqlite3.Connection, plan_id: str, tenant_id: str) -> dict[str, Any] | None:
    ensure_adapter_schema(c)
    row = c.execute("SELECT * FROM execution_plans WHERE id=? AND tenant_id=?", (plan_id, tenant_id)).fetchone()
    return _row_to_plan(row) if row else None


def _insert_plan(c: sqlite3.Connection, plan: dict[str, Any]) -> None:
    c.execute(
        """INSERT INTO execution_plans(
            id,execution_ticket_id,tenant_id,requesting_user_id,adapter_id,adapter_type,action,execution_type,
            resource_type,resource_id,resource_hash,destination,destination_hash,payload_hash,payload_canonical,
            payload_schema_version,created_at,expires_at,mode,risk_level,approval_refs,constitutional_decision_id,
            evidence_chain,status,approval_binding_id,approval_hash
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            plan["execution_plan_id"],
            plan["execution_ticket_id"],
            plan["tenant_id"],
            plan["requesting_user_id"],
            plan["adapter_id"],
            plan["adapter_type"],
            plan["action"],
            plan["execution_type"],
            plan.get("resource_type"),
            plan.get("resource_id"),
            plan.get("resource_hash"),
            plan.get("destination"),
            plan.get("destination_hash"),
            plan["payload_hash"],
            plan["payload_canonical"],
            plan.get("payload_schema_version", "1"),
            plan["created_at"],
            plan["expires_at"],
            plan["mode"],
            plan["risk_level"],
            json.dumps(plan.get("approval_refs") or []),
            plan.get("constitutional_decision_id"),
            json.dumps(plan.get("evidence_chain") or []),
            plan["status"],
            plan.get("approval_binding_id"),
            plan.get("approval_hash"),
        ),
    )


def _update_plan_status(c: sqlite3.Connection, plan_id: str, tenant_id: str, status: str, evidence_chain: list) -> int:
    cur = c.execute(
        """UPDATE execution_plans SET status=?, evidence_chain=?
           WHERE id=? AND tenant_id=?""",
        (status, json.dumps(evidence_chain or []), plan_id, tenant_id),
    )
    return cur.rowcount


def _claim_plan(c: sqlite3.Connection, plan_id: str, tenant_id: str) -> dict[str, Any]:
    cur = c.execute(
        """UPDATE execution_plans SET status='EXECUTING'
           WHERE id=? AND tenant_id=? AND status IN ('PREPARED','DRY_RUN_COMPLETE')""",
        (plan_id, tenant_id),
    )
    if cur.rowcount != 1:
        raise AdapterDenied("replay blocked")
    row = c.execute("SELECT * FROM execution_plans WHERE id=? AND tenant_id=?", (plan_id, tenant_id)).fetchone()
    if not row:
        raise AdapterDenied("execution plan not found")
    return _row_to_plan(row)


def public_plan(plan: dict[str, Any], *, include_destination: bool = False) -> dict[str, Any]:
    adapter_type = plan.get("adapter_type") or ""
    out = {
        "execution_plan_id": plan.get("execution_plan_id") or plan.get("id"),
        "execution_ticket_id": plan["execution_ticket_id"],
        "adapter_id": plan["adapter_id"],
        "adapter_type": plan["adapter_type"],
        "action": plan["action"],
        "execution_type": plan["execution_type"],
        "resource_type": plan.get("resource_type"),
        "resource_id": plan.get("resource_id"),
        "resource_hash": plan.get("resource_hash"),
        "destination": mask_destination(plan.get("destination"), adapter_type) if include_destination else None,
        "destination_hash": plan.get("destination_hash"),
        "payload_hash": plan["payload_hash"],
        "payload_schema_version": plan.get("payload_schema_version", "1"),
        "created_at": plan["created_at"],
        "expires_at": plan["expires_at"],
        "mode": plan["mode"],
        "risk_level": plan["risk_level"],
        "approval_refs": plan.get("approval_refs") or [],
        "constitutional_decision_id": plan.get("constitutional_decision_id"),
        "evidence_chain": plan.get("evidence_chain") or [],
        "status": plan["status"],
        "external_execution_enabled": False,
    }
    return out


def prepare_execution_plan(
    c: sqlite3.Connection,
    *,
    tenant_id: str,
    user_id: str,
    ticket_id: str,
    adapter_id: str,
    action: str,
    payload: dict[str, Any] | None = None,
    destination: str | None = None,
    resource_id: str | None = None,
    resource_hash: str | None = None,
    claimed_allow: bool | None = None,
    claimed_approval: str | None = None,
    env: str = "test",
) -> dict[str, Any]:
    ensure_adapter_schema(c)
    if claimed_allow:
        raise AdapterDenied("claimed ALLOW is not trusted")
    ticket = load_ticket(c, ticket_id, tenant_id)
    if ticket is None:
        raise AdapterDenied("execution ticket not found for this tenant")
    if ticket.requesting_user_id != user_id:
        raise AdapterDenied("execution ticket does not belong to this user")
    if ticket.execution_state == "DENIED":
        raise AdapterDenied("denied ticket cannot create a plan")
    if ticket.execution_state == "PENDING":
        raise AdapterDenied("pending ticket cannot create a plan")
    if ticket.execution_state in {"CONSUMED", "CANCELLED"}:
        raise AdapterDenied("ticket is not usable")
    expires = _parse_iso(ticket.expires_at)
    if expires and _now() > expires or ticket.execution_state == "EXPIRED":
        raise AdapterDenied("expired ticket blocked")
    if ticket.execution_state != "AUTHORISED":
        raise AdapterDenied("ticket is not authorised")
    if ticket.action != action:
        raise AdapterDenied("action does not match authorised ticket")
    if ticket.resource_id and resource_id and ticket.resource_id != resource_id:
        raise AdapterDenied("resource changed")
    if ticket.resource_hash and resource_hash and ticket.resource_hash != resource_hash:
        raise AdapterDenied("resource hash changed")

    adapter = get_adapter(adapter_id)
    if adapter.tenant_allowlist and tenant_id not in adapter.tenant_allowlist:
        raise AdapterDenied("adapter is not enabled for this tenant")
    if action not in adapter.supported_actions:
        raise AdapterDenied("unsupported action for adapter")
    if ticket.execution_type not in adapter.supported_execution_types:
        raise AdapterDenied("unsupported execution type for adapter")
    if adapter.requires_resource_hash and not (resource_hash or ticket.resource_hash):
        raise AdapterDenied("resource hash required")

    _record_control_event(c, tenant_id=tenant_id, user_id=user_id, action="execution_plan_prepare_started", result="started", extra={"ticket_id": ticket.execution_ticket_id})
    policy = _require_policy(c, tenant_id=tenant_id, adapter=adapter, action=action, risk_level=ticket.risk_level, destination=destination)
    allowed_destinations = json.loads(policy.get("allowed_destinations") or "[]")
    normalised = validate_destination(adapter, destination, allowed_destinations, env=env)
    dest_hash = destination_hash(normalised) if normalised else None
    body_hash = payload_hash(payload)
    approval_row = None
    if policy.get("requires_human_approval") or adapter.requires_human_approval:
        if claimed_approval:
            raise AdapterDenied("forged approval rejected")
        approval_row = load_valid_approval(
            c,
            tenant_id=tenant_id,
            ticket_id=ticket.execution_ticket_id,
            action=action,
            adapter_id=adapter.adapter_id,
            payload_hash_value=body_hash,
            destination_hash_value=dest_hash,
            resource_id=resource_id or ticket.resource_id,
            resource_hash=resource_hash or ticket.resource_hash,
        )
    created = _now()
    plan = {
        "execution_plan_id": str(uuid.uuid4()),
        "execution_ticket_id": ticket.execution_ticket_id,
        "tenant_id": tenant_id,
        "requesting_user_id": user_id,
        "adapter_id": adapter.adapter_id,
        "adapter_type": adapter.adapter_type,
        "action": action,
        "execution_type": ticket.execution_type,
        "resource_type": ticket.resource_type,
        "resource_id": resource_id or ticket.resource_id,
        "resource_hash": resource_hash or ticket.resource_hash,
        "destination": normalised,
        "destination_hash": dest_hash,
        "payload_hash": body_hash,
        "payload_canonical": canonical_payload(payload),
        "payload_schema_version": "1",
        "created_at": _iso(created),
        "expires_at": _iso(created + timedelta(minutes=PLAN_TTL_MINUTES)),
        "mode": "dry_run",
        "risk_level": ticket.risk_level,
        "approval_refs": list(ticket.approval_refs),
        "approval_binding_id": None if approval_row is None else approval_row["id"],
        "approval_hash": None if approval_row is None else approval_row["approval_hash"],
        "constitutional_decision_id": ticket.orchestrator_decision_id,
        "evidence_chain": [
            {"event": "execution_plan_prepare_started", "ticket_id": ticket.execution_ticket_id, "at": _iso()},
            {"event": "execution_adapter_selected", "adapter_id": adapter.adapter_id, "at": _iso()},
            {"event": "execution_payload_hashed", "payload_hash": body_hash, "at": _iso()},
            {"event": "execution_destination_validated", "destination_hash": dest_hash, "at": _iso()},
            {"event": "execution_resource_revalidated", "resource_hash": resource_hash or ticket.resource_hash, "at": _iso()},
            {"event": "execution_plan_prepared", "at": _iso()},
        ],
        "status": "PREPARED",
    }
    try:
        _insert_plan(c, plan)
        c.commit()
    except sqlite3.IntegrityError:
        existing = c.execute(
            """SELECT * FROM execution_plans WHERE tenant_id=? AND execution_ticket_id=? AND adapter_id=?
               AND payload_hash=? AND IFNULL(destination_hash,'')=IFNULL(?, '')""",
            (tenant_id, ticket.execution_ticket_id, adapter.adapter_id, body_hash, dest_hash),
        ).fetchone()
        if existing:
            return _row_to_plan(existing)
        raise
    return plan


def dry_run_execution_plan(
    c: sqlite3.Connection,
    *,
    tenant_id: str,
    user_id: str,
    plan_id: str,
    payload: dict[str, Any] | None = None,
    destination: str | None = None,
) -> dict[str, Any]:
    plan = load_plan(c, plan_id, tenant_id)
    if plan is None:
        raise AdapterDenied("execution plan not found")
    if plan["requesting_user_id"] != user_id:
        raise AdapterDenied("execution plan does not belong to this user")
    if plan["status"] in {"BLOCKED", "CANCELLED"}:
        raise AdapterDenied("plan is blocked")
    expires = _parse_iso(plan["expires_at"])
    if expires and _now() > expires:
        plan["status"] = "EXPIRED"
        _append_evidence(plan, "execution_plan_expired")
        _update_plan_status(c, plan.get("id") or plan["execution_plan_id"], tenant_id, plan["status"], plan.get("evidence_chain") or [])
        c.commit()
        raise AdapterDenied("expired plan blocked")
    if payload is not None and payload_hash(payload) != plan["payload_hash"]:
        raise AdapterDenied("payload change blocked")
    if destination is not None and destination_hash(destination) != plan.get("destination_hash"):
        raise AdapterDenied("destination change blocked")
    adapter = get_adapter(plan["adapter_id"])
    _append_evidence(plan, "execution_dry_run_started")
    _record_control_event(c, tenant_id=tenant_id, user_id=user_id, action="execution_dry_run_started", result="dry_run", extra={"plan_id": plan_id})
    preview = {
        "mode": "dry_run",
        "adapter": adapter.adapter_type,
        "adapter_id": adapter.adapter_id,
        "to": mask_destination(plan.get("destination"), adapter.adapter_type),
        "payload_hash": plan["payload_hash"],
        "destination_hash": plan.get("destination_hash"),
        "execution_allowed": False if adapter.external else True,
        "reason": "External execution disabled in Phase 2" if adapter.external else "Internal dry-run only; live execute still gated",
    }
    if "subject" in json.loads(plan.get("payload_canonical") or "{}"):
        preview["subject_hash"] = sha256_text(str(json.loads(plan["payload_canonical"]).get("subject")))
    if "body" in json.loads(plan.get("payload_canonical") or "{}"):
        preview["body_hash"] = sha256_text(str(json.loads(plan["payload_canonical"]).get("body")))
    plan["status"] = "DRY_RUN_COMPLETE"
    _append_evidence(plan, "execution_dry_run_completed")
    _record_control_event(c, tenant_id=tenant_id, user_id=user_id, action="execution_dry_run_completed", result="dry_run", extra={"plan_id": plan_id})
    plan_id_value = plan.get("id") or plan.get("execution_plan_id")
    plan["execution_plan_id"] = plan_id_value
    _update_plan_status(c, plan.get("id") or plan.get("execution_plan_id"), tenant_id, plan["status"], plan.get("evidence_chain") or [])
    c.commit()
    out = public_plan(plan, include_destination=True)
    out["dry_run"] = preview
    return out


def execute_execution_plan(
    c: sqlite3.Connection,
    *,
    tenant_id: str,
    user_id: str,
    plan_id: str,
    payload: dict[str, Any] | None = None,
    destination: str | None = None,
    resource_id: str | None = None,
    resource_hash: str | None = None,
) -> dict[str, Any]:
    loaded = load_plan(c, plan_id, tenant_id)
    if loaded is None:
        raise AdapterDenied("execution plan not found")
    if loaded["requesting_user_id"] != user_id:
        raise AdapterDenied("execution plan does not belong to this user")
    adapter = get_adapter(loaded["adapter_id"])
    if adapter.external or not adapter.live_execution_supported:
        _append_evidence(loaded, "execution_plan_blocked", reason="external_disabled")
        _update_plan_status(c, plan_id, tenant_id, "BLOCKED", loaded.get("evidence_chain") or [])
        _record_control_event(c, tenant_id=tenant_id, user_id=user_id, action="execution_plan_blocked", result="blocked", extra={"plan_id": plan_id})
        c.commit()
        raise AdapterDenied("External execution disabled in Controlled Execution Gateway Phase 2")

    expires = _parse_iso(loaded["expires_at"])
    if expires and _now() > expires:
        _append_evidence(loaded, "execution_plan_expired")
        _update_plan_status(c, plan_id, tenant_id, "EXPIRED", loaded.get("evidence_chain") or [])
        _record_control_event(c, tenant_id=tenant_id, user_id=user_id, action="execution_plan_expired", result="expired", extra={"plan_id": plan_id})
        c.commit()
        raise AdapterDenied("expired plan blocked")
    if payload is not None and payload_hash(payload) != loaded["payload_hash"]:
        raise AdapterDenied("payload change blocked")
    if destination is not None and destination_hash(destination) != loaded.get("destination_hash"):
        raise AdapterDenied("destination change blocked")

    plan = _claim_plan(c, plan_id, tenant_id)
    _record_control_event(c, tenant_id=tenant_id, user_id=user_id, action="execution_internal_started", result="executing", extra={"plan_id": plan_id})
    try:
        adapter = get_adapter(plan["adapter_id"])
        policy = _require_policy(
            c,
            tenant_id=tenant_id,
            adapter=adapter,
            action=plan["action"],
            risk_level=plan["risk_level"],
            destination=plan.get("destination"),
        )
        approval_required = adapter.requires_human_approval or bool(policy.get("requires_human_approval"))
        if approval_required:
            validate_plan_bound_approval(c, plan)
        ticket = consume_execution_ticket(
            connection=c,
            ticket_id=plan["execution_ticket_id"],
            tenant_id=tenant_id,
            user_id=user_id,
            exact_action=plan["action"],
            resource_id=resource_id or plan.get("resource_id"),
            resource_hash=resource_hash or plan.get("resource_hash"),
            commit=False,
        )
        if ticket.execution_state != "CONSUMED":
            raise AdapterDenied("ticket could not be consumed")
        handler = INTERNAL_EXECUTORS.get(plan["action"])
        if handler is None:
            raise AdapterDenied("no explicit internal executor for this action")
        effect_id = handler(c, plan)
        _append_evidence(plan, "execution_internal_completed", effect_id=effect_id)
        _update_plan_status(c, plan_id, tenant_id, "EXECUTED", plan.get("evidence_chain") or [])
        _record_control_event(c, tenant_id=tenant_id, user_id=user_id, action="execution_internal_completed", result="executed", extra={"plan_id": plan_id, "effect_id": effect_id})
        c.commit()
    except Exception:
        c.rollback()
        try:
            _update_plan_status(c, plan_id, tenant_id, "BLOCKED", (plan.get("evidence_chain") or []) + [{"event": "execution_plan_blocked", "at": _iso()}])
            c.commit()
        except Exception:
            pass
        raise
    out = public_plan({**plan, "status": "EXECUTED"})
    out["internal_effect_id"] = effect_id
    return out


def _internal_record_note(c: sqlite3.Connection, plan: dict[str, Any]) -> str:
    effect_id = str(uuid.uuid4())
    c.execute(
        "INSERT INTO execution_internal_effects(id,tenant_id,plan_id,action,resource_id,created_at) VALUES (?,?,?,?,?,?)",
        (effect_id, plan["tenant_id"], plan.get("id") or plan.get("execution_plan_id"), plan["action"], plan.get("resource_id"), _iso()),
    )
    return effect_id


INTERNAL_EXECUTORS = {
    "internal_record_note": _internal_record_note,
    "internal_status_transition": _internal_record_note,
}
