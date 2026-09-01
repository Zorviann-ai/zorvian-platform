"""Shared Three-Layer Control Plane — Integration Stage 1.

Fail-closed gates for existing Core document release.
The event chain is tamper-evident, not database-immutable.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import uuid
from typing import Any

from fastapi import HTTPException
from intelligence.legal import assess_document_release

ALLOWED_DATA_CLASSES = {
    "public",
    "internal",
    "personal",
    "special_category",
    "financial",
    "child",
    "health",
}
ALLOWED_ORG_TYPES = {
    "general",
    "legal_services",
    "financial",
    "healthcare",
    "education",
    "motor",
    "other",
}
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

DOCUMENT_COLUMNS = [
    ("content_hash", "TEXT"),
    ("version", "INTEGER NOT NULL DEFAULT 1"),
    ("approved_by", "TEXT"),
    ("approved_at", "TEXT"),
    ("approved_hash", "TEXT"),
    ("approval_revoked_at", "TEXT"),
    ("released_at", "TEXT"),
    ("purpose", "TEXT"),
    ("data_classes", "TEXT"),
    ("produced_by", "TEXT NOT NULL DEFAULT 'human'"),
    ("produced_by_model_id", "TEXT"),
    ("produced_by_provider", "TEXT"),
    ("produced_by_version", "TEXT"),
]


class FailClosed(HTTPException):
    def __init__(self, detail: str, status_code: int = 403):
        super().__init__(status_code=status_code, detail=detail)


def content_hash(body: str) -> str:
    return hashlib.sha256((body or "").encode("utf-8")).hexdigest()


def destination_hash(destination: str) -> str:
    return hashlib.sha256((destination or "").strip().lower().encode("utf-8")).hexdigest()


def validate_destination(destination: str) -> str:
    value = (destination or "").strip()
    if not value:
        raise FailClosed("destination is required")
    if value.lower() in {"client@example.test", "example@example.com", "user@example.com"}:
        raise FailClosed("invalid destination")
    if not EMAIL_RE.match(value) or len(value) > 254:
        raise FailClosed("invalid destination")
    return value


def parse_data_classes(raw) -> list[str]:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            raw = [p.strip() for p in raw.split(",") if p.strip()]
    if not raw:
        raise FailClosed("data classification is required")
    classes = []
    for item in raw:
        item = str(item).strip().lower()
        if item not in ALLOWED_DATA_CLASSES:
            raise FailClosed("invalid data classification")
        if item not in classes:
            classes.append(item)
    return classes


def validate_purpose(purpose: str) -> str:
    value = (purpose or "").strip()
    if len(value) < 3 or len(value) > 120:
        raise FailClosed("purpose must be declared")
    return value


def init_control_schema(c: sqlite3.Connection) -> None:
    script_path = os.path.join(os.path.dirname(__file__), "migrations", "0002_control_plane_stage1.sql")
    with open(script_path, encoding="utf-8") as fh:
        c.executescript(fh.read())
    existing = {r[1] for r in c.execute("PRAGMA table_info(documents)").fetchall()}
    for name, decl in DOCUMENT_COLUMNS:
        if name not in existing:
            c.execute(f"ALTER TABLE documents ADD COLUMN {name} {decl}")


def ensure_tenant_profile(c: sqlite3.Connection, tenant_id: str) -> dict:
    row = c.execute("SELECT * FROM control_tenant_profile WHERE tenant_id=?", (tenant_id,)).fetchone()
    if row:
        return dict(row)
    c.execute(
        "INSERT INTO control_tenant_profile(tenant_id,home_jurisdiction,org_type,is_financial_entity,is_essential_entity,sectors) VALUES (?,?,?,?,?,?)",
        (tenant_id, "", "general", 0, 0, ""),
    )
    return dict(c.execute("SELECT * FROM control_tenant_profile WHERE tenant_id=?", (tenant_id,)).fetchone())


def _sectors(profile: dict) -> set[str]:
    raw = profile.get("sectors") or ""
    parts = {p.strip().lower() for p in str(raw).replace(";", ",").split(",") if p.strip()}
    org = (profile.get("org_type") or "general").lower()
    if org:
        parts.add(org)
    return parts


def evaluate_layers(profile: dict, action: str, data_classes: list[str], produced_by: str = "human") -> dict[str, Any]:
    jurisdiction = profile.get("home_jurisdiction") or ""
    sectors = _sectors(profile)
    financial_entity = bool(profile.get("is_financial_entity"))
    essential = bool(profile.get("is_essential_entity"))
    personal = bool(set(data_classes) & {"personal", "special_category", "child", "health"})
    ai_used = produced_by == "model"
    financial_action = action in {"pay", "publish_promotion", "give_investment_advice"}
    nis_action = action in {"report_incident", "operate_essential_service"}

    legal_rules, legal_reasons = [], []
    legal_result = "not_applicable"
    if personal and jurisdiction == "UK":
        legal_rules.append("UK_GDPR")
        legal_reasons.append("personal data and UK jurisdiction")
        legal_result = "pass"
    elif personal and jurisdiction in {"EU", "DE", "FR", "IE", "NL"}:
        legal_rules.append("GDPR")
        legal_reasons.append("personal data and EU jurisdiction")
        legal_result = "pass"
    elif personal and not jurisdiction:
        legal_result = "review_required"
        legal_reasons.append("personal data present but jurisdiction is not declared")
    elif personal:
        legal_result = "review_required"
        legal_reasons.append("personal data present but no matching data-protection rule was established")

    if ai_used and jurisdiction in {"EU", "DE", "FR", "IE", "NL"}:
        legal_rules.append("AI_ACT")
        legal_reasons.append("model-produced output in EU jurisdiction")
        if legal_result == "not_applicable":
            legal_result = "pass"
    elif ai_used and not jurisdiction:
        legal_result = "review_required"
        legal_reasons.append("model-produced output but jurisdiction is not declared")

    fin_rules, fin_reasons = [], []
    if not financial_entity or not financial_action:
        financial_result = "not_applicable"
        fin_reasons.append("action is not a financial-regulated activity for this tenant")
    elif jurisdiction == "UK":
        fin_rules += ["FCA", "CONSUMER_DUTY"]
        financial_result = "pass"
        fin_reasons.append("UK financial entity performing a financial activity")
    elif jurisdiction in {"EU", "DE", "FR", "IE", "NL"}:
        if action == "pay":
            fin_rules.append("DORA")
        if action == "give_investment_advice":
            fin_rules.append("MIFID_II")
        if action == "publish_promotion":
            fin_rules.append("MIFID_II")
        financial_result = "pass" if fin_rules else "review_required"
        fin_reasons.append("EU financial entity; only activity-matched regimes applied")
    else:
        financial_result = "review_required"
        fin_reasons.append("financial entity without a declared matching jurisdiction")

    guard_rules, guard_reasons = [], []
    guardian_result = "review_required"
    if essential and nis_action and jurisdiction in {"EU", "DE", "FR", "IE", "NL"}:
        guard_rules.append("NIS2")
        guard_reasons.append("essential entity incident/service action in EU")
    if essential and nis_action and jurisdiction == "UK":
        guard_rules.append("UK_NIS")
        guard_reasons.append("essential entity incident/service action in UK")

    return {
        "legal_intelligence": {"result": legal_result, "rules": legal_rules, "reasons": legal_reasons},
        "financial_intelligence": {"result": financial_result, "rules": fin_rules, "reasons": fin_reasons},
        "guardian": {"result": guardian_result, "rules": guard_rules, "reasons": guard_reasons},
        "all_rules": legal_rules + fin_rules + guard_rules,
    }


def resolve_model(c: sqlite3.Connection, document: dict, claimed_model_id: str | None, action: str, tenant_id: str) -> dict[str, Any]:
    produced_by = (document.get("produced_by") or "").strip() or "human"
    stored_model = document.get("produced_by_model_id")
    stored_provider = document.get("produced_by_provider")
    stored_version = document.get("produced_by_version")
    if claimed_model_id and claimed_model_id != stored_model:
        raise FailClosed("model provenance mismatch")
    if produced_by == "model":
        if not stored_model:
            raise FailClosed("model provenance missing")
        row = c.execute("SELECT * FROM control_model_cards WHERE id=? AND (tenant_id IS NULL OR tenant_id=?)", (stored_model, tenant_id)).fetchone()
        if not row:
            raise FailClosed("model not registered")
        model = dict(row)
        if stored_provider and stored_provider != model.get("provider"):
            raise FailClosed("model provider mismatch")
        if stored_version and stored_version != model.get("version"):
            raise FailClosed("model version mismatch")
        if not model["approved"] or not model["enabled"]:
            raise FailClosed("unapproved model blocked")
        allowed = {p.strip() for p in (model.get("allowed_actions") or "").split(",") if p.strip()}
        if allowed and action not in allowed:
            raise FailClosed("model not approved for this action")
        return {
            "id": model["id"],
            "provider": model.get("provider"),
            "version": model.get("version"),
            "produced_by": "model",
        }
    if stored_model:
        raise FailClosed("model provenance mismatch")
    return {"id": None, "provider": None, "version": None, "produced_by": "human"}


def last_event_hash(c: sqlite3.Connection, tenant_id: str) -> str:
    row = c.execute(
        "SELECT event_hash FROM control_events WHERE tenant_id=? ORDER BY created_at DESC, id DESC LIMIT 1",
        (tenant_id,),
    ).fetchone()
    return row["event_hash"] if row else "genesis"


def compute_event_hash(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


def persist_event(c: sqlite3.Connection, event: dict[str, Any]) -> dict[str, Any]:
    if os.getenv("CONTROL_PLANE_FAIL_WRITE") == "1":
        raise FailClosed("evidence write failed", status_code=500)
    prev = last_event_hash(c, event["tenant_id"])
    body = {
        "id": event["id"],
        "tenant_id": event["tenant_id"],
        "actor_id": event["actor_id"],
        "workflow": event["workflow"],
        "action": event["action"],
        "purpose": event["purpose"],
        "data_classes": event["data_classes"],
        "jurisdiction_rules": event["jurisdiction_rules"],
        "layer_results": event["layer_results"],
        "document_id": event.get("document_id"),
        "document_hash": event.get("document_hash"),
        "approved_hash": event.get("approved_hash"),
        "model_id": event.get("model_id"),
        "model_provider": event.get("model_provider"),
        "model_version": event.get("model_version"),
        "produced_by": event.get("produced_by"),
        "approval_ref": event.get("approval_ref"),
        "destination_hash": event.get("destination_hash"),
        "result": event["result"],
        "prev_hash": prev,
        "created_at": event["created_at"],
        "payload_json": event.get("payload_json") or "{}",
    }
    event_hash = compute_event_hash(body)
    c.execute(
        """INSERT INTO control_events(
            id,tenant_id,actor_id,workflow,action,purpose,data_classes,jurisdiction_rules,layer_results,
            document_id,document_hash,approved_hash,model_id,model_provider,model_version,produced_by,
            approval_ref,destination_hash,result,prev_hash,event_hash,created_at,payload_json
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            body["id"], body["tenant_id"], body["actor_id"], body["workflow"], body["action"], body["purpose"],
            json.dumps(body["data_classes"]), json.dumps(body["jurisdiction_rules"]), json.dumps(body["layer_results"]),
            body["document_id"], body["document_hash"], body["approved_hash"], body["model_id"], body["model_provider"],
            body["model_version"], body["produced_by"], body["approval_ref"], body["destination_hash"], body["result"],
            prev, event_hash, body["created_at"], body["payload_json"],
        ),
    )
    event["prev_hash"] = prev
    event["event_hash"] = event_hash
    return event


def verify_chain(c: sqlite3.Connection, tenant_id: str) -> dict[str, Any]:
    rows = c.execute(
        "SELECT * FROM control_events WHERE tenant_id=? ORDER BY created_at ASC, id ASC",
        (tenant_id,),
    ).fetchall()
    prev = "genesis"
    for row in rows:
        d = dict(row)
        body = {
            "id": d["id"],
            "tenant_id": d["tenant_id"],
            "actor_id": d["actor_id"],
            "workflow": d["workflow"],
            "action": d["action"],
            "purpose": d["purpose"],
            "data_classes": json.loads(d["data_classes"]),
            "jurisdiction_rules": json.loads(d["jurisdiction_rules"]),
            "layer_results": json.loads(d["layer_results"]),
            "document_id": d["document_id"],
            "document_hash": d["document_hash"],
            "approved_hash": d["approved_hash"],
            "model_id": d["model_id"],
            "model_provider": d["model_provider"],
            "model_version": d["model_version"],
            "produced_by": d["produced_by"],
            "approval_ref": d["approval_ref"],
            "destination_hash": d["destination_hash"],
            "result": d["result"],
            "prev_hash": d["prev_hash"],
            "created_at": d["created_at"],
            "payload_json": d["payload_json"],
        }
        expected = compute_event_hash(body)
        if d["prev_hash"] != prev or d["event_hash"] != expected:
            return {"ok": False, "broken_event_id": d["id"], "tamper_evident": True, "immutable": False}
        prev = d["event_hash"]
    return {"ok": True, "events": len(rows), "tamper_evident": True, "immutable": False}


def gate_release_letter(
    c: sqlite3.Connection,
    *,
    user: dict,
    document_id: str,
    destination: str,
    now_iso: str,
    claimed_tenant_id: str | None = None,
    claimed_model_id: str | None = None,
) -> dict[str, Any]:
    tenant_id = user["tenant_id"]
    if claimed_tenant_id and claimed_tenant_id != tenant_id:
        raise FailClosed("cross-tenant access denied")

    destination = validate_destination(destination)
    doc = c.execute("SELECT * FROM documents WHERE id=? AND tenant_id=?", (document_id, tenant_id)).fetchone()
    if not doc:
        raise FailClosed("document not found", status_code=404)
    doc = dict(doc)

    if doc.get("released_at"):
        raise FailClosed("document already released", status_code=409)
    if doc.get("approval_revoked_at"):
        raise FailClosed("required approval missing")
    if doc.get("status") != "Principal Approved" or not doc.get("approved_by") or not doc.get("approved_hash"):
        raise FailClosed("required approval missing")

    live_hash = content_hash(doc.get("body") or "")
    if live_hash != doc["approved_hash"]:
        raise FailClosed("approved document hash mismatch")

    if not doc.get("purpose") or not doc.get("data_classes"):
        raise FailClosed("purpose and data classification are unresolved")
    purpose = validate_purpose(doc.get("purpose") or "")
    data_classes = parse_data_classes(doc.get("data_classes"))
    profile = ensure_tenant_profile(c, tenant_id)
    model = resolve_model(c, doc, claimed_model_id, "release_letter", tenant_id)
    layers = evaluate_layers(profile, "release_letter", data_classes, model["produced_by"])
    if layers["legal_intelligence"]["result"] == "review_required":
        raise FailClosed("legal intelligence review required")

    legal = assess_document_release(user=user, document=doc, profile=profile, destination=destination)
    layers["legal_intelligence"]["assessment_id"] = legal.legal_assessment_id
    layers["legal_intelligence"]["control"] = {
        "execution_allowed": legal.execution_allowed,
        "risk_level": legal.risk_level,
        "authority_state": legal.authority_state,
        "evidence_state": legal.evidence_state,
        "human_legal_review_required": legal.human_legal_review_required,
    }
    if not legal.execution_allowed:
        raise FailClosed("legal intelligence blocked controlled release: " + legal.reasoning_summary)
    if layers["financial_intelligence"]["result"] == "review_required":
        raise FailClosed("financial intelligence review required")
    guardian_checks = [
        ("ACCESS_CONTROL", "authenticated actor and approve right"),
        ("TENANT_ISOLATION", "document tenant matches session tenant"),
        ("APPROVAL_HASH", "live body hash matches approved hash"),
        ("TAMPER_EVIDENT_LOG", "control event will be hash-chained"),
    ]
    layers["guardian"] = {
        "result": "pass",
        "rules": [c[0] for c in guardian_checks] + layers["guardian"]["rules"],
        "reasons": [c[1] for c in guardian_checks] + layers["guardian"]["reasons"],
    }
    layers["all_rules"] = layers["legal_intelligence"]["rules"] + layers["financial_intelligence"]["rules"] + layers["guardian"]["rules"]

    updated = c.execute(
        """UPDATE documents SET status='Released', released_at=?
           WHERE id=? AND tenant_id=? AND status='Principal Approved'
             AND approval_revoked_at IS NULL AND released_at IS NULL""",
        (now_iso, document_id, tenant_id),
    )
    if updated.rowcount != 1:
        raise FailClosed("document already released", status_code=409)

    event = persist_event(
        c,
        {
            "id": str(uuid.uuid4()),
            "tenant_id": tenant_id,
            "actor_id": user["id"],
            "workflow": "legal_correspondence",
            "action": "release_letter",
            "purpose": purpose,
            "data_classes": data_classes,
            "jurisdiction_rules": layers["all_rules"],
            "layer_results": {
                "legal_intelligence": layers["legal_intelligence"],
                "financial_intelligence": layers["financial_intelligence"],
                "guardian": layers["guardian"],
            },
            "document_id": document_id,
            "document_hash": live_hash,
            "approved_hash": doc["approved_hash"],
            "model_id": model["id"],
            "model_provider": model["provider"],
            "model_version": model["version"],
            "produced_by": model["produced_by"],
            "approval_ref": doc.get("approved_by"),
            "destination_hash": destination_hash(destination),
            "result": "released",
            "created_at": now_iso,
            "payload_json": json.dumps({"version": doc.get("version") or 1}),
        },
    )
    event["layer_results"] = {
        "legal_intelligence": layers["legal_intelligence"],
        "financial_intelligence": layers["financial_intelligence"],
        "guardian": layers["guardian"],
    }
    return event


def trace_event(c: sqlite3.Connection, tenant_id: str, event_id: str) -> dict[str, Any]:
    row = c.execute("SELECT * FROM control_events WHERE id=? AND tenant_id=?", (event_id, tenant_id)).fetchone()
    if not row:
        raise FailClosed("event not found", status_code=404)
    d = dict(row)
    payload = json.loads(d["payload_json"] or "{}")
    payload.pop("body", None)
    payload.pop("destination", None)
    return {
        "who_requested": d["actor_id"],
        "tenant": d["tenant_id"],
        "action": d["action"],
        "purpose": d["purpose"],
        "data_classification": json.loads(d["data_classes"]),
        "jurisdiction_rules": json.loads(d["jurisdiction_rules"]),
        "layer_results": json.loads(d["layer_results"]),
        "model": d["model_id"],
        "model_provider": d["model_provider"],
        "model_version": d["model_version"],
        "produced_by": d["produced_by"],
        "document_id": d["document_id"],
        "document_hash": d["document_hash"],
        "approved_hash": d["approved_hash"],
        "approval_ref": d["approval_ref"],
        "destination_hash": d["destination_hash"],
        "timestamp": d["created_at"],
        "event_id": d["id"],
        "event_hash": d["event_hash"],
        "prev_hash": d["prev_hash"],
        "result": d["result"],
        "payload": payload,
        "chain": verify_chain(c, tenant_id),
        "evidence": "tamper-evident",
    }
