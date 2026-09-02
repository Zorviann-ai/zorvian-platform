"""Controlled Execution Gateway Phase 1.

Bound between constitutional decision and execution.
Phase 1 authorises tickets only. External execution stays disabled.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from intelligence.orchestrator import decide as constitutional_decide

STATES = ("PENDING", "AUTHORISED", "DENIED", "EXPIRED", "CANCELLED", "CONSUMED")
EXECUTION_TYPES = (
    "internal_release", "external_communication", "document_release", "financial_action",
    "payment_instruction", "refund_instruction", "legal_action", "data_export",
    "identity_change", "configuration_change", "publication", "supplier_action",
    "security_action", "other",
)

HIGH_EXPIRY_MINUTES = int(os.getenv("EXECUTION_TICKET_HIGH_EXPIRY_MINUTES", "15"))
NORMAL_EXPIRY_MINUTES = int(os.getenv("EXECUTION_TICKET_NORMAL_EXPIRY_MINUTES", "60"))


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _iso(dt: datetime | None = None) -> str:
    value = dt or _now()
    return value.isoformat().replace("+00:00", "Z")


def _parse_iso(raw: str | None) -> datetime | None:
    if not raw:
        return None
    return datetime.fromisoformat(raw.replace("Z", "+00:00"))


def classify_execution_type(action: str) -> str:
    blob = (action or "").lower()
    mapping = (
        ("document_release", ("release_document", "release_letter", "release")),
        ("payment_instruction", ("pay", "payment")),
        ("refund_instruction", ("refund",)),
        ("financial_action", ("invoice", "beneficiary", "financial")),
        ("legal_action", ("legal", "litigation", "hold")),
        ("data_export", ("export", "dump")),
        ("identity_change", ("password", "role", "invite", "mfa")),
        ("configuration_change", ("config", "setting", "provider credential")),
        ("publication", ("publish", "campaign")),
        ("external_communication", ("email", "sms", "notify")),
        ("supplier_action", ("supplier", "vendor")),
        ("security_action", ("guardian", "security", "incident")),
        ("internal_release", ("internal", "draft")),
    )
    for kind, markers in mapping:
        if any(m in blob for m in markers):
            return kind
    return "other"


def expiry_minutes(risk_level: str, consequential: bool) -> int:
    if risk_level in {"high", "critical"}:
        return max(1, HIGH_EXPIRY_MINUTES)
    if consequential:
        return max(1, NORMAL_EXPIRY_MINUTES)
    return max(1, NORMAL_EXPIRY_MINUTES)


def ensure_execution_schema(c: sqlite3.Connection) -> None:
    from intelligence.execution_adapters import ensure_adapter_schema
    from intelligence.execution_live import ensure_phase3_schema
    from intelligence.execution_pilot_ops import ensure_stage4b_schema
    from intelligence.execution_pilot_activation import ensure_stage4c1_schema
    ensure_adapter_schema(c)
    ensure_phase3_schema(c)
    ensure_stage4b_schema(c)
    ensure_stage4c1_schema(c)
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS execution_tickets(
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            requesting_user_id TEXT NOT NULL,
            module TEXT NOT NULL,
            action TEXT NOT NULL,
            resource_type TEXT,
            resource_id TEXT,
            resource_hash TEXT,
            consequential_action INTEGER NOT NULL DEFAULT 0,
            orchestrator_decision_id TEXT,
            constitutional_outcome TEXT,
            legal_assessment_id TEXT,
            financial_assessment_id TEXT,
            guardian_assessment_id TEXT,
            approval_refs TEXT,
            execution_type TEXT NOT NULL,
            execution_state TEXT NOT NULL,
            authority_state TEXT,
            evidence_state TEXT,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            executed_at TEXT,
            idempotency_key TEXT,
            reasoning_summary TEXT,
            blocking_reasons TEXT,
            missing_information TEXT,
            evidence_chain TEXT,
            risk_level TEXT,
            claimed_outcome TEXT,
            UNIQUE(tenant_id, idempotency_key)
        )
        """
    )


@dataclass
class ExecutionTicket:
    execution_ticket_id: str
    tenant_id: str
    requesting_user_id: str
    module: str
    action: str
    resource_type: str | None
    resource_id: str | None
    resource_hash: str | None
    consequential_action: bool
    orchestrator_decision_id: str | None
    constitutional_outcome: str
    legal_assessment_id: str | None
    financial_assessment_id: str | None
    guardian_assessment_id: str | None
    approval_refs: list[str]
    execution_type: str
    execution_state: str
    authority_state: str
    evidence_state: str
    created_at: str
    expires_at: str
    executed_at: str | None
    idempotency_key: str | None
    reasoning_summary: str
    blocking_reasons: list[str]
    missing_information: list[str]
    evidence_chain: list[dict[str, Any]] = field(default_factory=list)
    risk_level: str = "low"
    external_execution_enabled: bool = False
    user_facing: str = ""
    audit_events: list[str] = field(default_factory=list)

    def as_public(self) -> dict[str, Any]:
        return {
            "execution_ticket_id": self.execution_ticket_id,
            "module": self.module,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "resource_hash": self.resource_hash,
            "consequential_action": self.consequential_action,
            "orchestrator_decision_id": self.orchestrator_decision_id,
            "constitutional_outcome": self.constitutional_outcome,
            "legal_assessment_id": self.legal_assessment_id,
            "financial_assessment_id": self.financial_assessment_id,
            "guardian_assessment_id": self.guardian_assessment_id,
            "approval_refs": self.approval_refs,
            "execution_type": self.execution_type,
            "execution_state": self.execution_state,
            "authority_state": self.authority_state,
            "evidence_state": self.evidence_state,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "executed_at": self.executed_at,
            "idempotency_key": self.idempotency_key,
            "reasoning_summary": self.reasoning_summary,
            "blocking_reasons": self.blocking_reasons,
            "missing_information": self.missing_information,
            "evidence_chain": self.evidence_chain,
            "risk_level": self.risk_level,
            "external_execution_enabled": False,
            "user_facing": self.user_facing,
        }


def _row_to_ticket(row: sqlite3.Row | dict) -> ExecutionTicket:
    d = dict(row)
    return ExecutionTicket(
        execution_ticket_id=d["id"],
        tenant_id=d["tenant_id"],
        requesting_user_id=d["requesting_user_id"],
        module=d["module"],
        action=d["action"],
        resource_type=d.get("resource_type"),
        resource_id=d.get("resource_id"),
        resource_hash=d.get("resource_hash"),
        consequential_action=bool(d.get("consequential_action")),
        orchestrator_decision_id=d.get("orchestrator_decision_id"),
        constitutional_outcome=d.get("constitutional_outcome") or "",
        legal_assessment_id=d.get("legal_assessment_id"),
        financial_assessment_id=d.get("financial_assessment_id"),
        guardian_assessment_id=d.get("guardian_assessment_id"),
        approval_refs=json.loads(d.get("approval_refs") or "[]"),
        execution_type=d.get("execution_type") or "other",
        execution_state=d["execution_state"],
        authority_state=d.get("authority_state") or "unknown",
        evidence_state=d.get("evidence_state") or "partial",
        created_at=d["created_at"],
        expires_at=d["expires_at"],
        executed_at=d.get("executed_at"),
        idempotency_key=d.get("idempotency_key"),
        reasoning_summary=d.get("reasoning_summary") or "",
        blocking_reasons=json.loads(d.get("blocking_reasons") or "[]"),
        missing_information=json.loads(d.get("missing_information") or "[]"),
        evidence_chain=json.loads(d.get("evidence_chain") or "[]"),
        risk_level=d.get("risk_level") or "low",
        user_facing=_facing(d["execution_state"], d.get("reasoning_summary") or ""),
        audit_events=["execution_ticket_loaded"],
    )


def _facing(state: str, reason: str) -> str:
    labels = {
        "AUTHORISED": "EXECUTION: AUTHORISED",
        "PENDING": "EXECUTION: PENDING REVIEW",
        "DENIED": "EXECUTION: DENIED",
        "EXPIRED": "EXECUTION: EXPIRED",
        "CANCELLED": "EXECUTION: CANCELLED",
        "CONSUMED": "EXECUTION: CONSUMED",
    }
    heading = labels.get(state, "EXECUTION: DENIED")
    extra = " External execution is disabled in Phase 1." if state == "AUTHORISED" else ""
    return heading + "\n\nReason:\n" + reason + extra


def _persist(c: sqlite3.Connection, ticket: ExecutionTicket) -> None:
    ensure_execution_schema(c)
    c.execute(
        """INSERT OR REPLACE INTO execution_tickets(
            id,tenant_id,requesting_user_id,module,action,resource_type,resource_id,resource_hash,
            consequential_action,orchestrator_decision_id,constitutional_outcome,legal_assessment_id,
            financial_assessment_id,guardian_assessment_id,approval_refs,execution_type,execution_state,
            authority_state,evidence_state,created_at,expires_at,executed_at,idempotency_key,
            reasoning_summary,blocking_reasons,missing_information,evidence_chain,risk_level,claimed_outcome
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            ticket.execution_ticket_id, ticket.tenant_id, ticket.requesting_user_id, ticket.module,
            ticket.action, ticket.resource_type, ticket.resource_id, ticket.resource_hash,
            1 if ticket.consequential_action else 0, ticket.orchestrator_decision_id,
            ticket.constitutional_outcome, ticket.legal_assessment_id, ticket.financial_assessment_id,
            ticket.guardian_assessment_id, json.dumps(ticket.approval_refs), ticket.execution_type,
            ticket.execution_state, ticket.authority_state, ticket.evidence_state, ticket.created_at,
            ticket.expires_at, ticket.executed_at, ticket.idempotency_key, ticket.reasoning_summary,
            json.dumps(ticket.blocking_reasons), json.dumps(ticket.missing_information),
            json.dumps(ticket.evidence_chain), ticket.risk_level, None,
        ),
    )


def load_ticket(c: sqlite3.Connection, ticket_id: str, tenant_id: str) -> ExecutionTicket | None:
    ensure_execution_schema(c)
    row = c.execute(
        "SELECT * FROM execution_tickets WHERE id=? AND tenant_id=?",
        (ticket_id, tenant_id),
    ).fetchone()
    if not row:
        return None
    return _row_to_ticket(row)


def prepare(
    *,
    tenant_id: str,
    user_id: str,
    role: str,
    module: str,
    action: str,
    facts: str = "",
    resource_type: str | None = None,
    resource_id: str | None = None,
    resource_hash: str | None = None,
    current_resource_hash: str | None = None,
    proposed_action: str | None = None,
    consequential_action: bool = False,
    requested_outcome: str = "",
    payload_tenant_id: str | None = None,
    claimed_outcome: str | None = None,
    claimed_state: str | None = None,
    claimed_execution_allowed: bool | None = None,
    claimed_expires_at: str | None = None,
    idempotency_key: str | None = None,
    approvals: list[dict[str, Any]] | None = None,
    approval_present: bool = False,
    approval_count: int = 0,
    connection: sqlite3.Connection | None = None,
    user_status: str | None = None,
    identity_state: str | None = None,
    session_state: str | None = None,
    incident_state: str | None = None,
    legal_hold_state: str | None = None,
    jurisdiction_raw: str | None = None,
    financial_domain: str | None = None,
    amount: Any = None,
    currency: str | None = None,
    human_legal_review_present: bool = False,
    human_financial_review_present: bool = False,
    beneficiary_evidence_present: bool = False,
    aml_kyc_system_state: str | None = None,
    sanctions_system_state: str | None = None,
    **orchestrator_kwargs: Any,
) -> ExecutionTicket:
    events = ["execution_prepare_started"]
    if payload_tenant_id and payload_tenant_id != tenant_id:
        raise PermissionError("Tenant identity cannot be supplied by the client payload")

    if connection and idempotency_key:
        ensure_execution_schema(connection)
        existing = connection.execute(
            "SELECT * FROM execution_tickets WHERE tenant_id=? AND idempotency_key=?",
            (tenant_id, idempotency_key),
        ).fetchone()
        if existing:
            ticket = _row_to_ticket(existing)
            ticket.audit_events = ["execution_prepare_started", "execution_idempotent_reuse"]
            return ticket

    decision = constitutional_decide(
        tenant_id=tenant_id,
        user_id=user_id,
        role=role,
        module=module,
        action=action,
        facts=facts,
        resource_type=resource_type,
        resource_id=resource_id,
        resource_hash=resource_hash,
        consequential_action=consequential_action,
        requested_outcome=requested_outcome,
        payload_tenant_id=None,
        approvals=approvals,
        approval_present=approval_present,
        approval_count=approval_count,
        user_status=user_status,
        identity_state=identity_state,
        session_state=session_state,
        incident_state=incident_state,
        legal_hold_state=legal_hold_state,
        jurisdiction_raw=jurisdiction_raw,
        financial_domain=financial_domain,
        amount=amount,
        currency=currency,
        human_legal_review_present=human_legal_review_present,
        human_financial_review_present=human_financial_review_present,
        beneficiary_evidence_present=beneficiary_evidence_present,
        aml_kyc_system_state=aml_kyc_system_state,
        sanctions_system_state=sanctions_system_state,
        **{k: v for k, v in orchestrator_kwargs.items() if k in constitutional_decide.__code__.co_varnames},
    )

    blocking: list[str] = []
    state = "DENIED"
    if decision.outcome == "BLOCK":
        state = "DENIED"
        blocking.append("constitutional BLOCK")
        events.append("execution_constitutional_block")
    elif decision.outcome == "REVIEW_REQUIRED":
        state = "PENDING"
        events.append("execution_pending_review")
    elif decision.outcome == "ALLOW":
        state = "AUTHORISED"

    # Client forgeries never authorise.
    if claimed_outcome == "ALLOW" or claimed_execution_allowed is True or (claimed_state or "").upper() == "AUTHORISED":
        if decision.outcome != "ALLOW":
            state = "DENIED"
            blocking.append("client cannot forge constitutional ALLOW")
        # even if decision is ALLOW, ignore claimed fields

    exact_action = proposed_action or action
    if exact_action != action:
        state = "DENIED"
        blocking.append("action mismatch")
        events.append("execution_action_mismatch")

    assessed_hash = resource_hash
    live_hash = current_resource_hash if current_resource_hash is not None else resource_hash
    if assessed_hash and live_hash and assessed_hash != live_hash:
        state = "DENIED"
        blocking.append("resource hash changed after assessment")
        events.append("execution_resource_changed")

    if identity_state in {"unauthenticated", "expired", "locked", "suspended", "compromised"}:
        state = "DENIED"
        blocking.append("identity invalid")
    if session_state in {"expired", "revoked"}:
        state = "DENIED"
        blocking.append("session revoked or expired")
    if incident_state == "critical":
        state = "DENIED"
        blocking.append("critical incident revalidation")
        events.append("execution_guardian_revalidation_block")
    if legal_hold_state == "active" and any(x in f"{action} {requested_outcome}".lower() for x in ("delete", "purge", "erase")):
        state = "DENIED"
        blocking.append("legal hold revalidation")

    if approvals:
        for item in approvals:
            if item.get("revoked") or item.get("revoked_at"):
                state = "DENIED" if state != "PENDING" else state
                if state == "AUTHORISED":
                    state = "DENIED"
                blocking.append("approval revoked")
                events.append("execution_approval_invalid")
            if item.get("tenant_id") and item.get("tenant_id") != tenant_id:
                state = "DENIED"
                blocking.append("approval tenant mismatch")
                events.append("execution_approval_invalid")
            if resource_hash and item.get("resource_hash") and item.get("resource_hash") != resource_hash:
                state = "DENIED"
                blocking.append("approval resource version mismatch")
                events.append("execution_approval_invalid")

    if state == "AUTHORISED" and decision.outcome != "ALLOW":
        state = "DENIED"
        blocking.append("orchestrator did not ALLOW")

    created = _now()
    minutes = expiry_minutes(decision.risk_level, consequential_action)
    # Client-supplied expiry is ignored.
    expires = created + timedelta(minutes=minutes)
    _ = claimed_expires_at

    reasons = []
    if state == "AUTHORISED":
        reasons.append("The action passed all constitutional controls and the execution request matches the approved resource state.")
        reasons.append(f"Ticket expires in {minutes} minutes.")
        events.append("execution_authorised")
    elif state == "PENDING":
        reasons.append(decision.reasoning_summary or "Constitutional review is unresolved.")
    else:
        reasons.append(decision.reasoning_summary or "Execution is not authorised.")
        if blocking:
            reasons.append("Gateway: " + "; ".join(blocking) + ".")
        events.append("execution_denied")

    refs = []
    for item in approvals or []:
        ref = item.get("approval_id") or item.get("approver_id")
        if ref:
            refs.append(str(ref))

    chain = list(decision.evidence_chain)
    chain.append({
        "layer": "execution_gateway",
        "execution_state": state,
        "external_execution_enabled": False,
        "resource_hash": resource_hash,
        "action": action,
    })

    ticket = ExecutionTicket(
        execution_ticket_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        requesting_user_id=user_id,
        module=module,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        resource_hash=resource_hash,
        consequential_action=consequential_action,
        orchestrator_decision_id=decision.orchestrator_decision_id,
        constitutional_outcome=decision.outcome,
        legal_assessment_id=decision.legal_assessment_id,
        financial_assessment_id=decision.financial_assessment_id,
        guardian_assessment_id=decision.guardian_assessment_id,
        approval_refs=refs,
        execution_type=classify_execution_type(action),
        execution_state=state,
        authority_state="established" if state == "AUTHORISED" else ("conditional" if state == "PENDING" else "missing"),
        evidence_state="sufficient" if state == "AUTHORISED" else "insufficient",
        created_at=_iso(created),
        expires_at=_iso(expires),
        executed_at=None,
        idempotency_key=idempotency_key,
        reasoning_summary=" ".join(reasons),
        blocking_reasons=blocking + decision.blocking_layers,
        missing_information=list(decision.missing_information),
        evidence_chain=chain,
        risk_level=decision.risk_level,
        user_facing=_facing(state, " ".join(reasons)),
        audit_events=events + ["execution_ticket_created"],
    )
    if connection is not None:
        _persist(connection, ticket)
        try:
            connection.commit()
        except sqlite3.OperationalError:
            pass
    return ticket


def consume_execution_ticket(
    *,
    connection: sqlite3.Connection,
    ticket_id: str,
    tenant_id: str,
    user_id: str,
    exact_action: str,
    resource_id: str | None,
    resource_hash: str | None,
    user_status: str | None = None,
    session_state: str | None = None,
    incident_state: str | None = None,
    legal_hold_state: str | None = None,
    commit: bool = True,
) -> ExecutionTicket:
    ensure_execution_schema(connection)
    ticket = load_ticket(connection, ticket_id, tenant_id)
    if ticket is None:
        raise PermissionError("execution ticket not found for this tenant")
    if ticket.requesting_user_id != user_id:
        raise PermissionError("execution ticket does not belong to this user")

    now = _now()
    expires = _parse_iso(ticket.expires_at)
    events = list(ticket.audit_events)

    if ticket.execution_state == "CONSUMED":
        ticket.blocking_reasons = list(ticket.blocking_reasons) + ["replay blocked"]
        ticket.reasoning_summary = "Ticket already consumed."
        ticket.user_facing = _facing("CONSUMED", ticket.reasoning_summary)
        ticket.audit_events = events + ["execution_replay_blocked"]
        return ticket
    if ticket.execution_state in {"DENIED", "CANCELLED"}:
        ticket.audit_events = events + ["execution_denied"]
        return ticket
    if ticket.execution_state == "PENDING":
        ticket.audit_events = events + ["execution_pending_review"]
        return ticket
    if expires and now > expires:
        ticket.execution_state = "EXPIRED"
        ticket.reasoning_summary = "Ticket expired. Reassessment is required."
        ticket.user_facing = _facing("EXPIRED", ticket.reasoning_summary)
        ticket.audit_events = events + ["execution_expired"]
        _persist(connection, ticket)
        return ticket
    if ticket.action != exact_action:
        ticket.execution_state = "DENIED"
        ticket.blocking_reasons = list(ticket.blocking_reasons) + ["action mismatch on consume"]
        ticket.audit_events = events + ["execution_action_mismatch"]
        _persist(connection, ticket)
        return ticket
    if ticket.resource_id and resource_id and ticket.resource_id != resource_id:
        ticket.execution_state = "DENIED"
        ticket.blocking_reasons = list(ticket.blocking_reasons) + ["resource mismatch on consume"]
        ticket.audit_events = events + ["execution_resource_changed"]
        _persist(connection, ticket)
        return ticket
    if ticket.resource_hash and resource_hash and ticket.resource_hash != resource_hash:
        ticket.execution_state = "DENIED"
        ticket.blocking_reasons = list(ticket.blocking_reasons) + ["resource hash changed"]
        ticket.audit_events = events + ["execution_resource_changed"]
        _persist(connection, ticket)
        return ticket
    if user_status in {"locked", "suspended", "disabled", "compromised"}:
        ticket.execution_state = "DENIED"
        ticket.blocking_reasons = list(ticket.blocking_reasons) + ["user no longer executable"]
        _persist(connection, ticket)
        return ticket
    if session_state in {"expired", "revoked"}:
        ticket.execution_state = "DENIED"
        ticket.blocking_reasons = list(ticket.blocking_reasons) + ["session revoked"]
        _persist(connection, ticket)
        return ticket
    if incident_state == "critical":
        ticket.execution_state = "DENIED"
        ticket.audit_events = events + ["execution_guardian_revalidation_block"]
        _persist(connection, ticket)
        return ticket
    if legal_hold_state == "active" and any(x in ticket.action.lower() for x in ("delete", "purge", "erase")):
        ticket.execution_state = "DENIED"
        _persist(connection, ticket)
        return ticket
    if ticket.execution_state != "AUTHORISED":
        ticket.execution_state = "DENIED"
        _persist(connection, ticket)
        return ticket

    ticket.execution_state = "CONSUMED"
    ticket.executed_at = _iso(now)
    ticket.reasoning_summary = "Ticket consumed. External execution remains disabled in Phase 1."
    ticket.user_facing = _facing("CONSUMED", ticket.reasoning_summary)
    ticket.audit_events = events + ["execution_consumed"]
    ticket.external_execution_enabled = False
    _persist(connection, ticket)
    if commit:
        try:
            connection.commit()
        except sqlite3.OperationalError:
            pass
    return ticket
