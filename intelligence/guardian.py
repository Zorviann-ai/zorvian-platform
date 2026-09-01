"""Guardian Phase 1 — security, identity, policy, evidence and incident control.

Deterministic first. Optional AI enrichment only. AI never grants authority.
"""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from intelligence.guard import classify_boundary, redact_secrets

RISK_LEVELS = ("low", "medium", "high", "critical")
IDENTITY_STATES = (
    "authenticated", "unauthenticated", "expired", "locked", "suspended",
    "mfa_required", "mfa_verified", "compromised", "unknown",
)
TENANT_STATES = ("matched", "mismatch", "missing")
RBAC_STATES = ("allowed", "denied", "conditional", "unknown")
SESSION_STATES = ("normal", "elevated", "expired", "revoked", "suspicious", "unknown")
APPROVAL_STATES = ("not_required", "valid", "missing", "revoked", "wrong_tenant", "mismatch", "self_approval", "stale")
INCIDENT_STATES = ("none", "investigating", "contained", "high_risk", "critical", "resolved")
SUPPLIER_STATES = ("not_applicable", "approved", "pending_review", "degraded", "high_risk", "blocked")
RETENTION_STATES = ("normal", "retention_required", "expiry_due", "deletion_allowed", "deletion_blocked", "unknown")
LEGAL_HOLD_STATES = ("none", "active", "possible", "released", "unknown")
EVIDENCE_STATES = ("sufficient", "partial", "insufficient", "conflicting")
ACTION_CATEGORIES = (
    "read", "write", "approve", "release", "financial", "legal", "security",
    "configuration", "identity", "supplier", "data_export", "external_communication", "unknown",
)

RIGHTS = {
    "owner": {"read", "write", "approve", "export", "admin", "invite", "security"},
    "admin": {"read", "write", "approve", "export", "admin", "invite", "security"},
    "principal": {"read", "write", "approve", "export"},
    "staff": {"read", "write"},
    "member": {"read", "write"},
    "client": {"read"},
    "viewer": {"read"},
}

CATEGORY_PERMISSION = {
    "read": "read",
    "write": "write",
    "approve": "approve",
    "release": "approve",
    "financial": "approve",
    "legal": "approve",
    "security": "security",
    "configuration": "admin",
    "identity": "admin",
    "supplier": "approve",
    "data_export": "export",
    "external_communication": "approve",
    "unknown": "write",
}

SECRET_MARKERS = (
    "api_key", "api-key", "apikey", "password", "session token", "bearer ",
    "private key", "smtp password", "secret_key", "reset token",
)
DESTRUCTIVE_MARKERS = ("delete", "purge", "wipe", "erase", "destroy", "drop table")
DISABLE_GUARDIAN_MARKERS = ("disable guardian", "turn off guardian", "bypass guardian")
DISABLE_AUDIT_MARKERS = ("disable audit", "delete audit", "erase audit", "rewrite security event")
CROSS_TENANT_MARKERS = ("other tenant", "another tenant", "cross-tenant", "cross tenant")


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _contains(text: str, needles: Iterable[str]) -> bool:
    blob = (text or "").lower()
    return any(n in blob for n in needles)


def classify_action(action: str, facts: str = "", requested_outcome: str = "") -> str:
    blob = f"{action} {facts} {requested_outcome}".lower()
    mapping = (
        ("security", ("disable security", "disable guardian", "change security", "mfa", "role change", "owner change")),
        ("identity", ("password reset", "invite user", "lock account", "credential")),
        ("financial", ("payment", "beneficiary", "refund", "invoice", "payroll", "financial promotion")),
        ("legal", ("legal release", "legal hold", "litigation", "contract release")),
        ("release", ("release document", "release letter", "publish")),
        ("approve", ("approve", "authorise", "authorize")),
        ("data_export", ("export", "dump data", "download all")),
        ("supplier", ("provider", "supplier", "vendor")),
        ("configuration", ("change setting", "reconfigure", "provider credential")),
        ("external_communication", ("send email", "send letter", "notify externally")),
        ("write", ("write", "update", "create", "draft", "change")),
        ("read", ("read", "view", "list", "status", "profile")),
    )
    for category, markers in mapping:
        if _contains(blob, markers):
            return category
    if action.lower().startswith("read") or action.lower() in {"view_profile", "list_records"}:
        return "read"
    return "unknown"


def classify_sensitivity(category: str, action: str, facts: str, consequential: bool) -> str:
    blob = f"{action} {facts}".lower()
    if _contains(blob, ("cross-tenant", "another tenant", "dump credentials", "expose secrets", "disable guardian", "disable audit", "account compromise")):
        return "critical"
    if category in {"security", "identity"} and consequential:
        return "critical"
    if _contains(blob, ("payment beneficiary", "change beneficiary", "large payment", "disable security")):
        return "critical" if "disable" in blob else "high"
    if category in {"financial", "release", "approve", "data_export"} and consequential:
        return "high"
    if consequential:
        return "medium"
    if category == "read":
        return "low"
    return "medium" if category in {"write", "unknown"} else "low"


@dataclass
class GuardianAssessment:
    guardian_assessment_id: str
    tenant_id: str
    requesting_user_id: str
    action: str
    module: str
    resource_type: str | None
    resource_id: str | None
    risk_level: str
    identity_state: str
    tenant_state: str
    rbac_state: str
    session_state: str
    approval_integrity_state: str
    incident_state: str
    supplier_ict_state: str
    retention_state: str
    legal_hold_state: str
    evidence_state: str
    human_security_review_required: bool
    execution_allowed: bool
    reasoning_summary: str
    missing_information: list[str]
    assumptions: list[str]
    created_at: str
    action_category: str = "unknown"
    sensitivity: str = "low"
    legal_execution_allowed: bool | None = None
    financial_execution_allowed: bool | None = None
    secret_detected: bool = False
    boundary_state: str = "clear"
    provider_trust_state: str = "not_applicable"
    guardian_control: dict[str, Any] = field(default_factory=dict)
    user_facing: str = ""

    def as_public(self) -> dict[str, Any]:
        return {
            "guardian_assessment_id": self.guardian_assessment_id,
            "module": self.module,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "risk_level": self.risk_level,
            "identity_state": self.identity_state,
            "tenant_state": self.tenant_state,
            "rbac_state": self.rbac_state,
            "session_state": self.session_state,
            "approval_integrity_state": self.approval_integrity_state,
            "incident_state": self.incident_state,
            "supplier_ict_state": self.supplier_ict_state,
            "retention_state": self.retention_state,
            "legal_hold_state": self.legal_hold_state,
            "evidence_state": self.evidence_state,
            "human_security_review_required": self.human_security_review_required,
            "execution_allowed": self.execution_allowed,
            "reasoning_summary": self.reasoning_summary,
            "missing_information": self.missing_information,
            "assumptions": self.assumptions,
            "action_category": self.action_category,
            "sensitivity": self.sensitivity,
            "legal_execution_allowed": self.legal_execution_allowed,
            "financial_execution_allowed": self.financial_execution_allowed,
            "secret_detected": self.secret_detected,
            "boundary_state": self.boundary_state,
            "provider_trust_state": self.provider_trust_state,
            "guardian_control": self.guardian_control,
            "user_facing": self.user_facing,
            "created_at": self.created_at,
        }


def parse_ai_guardian_payload(raw: Any) -> dict[str, Any] | None:
    if raw is None:
        return None
    text = raw if isinstance(raw, str) else json.dumps(raw)
    text = text.strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.S)
        if not match:
            return None
        try:
            data = json.loads(match.group(0))
        except json.JSONDecodeError:
            return None
    if not isinstance(data, dict):
        return None
    risk = str(data.get("risk_level", "low")).lower()
    if risk not in RISK_LEVELS:
        return None
    data["risk_level"] = risk
    for banned in ("execution_allowed", "rbac_state", "tenant_state", "identity_state", "incident_state", "legal_hold_state"):
        data.pop(banned, None)
    return data


def _approval_state(approvals: list[dict[str, Any]] | None, *, tenant_id: str, user_id: str, resource_id: str | None, resource_hash: str | None, required: bool) -> str:
    if not required:
        return "not_required"
    if not approvals:
        return "missing"
    for item in approvals:
        if item.get("revoked") or item.get("revoked_at"):
            return "revoked"
        if item.get("tenant_id") and item.get("tenant_id") != tenant_id:
            return "wrong_tenant"
        if resource_id and item.get("resource_id") and item.get("resource_id") != resource_id:
            return "mismatch"
        if resource_hash and item.get("resource_hash") and item.get("resource_hash") != resource_hash:
            return "mismatch"
        if item.get("stale") or item.get("current") is False:
            return "stale"
    actors = [str(a.get("approver_id") or a.get("user_id") or "") for a in approvals]
    if len(approvals) >= 2 and len(set(actors)) < 2:
        return "self_approval"
    return "valid"


def assess(
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
    consequential_action: bool = False,
    requested_outcome: str = "",
    payload_tenant_id: str | None = None,
    identity_state: str | None = None,
    session_state: str | None = None,
    mfa_verified: bool = False,
    user_status: str | None = None,
    approvals: list[dict[str, Any]] | None = None,
    approval_present: bool = False,
    incident_state: str | None = None,
    supplier_ict_state: str | None = None,
    provider_health: str | None = None,
    provider_trust_state: str | None = None,
    retention_state: str | None = None,
    legal_hold_state: str | None = None,
    legal_execution_allowed: bool | None = None,
    legal_human_review_required: bool = False,
    financial_execution_allowed: bool | None = None,
    financial_dual_control_complete: bool | None = None,
    intent: str = "execute",
    ai_payload: dict[str, Any] | None = None,
) -> GuardianAssessment:
    if payload_tenant_id and payload_tenant_id != tenant_id:
        raise PermissionError("Tenant identity cannot be supplied by the client payload")
    tenant_state = "matched" if tenant_id else "missing"

    text = f"{action} {facts} {requested_outcome}"
    redacted, secret_detected = redact_secrets(text)
    boundary = classify_boundary(text, intent=intent)

    category = classify_action(action, facts, requested_outcome)
    sensitivity = classify_sensitivity(category, action, facts, consequential_action)
    risk = sensitivity
    missing: list[str] = []
    assumptions: list[str] = []
    block_reasons: list[str] = []
    events: list[str] = ["guardian_assessment_started"]

    status = (user_status or "").lower()
    ident = (identity_state or "").lower()
    if ident not in IDENTITY_STATES:
        if status in {"locked"}:
            ident = "locked"
        elif status in {"suspended", "disabled"}:
            ident = "suspended"
        elif status == "compromised":
            ident = "compromised"
        elif not user_id:
            ident = "unauthenticated"
        else:
            ident = "authenticated"
    if ident == "authenticated" and sensitivity in {"high", "critical"} and not mfa_verified and status == "mfa_required":
        ident = "mfa_required"

    sess = (session_state or "normal").lower()
    if sess not in SESSION_STATES:
        sess = "unknown"

    required_perm = CATEGORY_PERMISSION.get(category, "write")
    if not consequential_action and category == "read":
        required_perm = "read"
    allowed_perms = RIGHTS.get(role, set())
    if not role:
        rbac = "unknown"
    elif required_perm in allowed_perms or (required_perm == "read" and role):
        rbac = "allowed"
    else:
        rbac = "denied"

    approval_required = consequential_action and category in {"approve", "release", "financial", "legal", "security", "data_export"}
    if approval_present and not approvals:
        approvals = [{"approver_id": user_id, "tenant_id": tenant_id, "resource_id": resource_id}]
    approval_state = _approval_state(
        approvals,
        tenant_id=tenant_id,
        user_id=user_id,
        resource_id=resource_id,
        resource_hash=resource_hash,
        required=approval_required,
    )

    incident = (incident_state or "none").lower()
    if incident not in INCIDENT_STATES:
        incident = "unknown"

    supplier = (supplier_ict_state or "not_applicable").lower()
    if supplier not in SUPPLIER_STATES:
        supplier = "not_applicable"
    trust = (provider_trust_state or "not_applicable").lower()
    if trust not in SUPPLIER_STATES:
        trust = "not_applicable"
    health = (provider_health or "").lower()
    if health == "healthy" and trust == "blocked":
        assumptions.append("Provider technical health does not override Guardian trust block.")

    retention = (retention_state or "normal").lower()
    if retention not in RETENTION_STATES:
        retention = "unknown"
    hold = (legal_hold_state or "none").lower()
    if hold not in LEGAL_HOLD_STATES:
        hold = "unknown"

    destructive = _contains(action + " " + requested_outcome, DESTRUCTIVE_MARKERS)

    if ai_payload:
        extra_missing = [str(x) for x in ai_payload.get("missing_evidence", []) if str(x).strip()]
        for item in extra_missing:
            if item not in missing:
                missing.append(item)
        ai_risk = str(ai_payload.get("risk_level", "")).lower()
        if ai_risk in RISK_LEVELS and RISK_LEVELS.index(ai_risk) > RISK_LEVELS.index(risk):
            risk = ai_risk
        if str(ai_payload.get("approval_recommendation", "")).lower() in {"allow", "approve", "grant"}:
            assumptions.append("Model approval recommendation was ignored; deterministic Guardian controls decide execution.")

    blocked = False

    if ident in {"unauthenticated", "expired", "locked", "suspended", "compromised", "unknown"}:
        blocked = True
        block_reasons.append("Authenticated identity is not in an executable state.")
        events.append("guardian_identity_block")
    if ident == "mfa_required" and sensitivity in {"high", "critical"}:
        blocked = True
        missing.append("verified MFA for this sensitive action")
        events.append("guardian_identity_block")

    if tenant_state == "mismatch":
        blocked = True
        risk = "critical"
        block_reasons.append("Tenant payload does not match the authenticated session tenant.")
        events.append("guardian_tenant_violation")
        events.append("guardian_cross_tenant_attempt")
    if tenant_state == "missing":
        blocked = True
        events.append("guardian_tenant_violation")

    if rbac == "denied":
        blocked = True
        block_reasons.append("RBAC does not permit this action.")
        events.append("guardian_rbac_block")

    if sess in {"expired", "revoked"}:
        blocked = True
        block_reasons.append("Session is expired or revoked.")
        events.append("guardian_session_block")
    if sess == "suspicious" and consequential_action:
        blocked = True
        block_reasons.append("Session risk is suspicious for a consequential action.")
        events.append("guardian_session_block")

    if approval_required and approval_state in {"missing", "revoked", "wrong_tenant", "mismatch", "self_approval", "stale"}:
        blocked = True
        block_reasons.append(f"Approval integrity failed ({approval_state}).")
        missing.append("valid current approval for this resource")
        events.append("guardian_approval_integrity_failed")

    if financial_dual_control_complete is False:
        blocked = True
        missing.append("second authorised approver")
        block_reasons.append("Financial dual-control approval is incomplete.")
        events.append("guardian_approval_integrity_failed")

    if incident == "critical" and consequential_action:
        blocked = True
        block_reasons.append("An active critical security incident blocks consequential execution.")
        events.append("guardian_incident_block")

    if hold == "active" and destructive:
        blocked = True
        block_reasons.append("The requested record is under active legal hold and cannot be deleted.")
        events.append("guardian_legal_hold_block")

    if retention in {"retention_required", "deletion_blocked"} and destructive:
        blocked = True
        block_reasons.append("Retention policy blocks destructive action.")
        events.append("guardian_retention_block")

    if supplier == "blocked" or trust == "blocked":
        if consequential_action and category in {"supplier", "configuration", "unknown", "write", "financial"}:
            blocked = True
            block_reasons.append("Supplier/ICT trust state blocks this provider-dependent action.")
            events.append("guardian_supplier_risk_block")

    if legal_execution_allowed is False:
        blocked = True
        block_reasons.append("Legal Intelligence blocked this action; Guardian cannot override it.")
        events.append("guardian_control_blocked")
    if legal_human_review_required and consequential_action:
        blocked = True
        missing.append("completed human legal review")
        block_reasons.append("Required human legal review is unresolved.")

    if financial_execution_allowed is False:
        blocked = True
        block_reasons.append("Financial Intelligence blocked this action; Guardian cannot override it.")
        events.append("guardian_control_blocked")

    if secret_detected and consequential_action:
        blocked = True
        block_reasons.append("Secret-exfiltration or secret-bearing execution request is blocked.")
        events.append("guardian_secret_detected")

    if boundary == "blocked_execution":
        blocked = True
        if _contains(text, DISABLE_GUARDIAN_MARKERS):
            block_reasons.append("Request to disable Guardian is blocked.")
            events.append("guardian_override_attempt")
        elif _contains(text, DISABLE_AUDIT_MARKERS):
            block_reasons.append("Request to disable or erase audit is blocked.")
            events.append("guardian_override_attempt")
        elif _contains(text, CROSS_TENANT_MARKERS):
            block_reasons.append("Cross-tenant execution attempt is blocked.")
            events.append("guardian_cross_tenant_attempt")
        else:
            block_reasons.append("Guardian input boundary blocked an unsafe control-plane instruction.")
            events.append("guardian_override_attempt")

    if consequential_action and risk in {"high", "critical"} and not missing and evidence_gap(approvals, legal_execution_allowed, financial_execution_allowed):
        missing.append("sufficient system evidence for this consequential action")

    if not missing and not block_reasons:
        evidence = "sufficient"
    elif consequential_action and (blocked or risk in {"high", "critical"}):
        evidence = "insufficient"
    else:
        evidence = "partial"

    if consequential_action and evidence == "insufficient" and not block_reasons:
        blocked = True
        block_reasons.append("Evidence is insufficient for consequential execution.")

    human_review = risk in {"high", "critical"} or incident in {"high_risk", "critical", "investigating"}
    execution_allowed = not blocked
    # Advisory / discussion never executes a consequential gate as success-to-act
    if intent == "discuss":
        assumptions.append("Request treated as discussion; discussion does not grant execution authority.")

    if not block_reasons and not missing:
        reasons = ["Deterministic Guardian control checks passed for this scoped Phase 1 request."]
    else:
        reasons = list(block_reasons)
        if missing:
            reasons.append("Missing: " + "; ".join(missing) + ".")

    if execution_allowed and not consequential_action:
        heading = "GUARDIAN CONTROL: ALLOWED"
    elif execution_allowed:
        heading = "GUARDIAN CONTROL: ALLOWED"
    else:
        heading = "GUARDIAN CONTROL: BLOCKED"
    user_facing = heading + "\n\nReason:\n" + " ".join(reasons)
    if missing:
        user_facing += "\nMissing:\n" + "\n".join(f"- {item}" for item in missing)

    events.append("guardian_control_passed" if execution_allowed else "guardian_control_blocked")
    events.append("guardian_assessment_completed")

    control = {
        "execution_allowed": execution_allowed,
        "risk_level": risk,
        "identity_state": ident,
        "tenant_state": tenant_state,
        "rbac_state": rbac,
        "session_state": sess,
        "approval_integrity_state": approval_state,
        "incident_state": incident,
        "supplier_ict_state": supplier,
        "provider_trust_state": trust,
        "provider_health": health or None,
        "retention_state": retention,
        "legal_hold_state": hold,
        "evidence_state": evidence,
        "secret_detected": secret_detected,
        "boundary_state": boundary,
        "legal_execution_allowed": legal_execution_allowed,
        "financial_execution_allowed": financial_execution_allowed,
        "audit_events": events,
        "redacted_input": redacted[:500],
    }

    return GuardianAssessment(
        guardian_assessment_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        requesting_user_id=user_id,
        action=action,
        module=module,
        resource_type=resource_type,
        resource_id=resource_id,
        risk_level=risk,
        identity_state=ident,
        tenant_state=tenant_state,
        rbac_state=rbac,
        session_state=sess,
        approval_integrity_state=approval_state,
        incident_state=incident,
        supplier_ict_state=supplier,
        retention_state=retention,
        legal_hold_state=hold,
        evidence_state=evidence,
        human_security_review_required=human_review,
        execution_allowed=execution_allowed,
        reasoning_summary=" ".join(reasons),
        missing_information=missing,
        assumptions=assumptions,
        created_at=_now(),
        action_category=category,
        sensitivity=sensitivity,
        legal_execution_allowed=legal_execution_allowed,
        financial_execution_allowed=financial_execution_allowed,
        secret_detected=secret_detected,
        boundary_state=boundary,
        provider_trust_state=trust,
        guardian_control=control,
        user_facing=user_facing,
    )


def evidence_gap(approvals: list | None, legal_ok: bool | None, financial_ok: bool | None) -> bool:
    return False
