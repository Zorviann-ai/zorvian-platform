"""Constitutional Orchestrator Phase 1.

Coordinates Legal Intelligence, Financial Intelligence and Guardian.
Does not replace those layers. Does not grant authority.
Answers one question: may this action execute?
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from intelligence.financial import assess as assess_financial
from intelligence.guardian import assess as assess_guardian
from intelligence.legal import assess as assess_legal

OUTCOMES = ("ALLOW", "BLOCK", "REVIEW_REQUIRED")
RISK_LEVELS = ("low", "medium", "high", "critical")


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _risk_max(*levels: str | None) -> str:
    best = "low"
    for level in levels:
        if level in RISK_LEVELS and RISK_LEVELS.index(level) > RISK_LEVELS.index(best):
            best = level
    return best


@dataclass
class ConstitutionalDecision:
    orchestrator_decision_id: str
    tenant_id: str
    requesting_user_id: str
    module: str
    action: str
    consequential_action: bool
    outcome: str
    execution_allowed: bool
    risk_level: str
    legal_execution_allowed: bool
    financial_execution_allowed: bool
    guardian_execution_allowed: bool
    blocking_layers: list[str]
    review_layers: list[str]
    reasoning_summary: str
    missing_information: list[str]
    assumptions: list[str]
    evidence_chain: list[dict[str, Any]]
    created_at: str
    legal_assessment_id: str | None = None
    financial_assessment_id: str | None = None
    guardian_assessment_id: str | None = None
    constitutional_control: dict[str, Any] = field(default_factory=dict)
    user_facing: str = ""

    def as_public(self) -> dict[str, Any]:
        return {
            "orchestrator_decision_id": self.orchestrator_decision_id,
            "module": self.module,
            "action": self.action,
            "consequential_action": self.consequential_action,
            "outcome": self.outcome,
            "execution_allowed": self.execution_allowed,
            "risk_level": self.risk_level,
            "legal_execution_allowed": self.legal_execution_allowed,
            "financial_execution_allowed": self.financial_execution_allowed,
            "guardian_execution_allowed": self.guardian_execution_allowed,
            "blocking_layers": self.blocking_layers,
            "review_layers": self.review_layers,
            "reasoning_summary": self.reasoning_summary,
            "missing_information": self.missing_information,
            "assumptions": self.assumptions,
            "evidence_chain": self.evidence_chain,
            "legal_assessment_id": self.legal_assessment_id,
            "financial_assessment_id": self.financial_assessment_id,
            "guardian_assessment_id": self.guardian_assessment_id,
            "constitutional_control": self.constitutional_control,
            "user_facing": self.user_facing,
            "created_at": self.created_at,
        }


def _layer_review(legal, financial, guardian) -> list[str]:
    layers = []
    if legal.human_legal_review_required:
        layers.append("legal")
    if financial.human_financial_review_required:
        layers.append("financial")
    if guardian.human_security_review_required:
        layers.append("guardian")
    return layers


def decide(
    *,
    tenant_id: str,
    user_id: str,
    role: str,
    module: str,
    action: str,
    facts: str = "",
    jurisdiction_raw: str | None = None,
    matter_type: str = "general",
    financial_domain: str | None = None,
    amount: Any = None,
    currency: str | None = None,
    customer_id: str | None = None,
    invoice_id: str | None = None,
    invoice_number: str | None = None,
    payment_reference: str | None = None,
    original_transaction_amount: Any = None,
    beneficiary_evidence_present: bool = False,
    document_id: str | None = None,
    document_hash: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    resource_hash: str | None = None,
    consequential_action: bool = False,
    requested_outcome: str = "",
    data_classes: list[str] | None = None,
    payload_tenant_id: str | None = None,
    approval_present: bool = False,
    approval_count: int = 0,
    approvals: list[dict[str, Any]] | None = None,
    human_legal_review_present: bool = False,
    human_financial_review_present: bool = False,
    aml_kyc_system_state: str | None = None,
    sanctions_system_state: str | None = None,
    promotion_approval_present: bool = False,
    regulated_authorisation_system_state: str | None = None,
    identity_state: str | None = None,
    session_state: str | None = None,
    mfa_verified: bool = False,
    user_status: str | None = None,
    incident_state: str | None = None,
    supplier_ict_state: str | None = None,
    provider_health: str | None = None,
    provider_trust_state: str | None = None,
    retention_state: str | None = None,
    legal_hold_state: str | None = None,
    intent: str = "execute",
) -> ConstitutionalDecision:
    if payload_tenant_id and payload_tenant_id != tenant_id:
        raise PermissionError("Tenant identity cannot be supplied by the client payload")

    legal = assess_legal(
        tenant_id=tenant_id,
        user_id=user_id,
        role=role,
        module=module or "legal-pathways",
        action=action,
        facts=facts,
        jurisdiction_raw=jurisdiction_raw,
        matter_type=matter_type,
        document_id=document_id,
        document_hash=document_hash or resource_hash,
        consequential_action=consequential_action,
        requested_outcome=requested_outcome,
        data_classes=data_classes,
        approval_present=approval_present,
        human_legal_review_present=human_legal_review_present,
        payload_tenant_id=None,
    )
    financial = assess_financial(
        tenant_id=tenant_id,
        user_id=user_id,
        role=role,
        module=module or "finance-pathways",
        action=action,
        facts=facts,
        jurisdiction_raw=jurisdiction_raw,
        financial_domain=financial_domain,
        amount=amount,
        currency=currency,
        customer_id=customer_id,
        invoice_id=invoice_id,
        invoice_number=invoice_number,
        payment_reference=payment_reference,
        consequential_action=consequential_action,
        requested_outcome=requested_outcome,
        approval_present=approval_present,
        approval_count=approval_count,
        human_financial_review_present=human_financial_review_present,
        payload_tenant_id=None,
        aml_kyc_system_state=aml_kyc_system_state,
        sanctions_system_state=sanctions_system_state,
        original_transaction_amount=original_transaction_amount,
        beneficiary_evidence_present=beneficiary_evidence_present,
        legal_execution_allowed=legal.execution_allowed,
        guardian_ok=True,
        promotion_approval_present=promotion_approval_present,
        regulated_authorisation_system_state=regulated_authorisation_system_state,
    )
    guardian = assess_guardian(
        tenant_id=tenant_id,
        user_id=user_id,
        role=role,
        module=module or "security-analysis",
        action=action,
        facts=facts,
        resource_type=resource_type,
        resource_id=resource_id or document_id,
        resource_hash=resource_hash or document_hash,
        consequential_action=consequential_action,
        requested_outcome=requested_outcome,
        payload_tenant_id=None,
        identity_state=identity_state,
        session_state=session_state,
        mfa_verified=mfa_verified,
        user_status=user_status,
        approvals=approvals,
        approval_present=approval_present,
        incident_state=incident_state,
        supplier_ict_state=supplier_ict_state,
        provider_health=provider_health,
        provider_trust_state=provider_trust_state,
        retention_state=retention_state,
        legal_hold_state=legal_hold_state,
        legal_execution_allowed=legal.execution_allowed,
        legal_human_review_required=legal.human_legal_review_required and not human_legal_review_present,
        financial_execution_allowed=financial.execution_allowed,
        financial_dual_control_complete=(
            True if not financial.dual_control_required else (approval_count >= 2)
        ),
        intent=intent,
    )

    # Strictest-gate: Guardian is evaluated with Legal/Financial results so it cannot weaken them.
    # Re-evaluate financial with guardian_ok from the Guardian decision.
    if not guardian.execution_allowed:
        financial = assess_financial(
            tenant_id=tenant_id,
            user_id=user_id,
            role=role,
            module=module or "finance-pathways",
            action=action,
            facts=facts,
            jurisdiction_raw=jurisdiction_raw,
            financial_domain=financial_domain,
            amount=amount,
            currency=currency,
            customer_id=customer_id,
            invoice_id=invoice_id,
            invoice_number=invoice_number,
            payment_reference=payment_reference,
            consequential_action=consequential_action,
            requested_outcome=requested_outcome,
            approval_present=approval_present,
            approval_count=approval_count,
            human_financial_review_present=human_financial_review_present,
            aml_kyc_system_state=aml_kyc_system_state,
            sanctions_system_state=sanctions_system_state,
            original_transaction_amount=original_transaction_amount,
            beneficiary_evidence_present=beneficiary_evidence_present,
            legal_execution_allowed=legal.execution_allowed,
            guardian_ok=False,
            promotion_approval_present=promotion_approval_present,
            regulated_authorisation_system_state=regulated_authorisation_system_state,
        )

    layers = {
        "legal": legal.execution_allowed,
        "financial": financial.execution_allowed,
        "guardian": guardian.execution_allowed,
    }
    blocking = [name for name, allowed in layers.items() if not allowed]
    review_layers = _layer_review(legal, financial, guardian)

    missing: list[str] = []
    for src in (legal.missing_information, financial.missing_information, guardian.missing_information):
        for item in src:
            if item not in missing:
                missing.append(item)

    assumptions: list[str] = [
        "Constitutional Orchestrator coordinates Legal, Financial and Guardian; it does not replace them.",
        "AI cannot grant execution through the Orchestrator.",
    ]
    for src in (legal.assumptions, financial.assumptions, guardian.assumptions):
        for item in src:
            if item not in assumptions:
                assumptions.append(item)

    risk = _risk_max(legal.risk_level, financial.risk_level, guardian.risk_level)

    hard_block_signals = (
        guardian.identity_state in {"unauthenticated", "expired", "locked", "suspended", "compromised"}
        or guardian.tenant_state == "mismatch"
        or guardian.session_state in {"expired", "revoked"}
        or guardian.incident_state == "critical"
        or (guardian.legal_hold_state == "active" and "delete" in f"{action} {requested_outcome}".lower())
        or financial.sanctions_state in {"possible_match", "confirmed_match"}
        or financial.customer_outcome_state == "unacceptable_harm"
        or guardian.boundary_state == "blocked_execution"
        or guardian.secret_detected
    )

    review_reasons = (
        (legal.human_legal_review_required and not human_legal_review_present)
        or (financial.human_financial_review_required and not human_financial_review_present)
        or financial.dual_control_required
        or legal.approval_required and not approval_present and consequential_action
    )

    if blocking:
        if hard_block_signals or not review_reasons:
            outcome = "BLOCK"
        else:
            outcome = "REVIEW_REQUIRED"
        execution_allowed = False
    elif review_layers and consequential_action and (
        (legal.human_legal_review_required and not human_legal_review_present)
        or (financial.human_financial_review_required and not human_financial_review_present)
    ):
        # Layers should already have blocked; keep fail-closed.
        outcome = "REVIEW_REQUIRED"
        execution_allowed = False
    elif review_layers and not consequential_action:
        outcome = "REVIEW_REQUIRED" if risk in {"high", "critical"} else "ALLOW"
        execution_allowed = True
    else:
        outcome = "ALLOW"
        execution_allowed = True

    # Constitutional invariant: no layer block can become ALLOW.
    if blocking:
        execution_allowed = False
        if outcome == "ALLOW":
            outcome = "BLOCK"

    reasons = []
    if outcome == "ALLOW":
        reasons.append("Legal, Financial and Guardian all allow this scoped request.")
    elif outcome == "REVIEW_REQUIRED":
        reasons.append("Required constitutional review or approval is unresolved. Execution is not permitted.")
    else:
        reasons.append("A required constitutional layer blocked execution. The strictest gate wins.")
    if blocking:
        reasons.append("Blocking layers: " + ", ".join(blocking) + ".")
    if missing:
        reasons.append("Missing: " + "; ".join(missing[:12]) + ".")

    heading = {
        "ALLOW": "CONSTITUTIONAL CONTROL: ALLOW",
        "BLOCK": "CONSTITUTIONAL CONTROL: BLOCK",
        "REVIEW_REQUIRED": "CONSTITUTIONAL CONTROL: REVIEW REQUIRED",
    }[outcome]
    user_facing = heading + "\n\nReason:\n" + " ".join(reasons)
    if missing:
        user_facing += "\nMissing:\n" + "\n".join(f"- {item}" for item in missing[:12])

    evidence_chain = [
        {
            "layer": "legal",
            "assessment_id": legal.legal_assessment_id,
            "execution_allowed": legal.execution_allowed,
            "risk_level": legal.risk_level,
            "authority_state": legal.authority_state,
            "evidence_state": legal.evidence_state,
            "human_review_required": legal.human_legal_review_required,
        },
        {
            "layer": "financial",
            "assessment_id": financial.financial_assessment_id,
            "execution_allowed": financial.execution_allowed,
            "risk_level": financial.risk_level,
            "authority_state": financial.authority_state,
            "evidence_state": financial.evidence_state,
            "aml_kyc_state": financial.aml_kyc_state,
            "dual_control_required": financial.dual_control_required,
            "human_review_required": financial.human_financial_review_required,
        },
        {
            "layer": "guardian",
            "assessment_id": guardian.guardian_assessment_id,
            "execution_allowed": guardian.execution_allowed,
            "risk_level": guardian.risk_level,
            "identity_state": guardian.identity_state,
            "tenant_state": guardian.tenant_state,
            "rbac_state": guardian.rbac_state,
            "incident_state": guardian.incident_state,
            "legal_hold_state": guardian.legal_hold_state,
            "human_review_required": guardian.human_security_review_required,
        },
        {
            "layer": "orchestrator",
            "outcome": outcome,
            "execution_allowed": execution_allowed,
            "strictest_gate": True,
        },
    ]

    control = {
        "execution_allowed": execution_allowed,
        "outcome": outcome,
        "risk_level": risk,
        "legal_execution_allowed": legal.execution_allowed,
        "financial_execution_allowed": financial.execution_allowed,
        "guardian_execution_allowed": guardian.execution_allowed,
        "blocking_layers": blocking,
        "review_layers": review_layers,
    }

    return ConstitutionalDecision(
        orchestrator_decision_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        requesting_user_id=user_id,
        module=module,
        action=action,
        consequential_action=consequential_action,
        outcome=outcome,
        execution_allowed=execution_allowed,
        risk_level=risk,
        legal_execution_allowed=legal.execution_allowed,
        financial_execution_allowed=financial.execution_allowed,
        guardian_execution_allowed=guardian.execution_allowed,
        blocking_layers=blocking,
        review_layers=review_layers,
        reasoning_summary=" ".join(reasons),
        missing_information=missing,
        assumptions=assumptions,
        evidence_chain=evidence_chain,
        created_at=_now(),
        legal_assessment_id=legal.legal_assessment_id,
        financial_assessment_id=financial.financial_assessment_id,
        guardian_assessment_id=guardian.guardian_assessment_id,
        constitutional_control=control,
        user_facing=user_facing,
    )
