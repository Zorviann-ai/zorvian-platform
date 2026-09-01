"""Financial Intelligence Phase 1 — structured control gate.

Deterministic control decisions. Optional AI enrichment via finance-workflow.
Never fabricates AML/KYC results, authorisations, citations or payment execution.
"""
from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

RISK_LEVELS = ("low", "medium", "high", "critical")
AUTHORITY_STATES = ("established", "conditional", "missing", "conflicting", "not_required")
EVIDENCE_STATES = ("sufficient", "partial", "insufficient", "conflicting")
AML_KYC_STATES = ("not_applicable", "required", "pending", "verified", "insufficient", "failed", "review_required")
SANCTIONS_STATES = ("not_checked", "clear", "possible_match", "confirmed_match", "review_required")
CONSUMER_DUTY_STATES = ("not_applicable", "applicable", "review_required", "pass", "fail")
CUSTOMER_OUTCOME_STATES = ("positive", "neutral", "potential_harm", "unacceptable_harm", "unknown")
REGULATED_STATES = ("not_applicable", "possible", "applicable", "uncertain", "review_required")
FINANCIAL_DOMAINS = (
    "invoice", "payment", "refund", "credit", "leasing", "lending", "insurance",
    "investment", "financial_promotion", "pricing", "discount", "commission",
    "deposit", "subscription", "customer_money", "aml_kyc", "tax", "accounting",
    "expense", "supplier_payment", "payroll", "regulated_finance", "unknown",
)
ALLOWED_SOURCES: tuple[str, ...] = ()

DOMAIN_MARKERS = {
    "invoice": ("invoice", "vat invoice"),
    "payment": ("payment", "pay supplier", "payee", "payer"),
    "refund": ("refund", "chargeback"),
    "credit": ("consumer credit", "credit facility", "extend credit"),
    "leasing": ("lease", "leasing"),
    "lending": ("lend", "loan", "lending"),
    "insurance": ("insurance", "underwrit"),
    "investment": ("investment advice", "invest in", "portfolio advice"),
    "financial_promotion": ("financial promotion", "promote a financial", "investment advert"),
    "pricing": ("pricing", "price change"),
    "discount": ("discount", "markdown"),
    "commission": ("commission",),
    "deposit": ("customer deposit", "client deposit"),
    "subscription": ("subscription fee", "recurring fee"),
    "customer_money": ("client money", "customer money", "safeguarded funds"),
    "aml_kyc": ("aml", "kyc", "source of funds", "money laundering", "pep "),
    "tax": ("vat return", "tax filing"),
    "accounting": ("ledger", "journal entry"),
    "expense": ("expense claim",),
    "supplier_payment": ("supplier payment", "pay the supplier"),
    "payroll": ("payroll", "wage payment"),
    "regulated_finance": ("regulated activity", "fca authorised", "payment services"),
}

HARM_MARKERS = (
    "unexpected fee", "hidden fee", "misleading pricing", "unfair refund",
    "no disclosure", "vulnerable customer", "foreseeable harm",
)
UNACCEPTABLE_HARM_MARKERS = (
    "unacceptable harm", "exploit vulnerable", "mis-sell", "forced payment",
)
PROMOTION_MARKERS = ("financial promotion", "promote investment", "promote insurance", "promote a loan")
REGULATED_MARKERS = (
    "investment advice", "consumer credit", "insurance distribution",
    "mortgage", "payment services", "regulated financial",
)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def dual_control_threshold_gbp() -> float:
    raw = os.getenv("FIN_DUAL_CONTROL_THRESHOLD_GBP", "10000")
    try:
        value = float(raw)
    except ValueError:
        value = 10000.0
    return value if value > 0 else 10000.0


def _contains(text: str, needles: Iterable[str]) -> bool:
    blob = (text or "").lower()
    return any(n in blob for n in needles)


def _parse_amount(amount: Any, text: str) -> float | None:
    if amount is not None and str(amount).strip() != "":
        try:
            return float(str(amount).replace(",", "").replace("£", "").strip())
        except ValueError:
            return None
    match = re.search(r"(?:gbp|£)\s*([0-9][0-9,]*(?:\.[0-9]+)?)", (text or "").lower())
    if match:
        try:
            return float(match.group(1).replace(",", ""))
        except ValueError:
            return None
    return None


@dataclass
class FinancialAssessment:
    financial_assessment_id: str
    tenant_id: str
    requesting_user_id: str
    module: str
    action: str
    jurisdiction: str | None
    financial_domain: str
    financial_domains: list[str]
    risk_level: str
    regulated_activity_state: str
    authority_state: str
    evidence_state: str
    aml_kyc_state: str
    sanctions_state: str
    consumer_duty_state: str
    customer_outcome_state: str
    approval_required: bool
    dual_control_required: bool
    human_financial_review_required: bool
    execution_allowed: bool
    reasoning_summary: str
    missing_information: list[str]
    assumptions: list[str]
    financial_sources: list[str]
    created_at: str
    financial_control: dict[str, Any] = field(default_factory=dict)
    user_facing: str = ""

    def as_public(self) -> dict[str, Any]:
        return {
            "financial_assessment_id": self.financial_assessment_id,
            "module": self.module,
            "action": self.action,
            "jurisdiction": self.jurisdiction,
            "financial_domain": self.financial_domain,
            "financial_domains": self.financial_domains,
            "risk_level": self.risk_level,
            "regulated_activity_state": self.regulated_activity_state,
            "authority_state": self.authority_state,
            "evidence_state": self.evidence_state,
            "aml_kyc_state": self.aml_kyc_state,
            "sanctions_state": self.sanctions_state,
            "consumer_duty_state": self.consumer_duty_state,
            "customer_outcome_state": self.customer_outcome_state,
            "approval_required": self.approval_required,
            "dual_control_required": self.dual_control_required,
            "human_financial_review_required": self.human_financial_review_required,
            "execution_allowed": self.execution_allowed,
            "reasoning_summary": self.reasoning_summary,
            "missing_information": self.missing_information,
            "assumptions": self.assumptions,
            "financial_sources": self.financial_sources,
            "financial_control": self.financial_control,
            "user_facing": self.user_facing,
            "created_at": self.created_at,
        }


def _domains(declared: str | None, text: str) -> list[str]:
    found: list[str] = []
    declared_key = (declared or "").strip().lower()
    if declared_key in FINANCIAL_DOMAINS and declared_key != "unknown":
        found.append(declared_key)
    blob = text.lower()
    for domain, markers in DOMAIN_MARKERS.items():
        if _contains(blob, markers) and domain not in found:
            found.append(domain)
    if not found:
        found.append("unknown")
    return [d for d in found if d in FINANCIAL_DOMAINS]


def _primary_domain(domains: list[str]) -> str:
    for item in domains:
        if item != "unknown":
            return item
    return "unknown"


def _risk(action: str, text: str, domains: list[str], consequential: bool, amount: float | None) -> str:
    blob = f"{action} {text}".lower()
    if _contains(blob, ("money laundering", "sanctions match", "confirmed match")):
        return "critical"
    if "investment" in domains or _contains(blob, ("investment advice",)):
        return "critical"
    if "financial_promotion" in domains or _contains(blob, PROMOTION_MARKERS):
        return "high"
    if any(d in domains for d in ("lending", "credit", "insurance", "leasing", "customer_money", "regulated_finance")):
        return "high"
    if amount is not None and amount >= dual_control_threshold_gbp():
        return "high"
    if consequential and any(d in domains for d in ("payment", "refund", "supplier_payment", "payroll")):
        return "medium" if (amount is None or amount < dual_control_threshold_gbp()) else "high"
    if consequential:
        return "medium"
    if "invoice" in domains and not consequential:
        return "low"
    return "low"


def parse_ai_financial_payload(raw: Any) -> dict[str, Any] | None:
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
    data["financial_sources"] = []
    # Strip authority / AML / authorisation grants from the model.
    data.pop("authority_state", None)
    data.pop("aml_kyc_state", None)
    data.pop("execution_allowed", None)
    data.pop("regulated_authorised", None)
    return data


def assess(
    *,
    tenant_id: str,
    user_id: str,
    role: str,
    module: str,
    action: str,
    facts: str = "",
    jurisdiction_raw: str | None = None,
    financial_domain: str | None = None,
    amount: Any = None,
    currency: str | None = None,
    customer_id: str | None = None,
    invoice_id: str | None = None,
    invoice_number: str | None = None,
    payment_reference: str | None = None,
    consequential_action: bool = False,
    requested_outcome: str = "",
    approval_present: bool = False,
    approval_count: int = 0,
    human_financial_review_present: bool = False,
    payload_tenant_id: str | None = None,
    aml_kyc_system_state: str | None = None,
    sanctions_system_state: str | None = None,
    original_transaction_amount: Any = None,
    beneficiary_evidence_present: bool = False,
    legal_execution_allowed: bool | None = None,
    guardian_ok: bool = True,
    promotion_approval_present: bool = False,
    regulated_authorisation_system_state: str | None = None,
    ai_payload: dict[str, Any] | None = None,
) -> FinancialAssessment:
    if payload_tenant_id and payload_tenant_id != tenant_id:
        raise PermissionError("Tenant identity cannot be supplied by the client payload")

    text = f"{action} {facts} {requested_outcome} {financial_domain or ''}"
    parsed_amount = _parse_amount(amount, text)
    original_amount = _parse_amount(original_transaction_amount, "")
    domains = _domains(financial_domain, text)
    primary = _primary_domain(domains)
    risk = _risk(action, text, domains, consequential_action, parsed_amount)
    missing: list[str] = []
    assumptions: list[str] = []
    jurisdiction = (jurisdiction_raw or "").strip() or None

    if not guardian_ok:
        missing.append("Guardian control must pass before financial execution")

    # Authority
    authority = "not_required"
    if consequential_action:
        if role in {"owner", "admin"} and approval_present:
            authority = "established"
        elif role in {"owner", "admin"}:
            authority = "conditional"
            missing.append("recorded approval for this consequential financial action")
        else:
            authority = "missing"
            missing.append("authority to perform this financial action")
    elif role in {"owner", "admin", "member", "client", "staff", "principal"}:
        authority = "established"

    # Evidence distinctions: user assertions are not system confirmation.
    if _contains(text, ("customer is verified", "kyc complete", "aml cleared")) and not aml_kyc_system_state:
        assumptions.append("User assertion of verification was not treated as system-confirmed evidence.")

    # AML/KYC — never invent verification.
    aml_relevant = any(d in domains for d in ("aml_kyc", "lending", "investment", "customer_money", "regulated_finance")) or _contains(text, DOMAIN_MARKERS["aml_kyc"])
    system_aml = (aml_kyc_system_state or "").strip().lower()
    if system_aml and system_aml not in AML_KYC_STATES:
        system_aml = "review_required"
    if not aml_relevant:
        aml_state = "not_applicable"
    elif system_aml in AML_KYC_STATES and system_aml != "not_applicable":
        aml_state = system_aml
        if aml_state in {"required", "pending", "insufficient", "failed", "review_required"}:
            missing.append("completed AML/KYC verification from an approved process")
    else:
        aml_state = "required" if consequential_action else "not_applicable"
        if consequential_action and aml_relevant:
            aml_state = "insufficient"
            missing.append("completed AML/KYC verification from an approved process")

    # Sanctions — consume only known system state.
    sanctions = (sanctions_system_state or "not_checked").strip().lower()
    if sanctions not in SANCTIONS_STATES:
        sanctions = "not_checked"
    if sanctions in {"possible_match", "confirmed_match"}:
        risk = "critical"
        missing.append("sanctions clearance from an approved screening process")

    # Invoice control
    if "invoice" in domains:
        if not (customer_id or _contains(text, ("customer known", "supplier known"))):
            missing.append("known customer or supplier for the invoice")
        if consequential_action and not (invoice_id or invoice_number):
            missing.append("invoice identity")
        if consequential_action and parsed_amount is None:
            missing.append("invoice amount")

    # Payment control
    payment_like = any(d in domains for d in ("payment", "supplier_payment", "payroll", "refund", "customer_money"))
    if payment_like and consequential_action:
        if parsed_amount is None:
            missing.append("payment amount")
        if not (currency or _contains(text, ("gbp", "usd", "eur", "£"))):
            missing.append("payment currency")
        if not beneficiary_evidence_present and primary != "refund":
            missing.append("confirmed beneficiary evidence")

    # Refund control
    if "refund" in domains:
        if original_amount is None and consequential_action:
            missing.append("original transaction amount")
        if parsed_amount is not None and original_amount is not None and parsed_amount > original_amount:
            missing.append("refund must not exceed the original transaction")
            if risk not in {"high", "critical"}:
                risk = "high"
        if consequential_action:
            if risk not in {"high", "critical"}:
                risk = "high"

    # Dual control
    threshold = dual_control_threshold_gbp()
    dual_required = False
    if consequential_action and payment_like and parsed_amount is not None and parsed_amount >= threshold:
        dual_required = True
    if consequential_action and any(d in domains for d in ("customer_money", "regulated_finance")) and parsed_amount and parsed_amount >= threshold:
        dual_required = True
    recorded_approvals = max(int(approval_count or 0), 1 if approval_present else 0)
    if dual_required and recorded_approvals < 2:
        missing.append("second authorised approval")

    # Financial promotions
    promotion = "financial_promotion" in domains or _contains(text, PROMOTION_MARKERS)
    if promotion and consequential_action and not promotion_approval_present:
        missing.append("compliance approval for financial promotion")
        if risk not in {"high", "critical"}:
            risk = "high"

    # Regulated activity
    regulated = "not_applicable"
    if promotion or any(d in domains for d in ("investment", "lending", "credit", "insurance", "leasing", "regulated_finance")) or _contains(text, REGULATED_MARKERS):
        auth = (regulated_authorisation_system_state or "").strip().lower()
        if auth in {"authorised", "established"}:
            regulated = "applicable"
        elif auth in REGULATED_STATES:
            regulated = auth
        else:
            regulated = "uncertain"
            missing.append("regulated-activity authorisation status from system evidence")
        if regulated in {"uncertain", "review_required", "possible"}:
            missing.append("human review of regulated-finance status")

    # Consumer Duty / customer outcome
    ukish = bool(jurisdiction and jurisdiction.lower() in {"uk", "united kingdom", "england and wales", "scotland", "northern ireland"})
    retailish = any(d in domains for d in ("investment", "lending", "credit", "insurance", "refund", "financial_promotion", "customer_money", "pricing"))
    consumer_duty = "not_applicable"
    outcome = "unknown"
    if ukish and retailish:
        consumer_duty = "applicable"
        if _contains(text, UNACCEPTABLE_HARM_MARKERS):
            outcome = "unacceptable_harm"
            consumer_duty = "fail"
            missing.append("unacceptable customer-outcome risk must be resolved")
        elif _contains(text, HARM_MARKERS):
            outcome = "potential_harm"
            consumer_duty = "review_required"
            missing.append("Consumer Duty customer-outcome review")
        else:
            outcome = "neutral"
            consumer_duty = "review_required"
            if consequential_action:
                missing.append("Consumer Duty customer-outcome review")
    elif _contains(text, UNACCEPTABLE_HARM_MARKERS):
        outcome = "unacceptable_harm"
        missing.append("unacceptable customer-outcome risk must be resolved")
    elif _contains(text, HARM_MARKERS):
        outcome = "potential_harm"
        if consequential_action:
            missing.append("customer-outcome review")

    human_review = risk in {"high", "critical"} or consumer_duty in {"review_required", "fail"} or regulated in {"uncertain", "review_required", "possible", "applicable"} or outcome in {"potential_harm", "unacceptable_harm"}
    if "refund" in domains and consequential_action:
        human_review = True
    if human_review and not human_financial_review_present and consequential_action:
        missing.append("human financial review")

    if ai_payload:
        extra_missing = [str(x) for x in ai_payload.get("missing_evidence", []) if str(x).strip()]
        for item in extra_missing:
            if item not in missing:
                missing.append(item)
        for concern in ai_payload.get("consumer_outcome_concerns") or []:
            if str(concern).strip() and outcome == "unknown":
                outcome = "potential_harm"
        ai_risk = str(ai_payload.get("risk_level", "")).lower()
        if ai_risk in RISK_LEVELS and RISK_LEVELS.index(ai_risk) > RISK_LEVELS.index(risk):
            risk = ai_risk
            if risk in {"high", "critical"}:
                human_review = True
        incoming_sources = ai_payload.get("financial_sources") or ai_payload.get("legal_sources") or []
        if incoming_sources:
            assumptions.append("Model proposed financial sources were discarded; Phase 1 has no verified citation store.")
        # AI must never grant authority / AML verified / regulated authorised.
        if str(ai_payload.get("approval_recommendation", "")).lower() in {"allow", "approve", "grant"}:
            assumptions.append("Model approval recommendation was ignored; deterministic controls decide execution.")

    if not missing:
        evidence = "sufficient"
    elif consequential_action and (
        authority in {"missing", "conflicting"}
        or risk in {"high", "critical"}
        or aml_state in {"required", "insufficient", "failed", "pending", "review_required"}
        or sanctions in {"possible_match", "confirmed_match"}
        or outcome == "unacceptable_harm"
    ):
        evidence = "insufficient"
    else:
        evidence = "partial"

    approval_required = consequential_action or human_review or dual_required or promotion
    blocked = False
    block_reasons: list[str] = []
    if not guardian_ok:
        blocked = True
        block_reasons.append("Guardian blocked this financial action.")
    if legal_execution_allowed is False:
        blocked = True
        block_reasons.append("Legal Intelligence blocked this action; Financial Intelligence cannot override it.")
        missing.append("Legal Intelligence execution permission")
    if consequential_action:
        if authority in {"missing", "conflicting"}:
            blocked = True
            block_reasons.append("Financial authority is missing or conflicting.")
        if authority == "conditional" and not approval_present:
            blocked = True
        if evidence == "insufficient":
            blocked = True
        if human_review and not human_financial_review_present:
            blocked = True
        if aml_state in {"required", "insufficient", "failed", "pending", "review_required"}:
            blocked = True
            block_reasons.append("Required AML/KYC state is incomplete or failed.")
        if sanctions in {"possible_match", "confirmed_match", "review_required"}:
            blocked = True
            block_reasons.append("Sanctions screening blocks consequential execution.")
        if dual_required and recorded_approvals < 2:
            blocked = True
            block_reasons.append(
                f"The proposed action exceeds the dual-control threshold ({threshold:g} GBP) and only {recorded_approvals} authorised approval(s) are recorded."
            )
        if outcome == "unacceptable_harm":
            blocked = True
            block_reasons.append("Unacceptable customer harm was identified.")
        if consumer_duty in {"review_required", "fail"} and not human_financial_review_present:
            blocked = True
        if promotion and not promotion_approval_present:
            blocked = True
            block_reasons.append("Financial promotion cannot be released without compliance approval.")
        if regulated in {"uncertain", "review_required"}:
            blocked = True
            block_reasons.append("Regulated-finance status is unresolved.")
        if parsed_amount is not None and original_amount is not None and parsed_amount > original_amount and "refund" in domains:
            blocked = True
            block_reasons.append("Refund exceeds the original transaction.")

    execution_allowed = not blocked
    if not consequential_action and guardian_ok and legal_execution_allowed is not False:
        execution_allowed = True  # advisory / non-consequential assessments may proceed

    if not ALLOWED_SOURCES:
        assumptions.append("Source verification required.")
    if not consequential_action:
        assumptions.append("This is advisory financial control analysis only and is not a payment, investment or compliance determination.")

    reasons = list(block_reasons)
    if missing:
        reasons.append("Missing: " + "; ".join(missing) + ".")
    if not reasons:
        reasons.append("Deterministic financial control checks passed for this scoped Phase 1 request.")

    if not consequential_action:
        heading = "FINANCIAL CONTROL: ADVISORY"
    elif execution_allowed:
        heading = "FINANCIAL CONTROL: ALLOWED"
    else:
        heading = "FINANCIAL CONTROL: BLOCKED"
    user_facing = heading + "\n\nReason:\n" + " ".join(reasons)
    if missing:
        user_facing += "\nMissing:\n" + "\n".join(f"- {item}" for item in missing)

    control = {
        "execution_allowed": execution_allowed,
        "approval_required": approval_required,
        "dual_control_required": dual_required,
        "human_financial_review_required": human_review,
        "risk_level": risk,
        "authority_state": authority,
        "evidence_state": evidence,
        "aml_kyc_state": aml_state,
        "sanctions_state": sanctions,
        "amount": parsed_amount,
        "currency": currency or ("GBP" if parsed_amount is not None else None),
        "customer_id": customer_id,
        "invoice_id": invoice_id,
        "payment_reference": payment_reference,
        "legal_execution_allowed": legal_execution_allowed,
        "guardian_ok": guardian_ok,
    }

    return FinancialAssessment(
        financial_assessment_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        requesting_user_id=user_id,
        module=module,
        action=action,
        jurisdiction=jurisdiction,
        financial_domain=primary,
        financial_domains=domains,
        risk_level=risk,
        regulated_activity_state=regulated,
        authority_state=authority,
        evidence_state=evidence,
        aml_kyc_state=aml_state,
        sanctions_state=sanctions,
        consumer_duty_state=consumer_duty,
        customer_outcome_state=outcome,
        approval_required=approval_required,
        dual_control_required=dual_required,
        human_financial_review_required=human_review,
        execution_allowed=execution_allowed,
        reasoning_summary=" ".join(reasons),
        missing_information=missing,
        assumptions=assumptions,
        financial_sources=[],
        created_at=_now(),
        financial_control=control,
        user_facing=user_facing,
    )
