"""Legal Intelligence Phase 1 — structured control gate.

Deterministic control decisions. Optional AI enrichment via legal-pathways.
Never fabricates statutes, cases or citations.
"""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

RISK_LEVELS = ("low", "medium", "high", "critical")
AUTHORITY_STATES = ("established", "conditional", "missing", "conflicting", "not_required")
EVIDENCE_STATES = ("sufficient", "partial", "insufficient", "conflicting")
JURISDICTIONS = {
    "england and wales": "England and Wales",
    "scotland": "Scotland",
    "northern ireland": "Northern Ireland",
    "united kingdom": "United Kingdom",
    "uk": "United Kingdom",
    "uk-wide": "United Kingdom",
}
DOMAINS = (
    "contract", "consumer", "data_protection", "privacy", "employment",
    "commercial", "company", "intellectual_property", "financial_services",
    "aml_kyc", "property", "health_safety", "communications", "marketing",
    "electronic_transactions", "records_retention", "sector_specific", "unknown",
)
HIGH_RISK_MARKERS = (
    "litigation", "court", "tribunal", "injunction", "prosecut", "criminal",
    "settlement", "termination", "redundan", "waiver", "admit liability",
    "formal notice", "statutory demand", "winding up", "enforcement",
    "fca ", "pra ", "ico enforcement", "sra ", "money laundering",
    "sanction", "indemnity cap", "unlimited liability",
)
AML_MARKERS = ("aml", "kyc", "source of funds", "money laundering", "sanctions", "pep ")
GDPR_MARKERS = ("personal data", "gdpr", "special category", "lawful basis", "data subject", "retention")
CONTRACT_MARKERS = ("contract", "agreement", "deed", "terms", "counterparty", "governing law")

ALLOWED_SOURCES: tuple[str, ...] = ()  # Phase 1 has no verified citation store


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalise_jurisdiction(raw: str | None) -> str | None:
    if not raw:
        return None
    key = re.sub(r"\s+", " ", raw.strip().lower())
    return JURISDICTIONS.get(key)


def _contains(text: str, needles: Iterable[str]) -> bool:
    blob = (text or "").lower()
    return any(n in blob for n in needles)


@dataclass
class LegalAssessment:
    legal_assessment_id: str
    tenant_id: str
    requesting_user_id: str
    module: str
    action: str
    jurisdiction: str | None
    matter_type: str
    risk_level: str
    applicable_domains: list[str]
    authority_state: str
    evidence_state: str
    approval_required: bool
    human_legal_review_required: bool
    execution_allowed: bool
    reasoning_summary: str
    missing_information: list[str]
    legal_sources: list[str]
    assumptions: list[str]
    created_at: str
    aml_kyc_state: str = "not_applicable"
    gdpr: dict[str, Any] = field(default_factory=dict)
    legal_control: dict[str, Any] = field(default_factory=dict)
    user_facing: str = ""

    def as_public(self) -> dict[str, Any]:
        return {
            "legal_assessment_id": self.legal_assessment_id,
            "module": self.module,
            "action": self.action,
            "jurisdiction": self.jurisdiction,
            "matter_type": self.matter_type,
            "risk_level": self.risk_level,
            "applicable_domains": self.applicable_domains,
            "authority_state": self.authority_state,
            "evidence_state": self.evidence_state,
            "approval_required": self.approval_required,
            "human_legal_review_required": self.human_legal_review_required,
            "execution_allowed": self.execution_allowed,
            "reasoning_summary": self.reasoning_summary,
            "missing_information": self.missing_information,
            "legal_sources": self.legal_sources,
            "assumptions": self.assumptions,
            "aml_kyc_state": self.aml_kyc_state,
            "gdpr": self.gdpr,
            "legal_control": self.legal_control,
            "user_facing": self.user_facing,
            "created_at": self.created_at,
        }


def _domains(text: str, data_classes: list[str] | None) -> list[str]:
    found: list[str] = []
    blob = text.lower()
    classes = {c.lower() for c in (data_classes or [])}
    if classes & {"personal", "special_category", "child", "health"} or _contains(blob, GDPR_MARKERS):
        found.extend(["data_protection", "privacy"])
    if _contains(blob, CONTRACT_MARKERS):
        found.append("contract")
    if _contains(blob, AML_MARKERS):
        found.append("aml_kyc")
    if _contains(blob, ("employ", "dismissal", "redundan", "workplace")):
        found.append("employment")
    if _contains(blob, ("market", "advert", "promotion")):
        found.append("marketing")
    if _contains(blob, ("email", "letter", "correspondence", "notice")):
        found.append("communications")
    if _contains(blob, ("retain", "archive", "record")):
        found.append("records_retention")
    if not found:
        found.append("unknown")
    out = []
    for item in found:
        if item in DOMAINS and item not in out:
            out.append(item)
    return out


def _risk(action: str, text: str, consequential: bool, domains: list[str]) -> str:
    blob = f"{action} {text}".lower()
    if _contains(blob, HIGH_RISK_MARKERS) or "critical" in blob:
        return "critical" if _contains(blob, ("criminal", "court", "unlimited liability")) else "high"
    if consequential and ("data_protection" in domains or "aml_kyc" in domains or "contract" in domains):
        return "medium"
    if consequential:
        return "medium"
    return "low"


def assess(
    *,
    tenant_id: str,
    user_id: str,
    role: str,
    module: str,
    action: str,
    facts: str = "",
    jurisdiction_raw: str | None = None,
    matter_type: str = "general",
    document_id: str | None = None,
    document_hash: str | None = None,
    consequential_action: bool = False,
    requested_outcome: str = "",
    data_classes: list[str] | None = None,
    approval_present: bool = False,
    human_legal_review_present: bool = False,
    payload_tenant_id: str | None = None,
    ai_payload: dict[str, Any] | None = None,
) -> LegalAssessment:
    if payload_tenant_id and payload_tenant_id != tenant_id:
        raise PermissionError("Tenant identity cannot be supplied by the client payload")

    text = f"{action} {facts} {requested_outcome} {matter_type}"
    jurisdiction = normalise_jurisdiction(jurisdiction_raw)
    domains = _domains(text, data_classes)
    risk = _risk(action, text, consequential_action, domains)
    missing: list[str] = []
    assumptions: list[str] = []

    if jurisdiction_raw and not jurisdiction:
        missing.append("recognised UK jurisdiction (England and Wales, Scotland, Northern Ireland, or United Kingdom)")
    if not jurisdiction and (consequential_action or "data_protection" in domains or "contract" in domains):
        missing.append("governing jurisdiction")

    authority = "not_required"
    if consequential_action:
        if role in {"owner", "admin"} and approval_present:
            authority = "established"
        elif role in {"owner", "admin"}:
            authority = "conditional"
            missing.append("recorded approval for this consequential action")
        else:
            authority = "missing"
            missing.append("authority to bind or release")
    elif role in {"owner", "admin", "member", "client"}:
        authority = "established"

    gdpr = {
        "personal_data_involved": "data_protection" in domains,
        "special_category_indicators": bool(set(data_classes or []) & {"special_category", "health", "child"}) or _contains(text, ("special category", "health data")),
        "lawful_basis_known": _contains(text, ("lawful basis is consent", "lawful basis: consent", "contractual necessity", "legitimate interests", "legal obligation as basis", "vital interests", "public task")),
        "purpose_known": bool(requested_outcome or action),
        "data_sharing_involved": consequential_action and "data_protection" in domains,
        "retention_issue": _contains(text, ("retain", "delete", "erasure")),
        "cross_border_issue": _contains(text, ("transfer", "outside uk", "adequacy")),
        "human_review_required": False,
    }
    if gdpr["personal_data_involved"] and not gdpr["lawful_basis_known"]:
        if gdpr["special_category_indicators"] or _contains(text, ("lawful basis", "process personal data", "share personal data")):
            missing.append("lawful basis for personal data processing")
            gdpr["human_review_required"] = True
        else:
            assumptions.append("Personal data appears involved; a lawful basis was not stated and must be confirmed before reliance.")

    aml_state = "not_applicable"
    if "aml_kyc" in domains:
        aml_state = "required"
        if not _contains(text, ("kyc complete", "aml cleared", "verification complete")):
            aml_state = "insufficient"
            missing.append("completed AML/KYC verification from an approved process")

    bind_gap = consequential_action and "contract" in domains and not _contains(text, ("authorised to bind", "authority to sign", "board authority"))
    if bind_gap:
        if authority == "established":
            authority = "conditional"
        missing.append("authority to bind the organisation to the contract")

    human_review = risk in {"high", "critical"} or gdpr["human_review_required"] or aml_state in {"required", "insufficient", "review_required"}
    if human_review and not human_legal_review_present and consequential_action:
        missing.append("human legal review")

    if ai_payload:
        extra_missing = [str(x) for x in ai_payload.get("missing_evidence", []) if str(x).strip()]
        for item in extra_missing:
            if item not in missing:
                missing.append(item)
        ai_risk = str(ai_payload.get("risk_level", "")).lower()
        if ai_risk in RISK_LEVELS and RISK_LEVELS.index(ai_risk) > RISK_LEVELS.index(risk):
            risk = ai_risk
            if risk in {"high", "critical"}:
                human_review = True
        # Never accept model-invented sources.
        incoming_sources = ai_payload.get("legal_sources") or []
        if incoming_sources:
            assumptions.append("Model proposed legal sources were discarded; Phase 1 has no verified citation store.")

    if not missing:
        evidence = "sufficient"
    elif consequential_action and (authority in {"missing", "conflicting"} or risk in {"high", "critical"} or aml_state == "insufficient" or gdpr["human_review_required"]):
        evidence = "insufficient"
    else:
        evidence = "partial"

    approval_required = consequential_action or human_review
    blocked = False
    if consequential_action:
        if authority in {"missing", "conflicting"}:
            blocked = True
        if evidence == "insufficient":
            blocked = True
        if human_review and not human_legal_review_present:
            blocked = True
        if aml_state == "insufficient":
            blocked = True
        if "governing jurisdiction" in missing and "data_protection" in domains:
            blocked = True
        if bind_gap:
            blocked = True

    execution_allowed = (not consequential_action and not blocked) or (consequential_action and not blocked)

    reasons = []
    if blocked:
        reasons.append("Consequential execution is blocked until authority, evidence and required review are established.")
    if missing:
        reasons.append("Missing: " + "; ".join(missing) + ".")
    if not jurisdiction:
        reasons.append("Jurisdiction was not established as a specific UK nation or UK-wide position.")
    if not ALLOWED_SOURCES:
        reasons.append("No verified legal sources are attached; source verification is required before reliance.")
    if not reasons:
        reasons.append("Deterministic legal control checks passed for this scoped Phase 1 request.")
    if not consequential_action:
        assumptions.append("This is advisory analysis only and is not a solicitor opinion or final legal determination.")

    heading = "LEGAL CONTROL: ALLOWED" if execution_allowed and not blocked else "LEGAL CONTROL: BLOCKED"
    if not consequential_action:
        heading = "LEGAL CONTROL: ADVISORY"
    user_facing = heading + "\n\nReason:\n" + " ".join(reasons)

    control = {
        "execution_allowed": bool(execution_allowed and not blocked),
        "approval_required": approval_required,
        "human_legal_review_required": human_review,
        "risk_level": risk,
        "authority_state": authority,
        "evidence_state": evidence,
        "document_id": document_id,
        "document_hash": document_hash,
    }

    return LegalAssessment(
        legal_assessment_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        requesting_user_id=user_id,
        module=module,
        action=action,
        jurisdiction=jurisdiction,
        matter_type=matter_type or "general",
        risk_level=risk,
        applicable_domains=domains,
        authority_state=authority,
        evidence_state=evidence,
        approval_required=approval_required,
        human_legal_review_required=human_review,
        execution_allowed=control["execution_allowed"],
        reasoning_summary=" ".join(reasons),
        missing_information=missing,
        legal_sources=[],
        assumptions=assumptions,
        created_at=_now(),
        aml_kyc_state=aml_state,
        gdpr=gdpr,
        legal_control=control,
        user_facing=user_facing,
    )


def parse_ai_legal_payload(raw: Any) -> dict[str, Any] | None:
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
    data["legal_sources"] = []  # never accept model citations in Phase 1
    return data


def assess_document_release(*, user: dict, document: dict, profile: dict, destination: str) -> LegalAssessment:
    classes = []
    raw = document.get("data_classes")
    if raw:
        try:
            classes = json.loads(raw) if isinstance(raw, str) else list(raw)
        except json.JSONDecodeError:
            classes = []
    return assess(
        tenant_id=user["tenant_id"],
        user_id=user["id"],
        role=user.get("role") or "client",
        module="legal-pathways",
        action="release_letter",
        facts=f"{document.get('type','')} {document.get('purpose','')} destination_present={bool(destination)}",
        jurisdiction_raw=profile.get("home_jurisdiction") or None,
        matter_type=str(document.get("type") or "letter"),
        document_id=document.get("id"),
        document_hash=document.get("content_hash"),
        consequential_action=True,
        requested_outcome="controlled_release",
        data_classes=classes,
        approval_present=bool(document.get("approved_by") and not document.get("approval_revoked_at")),
        human_legal_review_present=False,
    )
