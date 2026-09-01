"""Gate 5 Core-connected API layer.

Extends the existing Zorvian FastAPI app without changing the proven Gate 2-4 core.
"""
import os

from fastapi import Depends, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app import app, audit, current_user, rate_limit, require, request_fingerprint, security_event
from intelligence.connected import ConnectedIntelligenceService, ConnectedRequest, SUPPORTED_MODULES
from intelligence.context import WorkspaceContext
from intelligence.executor import execute_provider
from intelligence.guard import guardian_check
from intelligence.providers import ProviderProfile, ProviderRegistry
from intelligence.resilience import status_snapshot
from intelligence.legal import assess, parse_ai_legal_payload
from intelligence.financial import assess as assess_financial, parse_ai_financial_payload
from intelligence.guardian import assess as assess_guardian, parse_ai_guardian_payload
from intelligence.orchestrator import decide as constitutional_decide


_ALL_CAPABILITIES = frozenset({
    "communications", "executive-operations", "scheduling", "automotive",
    "fresh-produce", "contracts-tenders", "growth", "marketing-content",
    "sales-commercial", "operations", "analytics", "documents",
    "document-assurance", "mobility", "automation-safety", "media-production",
    "legal-workflow", "finance-workflow", "security-analysis",
})


def _local_beta_enabled():
    return os.getenv("ALLOW_LOCAL_BETA", "0").strip() == "1"


def _configured_remote_providers():
    configured = []
    if os.getenv("OPENAI_API_KEY"):
        configured.append("openai")
    if os.getenv("ANTHROPIC_API_KEY"):
        configured.append("anthropic")
    if os.getenv("ZORVIAN_AI_ADAPTER_URL") and os.getenv("ZORVIAN_AI_ADAPTER_KEY"):
        configured.append("zorvian-remote")
    return configured


def _registry():
    profiles = []
    if os.getenv("OPENAI_API_KEY"):
        profiles.append(ProviderProfile("openai", _ALL_CAPABILITIES, True, True, True, 10, 20, True))
    if os.getenv("ANTHROPIC_API_KEY"):
        profiles.append(ProviderProfile("anthropic", _ALL_CAPABILITIES, True, True, True, 12, 22, True))
    if os.getenv("ZORVIAN_AI_ADAPTER_URL") and os.getenv("ZORVIAN_AI_ADAPTER_KEY"):
        profiles.append(ProviderProfile("zorvian-remote", _ALL_CAPABILITIES, True, True, True, 15, 25, True))
    if _local_beta_enabled():
        profiles.append(ProviderProfile("zorvian-local-beta", _ALL_CAPABILITIES, True, True, True, 90, 1, True))
    return ProviderRegistry(profiles)


def _service():
    return ConnectedIntelligenceService(_registry(), execute_provider)


class LegalAssessIn(BaseModel):
    module: str = Field(default="legal-pathways", min_length=2, max_length=50)
    action: str = Field(min_length=2, max_length=80)
    jurisdiction: str | None = None
    matter_type: str = "general"
    facts: str = Field(default="", max_length=12000)
    document_id: str | None = None
    document_hash: str | None = None
    consequential_action: bool = False
    requested_outcome: str = Field(default="", max_length=500)
    data_classes: list[str] = Field(default_factory=list)
    tenant_id: str | None = None
    approval_present: bool = False
    human_legal_review_present: bool = False


class FinancialAssessIn(BaseModel):
    module: str = Field(default="finance-pathways", min_length=2, max_length=50)
    action: str = Field(min_length=2, max_length=80)
    jurisdiction: str | None = None
    financial_domain: str | None = None
    facts: str = Field(default="", max_length=12000)
    amount: float | None = None
    currency: str | None = None
    customer_id: str | None = None
    invoice_id: str | None = None
    invoice_number: str | None = None
    payment_reference: str | None = None
    consequential_action: bool = False
    requested_outcome: str = Field(default="", max_length=500)
    tenant_id: str | None = None
    approval_present: bool = False
    approval_count: int = 0
    human_financial_review_present: bool = False
    aml_kyc_system_state: str | None = None
    sanctions_system_state: str | None = None
    original_transaction_amount: float | None = None
    beneficiary_evidence_present: bool = False
    legal_execution_allowed: bool | None = None
    promotion_approval_present: bool = False
    regulated_authorisation_system_state: str | None = None


class GuardianAssessIn(BaseModel):
    module: str = Field(default="security-analysis", min_length=2, max_length=50)
    action: str = Field(min_length=2, max_length=80)
    facts: str = Field(default="", max_length=12000)
    resource_type: str | None = None
    resource_id: str | None = None
    resource_hash: str | None = None
    consequential_action: bool = False
    requested_outcome: str = Field(default="", max_length=500)
    tenant_id: str | None = None
    identity_state: str | None = None
    session_state: str | None = None
    mfa_verified: bool = False
    approvals: list[dict] = Field(default_factory=list)
    approval_present: bool = False
    incident_state: str | None = None
    supplier_ict_state: str | None = None
    provider_health: str | None = None
    provider_trust_state: str | None = None
    retention_state: str | None = None
    legal_hold_state: str | None = None
    legal_execution_allowed: bool | None = None
    legal_human_review_required: bool = False
    financial_execution_allowed: bool | None = None
    financial_dual_control_complete: bool | None = None
    intent: str = "execute"
    requested_outcome_note: str | None = None


class OrchestratorDecideIn(BaseModel):
    module: str = Field(default="constitutional-core", min_length=2, max_length=50)
    action: str = Field(min_length=2, max_length=80)
    facts: str = Field(default="", max_length=12000)
    jurisdiction: str | None = None
    matter_type: str = "general"
    financial_domain: str | None = None
    amount: float | None = None
    currency: str | None = None
    customer_id: str | None = None
    invoice_id: str | None = None
    invoice_number: str | None = None
    payment_reference: str | None = None
    original_transaction_amount: float | None = None
    beneficiary_evidence_present: bool = False
    document_id: str | None = None
    document_hash: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    resource_hash: str | None = None
    consequential_action: bool = False
    requested_outcome: str = Field(default="", max_length=500)
    data_classes: list[str] = Field(default_factory=list)
    tenant_id: str | None = None
    approval_present: bool = False
    approval_count: int = 0
    approvals: list[dict] = Field(default_factory=list)
    human_legal_review_present: bool = False
    human_financial_review_present: bool = False
    aml_kyc_system_state: str | None = None
    sanctions_system_state: str | None = None
    promotion_approval_present: bool = False
    regulated_authorisation_system_state: str | None = None
    identity_state: str | None = None
    session_state: str | None = None
    mfa_verified: bool = False
    incident_state: str | None = None
    supplier_ict_state: str | None = None
    provider_health: str | None = None
    provider_trust_state: str | None = None
    retention_state: str | None = None
    legal_hold_state: str | None = None
    intent: str = "execute"


class IntelligenceRunIn(BaseModel):
    module: str = Field(min_length=2, max_length=50)
    task: str = Field(min_length=2, max_length=120)
    prompt: str = Field(min_length=1, max_length=12000)
    needs_retrieval: bool = False
    needs_tools: bool = False
    consequential_action: bool = False


@app.middleware("http")
async def gate5_beta_csp(request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/beta"):
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'"
        response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/intelligence/capabilities")
def intelligence_capabilities(u=Depends(current_user)):
    configured = _configured_remote_providers()
    states = status_snapshot(configured)
    healthy = sum(1 for s in states.values() if s["state"] == "healthy")
    degraded = sum(1 for s in states.values() if s["state"] in {"degraded", "cooldown"})
    if configured:
        provider_mode = "connected"
    elif _local_beta_enabled():
        provider_mode = "controlled-local-beta"
    else:
        provider_mode = "unavailable"
    return {
        "modules": sorted(SUPPORTED_MODULES),
        "guardian": "active",
        "provider_mode": provider_mode,
        "configured_provider_count": len(configured),
        "healthy_provider_count": healthy,
        "degraded_provider_count": degraded,
        "local_beta_enabled": _local_beta_enabled(),
        "external_actions": "approval-gated",
    }


@app.post("/legal/intelligence/assess")
def legal_intelligence_assess(d: LegalAssessIn, request: Request, u=Depends(current_user)):
    require(u, "write")
    ip, _ = request_fingerprint(request)
    rate_limit("legal-assess:" + u["tenant_id"] + ":" + str(ip), 60, 3600)
    audit(u, "legal_assessment_started", d.action)
    ai_payload = None
    try:
        prompt = (
            "Return JSON only with keys risk_level, applicable_domains, missing_evidence, "
            "legal_review_required, approval_required, execution_recommendation, reasoning_summary, assumptions. "
            "Do not invent case law or statute citations. Jurisdiction: "
            f"{d.jurisdiction or 'unspecified'}. Action: {d.action}. Facts: {d.facts[:4000]}"
        )
        ctx = WorkspaceContext(tenant_id=u["tenant_id"], user_id=u["id"], role=u["role"], module="legal-pathways", instructions=("Do not invent legal citations.",))
        result = _service().run(ConnectedRequest(module="legal-pathways", task="legal-control-assessment", prompt=prompt, consequential_action=d.consequential_action), ctx)
        ai_payload = parse_ai_legal_payload(result.output)
        if d.consequential_action and ai_payload is None:
            audit(u, "legal_control_blocked", "malformed AI legal decision")
            raise HTTPException(502, {"error": "ai_provider_failed", "message": "Legal Intelligence could not validate a structured legal decision."})
    except LookupError as exc:
        audit(u, "legal_control_blocked", f"provider unavailable:{exc}", "warning")
        if d.consequential_action:
            raise HTTPException(503, {"error": "ai_provider_unavailable", "message": "Celestial Core intelligence is temporarily unavailable. Please try again shortly."})
    except RuntimeError as exc:
        audit(u, "legal_control_blocked", f"provider failed:{exc}", "warning")
        if d.consequential_action:
            raise HTTPException(502, {"error": "ai_provider_failed", "message": "Celestial Core could not complete this intelligence request. Please try again shortly."})
    except PermissionError as exc:
        raise HTTPException(403, str(exc))

    try:
        assessment = assess(
            tenant_id=u["tenant_id"],
            user_id=u["id"],
            role=u["role"],
            module=d.module or "legal-pathways",
            action=d.action,
            facts=d.facts,
            jurisdiction_raw=d.jurisdiction,
            matter_type=d.matter_type,
            document_id=d.document_id,
            document_hash=d.document_hash,
            consequential_action=d.consequential_action,
            requested_outcome=d.requested_outcome,
            data_classes=d.data_classes,
            approval_present=d.approval_present,
            human_legal_review_present=d.human_legal_review_present,
            payload_tenant_id=d.tenant_id,
            ai_payload=ai_payload,
        )
    except PermissionError as exc:
        raise HTTPException(403, str(exc))

    if assessment.execution_allowed:
        audit(u, "legal_control_passed", assessment.legal_assessment_id)
        audit(u, "legal_assessment_completed", assessment.legal_assessment_id)
    else:
        audit(u, "legal_control_blocked", assessment.legal_assessment_id)
        if assessment.evidence_state == "insufficient":
            audit(u, "legal_evidence_insufficient", assessment.legal_assessment_id)
        if assessment.authority_state in {"missing", "conflicting"}:
            audit(u, "legal_authority_missing", assessment.legal_assessment_id)
        if assessment.human_legal_review_required:
            audit(u, "legal_review_required", assessment.legal_assessment_id)
        audit(u, "legal_assessment_completed", assessment.legal_assessment_id)
    return assessment.as_public()


@app.post("/financial/intelligence/assess")
def financial_intelligence_assess(d: FinancialAssessIn, request: Request, u=Depends(current_user)):
    require(u, "write")
    ip, _ = request_fingerprint(request)
    rate_limit("financial-assess:" + u["tenant_id"] + ":" + str(ip), 60, 3600)
    audit(u, "financial_assessment_started", d.action)
    guardian_ok = True
    try:
        guardian_check(d.facts or d.action)
    except PermissionError as exc:
        guardian_ok = False
        audit(u, "financial_control_blocked", "guardian:" + str(exc), "warning")
        if d.consequential_action:
            raise HTTPException(403, str(exc))
    except ValueError:
        guardian_ok = True

    ai_payload = None
    try:
        prompt = (
            "Return JSON only with keys financial_domains, risk_level, missing_evidence, "
            "consumer_outcome_concerns, regulated_activity_indicators, approval_recommendation, "
            "reasoning_summary, assumptions. Do not grant authority, mark AML/KYC verified, "
            "or invent regulatory citations. Action: "
            f"{d.action}. Facts: {d.facts[:4000]}"
        )
        ctx = WorkspaceContext(
            tenant_id=u["tenant_id"],
            user_id=u["id"],
            role=u["role"],
            module="finance-pathways",
            instructions=("Do not invent financial citations or grant financial authority.",),
        )
        result = _service().run(
            ConnectedRequest(module="finance-pathways", task="financial-control-assessment", prompt=prompt, consequential_action=d.consequential_action),
            ctx,
        )
        ai_payload = parse_ai_financial_payload(result.output)
        if d.consequential_action and ai_payload is None:
            audit(u, "financial_control_blocked", "malformed AI financial decision")
            raise HTTPException(502, {"error": "ai_provider_failed", "message": "Financial Intelligence could not validate a structured financial decision."})
    except LookupError as exc:
        audit(u, "financial_control_blocked", f"provider unavailable:{exc}", "warning")
        if d.consequential_action:
            raise HTTPException(503, {"error": "ai_provider_unavailable", "message": "Celestial Core intelligence is temporarily unavailable. Please try again shortly."})
    except RuntimeError as exc:
        audit(u, "financial_control_blocked", f"provider failed:{exc}", "warning")
        if d.consequential_action:
            raise HTTPException(502, {"error": "ai_provider_failed", "message": "Celestial Core could not complete this intelligence request. Please try again shortly."})
    except PermissionError as exc:
        raise HTTPException(403, str(exc))

    try:
        assessment = assess_financial(
            tenant_id=u["tenant_id"],
            user_id=u["id"],
            role=u["role"],
            module=d.module or "finance-pathways",
            action=d.action,
            facts=d.facts,
            jurisdiction_raw=d.jurisdiction,
            financial_domain=d.financial_domain,
            amount=d.amount,
            currency=d.currency,
            customer_id=d.customer_id,
            invoice_id=d.invoice_id,
            invoice_number=d.invoice_number,
            payment_reference=d.payment_reference,
            consequential_action=d.consequential_action,
            requested_outcome=d.requested_outcome,
            approval_present=d.approval_present,
            approval_count=d.approval_count,
            human_financial_review_present=d.human_financial_review_present,
            payload_tenant_id=d.tenant_id,
            aml_kyc_system_state=d.aml_kyc_system_state,
            sanctions_system_state=d.sanctions_system_state,
            original_transaction_amount=d.original_transaction_amount,
            beneficiary_evidence_present=d.beneficiary_evidence_present,
            legal_execution_allowed=d.legal_execution_allowed,
            guardian_ok=guardian_ok,
            promotion_approval_present=d.promotion_approval_present,
            regulated_authorisation_system_state=d.regulated_authorisation_system_state,
            ai_payload=ai_payload,
        )
    except PermissionError as exc:
        raise HTTPException(403, str(exc))

    if assessment.execution_allowed:
        audit(u, "financial_control_passed", assessment.financial_assessment_id)
        audit(u, "financial_assessment_completed", assessment.financial_assessment_id)
    else:
        audit(u, "financial_control_blocked", assessment.financial_assessment_id)
        if assessment.authority_state in {"missing", "conflicting"}:
            audit(u, "financial_authority_missing", assessment.financial_assessment_id)
        if assessment.evidence_state == "insufficient":
            audit(u, "financial_evidence_insufficient", assessment.financial_assessment_id)
        if assessment.human_financial_review_required:
            audit(u, "financial_review_required", assessment.financial_assessment_id)
        if assessment.dual_control_required:
            audit(u, "financial_dual_control_required", assessment.financial_assessment_id)
        if assessment.aml_kyc_state in {"required", "insufficient", "pending", "failed", "review_required"}:
            audit(u, "financial_aml_required", assessment.financial_assessment_id)
            audit(u, "financial_aml_blocked", assessment.financial_assessment_id)
        if assessment.consumer_duty_state in {"applicable", "review_required", "fail"}:
            audit(u, "financial_consumer_duty_review", assessment.financial_assessment_id)
        if assessment.customer_outcome_state in {"potential_harm", "unacceptable_harm"}:
            audit(u, "financial_customer_harm_detected", assessment.financial_assessment_id)
        if "financial_promotion" in assessment.financial_domains:
            audit(u, "financial_promotion_blocked", assessment.financial_assessment_id)
        audit(u, "financial_assessment_completed", assessment.financial_assessment_id)
    return assessment.as_public()


@app.post("/guardian/intelligence/assess")
def guardian_intelligence_assess(d: GuardianAssessIn, request: Request, u=Depends(current_user)):
    require(u, "write")
    ip, _ = request_fingerprint(request)
    rate_limit("guardian-assess:" + u["tenant_id"] + ":" + str(ip), 60, 3600)
    audit(u, "guardian_assessment_started", d.action)
    security_event("guardian_assessment_started", "info", u["tenant_id"], u["id"], d.action[:200], request)

    ai_payload = None
    needs_ai = d.consequential_action and d.intent != "discuss"
    try:
        guardian_check(d.facts or d.action, intent=d.intent)
    except PermissionError:
        pass
    except ValueError:
        pass

    if needs_ai:
        try:
            prompt = (
                "Return JSON only with keys risk_level, security_indicators, missing_evidence, "
                "incident_indicators, supplier_risk_indicators, review_recommendation, "
                "reasoning_summary, assumptions. Do not grant RBAC, tenant access, clear incidents, "
                "or override Legal/Financial/Guardian. Action: "
                f"{d.action}. Facts: {d.facts[:4000]}"
            )
            ctx = WorkspaceContext(
                tenant_id=u["tenant_id"],
                user_id=u["id"],
                role=u["role"],
                module="security-analysis",
                instructions=("Do not grant authority. Do not clear incidents or override control layers.",),
            )
            result = _service().run(
                ConnectedRequest(module="security-analysis", task="guardian-control-assessment", prompt=prompt, consequential_action=d.consequential_action),
                ctx,
            )
            ai_payload = parse_ai_guardian_payload(result.output)
            if ai_payload is None:
                audit(u, "guardian_control_blocked", "malformed AI guardian decision")
                raise HTTPException(502, {"error": "ai_provider_failed", "message": "Guardian could not validate a structured security decision."})
        except LookupError as exc:
            audit(u, "guardian_control_blocked", f"provider unavailable:{exc}", "warning")
            raise HTTPException(503, {"error": "ai_provider_unavailable", "message": "Celestial Core intelligence is temporarily unavailable. Please try again shortly."})
        except RuntimeError as exc:
            audit(u, "guardian_control_blocked", f"provider failed:{exc}", "warning")
            raise HTTPException(502, {"error": "ai_provider_failed", "message": "Celestial Core could not complete this intelligence request. Please try again shortly."})
        except PermissionError as exc:
            raise HTTPException(403, str(exc))

    try:
        assessment = assess_guardian(
            tenant_id=u["tenant_id"],
            user_id=u["id"],
            role=u["role"],
            module=d.module or "security-analysis",
            action=d.action,
            facts=d.facts,
            resource_type=d.resource_type,
            resource_id=d.resource_id,
            resource_hash=d.resource_hash,
            consequential_action=d.consequential_action,
            requested_outcome=d.requested_outcome,
            payload_tenant_id=d.tenant_id,
            identity_state=d.identity_state,
            session_state=d.session_state,
            mfa_verified=d.mfa_verified,
            user_status=u.get("status"),
            approvals=d.approvals or None,
            approval_present=d.approval_present,
            incident_state=d.incident_state,
            supplier_ict_state=d.supplier_ict_state,
            provider_health=d.provider_health,
            provider_trust_state=d.provider_trust_state,
            retention_state=d.retention_state,
            legal_hold_state=d.legal_hold_state,
            legal_execution_allowed=d.legal_execution_allowed,
            legal_human_review_required=d.legal_human_review_required,
            financial_execution_allowed=d.financial_execution_allowed,
            financial_dual_control_complete=d.financial_dual_control_complete,
            intent=d.intent,
            ai_payload=ai_payload,
        )
    except PermissionError as exc:
        audit(u, "guardian_tenant_violation", str(exc), "warning")
        audit(u, "guardian_cross_tenant_attempt", d.tenant_id or "", "warning")
        security_event("guardian_tenant_violation", "warning", u["tenant_id"], u["id"], "payload tenant rejected", request)
        security_event("guardian_cross_tenant_attempt", "warning", u["tenant_id"], u["id"], "payload tenant rejected", request)
        raise HTTPException(403, str(exc))

    for event_name in assessment.guardian_control.get("audit_events") or []:
        detail = assessment.guardian_assessment_id
        if event_name == "guardian_secret_detected":
            detail = "secret-marker-present"
        audit(u, event_name, detail, "warning" if "block" in event_name or "violation" in event_name else "info")
        if event_name in {"guardian_tenant_violation", "guardian_cross_tenant_attempt", "guardian_override_attempt", "guardian_secret_detected"}:
            security_event(event_name, "warning", u["tenant_id"], u["id"], detail, request)

    public = assessment.as_public()
    if assessment.secret_detected and d.facts:
        public["facts_redacted"] = True
    return public


@app.post("/core/intelligence/decide")
def constitutional_orchestrator_decide(d: OrchestratorDecideIn, request: Request, u=Depends(current_user)):
    require(u, "write")
    ip, _ = request_fingerprint(request)
    rate_limit("orchestrator-decide:" + u["tenant_id"] + ":" + str(ip), 60, 3600)
    audit(u, "constitutional_decision_started", d.action)
    try:
        decision = constitutional_decide(
            tenant_id=u["tenant_id"],
            user_id=u["id"],
            role=u["role"],
            module=d.module or "constitutional-core",
            action=d.action,
            facts=d.facts,
            jurisdiction_raw=d.jurisdiction,
            matter_type=d.matter_type,
            financial_domain=d.financial_domain,
            amount=d.amount,
            currency=d.currency,
            customer_id=d.customer_id,
            invoice_id=d.invoice_id,
            invoice_number=d.invoice_number,
            payment_reference=d.payment_reference,
            original_transaction_amount=d.original_transaction_amount,
            beneficiary_evidence_present=d.beneficiary_evidence_present,
            document_id=d.document_id,
            document_hash=d.document_hash,
            resource_type=d.resource_type,
            resource_id=d.resource_id,
            resource_hash=d.resource_hash,
            consequential_action=d.consequential_action,
            requested_outcome=d.requested_outcome,
            data_classes=d.data_classes,
            payload_tenant_id=d.tenant_id,
            approval_present=d.approval_present,
            approval_count=d.approval_count,
            approvals=d.approvals or None,
            human_legal_review_present=d.human_legal_review_present,
            human_financial_review_present=d.human_financial_review_present,
            aml_kyc_system_state=d.aml_kyc_system_state,
            sanctions_system_state=d.sanctions_system_state,
            promotion_approval_present=d.promotion_approval_present,
            regulated_authorisation_system_state=d.regulated_authorisation_system_state,
            identity_state=d.identity_state,
            session_state=d.session_state,
            mfa_verified=d.mfa_verified,
            user_status=u.get("status"),
            incident_state=d.incident_state,
            supplier_ict_state=d.supplier_ict_state,
            provider_health=d.provider_health,
            provider_trust_state=d.provider_trust_state,
            retention_state=d.retention_state,
            legal_hold_state=d.legal_hold_state,
            intent=d.intent,
        )
    except PermissionError as exc:
        audit(u, "constitutional_decision_blocked", "tenant-payload-rejected", "warning")
        security_event("constitutional_tenant_violation", "warning", u["tenant_id"], u["id"], "payload tenant rejected", request)
        raise HTTPException(403, str(exc))

    event = "constitutional_control_passed" if decision.execution_allowed else "constitutional_control_blocked"
    audit(u, event, decision.orchestrator_decision_id)
    audit(u, "constitutional_decision_completed", f"{decision.outcome}:{decision.orchestrator_decision_id}")
    if "legal" in decision.blocking_layers:
        audit(u, "constitutional_legal_gate_blocked", decision.legal_assessment_id or "")
    if "financial" in decision.blocking_layers:
        audit(u, "constitutional_financial_gate_blocked", decision.financial_assessment_id or "")
    if "guardian" in decision.blocking_layers:
        audit(u, "constitutional_guardian_gate_blocked", decision.guardian_assessment_id or "")
    return decision.as_public()


@app.post("/intelligence/run")
def intelligence_run(d: IntelligenceRunIn, request: Request, u=Depends(current_user)):
    require(u, "write")
    ip, _ = request_fingerprint(request)
    rate_limit("intelligence:" + u["tenant_id"] + ":" + str(ip), 60, 3600)
    try:
        prompt = guardian_check(d.prompt)
        ctx = WorkspaceContext(
            tenant_id=u["tenant_id"],
            user_id=u["id"],
            role=u["role"],
            module=d.module,
            instructions=("Operate only inside this authenticated Zorvian workspace and module.",),
        )
        result = _service().run(ConnectedRequest(
            module=d.module,
            task=d.task,
            prompt=prompt,
            needs_retrieval=d.needs_retrieval,
            needs_tools=d.needs_tools,
            consequential_action=d.consequential_action,
        ), ctx)
    except PermissionError as e:
        audit(u, "guardian_intelligence_block", str(e), "warning")
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(422, str(e))
    except LookupError as e:
        audit(u, "intelligence_provider_unavailable", str(e), "warning")
        raise HTTPException(503, {"error":"ai_provider_unavailable","message":"Celestial Core intelligence is temporarily unavailable. Please try again shortly."})
    except RuntimeError as e:
        audit(u, "intelligence_execution_failed", str(e), "warning")
        raise HTTPException(502, {"error":"ai_provider_failed","message":"Celestial Core could not complete this intelligence request. Please try again shortly."})

    if result.failover_from:
        audit(u, "ai_provider_failover", f"{result.failover_from} -> {result.provider}")
    audit(u, "intelligence_run", f"{d.module} · {d.task} · provider={result.provider}")
    return {
        "module": result.module,
        "capability": result.capability,
        "output": result.output,
        "confidence": result.confidence,
        "provider": result.provider,
        "failover_from": result.failover_from,
        "human_approval_required": result.human_approval_required,
        "tool_execution_allowed": result.tool_execution_allowed,
        "provenance": {
            "task_id": result.provenance.task_id,
            "source_refs": list(result.provenance.source_refs),
            "assumptions": list(result.provenance.assumptions),
            "needs_review": result.provenance.needs_review,
        },
    }


if os.path.isdir("beta"):
    app.mount("/beta", StaticFiles(directory="beta", html=True), name="beta")
