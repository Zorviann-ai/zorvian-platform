import pytest

from intelligence.orchestrator import decide


def base(**kwargs):
    payload = dict(
        tenant_id="tenant-a",
        user_id="user-a",
        role="owner",
        module="constitutional-core",
        action="read_tenant_profile",
        facts="Read own tenant profile",
        jurisdiction_raw="United Kingdom",
        consequential_action=False,
        identity_state="authenticated",
        session_state="normal",
        user_status="active",
    )
    payload.update(kwargs)
    return decide(**payload)


def test_low_risk_read_allows():
    result = base()
    assert result.outcome == "ALLOW"
    assert result.execution_allowed is True
    assert result.legal_execution_allowed is True
    assert result.financial_execution_allowed is True
    assert result.guardian_execution_allowed is True
    assert result.blocking_layers == []
    assert len(result.evidence_chain) == 4


def test_payload_tenant_override_rejected():
    with pytest.raises(PermissionError):
        base(payload_tenant_id="other-tenant")


def test_legal_block_cannot_be_overridden():
    result = base(
        action="release_letter",
        facts="Send formal court injunction and settlement admission of liability.",
        consequential_action=True,
        approval_present=True,
        human_legal_review_present=False,
        jurisdiction_raw="England and Wales",
    )
    assert result.legal_execution_allowed is False
    assert result.execution_allowed is False
    assert result.outcome in {"BLOCK", "REVIEW_REQUIRED"}
    assert "legal" in result.blocking_layers


def test_financial_block_cannot_be_overridden():
    result = base(
        action="approve_supplier_payment",
        facts="Pay supplier £25000 with sanctions match confirmed",
        financial_domain="payment",
        amount=25000,
        currency="GBP",
        consequential_action=True,
        approval_present=True,
        approval_count=2,
        sanctions_system_state="confirmed_match",
        beneficiary_evidence_present=True,
        human_financial_review_present=True,
        human_legal_review_present=True,
    )
    assert result.financial_execution_allowed is False
    assert result.execution_allowed is False
    assert result.outcome != "ALLOW"
    assert "financial" in result.blocking_layers


def test_guardian_block_cannot_be_overridden():
    result = base(
        action="delete_document",
        facts="Delete customer record",
        requested_outcome="delete",
        consequential_action=True,
        legal_hold_state="active",
        approval_present=True,
        approvals=[{"approver_id": "b", "tenant_id": "tenant-a"}],
        human_legal_review_present=True,
        human_financial_review_present=True,
    )
    assert result.guardian_execution_allowed is False
    assert result.execution_allowed is False
    assert result.outcome == "BLOCK"
    assert "guardian" in result.blocking_layers


def test_unauthenticated_blocks():
    result = base(identity_state="unauthenticated", user_id="")
    assert result.guardian_execution_allowed is False
    assert result.execution_allowed is False
    assert result.outcome == "BLOCK"


def test_dual_control_incomplete_not_allow():
    result = base(
        action="approve_supplier_payment",
        facts="Pay supplier £25000 GBP",
        financial_domain="payment",
        amount=25000,
        currency="GBP",
        consequential_action=True,
        approval_present=True,
        approval_count=1,
        beneficiary_evidence_present=True,
        human_financial_review_present=True,
        human_legal_review_present=True,
        jurisdiction_raw="United Kingdom",
    )
    assert result.execution_allowed is False
    assert result.outcome != "ALLOW"


def test_critical_incident_blocks():
    result = base(
        action="approve_payment",
        facts="Pay invoice £100",
        consequential_action=True,
        incident_state="critical",
        approval_present=True,
        approvals=[{"approver_id": "b", "tenant_id": "tenant-a"}],
        human_legal_review_present=True,
        human_financial_review_present=True,
    )
    assert result.guardian_execution_allowed is False
    assert result.execution_allowed is False
    assert result.outcome == "BLOCK"


def test_strictest_gate_any_block_wins():
    result = base(
        action="legal_release",
        facts="Release legal correspondence under hold",
        requested_outcome="delete",
        consequential_action=True,
        legal_hold_state="active",
        approval_present=True,
        human_legal_review_present=True,
        human_financial_review_present=True,
    )
    assert result.execution_allowed is False
    assert result.outcome != "ALLOW"


def test_ai_cannot_grant_via_orchestrator_fields():
    result = base(role="viewer", action="approve_payment", facts="Approve payment", consequential_action=True)
    assert result.execution_allowed is False
    assert result.guardian_execution_allowed is False or result.legal_execution_allowed is False
