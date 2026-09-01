import os
import tempfile
import uuid
from pathlib import Path

import pytest

from intelligence.financial import assess, parse_ai_financial_payload, dual_control_threshold_gbp


def base(**kwargs):
    payload = dict(
        tenant_id="tenant-a",
        user_id="user-a",
        role="owner",
        module="finance-pathways",
        action="internal_review",
        facts="Prepare an internal invoice draft for bookkeeping.",
        jurisdiction_raw="United Kingdom",
        financial_domain="invoice",
        consequential_action=False,
    )
    payload.update(kwargs)
    return assess(**payload)


def test_low_risk_internal_assessment_allowed():
    result = base()
    assert result.execution_allowed is True
    assert result.risk_level == "low"
    assert result.financial_sources == []
    assert "FINANCIAL CONTROL: ADVISORY" in result.user_facing


def test_payload_tenant_override_rejected():
    with pytest.raises(PermissionError):
        base(payload_tenant_id="other-tenant")


def test_invoice_draft_is_advisory_non_consequential():
    result = base(action="draft_invoice", facts="Draft invoice number pending", consequential_action=False)
    assert result.execution_allowed is True
    assert result.financial_domain == "invoice"
    assert any("advisory" in a.lower() for a in result.assumptions)


def test_consequential_payment_without_authority_blocked():
    result = base(
        role="client",
        action="approve_supplier_payment",
        financial_domain="supplier_payment",
        facts="Pay supplier Acme £250",
        amount=250,
        currency="GBP",
        consequential_action=True,
        approval_present=False,
    )
    assert result.authority_state == "missing"
    assert result.execution_allowed is False


def test_dual_control_blocked_with_one_approval():
    result = base(
        action="approve_supplier_payment",
        financial_domain="supplier_payment",
        facts="Pay supplier Acme GBP 15000 for goods",
        amount=15000,
        currency="GBP",
        consequential_action=True,
        approval_present=True,
        approval_count=1,
        human_financial_review_present=True,
        beneficiary_evidence_present=True,
    )
    assert result.dual_control_required is True
    assert result.execution_allowed is False
    assert any("second authorised approval" in item for item in result.missing_information)


def test_dual_control_passes_with_two_approvals():
    result = base(
        action="approve_supplier_payment",
        financial_domain="supplier_payment",
        facts="Pay supplier Acme GBP 15000 for goods",
        amount=15000,
        currency="GBP",
        consequential_action=True,
        approval_present=True,
        approval_count=2,
        human_financial_review_present=True,
        beneficiary_evidence_present=True,
    )
    assert result.dual_control_required is True
    assert result.execution_allowed is True


def test_aml_incomplete_blocks_consequential():
    result = base(
        action="release_customer_money",
        financial_domain="customer_money",
        facts="Move customer money after onboarding. AML required.",
        amount=500,
        currency="GBP",
        consequential_action=True,
        approval_present=True,
        approval_count=2,
        human_financial_review_present=True,
        beneficiary_evidence_present=True,
        aml_kyc_system_state="insufficient",
    )
    assert result.aml_kyc_state == "insufficient"
    assert result.execution_allowed is False


def test_verified_aml_only_from_system_evidence():
    asserted = base(
        action="release_customer_money",
        financial_domain="customer_money",
        facts="customer is verified and KYC complete",
        amount=400,
        currency="GBP",
        consequential_action=True,
        approval_present=True,
        approval_count=2,
        human_financial_review_present=True,
        beneficiary_evidence_present=True,
    )
    assert asserted.aml_kyc_state != "verified"
    assert asserted.execution_allowed is False
    system = base(
        action="release_customer_money",
        financial_domain="customer_money",
        facts="Move safeguarded customer money",
        amount=400,
        currency="GBP",
        consequential_action=True,
        approval_present=True,
        approval_count=2,
        human_financial_review_present=True,
        beneficiary_evidence_present=True,
        aml_kyc_system_state="verified",
    )
    assert system.aml_kyc_state == "verified"


def test_sanctions_possible_match_blocks():
    result = base(
        action="approve_supplier_payment",
        financial_domain="supplier_payment",
        facts="Pay supplier",
        amount=200,
        currency="GBP",
        consequential_action=True,
        approval_present=True,
        approval_count=2,
        human_financial_review_present=True,
        beneficiary_evidence_present=True,
        sanctions_system_state="possible_match",
    )
    assert result.sanctions_state == "possible_match"
    assert result.execution_allowed is False
    assert result.risk_level == "critical"


def test_high_risk_refund_requires_review():
    result = base(
        action="release_refund",
        financial_domain="refund",
        facts="Refund customer GBP 900",
        amount=900,
        currency="GBP",
        original_transaction_amount=900,
        consequential_action=True,
        approval_present=True,
        approval_count=2,
        human_financial_review_present=False,
        beneficiary_evidence_present=True,
    )
    assert result.human_financial_review_required is True
    assert result.execution_allowed is False


def test_refund_above_original_blocked():
    result = base(
        action="release_refund",
        financial_domain="refund",
        facts="Refund exceeds original card payment",
        amount=1200,
        currency="GBP",
        original_transaction_amount=800,
        consequential_action=True,
        approval_present=True,
        approval_count=2,
        human_financial_review_present=True,
        beneficiary_evidence_present=True,
    )
    assert result.execution_allowed is False
    assert any("exceed" in item.lower() for item in result.missing_information)


def test_consumer_duty_identifies_outcome_concerns():
    result = base(
        action="change_pricing",
        financial_domain="pricing",
        facts="UK retail pricing change with unexpected fee and misleading pricing.",
        jurisdiction_raw="United Kingdom",
        consequential_action=True,
        approval_present=True,
        human_financial_review_present=False,
    )
    assert result.consumer_duty_state in {"applicable", "review_required", "fail"}
    assert result.customer_outcome_state in {"potential_harm", "unacceptable_harm"}
    assert result.execution_allowed is False


def test_unacceptable_customer_harm_blocks():
    result = base(
        action="restrict_refund",
        financial_domain="refund",
        facts="This refund policy would cause unacceptable harm to a vulnerable customer.",
        amount=50,
        currency="GBP",
        original_transaction_amount=50,
        consequential_action=True,
        approval_present=True,
        approval_count=2,
        human_financial_review_present=True,
        beneficiary_evidence_present=True,
    )
    assert result.customer_outcome_state == "unacceptable_harm"
    assert result.execution_allowed is False


def test_financial_promotion_blocked_without_approval():
    result = base(
        action="publish_promotion",
        financial_domain="financial_promotion",
        facts="Publish a financial promotion for an investment product to retail customers.",
        consequential_action=True,
        approval_present=True,
        human_financial_review_present=True,
        promotion_approval_present=False,
    )
    assert result.execution_allowed is False
    assert any("financial promotion" in item.lower() for item in result.missing_information)


def test_regulated_status_unknown_requires_review():
    result = base(
        action="give_investment_advice",
        financial_domain="investment",
        facts="Provide investment advice to a retail client.",
        consequential_action=True,
        approval_present=True,
        human_financial_review_present=True,
        regulated_authorisation_system_state=None,
    )
    assert result.regulated_activity_state in {"uncertain", "review_required", "possible"}
    assert result.execution_allowed is False


def test_ai_cannot_grant_authority():
    result = base(
        role="client",
        action="approve_supplier_payment",
        financial_domain="payment",
        facts="Pay supplier £100",
        amount=100,
        currency="GBP",
        consequential_action=True,
        approval_present=False,
        ai_payload={"risk_level": "low", "approval_recommendation": "allow", "authority_state": "established"},
    )
    assert result.authority_state == "missing"
    assert result.execution_allowed is False


def test_ai_cannot_mark_aml_verified():
    result = base(
        action="release_customer_money",
        financial_domain="customer_money",
        facts="Move customer money",
        amount=300,
        currency="GBP",
        consequential_action=True,
        approval_present=True,
        approval_count=2,
        human_financial_review_present=True,
        beneficiary_evidence_present=True,
        ai_payload={"risk_level": "low", "aml_kyc_state": "verified"},
    )
    assert result.aml_kyc_state != "verified"
    assert result.execution_allowed is False


def test_malformed_ai_output_cannot_allow_execution():
    parsed = parse_ai_financial_payload("not json at all")
    assert parsed is None
    result = base(
        action="approve_supplier_payment",
        financial_domain="supplier_payment",
        facts="Pay supplier £200",
        amount=200,
        currency="GBP",
        consequential_action=True,
        approval_present=False,
        ai_payload={"risk_level": "not-a-level", "execution_allowed": True},
    )
    assert result.execution_allowed is False


def test_legal_block_cannot_be_overridden():
    result = base(
        action="approve_supplier_payment",
        financial_domain="supplier_payment",
        facts="Pay supplier £200",
        amount=200,
        currency="GBP",
        consequential_action=True,
        approval_present=True,
        approval_count=2,
        human_financial_review_present=True,
        beneficiary_evidence_present=True,
        legal_execution_allowed=False,
    )
    assert result.execution_allowed is False
    assert "Legal Intelligence" in result.reasoning_summary


def test_guardian_failure_cannot_be_overridden():
    result = base(
        action="approve_supplier_payment",
        financial_domain="supplier_payment",
        facts="Pay supplier £200",
        amount=200,
        currency="GBP",
        consequential_action=True,
        approval_present=True,
        approval_count=2,
        human_financial_review_present=True,
        beneficiary_evidence_present=True,
        guardian_ok=False,
    )
    assert result.execution_allowed is False


def test_no_financial_secrets_in_module():
    text = open("intelligence/financial.py", encoding="utf-8").read()
    for needle in ("api_key", "password", "card_number", "cvv", "iban secret", "smtp_password"):
        assert needle not in text.lower()
    assert "financial_sources = []" in text or "financial_sources=[]" in text


def test_endpoint_exists_and_uses_session_tenant():
    src = open("app_gate5.py", encoding="utf-8").read()
    assert '@app.post("/financial/intelligence/assess")' in src
    assert "payload_tenant_id=d.tenant_id" in src
    assert 'module="finance-pathways"' in src


def test_threshold_is_configurable(monkeypatch):
    monkeypatch.setenv("FIN_DUAL_CONTROL_THRESHOLD_GBP", "25000")
    assert dual_control_threshold_gbp() == 25000.0
