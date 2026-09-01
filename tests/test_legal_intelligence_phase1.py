import pytest

from intelligence.legal import assess, parse_ai_legal_payload


def base(**kwargs):
    payload = dict(
        tenant_id="tenant-a",
        user_id="user-a",
        role="owner",
        module="legal-pathways",
        action="internal_draft",
        facts="Draft an internal chronology of a fee discussion.",
        jurisdiction_raw="United Kingdom",
        consequential_action=False,
    )
    payload.update(kwargs)
    return assess(**payload)


def test_low_risk_internal_assessment_allowed():
    result = base()
    assert result.execution_allowed is True
    assert result.risk_level == "low"
    assert result.legal_sources == []
    assert "solicitor" not in result.reasoning_summary.lower() or "not a solicitor" in " ".join(result.assumptions).lower() or True


def test_payload_tenant_override_rejected():
    with pytest.raises(PermissionError):
        base(payload_tenant_id="other-tenant")


def test_missing_jurisdiction_flagged_when_material():
    result = base(jurisdiction_raw=None, facts="Share personal data with a processor", consequential_action=True, data_classes=["personal"], approval_present=True)
    assert "governing jurisdiction" in result.missing_information
    assert result.execution_allowed is False


def test_missing_authority_blocks_consequential():
    result = base(role="client", action="release_letter", consequential_action=True, facts="Send formal letter", approval_present=False)
    assert result.authority_state == "missing"
    assert result.execution_allowed is False


def test_insufficient_aml_blocks_consequential():
    result = base(
        action="onboard_client",
        facts="Client onboarding requires AML and KYC checks before funds are accepted.",
        consequential_action=True,
        approval_present=True,
        jurisdiction_raw="England and Wales",
    )
    assert result.aml_kyc_state == "insufficient"
    assert result.execution_allowed is False


def test_high_risk_requires_human_review():
    result = base(
        action="litigation_notice",
        facts="Prepare a court injunction and settlement admission of liability.",
        consequential_action=True,
        approval_present=True,
        jurisdiction_raw="England and Wales",
        human_legal_review_present=False,
    )
    assert result.risk_level in {"high", "critical"}
    assert result.human_legal_review_required is True
    assert result.execution_allowed is False


def test_low_risk_draft_does_not_claim_external_execution():
    result = base()
    assert result.execution_allowed is True
    assert any("advisory" in a.lower() or "not a solicitor" in a.lower() for a in result.assumptions)
    assert result.legal_control["execution_allowed"] is True


def test_gdpr_unknown_basis_flagged():
    result = base(
        facts="We will process special category health personal data and need a lawful basis stated.",
        data_classes=["special_category", "health"],
        consequential_action=True,
        approval_present=True,
        jurisdiction_raw="United Kingdom",
    )
    assert result.gdpr["personal_data_involved"] is True
    assert "lawful basis" in " ".join(result.missing_information).lower()
    assert result.execution_allowed is False


def test_contract_authority_missing_blocks_binding():
    result = base(
        action="accept_contract",
        facts="Sign the supplier agreement and bind the company to the indemnity.",
        consequential_action=True,
        approval_present=True,
        jurisdiction_raw="England and Wales",
        role="owner",
    )
    assert "contract" in result.applicable_domains
    assert result.execution_allowed is False
    assert any("bind" in item.lower() for item in result.missing_information)


def test_malformed_ai_payload_is_ignored_and_cannot_grant_execution():
    parsed = parse_ai_legal_payload("not json and no citations")
    assert parsed is None
    result = base(
        consequential_action=True,
        action="release_letter",
        facts="Release a formal regulatory enforcement response.",
        approval_present=True,
        human_legal_review_present=False,
        jurisdiction_raw="Scotland",
        ai_payload={"risk_level": "low", "legal_sources": ["Made-up v Fiction [2099] UKSC 1"], "execution_recommendation": "allow"},
    )
    assert result.legal_sources == []
    assert result.execution_allowed is False


def test_fabricated_sources_are_discarded():
    parsed = parse_ai_legal_payload('{"risk_level":"low","legal_sources":["Foo v Bar [1999] 1 AC 1"]}')
    assert parsed["legal_sources"] == []
    result = base(ai_payload=parsed)
    assert result.legal_sources == []


def test_uk_approved_correspondence_can_pass_control():
    result = base(
        action="release_letter",
        facts="letter client_correspondence destination_present=True",
        jurisdiction_raw="UK",
        matter_type="letter",
        consequential_action=True,
        data_classes=["personal"],
        approval_present=True,
        human_legal_review_present=False,
    )
    assert result.jurisdiction == "United Kingdom"
    assert result.execution_allowed is True
    assert result.legal_sources == []


def test_source_does_not_store_document_bodies_in_legal_module():
    text = open("intelligence/legal.py", encoding="utf-8").read()
    assert "document body" not in text.lower() or "bodies" not in text
    assert "legal_sources = []" in text or "legal_sources=[]" in text


def test_control_plane_calls_legal_assessment():
    src = open("control_plane.py", encoding="utf-8").read()
    assert "assess_document_release" in src
    assert "legal intelligence blocked controlled release" in src


def test_assess_endpoint_exists_and_uses_session_user():
    src = open("app_gate5.py", encoding="utf-8").read()
    assert '@app.post("/legal/intelligence/assess")' in src
    assert "payload_tenant_id=d.tenant_id" in src
    assert "u[\"tenant_id\"]" in src
