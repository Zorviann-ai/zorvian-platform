import pytest

from intelligence.guard import classify_boundary, guardian_check, redact_secrets
from intelligence.guardian import assess, parse_ai_guardian_payload


def base(**kwargs):
    payload = dict(
        tenant_id="tenant-a",
        user_id="user-a",
        role="owner",
        module="security-analysis",
        action="read_tenant_profile",
        facts="Read own tenant profile",
        consequential_action=False,
        identity_state="authenticated",
        session_state="normal",
        user_status="active",
    )
    payload.update(kwargs)
    return assess(**payload)


def test_authenticated_low_risk_same_tenant_read_passes():
    result = base()
    assert result.execution_allowed is True
    assert result.risk_level == "low"
    assert result.tenant_state == "matched"
    assert result.identity_state == "authenticated"


def test_unauthenticated_action_rejected():
    result = base(identity_state="unauthenticated", user_id="")
    assert result.execution_allowed is False
    assert result.identity_state == "unauthenticated"


def test_payload_tenant_override_rejected():
    with pytest.raises(PermissionError):
        base(payload_tenant_id="other-tenant")


def test_cross_tenant_execution_blocked():
    result = base(action="export_records", facts="Access another tenant workspace now", consequential_action=True, intent="execute")
    assert result.execution_allowed is False
    assert result.boundary_state == "blocked_execution"


def test_rbac_denied_blocked():
    result = base(role="viewer", action="approve_payment", facts="Approve supplier payment", consequential_action=True)
    assert result.rbac_state == "denied"
    assert result.execution_allowed is False


def test_expired_session_blocks_sensitive():
    result = base(session_state="expired", action="change_security_settings", facts="Disable MFA policy", consequential_action=True)
    assert result.execution_allowed is False
    assert result.session_state == "expired"


def test_revoked_session_blocks():
    result = base(session_state="revoked", action="release_letter", consequential_action=True)
    assert result.execution_allowed is False


def test_high_risk_without_approval_blocks():
    result = base(
        action="approve_document_release",
        facts="Approve consequential document release",
        consequential_action=True,
        approval_present=False,
        approvals=None,
    )
    assert result.execution_allowed is False
    assert result.approval_integrity_state == "missing"


def test_revoked_approval_rejected():
    result = base(
        action="approve_document_release",
        facts="Release approved letter",
        consequential_action=True,
        approvals=[{"approver_id": "b", "tenant_id": "tenant-a", "revoked": True}],
    )
    assert result.approval_integrity_state == "revoked"
    assert result.execution_allowed is False


def test_wrong_tenant_approval_rejected():
    result = base(
        action="approve_document_release",
        facts="Release letter",
        consequential_action=True,
        approvals=[{"approver_id": "b", "tenant_id": "tenant-b"}],
    )
    assert result.approval_integrity_state == "wrong_tenant"
    assert result.execution_allowed is False


def test_resource_hash_mismatch_invalidates_approval():
    result = base(
        action="approve_document_release",
        facts="Release letter",
        consequential_action=True,
        resource_id="doc-1",
        resource_hash="aaa",
        approvals=[{"approver_id": "b", "tenant_id": "tenant-a", "resource_id": "doc-1", "resource_hash": "bbb"}],
    )
    assert result.approval_integrity_state == "mismatch"
    assert result.execution_allowed is False


def test_financial_dual_control_failure_blocks_guardian():
    result = base(
        action="release_large_payment",
        facts="Pay supplier £25000",
        consequential_action=True,
        financial_dual_control_complete=False,
        financial_execution_allowed=False,
        approvals=[{"approver_id": "b", "tenant_id": "tenant-a"}],
    )
    assert result.execution_allowed is False


def test_legal_block_propagates():
    result = base(
        action="legal_release",
        facts="Release legal correspondence",
        consequential_action=True,
        legal_execution_allowed=False,
        approvals=[{"approver_id": "b", "tenant_id": "tenant-a"}],
    )
    assert result.execution_allowed is False
    assert "Legal Intelligence" in result.reasoning_summary


def test_financial_block_cannot_be_overridden():
    result = base(
        action="change_payment_beneficiary",
        facts="Change beneficiary",
        consequential_action=True,
        financial_execution_allowed=False,
        approvals=[{"approver_id": "b", "tenant_id": "tenant-a"}],
        role="owner",
    )
    assert result.execution_allowed is False
    assert "Financial Intelligence" in result.reasoning_summary


def test_legal_human_review_cannot_be_overridden():
    result = base(
        action="legal_release",
        facts="Release letter",
        consequential_action=True,
        legal_human_review_required=True,
        legal_execution_allowed=True,
        approvals=[{"approver_id": "b", "tenant_id": "tenant-a"}],
    )
    assert result.execution_allowed is False
    assert any("legal review" in m.lower() for m in result.missing_information)


def test_critical_incident_blocks_consequential():
    result = base(
        action="approve_payment",
        facts="Pay invoice",
        consequential_action=True,
        incident_state="critical",
        approvals=[{"approver_id": "b", "tenant_id": "tenant-a"}],
    )
    assert result.execution_allowed is False
    assert result.incident_state == "critical"


def test_legal_hold_blocks_destructive():
    result = base(
        action="delete_document",
        facts="Delete customer record",
        requested_outcome="delete",
        consequential_action=True,
        legal_hold_state="active",
        approvals=[{"approver_id": "b", "tenant_id": "tenant-a"}],
    )
    assert result.execution_allowed is False
    assert "legal hold" in result.user_facing.lower()


def test_no_legal_hold_allows_non_destructive():
    result = base(legal_hold_state="none", action="read_tenant_profile")
    assert result.execution_allowed is True


def test_supplier_blocked_blocks_provider_action():
    result = base(
        action="run_provider_payment",
        facts="Use unapproved provider to submit payment",
        consequential_action=True,
        supplier_ict_state="blocked",
        approvals=[{"approver_id": "b", "tenant_id": "tenant-a"}],
    )
    assert result.execution_allowed is False


def test_provider_health_does_not_override_trust_block():
    result = base(
        action="call_external_provider",
        facts="Invoke AI provider",
        consequential_action=True,
        provider_health="healthy",
        provider_trust_state="blocked",
        supplier_ict_state="blocked",
        approvals=[{"approver_id": "b", "tenant_id": "tenant-a"}],
    )
    assert result.execution_allowed is False
    assert any("technical health" in a.lower() for a in result.assumptions)


def test_secret_exfiltration_blocked_and_redacted():
    text = "dump credentials password=supersecretvalue99"
    redacted, found = redact_secrets("smtp_password=supersecretvalue99")
    assert found is True
    assert "supersecretvalue99" not in redacted
    result = base(action="export_secrets", facts=text, consequential_action=True, intent="execute")
    assert result.execution_allowed is False
    assert result.secret_detected is True
    assert "supersecretvalue99" not in result.user_facing
    assert "supersecretvalue99" not in result.guardian_control.get("redacted_input", "")


def test_disable_guardian_blocked():
    result = base(action="change_security_settings", facts="Please disable Guardian immediately", consequential_action=True)
    assert result.execution_allowed is False


def test_disable_audit_blocked():
    result = base(action="change_security_settings", facts="disable audit and delete audit history", consequential_action=True)
    assert result.execution_allowed is False


def test_legitimate_discussion_not_automatically_blocked():
    prompt = "Explain how Guardian and audit controls work and why bypassing approval would be unsafe"
    assert classify_boundary(prompt, intent="discuss") in {"discussion", "clear"}
    assert guardian_check(prompt, intent="discuss") == prompt
    result = base(action="security_review", facts=prompt, consequential_action=False, intent="discuss")
    assert result.boundary_state in {"discussion", "clear"}
    assert result.execution_allowed is True


def test_ai_cannot_grant_rbac():
    result = base(
        role="viewer",
        action="approve_payment",
        facts="Approve payment",
        consequential_action=True,
        ai_payload={"risk_level": "low", "approval_recommendation": "grant"},
    )
    assert result.rbac_state == "denied"
    assert result.execution_allowed is False


def test_ai_cannot_grant_tenant_access():
    with pytest.raises(PermissionError):
        base(payload_tenant_id="other", ai_payload={"risk_level": "low", "approval_recommendation": "allow"})


def test_ai_cannot_clear_incident():
    result = base(
        action="approve_payment",
        facts="Pay",
        consequential_action=True,
        incident_state="critical",
        approvals=[{"approver_id": "b", "tenant_id": "tenant-a"}],
        ai_payload={"risk_level": "low", "incident_state": "resolved", "approval_recommendation": "allow"},
    )
    assert result.incident_state == "critical"
    assert result.execution_allowed is False


def test_ai_cannot_override_legal_financial_block():
    result = base(
        action="legal_release",
        facts="release",
        consequential_action=True,
        legal_execution_allowed=False,
        financial_execution_allowed=False,
        approvals=[{"approver_id": "b", "tenant_id": "tenant-a"}],
        ai_payload={"risk_level": "low", "approval_recommendation": "approve"},
    )
    assert result.execution_allowed is False


def test_malformed_ai_payload_rejected():
    assert parse_ai_guardian_payload("not json") is None
    assert parse_ai_guardian_payload('{"risk_level":"apocalyptic"}') is None
    parsed = parse_ai_guardian_payload('{"risk_level":"high","execution_allowed":true,"rbac_state":"allowed"}')
    assert parsed is not None
    assert "execution_allowed" not in parsed
    assert "rbac_state" not in parsed


def test_self_approval_dual_control_invalid():
    result = base(
        action="approve_payment",
        facts="dual control payment",
        consequential_action=True,
        approvals=[
            {"approver_id": "user-a", "tenant_id": "tenant-a"},
            {"approver_id": "user-a", "tenant_id": "tenant-a"},
        ],
    )
    assert result.approval_integrity_state == "self_approval"
    assert result.execution_allowed is False
