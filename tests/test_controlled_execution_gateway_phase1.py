import sqlite3

import pytest

from intelligence.execution import consume_execution_ticket, ensure_execution_schema, prepare


def conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    ensure_execution_schema(c)
    return c


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
        connection=conn(),
    )
    payload.update(kwargs)
    return prepare(**payload)


def test_allow_may_authorise_low_risk():
    ticket = base()
    assert ticket.execution_state == "AUTHORISED"
    assert ticket.constitutional_outcome == "ALLOW"
    assert ticket.external_execution_enabled is False
    assert ticket.legal_assessment_id
    assert ticket.financial_assessment_id
    assert ticket.guardian_assessment_id
    assert ticket.orchestrator_decision_id
    assert any(step["layer"] == "execution_gateway" for step in ticket.evidence_chain)


def test_payload_tenant_rejected():
    with pytest.raises(PermissionError):
        base(payload_tenant_id="other")


def test_block_maps_to_denied():
    ticket = base(
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
    assert ticket.constitutional_outcome == "BLOCK" or ticket.execution_state == "DENIED"
    assert ticket.execution_state == "DENIED"


def test_review_maps_to_pending_or_denied_not_authorised():
    ticket = base(
        action="approve_supplier_payment",
        facts="Pay supplier £25000",
        financial_domain="payment",
        amount=25000,
        currency="GBP",
        consequential_action=True,
        approval_present=False,
    )
    assert ticket.execution_state in {"PENDING", "DENIED"}
    assert ticket.execution_state != "AUTHORISED"


def test_resource_hash_mismatch_denied():
    ticket = base(
        action="read_tenant_profile",
        resource_hash="aaa",
        current_resource_hash="bbb",
    )
    assert ticket.execution_state == "DENIED"
    assert any("hash" in r.lower() for r in ticket.blocking_reasons)


def test_action_mismatch_denied():
    ticket = base(action="create_invoice", proposed_action="send_payment")
    assert ticket.execution_state == "DENIED"
    assert any("action" in r.lower() for r in ticket.blocking_reasons)


def test_client_cannot_forge_allow():
    ticket = base(
        action="approve_supplier_payment",
        facts="Pay £1 without authority",
        financial_domain="payment",
        amount=1,
        consequential_action=True,
        claimed_outcome="ALLOW",
        claimed_state="AUTHORISED",
        claimed_execution_allowed=True,
    )
    assert ticket.execution_state != "AUTHORISED"
    assert ticket.constitutional_outcome != "ALLOW" or ticket.execution_state in {"PENDING", "DENIED"}


def test_client_cannot_extend_expiry():
    ticket = base(claimed_expires_at="2099-01-01T00:00:00Z")
    assert ticket.expires_at.startswith("20")
    assert "2099" not in ticket.expires_at


def test_revoked_approval_not_authorised():
    ticket = base(
        action="release_letter",
        facts="Release approved letter",
        consequential_action=True,
        approval_present=True,
        approvals=[{"approver_id": "b", "tenant_id": "tenant-a", "revoked": True}],
        human_legal_review_present=True,
        human_financial_review_present=True,
    )
    assert ticket.execution_state in {"DENIED", "PENDING"}


def test_wrong_tenant_approval_denied():
    ticket = base(
        action="release_letter",
        facts="Release letter",
        consequential_action=True,
        approvals=[{"approver_id": "b", "tenant_id": "tenant-b"}],
        human_legal_review_present=True,
        human_financial_review_present=True,
    )
    assert ticket.execution_state == "DENIED"


def test_approval_hash_mismatch():
    ticket = base(
        action="release_letter",
        facts="Release letter",
        consequential_action=True,
        resource_hash="aaa",
        current_resource_hash="aaa",
        approvals=[{"approver_id": "b", "tenant_id": "tenant-a", "resource_hash": "zzz"}],
        human_legal_review_present=True,
        human_financial_review_present=True,
    )
    assert ticket.execution_state == "DENIED"


def test_critical_incident_denied():
    ticket = base(incident_state="critical", consequential_action=True, action="approve_payment")
    assert ticket.execution_state == "DENIED"


def test_consume_replay_blocked():
    c = conn()
    ticket = base(connection=c, action="read_tenant_profile")
    assert ticket.execution_state == "AUTHORISED"
    first = consume_execution_ticket(
        connection=c,
        ticket_id=ticket.execution_ticket_id,
        tenant_id="tenant-a",
        user_id="user-a",
        exact_action="read_tenant_profile",
        resource_id=None,
        resource_hash=None,
    )
    assert first.execution_state == "CONSUMED"
    second = consume_execution_ticket(
        connection=c,
        ticket_id=ticket.execution_ticket_id,
        tenant_id="tenant-a",
        user_id="user-a",
        exact_action="read_tenant_profile",
        resource_id=None,
        resource_hash=None,
    )
    assert second.execution_state == "CONSUMED"
    assert "execution_replay_blocked" in second.audit_events


def test_consume_action_mismatch():
    c = conn()
    ticket = base(connection=c)
    out = consume_execution_ticket(
        connection=c,
        ticket_id=ticket.execution_ticket_id,
        tenant_id="tenant-a",
        user_id="user-a",
        exact_action="send_payment",
        resource_id=None,
        resource_hash=None,
    )
    assert out.execution_state == "DENIED"


def test_consume_wrong_user():
    c = conn()
    ticket = base(connection=c)
    with pytest.raises(PermissionError):
        consume_execution_ticket(
            connection=c,
            ticket_id=ticket.execution_ticket_id,
            tenant_id="tenant-a",
            user_id="other-user",
            exact_action="read_tenant_profile",
            resource_id=None,
            resource_hash=None,
        )


def test_consume_wrong_tenant():
    c = conn()
    ticket = base(connection=c)
    with pytest.raises(PermissionError):
        consume_execution_ticket(
            connection=c,
            ticket_id=ticket.execution_ticket_id,
            tenant_id="other-tenant",
            user_id="user-a",
            exact_action="read_tenant_profile",
            resource_id=None,
            resource_hash=None,
        )


def test_idempotency_reuses_ticket():
    c = conn()
    first = base(connection=c, idempotency_key="k-1")
    second = base(connection=c, idempotency_key="k-1")
    assert first.execution_ticket_id == second.execution_ticket_id


def test_revoked_session_blocks_consume():
    c = conn()
    ticket = base(connection=c)
    out = consume_execution_ticket(
        connection=c,
        ticket_id=ticket.execution_ticket_id,
        tenant_id="tenant-a",
        user_id="user-a",
        exact_action="read_tenant_profile",
        resource_id=None,
        resource_hash=None,
        session_state="revoked",
    )
    assert out.execution_state == "DENIED"


def test_suspended_user_blocks_consume():
    c = conn()
    ticket = base(connection=c)
    out = consume_execution_ticket(
        connection=c,
        ticket_id=ticket.execution_ticket_id,
        tenant_id="tenant-a",
        user_id="user-a",
        exact_action="read_tenant_profile",
        resource_id=None,
        resource_hash=None,
        user_status="suspended",
    )
    assert out.execution_state == "DENIED"


def test_legal_financial_guardian_inherited():
    legal_block = base(
        action="release_letter",
        facts="court injunction admission of liability",
        consequential_action=True,
        approval_present=True,
        jurisdiction_raw="England and Wales",
    )
    assert legal_block.execution_state != "AUTHORISED"
    fin = base(
        action="approve_supplier_payment",
        facts="Pay £25000 sanctions confirmed match",
        financial_domain="payment",
        amount=25000,
        currency="GBP",
        consequential_action=True,
        sanctions_system_state="confirmed_match",
        approval_count=2,
        approval_present=True,
        beneficiary_evidence_present=True,
        human_financial_review_present=True,
        human_legal_review_present=True,
    )
    assert fin.execution_state == "DENIED"
