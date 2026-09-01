import sqlite3

import pytest

from intelligence.execution import ensure_execution_schema, prepare
import os

from intelligence.execution_adapters import (
    AdapterDenied,
    dry_run_execution_plan,
    enable_adapter_policy,
    execute_execution_plan,
    payload_hash,
    destination_hash,
    prepare_execution_plan,
    record_approval_binding,
    validate_destination,
    get_adapter,
)


def conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    ensure_execution_schema(c)
    return c


def ticket(c, **kwargs):
    payload = dict(
        tenant_id="tenant-a",
        user_id="user-a",
        role="owner",
        module="constitutional-core",
        action="internal_record_note",
        facts="Record an internal status note",
        jurisdiction_raw="United Kingdom",
        consequential_action=False,
        identity_state="authenticated",
        session_state="normal",
        user_status="active",
        connection=c,
        approval_present=True,
        approvals=[{"approver_id": "approver-1", "tenant_id": "tenant-a"}],
    )
    payload.update(kwargs)
    return prepare(**payload)


def test_authorised_ticket_creates_plan():
    c = conn()
    enable_adapter_policy(c, tenant_id="tenant-a", adapter_id="internal.record_transition", allowed_actions=["internal_record_note"])
    t = ticket(c)
    assert t.execution_state == "AUTHORISED"
    plan = prepare_execution_plan(c, tenant_id="tenant-a", user_id="user-a", ticket_id=t.execution_ticket_id, adapter_id="internal.record_transition", action="internal_record_note", payload={"note": "ok"})
    assert plan["status"] == "PREPARED"
    assert plan["payload_hash"] == payload_hash({"note": "ok"})
    assert any(ev["event"] == "execution_plan_prepared" for ev in plan["evidence_chain"])


def test_denied_and_pending_cannot_plan():
    c = conn()
    enable_adapter_policy(c, tenant_id="tenant-a", adapter_id="internal.record_transition", allowed_actions=["internal_record_note", "delete_document"])
    denied = ticket(c, action="delete_document", facts="Delete customer record", requested_outcome="delete", consequential_action=True, legal_hold_state="active")
    with pytest.raises(AdapterDenied):
        prepare_execution_plan(c, tenant_id="tenant-a", user_id="user-a", ticket_id=denied.execution_ticket_id, adapter_id="internal.record_transition", action="delete_document", payload={})


def test_wrong_tenant_and_user_blocked():
    c = conn()
    enable_adapter_policy(c, tenant_id="tenant-a", adapter_id="internal.record_transition")
    t = ticket(c)
    with pytest.raises(AdapterDenied):
        prepare_execution_plan(c, tenant_id="tenant-b", user_id="user-a", ticket_id=t.execution_ticket_id, adapter_id="internal.record_transition", action="internal_record_note")
    with pytest.raises(AdapterDenied):
        prepare_execution_plan(c, tenant_id="tenant-a", user_id="user-b", ticket_id=t.execution_ticket_id, adapter_id="internal.record_transition", action="internal_record_note")


def test_resource_and_payload_and_destination_change_blocked():
    c = conn()
    enable_adapter_policy(c, tenant_id="tenant-a", adapter_id="email.send", allowed_actions=["send_email"], allowed_destinations=["ops@caelomere.test"], max_risk_level="critical", requires_human_approval=True)
    t = ticket(c, action="send_email", facts="Email the operations inbox", consequential_action=True, resource_id="res-1", resource_hash="abc", human_legal_review_present=True, human_financial_review_present=True)
    if t.execution_state != "AUTHORISED":
        pytest.skip("email ticket not authorised under current constitutional rules")
    body = {"subject": "Hi", "body": "x"}
    record_approval_binding(
        c, tenant_id="tenant-a", ticket_id=t.execution_ticket_id, action="send_email", adapter_id="email.send",
        payload_hash_value=payload_hash(body), destination_hash_value=destination_hash("ops@caelomere.test"),
        resource_id="res-1", resource_hash="abc",
    )
    plan = prepare_execution_plan(c, tenant_id="tenant-a", user_id="user-a", ticket_id=t.execution_ticket_id, adapter_id="email.send", action="send_email", payload=body, destination="ops@caelomere.test", resource_id="res-1", resource_hash="abc")
    with pytest.raises(AdapterDenied):
        dry_run_execution_plan(c, tenant_id="tenant-a", user_id="user-a", plan_id=plan["execution_plan_id"], payload={"subject": "changed"})
    with pytest.raises(AdapterDenied):
        dry_run_execution_plan(c, tenant_id="tenant-a", user_id="user-a", plan_id=plan["execution_plan_id"], destination="other@caelomere.test")
    with pytest.raises(AdapterDenied):
        prepare_execution_plan(c, tenant_id="tenant-a", user_id="user-a", ticket_id=t.execution_ticket_id, adapter_id="email.send", action="send_email", payload={"subject": "Hi"}, destination="ops@caelomere.test", resource_hash="CHANGED")


def test_unknown_and_disabled_and_tenant_denied_adapters():
    c = conn()
    t = ticket(c)
    with pytest.raises(AdapterDenied):
        prepare_execution_plan(c, tenant_id="tenant-a", user_id="user-a", ticket_id=t.execution_ticket_id, adapter_id="not.an.adapter", action="internal_record_note")
    with pytest.raises(AdapterDenied):
        prepare_execution_plan(c, tenant_id="tenant-a", user_id="user-a", ticket_id=t.execution_ticket_id, adapter_id="internal.record_transition", action="internal_record_note")


def test_external_dry_run_and_execute_blocked():
    c = conn()
    enable_adapter_policy(c, tenant_id="tenant-a", adapter_id="email.send", allowed_actions=["send_email"], allowed_destinations=["ops@caelomere.test"], max_risk_level="critical")
    t = ticket(c, action="send_email", facts="Notify operations by email", consequential_action=True, human_legal_review_present=True, human_financial_review_present=True)
    if t.execution_state != "AUTHORISED":
        pytest.skip("email ticket not authorised")
    body = {"subject": "Ops", "body": "note"}
    record_approval_binding(
        c, tenant_id="tenant-a", ticket_id=t.execution_ticket_id, action="send_email", adapter_id="email.send",
        payload_hash_value=payload_hash(body), destination_hash_value=destination_hash("ops@caelomere.test"),
    )
    plan = prepare_execution_plan(c, tenant_id="tenant-a", user_id="user-a", ticket_id=t.execution_ticket_id, adapter_id="email.send", action="send_email", payload=body, destination="ops@caelomere.test")
    preview = dry_run_execution_plan(c, tenant_id="tenant-a", user_id="user-a", plan_id=plan["execution_plan_id"])
    assert preview["dry_run"]["mode"] == "dry_run"
    assert preview["dry_run"]["execution_allowed"] is False
    assert "sk-" not in str(preview)
    assert "Authorization" not in str(preview)
    with pytest.raises(AdapterDenied, match="External execution disabled"):
        execute_execution_plan(c, tenant_id="tenant-a", user_id="user-a", plan_id=plan["execution_plan_id"])


def test_internal_execute_and_replay_blocked():
    c = conn()
    enable_adapter_policy(c, tenant_id="tenant-a", adapter_id="internal.record_transition", allowed_actions=["internal_record_note"])
    t = ticket(c)
    plan = prepare_execution_plan(c, tenant_id="tenant-a", user_id="user-a", ticket_id=t.execution_ticket_id, adapter_id="internal.record_transition", action="internal_record_note", payload={"note": "done"})
    first = execute_execution_plan(c, tenant_id="tenant-a", user_id="user-a", plan_id=plan["execution_plan_id"])
    assert first["status"] == "EXECUTED"
    assert first.get("internal_effect_id")
    with pytest.raises(AdapterDenied):
        execute_execution_plan(c, tenant_id="tenant-a", user_id="user-a", plan_id=plan["execution_plan_id"])


def test_forged_allow_and_approval_rejected():
    c = conn()
    enable_adapter_policy(c, tenant_id="tenant-a", adapter_id="internal.record_transition")
    t = ticket(c)
    with pytest.raises(AdapterDenied):
        prepare_execution_plan(c, tenant_id="tenant-a", user_id="user-a", ticket_id=t.execution_ticket_id, adapter_id="internal.record_transition", action="internal_record_note", claimed_allow=True)
    enable_adapter_policy(c, tenant_id="tenant-a", adapter_id="email.send", allowed_actions=["send_email"], allowed_destinations=["ops@caelomere.test"], max_risk_level="critical", requires_human_approval=True)
    mail = ticket(c, action="send_email", facts="Email operations", consequential_action=True, human_legal_review_present=True, human_financial_review_present=True)
    if mail.execution_state == "AUTHORISED":
        with pytest.raises(AdapterDenied):
            prepare_execution_plan(c, tenant_id="tenant-a", user_id="user-a", ticket_id=mail.execution_ticket_id, adapter_id="email.send", action="send_email", destination="ops@caelomere.test", payload={}, claimed_approval="forged-approval")


def test_webhook_destination_rules():
    adapter = get_adapter("webhook.post")
    with pytest.raises(AdapterDenied):
        validate_destination(adapter, "http://hooks.example.com/x", ["hooks.example.com"])
    with pytest.raises(AdapterDenied):
        validate_destination(adapter, "https://localhost/hook", ["localhost"])
    with pytest.raises(AdapterDenied):
        validate_destination(adapter, "https://127.0.0.1/hook", ["127.0.0.1"])
    with pytest.raises(AdapterDenied):
        validate_destination(adapter, "https://10.0.0.8/hook", ["10.0.0.8"])
    with pytest.raises(AdapterDenied):
        validate_destination(adapter, "https://evil.example/hook", ["hooks.allowed.test"])
    assert validate_destination(adapter, "https://hooks.allowed.test/hook", ["hooks.allowed.test"]).startswith("https://")


def test_idempotent_plan_prepare():
    c = conn()
    enable_adapter_policy(c, tenant_id="tenant-a", adapter_id="internal.record_transition", allowed_actions=["internal_record_note"])
    t = ticket(c)
    first = prepare_execution_plan(c, tenant_id="tenant-a", user_id="user-a", ticket_id=t.execution_ticket_id, adapter_id="internal.record_transition", action="internal_record_note", payload={"note": "same"})
    second = prepare_execution_plan(c, tenant_id="tenant-a", user_id="user-a", ticket_id=t.execution_ticket_id, adapter_id="internal.record_transition", action="internal_record_note", payload={"note": "same"})
    assert first["payload_hash"] == second["payload_hash"]


def test_source_has_no_eval_or_subprocess():
    src = open("intelligence/execution_adapters.py", encoding="utf-8").read()
    assert "eval(" not in src
    assert "exec(" not in src
    assert "subprocess" not in src
    assert "/api/execution/plans" in open("app_gate5.py", encoding="utf-8").read()


def test_execution_type_match_cannot_authorise_unsupported_action():
    c = conn()
    enable_adapter_policy(c, tenant_id="tenant-a", adapter_id="internal.record_transition", allowed_actions=["do_something_else", "internal_record_note"])
    t = ticket(c, action="do_something_else", facts="Unlisted internal action")
    if t.execution_state != "AUTHORISED":
        pytest.skip("ticket not authorised")
    with pytest.raises(AdapterDenied, match="unsupported action"):
        prepare_execution_plan(c, tenant_id="tenant-a", user_id="user-a", ticket_id=t.execution_ticket_id, adapter_id="internal.record_transition", action="do_something_else", payload={})


def test_approval_hash_mismatches_and_revoked_expired():
    c = conn()
    enable_adapter_policy(c, tenant_id="tenant-a", adapter_id="email.send", allowed_actions=["send_email"], allowed_destinations=["ops@caelomere.test"], max_risk_level="critical", requires_human_approval=True)
    t = ticket(c, action="send_email", facts="Email operations", consequential_action=True, human_legal_review_present=True, human_financial_review_present=True)
    if t.execution_state != "AUTHORISED":
        pytest.skip("email ticket not authorised")
    good = {"subject": "A"}
    with pytest.raises(AdapterDenied):
        prepare_execution_plan(c, tenant_id="tenant-a", user_id="user-a", ticket_id=t.execution_ticket_id, adapter_id="email.send", action="send_email", payload=good, destination="ops@caelomere.test")
    record_approval_binding(
        c, tenant_id="tenant-a", ticket_id=t.execution_ticket_id, action="send_email", adapter_id="email.send",
        payload_hash_value=payload_hash({"subject": "B"}), destination_hash_value=destination_hash("ops@caelomere.test"),
    )
    with pytest.raises(AdapterDenied):
        prepare_execution_plan(c, tenant_id="tenant-a", user_id="user-a", ticket_id=t.execution_ticket_id, adapter_id="email.send", action="send_email", payload=good, destination="ops@caelomere.test")
    record_approval_binding(
        c, tenant_id="tenant-other", ticket_id=t.execution_ticket_id, action="send_email", adapter_id="email.send",
        payload_hash_value=payload_hash(good), destination_hash_value=destination_hash("ops@caelomere.test"),
    )
    with pytest.raises(AdapterDenied):
        prepare_execution_plan(c, tenant_id="tenant-a", user_id="user-a", ticket_id=t.execution_ticket_id, adapter_id="email.send", action="send_email", payload=good, destination="ops@caelomere.test")
    record_approval_binding(
        c, tenant_id="tenant-a", ticket_id="other-ticket", action="send_email", adapter_id="email.send",
        payload_hash_value=payload_hash(good), destination_hash_value=destination_hash("ops@caelomere.test"),
    )
    with pytest.raises(AdapterDenied):
        prepare_execution_plan(c, tenant_id="tenant-a", user_id="user-a", ticket_id=t.execution_ticket_id, adapter_id="email.send", action="send_email", payload=good, destination="ops@caelomere.test")
    record_approval_binding(
        c, tenant_id="tenant-a", ticket_id=t.execution_ticket_id, action="send_email", adapter_id="email.send",
        payload_hash_value=payload_hash(good), destination_hash_value=destination_hash("ops@caelomere.test"),
        revoked_at="2020-01-01T00:00:00Z",
    )
    with pytest.raises(AdapterDenied):
        prepare_execution_plan(c, tenant_id="tenant-a", user_id="user-a", ticket_id=t.execution_ticket_id, adapter_id="email.send", action="send_email", payload=good, destination="ops@caelomere.test")
    record_approval_binding(
        c, tenant_id="tenant-a", ticket_id=t.execution_ticket_id, action="send_email", adapter_id="email.send",
        payload_hash_value=payload_hash(good), destination_hash_value=destination_hash("ops@caelomere.test"),
        expires_at="2020-01-01T00:00:00Z",
    )
    with pytest.raises(AdapterDenied):
        prepare_execution_plan(c, tenant_id="tenant-a", user_id="user-a", ticket_id=t.execution_ticket_id, adapter_id="email.send", action="send_email", payload=good, destination="ops@caelomere.test")


def test_policy_rechecked_at_execute():
    c = conn()
    enable_adapter_policy(c, tenant_id="tenant-a", adapter_id="internal.record_transition", allowed_actions=["internal_record_note"])
    t = ticket(c)
    plan = prepare_execution_plan(c, tenant_id="tenant-a", user_id="user-a", ticket_id=t.execution_ticket_id, adapter_id="internal.record_transition", action="internal_record_note", payload={"note": "x"})
    c.execute("UPDATE execution_adapter_policy SET enabled=0 WHERE tenant_id=? AND adapter_id=?", ("tenant-a", "internal.record_transition"))
    c.commit()
    with pytest.raises(AdapterDenied):
        execute_execution_plan(c, tenant_id="tenant-a", user_id="user-a", plan_id=plan["execution_plan_id"])


def test_audit_write_failure_fails_closed(monkeypatch):
    c = conn()
    enable_adapter_policy(c, tenant_id="tenant-a", adapter_id="internal.record_transition", allowed_actions=["internal_record_note"])
    t = ticket(c)
    os.environ["CONTROL_PLANE_FAIL_WRITE"] = "1"
    try:
        with pytest.raises(AdapterDenied, match="evidence write failed"):
            prepare_execution_plan(c, tenant_id="tenant-a", user_id="user-a", ticket_id=t.execution_ticket_id, adapter_id="internal.record_transition", action="internal_record_note", payload={"note": "x"})
    finally:
        os.environ.pop("CONTROL_PLANE_FAIL_WRITE", None)


def test_atomic_claim_blocks_second_execute():
    c = conn()
    enable_adapter_policy(c, tenant_id="tenant-a", adapter_id="internal.record_transition", allowed_actions=["internal_record_note"])
    t = ticket(c)
    plan = prepare_execution_plan(c, tenant_id="tenant-a", user_id="user-a", ticket_id=t.execution_ticket_id, adapter_id="internal.record_transition", action="internal_record_note", payload={"note": "x"})
    c.execute("UPDATE execution_plans SET status='EXECUTING' WHERE id=?", (plan["execution_plan_id"],))
    c.commit()
    with pytest.raises(AdapterDenied, match="replay"):
        execute_execution_plan(c, tenant_id="tenant-a", user_id="user-a", plan_id=plan["execution_plan_id"])


def test_policy_newly_requires_approval_blocks_existing_plan():
    c = conn()
    enable_adapter_policy(c, tenant_id="tenant-a", adapter_id="internal.record_transition", allowed_actions=["internal_record_note"], requires_human_approval=False)
    t = ticket(c)
    plan = prepare_execution_plan(c, tenant_id="tenant-a", user_id="user-a", ticket_id=t.execution_ticket_id, adapter_id="internal.record_transition", action="internal_record_note", payload={"note": "x"})
    assert not plan.get("approval_binding_id")
    c.execute("UPDATE execution_adapter_policy SET requires_human_approval=1 WHERE tenant_id=? AND adapter_id=?", ("tenant-a", "internal.record_transition"))
    c.commit()
    with pytest.raises(AdapterDenied):
        execute_execution_plan(c, tenant_id="tenant-a", user_id="user-a", plan_id=plan["execution_plan_id"])
    row = c.execute("SELECT status FROM execution_plans WHERE id=?", (plan["execution_plan_id"],)).fetchone()
    assert row["status"] != "EXECUTED"
    assert c.execute("SELECT count(*) AS n FROM execution_internal_effects").fetchone()["n"] == 0
    loaded = __import__("intelligence.execution", fromlist=["load_ticket"]).load_ticket(c, t.execution_ticket_id, "tenant-a")
    assert loaded.execution_state != "CONSUMED"


def test_plan_bound_approval_succeeds_and_substitutes_fail():
    c = conn()
    enable_adapter_policy(c, tenant_id="tenant-a", adapter_id="internal.record_transition", allowed_actions=["internal_record_note"], requires_human_approval=True)
    t = ticket(c)
    body = {"note": "bound"}
    first = record_approval_binding(
        c, tenant_id="tenant-a", ticket_id=t.execution_ticket_id, action="internal_record_note",
        adapter_id="internal.record_transition", payload_hash_value=payload_hash(body),
    )
    plan = prepare_execution_plan(c, tenant_id="tenant-a", user_id="user-a", ticket_id=t.execution_ticket_id, adapter_id="internal.record_transition", action="internal_record_note", payload=body)
    assert plan["approval_binding_id"] == first["id"]
    out = execute_execution_plan(c, tenant_id="tenant-a", user_id="user-a", plan_id=plan["execution_plan_id"])
    assert out["status"] == "EXECUTED"


def test_revoked_expired_altered_and_substituted_approval_block_execute():
    c = conn()
    enable_adapter_policy(c, tenant_id="tenant-a", adapter_id="internal.record_transition", allowed_actions=["internal_record_note"], requires_human_approval=True)
    t = ticket(c)
    body = {"note": "lock"}
    binding = record_approval_binding(
        c, tenant_id="tenant-a", ticket_id=t.execution_ticket_id, action="internal_record_note",
        adapter_id="internal.record_transition", payload_hash_value=payload_hash(body),
    )
    plan = prepare_execution_plan(c, tenant_id="tenant-a", user_id="user-a", ticket_id=t.execution_ticket_id, adapter_id="internal.record_transition", action="internal_record_note", payload=body)
    c.execute("UPDATE execution_approval_bindings SET revoked_at=? WHERE id=?", ("2026-01-01T00:00:00Z", binding["id"]))
    c.commit()
    with pytest.raises(AdapterDenied):
        execute_execution_plan(c, tenant_id="tenant-a", user_id="user-a", plan_id=plan["execution_plan_id"])

    c2 = conn()
    enable_adapter_policy(c2, tenant_id="tenant-a", adapter_id="internal.record_transition", allowed_actions=["internal_record_note"], requires_human_approval=True)
    t2 = ticket(c2)
    binding2 = record_approval_binding(
        c2, tenant_id="tenant-a", ticket_id=t2.execution_ticket_id, action="internal_record_note",
        adapter_id="internal.record_transition", payload_hash_value=payload_hash(body),
    )
    plan2 = prepare_execution_plan(c2, tenant_id="tenant-a", user_id="user-a", ticket_id=t2.execution_ticket_id, adapter_id="internal.record_transition", action="internal_record_note", payload=body)
    c2.execute("UPDATE execution_approval_bindings SET expires_at=? WHERE id=?", ("2020-01-01T00:00:00Z", binding2["id"]))
    c2.commit()
    with pytest.raises(AdapterDenied):
        execute_execution_plan(c2, tenant_id="tenant-a", user_id="user-a", plan_id=plan2["execution_plan_id"])

    c3 = conn()
    enable_adapter_policy(c3, tenant_id="tenant-a", adapter_id="internal.record_transition", allowed_actions=["internal_record_note"], requires_human_approval=True)
    t3 = ticket(c3)
    binding3 = record_approval_binding(
        c3, tenant_id="tenant-a", ticket_id=t3.execution_ticket_id, action="internal_record_note",
        adapter_id="internal.record_transition", payload_hash_value=payload_hash(body),
    )
    plan3 = prepare_execution_plan(c3, tenant_id="tenant-a", user_id="user-a", ticket_id=t3.execution_ticket_id, adapter_id="internal.record_transition", action="internal_record_note", payload=body)
    c3.execute("UPDATE execution_approval_bindings SET approval_hash=? WHERE id=?", ("deadbeef", binding3["id"]))
    c3.commit()
    with pytest.raises(AdapterDenied):
        execute_execution_plan(c3, tenant_id="tenant-a", user_id="user-a", plan_id=plan3["execution_plan_id"])

    c4 = conn()
    enable_adapter_policy(c4, tenant_id="tenant-a", adapter_id="internal.record_transition", allowed_actions=["internal_record_note"], requires_human_approval=True)
    t4 = ticket(c4)
    first = record_approval_binding(
        c4, tenant_id="tenant-a", ticket_id=t4.execution_ticket_id, action="internal_record_note",
        adapter_id="internal.record_transition", payload_hash_value=payload_hash(body),
    )
    plan4 = prepare_execution_plan(c4, tenant_id="tenant-a", user_id="user-a", ticket_id=t4.execution_ticket_id, adapter_id="internal.record_transition", action="internal_record_note", payload=body)
    c4.execute("UPDATE execution_approval_bindings SET revoked_at=? WHERE id=?", ("2026-01-01T00:00:00Z", first["id"]))
    record_approval_binding(
        c4, tenant_id="tenant-a", ticket_id=t4.execution_ticket_id, action="internal_record_note",
        adapter_id="internal.record_transition", payload_hash_value=payload_hash(body),
    )
    c4.commit()
    with pytest.raises(AdapterDenied):
        execute_execution_plan(c4, tenant_id="tenant-a", user_id="user-a", plan_id=plan4["execution_plan_id"])


def test_injected_executor_failure_rolls_back_ticket_and_effect(monkeypatch):
    from intelligence import execution_adapters as adapters
    from intelligence.execution import load_ticket

    c = conn()
    enable_adapter_policy(c, tenant_id="tenant-a", adapter_id="internal.record_transition", allowed_actions=["internal_record_note"])
    t = ticket(c)
    plan = prepare_execution_plan(c, tenant_id="tenant-a", user_id="user-a", ticket_id=t.execution_ticket_id, adapter_id="internal.record_transition", action="internal_record_note", payload={"note": "x"})

    def boom(_c, _plan):
        raise RuntimeError("injected executor failure")

    monkeypatch.setitem(adapters.INTERNAL_EXECUTORS, "internal_record_note", boom)
    with pytest.raises(RuntimeError, match="injected executor failure"):
        execute_execution_plan(c, tenant_id="tenant-a", user_id="user-a", plan_id=plan["execution_plan_id"])
    loaded = load_ticket(c, t.execution_ticket_id, "tenant-a")
    assert loaded.execution_state == "AUTHORISED"
    assert c.execute("SELECT count(*) AS n FROM execution_internal_effects").fetchone()["n"] == 0
    status = c.execute("SELECT status FROM execution_plans WHERE id=?", (plan["execution_plan_id"],)).fetchone()["status"]
    assert status != "EXECUTED"
    events = c.execute("SELECT action FROM control_events WHERE action='execution_internal_completed'").fetchall()
    assert events == []


def test_successful_internal_execution_is_atomic():
    from intelligence.execution import load_ticket
    c = conn()
    enable_adapter_policy(c, tenant_id="tenant-a", adapter_id="internal.record_transition", allowed_actions=["internal_record_note"])
    t = ticket(c)
    plan = prepare_execution_plan(c, tenant_id="tenant-a", user_id="user-a", ticket_id=t.execution_ticket_id, adapter_id="internal.record_transition", action="internal_record_note", payload={"note": "ok"})
    out = execute_execution_plan(c, tenant_id="tenant-a", user_id="user-a", plan_id=plan["execution_plan_id"])
    assert out["status"] == "EXECUTED"
    loaded = load_ticket(c, t.execution_ticket_id, "tenant-a")
    assert loaded.execution_state == "CONSUMED"
    assert c.execute("SELECT count(*) AS n FROM execution_internal_effects").fetchone()["n"] == 1
    assert c.execute("SELECT count(*) AS n FROM control_events WHERE action='execution_internal_completed'").fetchone()["n"] == 1
    with pytest.raises(AdapterDenied):
        execute_execution_plan(c, tenant_id="tenant-a", user_id="user-a", plan_id=plan["execution_plan_id"])
    assert c.execute("SELECT count(*) AS n FROM execution_internal_effects").fetchone()["n"] == 1
