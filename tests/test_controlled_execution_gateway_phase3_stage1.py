import os
import sqlite3
import threading
import time
from pathlib import Path

import pytest

from intelligence.execution import ensure_execution_schema, prepare
from intelligence.execution_adapters import (
    AdapterDenied,
    destination_hash,
    enable_adapter_policy,
    payload_hash,
    prepare_execution_plan,
    record_approval_binding,
)
from intelligence.execution_live import (
    LIVE_ENV_SWITCH,
    apply_phase3_disablement,
    add_destination_allowlist,
    consume_confirmation_token,
    evaluate_live_gates,
    grant_live,
    hash_token,
    issue_confirmation_token,
    operator_status,
    request_live_execution,
    revoke_confirmation_token,
    set_kill_switch,
    shadow_execution_plan,
    submit_live,
    transition_plan_status,
    validate_webhook_destination_stage1,
)
from intelligence.execution_providers import ClosedProvider, ProviderDenied, get_provider
from intelligence.execution_receipts import list_receipts_for_attempt, record_receipt
from intelligence.execution_adapters import get_adapter


def conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    ensure_execution_schema(c)
    return c


def file_conn(path):
    c = sqlite3.connect(path, check_same_thread=False, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA busy_timeout=5000")
    ensure_execution_schema(c)
    c.commit()
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


def internal_plan(c):
    enable_adapter_policy(c, tenant_id="tenant-a", adapter_id="internal.record_transition", allowed_actions=["internal_record_note"])
    t = ticket(c)
    plan = prepare_execution_plan(
        c,
        tenant_id="tenant-a",
        user_id="user-a",
        ticket_id=t.execution_ticket_id,
        adapter_id="internal.record_transition",
        action="internal_record_note",
        payload={"note": "ok"},
    )
    return t, plan


def email_plan(c):
    dest = "ops@caelomere.test"
    body = {"subject": "Ops", "body": "note"}
    enable_adapter_policy(
        c,
        tenant_id="tenant-a",
        adapter_id="email.send",
        allowed_actions=["send_email"],
        allowed_destinations=[dest],
        max_risk_level="critical",
    )
    t = ticket(
        c,
        action="send_email",
        facts="Notify operations by email",
        consequential_action=True,
        human_legal_review_present=True,
        human_financial_review_present=True,
    )
    if t.execution_state != "AUTHORISED":
        pytest.skip("email ticket not authorised")
    record_approval_binding(
        c,
        tenant_id="tenant-a",
        ticket_id=t.execution_ticket_id,
        action="send_email",
        adapter_id="email.send",
        payload_hash_value=payload_hash(body),
        destination_hash_value=destination_hash(dest),
    )
    plan = prepare_execution_plan(
        c,
        tenant_id="tenant-a",
        user_id="user-a",
        ticket_id=t.execution_ticket_id,
        adapter_id="email.send",
        action="send_email",
        payload=body,
        destination=dest,
    )
    add_destination_allowlist(c, tenant_id="tenant-a", adapter_id="email.send", destination=dest, label="ops")
    return t, plan, dest, body


def test_external_execution_defaults_disabled():
    c = conn()
    t, plan = internal_plan(c)
    assert t.external_execution_enabled is False
    assert plan.get("status") == "PREPARED"
    os.environ.pop(LIVE_ENV_SWITCH, None)
    with pytest.raises(AdapterDenied):
        evaluate_live_gates(c, tenant_id="tenant-a", adapter_id="email.send", action="send_email")
    with pytest.raises(AdapterDenied, match="Stage 1"):
        request_live_execution()
    with pytest.raises(AdapterDenied):
        submit_live()


def test_every_missing_gate_denies_live(monkeypatch):
    c = conn()
    monkeypatch.setenv(LIVE_ENV_SWITCH, "pilot")
    with pytest.raises(AdapterDenied, match="grant"):
        evaluate_live_gates(c, tenant_id="tenant-a", adapter_id="email.send", action="send_email")
    grant_live(c, tenant_id="tenant-a", adapter_id="email.send", action="send_email", env="prod", actor_id="op", enabled=True)
    with pytest.raises(AdapterDenied, match="adapter live support"):
        evaluate_live_gates(c, tenant_id="tenant-a", adapter_id="email.send", action="send_email")
    monkeypatch.delenv(LIVE_ENV_SWITCH, raising=False)
    with pytest.raises(AdapterDenied, match="missing"):
        evaluate_live_gates(c, tenant_id="tenant-a", adapter_id="email.send", action="send_email")


def test_no_outbound_provider_implementation():
    adapter = get_adapter("webhook.post")
    provider = get_provider(adapter)
    assert isinstance(provider, ClosedProvider)
    with pytest.raises(ProviderDenied):
        provider.submit({"payload_hash": "x"}, "key", 1.0)
    with pytest.raises(ProviderDenied):
        provider.cancel("ref")
    root = Path(__file__).resolve().parents[1]
    banned = ("requests", "httpx", "urllib.request", "urllib.error", "subprocess", "eval(", "exec(")
    for rel in (
        "intelligence/execution_providers.py",
        "intelligence/execution_live.py",
        "intelligence/execution_receipts.py",
    ):
        text = (root / rel).read_text()
        for token in banned:
            assert token not in text, f"{rel} contains {token}"


def test_shadow_validates_without_consuming_ticket():
    c = conn()
    t, plan = internal_plan(c)
    out = shadow_execution_plan(c, tenant_id="tenant-a", user_id="user-a", plan_id=plan["execution_plan_id"], role="owner")
    assert out["external_execution_enabled"] is False
    assert out["shadow"]["execution_allowed"] is False
    assert out["plan_status"] == "SHADOW_COMPLETE"
    assert out["ticket_state"] == "AUTHORISED"
    c.row_factory = sqlite3.Row
    row = c.execute("SELECT execution_state FROM execution_tickets WHERE id=?", (t.execution_ticket_id,)).fetchone()
    assert row["execution_state"] == "AUTHORISED"


def test_wrong_tenant_and_user_rejected():
    c = conn()
    _t, plan = internal_plan(c)
    with pytest.raises(AdapterDenied):
        shadow_execution_plan(c, tenant_id="tenant-b", user_id="user-a", plan_id=plan["execution_plan_id"])
    with pytest.raises(AdapterDenied):
        shadow_execution_plan(c, tenant_id="tenant-a", user_id="user-b", plan_id=plan["execution_plan_id"])
    with pytest.raises(AdapterDenied):
        shadow_execution_plan(
            c,
            tenant_id="tenant-a",
            user_id="user-a",
            plan_id=plan["execution_plan_id"],
            payload_tenant_id="tenant-b",
        )


def test_hash_and_approval_mismatches_rejected():
    c = conn()
    t, plan, dest, body = email_plan(c)
    with pytest.raises(AdapterDenied, match="payload"):
        shadow_execution_plan(
            c,
            tenant_id="tenant-a",
            user_id="user-a",
            plan_id=plan["execution_plan_id"],
            payload={"subject": "other", "body": "note"},
        )
    with pytest.raises(AdapterDenied, match="destination"):
        shadow_execution_plan(
            c,
            tenant_id="tenant-a",
            user_id="user-a",
            plan_id=plan["execution_plan_id"],
            destination="other@caelomere.test",
        )
    with pytest.raises(AdapterDenied, match="resource"):
        shadow_execution_plan(
            c,
            tenant_id="tenant-a",
            user_id="user-a",
            plan_id=plan["execution_plan_id"],
            resource_hash="deadbeef",
        )
    c.execute("UPDATE execution_approval_bindings SET revoked_at=? WHERE execution_ticket_id=?", ("2026-01-01T00:00:00+00:00", t.execution_ticket_id))
    with pytest.raises(AdapterDenied):
        shadow_execution_plan(
            c,
            tenant_id="tenant-a",
            user_id="user-a",
            plan_id=plan["execution_plan_id"],
            payload=body,
            destination=dest,
        )


def test_confirmation_token_expiry_revoke_replay():
    c = conn()
    token = issue_confirmation_token(
        c,
        tenant_id="tenant-a",
        user_id="user-a",
        plan_id="plan-1",
        approval_hash="appr",
        idempotency_key="idem",
        ttl_seconds=60,
    )
    assert token not in str(operator_status(c))
    consume_confirmation_token(
        c,
        tenant_id="tenant-a",
        user_id="user-a",
        plan_id="plan-1",
        approval_hash="appr",
        idempotency_key="idem",
        token=token,
    )
    with pytest.raises(AdapterDenied, match="replay"):
        consume_confirmation_token(
            c,
            tenant_id="tenant-a",
            user_id="user-a",
            plan_id="plan-1",
            approval_hash="appr",
            idempotency_key="idem",
            token=token,
        )
    token2 = issue_confirmation_token(
        c, tenant_id="tenant-a", user_id="user-a", plan_id="plan-2", approval_hash="appr", idempotency_key="idem2", ttl_seconds=60
    )
    revoke_confirmation_token(c, tenant_id="tenant-a", token_hash=hash_token(token2), actor_id="user-a")
    with pytest.raises(AdapterDenied, match="revoked"):
        consume_confirmation_token(
            c, tenant_id="tenant-a", user_id="user-a", plan_id="plan-2", approval_hash="appr", idempotency_key="idem2", token=token2
        )
    token3 = issue_confirmation_token(
        c, tenant_id="tenant-a", user_id="user-a", plan_id="plan-3", approval_hash="appr", idempotency_key="idem3", ttl_seconds=60
    )
    c.execute("UPDATE execution_confirmation_tokens SET expires_at='2020-01-01T00:00:00Z' WHERE plan_id='plan-3'")
    with pytest.raises(AdapterDenied, match="expired"):
        consume_confirmation_token(
            c, tenant_id="tenant-a", user_id="user-a", plan_id="plan-3", approval_hash="appr", idempotency_key="idem3", token=token3
        )


def test_confirmation_token_atomic_under_concurrency(tmp_path):
    db = str(tmp_path / "phase3.db")
    c = file_conn(db)
    token = issue_confirmation_token(
        c, tenant_id="tenant-a", user_id="user-a", plan_id="plan-c", approval_hash="h", idempotency_key="k", ttl_seconds=120
    )
    c.commit()
    results = []

    def worker():
        local = file_conn(db)
        try:
            consume_confirmation_token(
                local,
                tenant_id="tenant-a",
                user_id="user-a",
                plan_id="plan-c",
                approval_hash="h",
                idempotency_key="k",
                token=token,
            )
            local.commit()
            results.append("ok")
        except AdapterDenied:
            results.append("denied")
        finally:
            local.close()

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert results.count("ok") == 1
    assert results.count("denied") == 7


def test_kill_switches_fail_closed(monkeypatch):
    c = conn()
    monkeypatch.setenv(LIVE_ENV_SWITCH, "pilot")
    grant_live(c, tenant_id="tenant-a", adapter_id="email.send", action="send_email", env="prod", actor_id="op", enabled=True)
    set_kill_switch(c, scope="global", enabled=True, reason="stop", actor_id="op")
    with pytest.raises(AdapterDenied, match="global kill"):
        evaluate_live_gates(c, tenant_id="tenant-a", adapter_id="email.send", action="send_email")
    c2 = conn()
    monkeypatch.setenv(LIVE_ENV_SWITCH, "pilot")
    grant_live(c2, tenant_id="tenant-a", adapter_id="email.send", action="send_email", env="prod", actor_id="op", enabled=True)
    set_kill_switch(c2, scope="tenant", enabled=True, reason="stop", actor_id="op", tenant_id="tenant-a", adapter_id="email.send")
    with pytest.raises(AdapterDenied, match="tenant kill"):
        evaluate_live_gates(c2, tenant_id="tenant-a", adapter_id="email.send", action="send_email")
    set_kill_switch(c2, scope="global", enabled=True, reason="stop-all", actor_id="op")
    t, plan = internal_plan(c2)
    with pytest.raises(AdapterDenied, match="kill"):
        shadow_execution_plan(c2, tenant_id="tenant-a", user_id="user-a", plan_id=plan["execution_plan_id"])


def test_missing_destination_allowlist_denies():
    with pytest.raises(AdapterDenied):
        validate_webhook_destination_stage1("https://hooks.example.test/sink", [])
    with pytest.raises(AdapterDenied):
        validate_webhook_destination_stage1("http://hooks.example.test/sink", ["abc"])
    with pytest.raises(AdapterDenied):
        validate_webhook_destination_stage1("https://user:pass@hooks.example.test/sink", ["abc"])
    with pytest.raises(AdapterDenied):
        validate_webhook_destination_stage1("https://127.0.0.1/sink", [destination_hash("https://127.0.0.1/sink")])
    with pytest.raises(AdapterDenied):
        validate_webhook_destination_stage1("https://169.254.169.254/latest", [destination_hash("https://169.254.169.254/latest")])
    with pytest.raises(AdapterDenied):
        validate_webhook_destination_stage1("https://localhost/sink", [destination_hash("https://localhost/sink")])


def test_invalid_state_transitions_deny():
    with pytest.raises(AdapterDenied):
        transition_plan_status("PREPARED", "EXECUTED")
    with pytest.raises(AdapterDenied):
        transition_plan_status("PREPARED", "SUBMITTING")
    with pytest.raises(AdapterDenied):
        transition_plan_status("SHADOW_COMPLETE", "EXECUTED")
    assert transition_plan_status("PREPARED", "SHADOW_COMPLETE") == "SHADOW_COMPLETE"
    assert transition_plan_status("SUBMITTING", "UNCERTAIN") == "UNCERTAIN"


def test_historical_receipts_survive_disablement():
    c = conn()
    c.execute(
        """INSERT INTO execution_attempts(id,tenant_id,plan_id,ticket_id,adapter_id,idempotency_key,state,created_at,updated_at)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        ("att-1", "tenant-a", "plan-1", "tix-1", "email.send", "idem-1", "UNCERTAIN", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00"),
    )
    record_receipt(c, tenant_id="tenant-a", attempt_id="att-1", classification="uncertain", payload_hash="p", destination_hash="d")
    apply_phase3_disablement(c)
    rows = list_receipts_for_attempt(c, "att-1", "tenant-a")
    assert len(rows) == 1
    attempt = c.execute("SELECT * FROM execution_attempts WHERE id='att-1'").fetchone()
    assert attempt is not None
    grants = c.execute("SELECT enabled FROM execution_live_grants").fetchall()
    assert all(g["enabled"] == 0 for g in grants)
    status = operator_status(c, tenant_id="tenant-a")
    assert status["external_execution_enabled"] is False
    assert status["uncertain_attempts"]


def test_secrets_and_tokens_not_in_responses():
    c = conn()
    token = issue_confirmation_token(
        c, tenant_id="tenant-a", user_id="user-a", plan_id="plan-s", approval_hash="h", idempotency_key="k"
    )
    t, plan = internal_plan(c)
    out = shadow_execution_plan(c, tenant_id="tenant-a", user_id="user-a", plan_id=plan["execution_plan_id"], role="owner")
    blob = str(out) + str(operator_status(c))
    audits = c.execute("SELECT detail_json FROM execution_phase3_audit").fetchall()
    blob += "".join(r["detail_json"] for r in audits)
    assert token not in blob
    assert "sk-" not in blob
    assert "Authorization" not in blob
    assert "Bearer " not in blob


def test_source_scan_phase3_modules():
    root = Path(__file__).resolve().parents[1]
    text = (root / "intelligence/execution_providers.py").read_text()
    assert "class ProviderPort" in text
    assert "def submit" in text
    assert "def cancel" in text
