"""Phase 3 Stage 3 — isolated-CI webhook live lifecycle."""
from __future__ import annotations

import os
import sqlite3
import threading
from datetime import timedelta
from pathlib import Path

import pytest

from intelligence.execution import consume_execution_ticket, ensure_execution_schema, prepare, _iso, _now
from intelligence.execution_adapters import (
    destination_hash,
    enable_adapter_policy,
    payload_hash,
    prepare_execution_plan,
    record_approval_binding,
    get_adapter,
)
from intelligence.execution_ci_sink import (
    ISOLATED_CI_HOSTNAME,
    ISOLATED_CI_PINNED_IP,
    HermeticTlsCiSink,
    IsolatedCiDenied,
    IsolatedCiUncertain,
    IsolatedTlsResponse,
    ScriptedTransport,
    isolated_tls_post,
)
from intelligence.execution_live import (
    LiveDenied,
    add_destination_allowlist,
    issue_confirmation_token,
    set_kill_switch,
    shadow_execution_plan,
    submit_live,
)
from intelligence.execution_isolated_live import (
    IsolatedLiveDenied,
    classify_http_outcome,
    grant_isolated_ci,
    production_live_still_closed,
    recover_stale_submitting,
    request_isolated_cancel,
    submit_isolated_live,
)
from intelligence.execution_providers import ClosedProvider, ProviderDenied, get_provider
from intelligence.execution_providers_webhook import IsolatedWebhookProvider, WebhookSandboxProvider
from intelligence.execution_receipts import list_receipts_for_attempt


DEST = f"https://{ISOLATED_CI_HOSTNAME}/isolated"
BODY = {"event": "isolated-ci", "ref": "stage3"}


def conn():
    c = sqlite3.connect(":memory:", check_same_thread=False)
    c.row_factory = sqlite3.Row
    ensure_execution_schema(c)
    return c


def authorised_plan(c, destination=DEST, body=None, tenant="tenant-a", user="user-a"):
    body = body or dict(BODY)
    os.environ.pop("ZORVIAN_EXTERNAL_EXECUTION", None)
    enable_adapter_policy(
        c,
        tenant_id=tenant,
        adapter_id="webhook.post",
        allowed_actions=["post_webhook"],
        allowed_destinations=[destination],
        max_risk_level="critical",
    )
    add_destination_allowlist(c, tenant_id=tenant, adapter_id="webhook.post", destination=destination)
    t = prepare(
        tenant_id=tenant,
        user_id=user,
        role="owner",
        module="constitutional-core",
        action="post_webhook",
        facts="Post an approved isolated CI webhook",
        jurisdiction_raw="United Kingdom",
        consequential_action=True,
        identity_state="authenticated",
        session_state="normal",
        user_status="active",
        connection=c,
        approval_present=True,
        approvals=[{"approver_id": "approver-1", "tenant_id": tenant}],
        human_legal_review_present=True,
        human_financial_review_present=True,
    )
    assert t.execution_state == "AUTHORISED"
    record_approval_binding(
        c,
        tenant_id=tenant,
        ticket_id=t.execution_ticket_id,
        action="post_webhook",
        adapter_id="webhook.post",
        payload_hash_value=payload_hash(body),
        destination_hash_value=destination_hash(destination),
    )
    plan = prepare_execution_plan(
        c,
        tenant_id=tenant,
        user_id=user,
        ticket_id=t.execution_ticket_id,
        adapter_id="webhook.post",
        action="post_webhook",
        payload=body,
        destination=destination,
    )
    return t, plan, body


def arm_isolated(c, tenant="tenant-a"):
    os.environ.pop("ZORVIAN_EXTERNAL_EXECUTION", None)
    os.environ["ZORVIAN_ISOLATED_CI_EXECUTION"] = "1"
    grant_isolated_ci(c, tenant_id=tenant)


def token_for(c, plan, ticket, user="user-a"):
    return issue_confirmation_token(
        c,
        tenant_id=plan["tenant_id"],
        user_id=user,
        plan_id=plan["execution_plan_id"],
        approval_hash=plan.get("approval_hash"),
        idempotency_key=plan.get("idempotency_key"),
    )


def shadow(c, plan, user="user-a"):
    return shadow_execution_plan(
        c,
        tenant_id=plan["tenant_id"],
        user_id=user,
        plan_id=plan["execution_plan_id"],
        role="owner",
    )


def test_production_remains_closed():
    os.environ.pop("ZORVIAN_EXTERNAL_EXECUTION", None)
    status = production_live_still_closed()
    assert status["submit_live_closed"] is True
    assert status["provider_is_closed"] is True
    assert status["adapter_live_supported"] is False
    assert status["external_execution_enabled"] is False
    adapter = get_adapter("webhook.post")
    assert isinstance(get_provider(adapter), ClosedProvider)
    assert isinstance(get_provider(adapter, mode="production"), ClosedProvider)
    with pytest.raises(LiveDenied):
        submit_live()
    with pytest.raises(ProviderDenied):
        IsolatedWebhookProvider(adapter, production_mode=True)


def test_stage2_modules_still_forbid_http_clients():
    import re

    files = [
        "intelligence/execution_providers_webhook.py",
        "intelligence/execution_providers.py",
        "intelligence/execution_live.py",
    ]
    patterns = [
        r"(?m)^\s*import requests\b",
        r"(?m)^\s*import httpx\b",
        r"(?m)^\s*import socket\b",
        r"(?m)^\s*import subprocess\b",
        r"urllib\.request",
    ]
    for rel in files:
        text = Path(rel).read_text(encoding="utf-8")
        for pattern in patterns:
            assert re.search(pattern, text) is None, (rel, pattern)


def test_http_outcome_mapping():
    assert classify_http_outcome(200) == "EXECUTED"
    assert classify_http_outcome(204) == "EXECUTED"
    assert classify_http_outcome(400) == "FAILED"
    assert classify_http_outcome(404) == "FAILED"
    assert classify_http_outcome(409) == "FAILED"
    assert classify_http_outcome(500) == "UNCERTAIN"
    assert classify_http_outcome(502) == "UNCERTAIN"
    assert classify_http_outcome(503) == "UNCERTAIN"


def test_verified_2xx_executed_consumes_token_and_ticket():
    c = conn()
    t, plan, body = authorised_plan(c)
    arm_isolated(c)
    shadow(c, plan)
    token = token_for(c, plan, t)
    result = submit_isolated_live(
        c,
        tenant_id="tenant-a",
        user_id="user-a",
        plan_id=plan["execution_plan_id"],
        confirmation_token=token,
        role="owner",
        transport=ScriptedTransport([200]),
    )
    assert result["state"] == "EXECUTED"
    assert result["provider_submitted"] is True
    assert result["ticket_state"] == "CONSUMED"
    assert result["external_execution_enabled"] is False
    receipts = list_receipts_for_attempt(c, result["attempt_id"], "tenant-a")
    assert receipts
    assert receipts[0]["classification"] == "isolated_ci_executed"
    replay = consume_execution_ticket(
        connection=c,
        ticket_id=t.execution_ticket_id,
        tenant_id="tenant-a",
        user_id="user-a",
        exact_action="post_webhook",
        resource_id=None,
        resource_hash=None,
        commit=False,
    )
    assert replay.execution_state == "CONSUMED"


def test_4xx_failed_and_5xx_uncertain_no_retry_script():
    c = conn()
    t, plan, body = authorised_plan(c)
    arm_isolated(c)
    shadow(c, plan)
    token = token_for(c, plan, t)
    transport = ScriptedTransport([404])
    failed = submit_isolated_live(
        c,
        tenant_id="tenant-a",
        user_id="user-a",
        plan_id=plan["execution_plan_id"],
        confirmation_token=token,
        role="owner",
        transport=transport,
    )
    assert failed["state"] == "FAILED"
    assert len(transport.calls) == 1

    c2 = conn()
    t2, plan2, _ = authorised_plan(c2, body={"event": "b", "ref": "2"})
    arm_isolated(c2)
    shadow(c2, plan2)
    token2 = token_for(c2, plan2, t2)
    transport2 = ScriptedTransport([503])
    uncertain = submit_isolated_live(
        c2,
        tenant_id="tenant-a",
        user_id="user-a",
        plan_id=plan2["execution_plan_id"],
        confirmation_token=token2,
        role="owner",
        transport=transport2,
    )
    assert uncertain["state"] == "UNCERTAIN"
    assert len(transport2.calls) == 1


def test_timeout_and_reset_uncertain():
    c = conn()
    t, plan, _ = authorised_plan(c)
    arm_isolated(c)
    shadow(c, plan)
    token = token_for(c, plan, t)
    result = submit_isolated_live(
        c,
        tenant_id="tenant-a",
        user_id="user-a",
        plan_id=plan["execution_plan_id"],
        confirmation_token=token,
        role="owner",
        transport=ScriptedTransport([IsolatedCiUncertain("connect timeout")]),
    )
    assert result["state"] == "UNCERTAIN"

    c2 = conn()
    t2, plan2, _ = authorised_plan(c2, body={"event": "reset", "ref": "3"})
    arm_isolated(c2)
    shadow(c2, plan2)
    token2 = token_for(c2, plan2, t2)
    result2 = submit_isolated_live(
        c2,
        tenant_id="tenant-a",
        user_id="user-a",
        plan_id=plan2["execution_plan_id"],
        confirmation_token=token2,
        role="owner",
        transport=ScriptedTransport([IsolatedCiUncertain("transport reset")]),
    )
    assert result2["state"] == "UNCERTAIN"


def test_deterministic_idempotency_single_submission():
    c = conn()
    t, plan, _ = authorised_plan(c)
    arm_isolated(c)
    shadow(c, plan)
    token = token_for(c, plan, t)
    transport = ScriptedTransport([200, 200])
    first = submit_isolated_live(
        c,
        tenant_id="tenant-a",
        user_id="user-a",
        plan_id=plan["execution_plan_id"],
        confirmation_token=token,
        role="owner",
        transport=transport,
    )
    second = submit_isolated_live(
        c,
        tenant_id="tenant-a",
        user_id="user-a",
        plan_id=plan["execution_plan_id"],
        confirmation_token=token,
        role="owner",
        transport=transport,
    )
    assert first["state"] == "EXECUTED"
    assert second["idempotent_replay"] is True
    assert second["attempt_id"] == first["attempt_id"]
    assert len(transport.calls) == 1


def test_stale_submitting_recovery_does_not_resubmit():
    c = conn()
    t, plan, _ = authorised_plan(c)
    arm_isolated(c)
    shadow(c, plan)
    token = token_for(c, plan, t)
    # Force a SUBMITTING row without a provider call by inserting directly after claim failure path:
    submit_isolated_live(
        c,
        tenant_id="tenant-a",
        user_id="user-a",
        plan_id=plan["execution_plan_id"],
        confirmation_token=token,
        role="owner",
        transport=ScriptedTransport([IsolatedCiUncertain("hung then process crash")]),
    )
    attempt = c.execute("SELECT * FROM execution_attempts").fetchone()
    c.execute(
        "UPDATE execution_attempts SET state='SUBMITTING', updated_at=? WHERE id=?",
        (_iso(_now() - timedelta(seconds=120)), attempt["id"]),
    )
    recovered = recover_stale_submitting(c, tenant_id="tenant-a", older_than_seconds=30)
    assert recovered == [attempt["id"]]
    row = c.execute("SELECT state FROM execution_attempts WHERE id=?", (attempt["id"],)).fetchone()
    assert row["state"] == "UNCERTAIN"
    iso = c.execute(
        "SELECT submit_count FROM execution_isolated_attempts WHERE attempt_id=?",
        (attempt["id"],),
    ).fetchone()
    assert iso["submit_count"] == 1


def test_cancel_late_success():
    c = conn()
    t, plan, _ = authorised_plan(c)
    arm_isolated(c)
    shadow(c, plan)
    token = token_for(c, plan, t)

    class CancelMidTransport:
        def __init__(self):
            self.calls = []

        def post(self, **kwargs):
            self.calls.append(kwargs)
            attempt = c.execute("SELECT id FROM execution_attempts").fetchone()
            request_isolated_cancel(
                c,
                tenant_id="tenant-a",
                attempt_id=attempt["id"],
                actor_id="user-a",
            )
            return IsolatedTlsResponse(200, b'{"ok":true}', {}, ISOLATED_CI_HOSTNAME, ISOLATED_CI_PINNED_IP)

    result = submit_isolated_live(
        c,
        tenant_id="tenant-a",
        user_id="user-a",
        plan_id=plan["execution_plan_id"],
        confirmation_token=token,
        role="owner",
        transport=CancelMidTransport(),
    )
    assert result["state"] == "EXECUTED_AFTER_CANCEL_REQUEST"


def test_circuit_breaker_opens():
    os.environ["ZORVIAN_ISOLATED_CI_EXECUTION"] = "1"
    c = conn()
    grant_isolated_ci(c, tenant_id="tenant-a")
    for idx in range(5):
        t, plan, _ = authorised_plan(c, body={"event": "cb", "ref": str(idx)})
        shadow(c, plan)
        token = token_for(c, plan, t)
        submit_isolated_live(
            c,
            tenant_id="tenant-a",
            user_id="user-a",
            plan_id=plan["execution_plan_id"],
            confirmation_token=token,
            role="owner",
            transport=ScriptedTransport([500]),
        )
    t6, plan6, _ = authorised_plan(c, body={"event": "cb", "ref": "blocked"})
    shadow(c, plan6)
    token6 = token_for(c, plan6, t6)
    with pytest.raises(IsolatedLiveDenied, match="circuit breaker"):
        submit_isolated_live(
            c,
            tenant_id="tenant-a",
            user_id="user-a",
            plan_id=plan6["execution_plan_id"],
            confirmation_token=token6,
            role="owner",
            transport=ScriptedTransport([200]),
        )


def test_kill_switch_and_missing_isolated_switch_fail_closed():
    c = conn()
    t, plan, _ = authorised_plan(c)
    os.environ.pop("ZORVIAN_ISOLATED_CI_EXECUTION", None)
    grant_isolated_ci(c, tenant_id="tenant-a")
    shadow(c, plan)
    token = token_for(c, plan, t)
    with pytest.raises(IsolatedLiveDenied):
        submit_isolated_live(
            c,
            tenant_id="tenant-a",
            user_id="user-a",
            plan_id=plan["execution_plan_id"],
            confirmation_token=token,
            role="owner",
            transport=ScriptedTransport([200]),
        )
    arm_isolated(c)
    set_kill_switch(c, scope="global", enabled=True, reason="stop", actor_id="ops")
    with pytest.raises(IsolatedLiveDenied):
        submit_isolated_live(
            c,
            tenant_id="tenant-a",
            user_id="user-a",
            plan_id=plan["execution_plan_id"],
            confirmation_token=token,
            role="owner",
            transport=ScriptedTransport([200]),
        )


def test_production_switch_on_blocks_isolated_path():
    c = conn()
    t, plan, _ = authorised_plan(c)
    arm_isolated(c)
    os.environ["ZORVIAN_EXTERNAL_EXECUTION"] = "on"
    shadow(c, plan)
    token = token_for(c, plan, t)
    with pytest.raises(IsolatedLiveDenied, match="production external execution"):
        submit_isolated_live(
            c,
            tenant_id="tenant-a",
            user_id="user-a",
            plan_id=plan["execution_plan_id"],
            confirmation_token=token,
            role="owner",
            transport=ScriptedTransport([200]),
        )


def test_redirects_rejected_by_tls_client_and_sink():
    sink = HermeticTlsCiSink(programmed_status=302)
    sink.start()
    try:
        with pytest.raises(IsolatedCiDenied, match="redirect"):
            isolated_tls_post(
                pinned_ip=ISOLATED_CI_PINNED_IP,
                port=sink.port,
                hostname=ISOLATED_CI_HOSTNAME,
                path="/isolated",
                body="{}",
                idempotency_key="k1",
                ca_file=sink.cert_file,
                timeout=2.0,
            )
    finally:
        sink.stop()


def test_hermetic_tls_verified_2xx_and_hostname_pin():
    sink = HermeticTlsCiSink(programmed_status=200)
    sink.start()
    try:
        os.environ["HTTP_PROXY"] = "http://127.0.0.1:9"
        os.environ["HTTPS_PROXY"] = "http://127.0.0.1:9"
        response = isolated_tls_post(
            pinned_ip=ISOLATED_CI_PINNED_IP,
            port=sink.port,
            hostname=ISOLATED_CI_HOSTNAME,
            path="/isolated",
            body='{"event":"tls"}',
            idempotency_key="tls-1",
            ca_file=sink.cert_file,
            timeout=2.0,
        )
        assert response.status == 200
        assert response.verified_hostname == ISOLATED_CI_HOSTNAME
        assert response.pinned_ip == ISOLATED_CI_PINNED_IP
        with pytest.raises(IsolatedCiDenied):
            isolated_tls_post(
                pinned_ip=ISOLATED_CI_PINNED_IP,
                port=sink.port,
                hostname="evil.example",
                path="/isolated",
                body="{}",
                idempotency_key="tls-bad-host",
                ca_file=sink.cert_file,
                timeout=2.0,
            )
    finally:
        os.environ.pop("HTTP_PROXY", None)
        os.environ.pop("HTTPS_PROXY", None)
        sink.stop()


def test_end_to_end_real_tls_sink_submit():
    sink = HermeticTlsCiSink(programmed_status=200)
    sink.start()
    try:
        c = conn()
        t, plan, _ = authorised_plan(c)
        arm_isolated(c)
        shadow(c, plan)
        token = token_for(c, plan, t)
        result = submit_isolated_live(
            c,
            tenant_id="tenant-a",
            user_id="user-a",
            plan_id=plan["execution_plan_id"],
            confirmation_token=token,
            role="owner",
            sink_port=sink.port,
            ca_file=sink.cert_file,
        )
        assert result["state"] == "EXECUTED"
        assert result["http_status"] == 200
        assert len(sink.received) == 1
    finally:
        sink.stop()


def test_receipts_are_append_only():
    c = conn()
    t, plan, _ = authorised_plan(c)
    arm_isolated(c)
    shadow(c, plan)
    token = token_for(c, plan, t)
    result = submit_isolated_live(
        c,
        tenant_id="tenant-a",
        user_id="user-a",
        plan_id=plan["execution_plan_id"],
        confirmation_token=token,
        role="owner",
        transport=ScriptedTransport([200]),
    )
    receipts = list_receipts_for_attempt(c, result["attempt_id"], "tenant-a")
    assert len(receipts) == 1
    from intelligence.execution_receipts import record_receipt

    record_receipt(
        c,
        tenant_id="tenant-a",
        attempt_id=result["attempt_id"],
        classification="isolated_ci_executed",
        extra={"note": "second evidence row"},
    )
    rows = list_receipts_for_attempt(c, result["attempt_id"], "tenant-a")
    assert len(rows) == 2
    assert rows[0]["id"] != rows[1]["id"]


def test_sandbox_provider_submit_still_closed():
    adapter = get_adapter("webhook.post")
    provider = WebhookSandboxProvider(adapter, production_mode=False)
    with pytest.raises(ProviderDenied):
        provider.submit({"id": "p"}, "k", 1.0)
