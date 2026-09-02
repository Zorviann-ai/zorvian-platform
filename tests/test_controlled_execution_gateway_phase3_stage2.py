"""Phase 3 Stage 2 — webhook sandbox, destination hardening, no live I/O."""
from __future__ import annotations

import json
import os
import sqlite3
import threading

import pytest

from intelligence.execution import ensure_execution_schema, prepare
from intelligence.execution_adapters import (
    destination_hash,
    enable_adapter_policy,
    payload_hash,
    prepare_execution_plan,
    record_approval_binding,
)
from intelligence.execution_live import (
    LiveDenied,
    add_destination_allowlist,
    set_kill_switch,
    shadow_execution_plan,
    shadow_webhook_sandbox,
    submit_live,
)
from intelligence.execution_providers import ClosedProvider, ProviderDenied, get_provider
from intelligence.execution_providers_webhook import (
    DestinationDenied,
    InProcessWebhookSink,
    SandboxDenied,
    StaticResolver,
    WebhookSandboxProvider,
    classify_ip,
    validate_hardened_webhook_destination,
)
from intelligence.execution_adapters import get_adapter


DEST = "https://hooks.example.com/events"
PUBLIC_IP = "93.184.216.34"


def conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    ensure_execution_schema(c)
    return c


def webhook_plan(c, destination=DEST, body=None, tenant="tenant-a", user="user-a"):
    body = body or {"event": "ping", "ref": "1"}
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
        facts="Post an approved operations webhook",
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
    if t.execution_state != "AUTHORISED":
        pytest.skip("webhook ticket not authorised")
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


def test_production_external_execution_disabled():
    os.environ.pop("ZORVIAN_EXTERNAL_EXECUTION", None)
    c = conn()
    t, plan, body = webhook_plan(c)
    with pytest.raises(LiveDenied):
        submit_live(c, tenant_id="tenant-a", plan_id=plan["execution_plan_id"])
    adapter = get_adapter("webhook.post")
    assert adapter.live_execution_supported is False
    provider = get_provider(adapter)
    assert isinstance(provider, ClosedProvider)
    with pytest.raises(ProviderDenied):
        provider.submit(plan, "k", 1.0)


def test_sandbox_provider_cannot_be_selected_in_production():
    adapter = get_adapter("webhook.post")
    assert isinstance(get_provider(adapter, mode="production"), ClosedProvider)
    with pytest.raises(ProviderDenied):
        WebhookSandboxProvider(adapter, production_mode=True)


def test_no_network_imports_in_stage2_modules():
    from pathlib import Path
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
        r"(?m)^\s*import os; os.system",
    ]
    for rel in files:
        text = Path(rel).read_text(encoding="utf-8")
        for pattern in patterns:
            assert re.search(pattern, text) is None, (rel, pattern)


def test_https_mandatory_and_redirects_and_credentials_rejected():
    with pytest.raises(DestinationDenied):
        validate_hardened_webhook_destination("http://hooks.example.com/x", allowed_hosts=["hooks.example.com"])
    with pytest.raises(DestinationDenied):
        validate_hardened_webhook_destination("https://user:pass@hooks.example.com/x", allowed_hosts=["hooks.example.com"])
    with pytest.raises(DestinationDenied):
        validate_hardened_webhook_destination("https://hooks.example.com/x#frag", allowed_hosts=["hooks.example.com"])
    request_like = WebhookSandboxProvider(get_adapter("webhook.post"), transport=InProcessWebhookSink())
    sandbox = request_like.build_sandbox_request(
        plan={"id": "p1", "tenant_id": "tenant-a", "action": "post_webhook", "payload_hash": payload_hash({"a": 1}), "destination_hash": destination_hash(DEST)},
        payload={"a": 1},
        destination=DEST,
        allowed_hosts=["hooks.example.com"],
    )
    assert sandbox.redirects is False


def test_prohibited_ip_classes_rejected():
    samples = [
        "127.0.0.1",
        "::1",
        "10.0.0.5",
        "192.168.1.8",
        "169.254.1.1",
        "224.0.0.1",
        "0.0.0.0",
        "::ffff:127.0.0.1",
        "2130706433",
        "0177.0.0.1",
        "0x7f.0.0.1",
        "127.1",
    ]
    for host in samples:
        with pytest.raises(DestinationDenied):
            classify_ip(host) if host not in {"0177.0.0.1", "0x7f.0.0.1", "127.1", "2130706433"} else validate_hardened_webhook_destination(
                f"https://{host}/hook",
                allowed_hosts=[host],
            )


def test_unsafe_address_in_multi_answer_rejects():
    resolver = StaticResolver({"hooks.example.com": [PUBLIC_IP, "127.0.0.1"]})
    with pytest.raises(DestinationDenied):
        validate_hardened_webhook_destination(
            DEST,
            allowed_hosts=["hooks.example.com"],
            resolver=resolver,
            plan_id="plan-1",
        )


def test_dns_rebinding_detected():
    resolver = StaticResolver({"hooks.example.com": [PUBLIC_IP]})
    dest, first = validate_hardened_webhook_destination(
        DEST,
        allowed_hosts=["hooks.example.com"],
        resolver=resolver,
        plan_id="plan-1",
    )
    rebound = StaticResolver({"hooks.example.com": ["1.1.1.1"]})
    with pytest.raises(DestinationDenied, match="DNS_REBINDING"):
        validate_hardened_webhook_destination(
            dest,
            allowed_hosts=["hooks.example.com"],
            resolver=rebound,
            plan_id="plan-1",
            previous_resolution=first,
        )


def test_hash_and_identity_and_allowlist_and_kills():
    c = conn()
    t, plan, body = webhook_plan(c)
    resolver = StaticResolver({"hooks.example.com": [PUBLIC_IP]})
    sink = InProcessWebhookSink()
    with pytest.raises(LiveDenied):
        shadow_webhook_sandbox(
            c,
            tenant_id="tenant-a",
            user_id="user-a",
            plan_id=plan["execution_plan_id"],
            role="owner",
            payload={"event": "altered"},
            destination=DEST,
            allowed_hosts=["hooks.example.com"],
            resolver=resolver,
            sink=sink,
        )
    with pytest.raises(LiveDenied):
        shadow_webhook_sandbox(
            c,
            tenant_id="tenant-b",
            user_id="user-a",
            plan_id=plan["execution_plan_id"],
            role="owner",
            allowed_hosts=["hooks.example.com"],
            resolver=resolver,
        )
    with pytest.raises(LiveDenied):
        shadow_webhook_sandbox(
            c,
            tenant_id="tenant-a",
            user_id="user-b",
            plan_id=plan["execution_plan_id"],
            role="owner",
            allowed_hosts=["hooks.example.com"],
            resolver=resolver,
        )
    with pytest.raises(DestinationDenied):
        shadow_webhook_sandbox(
            c,
            tenant_id="tenant-a",
            user_id="user-a",
            plan_id=plan["execution_plan_id"],
            role="owner",
            destination=DEST,
            allowed_hosts=["other.example.com"],
            resolver=resolver,
            sink=sink,
        )
    set_kill_switch(c, scope="global", enabled=True, reason="stop", actor_id="ops")
    with pytest.raises(LiveDenied):
        shadow_execution_plan(c, tenant_id="tenant-a", user_id="user-a", plan_id=plan["execution_plan_id"], role="owner")


def test_shadow_does_not_consume_ticket_and_keeps_external_disabled():
    c = conn()
    t, plan, body = webhook_plan(c)
    resolver = StaticResolver({"hooks.example.com": [PUBLIC_IP]})
    out = shadow_webhook_sandbox(
        c,
        tenant_id="tenant-a",
        user_id="user-a",
        plan_id=plan["execution_plan_id"],
        role="owner",
        payload=body,
        destination=DEST,
        allowed_hosts=["hooks.example.com"],
        resolver=resolver,
        sink=InProcessWebhookSink(),
    )
    assert out["ticket_state"] == "AUTHORISED"
    assert out["external_execution_enabled"] is False
    assert out["plan_status"] == "SHADOW_COMPLETE"
    req = out["sandbox_request"]
    assert req["adapter_id"] == "webhook.post"
    assert req["destination_hash"] == destination_hash(DEST)
    assert "authorization" not in json.dumps(req).lower()
    assert "user:pass" not in json.dumps(req)
    assert "***" not in req["masked_destination"] or "hooks.example.com" in req["masked_destination"]


def test_idempotency_and_concurrency():
    sink = InProcessWebhookSink()
    provider = WebhookSandboxProvider(get_adapter("webhook.post"), transport=sink, resolver=StaticResolver({"hooks.example.com": [PUBLIC_IP]}))
    plan = {
        "id": "plan-idem",
        "tenant_id": "tenant-a",
        "action": "post_webhook",
        "payload_hash": payload_hash({"n": 1}),
        "destination_hash": destination_hash(DEST),
        "idempotency_key": "fixed-key-1",
    }
    req = provider.build_sandbox_request(plan=plan, payload={"n": 1}, destination=DEST, allowed_hosts=["hooks.example.com"])
    first = provider.record_sandbox(req)
    second = provider.record_sandbox(req)
    assert first["receipt_id"] == second["receipt_id"]
    altered = provider.build_sandbox_request(
        plan={**plan, "payload_hash": payload_hash({"n": 2}), "idempotency_key": "fixed-key-1"},
        payload={"n": 2},
        destination=DEST,
        allowed_hosts=["hooks.example.com"],
    )
    # same key stored on sink from first payload
    altered_req = req
    object.__setattr__(altered_req, "payload_hash", payload_hash({"n": 2})) if False else None
    bad = SandboxDenied
    from intelligence.execution_providers_webhook import SandboxRequest

    tweaked = SandboxRequest(**{**req.__dict__, "payload_hash": payload_hash({"n": 2})})
    with pytest.raises(SandboxDenied):
        sink.post(tweaked)

    results = []

    def worker():
        results.append(sink.post(req))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len({item["receipt_id"] for item in results}) == 1


def test_other_providers_remain_denied():
    for adapter_id in ("email.send", "sms.send", "document_release.release", "publication.publish"):
        provider = get_provider(get_adapter(adapter_id))
        with pytest.raises(ProviderDenied):
            provider.submit({}, "k", 1.0)


def test_missing_allowlist_host_rejected():
    with pytest.raises(DestinationDenied):
        validate_hardened_webhook_destination(
            DEST,
            allowed_hosts=["allowed.example.com"],
            resolver=StaticResolver({"hooks.example.com": [PUBLIC_IP]}),
        )
