"""Phase 3 Stage 4A — production webhook pilot capability, switched off."""
from __future__ import annotations

import os
import sqlite3
import tempfile
import threading
from pathlib import Path

import pytest

from intelligence.execution import ensure_execution_schema, prepare
from intelligence.execution_adapters import (
    destination_hash,
    enable_adapter_policy,
    get_adapter,
    payload_hash,
    prepare_execution_plan,
    record_approval_binding,
)
from intelligence.execution_live import (
    LiveDenied,
    add_destination_allowlist,
    grant_live,
    issue_confirmation_token,
    set_kill_switch,
    shadow_execution_plan,
    submit_live,
)
from intelligence.execution_production_webhook import (
    HARD_MAX_PAYLOAD,
    ProductionPilotDenied,
    ProductionUncertain,
    ScriptedProductionTransport,
    SystemResolver,
    _in_transaction,
    build_signed_headers,
    classify_outcome,
    load_signing_secret,
    record_circuit_failure,
    recover_stale_production,
    request_target,
    select_production_provider,
    submit_production_pilot,
    validate_pilot_destination,
    verify_signature,
)
from intelligence.execution_providers import ClosedProvider, get_provider
from intelligence.execution_providers_webhook import DestinationDenied, StaticResolver
from intelligence.execution_receipts import list_receipts_for_attempt


DEST = "https://hooks.pilot.example/events"
PUBLIC_IP = "93.184.216.34"
PILOT_TENANT = "stage4a-pilot-tenant"
BODY = {"event": "pilot", "ref": "4a"}


def conn():
    c = sqlite3.connect(":memory:", check_same_thread=False)
    c.row_factory = sqlite3.Row
    ensure_execution_schema(c)
    return c


def _clear_pilot_env():
    for key in (
        "ZORVIAN_EXTERNAL_EXECUTION",
        "ZORVIAN_WEBHOOK_PILOT_ENABLED",
        "ZORVIAN_WEBHOOK_PILOT_TENANT_ID",
        "ZORVIAN_WEBHOOK_PILOT_HOST_SUFFIX",
        "ZORVIAN_WEBHOOK_PILOT_SIGNING_SECRET",
        "ZORVIAN_WEBHOOK_PILOT_SIGNING_SECRET_NEXT",
        "ZORVIAN_WEBHOOK_PILOT_KEY_ID",
        "ZORVIAN_WEBHOOK_PILOT_KEY_ID_NEXT",
        "ZORVIAN_ISOLATED_CI_EXECUTION",
    ):
        os.environ.pop(key, None)
    os.environ["ZORVIAN_ENV"] = "prod"


def arm_process():
    os.environ["ZORVIAN_EXTERNAL_EXECUTION"] = "pilot"
    os.environ["ZORVIAN_WEBHOOK_PILOT_ENABLED"] = "true"
    os.environ["ZORVIAN_ENV"] = "prod"
    os.environ["ZORVIAN_WEBHOOK_PILOT_TENANT_ID"] = PILOT_TENANT
    os.environ["ZORVIAN_WEBHOOK_PILOT_HOST_SUFFIX"] = "pilot.example"
    os.environ["ZORVIAN_WEBHOOK_PILOT_SIGNING_SECRET"] = "stage4a-test-signing-secret"
    os.environ["ZORVIAN_WEBHOOK_PILOT_KEY_ID"] = "key-test-1"


def authorised_plan(c, tenant=PILOT_TENANT, user="user-a", destination=DEST, body=None):
    body = body or dict(BODY)
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
        facts="Pilot webhook",
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


def _install_stage4c1_activation(c, *, tenant_id, destination, hostname_suffix, signing_key_id):
    from datetime import timedelta
    from intelligence.execution import _iso, _now
    from intelligence.execution_pilot_activation import (
        OWNER_IDS_ENV,
        SECURITY_IDS_ENV,
        activate_pilot,
        issue_activation_challenge,
        load_offline_platform_principal,
        record_platform_approval,
    )
    from intelligence.execution_pilot_ops import ADAPTER_ID, approve_pilot, bind_pilot_to_guardian_assessment, propose_pilot
    from intelligence.guardian import (
        GUARDIAN_POLICY_VERSION,
        PILOT_PURPOSE,
        assess as assess_guardian,
        canonical_pilot_context,
        guardian_policy_hash,
        persist_guardian_assessment,
    )
    os.environ.setdefault(OWNER_IDS_ENV, "plat-owner")
    os.environ.setdefault(SECURITY_IDS_ENV, "plat-sec")
    owner = load_offline_platform_principal(actor_id="plat-owner", requested_role="platform_owner")
    security = load_offline_platform_principal(actor_id="plat-sec", requested_role="security_operator")
    prep = propose_pilot(
        c,
        tenant_id=tenant_id,
        proposer_id="user-a",
        role="owner",
        destination=destination,
        hostname_suffix=hostname_suffix,
        signing_key_id=signing_key_id,
        reason="isolated 4a fixture",
        change_ref="CHG-4A",
        max_requests=1,
        max_exposure="none",
    )
    approve_pilot(c, tenant_id=tenant_id, pilot_id=prep["pilot_id"], approver_id="user-b", role="admin")
    row = c.execute("SELECT * FROM execution_pilot_preparations WHERE pilot_id=?", (prep["pilot_id"],)).fetchone()
    expiry = _iso(_now() + timedelta(hours=1))
    context = canonical_pilot_context(
        {
            "purpose": PILOT_PURPOSE,
            "pilot_id": row["pilot_id"],
            "tenant_id": tenant_id,
            "requesting_user_id": "user-a",
            "adapter_id": ADAPTER_ID,
            "action": "post_webhook",
            "destination_hash": row["destination_hash"],
            "manifest_hash": row["manifest_hash"],
            "policy_version": GUARDIAN_POLICY_VERSION,
            "policy_hash": guardian_policy_hash(),
            "consequential_action": True,
            "expiry": expiry,
        }
    )
    assessment = assess_guardian(
        tenant_id=tenant_id,
        user_id="user-a",
        role="owner",
        module="execution-gateway",
        action="post_webhook",
        facts="production_webhook_pilot exact context",
        consequential_action=True,
        identity_state="authenticated",
        session_state="normal",
        user_status="active",
        connection=c,
        pilot_context=context,
    )
    persist_guardian_assessment(c, assessment)
    bind_pilot_to_guardian_assessment(
        c,
        guardian_assessment_id=assessment.guardian_assessment_id,
        pilot_id=row["pilot_id"],
        tenant_id=tenant_id,
        actor_id="user-a",
    )
    if c.in_transaction:
        c.commit()
    record_platform_approval(c, pilot_id=row["pilot_id"], principal=owner)
    record_platform_approval(c, pilot_id=row["pilot_id"], principal=security)
    issued = issue_activation_challenge(c, pilot_id=row["pilot_id"], owner=owner, security=security)
    activate_pilot(c, pilot_id=row["pilot_id"], principal=owner, challenge_nonce=issued["nonce"])
    if c.in_transaction:
        c.commit()
    return row["pilot_id"]


def ready(c, grant=True, activate=True):
    arm_process()
    t, plan, body = authorised_plan(c)
    if grant:
        grant_live(c, tenant_id=PILOT_TENANT, adapter_id="webhook.post", action="post_webhook", env="prod", actor_id="ops", enabled=True)
    if activate and grant:
        _install_stage4c1_activation(
            c,
            tenant_id=PILOT_TENANT,
            destination=DEST,
            hostname_suffix="pilot.example",
            signing_key_id="key-test-1",
        )
    shadow_execution_plan(c, tenant_id=PILOT_TENANT, user_id="user-a", plan_id=plan["execution_plan_id"], role="owner")
    token = issue_confirmation_token(
        c,
        tenant_id=PILOT_TENANT,
        user_id="user-a",
        plan_id=plan["execution_plan_id"],
        approval_hash=plan.get("approval_hash"),
        idempotency_key=plan.get("idempotency_key"),
    )
    if c.in_transaction:
        c.commit()
    return t, plan, token, ScriptedProductionTransport([200]), StaticResolver({"hooks.pilot.example": [PUBLIC_IP]})


def test_default_production_cannot_execute():
    _clear_pilot_env()
    adapter = get_adapter("webhook.post")
    assert isinstance(get_provider(adapter), ClosedProvider)
    assert isinstance(get_provider(adapter, mode="production"), ClosedProvider)
    with pytest.raises(LiveDenied):
        submit_live()
    c = conn()
    assert isinstance(select_production_provider(adapter, connection=c, tenant_id="anyone"), ClosedProvider)


def test_missing_each_process_gate_denies():
    c = conn()
    adapter = get_adapter("webhook.post")
    arm_process()
    grant_live(c, tenant_id=PILOT_TENANT, adapter_id="webhook.post", action="post_webhook", env="prod", actor_id="ops", enabled=True)
    keys = [
        "ZORVIAN_EXTERNAL_EXECUTION",
        "ZORVIAN_WEBHOOK_PILOT_ENABLED",
        "ZORVIAN_WEBHOOK_PILOT_TENANT_ID",
        "ZORVIAN_WEBHOOK_PILOT_HOST_SUFFIX",
        "ZORVIAN_WEBHOOK_PILOT_SIGNING_SECRET",
        "ZORVIAN_WEBHOOK_PILOT_KEY_ID",
    ]
    for key in keys:
        saved = os.environ.pop(key)
        assert isinstance(select_production_provider(adapter, connection=c, tenant_id=PILOT_TENANT), ClosedProvider)
        os.environ[key] = saved
    os.environ["ZORVIAN_ENV"] = "test"
    assert isinstance(select_production_provider(adapter, connection=c, tenant_id=PILOT_TENANT), ClosedProvider)
    os.environ["ZORVIAN_ENV"] = "prod"


def test_wrong_tenant_and_adapter_denied():
    c = conn()
    t, plan, token, transport, resolver = ready(c)
    with pytest.raises(ProductionPilotDenied):
        submit_production_pilot(c, tenant_id="other-tenant", user_id="user-a", plan_id=plan["execution_plan_id"], confirmation_token=token, transport=transport, resolver=resolver)
    email_adapter = get_adapter("email.send")
    assert isinstance(select_production_provider(email_adapter, connection=c, tenant_id=PILOT_TENANT), ClosedProvider)


def test_missing_grant_and_empty_allowlist_and_secret():
    c = conn()
    t, plan, token, transport, resolver = ready(c, grant=False, activate=False)
    with pytest.raises(ProductionPilotDenied, match="grant"):
        submit_production_pilot(c, tenant_id=PILOT_TENANT, user_id="user-a", plan_id=plan["execution_plan_id"], confirmation_token=token, role="owner", transport=transport, resolver=resolver)
    grant_live(c, tenant_id=PILOT_TENANT, adapter_id="webhook.post", action="post_webhook", env="prod", actor_id="ops", enabled=True)
    _install_stage4c1_activation(
        c,
        tenant_id=PILOT_TENANT,
        destination=DEST,
        hostname_suffix="pilot.example",
        signing_key_id="key-test-1",
    )
    c.execute("DELETE FROM execution_destination_allowlist")
    if c.in_transaction:
        c.commit()
    with pytest.raises(ProductionPilotDenied, match="allowlist"):
        submit_production_pilot(c, tenant_id=PILOT_TENANT, user_id="user-a", plan_id=plan["execution_plan_id"], confirmation_token=token, role="owner", transport=transport, resolver=resolver)
    os.environ.pop("ZORVIAN_WEBHOOK_PILOT_SIGNING_SECRET")
    with pytest.raises(ProductionPilotDenied, match="signing secret"):
        load_signing_secret()


def test_hmac_signature_fields():
    arm_process()
    headers = build_signed_headers(body='{"a":1}', idempotency_key="abc")
    assert headers["X-Zorvian-Key-Id"] == "key-test-1"
    assert headers["X-Zorvian-Signature"].startswith("v1=")
    assert headers["X-Zorvian-Timestamp"]
    assert headers["X-Zorvian-Nonce"]
    assert verify_signature(headers, '{"a":1}', "abc") is True
    assert verify_signature(headers, '{"a":2}', "abc") is False
    blob = str(headers)
    assert "stage4a-test-signing-secret" not in blob


def test_secrets_never_in_receipts():
    c = conn()
    t, plan, token, transport, resolver = ready(c)
    result = submit_production_pilot(c, tenant_id=PILOT_TENANT, user_id="user-a", plan_id=plan["execution_plan_id"], confirmation_token=token, role="owner", transport=transport, resolver=resolver)
    rows = list_receipts_for_attempt(c, result["attempt_id"], PILOT_TENANT)
    dumped = str([dict(r) for r in rows]) + str(result)
    assert "stage4a-test-signing-secret" not in dumped
    assert result["external_execution_enabled"] is False
    assert result["exactly_once"] is False


def test_wrong_user_and_hash_change():
    c = conn()
    t, plan, token, transport, resolver = ready(c)
    with pytest.raises(ProductionPilotDenied, match="does not belong"):
        submit_production_pilot(c, tenant_id=PILOT_TENANT, user_id="other-user", plan_id=plan["execution_plan_id"], confirmation_token=token, role="owner", transport=transport, resolver=resolver)
    with pytest.raises(ProductionPilotDenied, match="payload change"):
        submit_production_pilot(c, tenant_id=PILOT_TENANT, user_id="user-a", plan_id=plan["execution_plan_id"], confirmation_token=token, role="owner", payload={"tampered": True}, transport=transport, resolver=resolver)


def test_dns_rebinding_and_private_address():
    c = conn()
    t, plan, token, transport, resolver = ready(c)

    class FlipResolver:
        def __init__(self):
            self.n = 0

        def resolve(self, hostname):
            self.n += 1
            return [PUBLIC_IP] if self.n == 1 else ["1.2.3.4"]

    with pytest.raises(DestinationDenied, match="DNS_REBINDING"):
        submit_production_pilot(c, tenant_id=PILOT_TENANT, user_id="user-a", plan_id=plan["execution_plan_id"], confirmation_token=token, role="owner", transport=transport, resolver=FlipResolver())

    c2 = conn()
    t2, plan2, token2, transport2, _ = ready(c2)
    with pytest.raises((ProductionPilotDenied, DestinationDenied)):
        submit_production_pilot(
            c2,
            tenant_id=PILOT_TENANT,
            user_id="user-a",
            plan_id=plan2["execution_plan_id"],
            confirmation_token=token2,
            role="owner",
            transport=transport2,
            resolver=StaticResolver({"hooks.pilot.example": ["127.0.0.1"]}),
        )


def test_outcomes_and_no_retry():
    assert classify_outcome(200) == "EXECUTED"
    assert classify_outcome(404) == "FAILED"
    assert classify_outcome(503) == "UNCERTAIN"
    c = conn()
    t, plan, token, _, resolver = ready(c)
    transport = ScriptedProductionTransport([503, 200])
    result = submit_production_pilot(c, tenant_id=PILOT_TENANT, user_id="user-a", plan_id=plan["execution_plan_id"], confirmation_token=token, role="owner", transport=transport, resolver=resolver)
    assert result["state"] == "UNCERTAIN"
    assert len(transport.calls) == 1
    replay = submit_production_pilot(c, tenant_id=PILOT_TENANT, user_id="user-a", plan_id=plan["execution_plan_id"], confirmation_token=token, role="owner", transport=transport, resolver=resolver)
    assert replay["idempotent_replay"] is True
    assert len(transport.calls) == 1


def test_timeout_uncertain():
    c = conn()
    t, plan, token, _, resolver = ready(c)
    result = submit_production_pilot(
        c,
        tenant_id=PILOT_TENANT,
        user_id="user-a",
        plan_id=plan["execution_plan_id"],
        confirmation_token=token,
        role="owner",
        transport=ScriptedProductionTransport([ProductionUncertain("timeout")]),
        resolver=resolver,
    )
    assert result["state"] == "UNCERTAIN"


def test_stale_recovery_does_not_submit():
    c = conn()
    t, plan, token, transport, resolver = ready(c)
    result = submit_production_pilot(c, tenant_id=PILOT_TENANT, user_id="user-a", plan_id=plan["execution_plan_id"], confirmation_token=token, role="owner", transport=ScriptedProductionTransport([ProductionUncertain("x")]), resolver=resolver)
    c.execute("UPDATE execution_attempts SET state='SUBMITTING', updated_at='2000-01-01T00:00:00Z' WHERE id=?", (result["attempt_id"],))
    recovered = recover_stale_production(c, tenant_id=PILOT_TENANT, older_than_seconds=1)
    assert result["attempt_id"] in recovered
    row = c.execute("SELECT submit_count FROM execution_pilot_attempts WHERE attempt_id=?", (result["attempt_id"],)).fetchone()
    assert row["submit_count"] == 1


def test_kill_switch_blocks():
    c = conn()
    t, plan, token, transport, resolver = ready(c)
    set_kill_switch(c, scope="global", enabled=True, reason="stop", actor_id="ops")
    with pytest.raises(ProductionPilotDenied, match="kill"):
        submit_production_pilot(c, tenant_id=PILOT_TENANT, user_id="user-a", plan_id=plan["execution_plan_id"], confirmation_token=token, role="owner", transport=transport, resolver=resolver)


def test_payload_limit():
    assert HARD_MAX_PAYLOAD == 32 * 1024
    c = conn()
    t, plan, token, transport, resolver = ready(c)
    with pytest.raises(ProductionPilotDenied, match="payload change"):
        submit_production_pilot(
            c,
            tenant_id=PILOT_TENANT,
            user_id="user-a",
            plan_id=plan["execution_plan_id"],
            confirmation_token=token,
            role="owner",
            payload={"blob": "x" * (HARD_MAX_PAYLOAD + 10)},
            transport=transport,
            resolver=resolver,
        )


def test_circuit_opens():
    arm_process()
    c = conn()
    grant_live(c, tenant_id=PILOT_TENANT, adapter_id="webhook.post", action="post_webhook", env="prod", actor_id="ops", enabled=True)
    from intelligence.execution_production_webhook import ensure_stage4a_schema

    ensure_stage4a_schema(c)
    for _ in range(5):
        record_circuit_failure(c, PILOT_TENANT, "webhook.post")
    t6, plan6, _ = authorised_plan(c, body={"event": "cb", "ref": "blocked"})
    shadow_execution_plan(c, tenant_id=PILOT_TENANT, user_id="user-a", plan_id=plan6["execution_plan_id"], role="owner")
    token6 = issue_confirmation_token(c, tenant_id=PILOT_TENANT, user_id="user-a", plan_id=plan6["execution_plan_id"], approval_hash=plan6.get("approval_hash"), idempotency_key=plan6.get("idempotency_key"))
    with pytest.raises(ProductionPilotDenied, match="circuit"):
        submit_production_pilot(
            c,
            tenant_id=PILOT_TENANT,
            user_id="user-a",
            plan_id=plan6["execution_plan_id"],
            confirmation_token=token6,
            role="owner",
            transport=ScriptedProductionTransport([200]),
            resolver=StaticResolver({"hooks.pilot.example": [PUBLIC_IP]}),
        )


def test_no_network_on_import_or_default_get_provider():
    _clear_pilot_env()
    import intelligence.execution_production_webhook as mod

    assert isinstance(get_provider(get_adapter("webhook.post")), ClosedProvider)
    assert "socket.create_connection" not in Path("intelligence/execution_providers.py").read_text()


def test_verified_2xx_and_duplicate():
    c = conn()
    t, plan, token, transport, resolver = ready(c)
    first = submit_production_pilot(c, tenant_id=PILOT_TENANT, user_id="user-a", plan_id=plan["execution_plan_id"], confirmation_token=token, role="owner", transport=transport, resolver=resolver)
    assert first["state"] == "EXECUTED"
    assert first["ticket_state"] == "CONSUMED"
    second = submit_production_pilot(c, tenant_id=PILOT_TENANT, user_id="user-a", plan_id=plan["execution_plan_id"], confirmation_token=token, role="owner", transport=transport, resolver=resolver)
    assert second["idempotent_replay"] is True
    assert len(transport.calls) == 1


def test_live_endpoint_exists_and_requires_auth():
    src = Path("app_gate5.py").read_text()
    assert '@app.post("/api/execution/plans/{plan_id}/live")' in src
    assert "confirmation token is required" in src
    assert "Tenant identity cannot be supplied by the client payload" in src


def test_tls_hostname_cannot_be_disabled():
    src = Path("intelligence/execution_production_webhook.py").read_text()
    assert "check_hostname = True" in src
    assert "CERT_REQUIRED" in src
    assert "TLSVersion.TLSv1_2" in src
    assert "HTTP_PROXY" in src
    assert "except sqlite3.OperationalError:\n        pass" not in src


class _HookedConn:
    def __init__(self, inner, fail_begin=False, fail_commit=False):
        self._inner = inner
        self.fail_begin = fail_begin
        self.fail_commit = fail_commit
        self.commits = 0

    def execute(self, sql, params=()):
        text = str(sql).strip().upper()
        if self.fail_begin and text.startswith("BEGIN IMMEDIATE"):
            raise sqlite3.OperationalError("database is locked")
        return self._inner.execute(sql, params)

    def commit(self):
        self.commits += 1
        if self.fail_commit and self.commits == 1:
            raise sqlite3.OperationalError("disk I/O error")
        return self._inner.commit()

    def rollback(self):
        return self._inner.rollback()

    def __getattr__(self, name):
        return getattr(self._inner, name)


def test_begin_immediate_failure_makes_zero_provider_calls():
    c = conn()
    t, plan, token, transport, resolver = ready(c)
    hooked = _HookedConn(c, fail_begin=True)
    with pytest.raises(ProductionPilotDenied, match="BEGIN IMMEDIATE"):
        submit_production_pilot(
            hooked,
            tenant_id=PILOT_TENANT,
            user_id="user-a",
            plan_id=plan["execution_plan_id"],
            confirmation_token=token,
            role="owner",
            transport=transport,
            resolver=resolver,
        )
    assert transport.calls == []
    assert _in_transaction(c) is False
    ticket = c.execute("SELECT execution_state FROM execution_tickets WHERE id=?", (t.execution_ticket_id,)).fetchone()
    assert ticket["execution_state"] != "CONSUMED"


def test_pre_io_commit_failure_makes_zero_provider_calls():
    c = conn()
    t, plan, token, transport, resolver = ready(c)

    def fail_claim_commit(_conn):
        raise sqlite3.OperationalError("disk I/O error")

    with pytest.raises(ProductionPilotDenied, match="claim transaction failed|pre-I/O commit|disk I/O"):
        submit_production_pilot(
            c,
            tenant_id=PILOT_TENANT,
            user_id="user-a",
            plan_id=plan["execution_plan_id"],
            confirmation_token=token,
            role="owner",
            transport=transport,
            resolver=resolver,
            _commit_claim=fail_claim_commit,
        )
    assert transport.calls == []
    assert _in_transaction(c) is False
    ticket = c.execute("SELECT execution_state FROM execution_tickets WHERE id=?", (t.execution_ticket_id,)).fetchone()
    assert ticket["execution_state"] != "CONSUMED"
    token_row = c.execute("SELECT consumed_at FROM execution_confirmation_tokens").fetchone()
    assert token_row["consumed_at"] is None
    attempts = c.execute("SELECT id FROM execution_attempts").fetchall()
    assert attempts == []
    plan_row = c.execute("SELECT status FROM execution_plans WHERE id=?", (plan["execution_plan_id"],)).fetchone()
    assert plan_row["status"] != "SUBMITTING"


def test_unexpected_exception_in_claim_rolls_back():
    c = conn()
    t, plan, token, transport, resolver = ready(c)

    def boom():
        raise RuntimeError("injected claim failure")

    with pytest.raises(RuntimeError, match="injected claim failure"):
        submit_production_pilot(
            c,
            tenant_id=PILOT_TENANT,
            user_id="user-a",
            plan_id=plan["execution_plan_id"],
            confirmation_token=token,
            role="owner",
            transport=transport,
            resolver=resolver,
            _after_claim_writes=boom,
        )
    assert transport.calls == []
    assert _in_transaction(c) is False
    ticket = c.execute("SELECT execution_state FROM execution_tickets WHERE id=?", (t.execution_ticket_id,)).fetchone()
    assert ticket["execution_state"] != "CONSUMED"
    assert c.execute("SELECT id FROM execution_attempts").fetchall() == []


def test_concurrent_identical_submissions_one_provider_call():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    bootstrap = sqlite3.connect(path)
    bootstrap.row_factory = sqlite3.Row
    from intelligence.execution import ensure_execution_schema

    ensure_execution_schema(bootstrap)
    t, plan, token, _, _ = ready(bootstrap)
    bootstrap.commit()
    bootstrap.close()

    transport = ScriptedProductionTransport([200, 200])
    resolver = StaticResolver({"hooks.pilot.example": [PUBLIC_IP]})
    results = []
    errors = []

    def worker():
        c = sqlite3.connect(path, timeout=5)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA busy_timeout=5000")
        try:
            results.append(
                submit_production_pilot(
                    c,
                    tenant_id=PILOT_TENANT,
                    user_id="user-a",
                    plan_id=plan["execution_plan_id"],
                    confirmation_token=token,
                    role="owner",
                    transport=transport,
                    resolver=resolver,
                )
            )
        except Exception as exc:
            errors.append(exc)
        finally:
            if c.in_transaction:
                c.rollback()
            assert c.in_transaction is False
            c.close()

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert errors == []
    assert len(results) == 2
    assert sum(1 for r in results if r.get("idempotent_replay")) == 1
    assert len(transport.calls) == 1
    inspect = sqlite3.connect(path)
    inspect.row_factory = sqlite3.Row
    tickets = inspect.execute("SELECT execution_state FROM execution_tickets").fetchall()
    consumed = [row for row in tickets if row["execution_state"] == "CONSUMED"]
    assert len(consumed) == 1
    tokens = inspect.execute("SELECT consumed_at FROM execution_confirmation_tokens").fetchall()
    assert sum(1 for row in tokens if row["consumed_at"]) == 1
    inspect.close()


def test_query_strings_rejected_not_rewritten():
    with pytest.raises(ProductionPilotDenied, match="query strings"):
        request_target("https://hooks.pilot.example/events?token=1")
    with pytest.raises(ProductionPilotDenied, match="query strings"):
        validate_pilot_destination(
            DEST + "?x=1",
            allowed_hashes=["deadbeef"],
            resolver=StaticResolver({"hooks.pilot.example": [PUBLIC_IP]}),
            plan_id="plan",
        )


def test_denial_leaves_no_open_transaction():
    c = conn()
    t, plan, token, transport, resolver = ready(c)
    with pytest.raises(ProductionPilotDenied):
        submit_production_pilot(
            c,
            tenant_id=PILOT_TENANT,
            user_id="user-a",
            plan_id=plan["execution_plan_id"],
            confirmation_token="wrong-token",
            role="owner",
            transport=transport,
            resolver=resolver,
        )
    assert _in_transaction(c) is False
    assert transport.calls == []
