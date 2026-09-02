from __future__ import annotations

import os
import sqlite3
import tempfile
import threading
from datetime import timedelta
from pathlib import Path

import pytest

from intelligence.execution import _iso, _now, ensure_execution_schema
from intelligence.execution_adapters import get_adapter
from intelligence.execution_pilot_activation import (
    OWNER_IDS_ENV,
    SECURITY_IDS_ENV,
    ActivationDenied,
    PlatformPrincipal,
    activate_pilot,
    claim_activation_success,
    enforce_activation_for_runtime,
    issue_activation_challenge,
    load_offline_platform_principal,
    record_platform_approval,
)
from intelligence.execution_pilot_ops import ADAPTER_ID
from intelligence.execution_pilot_reconciliation import (
    ReconciliationDenied,
    assert_no_public_4c2_routes,
    ensure_stage4c2_schema,
    inspect_attempt_redacted,
    list_uncertain_attempts,
    maintain_pilot_runtime,
    observe_pilot_runtime,
    record_reconciliation,
    require_exact_activation_binding,
)
from intelligence.execution_production_webhook import (
    PILOT_KEY_ID_ENV,
    PILOT_SECRET_ENV,
    ProductionPilotDenied,
    ProductionTlsResponse,
    ProductionUncertain,
    ScriptedProductionTransport,
    classify_outcome,
    evaluate_pilot_runtime_gates,
    recover_stale_production,
    request_production_cancel,
    select_production_provider,
    submit_production_pilot,
)
from intelligence.execution_providers import ClosedProvider, get_provider
from intelligence.execution_providers_webhook import StaticResolver

from tests.test_controlled_execution_gateway_phase3_stage4c1 import (
    DEST,
    OWNER,
    SEC,
    SUFFIX,
    TENANT,
    _approve_both,
    _arm_secret,
    _challenge,
    _ready_pilot,
    owner,
    security,
)
from tests.test_controlled_execution_gateway_phase3_stage4a import (
    BODY,
    PILOT_TENANT,
    PUBLIC_IP,
    ready as ready_4a,
)


def conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    ensure_stage4c2_schema(c)
    if c.in_transaction:
        c.commit()
    return c


@pytest.fixture(autouse=True)
def _clean():
    for key in [
        "ZORVIAN_EXTERNAL_EXECUTION",
        "ZORVIAN_WEBHOOK_PILOT_ENABLED",
        "ZORVIAN_WEBHOOK_PILOT_TENANT_ID",
        "ZORVIAN_WEBHOOK_PILOT_HOST_SUFFIX",
        PILOT_SECRET_ENV,
        PILOT_KEY_ID_ENV,
        OWNER_IDS_ENV,
        SECURITY_IDS_ENV,
        "ZORVIAN_ENV",
    ]:
        os.environ.pop(key, None)
    os.environ[OWNER_IDS_ENV] = OWNER
    os.environ[SECURITY_IDS_ENV] = SEC
    yield
    os.environ.pop(OWNER_IDS_ENV, None)
    os.environ.pop(SECURITY_IDS_ENV, None)


def _activated(c):
    prep = _ready_pilot(c)
    _arm_secret()
    _approve_both(c, prep["pilot_id"])
    issued = _challenge(c, prep["pilot_id"])
    activate_pilot(c, pilot_id=prep["pilot_id"], principal=owner(), challenge_nonce=issued["nonce"])
    if c.in_transaction:
        c.commit()
    return prep


def test_default_provider_remains_closed():
    assert isinstance(get_provider(get_adapter("webhook.post")), ClosedProvider)
    routes = assert_no_public_4c2_routes()
    assert routes["activate_route"] is False
    assert routes["reconcile_route"] is False


def test_bootstrap_creates_no_pilot_grant_or_secret():
    c = conn()
    assert c.execute("SELECT COUNT(*) AS n FROM execution_pilot_activations").fetchone()["n"] == 0
    assert c.execute("SELECT COUNT(*) AS n FROM execution_live_grants WHERE enabled=1").fetchone()["n"] == 0
    assert c.execute("SELECT COUNT(*) AS n FROM execution_destination_allowlist").fetchone()["n"] == 0
    assert os.getenv(PILOT_SECRET_ENV) in {None, ""}


def test_missing_activation_denies_zero_provider():
    c = conn()
    transport = ScriptedProductionTransport([200])
    with pytest.raises((ActivationDenied, ProductionPilotDenied)):
        evaluate_pilot_runtime_gates(c, tenant_id=TENANT, adapter_id=ADAPTER_ID, action="post_webhook")
    assert isinstance(select_production_provider(get_adapter("webhook.post"), connection=c, tenant_id=TENANT), ClosedProvider)
    assert transport.calls == []


def test_non_active_and_expired_close_grant_allowlist():
    c = conn()
    _activated(c)
    c.execute("UPDATE execution_pilot_activations SET status='SUSPENDED'")
    if c.in_transaction:
        c.commit()
    with pytest.raises(ActivationDenied):
        claim_activation_success(c, tenant_id=TENANT, adapter_id=ADAPTER_ID)
    c2 = conn()
    prep2 = _activated(c2)
    dest_h = prep2["destination_hash"]
    c2.execute("UPDATE execution_pilot_activations SET expires_at=?", (_iso(_now() - timedelta(minutes=1)),))
    if c2.in_transaction:
        c2.commit()
    with pytest.raises(ActivationDenied):
        enforce_activation_for_runtime(c2, tenant_id=TENANT, adapter_id=ADAPTER_ID, action="post_webhook")
    assert c2.execute("SELECT enabled FROM execution_live_grants WHERE tenant_id=?", (TENANT,)).fetchone()["enabled"] == 0
    assert c2.execute(
        "SELECT COUNT(*) AS n FROM execution_destination_allowlist WHERE tenant_id=? AND destination_hash=?",
        (TENANT, dest_h),
    ).fetchone()["n"] == 0


def _conn_activated():
    c = conn()
    c._prep = _activated(c)
    return c


def test_exact_binding_mismatches_denied():
    c = conn()
    prep = _activated(c)
    act = c.execute("SELECT * FROM execution_pilot_activations WHERE pilot_id=?", (prep["pilot_id"],)).fetchone()
    with pytest.raises(ActivationDenied):
        require_exact_activation_binding(
            c, tenant_id="other", adapter_id=ADAPTER_ID, action="post_webhook",
            pilot_id=prep["pilot_id"], destination_hash=prep["destination_hash"],
            manifest_hash=prep["manifest_hash"], signing_key_id="k1",
        )
    with pytest.raises(ActivationDenied):
        require_exact_activation_binding(
            c, tenant_id=TENANT, adapter_id=ADAPTER_ID, action="email.send",
            pilot_id=prep["pilot_id"], destination_hash=prep["destination_hash"],
            manifest_hash=prep["manifest_hash"], signing_key_id="k1",
        )
    with pytest.raises(ActivationDenied):
        require_exact_activation_binding(
            c, tenant_id=TENANT, adapter_id=ADAPTER_ID, action="post_webhook",
            pilot_id=prep["pilot_id"], destination_hash="ff" * 32,
            manifest_hash=prep["manifest_hash"], signing_key_id="k1",
        )
    with pytest.raises(ActivationDenied):
        require_exact_activation_binding(
            c, tenant_id=TENANT, adapter_id=ADAPTER_ID, action="post_webhook",
            pilot_id=prep["pilot_id"], destination_hash=prep["destination_hash"],
            manifest_hash="ab" * 32, signing_key_id="k1",
        )
    with pytest.raises(ActivationDenied):
        require_exact_activation_binding(
            c, tenant_id=TENANT, adapter_id=ADAPTER_ID, action="post_webhook",
            pilot_id=prep["pilot_id"], destination_hash=prep["destination_hash"],
            manifest_hash=prep["manifest_hash"], signing_key_id="other-key",
        )
    with pytest.raises(ActivationDenied):
        require_exact_activation_binding(
            c, tenant_id=TENANT, adapter_id=ADAPTER_ID, action="post_webhook",
            pilot_id=prep["pilot_id"], destination_hash=prep["destination_hash"],
            manifest_hash=prep["manifest_hash"], signing_key_id="k1",
            guardian_assessment_id="wrong",
        )
    with pytest.raises(ActivationDenied):
        require_exact_activation_binding(
            c, tenant_id=TENANT, adapter_id=ADAPTER_ID, action="post_webhook",
            pilot_id=prep["pilot_id"], destination_hash=prep["destination_hash"],
            manifest_hash=prep["manifest_hash"], signing_key_id="k1",
            guardian_context_hash="00" * 32,
        )
    with pytest.raises(ActivationDenied):
        require_exact_activation_binding(
            c, tenant_id=TENANT, adapter_id=ADAPTER_ID, action="post_webhook",
            pilot_id=prep["pilot_id"], destination_hash=prep["destination_hash"],
            manifest_hash=prep["manifest_hash"], signing_key_id="k1",
            policy_version="not-the-policy",
        )
    bound = require_exact_activation_binding(
        c, tenant_id=TENANT, adapter_id=ADAPTER_ID, action="post_webhook",
        pilot_id=prep["pilot_id"], destination_hash=prep["destination_hash"],
        manifest_hash=prep["manifest_hash"], signing_key_id="k1",
        guardian_assessment_id=act["guardian_assessment_id"],
        guardian_context_hash=act["guardian_context_hash"],
        policy_version=act["policy_version"],
        policy_hash=act["policy_hash"],
    )
    assert bound["pilot_id"] == prep["pilot_id"]


def test_quota_claim_closes_grant_and_allowlist():
    c = conn()
    prep = _activated(c)
    dest_h = prep["destination_hash"]
    claim_activation_success(c, tenant_id=TENANT, adapter_id=ADAPTER_ID)
    if c.in_transaction:
        c.commit()
    act = c.execute("SELECT * FROM execution_pilot_activations WHERE pilot_id=?", (prep["pilot_id"],)).fetchone()
    assert act["successes_claimed"] == 1
    assert act["status"] == "QUOTA_EXHAUSTED"
    assert c.execute("SELECT enabled FROM execution_live_grants WHERE tenant_id=?", (TENANT,)).fetchone()["enabled"] == 0
    assert c.execute(
        "SELECT COUNT(*) AS n FROM execution_destination_allowlist WHERE destination_hash=?",
        (dest_h,),
    ).fetchone()["n"] == 0
    transport = ScriptedProductionTransport([200])
    assert isinstance(select_production_provider(get_adapter("webhook.post"), connection=c, tenant_id=TENANT), ClosedProvider)
    assert transport.calls == []


def test_begin_and_commit_failure_zero_provider(monkeypatch):
    c = conn()
    prep = _activated(c)
    transport = ScriptedProductionTransport([200])

    def boom(_c):
        raise sqlite3.OperationalError("cannot start")

    monkeypatch.setattr("intelligence.execution_pilot_activation._begin_immediate", boom)
    with pytest.raises(sqlite3.Error):
        claim_activation_success(c, tenant_id=TENANT, adapter_id=ADAPTER_ID)
    assert transport.calls == []
    assert c.execute("SELECT successes_claimed FROM execution_pilot_activations").fetchone()["successes_claimed"] == 0


def test_commit_failure_zero_partial(monkeypatch):
    c = conn()
    _activated(c)
    transport = ScriptedProductionTransport([200])

    def boom(_c):
        raise sqlite3.OperationalError("commit failed")

    monkeypatch.setattr("intelligence.execution_pilot_activation._commit_activation_claim", boom)
    with pytest.raises(sqlite3.OperationalError):
        claim_activation_success(c, tenant_id=TENANT, adapter_id=ADAPTER_ID)
    assert transport.calls == []


def test_outcome_classes_and_no_retry():
    assert classify_outcome(200) == "EXECUTED"
    assert classify_outcome(404) == "FAILED"
    assert classify_outcome(500) == "UNCERTAIN"
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    ensure_execution_schema(c)
    now = _iso(_now() - timedelta(minutes=5))
    c.execute(
        """INSERT INTO execution_attempts(id,tenant_id,plan_id,ticket_id,adapter_id,idempotency_key,state,provider_ref,created_at,updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        ("att-1", TENANT, "plan", "tix", ADAPTER_ID, "idem", "SUBMITTING", None, now, now),
    )
    if c.in_transaction:
        c.commit()
    recovered = recover_stale_production(c, tenant_id=TENANT, older_than_seconds=1)
    assert recovered == ["att-1"]
    assert c.execute("SELECT state FROM execution_attempts WHERE id='att-1'").fetchone()["state"] == "UNCERTAIN"


def test_reconciliation_requires_principal_and_is_append_only():
    c = conn()
    _activated(c)
    now = _iso()
    act = c.execute("SELECT activation_id, pilot_id FROM execution_pilot_activations").fetchone()
    c.execute(
        """INSERT INTO execution_attempts(id,tenant_id,plan_id,ticket_id,adapter_id,idempotency_key,state,provider_ref,created_at,updated_at,activation_id,pilot_id)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        ("att-r", TENANT, "plan", "tix", ADAPTER_ID, "idem", "UNCERTAIN", None, now, now, act["activation_id"], act["pilot_id"]),
    )
    if c.in_transaction:
        c.commit()
    with pytest.raises((ActivationDenied, ReconciliationDenied)):
        record_reconciliation(
            c, principal=PlatformPrincipal("user-a", "owner"), tenant_id=TENANT,
            attempt_id="att-r", decision="confirmed-failure",
        )
    first = record_reconciliation(c, principal=owner(), tenant_id=TENANT, attempt_id="att-r", decision="unresolved")
    assert first["provider_calls"] == 0
    listed = list_uncertain_attempts(c, principal=owner(), tenant_id=TENANT)
    assert listed[0]["signing_secret"] is None
    second = record_reconciliation(c, principal=security(), tenant_id=TENANT, attempt_id="att-r", decision="confirmed-failure")
    assert second["provider_calls"] == 0
    n = c.execute("SELECT COUNT(*) AS n FROM execution_pilot_reconciliations WHERE attempt_id='att-r'").fetchone()["n"]
    assert n == 2
    assert c.execute("SELECT state FROM execution_attempts WHERE id='att-r'").fetchone()["state"] == "RECONCILED_FAILURE"
    with pytest.raises(ReconciliationDenied):
        record_reconciliation(c, principal=owner(), tenant_id=TENANT, attempt_id="att-r", decision="confirmed-success")
    redacted = inspect_attempt_redacted(c, principal=owner(), tenant_id=TENANT, attempt_id="att-r")
    assert redacted["payload"] is None
    assert redacted["destination"] is None
    assert "secret" not in str(redacted).lower() or redacted["signing_secret"] is None


def test_observability_select_only_and_redacted():
    c = conn()
    prep = _activated(c)
    write_codes = {
        getattr(sqlite3, name)
        for name in (
            "SQLITE_CREATE_INDEX", "SQLITE_CREATE_TABLE", "SQLITE_DELETE", "SQLITE_DROP_TABLE",
            "SQLITE_INSERT", "SQLITE_UPDATE", "SQLITE_ALTER_TABLE", "SQLITE_DROP_INDEX", "SQLITE_REPLACE",
        )
        if hasattr(sqlite3, name)
    }
    traced = []

    def tracer(statement):
        traced.append(statement)

    def authorizer(action, arg1, arg2, dbname, source):
        if action in write_codes:
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    c.set_trace_callback(tracer)
    c.set_authorizer(authorizer)
    try:
        view = observe_pilot_runtime(c, principal=owner(), tenant_id=TENANT, pilot_id=prep["pilot_id"])
    finally:
        c.set_authorizer(None)
        c.set_trace_callback(None)
    assert view["external_execution_enabled"] is False
    assert view["destination"] is None
    assert view["signing_secret"] is None
    for statement in traced:
        lead = statement.strip().split(None, 1)[0].upper() if statement.strip() else ""
        assert lead in {"SELECT", "BEGIN", "COMMIT", ""}


def test_maintenance_idempotent_no_network():
    c = conn()
    prep = _activated(c)
    c.execute("UPDATE execution_pilot_activations SET expires_at=?", (_iso(_now() - timedelta(minutes=1)),))
    if c.in_transaction:
        c.commit()
    first = maintain_pilot_runtime(c)
    second = maintain_pilot_runtime(c)
    assert first["provider_calls"] == second["provider_calls"] == 0
    assert c.execute("SELECT status FROM execution_pilot_activations WHERE pilot_id=?", (prep["pilot_id"],)).fetchone()["status"] in {"EXPIRED", "SUSPENDED", "QUOTA_EXHAUSTED"}
    assert c.execute("SELECT enabled FROM execution_live_grants WHERE tenant_id=?", (TENANT,)).fetchone()["enabled"] == 0


def test_4a_submit_missing_activation_makes_zero_calls():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    ensure_execution_schema(c)
    t, plan, token, transport, resolver = ready_4a(c, grant=True, activate=False)
    with pytest.raises(ProductionPilotDenied):
        submit_production_pilot(
            c, tenant_id=PILOT_TENANT, user_id="user-a", plan_id=plan["execution_plan_id"],
            confirmation_token=token, role="owner", transport=transport, resolver=resolver,
        )
    assert transport.calls == []


def test_4a_uncertain_does_not_retry_provider():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    ensure_execution_schema(c)
    t, plan, token, _, resolver = ready_4a(c)
    transport = ScriptedProductionTransport([ProductionUncertain("timeout")])
    result = submit_production_pilot(
        c, tenant_id=PILOT_TENANT, user_id="user-a", plan_id=plan["execution_plan_id"],
        confirmation_token=token, role="owner", transport=transport, resolver=resolver,
    )
    assert result["state"] == "UNCERTAIN"
    replay = submit_production_pilot(
        c, tenant_id=PILOT_TENANT, user_id="user-a", plan_id=plan["execution_plan_id"],
        confirmation_token=token, role="owner", transport=transport, resolver=resolver,
    )
    assert replay.get("idempotent_replay") is True
    assert len(transport.calls) == 1


def test_static_routes_and_docs():
    src = Path("app_gate5.py").read_text()
    assert "/activate" not in src
    assert "/reconcile" not in src
    assert Path("CONTROLLED_EXECUTION_GATEWAY_PHASE3_STAGE4C2_RUNBOOK.md").exists()


def test_submit_calls_exact_binding_before_transport(monkeypatch):
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    ensure_execution_schema(c)
    called = {"n": 0}
    real = require_exact_activation_binding

    def wrapped(*args, **kwargs):
        called["n"] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr("intelligence.execution_pilot_reconciliation.require_exact_activation_binding", wrapped)
    t, plan, token, transport, resolver = ready_4a(c)
    submit_production_pilot(
        c, tenant_id=PILOT_TENANT, user_id="user-a", plan_id=plan["execution_plan_id"],
        confirmation_token=token, role="owner", transport=transport, resolver=resolver,
    )
    assert called["n"] >= 1
    assert len(transport.calls) == 1
    row = c.execute("SELECT activation_id, pilot_id FROM execution_attempts").fetchone()
    assert row["activation_id"]
    assert row["pilot_id"]


def test_concurrent_identical_submits_one_provider_call():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    bootstrap = sqlite3.connect(path)
    bootstrap.row_factory = sqlite3.Row
    ensure_execution_schema(bootstrap)
    t, plan, token, _, _ = ready_4a(bootstrap)
    bootstrap.commit()
    bootstrap.close()
    transport = ScriptedProductionTransport([200, 200])
    resolver = StaticResolver({"hooks.pilot.example": [PUBLIC_IP]})
    results, errors = [], []

    def worker():
        c = sqlite3.connect(path, timeout=5)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA busy_timeout=5000")
        try:
            results.append(
                submit_production_pilot(
                    c, tenant_id=PILOT_TENANT, user_id="user-a", plan_id=plan["execution_plan_id"],
                    confirmation_token=token, role="owner", transport=transport, resolver=resolver,
                )
            )
        except Exception as exc:
            errors.append(exc)
        finally:
            c.close()

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert errors == []
    assert sum(1 for r in results if r.get("idempotent_replay")) == 1
    assert len(transport.calls) == 1
    inspect = sqlite3.connect(path)
    inspect.row_factory = sqlite3.Row
    assert inspect.execute("SELECT COUNT(*) AS n FROM execution_tickets WHERE execution_state='CONSUMED'").fetchone()["n"] == 1
    assert inspect.execute("SELECT COUNT(*) AS n FROM execution_confirmation_tokens WHERE consumed_at IS NOT NULL").fetchone()["n"] == 1
    inspect.close()


def test_altered_payload_same_idempotency_denied():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    ensure_execution_schema(c)
    t, plan, token, transport, resolver = ready_4a(c)
    with pytest.raises(ProductionPilotDenied, match="payload"):
        submit_production_pilot(
            c, tenant_id=PILOT_TENANT, user_id="user-a", plan_id=plan["execution_plan_id"],
            confirmation_token=token, role="owner", transport=transport, resolver=resolver,
            payload={"changed": True},
        )
    assert transport.calls == []


def test_exact_classifications_and_cancel_late_success():
    assert classify_outcome(201) == "EXECUTED"
    assert classify_outcome(409) == "FAILED"
    assert classify_outcome(503) == "UNCERTAIN"
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    ensure_execution_schema(c)
    t, plan, token, _, resolver = ready_4a(c)
    transport = ScriptedProductionTransport([200])
    out = submit_production_pilot(
        c, tenant_id=PILOT_TENANT, user_id="user-a", plan_id=plan["execution_plan_id"],
        confirmation_token=token, role="owner", transport=transport, resolver=resolver,
    )
    assert out["state"] == "EXECUTED"
    late = request_production_cancel(c, tenant_id=PILOT_TENANT, attempt_id=out["attempt_id"])
    assert late["state"] == "EXECUTED_AFTER_CANCEL_REQUEST"


def _submit_scripted(outcome):
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    ensure_execution_schema(c)
    t, plan, token, _, resolver = ready_4a(c)
    transport = ScriptedProductionTransport([outcome])
    out = submit_production_pilot(
        c, tenant_id=PILOT_TENANT, user_id="user-a", plan_id=plan["execution_plan_id"],
        confirmation_token=token, role="owner", transport=transport, resolver=resolver,
    )
    return out, transport


def test_submit_2xx_is_executed():
    out, transport = _submit_scripted(201)
    assert out["state"] == "EXECUTED"
    assert len(transport.calls) == 1


def test_submit_4xx_is_failed():
    out, transport = _submit_scripted(404)
    assert out["state"] == "FAILED"
    assert len(transport.calls) == 1


def test_submit_5xx_is_uncertain():
    out, transport = _submit_scripted(503)
    assert out["state"] == "UNCERTAIN"
    assert len(transport.calls) == 1


def test_submit_timeout_is_uncertain():
    out, transport = _submit_scripted(ProductionUncertain("timeout"))
    assert out["state"] == "UNCERTAIN"
    assert len(transport.calls) == 1


def test_submit_reset_is_uncertain():
    out, transport = _submit_scripted(ProductionUncertain("connection reset"))
    assert out["state"] == "UNCERTAIN"
    assert len(transport.calls) == 1


def test_submit_malformed_is_uncertain():
    out, transport = _submit_scripted(ProductionUncertain("malformed response"))
    assert out["state"] == "UNCERTAIN"
    assert len(transport.calls) == 1


def test_submit_redirect_denied_not_followed():
    out, transport = _submit_scripted(ProductionPilotDenied("redirects are rejected"))
    assert out["state"] == "FAILED"
    assert len(transport.calls) == 1


def test_claim_mutation_and_unexpected_exception_zero_calls():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    ensure_execution_schema(c)
    t, plan, token, transport, resolver = ready_4a(c)

    def boom():
        raise RuntimeError("claim exploded")

    with pytest.raises(RuntimeError):
        submit_production_pilot(
            c, tenant_id=PILOT_TENANT, user_id="user-a", plan_id=plan["execution_plan_id"],
            confirmation_token=token, role="owner", transport=transport, resolver=resolver,
            _after_claim_writes=boom,
        )
    assert transport.calls == []
    assert c.execute("SELECT COUNT(*) AS n FROM execution_attempts").fetchone()["n"] == 0


def test_reconciliation_rejects_non_uncertain_and_other_tenant():
    c = conn()
    prep = _activated(c)
    act = c.execute("SELECT activation_id, pilot_id FROM execution_pilot_activations").fetchone()
    now = _iso()
    c.execute(
        """INSERT INTO execution_attempts(id,tenant_id,plan_id,ticket_id,adapter_id,idempotency_key,state,provider_ref,created_at,updated_at,activation_id,pilot_id)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        ("att-x", TENANT, "plan", "tix", ADAPTER_ID, "idem-x", "EXECUTED", None, now, now, act["activation_id"], act["pilot_id"]),
    )
    if c.in_transaction:
        c.commit()
    with pytest.raises(ReconciliationDenied, match="UNCERTAIN"):
        record_reconciliation(c, principal=owner(), tenant_id=TENANT, attempt_id="att-x", decision="confirmed-success")
    with pytest.raises(ReconciliationDenied):
        inspect_attempt_redacted(c, principal=owner(), tenant_id="other-tenant", attempt_id="att-x")
    with pytest.raises(ReconciliationDenied):
        record_reconciliation(c, principal=owner(), tenant_id="other-tenant", attempt_id="att-x", decision="unresolved")


def test_observability_reads_stored_provider_submitted():
    c = conn()
    _activated(c)
    view = observe_pilot_runtime(c, principal=owner(), tenant_id=TENANT)
    assert view["provider_submitted"] is False
    now = _iso()
    act = c.execute("SELECT activation_id, pilot_id FROM execution_pilot_activations").fetchone()
    c.execute(
        """INSERT INTO execution_attempts(id,tenant_id,plan_id,ticket_id,adapter_id,idempotency_key,state,provider_ref,created_at,updated_at,activation_id,pilot_id)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        ("att-s", TENANT, "plan", "tix", ADAPTER_ID, "idem-s", "SUBMITTING", None, now, now, act["activation_id"], act["pilot_id"]),
    )
    c.execute(
        """INSERT INTO execution_pilot_attempts(attempt_id,tenant_id,plan_id,user_id,idempotency_key,provider_submitted,submit_count,cancel_requested,created_at,updated_at,activation_id,pilot_id)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        ("att-s", TENANT, "plan", "user-a", "idem-s", 0, 0, 0, now, now, act["activation_id"], act["pilot_id"]),
    )
    if c.in_transaction:
        c.commit()
    view = observe_pilot_runtime(c, principal=owner(), tenant_id=TENANT)
    assert view["provider_submitted"] is False
    c.execute("UPDATE execution_pilot_attempts SET provider_submitted=1 WHERE attempt_id='att-s'")
    if c.in_transaction:
        c.commit()
    view = observe_pilot_runtime(c, principal=owner(), tenant_id=TENANT)
    assert view["provider_submitted"] is True


def test_maintenance_rollback_and_rejects_open_transaction(monkeypatch):
    c = conn()
    prep = _activated(c)
    c.execute("UPDATE execution_pilot_activations SET expires_at=?", (_iso(_now() - timedelta(minutes=1)),))
    if c.in_transaction:
        c.commit()
    grant_before = c.execute("SELECT enabled FROM execution_live_grants WHERE tenant_id=?", (TENANT,)).fetchone()["enabled"]

    def boom(*args, **kwargs):
        raise sqlite3.OperationalError("close failed")

    monkeypatch.setattr("intelligence.execution_pilot_reconciliation._close_activation", boom)
    with pytest.raises(sqlite3.OperationalError):
        maintain_pilot_runtime(c)
    assert c.execute("SELECT enabled FROM execution_live_grants WHERE tenant_id=?", (TENANT,)).fetchone()["enabled"] == grant_before
    c.execute("BEGIN")
    with pytest.raises(ReconciliationDenied, match="open transaction"):
        maintain_pilot_runtime(c)
    c.rollback()


def test_concurrent_maintenance_one_consistent_state():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    bootstrap = sqlite3.connect(path)
    bootstrap.row_factory = sqlite3.Row
    ensure_stage4c2_schema(bootstrap)
    prep = _activated(bootstrap)
    dest_h = prep["destination_hash"]
    bootstrap.execute("UPDATE execution_pilot_activations SET expires_at=?", (_iso(_now() - timedelta(minutes=1)),))
    bootstrap.commit()
    bootstrap.close()
    results, errors = [], []

    def worker():
        c = sqlite3.connect(path, timeout=10)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA busy_timeout=10000")
        try:
            results.append(maintain_pilot_runtime(c))
        except Exception as exc:
            errors.append(exc)
        finally:
            c.close()

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert errors == []
    assert all(r["provider_calls"] == 0 for r in results)
    inspect = sqlite3.connect(path)
    inspect.row_factory = sqlite3.Row
    status = inspect.execute("SELECT status FROM execution_pilot_activations WHERE pilot_id=?", (prep["pilot_id"],)).fetchone()["status"]
    assert status in {"EXPIRED", "SUSPENDED"}
    assert inspect.execute("SELECT enabled FROM execution_live_grants WHERE tenant_id=?", (TENANT,)).fetchone()["enabled"] == 0
    assert inspect.execute(
        "SELECT COUNT(*) AS n FROM execution_destination_allowlist WHERE tenant_id=? AND destination_hash=?",
        (TENANT, dest_h),
    ).fetchone()["n"] == 0
    audits = inspect.execute("SELECT COUNT(*) AS n FROM execution_pilot_closure_audit WHERE pilot_id=?", (prep["pilot_id"],)).fetchone()["n"]
    assert audits >= 1
    inspect.close()


def _uncertain_bound(c, attempt_id="att-r2"):
    act = c.execute("SELECT activation_id, pilot_id FROM execution_pilot_activations").fetchone()
    now = _iso()
    c.execute(
        """INSERT INTO execution_attempts(id,tenant_id,plan_id,ticket_id,adapter_id,idempotency_key,state,provider_ref,created_at,updated_at,activation_id,pilot_id)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (attempt_id, TENANT, "plan", "tix", ADAPTER_ID, f"idem-{attempt_id}", "UNCERTAIN", None, now, now, act["activation_id"], act["pilot_id"]),
    )
    c.execute(
        """INSERT INTO execution_pilot_attempts(attempt_id,tenant_id,plan_id,user_id,idempotency_key,provider_submitted,submit_count,cancel_requested,created_at,updated_at,activation_id,pilot_id)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (attempt_id, TENANT, "plan", "user-a", f"idem-{attempt_id}", 1, 1, 0, now, now, act["activation_id"], act["pilot_id"]),
    )
    if c.in_transaction:
        c.commit()
    return act


def test_reconciliation_rejects_open_transaction_and_rolls_back_failures(monkeypatch):
    c = conn()
    _activated(c)
    _uncertain_bound(c, "att-open")
    c.execute("BEGIN")
    with pytest.raises(ReconciliationDenied, match="open transaction"):
        record_reconciliation(c, principal=owner(), tenant_id=TENANT, attempt_id="att-open", decision="confirmed-failure")
    c.rollback()

    def boom(*a, **k):
        raise sqlite3.OperationalError("injected")

    cases = [
        ("att-audit", "intelligence.execution_pilot_reconciliation._audit_closure"),
        ("att-suspend", "intelligence.execution_pilot_activation._suspend_pilot_locked"),
        ("att-ops", "intelligence.execution_pilot_reconciliation._ops_audit"),
    ]
    import intelligence.execution_pilot_activation as actmod
    import intelligence.execution_pilot_reconciliation as recmod
    originals = {
        "intelligence.execution_pilot_reconciliation._audit_closure": recmod._audit_closure,
        "intelligence.execution_pilot_activation._suspend_pilot_locked": actmod._suspend_pilot_locked,
        "intelligence.execution_pilot_reconciliation._ops_audit": recmod._ops_audit,
    }
    for attempt_id, target in cases:
        _uncertain_bound(c, attempt_id)
        before_recon = c.execute("SELECT COUNT(*) AS n FROM execution_pilot_reconciliations").fetchone()["n"]
        before_state = c.execute("SELECT state FROM execution_attempts WHERE id=?", (attempt_id,)).fetchone()["state"]
        before_status = c.execute("SELECT status FROM execution_pilot_activations").fetchone()["status"]
        monkeypatch.setattr(target, boom)
        with pytest.raises(sqlite3.OperationalError):
            record_reconciliation(c, principal=owner(), tenant_id=TENANT, attempt_id=attempt_id, decision="confirmed-failure")
        assert c.execute("SELECT COUNT(*) AS n FROM execution_pilot_reconciliations").fetchone()["n"] == before_recon
        assert c.execute("SELECT state FROM execution_attempts WHERE id=?", (attempt_id,)).fetchone()["state"] == before_state
        assert c.execute("SELECT status FROM execution_pilot_activations").fetchone()["status"] == before_status
        monkeypatch.setattr(target, originals[target])


def test_observability_does_not_mix_two_attempts():
    c = conn()
    prep = _activated(c)
    act = c.execute("SELECT activation_id, pilot_id FROM execution_pilot_activations").fetchone()
    now = _iso()
    for i, state, submitted in (("a1", "UNCERTAIN", 1), ("a2", "EXECUTED", 1)):
        c.execute(
            """INSERT INTO execution_attempts(id,tenant_id,plan_id,ticket_id,adapter_id,idempotency_key,state,provider_ref,created_at,updated_at,activation_id,pilot_id)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (i, TENANT, "plan", "tix", ADAPTER_ID, f"idem-{i}", state, None, now, now, act["activation_id"], act["pilot_id"]),
        )
        c.execute(
            """INSERT INTO execution_pilot_attempts(attempt_id,tenant_id,plan_id,user_id,idempotency_key,provider_submitted,submit_count,cancel_requested,created_at,updated_at,activation_id,pilot_id)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (i, TENANT, "plan", "user-a", f"idem-{i}", submitted, 1, 0, now, now, act["activation_id"], act["pilot_id"]),
        )
    c.execute(
        """INSERT INTO execution_attempts(id,tenant_id,plan_id,ticket_id,adapter_id,idempotency_key,state,provider_ref,created_at,updated_at,activation_id,pilot_id)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        ("other", TENANT, "plan", "tix", ADAPTER_ID, "idem-other", "FAILED", None, now, now, "other-act", "other-pilot"),
    )
    c.execute(
        """INSERT INTO execution_pilot_attempts(attempt_id,tenant_id,plan_id,user_id,idempotency_key,provider_submitted,submit_count,cancel_requested,created_at,updated_at,activation_id,pilot_id)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        ("other", TENANT, "plan", "user-a", "idem-other", 1, 1, 0, now, now, "other-act", "other-pilot"),
    )
    if c.in_transaction:
        c.commit()
    view = observe_pilot_runtime(c, principal=owner(), tenant_id=TENANT, pilot_id=prep["pilot_id"], activation_id=act["activation_id"])
    assert view["bound_pilot_id"] == prep["pilot_id"]
    assert view["bound_activation_id"] == act["activation_id"]
    assert view["attempt_id"] in {"a1", "a2"}
    assert view["attempt_id"] != "other"
    listed = list_uncertain_attempts(c, principal=owner(), tenant_id=TENANT, pilot_id=prep["pilot_id"], activation_id=act["activation_id"])
    assert {row["attempt_id"] for row in listed} == {"a1"}


def test_cancel_during_in_flight_becomes_executed_after_cancel():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    bootstrap = sqlite3.connect(path)
    bootstrap.row_factory = sqlite3.Row
    ensure_execution_schema(bootstrap)
    t, plan, token, _, resolver = ready_4a(bootstrap)
    bootstrap.commit()
    bootstrap.close()

    class BlockingTransport:
        def __init__(self):
            self.entered = threading.Event()
            self.release = threading.Event()
            self.calls = []

        def post(self, **kwargs):
            self.calls.append(kwargs)
            self.entered.set()
            assert self.release.wait(8)
            return ProductionTlsResponse(200, b'{"ok":true}', {})

    transport = BlockingTransport()
    result = {}

    def submitter():
        c = sqlite3.connect(path, timeout=10)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA busy_timeout=10000")
        result["out"] = submit_production_pilot(
            c, tenant_id=PILOT_TENANT, user_id="user-a", plan_id=plan["execution_plan_id"],
            confirmation_token=token, role="owner", transport=transport, resolver=resolver,
        )
        c.close()

    th = threading.Thread(target=submitter)
    th.start()
    assert transport.entered.wait(8)
    ctl = sqlite3.connect(path, timeout=10)
    ctl.row_factory = sqlite3.Row
    attempt = ctl.execute("SELECT id, state FROM execution_attempts WHERE tenant_id=?", (PILOT_TENANT,)).fetchone()
    assert attempt["state"] == "SUBMITTING"
    cancelled = request_production_cancel(ctl, tenant_id=PILOT_TENANT, attempt_id=attempt["id"])
    if ctl.in_transaction:
        ctl.commit()
    ctl.close()
    assert cancelled["state"] == "CANCEL_REQUESTED"
    transport.release.set()
    th.join(10)
    assert result["out"]["state"] == "EXECUTED_AFTER_CANCEL_REQUEST"
    assert len(transport.calls) == 1
