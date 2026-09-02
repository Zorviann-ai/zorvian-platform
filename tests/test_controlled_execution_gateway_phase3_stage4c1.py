from __future__ import annotations

import os
import sqlite3
import threading
from datetime import timedelta
from pathlib import Path

import pytest

from intelligence.execution import _iso, _now
from intelligence.execution_adapters import get_adapter
from intelligence.execution_pilot_activation import (
    MAX_CONCURRENT,
    MAX_RETRIES,
    MAX_SUCCESSES,
    MAX_WINDOW_MINUTES,
    OWNER_IDS_ENV,
    SECURITY_IDS_ENV,
    ActivationDenied,
    PlatformPrincipal,
    activate_pilot,
    assert_no_http_activation_route,
    claim_activation_success,
    classify_activation_state,
    down_migrate_stage4c1,
    ensure_stage4c1_schema,
    issue_activation_challenge,
    load_offline_platform_principal,
    preflight_activation,
    record_platform_approval,
    suspend_pilot,
)
from intelligence.execution_pilot_ops import (
    ADAPTER_ID,
    PilotOpsDenied,
    approve_pilot,
    assess_pilot_readiness,
    bind_pilot_to_guardian_assessment,
    propose_pilot,
)
from intelligence.execution_production_webhook import (
    PILOT_KEY_ID_ENV,
    PILOT_SECRET_ENV,
    ProductionPilotDenied,
    evaluate_pilot_runtime_gates,
    select_production_provider,
)
from intelligence.execution_providers import ClosedProvider, get_provider
from intelligence.guardian import (
    GUARDIAN_POLICY_VERSION,
    PILOT_PURPOSE,
    assess as assess_guardian,
    canonical_pilot_context,
    guardian_policy_hash,
    persist_guardian_assessment,
)


TENANT = "tenant-ops"
DEST = "https://hooks.pilot.example/events"
SUFFIX = "pilot.example"
OWNER = "plat-owner"
SEC = "plat-sec"


def conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    ensure_stage4c1_schema(c)
    if c.in_transaction:
        c.commit()
    return c


def file_conn(path):
    c = sqlite3.connect(path, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA busy_timeout=10000")
    ensure_stage4c1_schema(c)
    c.commit()
    return c


def clear_env():
    for key in [
        "ZORVIAN_EXTERNAL_EXECUTION",
        "ZORVIAN_WEBHOOK_PILOT_ENABLED",
        "ZORVIAN_WEBHOOK_PILOT_TENANT_ID",
        "ZORVIAN_WEBHOOK_PILOT_HOST_SUFFIX",
        PILOT_SECRET_ENV,
        PILOT_KEY_ID_ENV,
        OWNER_IDS_ENV,
        SECURITY_IDS_ENV,
    ]:
        os.environ.pop(key, None)


@pytest.fixture(autouse=True)
def _clean():
    clear_env()
    os.environ[OWNER_IDS_ENV] = OWNER
    os.environ[SECURITY_IDS_ENV] = SEC
    yield
    clear_env()


def owner():
    return load_offline_platform_principal(actor_id=OWNER, requested_role="platform_owner")


def security():
    return load_offline_platform_principal(actor_id=SEC, requested_role="security_operator")


def _prep(c):
    return propose_pilot(
        c,
        tenant_id=TENANT,
        proposer_id="user-a",
        role="owner",
        destination=DEST,
        hostname_suffix=SUFFIX,
        signing_key_id="k1",
        reason="internal sink",
        change_ref="CHG-1",
        max_requests=1,
        max_exposure="none",
    )


def _bind(c, prep, user_id="user-a"):
    expiry = _iso(_now() + timedelta(hours=1))
    context = canonical_pilot_context(
        {
            "purpose": PILOT_PURPOSE,
            "pilot_id": prep["pilot_id"],
            "tenant_id": TENANT,
            "requesting_user_id": user_id,
            "adapter_id": ADAPTER_ID,
            "action": "post_webhook",
            "destination_hash": prep["destination_hash"],
            "manifest_hash": prep["manifest_hash"],
            "policy_version": GUARDIAN_POLICY_VERSION,
            "policy_hash": guardian_policy_hash(),
            "consequential_action": True,
            "expiry": expiry,
        }
    )
    assessment = assess_guardian(
        tenant_id=TENANT,
        user_id=user_id,
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
        pilot_id=prep["pilot_id"],
        tenant_id=TENANT,
        actor_id=user_id,
    )


def _ready_pilot(c):
    prep = _prep(c)
    approve_pilot(c, tenant_id=TENANT, pilot_id=prep["pilot_id"], approver_id="user-b", role="admin")
    row = c.execute("SELECT * FROM execution_pilot_preparations WHERE pilot_id=?", (prep["pilot_id"],)).fetchone()
    prep = {
        "pilot_id": row["pilot_id"],
        "destination_hash": row["destination_hash"],
        "manifest_hash": row["manifest_hash"],
        "signing_key_id": row["signing_key_id"],
        "tenant_id": row["tenant_id"],
    }
    _bind(c, prep)
    if c.in_transaction:
        c.commit()
    return prep


def _arm_secret():
    os.environ[PILOT_KEY_ID_ENV] = "k1"
    os.environ[PILOT_SECRET_ENV] = "test-only-secret-value"


def _approve_both(c, pilot_id):
    record_platform_approval(c, pilot_id=pilot_id, principal=owner())
    record_platform_approval(c, pilot_id=pilot_id, principal=security())


def _challenge(c, pilot_id):
    return issue_activation_challenge(c, pilot_id=pilot_id, owner=owner(), security=security())


def test_default_provider_remains_closed():
    assert isinstance(get_provider(get_adapter("webhook.post")), ClosedProvider)
    assert assert_no_http_activation_route()["stage4c_activation_route"] is False


def test_merge_bootstrap_activates_nothing():
    c = conn()
    assert c.execute("SELECT COUNT(*) AS n FROM execution_live_grants WHERE enabled=1").fetchone()["n"] == 0
    assert c.execute("SELECT COUNT(*) AS n FROM execution_destination_allowlist").fetchone()["n"] == 0
    assert c.execute("SELECT COUNT(*) AS n FROM execution_pilot_activations").fetchone()["n"] == 0


def test_fabricated_platform_roles_denied():
    with pytest.raises(ActivationDenied):
        load_offline_platform_principal(actor_id="user-a", requested_role="platform_owner")
    fake = PlatformPrincipal(actor_id="user-a", role="platform_owner")
    c = conn()
    prep = _ready_pilot(c)
    with pytest.raises(ActivationDenied):
        record_platform_approval(c, pilot_id=prep["pilot_id"], principal=fake)


def test_tenant_owner_cannot_platform_activate():
    c = conn()
    prep = _ready_pilot(c)
    with pytest.raises(ActivationDenied):
        activate_pilot(c, pilot_id=prep["pilot_id"], principal=PlatformPrincipal("user-a", "owner"), challenge_nonce="x")


def test_existing_transaction_denied_and_not_committed():
    c = conn()
    prep = _ready_pilot(c)
    _arm_secret()
    _approve_both(c, prep["pilot_id"])
    issued = _challenge(c, prep["pilot_id"])
    c.execute("CREATE TABLE IF NOT EXISTS txn_canary(id INTEGER)")
    if c.in_transaction:
        c.commit()
    c.execute("INSERT INTO txn_canary(id) VALUES (1)")
    assert c.in_transaction
    with pytest.raises(ActivationDenied, match="open transaction"):
        activate_pilot(c, pilot_id=prep["pilot_id"], principal=owner(), challenge_nonce=issued["nonce"])
    c.rollback()
    assert c.execute("SELECT COUNT(*) AS n FROM txn_canary").fetchone()["n"] == 0
    assert c.execute("SELECT COUNT(*) AS n FROM execution_pilot_activations").fetchone()["n"] == 0


def test_activation_commit_failure_leaves_zero_partial_state(monkeypatch):
    c = conn()
    prep = _ready_pilot(c)
    _arm_secret()
    _approve_both(c, prep["pilot_id"])
    issued = _challenge(c, prep["pilot_id"])

    def boom(_c):
        raise sqlite3.OperationalError("commit failed")

    monkeypatch.setattr("intelligence.execution_pilot_activation._commit_activation_claim", boom)
    with pytest.raises(sqlite3.OperationalError):
        activate_pilot(c, pilot_id=prep["pilot_id"], principal=owner(), challenge_nonce=issued["nonce"])
    assert c.execute("SELECT COUNT(*) AS n FROM execution_pilot_activations").fetchone()["n"] == 0
    assert c.execute("SELECT COUNT(*) AS n FROM execution_live_grants WHERE enabled=1").fetchone()["n"] == 0
    assert c.execute("SELECT COUNT(*) AS n FROM execution_destination_allowlist").fetchone()["n"] == 0


def test_client_supplied_limits_denied():
    c = conn()
    prep = _ready_pilot(c)
    _arm_secret()
    _approve_both(c, prep["pilot_id"])
    issued = _challenge(c, prep["pilot_id"])
    with pytest.raises(ActivationDenied):
        activate_pilot(c, pilot_id=prep["pilot_id"], principal=owner(), challenge_nonce=issued["nonce"], window_minutes=31)
    assert MAX_WINDOW_MINUTES == 30 and MAX_SUCCESSES == 1 and MAX_CONCURRENT == 1 and MAX_RETRIES == 0


def test_same_actor_cannot_supply_both_platform_approvals():
    os.environ[SECURITY_IDS_ENV] = OWNER
    c = conn()
    prep = _ready_pilot(c)
    record_platform_approval(c, pilot_id=prep["pilot_id"], principal=owner())
    same = load_offline_platform_principal(actor_id=OWNER, requested_role="security_operator")
    with pytest.raises(ActivationDenied):
        record_platform_approval(c, pilot_id=prep["pilot_id"], principal=same)


def test_approval_uniqueness_under_concurrency(tmp_path):
    db = str(tmp_path / "appr.sqlite")
    c = file_conn(db)
    prep = _ready_pilot(c)
    c.commit()
    c.close()
    results = []

    def worker():
        local = file_conn(db)
        try:
            record_platform_approval(local, pilot_id=prep["pilot_id"], principal=owner())
            results.append("ok")
        except Exception:
            results.append("err")
        finally:
            local.close()

    t1 = threading.Thread(target=worker)
    t2 = threading.Thread(target=worker)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    check = file_conn(db)
    n = check.execute("SELECT COUNT(*) AS n FROM execution_pilot_platform_approvals WHERE role='platform_owner'").fetchone()["n"]
    check.close()
    assert n == 1
    assert results.count("ok") == 1


def test_changed_manifest_invalidates_approvals():
    c = conn()
    prep = _ready_pilot(c)
    record_platform_approval(c, pilot_id=prep["pilot_id"], principal=owner())
    assert c.execute("SELECT COUNT(*) AS n FROM execution_pilot_platform_approvals").fetchone()["n"] == 1
    c.execute("UPDATE execution_pilot_preparations SET manifest_hash=? WHERE pilot_id=?", ("deadbeef" * 8, prep["pilot_id"]))
    if c.in_transaction:
        c.commit()
    with pytest.raises((ActivationDenied, PilotOpsDenied)):
        record_platform_approval(c, pilot_id=prep["pilot_id"], principal=security())
    remaining = c.execute("SELECT COUNT(*) AS n FROM execution_pilot_platform_approvals WHERE pilot_id=?", (prep["pilot_id"],)).fetchone()["n"]
    assert remaining == 0


def test_tampered_guardian_context_denies():
    c = conn()
    prep = _ready_pilot(c)
    _arm_secret()
    _approve_both(c, prep["pilot_id"])
    c.execute("UPDATE guardian_assessments SET context_hash=?", ("0" * 64,))
    if c.in_transaction:
        c.commit()
    with pytest.raises(ActivationDenied):
        _challenge(c, prep["pilot_id"])


def test_missing_secret_denies_without_revealing_it():
    c = conn()
    prep = _ready_pilot(c)
    _approve_both(c, prep["pilot_id"])
    with pytest.raises(ActivationDenied, match="secret") as exc:
        _challenge(c, prep["pilot_id"])
    assert "test-only" not in str(exc.value)


def test_challenge_and_duplicate_bound_to_ceremony():
    c = conn()
    prep = _ready_pilot(c)
    _arm_secret()
    _approve_both(c, prep["pilot_id"])
    issued = _challenge(c, prep["pilot_id"])
    row = c.execute("SELECT nonce_hash FROM execution_pilot_activation_challenges").fetchone()
    assert issued["nonce"] not in row["nonce_hash"]
    first = activate_pilot(c, pilot_id=prep["pilot_id"], principal=owner(), challenge_nonce=issued["nonce"])
    assert first["duplicate"] is False
    with pytest.raises(ActivationDenied):
        activate_pilot(c, pilot_id=prep["pilot_id"], principal=owner(), challenge_nonce="arbitrary-nonce")
    replay = activate_pilot(c, pilot_id=prep["pilot_id"], principal=owner(), challenge_nonce=issued["nonce"])
    assert replay["duplicate"] is True
    assert c.execute("SELECT COUNT(*) AS n FROM execution_pilot_activations").fetchone()["n"] == 1


def test_successful_ceremony_no_provider_call():
    c = conn()
    prep = _ready_pilot(c)
    _arm_secret()
    _approve_both(c, prep["pilot_id"])
    issued = _challenge(c, prep["pilot_id"])
    out = activate_pilot(c, pilot_id=prep["pilot_id"], principal=security(), challenge_nonce=issued["nonce"])
    assert out["provider_calls"] == 0
    assert out["signing_secret"] is None
    assert isinstance(get_provider(get_adapter("webhook.post")), ClosedProvider)
    assert classify_activation_state(c, tenant_id=TENANT, pilot_id=prep["pilot_id"]) == "active"


def test_begin_failure_leaves_zero_partial_state(monkeypatch):
    c = conn()
    prep = _ready_pilot(c)
    _arm_secret()
    _approve_both(c, prep["pilot_id"])
    issued = _challenge(c, prep["pilot_id"])

    def boom(_c):
        raise sqlite3.OperationalError("cannot start transaction")

    monkeypatch.setattr("intelligence.execution_pilot_activation._begin_immediate", boom)
    with pytest.raises(sqlite3.Error):
        activate_pilot(c, pilot_id=prep["pilot_id"], principal=owner(), challenge_nonce=issued["nonce"])
    assert c.execute("SELECT COUNT(*) AS n FROM execution_pilot_activations").fetchone()["n"] == 0


def test_expiry_blocks_actual_provider_path():
    c = conn()
    prep = _ready_pilot(c)
    _arm_secret()
    os.environ["ZORVIAN_EXTERNAL_EXECUTION"] = "pilot"
    os.environ["ZORVIAN_WEBHOOK_PILOT_ENABLED"] = "true"
    os.environ["ZORVIAN_WEBHOOK_PILOT_TENANT_ID"] = TENANT
    os.environ["ZORVIAN_WEBHOOK_PILOT_HOST_SUFFIX"] = SUFFIX
    _approve_both(c, prep["pilot_id"])
    issued = _challenge(c, prep["pilot_id"])
    activate_pilot(c, pilot_id=prep["pilot_id"], principal=owner(), challenge_nonce=issued["nonce"])
    c.execute("UPDATE execution_pilot_activations SET expires_at=?", (_iso(_now() - timedelta(minutes=1)),))
    if c.in_transaction:
        c.commit()
    provider = select_production_provider(get_adapter("webhook.post"), connection=c, tenant_id=TENANT)
    assert isinstance(provider, ClosedProvider)
    with pytest.raises((ActivationDenied, ProductionPilotDenied)):
        evaluate_pilot_runtime_gates(c, tenant_id=TENANT, adapter_id=ADAPTER_ID, action="post_webhook")


def test_one_success_blocks_second_provider_claim():
    c = conn()
    prep = _ready_pilot(c)
    _arm_secret()
    _approve_both(c, prep["pilot_id"])
    issued = _challenge(c, prep["pilot_id"])
    activate_pilot(c, pilot_id=prep["pilot_id"], principal=owner(), challenge_nonce=issued["nonce"])
    dest_h = prep["destination_hash"]
    assert claim_activation_success(c, tenant_id=TENANT, adapter_id=ADAPTER_ID)
    if c.in_transaction:
        c.commit()
    act = c.execute("SELECT * FROM execution_pilot_activations WHERE pilot_id=?", (prep["pilot_id"],)).fetchone()
    assert act["successes_claimed"] == 1
    assert act["status"] == "QUOTA_EXHAUSTED"
    assert c.execute("SELECT enabled FROM execution_live_grants WHERE tenant_id=?", (TENANT,)).fetchone()["enabled"] == 0
    assert c.execute(
        "SELECT COUNT(*) AS n FROM execution_destination_allowlist WHERE tenant_id=? AND destination_hash=?",
        (TENANT, dest_h),
    ).fetchone()["n"] == 0
    with pytest.raises(ActivationDenied, match="quota|ACTIVE|exhausted"):
        claim_activation_success(c, tenant_id=TENANT, adapter_id=ADAPTER_ID)
    provider = select_production_provider(get_adapter("webhook.post"), connection=c, tenant_id=TENANT)
    assert isinstance(provider, ClosedProvider)


def test_concurrent_success_claim_one_winner(tmp_path):
    db = str(tmp_path / "claim.sqlite")
    c = file_conn(db)
    prep = _ready_pilot(c)
    _arm_secret()
    _approve_both(c, prep["pilot_id"])
    issued = _challenge(c, prep["pilot_id"])
    activate_pilot(c, pilot_id=prep["pilot_id"], principal=owner(), challenge_nonce=issued["nonce"])
    c.commit()
    c.close()
    wins = []

    def worker():
        local = file_conn(db)
        try:
            claim_activation_success(local, tenant_id=TENANT, adapter_id=ADAPTER_ID)
            if local.in_transaction:
                local.commit()
            wins.append("ok")
        except Exception:
            try:
                local.rollback()
            except sqlite3.Error:
                pass
            wins.append("err")
        finally:
            local.close()

    t1 = threading.Thread(target=worker)
    t2 = threading.Thread(target=worker)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    assert wins.count("ok") == 1


def test_uncertain_does_not_retry_quota():
    c = conn()
    prep = _ready_pilot(c)
    _arm_secret()
    _approve_both(c, prep["pilot_id"])
    issued = _challenge(c, prep["pilot_id"])
    activate_pilot(c, pilot_id=prep["pilot_id"], principal=owner(), challenge_nonce=issued["nonce"])
    claim_activation_success(c, tenant_id=TENANT, adapter_id=ADAPTER_ID)
    if c.in_transaction:
        c.commit()
    with pytest.raises(ActivationDenied):
        claim_activation_success(c, tenant_id=TENANT, adapter_id=ADAPTER_ID)


def test_arbitrary_tenant_role_cannot_invoke_stage4c1_suspension():
    c = conn()
    prep = _ready_pilot(c)
    _arm_secret()
    _approve_both(c, prep["pilot_id"])
    issued = _challenge(c, prep["pilot_id"])
    activate_pilot(c, pilot_id=prep["pilot_id"], principal=owner(), challenge_nonce=issued["nonce"])
    with pytest.raises(TypeError):
        suspend_pilot(c, pilot_id=prep["pilot_id"], tenant_id="other-tenant", tenant_role="owner", actor_id="owner-b", reason="cross")
    with pytest.raises(ActivationDenied):
        suspend_pilot(c, pilot_id=prep["pilot_id"], principal=PlatformPrincipal("owner-b", "owner"), reason="cross")
    assert c.execute("SELECT status FROM execution_pilot_activations WHERE pilot_id=?", (prep["pilot_id"],)).fetchone()["status"] == "ACTIVE"


def test_suspension_idempotent_and_preserves_evidence():
    c = conn()
    prep = _ready_pilot(c)
    _arm_secret()
    _approve_both(c, prep["pilot_id"])
    issued = _challenge(c, prep["pilot_id"])
    activate_pilot(c, pilot_id=prep["pilot_id"], principal=owner(), challenge_nonce=issued["nonce"])
    first = suspend_pilot(c, pilot_id=prep["pilot_id"], principal=security(), reason="close")
    second = suspend_pilot(c, pilot_id=prep["pilot_id"], principal=security(), reason="close")
    assert first["status"] == second["status"] == "SUSPENDED"
    assert c.execute("SELECT COUNT(*) AS n FROM guardian_assessments").fetchone()["n"] >= 1


def test_preflight_select_plus_one_audit_insert_only():
    c = conn()
    prep = _ready_pilot(c)
    _arm_secret()
    _approve_both(c, prep["pilot_id"])
    write_codes = {
        getattr(sqlite3, name)
        for name in (
            "SQLITE_CREATE_INDEX", "SQLITE_CREATE_TABLE", "SQLITE_DELETE", "SQLITE_DROP_TABLE",
            "SQLITE_UPDATE", "SQLITE_ALTER_TABLE", "SQLITE_DROP_INDEX", "SQLITE_REPLACE",
        )
        if hasattr(sqlite3, name)
    }
    traced = []
    inserts = 0

    def tracer(statement):
        traced.append(statement)

    def authorizer(action, arg1, arg2, dbname, source):
        nonlocal inserts
        if action == sqlite3.SQLITE_INSERT and (arg1 or "") == "execution_pilot_preflight_audit":
            inserts += 1
            return sqlite3.SQLITE_OK
        if action in write_codes or action == sqlite3.SQLITE_INSERT:
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    c.set_trace_callback(tracer)
    c.set_authorizer(authorizer)
    try:
        out = preflight_activation(c, pilot_id=prep["pilot_id"], principal=owner())
    finally:
        c.set_authorizer(None)
        c.set_trace_callback(None)
    assert out["activated"] is False
    assert inserts == 1
    for statement in traced:
        lead = statement.strip().split(None, 1)[0].upper() if statement.strip() else ""
        if lead == "INSERT":
            assert "execution_pilot_preflight_audit" in statement
        assert lead not in {"CREATE", "ALTER", "UPDATE", "DELETE", "DROP", "REPLACE"}


def test_readiness_fail_closed_and_static_routes():
    ready = assess_pilot_readiness(conn(), tenant_id=TENANT)
    assert ready["overall"] != "PASS"
    src = Path("app_gate5.py").read_text()
    assert "/activate" not in src


def test_down_migration_keeps_evidence():
    c = conn()
    prep = _ready_pilot(c)
    _arm_secret()
    _approve_both(c, prep["pilot_id"])
    issued = _challenge(c, prep["pilot_id"])
    activate_pilot(c, pilot_id=prep["pilot_id"], principal=owner(), challenge_nonce=issued["nonce"])
    down_migrate_stage4c1(c)
    assert c.execute("SELECT COUNT(*) AS n FROM execution_pilot_activations").fetchone()["n"] == 1
    assert c.execute("SELECT enabled FROM execution_live_grants").fetchone()["enabled"] == 0
    from intelligence.execution_live import _global_kill_active, _tenant_kill_active
    assert _global_kill_active(c) is True
    assert _tenant_kill_active(c, TENANT, ADAPTER_ID) is True


def test_stage4a_flags_grant_allowlist_without_activation_denied():
    from intelligence.execution_live import add_destination_allowlist, grant_live
    c = conn()
    os.environ["ZORVIAN_ENV"] = "prod"
    os.environ["ZORVIAN_EXTERNAL_EXECUTION"] = "pilot"
    os.environ["ZORVIAN_WEBHOOK_PILOT_ENABLED"] = "true"
    os.environ["ZORVIAN_WEBHOOK_PILOT_TENANT_ID"] = TENANT
    os.environ["ZORVIAN_WEBHOOK_PILOT_HOST_SUFFIX"] = SUFFIX
    _arm_secret()
    grant_live(c, tenant_id=TENANT, adapter_id=ADAPTER_ID, action="post_webhook", env="prod", actor_id="ops", enabled=True)
    add_destination_allowlist(c, tenant_id=TENANT, adapter_id=ADAPTER_ID, destination=DEST)
    if c.in_transaction:
        c.commit()
    provider = select_production_provider(get_adapter("webhook.post"), connection=c, tenant_id=TENANT)
    assert isinstance(provider, ClosedProvider)
    with pytest.raises((ActivationDenied, ProductionPilotDenied), match="activation"):
        evaluate_pilot_runtime_gates(c, tenant_id=TENANT, adapter_id=ADAPTER_ID, action="post_webhook")
    with pytest.raises(ActivationDenied, match="activation"):
        claim_activation_success(c, tenant_id=TENANT, adapter_id=ADAPTER_ID)


def test_missing_activation_table_is_denied():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    with pytest.raises(ActivationDenied, match="unreadable"):
        claim_activation_success(c, tenant_id=TENANT, adapter_id=ADAPTER_ID)


def test_activation_destination_and_key_and_pilot_must_match():
    c = conn()
    prep = _ready_pilot(c)
    _arm_secret()
    _approve_both(c, prep["pilot_id"])
    issued = _challenge(c, prep["pilot_id"])
    activate_pilot(c, pilot_id=prep["pilot_id"], principal=owner(), challenge_nonce=issued["nonce"])
    other = "ff" * 32
    with pytest.raises(ActivationDenied, match="does not match"):
        claim_activation_success(
            c, tenant_id=TENANT, adapter_id=ADAPTER_ID, destination_hash=other, exact=True,
        )
    with pytest.raises(ActivationDenied, match="does not match"):
        claim_activation_success(
            c, tenant_id=TENANT, adapter_id=ADAPTER_ID, signing_key_id="other-key", exact=True,
        )
    with pytest.raises(ActivationDenied, match="does not match"):
        claim_activation_success(
            c, tenant_id=TENANT, adapter_id=ADAPTER_ID, manifest_hash="ab" * 32, exact=True,
        )
    with pytest.raises(ActivationDenied, match="does not match"):
        claim_activation_success(
            c, tenant_id=TENANT, adapter_id=ADAPTER_ID, pilot_id="other-pilot", exact=True,
        )


def test_stage4b_shutdown_remains_tenant_isolated():
    from intelligence.execution_pilot_ops import emergency_shutdown
    c = conn()
    prep = _ready_pilot(c)
    emergency_shutdown(c, tenant_id=TENANT, actor_id="user-a", role="owner", reason="tenant-stop", pilot_id=prep["pilot_id"])
    other = c.execute("SELECT COUNT(*) AS n FROM execution_kill_switches WHERE tenant_id=?", ("other-tenant",)).fetchone()["n"]
    assert other == 0
    own = c.execute("SELECT COUNT(*) AS n FROM execution_kill_switches WHERE tenant_id=?", (TENANT,)).fetchone()["n"]
    assert own >= 1


def _ready_pilot_for(c, tenant, proposer="user-a", approver="user-b"):
    prep = propose_pilot(
        c,
        tenant_id=tenant,
        proposer_id=proposer,
        role="owner",
        destination=DEST,
        hostname_suffix=SUFFIX,
        signing_key_id="k1",
        reason="internal sink",
        change_ref="CHG-X",
        max_requests=1,
        max_exposure="none",
    )
    approve_pilot(c, tenant_id=tenant, pilot_id=prep["pilot_id"], approver_id=approver, role="admin")
    row = c.execute("SELECT * FROM execution_pilot_preparations WHERE pilot_id=?", (prep["pilot_id"],)).fetchone()
    expiry = _iso(_now() + timedelta(hours=1))
    context = canonical_pilot_context(
        {
            "purpose": PILOT_PURPOSE,
            "pilot_id": row["pilot_id"],
            "tenant_id": tenant,
            "requesting_user_id": proposer,
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
        tenant_id=tenant,
        user_id=proposer,
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
        tenant_id=tenant,
        actor_id=proposer,
    )
    if c.in_transaction:
        c.commit()
    return {
        "pilot_id": row["pilot_id"],
        "destination_hash": row["destination_hash"],
        "manifest_hash": row["manifest_hash"],
        "tenant_id": tenant,
    }


def test_second_active_pilot_same_tenant_denied_challenge_unused():
    c = conn()
    first = _ready_pilot(c)
    _arm_secret()
    _approve_both(c, first["pilot_id"])
    first_ch = _challenge(c, first["pilot_id"])
    activate_pilot(c, pilot_id=first["pilot_id"], principal=owner(), challenge_nonce=first_ch["nonce"])
    second = _ready_pilot_for(c, TENANT, proposer="user-c", approver="user-d")
    _approve_both(c, second["pilot_id"])
    second_ch = _challenge(c, second["pilot_id"])
    with pytest.raises(ActivationDenied, match="one ACTIVE"):
        activate_pilot(c, pilot_id=second["pilot_id"], principal=owner(), challenge_nonce=second_ch["nonce"])
    row = c.execute(
        "SELECT consumed_at FROM execution_pilot_activation_challenges WHERE nonce_hash=?",
        (__import__("hashlib").sha256(second_ch["nonce"].encode()).hexdigest(),),
    ).fetchone()
    assert row["consumed_at"] is None
    assert c.execute("SELECT COUNT(*) AS n FROM execution_pilot_activations WHERE status='ACTIVE'").fetchone()["n"] == 1
    assert c.execute("SELECT COUNT(*) AS n FROM execution_pilot_activations WHERE pilot_id=?", (second["pilot_id"],)).fetchone()["n"] == 0


def test_other_tenant_activation_remains_isolated():
    c = conn()
    first = _ready_pilot(c)
    _arm_secret()
    _approve_both(c, first["pilot_id"])
    activate_pilot(c, pilot_id=first["pilot_id"], principal=owner(), challenge_nonce=_challenge(c, first["pilot_id"])["nonce"])
    other = _ready_pilot_for(c, "tenant-other", proposer="user-e", approver="user-f")
    _approve_both(c, other["pilot_id"])
    out = activate_pilot(c, pilot_id=other["pilot_id"], principal=owner(), challenge_nonce=_challenge(c, other["pilot_id"])["nonce"])
    assert out["status"] == "ACTIVE"
    assert out["tenant_id"] == "tenant-other"
    assert c.execute("SELECT COUNT(*) AS n FROM execution_pilot_activations WHERE status='ACTIVE'").fetchone()["n"] == 2


def test_tampered_duplicate_active_rows_denied_at_runtime():
    c = conn()
    first = _ready_pilot(c)
    _arm_secret()
    _approve_both(c, first["pilot_id"])
    activate_pilot(c, pilot_id=first["pilot_id"], principal=owner(), challenge_nonce=_challenge(c, first["pilot_id"])["nonce"])
    c.execute("DROP INDEX IF EXISTS ux_one_active_pilot_per_tenant_adapter")
    act = c.execute("SELECT * FROM execution_pilot_activations WHERE pilot_id=?", (first["pilot_id"],)).fetchone()
    c.execute(
        """INSERT INTO execution_pilot_activations(
            activation_id,pilot_id,tenant_id,adapter_id,destination_hash,manifest_hash,
            signing_key_id,platform_owner_id,security_operator_id,challenge_id,
            activated_at,expires_at,max_successes,max_concurrent,max_retries,
            successes_claimed,concurrent_claimed,status,created_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            "dup-act", "dup-pilot", TENANT, ADAPTER_ID, act["destination_hash"], act["manifest_hash"],
            act["signing_key_id"], act["platform_owner_id"], act["security_operator_id"], "dup-ch",
            act["activated_at"], act["expires_at"], 1, 1, 0, 0, 0, "ACTIVE", act["created_at"],
        ),
    )
    if c.in_transaction:
        c.commit()
    with pytest.raises(ActivationDenied, match="ambiguous"):
        claim_activation_success(c, tenant_id=TENANT, adapter_id=ADAPTER_ID)
    provider = select_production_provider(get_adapter("webhook.post"), connection=c, tenant_id=TENANT)
    assert isinstance(provider, ClosedProvider)
