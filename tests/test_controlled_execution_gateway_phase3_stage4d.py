from __future__ import annotations

import os
import socket
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
    PlatformPrincipal,
    activate_pilot,
)
from intelligence.execution_pilot_ops import ADAPTER_ID, approve_pilot, bind_pilot_to_guardian_assessment, propose_pilot
from intelligence.execution_pilot_readiness import (
    ReadinessDenied,
    assert_drill_environment,
    export_redacted_evidence,
    render_stage4d_readiness,
    require_tenant_operator,
    run_emergency_shutdown_drill,
    run_expiry_maintenance_drill,
    run_uncertain_reconciliation_drill,
    verify_deployment_default_off,
)
from intelligence.execution_pilot_reconciliation import maintain_pilot_runtime
from intelligence.execution_production_webhook import (
    PILOT_KEY_ID_ENV,
    PILOT_SECRET_ENV,
    ProductionUncertain,
    ScriptedProductionTransport,
    submit_production_pilot,
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

from tests.test_controlled_execution_gateway_phase3_stage4a import PILOT_TENANT, ready as ready_4a
from tests.test_controlled_execution_gateway_phase3_stage4c1 import (
    DEST,
    OWNER,
    SEC,
    TENANT,
    _approve_both,
    _arm_secret,
    _challenge,
    _prep,
    _ready_pilot,
    owner,
)


DRILL_TENANT = "drill-tenant"
DRILL_DEST = "https://hooks.drill.invalid/events"
DRILL_SUFFIX = "drill.invalid"


def conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    ensure_execution_schema(c)
    if c.in_transaction:
        c.commit()
    return c


@pytest.fixture(autouse=True)
def _clean():
    for key in [
        "ZORVIAN_EXTERNAL_EXECUTION", "ZORVIAN_WEBHOOK_PILOT_ENABLED",
        "ZORVIAN_WEBHOOK_PILOT_TENANT_ID", "ZORVIAN_WEBHOOK_PILOT_HOST_SUFFIX",
        "ZORVIAN_ENV", "STAGE4D_DRILL", "SQLITE_PATH",
        PILOT_SECRET_ENV, PILOT_KEY_ID_ENV, OWNER_IDS_ENV, SECURITY_IDS_ENV,
    ]:
        os.environ.pop(key, None)
    os.environ[OWNER_IDS_ENV] = OWNER
    os.environ[SECURITY_IDS_ENV] = SEC
    yield


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network invoked")
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)


def _activated(c):
    prep = _ready_pilot(c)
    _arm_secret()
    _approve_both(c, prep["pilot_id"])
    activate_pilot(c, pilot_id=prep["pilot_id"], principal=owner(), challenge_nonce=_challenge(c, prep["pilot_id"])["nonce"])
    if c.in_transaction:
        c.commit()
    return prep


def _drill_ready(c):
    prep = propose_pilot(
        c, tenant_id=DRILL_TENANT, proposer_id="user-a", role="owner",
        destination=DRILL_DEST, hostname_suffix=DRILL_SUFFIX, signing_key_id="k1",
        reason="drill", change_ref="CHG-D", max_requests=1, max_exposure="none",
    )
    approve_pilot(c, tenant_id=DRILL_TENANT, pilot_id=prep["pilot_id"], approver_id="user-b", role="admin")
    c.execute(
        """INSERT INTO execution_pilot_approvals(id,pilot_id,tenant_id,role,actor_id,decision,note,created_at)
           VALUES (?,?,?,?,?,?,?,?)""",
        ("drill-admin", prep["pilot_id"], DRILL_TENANT, "admin", "user-b", "approved", "persisted-admin", _iso()),
    )
    row = c.execute("SELECT * FROM execution_pilot_preparations WHERE pilot_id=?", (prep["pilot_id"],)).fetchone()
    expiry = _iso(_now() + timedelta(hours=1))
    context = canonical_pilot_context({
        "purpose": PILOT_PURPOSE, "pilot_id": row["pilot_id"], "tenant_id": DRILL_TENANT,
        "requesting_user_id": "user-a", "adapter_id": ADAPTER_ID, "action": "post_webhook",
        "destination_hash": row["destination_hash"], "manifest_hash": row["manifest_hash"],
        "policy_version": GUARDIAN_POLICY_VERSION, "policy_hash": guardian_policy_hash(),
        "consequential_action": True, "expiry": expiry,
    })
    assessment = assess_guardian(
        tenant_id=DRILL_TENANT, user_id="user-a", role="owner", module="execution-gateway",
        action="post_webhook", facts="production_webhook_pilot exact context",
        consequential_action=True, identity_state="authenticated", session_state="normal",
        user_status="active", connection=c, pilot_context=context,
    )
    persist_guardian_assessment(c, assessment)
    bind_pilot_to_guardian_assessment(
        c, guardian_assessment_id=assessment.guardian_assessment_id,
        pilot_id=row["pilot_id"], tenant_id=DRILL_TENANT, actor_id="user-a",
    )
    if c.in_transaction:
        c.commit()
    return {"pilot_id": row["pilot_id"], "destination_hash": row["destination_hash"]}


def _select_only(c, fn):
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
        out = fn()
    finally:
        c.set_authorizer(None)
        c.set_trace_callback(None)
    for statement in traced:
        lead = statement.strip().split(None, 1)[0].upper() if statement.strip() else ""
        assert lead in {"SELECT", "BEGIN", "COMMIT", ""}
    return out


def test_default_off_bootstrap():
    assert isinstance(get_provider(get_adapter("webhook.post")), ClosedProvider)
    assert verify_deployment_default_off(conn())["ok"] is True
    assert "/activate" not in Path("app_gate5.py").read_text()


def test_readiness_select_only_and_redacted():
    c = conn()
    prep = _activated(c)
    report = _select_only(c, lambda: render_stage4d_readiness(c, principal=owner(), tenant_id=TENANT, pilot_id=prep["pilot_id"]))
    assert report["activation_permitted"] is False
    assert report["signing_secret"] is None
    bundle = _select_only(c, lambda: export_redacted_evidence(
        c, principal=owner(), tenant_id=TENANT, pilot_id=prep["pilot_id"],
        base_commit="99f0197601dc91d0be021fb92329141a94d3b345",
    ))
    assert bundle["readiness_checks"]
    assert bundle["payload"] is None


def test_missing_evidence_and_process_not_ready():
    c = conn()
    prep = _prep(c)
    names = {i["name"]: i["status"] for i in render_stage4d_readiness(c, principal=owner(), tenant_id=TENANT, pilot_id=prep["pilot_id"])["checks"]}
    assert names["guardian"] == "FAIL"
    assert names["platform_owner_approval"] == "FAIL"
    assert names["process_switches"] == "NOT_READY"


def test_orphan_grant_and_allowlist_fail_default_off():
    c = conn()
    prep = _prep(c)
    c.execute(
        "INSERT INTO execution_live_grants(tenant_id,adapter_id,action,env,enabled,created_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)",
        (TENANT, ADAPTER_ID, "post_webhook", "prod", 1, "ops", _iso(), _iso()),
    )
    c.commit() if c.in_transaction else None
    assert verify_deployment_default_off(c)["ok"] is False
    c.execute("UPDATE execution_live_grants SET enabled=0")
    c.execute(
        "INSERT INTO execution_destination_allowlist(tenant_id,adapter_id,destination_hash,label,created_at) VALUES (?,?,?,?,?)",
        (TENANT, ADAPTER_ID, prep["destination_hash"], "orphan", _iso()),
    )
    c.commit() if c.in_transaction else None
    assert verify_deployment_default_off(c)["ok"] is False


def test_drill_identity_rules():
    os.environ["STAGE4D_DRILL"] = "true"
    os.environ["ZORVIAN_ENV"] = "test"
    with pytest.raises(ReadinessDenied, match="synthetic drill tenant"):
        assert_drill_environment(db_path="/tmp/drill.sqlite", tenant_id=TENANT, destination=DRILL_DEST)
    with pytest.raises(ReadinessDenied, match="permitted synthetic host"):
        assert_drill_environment(db_path="/tmp/drill.sqlite", tenant_id=DRILL_TENANT, destination=DEST)
    with pytest.raises(ReadinessDenied, match="permitted synthetic host"):
        assert_drill_environment(db_path="/tmp/drill.sqlite", tenant_id=DRILL_TENANT, destination="https://evil.example/hooks.drill.invalid")
    with pytest.raises(ReadinessDenied, match="userinfo"):
        assert_drill_environment(db_path="/tmp/drill.sqlite", tenant_id=DRILL_TENANT, destination="https://a:b@hooks.drill.invalid/events")
    with pytest.raises(ReadinessDenied, match="query"):
        assert_drill_environment(db_path="/tmp/drill.sqlite", tenant_id=DRILL_TENANT, destination="https://hooks.drill.invalid/events?x=1")


def test_configured_sqlite_and_symlink_rejected():
    os.environ["STAGE4D_DRILL"] = "true"
    os.environ["ZORVIAN_ENV"] = "test"
    fd, path = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)
    os.environ["SQLITE_PATH"] = path
    with pytest.raises(ReadinessDenied, match="configured production database"):
        assert_drill_environment(db_path=path, tenant_id=DRILL_TENANT, destination=DRILL_DEST)
    alias = path + ".alias"
    os.symlink(path, alias)
    with pytest.raises(ReadinessDenied, match="configured production database"):
        assert_drill_environment(db_path=alias, tenant_id=DRILL_TENANT, destination=DRILL_DEST)
    with pytest.raises(ReadinessDenied, match="empty/unknown"):
        assert_drill_environment(db_path="", tenant_id=DRILL_TENANT, destination=DRILL_DEST)
    with pytest.raises(ReadinessDenied, match="memory"):
        assert_drill_environment(db_path=":memory:", tenant_id=DRILL_TENANT, destination=DRILL_DEST)
    c = sqlite3.connect(path)
    c.row_factory = sqlite3.Row
    with pytest.raises(ReadinessDenied, match="connection path mismatch"):
        assert_drill_environment(db_path="/tmp/other-drill.sqlite", tenant_id=DRILL_TENANT, destination=DRILL_DEST, connection=c)
    c.close()


def test_authorities_remain_separate():
    c = conn()
    prep = _activated(c)
    with pytest.raises(ReadinessDenied):
        require_tenant_operator(c, tenant_id=TENANT, actor_id=OWNER, pilot_id=prep["pilot_id"])
    with pytest.raises(ReadinessDenied):
        require_tenant_operator(c, tenant_id=TENANT, actor_id="user-a", pilot_id=prep["pilot_id"])
    c.execute(
        """INSERT INTO execution_pilot_approvals(id,pilot_id,tenant_id,role,actor_id,decision,note,created_at)
           VALUES (?,?,?,?,?,?,?,?)""",
        ("ap-admin", prep["pilot_id"], TENANT, "admin", "user-admin", "approved", "drill", _iso()),
    )
    if c.in_transaction:
        c.commit()
    assert require_tenant_operator(c, tenant_id=TENANT, actor_id="user-admin", pilot_id=prep["pilot_id"]) == "admin"
    from intelligence.execution_pilot_ops import emergency_global_shutdown
    with pytest.raises(Exception):
        emergency_global_shutdown(c, actor_id="user-admin", role="admin", reason="no")


def test_stale_approval_policy_challenge_activation_fail():
    c = conn()
    prep = _activated(c)
    c.execute("UPDATE execution_pilot_platform_approvals SET created_at=?", (_iso(_now() - timedelta(days=2)),))
    c.commit() if c.in_transaction else None
    names = {i["name"]: i["status"] for i in render_stage4d_readiness(c, principal=owner(), tenant_id=TENANT, pilot_id=prep["pilot_id"])["checks"]}
    assert names["approval_freshness"] == "FAIL"
    c.execute("UPDATE guardian_assessments SET policy_hash=?", ("00" * 32,))
    c.commit() if c.in_transaction else None
    names = {i["name"]: i["status"] for i in render_stage4d_readiness(c, principal=owner(), tenant_id=TENANT, pilot_id=prep["pilot_id"])["checks"]}
    assert names["policy_match"] == "FAIL"
    c.execute("UPDATE execution_pilot_activation_challenges SET expires_at=?", (_iso(_now() - timedelta(minutes=1)),))
    c.commit() if c.in_transaction else None
    names = {i["name"]: i["status"] for i in render_stage4d_readiness(c, principal=owner(), tenant_id=TENANT, pilot_id=prep["pilot_id"])["checks"]}
    assert names["challenge"] == "FAIL"
    c.execute("UPDATE execution_pilot_activations SET status='QUOTA_EXHAUSTED'")
    c.commit() if c.in_transaction else None
    names = {i["name"]: i["status"] for i in render_stage4d_readiness(c, principal=owner(), tenant_id=TENANT, pilot_id=prep["pilot_id"])["checks"]}
    assert names["activation"] == "FAIL"


def test_ambiguous_and_unexpected_process_fail_default_off():
    c = conn()
    prep = _activated(c)
    act = c.execute("SELECT * FROM execution_pilot_activations").fetchone()
    c.execute("DROP INDEX IF EXISTS ux_one_active_pilot_per_tenant_adapter")
    c.execute(
        """INSERT INTO execution_pilot_activations(
            activation_id,pilot_id,tenant_id,adapter_id,destination_hash,manifest_hash,
            signing_key_id,platform_owner_id,security_operator_id,challenge_id,
            activated_at,expires_at,max_successes,max_concurrent,max_retries,
            successes_claimed,concurrent_claimed,status,created_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        ("dup", "p2", TENANT, ADAPTER_ID, act["destination_hash"], act["manifest_hash"],
         act["signing_key_id"], act["platform_owner_id"], act["security_operator_id"], "ch",
         act["activated_at"], act["expires_at"], 1, 1, 0, 0, 0, "ACTIVE", act["created_at"]),
    )
    c.commit() if c.in_transaction else None
    assert verify_deployment_default_off(c)["ok"] is False
    os.environ["ZORVIAN_WEBHOOK_PILOT_ENABLED"] = "maybe"
    assert verify_deployment_default_off(conn())["ok"] is False


def test_shutdown_drill_preserves_evidence_zero_calls():
    os.environ["STAGE4D_DRILL"] = "true"
    os.environ["ZORVIAN_ENV"] = "test"
    fd, path = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)
    c = sqlite3.connect(path)
    c.row_factory = sqlite3.Row
    ensure_execution_schema(c)
    prep = _drill_ready(c)
    _arm_secret()
    _approve_both(c, prep["pilot_id"])
    activate_pilot(c, pilot_id=prep["pilot_id"], principal=owner(), challenge_nonce=_challenge(c, prep["pilot_id"])["nonce"])
    c.execute(
        """INSERT INTO execution_receipts(id,tenant_id,attempt_id,classification,payload_hash,destination_hash,recorded_at)
           VALUES (?,?,?,?,?,?,?)""",
        ("r1", DRILL_TENANT, "att", "kept", "ph", prep["destination_hash"], _iso()),
    )
    c.commit()
    out = run_emergency_shutdown_drill(
        c, principal=owner(), tenant_principal_id="user-b", tenant_id=DRILL_TENANT,
        other_tenant_id="other-tenant", pilot_id=prep["pilot_id"], destination=DRILL_DEST, db_path=path,
    )
    assert out["tenant_isolated"] is True
    assert out["global_unchanged_by_tenant"] is True
    assert out["platform_cannot_impersonate_tenant"] is True
    assert out["tenant_cannot_global_shutdown"] is True
    assert c.execute("SELECT COUNT(*) AS n FROM execution_receipts").fetchone()["n"] == 1
    assert c.execute("SELECT status FROM execution_pilot_activations").fetchone()["status"] == "SUSPENDED"


def test_runbook_exists():
    assert Path("CONTROLLED_EXECUTION_GATEWAY_PHASE3_STAGE4D_RUNBOOK.md").exists()


def test_activation_grant_allowlist_and_policy_mismatch():
    c = conn()
    prep = _activated(c)
    c.execute("UPDATE execution_live_grants SET enabled=0 WHERE tenant_id=?", (TENANT,))
    if c.in_transaction:
        c.commit()
    names = {i["name"]: i["status"] for i in render_stage4d_readiness(c, principal=owner(), tenant_id=TENANT, pilot_id=prep["pilot_id"])["checks"]}
    assert names["grant_matches_activation"] == "FAIL"
    c.execute("UPDATE execution_live_grants SET enabled=1")
    c.execute("DELETE FROM execution_destination_allowlist WHERE tenant_id=?", (TENANT,))
    if c.in_transaction:
        c.commit()
    names = {i["name"]: i["status"] for i in render_stage4d_readiness(c, principal=owner(), tenant_id=TENANT, pilot_id=prep["pilot_id"])["checks"]}
    assert names["allowlist_matches_activation"] == "FAIL"
    c.execute("UPDATE execution_pilot_activations SET policy_hash=?", ("00" * 32,))
    if c.in_transaction:
        c.commit()
    names = {i["name"]: i["status"] for i in render_stage4d_readiness(c, principal=owner(), tenant_id=TENANT, pilot_id=prep["pilot_id"])["checks"]}
    assert names["activation"] == "FAIL"


def test_uncertain_submit_replay_and_reconciliation_drill():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    ensure_execution_schema(c)
    t, plan, token, _, resolver = ready_4a(c)
    transport = ScriptedProductionTransport([ProductionUncertain("timeout")])
    out = submit_production_pilot(
        c, tenant_id=PILOT_TENANT, user_id="user-a", plan_id=plan["execution_plan_id"],
        confirmation_token=token, role="owner", transport=transport, resolver=resolver,
    )
    assert out["state"] == "UNCERTAIN"
    replay = submit_production_pilot(
        c, tenant_id=PILOT_TENANT, user_id="user-a", plan_id=plan["execution_plan_id"],
        confirmation_token=token, role="owner", transport=transport, resolver=resolver,
    )
    assert replay.get("idempotent_replay") is True
    assert len(transport.calls) == 1
    os.environ.pop("ZORVIAN_WEBHOOK_PILOT_HOST_SUFFIX", None)
    os.environ.pop("ZORVIAN_WEBHOOK_PILOT_TENANT_ID", None)
    os.environ.pop("ZORVIAN_WEBHOOK_PILOT_ENABLED", None)
    os.environ.pop("ZORVIAN_EXTERNAL_EXECUTION", None)
    os.environ.pop("ZORVIAN_ENV", None)
    os.environ["STAGE4D_DRILL"] = "true"
    os.environ["ZORVIAN_ENV"] = "test"
    fd, path = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)
    d = sqlite3.connect(path)
    d.row_factory = sqlite3.Row
    ensure_execution_schema(d)
    prep = _drill_ready(d)
    _arm_secret()
    _approve_both(d, prep["pilot_id"])
    activate_pilot(d, pilot_id=prep["pilot_id"], principal=owner(), challenge_nonce=_challenge(d, prep["pilot_id"])["nonce"])
    act = d.execute("SELECT activation_id, pilot_id FROM execution_pilot_activations").fetchone()
    now = _iso()
    calls = {"n": 0}

    def submit():
        existing = d.execute("SELECT id, state FROM execution_attempts WHERE tenant_id=?", (DRILL_TENANT,)).fetchone()
        if existing:
            return {"attempt_id": existing["id"], "state": existing["state"], "idempotent_replay": True}
        calls["n"] += 1
        d.execute(
            """INSERT INTO execution_attempts(id,tenant_id,plan_id,ticket_id,adapter_id,idempotency_key,state,provider_ref,created_at,updated_at,activation_id,pilot_id)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("att-u", DRILL_TENANT, "plan", "tix", ADAPTER_ID, "idem-u", "UNCERTAIN", None, now, now, act["activation_id"], act["pilot_id"]),
        )
        d.execute(
            """INSERT INTO execution_pilot_attempts(attempt_id,tenant_id,plan_id,user_id,idempotency_key,provider_submitted,submit_count,cancel_requested,created_at,updated_at,activation_id,pilot_id)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("att-u", DRILL_TENANT, "plan", "user-a", "idem-u", 1, 1, 0, now, now, act["activation_id"], act["pilot_id"]),
        )
        if d.in_transaction:
            d.commit()
        return {"attempt_id": "att-u", "state": "UNCERTAIN"}

    drilled = run_uncertain_reconciliation_drill(
        d, principal=owner(), unauthorized=PlatformPrincipal("user-a", "owner"),
        tenant_id=DRILL_TENANT, other_tenant_id="other-tenant", pilot_id=prep["pilot_id"],
        destination=DRILL_DEST, db_path=path, submit=submit,
    )
    assert calls["n"] == 1
    assert drilled["append_only"] and drilled["suspended"] and drilled["grant_closed"]


def test_expiry_maintenance_concurrent_and_rollback(monkeypatch):
    os.environ["STAGE4D_DRILL"] = "true"
    os.environ["ZORVIAN_ENV"] = "test"
    fd, path = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)
    c = sqlite3.connect(path)
    c.row_factory = sqlite3.Row
    ensure_execution_schema(c)
    prep = _drill_ready(c)
    _arm_secret()
    _approve_both(c, prep["pilot_id"])
    activate_pilot(c, pilot_id=prep["pilot_id"], principal=owner(), challenge_nonce=_challenge(c, prep["pilot_id"])["nonce"])
    if c.in_transaction:
        c.commit()
    out = run_expiry_maintenance_drill(c, tenant_id=DRILL_TENANT, pilot_id=prep["pilot_id"], destination=DRILL_DEST, db_path=path)
    assert out["status"] in {"EXPIRED", "SUSPENDED"}
    assert out["stale_state"] == "UNCERTAIN"
    c.close()
    results, errors = [], []

    def worker():
        cx = sqlite3.connect(path, timeout=10)
        cx.row_factory = sqlite3.Row
        try:
            results.append(maintain_pilot_runtime(cx))
        except Exception as exc:
            errors.append(exc)
        finally:
            cx.close()

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert errors == []
    c2 = conn()
    _activated(c2)
    c2.execute("UPDATE execution_pilot_activations SET expires_at=?", (_iso(_now() - timedelta(minutes=1)),))
    if c2.in_transaction:
        c2.commit()
    before = c2.execute("SELECT enabled FROM execution_live_grants").fetchone()["enabled"]
    monkeypatch.setattr("intelligence.execution_pilot_reconciliation._close_activation", lambda *a, **k: (_ for _ in ()).throw(sqlite3.OperationalError("injected")))
    with pytest.raises(sqlite3.OperationalError):
        maintain_pilot_runtime(c2)
    assert c2.execute("SELECT enabled FROM execution_live_grants").fetchone()["enabled"] == before


def test_rejected_approval_cannot_authorize_drill():
    c = conn()
    prep = _activated(c)
    c.execute(
        """INSERT INTO execution_pilot_approvals(id,pilot_id,tenant_id,role,actor_id,decision,note,created_at)
           VALUES (?,?,?,?,?,?,?,?)""",
        ("rej", prep["pilot_id"], TENANT, "admin", "user-rej", "rejected", "no", _iso()),
    )
    if c.in_transaction:
        c.commit()
    with pytest.raises(ReadinessDenied):
        require_tenant_operator(c, tenant_id=TENANT, actor_id="user-rej", pilot_id=prep["pilot_id"])


def test_missing_activation_guardian_fields_fail_readiness():
    for column in ("guardian_assessment_id", "guardian_context_hash", "policy_version", "policy_hash"):
        for value in (None, ""):
            c = conn()
            prep = _activated(c)
            if value is None:
                c.execute(f"UPDATE execution_pilot_activations SET {column}=NULL")
            else:
                c.execute(f"UPDATE execution_pilot_activations SET {column}=?", (value,))
            if c.in_transaction:
                c.commit()
            names = {i["name"]: i["status"] for i in render_stage4d_readiness(c, principal=owner(), tenant_id=TENANT, pilot_id=prep["pilot_id"])["checks"]}
            assert names["activation"] == "FAIL", f"{column}={value!r}"
            c.close()


def test_drill_environment_must_be_explicit_test_or_ci():
    os.environ["STAGE4D_DRILL"] = "true"
    os.environ.pop("ZORVIAN_ENV", None)
    with pytest.raises(ReadinessDenied, match="explicit ZORVIAN_ENV"):
        assert_drill_environment(db_path="/tmp/drill.sqlite", tenant_id=DRILL_TENANT, destination=DRILL_DEST)
    for bad in ("", "staging", "production", "prod", "unknown"):
        os.environ["ZORVIAN_ENV"] = bad
        with pytest.raises(ReadinessDenied):
            assert_drill_environment(db_path="/tmp/drill.sqlite", tenant_id=DRILL_TENANT, destination=DRILL_DEST)
    fd, path = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)
    for good in ("test", "ci"):
        os.environ["ZORVIAN_ENV"] = good
        assert_drill_environment(db_path=path, tenant_id=DRILL_TENANT, destination=DRILL_DEST)

def test_active_missing_or_empty_challenge_id_fails_readiness():
    from intelligence.execution_pilot_readiness import _classify_challenge
    c = conn()
    prep = _activated(c)
    act = c.execute("SELECT * FROM execution_pilot_activations WHERE pilot_id=?", (prep["pilot_id"],)).fetchone()
    challenge = c.execute("SELECT * FROM execution_pilot_activation_challenges WHERE pilot_id=?", (prep["pilot_id"],)).fetchone()
    assessment = c.execute("SELECT * FROM guardian_assessments").fetchone()
    approvals = c.execute("SELECT * FROM execution_pilot_platform_approvals WHERE pilot_id=?", (prep["pilot_id"],)).fetchall()
    for missing in (None, ""):
        patched = dict(act)
        patched["challenge_id"] = missing
        out = _classify_challenge(challenge, prep if hasattr(prep, "keys") else c.execute("SELECT * FROM execution_pilot_preparations WHERE pilot_id=?", (prep["pilot_id"],)).fetchone(), assessment, approvals, act=patched)
        assert out["status"] == "FAIL", f"challenge_id={missing!r}"
    c.execute("UPDATE execution_pilot_activations SET challenge_id=?", ("",))
    if c.in_transaction:
        c.commit()
    names = {i["name"]: i["status"] for i in render_stage4d_readiness(c, principal=owner(), tenant_id=TENANT, pilot_id=prep["pilot_id"])["checks"]}
    assert names["challenge"] == "FAIL"
    c.close()


def test_challenge_missing_or_empty_guardian_context_fails_readiness():
    from intelligence.execution_pilot_readiness import _classify_challenge
    c = conn()
    prep = _activated(c)
    row = c.execute("SELECT * FROM execution_pilot_preparations WHERE pilot_id=?", (prep["pilot_id"],)).fetchone()
    act = c.execute("SELECT * FROM execution_pilot_activations WHERE pilot_id=?", (prep["pilot_id"],)).fetchone()
    challenge = c.execute("SELECT * FROM execution_pilot_activation_challenges WHERE pilot_id=?", (prep["pilot_id"],)).fetchone()
    assessment = c.execute("SELECT * FROM guardian_assessments").fetchone()
    approvals = c.execute("SELECT * FROM execution_pilot_platform_approvals WHERE pilot_id=?", (prep["pilot_id"],)).fetchall()
    for missing in (None, ""):
        patched = dict(challenge)
        patched["guardian_context_hash"] = missing
        out = _classify_challenge(patched, row, assessment, approvals, act=act)
        assert out["status"] == "FAIL", f"guardian_context_hash={missing!r}"
    c.execute("UPDATE execution_pilot_activation_challenges SET guardian_context_hash=?", ("",))
    if c.in_transaction:
        c.commit()
    names = {i["name"]: i["status"] for i in render_stage4d_readiness(c, principal=owner(), tenant_id=TENANT, pilot_id=prep["pilot_id"])["checks"]}
    assert names["challenge"] == "FAIL"
    c.close()
