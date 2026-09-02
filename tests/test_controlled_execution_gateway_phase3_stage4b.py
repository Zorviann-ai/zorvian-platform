from __future__ import annotations

import os
import sqlite3
from datetime import timedelta
from pathlib import Path

import pytest

from intelligence.execution import _iso, _now
from intelligence.execution_adapters import destination_hash, get_adapter
from intelligence.execution_live import _global_kill_active, _tenant_kill_active
from intelligence.execution_pilot_ops import (
    ADAPTER_ID,
    POLICY_VERSION,
    PilotOpsDenied,
    activation_precheck,
    approve_pilot,
    assess_pilot_readiness,
    assert_no_activation_route,
    canonical_pilot_destination,
    claims_blocked,
    classify_provider_state,
    emergency_global_shutdown,
    emergency_shutdown,
    ensure_stage4b_schema,
    invoke_closing,
    observability,
    bind_pilot_to_guardian_assessment,
    propose_pilot,
    public_manifest,
    verify_manifest_integrity,
)
from intelligence.execution_providers import ClosedProvider, get_provider
from intelligence.execution_receipts import record_receipt
from intelligence.guardian import (
    GUARDIAN_POLICY_VERSION,
    PILOT_PURPOSE,
    assess as assess_guardian,
    canonical_pilot_context,
    guardian_policy_hash,
    load_guardian_assessment,
    persist_guardian_assessment,
)


TENANT = "tenant-ops"
DEST = "https://hooks.pilot.example/events"
SUFFIX = "pilot.example"


def conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    ensure_stage4b_schema(c)
    return c


def clear_env():
    for key in [
        "ZORVIAN_EXTERNAL_EXECUTION",
        "ZORVIAN_WEBHOOK_PILOT_ENABLED",
        "ZORVIAN_WEBHOOK_PILOT_TENANT_ID",
        "ZORVIAN_WEBHOOK_PILOT_HOST_SUFFIX",
        "ZORVIAN_WEBHOOK_PILOT_SIGNING_SECRET",
        "ZORVIAN_WEBHOOK_PILOT_KEY_ID",
        "ZORVIAN_EXECUTION_ENV",
        "APP_ENV",
    ]:
        os.environ.pop(key, None)


@pytest.fixture(autouse=True)
def _clean():
    clear_env()
    yield
    clear_env()


def test_production_remains_off_by_default():
    provider = get_provider(get_adapter("webhook.post"))
    assert isinstance(provider, ClosedProvider)
    assert os.getenv("ZORVIAN_EXTERNAL_EXECUTION") in {None, "", "off"}
    assert os.getenv("ZORVIAN_WEBHOOK_PILOT_ENABLED") in {None, ""}
    c = conn()
    ready = assess_pilot_readiness(c, tenant_id=TENANT, destination_hash_value=destination_hash(DEST))
    assert ready["overall"] != "PASS"
    assert ready["external_execution_enabled"] is False
    assert ready["production_provider"] == "ClosedProvider"
    assert ready["network_calls"] == 0


def test_readiness_is_read_only_and_zero_network():
    c = conn()
    before = c.total_changes
    assess_pilot_readiness(c, tenant_id=TENANT)
    assert c.total_changes == before
    assert os.getenv("ZORVIAN_WEBHOOK_PILOT_SIGNING_SECRET") in {None, ""}


def test_same_user_cannot_propose_and_approve():
    c = conn()
    prep = propose_pilot(
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
    with pytest.raises(PilotOpsDenied, match="same user"):
        approve_pilot(c, tenant_id=TENANT, pilot_id=prep["pilot_id"], approver_id="user-a", role="owner")


def test_cross_tenant_preparation_is_rejected():
    c = conn()
    prep = propose_pilot(
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
    with pytest.raises(PilotOpsDenied, match="not found"):
        public_manifest(c, tenant_id="other-tenant", pilot_id=prep["pilot_id"])


def test_manifest_tampering_is_rejected():
    c = conn()
    prep = propose_pilot(
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
    c.execute(
        "UPDATE execution_pilot_preparations SET manifest_json=? WHERE pilot_id=?",
        ('{"status":"ACTIVE","tenant_id":"x"}', prep["pilot_id"]),
    )
    with pytest.raises(PilotOpsDenied, match="hash mismatch"):
        verify_manifest_integrity(c, tenant_id=TENANT, pilot_id=prep["pilot_id"])


def test_destination_key_mismatch_rejected():
    c = conn()
    prep = propose_pilot(
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
    approve_pilot(c, tenant_id=TENANT, pilot_id=prep["pilot_id"], approver_id="user-b", role="admin")
    with pytest.raises(PilotOpsDenied, match="destination hash"):
        activation_precheck(c, tenant_id=TENANT, pilot_id=prep["pilot_id"], destination_hash_value="deadbeef")
    with pytest.raises(PilotOpsDenied, match="signing key"):
        activation_precheck(c, tenant_id=TENANT, pilot_id=prep["pilot_id"], signing_key_id="other")


def test_expired_preparation_rejected():
    c = conn()
    past = _iso(_now() - timedelta(hours=2))
    with pytest.raises(PilotOpsDenied, match="expiry"):
        propose_pilot(
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
            expires_at=past,
        )


def test_unknown_or_fail_readiness_denies_precheck():
    c = conn()
    prep = propose_pilot(
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
    approve_pilot(c, tenant_id=TENANT, pilot_id=prep["pilot_id"], approver_id="user-b", role="admin")
    with pytest.raises(PilotOpsDenied, match="readiness"):
        activation_precheck(c, tenant_id=TENANT, pilot_id=prep["pilot_id"])


def test_no_signing_secret_stored_or_returned():
    c = conn()
    prep = propose_pilot(
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
    blob = str(c.execute("SELECT manifest_json FROM execution_pilot_preparations").fetchone()[0])
    assert "stage4a-test-signing-secret" not in blob
    view = public_manifest(c, tenant_id=TENANT, pilot_id=prep["pilot_id"])
    assert "secret" not in view
    obs = observability(c, tenant_id=TENANT, pilot_id=prep["pilot_id"])
    assert obs["signing_secret"] is None
    assert obs["destination"] is None


def test_shutdown_blocks_claims_and_preserves_evidence():
    c = conn()
    record_receipt(c, tenant_id=TENANT, attempt_id="att-1", classification="kept")
    c.execute(
        """INSERT INTO execution_attempts(id,tenant_id,plan_id,ticket_id,adapter_id,idempotency_key,state,provider_ref,created_at,updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        ("att-1", TENANT, "plan", "tix", ADAPTER_ID, "idem", "UNCERTAIN", None, _iso(), _iso()),
    )
    prep = propose_pilot(
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
    out = emergency_shutdown(c, tenant_id=TENANT, actor_id="owner-1", role="owner", reason="drill", pilot_id=prep["pilot_id"])
    assert out["global_kill_active"] is False
    assert out["tenant_adapter_kill_active"] is True
    assert out["receipts_preserved"] >= 1
    assert out["attempts_preserved"] >= 1
    assert claims_blocked(c, TENANT) is True
    assert public_manifest(c, tenant_id=TENANT, pilot_id=prep["pilot_id"])["status"] == "SUSPENDED"


def test_prepared_cannot_become_active_and_no_stage4c_route():
    src = Path("intelligence/execution_pilot_ops.py").read_text() + Path("app_gate5.py").read_text()
    assert "/activate" not in src
    assert "status'] = \"ACTIVE\"" not in src
    assert assert_no_activation_route()["stage4c_activation_route"] is False
    c = conn()
    prep = propose_pilot(
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
    assert prep["status"] == "PREPARED"
    assert prep["active"] is False


def test_owner_routes_exist_and_are_authenticated():
    src = Path("app_gate5.py").read_text()
    assert '@app.get("/api/execution/pilot/readiness")' in src
    assert '@app.get("/api/execution/pilot/shutdown-status")' in src
    assert '@app.get("/api/execution/pilot/observability")' in src
    assert '@app.get("/api/execution/pilot/manifests/{pilot_id}")' in src
    assert src.index("/api/execution/pilot/shutdown-status") < src.index("/api/execution/pilot/manifests/{pilot_id}")
    assert src.index("/api/execution/pilot/observability") < src.index("/api/execution/pilot/manifests/{pilot_id}")
    assert '@app.post("/api/execution/pilot/prepare")' in src
    assert '@app.post("/api/execution/pilot/shutdown")' in src
    assert "owner or admin role is required" in src


def test_grant_helper_is_not_called_by_stage4b_prepare():
    src = Path("intelligence/execution_pilot_ops.py").read_text()
    assert "grant_live(" not in src
    assert "add_destination_allowlist(" not in src


def test_existing_closed_provider_unchanged():
    assert isinstance(get_provider(get_adapter("webhook.post")), ClosedProvider)
    assert "def activate_" not in Path("intelligence/execution_pilot_ops.py").read_text()


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


def test_missing_guardian_evidence_fails():
    c = conn()
    prep = _prep(c)
    approve_pilot(c, tenant_id=TENANT, pilot_id=prep["pilot_id"], approver_id="user-b", role="admin")
    ready = assess_pilot_readiness(
        c,
        tenant_id=TENANT,
        destination_hash_value=prep["destination_hash"],
        pilot_id=prep["pilot_id"],
        manifest_hash=prep["manifest_hash"],
    )
    assert any(x["name"] == "guardian_approval" and x["status"] == "FAIL" for x in ready["checks"])
    with pytest.raises(PilotOpsDenied, match="readiness"):
        activation_precheck(c, tenant_id=TENANT, pilot_id=prep["pilot_id"])



def _allow_assessment(c, tenant_id=TENANT):
    assessment = assess_guardian(
        tenant_id=tenant_id,
        user_id="user-a",
        role="owner",
        module="security-analysis",
        action="review webhook pilot",
        facts="internal platform-owned sink readiness",
        consequential_action=False,
        identity_state="authenticated",
        connection=c,
    )
    persist_guardian_assessment(c, assessment)
    return assessment


def _exact_consequential_allow(c, prep, tenant_id=TENANT, user_id="user-a"):
    expiry = _iso(_now() + timedelta(hours=1))
    context = canonical_pilot_context(
        {
            "purpose": PILOT_PURPOSE,
            "pilot_id": prep["pilot_id"],
            "tenant_id": tenant_id,
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
        tenant_id=tenant_id,
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
    return assessment


def _deny_assessment(c, tenant_id=TENANT):
    assessment = assess_guardian(
        tenant_id=tenant_id,
        user_id="user-a",
        role="owner",
        module="security-analysis",
        action="review webhook pilot",
        facts="locked identity",
        consequential_action=False,
        identity_state="locked",
        connection=c,
    )
    persist_guardian_assessment(c, assessment)
    return assessment


def test_nonexistent_guardian_assessment_denies_bind():
    c = conn()
    prep = _prep(c)
    with pytest.raises(PilotOpsDenied, match="does not exist"):
        bind_pilot_to_guardian_assessment(
            c,
            guardian_assessment_id="missing-id",
            pilot_id=prep["pilot_id"],
            tenant_id=TENANT,
            actor_id="user-a",
        )


def test_unrelated_guardian_allow_cannot_bind():
    c = conn()
    prep = _prep(c)
    generic = _allow_assessment(c)
    with pytest.raises(PilotOpsDenied):
        bind_pilot_to_guardian_assessment(
            c,
            guardian_assessment_id=generic.guardian_assessment_id,
            pilot_id=prep["pilot_id"],
            tenant_id=TENANT,
            actor_id="user-a",
        )


def test_consequential_action_false_cannot_bind():
    c = conn()
    prep = _prep(c)
    advisory = _allow_assessment(c)
    assert advisory.consequential_action is False
    with pytest.raises(PilotOpsDenied, match="consequential_action"):
        bind_pilot_to_guardian_assessment(
            c,
            guardian_assessment_id=advisory.guardian_assessment_id,
            pilot_id=prep["pilot_id"],
            tenant_id=TENANT,
            actor_id="user-a",
        )


def test_caller_cannot_supply_replacement_destination_or_manifest_hashes():
    c = conn()
    prep = _prep(c)
    allowed = _exact_consequential_allow(c, prep)
    with pytest.raises(PilotOpsDenied, match="replacement destination or manifest hashes"):
        bind_pilot_to_guardian_assessment(
            c,
            guardian_assessment_id=allowed.guardian_assessment_id,
            pilot_id=prep["pilot_id"],
            tenant_id=TENANT,
            actor_id="user-a",
            destination_hash_value="deadbeef",
            manifest_hash=prep["manifest_hash"],
        )


def test_wrong_pilot_action_adapter_destination_manifest_cannot_bind():
    c = conn()
    prep = _prep(c)
    other = _prep(c)
    exact_other = _exact_consequential_allow(c, other)
    with pytest.raises(PilotOpsDenied):
        bind_pilot_to_guardian_assessment(
            c,
            guardian_assessment_id=exact_other.guardian_assessment_id,
            pilot_id=prep["pilot_id"],
            tenant_id=TENANT,
            actor_id="user-a",
        )


def test_deny_and_cross_tenant_and_tampered_bindings_fail():
    c = conn()
    prep = _prep(c)
    denied = _deny_assessment(c)
    with pytest.raises(PilotOpsDenied):
        bind_pilot_to_guardian_assessment(
            c,
            guardian_assessment_id=denied.guardian_assessment_id,
            pilot_id=prep["pilot_id"],
            tenant_id=TENANT,
            actor_id="user-a",
        )
    foreign = _allow_assessment(c, tenant_id="other-tenant")
    with pytest.raises(PilotOpsDenied, match="tenant mismatch"):
        bind_pilot_to_guardian_assessment(
            c,
            guardian_assessment_id=foreign.guardian_assessment_id,
            pilot_id=prep["pilot_id"],
            tenant_id=TENANT,
            actor_id="user-a",
        )


def test_exact_persisted_consequential_guardian_allow_passes():
    c = conn()
    prep = _prep(c)
    allowed = _exact_consequential_allow(c, prep)
    assert allowed.execution_allowed is True
    assert allowed.consequential_action is True
    bind_id = bind_pilot_to_guardian_assessment(
        c,
        guardian_assessment_id=allowed.guardian_assessment_id,
        pilot_id=prep["pilot_id"],
        tenant_id=TENANT,
        actor_id="user-a",
    )
    assert bind_id
    ready = assess_pilot_readiness(
        c,
        tenant_id=TENANT,
        destination_hash_value=prep["destination_hash"],
        pilot_id=prep["pilot_id"],
        manifest_hash=prep["manifest_hash"],
    )
    assert any(x["name"] == "guardian_approval" and x["status"] == "PASS" for x in ready["checks"])
    assert ready["overall"] != "PASS"
    assert ready["external_execution_enabled"] is False
    src = Path("intelligence/execution_pilot_ops.py").read_text()
    assert "persist_guardian_evidence" not in src


def test_same_tenant_different_user_assessment_cannot_bind():
    c = conn()
    prep = _prep(c)
    other = _exact_consequential_allow(c, prep, user_id="user-other")
    assert other.requesting_user_id == "user-other"
    with pytest.raises(PilotOpsDenied, match="requesting user"):
        bind_pilot_to_guardian_assessment(
            c,
            guardian_assessment_id=other.guardian_assessment_id,
            pilot_id=prep["pilot_id"],
            tenant_id=TENANT,
            actor_id="user-a",
        )


def _guardian_status(ready):
    return next(x for x in ready["checks"] if x["name"] == "guardian_approval")


def test_altered_assessment_context_fails_readiness():
    c = conn()
    prep = _prep(c)
    allowed = _exact_consequential_allow(c, prep)
    bind_pilot_to_guardian_assessment(
        c,
        guardian_assessment_id=allowed.guardian_assessment_id,
        pilot_id=prep["pilot_id"],
        tenant_id=TENANT,
        actor_id="user-a",
    )
    ready = assess_pilot_readiness(
        c,
        tenant_id=TENANT,
        destination_hash_value=prep["destination_hash"],
        pilot_id=prep["pilot_id"],
        manifest_hash=prep["manifest_hash"],
    )
    assert _guardian_status(ready)["status"] == "PASS"
    c.execute(
        "UPDATE guardian_assessments SET action=?, purpose=? WHERE guardian_assessment_id=?",
        ("review webhook pilot", "generic_review", allowed.guardian_assessment_id),
    )
    ready = assess_pilot_readiness(
        c,
        tenant_id=TENANT,
        destination_hash_value=prep["destination_hash"],
        pilot_id=prep["pilot_id"],
        manifest_hash=prep["manifest_hash"],
    )
    assert _guardian_status(ready)["status"] == "FAIL"
    assert ready["overall"] != "PASS"


def test_altered_context_hash_fails_readiness():
    c = conn()
    prep = _prep(c)
    allowed = _exact_consequential_allow(c, prep)
    bind_pilot_to_guardian_assessment(
        c,
        guardian_assessment_id=allowed.guardian_assessment_id,
        pilot_id=prep["pilot_id"],
        tenant_id=TENANT,
        actor_id="user-a",
    )
    c.execute(
        "UPDATE guardian_assessments SET context_hash=? WHERE guardian_assessment_id=?",
        ("0" * 64, allowed.guardian_assessment_id),
    )
    ready = assess_pilot_readiness(
        c,
        tenant_id=TENANT,
        destination_hash_value=prep["destination_hash"],
        pilot_id=prep["pilot_id"],
        manifest_hash=prep["manifest_hash"],
    )
    assert _guardian_status(ready)["status"] == "FAIL"
    assert ready["overall"] != "PASS"


def test_unmodified_bound_evidence_passes_guardian_readiness_check():
    c = conn()
    prep = _prep(c)
    allowed = _exact_consequential_allow(c, prep)
    bind_pilot_to_guardian_assessment(
        c,
        guardian_assessment_id=allowed.guardian_assessment_id,
        pilot_id=prep["pilot_id"],
        tenant_id=TENANT,
        actor_id="user-a",
    )
    ready = assess_pilot_readiness(
        c,
        tenant_id=TENANT,
        destination_hash_value=prep["destination_hash"],
        pilot_id=prep["pilot_id"],
        manifest_hash=prep["manifest_hash"],
    )
    assert _guardian_status(ready)["status"] == "PASS"
    assert ready["overall"] != "PASS"
    assert ready["external_execution_enabled"] is False


def test_readiness_executes_select_only_sql():
    c = conn()
    prep = _prep(c)
    allowed = _exact_consequential_allow(c, prep)
    bind_pilot_to_guardian_assessment(
        c,
        guardian_assessment_id=allowed.guardian_assessment_id,
        pilot_id=prep["pilot_id"],
        tenant_id=TENANT,
        actor_id="user-a",
    )
    if c.in_transaction:
        c.commit()
    write_codes = {
        getattr(sqlite3, name)
        for name in (
            "SQLITE_CREATE_INDEX", "SQLITE_CREATE_TABLE", "SQLITE_DELETE", "SQLITE_DROP_TABLE",
            "SQLITE_INSERT", "SQLITE_UPDATE", "SQLITE_ALTER_TABLE", "SQLITE_DROP_INDEX",
            "SQLITE_CREATE_VIEW", "SQLITE_DROP_VIEW", "SQLITE_ATTACH", "SQLITE_DETACH",
        )
        if hasattr(sqlite3, name)
    }
    traced: list[str] = []
    authorized: list[tuple] = []

    def tracer(statement: str) -> None:
        traced.append(statement)

    def authorizer(action, arg1, arg2, dbname, source):
        authorized.append((action, arg1, arg2))
        if action in write_codes:
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    c.set_trace_callback(tracer)
    c.set_authorizer(authorizer)
    try:
        loaded = load_guardian_assessment(c, allowed.guardian_assessment_id)
        ready = assess_pilot_readiness(
            c,
            tenant_id=TENANT,
            destination_hash_value=prep["destination_hash"],
            pilot_id=prep["pilot_id"],
            manifest_hash=prep["manifest_hash"],
        )
    finally:
        c.set_authorizer(None)
        c.set_trace_callback(None)
    assert loaded is not None
    assert ready["external_execution_enabled"] is False
    for statement in traced:
        lead = statement.strip().split(None, 1)[0].upper() if statement.strip() else ""
        assert lead not in {"CREATE", "INSERT", "UPDATE", "DELETE", "ALTER", "DROP", "REPLACE"}
    assert not any(item[0] in write_codes for item in authorized)
    src = Path("intelligence/guardian.py").read_text()
    load_fn = src.split("def load_guardian_assessment", 1)[1].split("\ndef ", 1)[0]
    assert "ensure_guardian_schema" not in load_fn


def test_destination_suffix_mismatch_rejected():
    c = conn()
    with pytest.raises(PilotOpsDenied, match="platform-owned suffix"):
        propose_pilot(
            c,
            tenant_id=TENANT,
            proposer_id="user-a",
            role="owner",
            destination="https://evil.example/events",
            hostname_suffix=SUFFIX,
            signing_key_id="k1",
            reason="no",
            change_ref="CHG-x",
            max_requests=1,
            max_exposure="none",
        )


def test_idna_canonical_destination_binding():
    url = canonical_pilot_destination("https://Hooks.Pilot.Example/events", "pilot.example")
    assert url == "https://hooks.pilot.example/events"
    assert destination_hash(url) == destination_hash("https://hooks.pilot.example/events")
    with pytest.raises(PilotOpsDenied):
        canonical_pilot_destination("https://user:pass@hooks.pilot.example/events", SUFFIX)
    with pytest.raises(PilotOpsDenied):
        canonical_pilot_destination("https://hooks.pilot.example/events?x=1", SUFFIX)
    with pytest.raises(PilotOpsDenied):
        canonical_pilot_destination("https://hooks.pilot.example:8443/events", SUFFIX)


def test_tenant_admin_cannot_activate_global_kill():
    c = conn()
    with pytest.raises(PilotOpsDenied, match="platform operator"):
        emergency_global_shutdown(c, actor_id="admin-1", role="admin", reason="no")
    emergency_shutdown(c, tenant_id=TENANT, actor_id="admin-1", role="admin", reason="local")
    assert _global_kill_active(c) is False
    assert _tenant_kill_active(c, TENANT, ADAPTER_ID) is True


def test_tenant_a_cannot_affect_tenant_b():
    c = conn()
    emergency_shutdown(c, tenant_id="tenant-a", actor_id="oa", role="owner", reason="a")
    assert _tenant_kill_active(c, "tenant-a", ADAPTER_ID) is True
    assert _tenant_kill_active(c, "tenant-b", ADAPTER_ID) is False
    assert _global_kill_active(c) is False
    prep = propose_pilot(
        c,
        tenant_id="tenant-b",
        proposer_id="ub",
        role="owner",
        destination=DEST,
        hostname_suffix=SUFFIX,
        signing_key_id="k1",
        reason="b",
        change_ref="CHG-b",
        max_requests=1,
        max_exposure="none",
    )
    assert public_manifest(c, tenant_id="tenant-b", pilot_id=prep["pilot_id"])["status"] == "PREPARED"


def test_observability_reports_gate_states():
    c = conn()
    obs = observability(c, tenant_id=TENANT)
    assert obs["provider_state"] == "default_closed"
    assert obs["external_execution_enabled"] is False
    os.environ["ZORVIAN_EXTERNAL_EXECUTION"] = "pilot"
    obs = observability(c, tenant_id=TENANT)
    assert obs["provider_state"] == "gates_incomplete"


def test_unexpected_api_errors_close_connections():
    closed = {"n": 0}

    class Dummy:
        def close(self):
            closed["n"] += 1

    def factory():
        return Dummy()

    with pytest.raises(RuntimeError):
        invoke_closing(factory, lambda c: (_ for _ in ()).throw(RuntimeError("boom")))
    assert closed["n"] == 1


def _run_isolated_api_script(script: str) -> None:
    import subprocess
    import sys
    import tempfile
    import textwrap
    env = os.environ.copy()
    env["SQLITE_PATH"] = str(Path(tempfile.gettempdir()) / f"zorvian_stage4b_{os.getpid()}.db")
    env["ZORVIAN_ENV"] = "test"
    env["DEV_EXPOSE_TOKENS"] = "1"
    proc = subprocess.run([sys.executable, "-c", textwrap.dedent(script)], cwd=str(Path(__file__).resolve().parents[1]), env=env, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_static_pilot_routes_are_not_shadowed():
    _run_isolated_api_script(
        """
        from fastapi.testclient import TestClient
        from app_gate12 import app
        client = TestClient(app)
        email = "ops-static@example.com"
        password = "VeryStrongExec!Password"
        reg = client.post("/auth/register", json={"company_name": "Ops Co", "name": "Ops User", "email": email, "password": password})
        assert reg.status_code == 201, reg.text
        token = reg.json()["verification_token"]
        assert client.post("/auth/verify-email", json={"token": token}).status_code == 200
        login = client.post("/auth/login", json={"email": email, "password": password})
        headers = {"Authorization": "Bearer " + login.json()["token"]}
        status = client.get("/api/execution/pilot/shutdown-status", headers=headers)
        assert status.status_code == 200, status.text
        assert "shutdown_effective" in status.json()
        obs = client.get("/api/execution/pilot/observability", headers=headers)
        assert obs.status_code == 200, obs.text
        assert "provider_state" in obs.json()
        """
    )


def test_manifest_route_is_tenant_isolated():
    _run_isolated_api_script(
        """
        from fastapi.testclient import TestClient
        from app_gate12 import app
        client = TestClient(app)

        def headers(email):
            password = "VeryStrongExec!Password"
            reg = client.post("/auth/register", json={"company_name": "Ops Co", "name": "Ops User", "email": email, "password": password})
            assert reg.status_code == 201, reg.text
            token = reg.json()["verification_token"]
            assert client.post("/auth/verify-email", json={"token": token}).status_code == 200
            login = client.post("/auth/login", json={"email": email, "password": password})
            return {"Authorization": "Bearer " + login.json()["token"]}

        h1 = headers("ops-a@example.com")
        missing = client.get("/api/execution/pilot/manifests/does-not-exist", headers=h1)
        assert missing.status_code == 403
        created = client.post("/api/execution/pilot/prepare", headers=h1, json={
            "destination": "https://hooks.pilot.example/events",
            "hostname_suffix": "pilot.example",
            "signing_key_id": "k1",
            "reason": "internal",
            "change_ref": "CHG-api",
            "max_requests": 1,
            "max_exposure": "none",
        })
        assert created.status_code == 200, created.text
        pilot_id = created.json()["pilot_id"]
        got = client.get(f"/api/execution/pilot/manifests/{pilot_id}", headers=h1)
        assert got.status_code == 200
        assert got.json()["pilot_id"] == pilot_id
        h2 = headers("ops-b@example.com")
        hidden = client.get(f"/api/execution/pilot/manifests/{pilot_id}", headers=h2)
        assert hidden.status_code == 403
        """
    )
