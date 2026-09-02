from __future__ import annotations

import os
import socket
import sqlite3
import threading

import pytest

from intelligence.execution import ensure_execution_schema
from intelligence.execution_adapters import get_adapter
from intelligence.execution_live import issue_confirmation_token, shadow_execution_plan
from intelligence.execution_pilot_activation import OWNER_IDS_ENV, SECURITY_IDS_ENV, ActivationDenied
from intelligence.execution_pilot_ceremony import (
    execute_ceremony,
    issue_ceremony_confirmation,
    read_confirmation_handoff,
    write_confirmation_handoff,
)
from intelligence.execution_pilot_dispatch import (
    DispatchDenied,
    abort_dispatch,
    closeout_dispatch,
    dispatch_default_off,
    dispatch_status,
    execute_once,
    issue_dispatch_confirmation,
    preflight_dispatch,
    record_dispatch_approval,
)
from intelligence.execution_production_webhook import (
    PILOT_KEY_ID_ENV,
    PILOT_SECRET_ENV,
    ProductionUncertain,
    ScriptedProductionTransport,
)
from intelligence.execution_providers import ClosedProvider, get_provider
from intelligence.execution_providers_webhook import StaticResolver

from tests.test_controlled_execution_gateway_phase3_stage4a import authorised_plan
from tests.test_controlled_execution_gateway_phase3_stage4c1 import (
    DEST,
    OWNER,
    SEC,
    TENANT,
    owner,
    security,
)
from tests.test_controlled_execution_gateway_phase3_stage4e import _armed


PUBLIC_IP = "93.184.216.34"


def conn():
    c = sqlite3.connect(":memory:", check_same_thread=False)
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


def _arm_process():
    os.environ["ZORVIAN_EXTERNAL_EXECUTION"] = "pilot"
    os.environ["ZORVIAN_WEBHOOK_PILOT_ENABLED"] = "true"
    os.environ["ZORVIAN_ENV"] = "prod"
    os.environ["ZORVIAN_WEBHOOK_PILOT_TENANT_ID"] = TENANT
    os.environ["ZORVIAN_WEBHOOK_PILOT_HOST_SUFFIX"] = "pilot.example"
    os.environ[PILOT_SECRET_ENV] = "test-only-secret-value"
    os.environ[PILOT_KEY_ID_ENV] = "k1"


def _ceremonial(c):
    prep, challenge = _armed(c)
    conf = issue_ceremony_confirmation(c, pilot_id=prep["pilot_id"], owner=owner(), security=security())
    execute_ceremony(
        c, pilot_id=prep["pilot_id"], owner=owner(), security=security(),
        challenge_nonce=challenge["nonce"], confirmation_token=conf["confirmation_token"],
    )
    t, plan, body = authorised_plan(c, tenant=TENANT, destination=DEST)
    shadow_execution_plan(c, tenant_id=TENANT, user_id="user-a", plan_id=plan["execution_plan_id"], role="owner")
    token = issue_confirmation_token(
        c, tenant_id=TENANT, user_id="user-a", plan_id=plan["execution_plan_id"],
        approval_hash=plan.get("approval_hash"), idempotency_key=plan.get("idempotency_key"),
    )
    if c.in_transaction:
        c.commit()
    return prep, plan, token


def _approve_dispatch(c, pilot_id, plan_id):
    record_dispatch_approval(c, pilot_id=pilot_id, plan_id=plan_id, principal=owner())
    record_dispatch_approval(c, pilot_id=pilot_id, plan_id=plan_id, principal=security())


def test_merge_bootstrap_activates_nothing():
    c = conn()
    assert c.execute("SELECT COUNT(*) AS n FROM execution_pilot_activations").fetchone()["n"] == 0
    assert dispatch_default_off()["closed_provider"] is True
    assert dispatch_default_off()["activated"] is False


def test_default_provider_closed():
    assert isinstance(get_provider(get_adapter("webhook.post")), ClosedProvider)


def test_no_public_dispatch_routes():
    text = open("app_gate5.py").read()
    for route in ("/activate", "/reconcile", "/ceremony", "/dispatch"):
        assert route not in text


def test_preflight_select_only():
    c = conn()
    prep, plan, _ = _ceremonial(c)
    traces: list[str] = []
    write_codes = {
        getattr(sqlite3, name)
        for name in ("SQLITE_INSERT", "SQLITE_UPDATE", "SQLITE_DELETE", "SQLITE_CREATE_TABLE", "SQLITE_DROP_TABLE")
        if hasattr(sqlite3, name)
    }

    def authorizer(action, *_a):
        if action in write_codes:
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    c.set_authorizer(authorizer)
    c.set_trace_callback(lambda s: traces.append(s))
    out = preflight_dispatch(c, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"], owner=owner(), security=security())
    c.set_authorizer(None)
    c.set_trace_callback(None)
    assert out["activation_permitted"] is False
    assert out["webhook_submitted"] is False
    starts = [t.strip().split()[0].upper() for t in traces if t and t.strip()]
    for word in ("CREATE", "INSERT", "UPDATE", "DELETE"):
        assert word not in starts


def test_wrong_plan_and_yes_flag_denied():
    c = conn()
    prep, plan, token = _ceremonial(c)
    with pytest.raises(DispatchDenied):
        preflight_dispatch(c, pilot_id=prep["pilot_id"], plan_id="missing-plan", owner=owner(), security=security())
    _approve_dispatch(c, prep["pilot_id"], plan["execution_plan_id"])
    with pytest.raises(DispatchDenied, match="single-use"):
        execute_once(
            c, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"],
            owner=owner(), security=security(), confirmation_token="yes",
            plan_confirmation_token=token,
        )


def test_same_actor_dual_approval_denied():
    c = conn()
    prep, plan, _ = _ceremonial(c)
    os.environ[SECURITY_IDS_ENV] = OWNER
    from intelligence.execution_pilot_activation import load_offline_platform_principal
    same = load_offline_platform_principal(actor_id=OWNER, requested_role="security_operator")
    with pytest.raises(DispatchDenied, match="different"):
        preflight_dispatch(c, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"], owner=owner(), security=same)


def test_handoff_mode_symlink_and_single_use(tmp_path):
    path = write_confirmation_handoff("dispatch-token", str(tmp_path))
    assert os.stat(path).st_mode & 0o777 == 0o600
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(Exception):
        read_confirmation_handoff(str(link))
    os.chmod(path, 0o644)
    with pytest.raises(Exception):
        read_confirmation_handoff(path)
    os.chmod(path, 0o600)
    assert read_confirmation_handoff(path) == "dispatch-token"
    assert not os.path.exists(path)


def test_execute_2xx_closes_authority_one_call():
    _arm_process()
    c = conn()
    prep, plan, token = _ceremonial(c)
    _approve_dispatch(c, prep["pilot_id"], plan["execution_plan_id"])
    issued = issue_dispatch_confirmation(c, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"], owner=owner(), security=security())
    transport = ScriptedProductionTransport([200])
    resolver = StaticResolver({"hooks.pilot.example": [PUBLIC_IP]})
    out = execute_once(
        c, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"],
        owner=owner(), security=security(),
        confirmation_token=issued["confirmation_token"], plan_confirmation_token=token,
        transport=transport, resolver=resolver,
    )
    assert out["state"] == "EXECUTED"
    assert out["provider_calls"] == 1
    assert len(transport.calls) == 1
    assert c.execute("SELECT enabled FROM execution_live_grants WHERE tenant_id=?", (TENANT,)).fetchone()["enabled"] == 0
    assert c.execute("SELECT COUNT(*) AS n FROM execution_destination_allowlist WHERE tenant_id=?", (TENANT,)).fetchone()["n"] == 0
    assert c.execute("SELECT status FROM execution_pilot_activations WHERE pilot_id=?", (prep["pilot_id"],)).fetchone()["status"] != "ACTIVE"
    replay = execute_once(
        c, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"],
        owner=owner(), security=security(),
        confirmation_token=issued["confirmation_token"], plan_confirmation_token=token,
        transport=transport, resolver=resolver,
    )
    assert replay.get("idempotent_replay") is True
    assert len(transport.calls) == 1


def test_4xx_5xx_timeout_redirect_and_uncertain_no_retry():
    _arm_process()
    mappings = [
        (400, "FAILED"),
        (500, "UNCERTAIN"),
        (ProductionUncertain("timeout"), "UNCERTAIN"),
        (ProductionUncertain("reset"), "UNCERTAIN"),
        (ProductionUncertain("malformed"), "UNCERTAIN"),
    ]
    for scripted, expected in mappings:
        c = conn()
        prep, plan, token = _ceremonial(c)
        _approve_dispatch(c, prep["pilot_id"], plan["execution_plan_id"])
        issued = issue_dispatch_confirmation(c, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"], owner=owner(), security=security())
        transport = ScriptedProductionTransport([scripted])
        resolver = StaticResolver({"hooks.pilot.example": [PUBLIC_IP]})
        out = execute_once(
            c, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"],
            owner=owner(), security=security(),
            confirmation_token=issued["confirmation_token"], plan_confirmation_token=token,
            transport=transport, resolver=resolver,
        )
        assert out["state"] == expected, (scripted, out)
        assert len(transport.calls) == 1
        if expected == "UNCERTAIN":
            replay = execute_once(
                c, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"],
                owner=owner(), security=security(),
                confirmation_token=issued["confirmation_token"], plan_confirmation_token=token,
                transport=transport, resolver=resolver,
            )
            assert replay.get("idempotent_replay") is True
            assert len(transport.calls) == 1
        c.close()


def test_claim_commit_failure_zero_calls(monkeypatch):
    _arm_process()
    c = conn()
    prep, plan, token = _ceremonial(c)
    _approve_dispatch(c, prep["pilot_id"], plan["execution_plan_id"])
    issued = issue_dispatch_confirmation(c, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"], owner=owner(), security=security())
    transport = ScriptedProductionTransport([200])
    resolver = StaticResolver({"hooks.pilot.example": [PUBLIC_IP]})

    def boom(_c):
        raise sqlite3.OperationalError("commit-fail")

    with pytest.raises((DispatchDenied, sqlite3.OperationalError)):
        execute_once(
            c, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"],
            owner=owner(), security=security(),
            confirmation_token=issued["confirmation_token"], plan_confirmation_token=token,
            transport=transport, resolver=resolver, _commit_claim=boom,
        )
    assert transport.calls == []
    assert c.execute("SELECT COUNT(*) AS n FROM execution_attempts").fetchone()["n"] == 0
    assert c.execute("SELECT consumed_at FROM execution_pilot_dispatch_confirmations").fetchone()["consumed_at"] is None


def test_caller_substitution_denied():
    c = conn()
    prep, plan, token = _ceremonial(c)
    with pytest.raises(DispatchDenied, match="substitutes"):
        execute_once(
            c, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"],
            owner=owner(), security=security(), confirmation_token="abc",
            plan_confirmation_token=token, destination_hash="deadbeef",
        )


def test_cli_rejects_credential_argv():
    from intelligence.execution_pilot_dispatch_cli import main
    with pytest.raises(SystemExit):
        main(["execute-once", "--db", ":memory:", "--pilot-id", "p", "--owner-id", OWNER, "--confirmation", "x"])


def test_token_not_in_receipt_or_output():
    _arm_process()
    c = conn()
    prep, plan, token = _ceremonial(c)
    _approve_dispatch(c, prep["pilot_id"], plan["execution_plan_id"])
    issued = issue_dispatch_confirmation(c, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"], owner=owner(), security=security())
    secret = issued["confirmation_token"]
    transport = ScriptedProductionTransport([200])
    resolver = StaticResolver({"hooks.pilot.example": [PUBLIC_IP]})
    out = execute_once(
        c, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"],
        owner=owner(), security=security(),
        confirmation_token=secret, plan_confirmation_token=token,
        transport=transport, resolver=resolver,
    )
    dump = " ".join(row[0] for row in c.execute("SELECT detail_json FROM execution_pilot_dispatch_receipts"))
    assert secret not in dump
    assert secret not in str(out)
    assert os.environ[PILOT_SECRET_ENV] not in dump


def test_status_select_only_and_abort():
    c = conn()
    prep, plan, _ = _ceremonial(c)
    traces = []
    c.set_trace_callback(lambda s: traces.append(s))
    st = dispatch_status(c, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"], principal=owner())
    c.set_trace_callback(None)
    assert st["activation_permitted"] is False
    starts = [t.strip().split()[0].upper() for t in traces if t and t.strip()]
    assert "INSERT" not in starts
    out = abort_dispatch(c, pilot_id=prep["pilot_id"], principal=owner())
    assert out["aborted"] is True


def test_altered_payload_hash_denied():
    c = conn()
    prep, plan, token = _ceremonial(c)
    _approve_dispatch(c, prep["pilot_id"], plan["execution_plan_id"])
    c.execute("UPDATE execution_plans SET payload_hash=?", ("00" * 32,))
    if c.in_transaction:
        c.commit()
    with pytest.raises(DispatchDenied):
        issue_dispatch_confirmation(c, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"], owner=owner(), security=security())


def test_cross_pilot_isolation():
    c_a = conn()
    c_b = conn()
    prep_a, plan_a, token_a = _ceremonial(c_a)
    prep_b, plan_b, token_b = _ceremonial(c_b)
    _approve_dispatch(c_a, prep_a["pilot_id"], plan_a["execution_plan_id"])
    issued_a = issue_dispatch_confirmation(c_a, pilot_id=prep_a["pilot_id"], plan_id=plan_a["execution_plan_id"], owner=owner(), security=security())
    with pytest.raises((DispatchDenied, ActivationDenied)):
        execute_once(
            c_b, pilot_id=prep_b["pilot_id"], plan_id=plan_b["execution_plan_id"],
            owner=owner(), security=security(),
            confirmation_token=issued_a["confirmation_token"], plan_confirmation_token=token_b,
        )


def test_concurrent_dispatch_one_provider_call(tmp_path):
    _arm_process()
    path = str(tmp_path / "d4f.sqlite")
    setup = sqlite3.connect(path)
    setup.row_factory = sqlite3.Row
    ensure_execution_schema(setup)
    if setup.in_transaction:
        setup.commit()
    prep, plan, token = _ceremonial(setup)
    _approve_dispatch(setup, prep["pilot_id"], plan["execution_plan_id"])
    issued = issue_dispatch_confirmation(setup, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"], owner=owner(), security=security())
    setup.close()
    transport = ScriptedProductionTransport([200])
    resolver = StaticResolver({"hooks.pilot.example": [PUBLIC_IP]})
    results: list[str] = []

    def worker():
        local = sqlite3.connect(path, timeout=10)
        local.row_factory = sqlite3.Row
        try:
            execute_once(
                local, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"],
                owner=owner(), security=security(),
                confirmation_token=issued["confirmation_token"], plan_confirmation_token=token,
                transport=transport, resolver=resolver,
            )
            results.append("win")
        except Exception:
            results.append("lose")
        finally:
            local.close()

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert results.count("win") >= 1
    assert len(transport.calls) == 1


def test_foreign_pilot_replay_denied():
    _arm_process()
    c = conn()
    prep, plan, token = _ceremonial(c)
    _approve_dispatch(c, prep["pilot_id"], plan["execution_plan_id"])
    issued = issue_dispatch_confirmation(c, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"], owner=owner(), security=security())
    transport = ScriptedProductionTransport([200])
    resolver = StaticResolver({"hooks.pilot.example": [PUBLIC_IP]})
    execute_once(
        c, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"],
        owner=owner(), security=security(),
        confirmation_token=issued["confirmation_token"], plan_confirmation_token=token,
        transport=transport, resolver=resolver,
    )
    with pytest.raises(DispatchDenied, match="pilot preparation not found"):
        execute_once(
            c, pilot_id="foreign-pilot", plan_id=plan["execution_plan_id"],
            owner=owner(), security=security(),
            confirmation_token="invalid-token", plan_confirmation_token="invalid-plan",
            transport=transport, resolver=resolver,
        )


def test_confirmation_issuers_must_match_stored_approvers():
    from intelligence.execution_pilot_activation import load_offline_platform_principal
    os.environ[OWNER_IDS_ENV] = f"{OWNER},owner-alt"
    os.environ[SECURITY_IDS_ENV] = f"{SEC},sec-alt"
    c = conn()
    prep, plan, token = _ceremonial(c)
    _approve_dispatch(c, prep["pilot_id"], plan["execution_plan_id"])
    alt_owner = load_offline_platform_principal(actor_id="owner-alt", requested_role="platform_owner")
    alt_sec = load_offline_platform_principal(actor_id="sec-alt", requested_role="security_operator")
    with pytest.raises(DispatchDenied, match="stored approvers"):
        issue_dispatch_confirmation(
            c, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"],
            owner=alt_owner, security=alt_sec,
        )


def test_duplicate_active_approval_denied():
    c = conn()
    prep, plan, token = _ceremonial(c)
    record_dispatch_approval(c, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"], principal=owner())
    with pytest.raises(DispatchDenied, match="active approval"):
        record_dispatch_approval(c, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"], principal=owner())


def test_status_requires_validated_principal():
    c = conn()
    prep, plan, token = _ceremonial(c)
    with pytest.raises(TypeError):
        dispatch_status(c, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"])
    with pytest.raises(DispatchDenied):
        dispatch_status(c, pilot_id="missing", plan_id=plan["execution_plan_id"], principal=owner())
    with pytest.raises(DispatchDenied):
        dispatch_status(c, pilot_id=prep["pilot_id"], plan_id="other-plan", principal=owner())


def test_replay_requires_original_principals():
    from intelligence.execution_pilot_activation import load_offline_platform_principal
    _arm_process()
    os.environ[OWNER_IDS_ENV] = f"{OWNER},owner-alt"
    os.environ[SECURITY_IDS_ENV] = f"{SEC},sec-alt"
    c = conn()
    prep, plan, token = _ceremonial(c)
    _approve_dispatch(c, prep["pilot_id"], plan["execution_plan_id"])
    issued = issue_dispatch_confirmation(c, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"], owner=owner(), security=security())
    transport = ScriptedProductionTransport([200])
    resolver = StaticResolver({"hooks.pilot.example": [PUBLIC_IP]})
    execute_once(
        c, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"],
        owner=owner(), security=security(),
        confirmation_token=issued["confirmation_token"], plan_confirmation_token=token,
        transport=transport, resolver=resolver,
    )
    alt_owner = load_offline_platform_principal(actor_id="owner-alt", requested_role="platform_owner")
    alt_sec = load_offline_platform_principal(actor_id="sec-alt", requested_role="security_operator")
    with pytest.raises(DispatchDenied, match="original authorised principals"):
        execute_once(
            c, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"],
            owner=alt_owner, security=alt_sec,
            confirmation_token="invalid", plan_confirmation_token="invalid",
            transport=transport, resolver=resolver,
        )


def test_revoked_approvals_during_resolution_zero_calls():
    from intelligence.execution import _iso

    _arm_process()
    c = conn()
    prep, plan, token = _ceremonial(c)
    _approve_dispatch(c, prep["pilot_id"], plan["execution_plan_id"])
    issued = issue_dispatch_confirmation(
        c, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"], owner=owner(), security=security()
    )
    transport = ScriptedProductionTransport([200])
    inner = StaticResolver({"hooks.pilot.example": [PUBLIC_IP]})

    class RevokingResolver:
        def resolve(self, hostname: str):
            c.execute(
                "UPDATE execution_pilot_dispatch_approvals SET revoked_at=? WHERE pilot_id=? AND revoked_at IS NULL",
                (_iso(), prep["pilot_id"]),
            )
            if c.in_transaction:
                c.commit()
            return inner.resolve(hostname)

    with pytest.raises(DispatchDenied):
        execute_once(
            c, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"],
            owner=owner(), security=security(),
            confirmation_token=issued["confirmation_token"], plan_confirmation_token=token,
            transport=transport, resolver=RevokingResolver(),
        )
    assert transport.calls == []
    assert c.execute("SELECT COUNT(*) AS n FROM execution_attempts").fetchone()["n"] == 0
    assert c.execute("SELECT consumed_at FROM execution_pilot_dispatch_confirmations").fetchone()["consumed_at"] is None
    grant = c.execute("SELECT enabled FROM execution_live_grants WHERE tenant_id=?", (TENANT,)).fetchone()
    assert grant is not None and grant["enabled"] == 1


def test_production_remains_off():
    assert dispatch_default_off()["external_execution"] is False
    assert dispatch_default_off()["webhook_submitted"] is False
