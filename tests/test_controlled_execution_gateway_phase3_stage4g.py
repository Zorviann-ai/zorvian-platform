from __future__ import annotations

import ast
import contextvars
import os
import socket
import sqlite3
from pathlib import Path

import pytest

from intelligence.execution import ensure_execution_schema
from intelligence.execution_adapters import get_adapter
from intelligence.execution_pilot_activation import OWNER_IDS_ENV, SECURITY_IDS_ENV
from intelligence.execution_pilot_dispatch import (
    DispatchDenied,
    dispatch_default_off,
    execute_once,
    issue_dispatch_confirmation,
)
from intelligence import execution_production_webhook as webhook
from intelligence.execution_production_webhook import (
    PILOT_KEY_ID_ENV,
    PILOT_SECRET_ENV,
    ProductionPilotDenied,
    ScriptedProductionTransport,
    refuse_live_http_dispatch,
    submit_production_pilot,
)
from intelligence.execution_providers import ClosedProvider, get_provider
from intelligence.execution_providers_webhook import StaticResolver

from tests.test_controlled_execution_gateway_phase3_stage4a import PILOT_TENANT, ready as ready_4a
from tests.test_controlled_execution_gateway_phase3_stage4c1 import OWNER, SEC, owner, security
from tests.test_controlled_execution_gateway_phase3_stage4f import (
    PUBLIC_IP,
    _approve_dispatch,
    _arm_process,
    _ceremonial,
)


PRIVATE_ENGINE = "_claimed_production_submit"
SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules",
    "__pycache__", "build", "dist", "site-packages", ".tox", ".mypy_cache",
    ".pytest_cache", "tests",
}


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


def test_default_provider_closed():
    assert isinstance(get_provider(get_adapter("webhook.post")), ClosedProvider)
    off = dispatch_default_off()
    assert off["webhook_submitted"] is False
    assert off["activated"] is False


def test_no_public_control_routes():
    text = Path("app_gate5.py").read_text()
    assert "/dispatch" not in text
    assert "/activate" not in text
    assert "/reconcile" not in text
    assert "/ceremony" not in text
    assert "submit_production_pilot(" not in text
    live = text.split('@app.post("/api/execution/plans/{plan_id}/live")', 1)[1].split("@app.", 1)[0]
    assert "refuse_live_http_dispatch()" in live
    assert "confirmation token is required" not in live


def test_public_lower_level_functions_denied_zero_state():
    c = conn()
    t, plan, token, transport, resolver = ready_4a(c)
    _arm_process()
    with pytest.raises(ProductionPilotDenied, match="permanently closed"):
        refuse_live_http_dispatch()
    with pytest.raises(ProductionPilotDenied, match="reserved to Stage 4F"):
        submit_production_pilot(
            c, tenant_id=PILOT_TENANT, user_id="user-a", plan_id=plan["execution_plan_id"],
            confirmation_token=token, role="owner", transport=transport, resolver=resolver,
        )
    with pytest.raises(ProductionPilotDenied, match="reserved to Stage 4F"):
        submit_production_pilot(
            c, tenant_id=PILOT_TENANT, user_id="user-a", plan_id=plan["execution_plan_id"],
            confirmation_token=token, role="owner", transport=transport, resolver=resolver,
        )
    assert not hasattr(webhook, "authorise_production_submit")
    with pytest.raises(ProductionPilotDenied, match="reserved to Stage 4F"):
        webhook._claimed_production_submit(
            c, tenant_id=PILOT_TENANT, user_id="user-a", plan_id=plan["execution_plan_id"],
            confirmation_token=token, role="owner", transport=transport, resolver=resolver,
        )
    with webhook._stage4f_submit_authority():
        with pytest.raises(ProductionPilotDenied, match="reserved to Stage 4F"):
            webhook._claimed_production_submit(
                c, tenant_id=PILOT_TENANT, user_id="user-a", plan_id=plan["execution_plan_id"],
                confirmation_token=token, role="owner", transport=transport, resolver=resolver,
            )
    assert transport.calls == []
    assert c.execute("SELECT COUNT(*) AS n FROM execution_attempts").fetchone()["n"] == 0


def test_reentrant_and_double_submit_via_execute_once(monkeypatch):
    import intelligence.execution_pilot_dispatch as dispatch
    c = conn()
    prep, plan, token = _ceremonial(c)
    _arm_process()
    _approve_dispatch(c, prep["pilot_id"], plan["execution_plan_id"])
    issued = issue_dispatch_confirmation(
        c, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"],
        owner=owner(), security=security(),
    )
    transport = ScriptedProductionTransport([200])
    resolver = StaticResolver({"hooks.pilot.example": [PUBLIC_IP]})
    nested = {"denied": False}
    real = webhook._claimed_production_submit

    def wrap(*a, **k):
        orig = k.get("_after_claim_writes")

        def after():
            if orig:
                orig()
            with pytest.raises(ProductionPilotDenied, match="re-entrant"):
                real(*a, **{key: val for key, val in k.items() if key != "_after_claim_writes"})
            nested["denied"] = True

        k = dict(k)
        k["_after_claim_writes"] = after
        return real(*a, **k)

    def wrap_and_copy(*a, **k):
        copied = contextvars.copy_context()
        out = wrap(*a, **k)
        with pytest.raises(ProductionPilotDenied, match="reserved to Stage 4F"):
            copied.run(
                real,
                *a,
                **{key: val for key, val in k.items() if key != "_after_claim_writes"},
            )
        return out

    monkeypatch.setattr(dispatch, "_claimed_production_submit", wrap_and_copy)
    out = execute_once(
        c, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"],
        owner=owner(), security=security(),
        confirmation_token=issued["confirmation_token"],
        plan_confirmation_token=token, transport=transport, resolver=resolver,
    )
    assert nested["denied"] is True
    assert out["state"] == "EXECUTED"
    assert len(transport.calls) == 1
    replay = execute_once(
        c, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"],
        owner=owner(), security=security(),
        confirmation_token=issued["confirmation_token"],
        plan_confirmation_token=token, transport=transport, resolver=resolver,
    )
    assert replay.get("idempotent_replay") is True or replay.get("state") in {"EXECUTED", "COMPLETED"}
    assert len(transport.calls) == 1


def test_missing_and_revoked_4f_approval_zero_calls():
    c = conn()
    prep, plan, token = _ceremonial(c)
    _arm_process()
    transport = ScriptedProductionTransport([200])
    resolver = StaticResolver({"hooks.pilot.example": [PUBLIC_IP]})
    with pytest.raises((DispatchDenied, ProductionPilotDenied)):
        execute_once(
            c, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"],
            owner=owner(), security=security(),
            confirmation_token="not-a-real-token",
            plan_confirmation_token=token, transport=transport, resolver=resolver,
        )
    assert transport.calls == []
    _approve_dispatch(c, prep["pilot_id"], plan["execution_plan_id"])
    issued = issue_dispatch_confirmation(
        c, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"],
        owner=owner(), security=security(),
    )
    c.execute("UPDATE execution_pilot_dispatch_approvals SET revoked_at=?", ("2000-01-01T00:00:00+00:00",))
    if c.in_transaction:
        c.commit()
    with pytest.raises((DispatchDenied, ProductionPilotDenied)):
        execute_once(
            c, pilot_id=prep["pilot_id"], plan_id=plan["execution_plan_id"],
            owner=owner(), security=security(),
            confirmation_token=issued["confirmation_token"],
            plan_confirmation_token=token, transport=transport, resolver=resolver,
        )
    assert transport.calls == []


def _skipped(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def _refers(node: ast.AST, name: str) -> bool:
    if isinstance(node, ast.Name) and node.id == name:
        return True
    if isinstance(node, ast.Attribute) and node.attr == name:
        return True
    if isinstance(node, ast.alias) and name in {node.name, node.asname}:
        return True
    if isinstance(node, ast.Constant) and node.value == name:
        return True
    return False


def _production_py_files() -> list[Path]:
    files = []
    for path in Path(".").rglob("*.py"):
        if _skipped(path):
            continue
        files.append(path)
    return files


def test_static_scan_private_engine_only_inside_execute_once():
    dispatch = Path("intelligence/execution_pilot_dispatch.py")
    webhook_path = Path("intelligence/execution_production_webhook.py")
    call_sites = []
    import_sites = []
    other_refs = []
    for path in _production_py_files():
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if PRIVATE_ENGINE in {alias.name, alias.asname}:
                        import_sites.append((path, alias.asname or alias.name, node.lineno))
            elif isinstance(node, ast.Call):
                func = node.func
                called = None
                if isinstance(func, ast.Name) and func.id == PRIVATE_ENGINE:
                    called = func.id
                elif isinstance(func, ast.Attribute) and func.attr == PRIVATE_ENGINE:
                    called = func.attr
                if called:
                    call_sites.append((path, node.lineno))
            elif _refers(node, PRIVATE_ENGINE):
                if path not in {dispatch, webhook_path}:
                    other_refs.append((str(path), getattr(node, "lineno", 0)))

    assert other_refs == []
    assert import_sites == [(dispatch, PRIVATE_ENGINE, import_sites[0][2])] if import_sites else False
    assert len(import_sites) == 1
    assert import_sites[0][0] == dispatch
    assert len(call_sites) == 1
    assert call_sites[0][0] == dispatch

    tree = ast.parse(dispatch.read_text())
    execute = None
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "execute_once":
            execute = node
            break
    assert execute is not None
    inner_calls = 0
    for node in ast.walk(execute):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id == PRIVATE_ENGINE:
            inner_calls += 1
        elif isinstance(func, ast.Attribute) and func.attr == PRIVATE_ENGINE:
            inner_calls += 1
    assert inner_calls == 1
    src = webhook_path.read_text()
    assert "def authorise_production_submit" not in src
    assert "PYTEST_CURRENT_TEST" not in src


def test_merge_bootstrap_activates_nothing():
    c = conn()
    assert c.execute("SELECT COUNT(*) AS n FROM execution_pilot_activations").fetchone()["n"] == 0
    assert c.execute("SELECT COUNT(*) AS n FROM execution_live_grants WHERE enabled=1").fetchone()["n"] == 0
    assert isinstance(get_provider(get_adapter("webhook.post")), ClosedProvider)
