import os
import tempfile
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

DB_PATH = Path(tempfile.gettempdir()) / "zorvian_fix2_test.db"
if DB_PATH.exists():
    DB_PATH.unlink()
os.environ["SQLITE_PATH"] = str(DB_PATH)
os.environ["ZORVIAN_ENV"] = "test"
os.environ["DEV_EXPOSE_TOKENS"] = "1"

from app_gate12 import app
import app_gate5
import app_gate12

CLIENT = TestClient(app)


def _verified_session():
    email = f"fix2-{uuid.uuid4().hex[:8]}@example.com"
    password = "VeryStrongFix2!Password"
    reg = CLIENT.post("/auth/register", json={"company_name":"Fix 2 Test Co","name":"Fix Two","email":email,"password":password})
    assert reg.status_code == 201
    verification = reg.json()["verification_token"]
    assert CLIENT.post("/auth/verify-email", json={"token":verification}).status_code == 200
    login = CLIENT.post("/auth/login", json={"email":email,"password":password})
    assert login.status_code == 200
    return login.json()["token"]


def _headers():
    return {"Authorization": "Bearer " + _verified_session()}


def _clear_provider_env(monkeypatch):
    for key in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "ZORVIAN_AI_ADAPTER_URL", "ZORVIAN_AI_ADAPTER_KEY", "ALLOW_LOCAL_BETA"):
        monkeypatch.delenv(key, raising=False)


def test_local_beta_defaults_off(monkeypatch):
    _clear_provider_env(monkeypatch)
    assert app_gate5._local_beta_enabled() is False


def test_capabilities_unavailable_without_provider(monkeypatch):
    _clear_provider_env(monkeypatch)
    response = CLIENT.get("/intelligence/capabilities", headers=_headers())
    assert response.status_code == 200
    body = response.json()
    assert body["provider_mode"] == "unavailable"
    assert body["configured_provider_count"] == 0
    assert body["local_beta_enabled"] is False


def test_capabilities_identify_controlled_local_beta(monkeypatch):
    _clear_provider_env(monkeypatch)
    monkeypatch.setenv("ALLOW_LOCAL_BETA", "1")
    response = CLIENT.get("/intelligence/capabilities", headers=_headers())
    assert response.status_code == 200
    body = response.json()
    assert body["provider_mode"] == "controlled-local-beta"
    assert body["local_beta_enabled"] is True


def test_intelligence_returns_503_without_provider(monkeypatch):
    _clear_provider_env(monkeypatch)
    response = CLIENT.post(
        "/intelligence/run",
        headers=_headers(),
        json={"module":"business-control","task":"review","prompt":"Review this workspace"},
    )
    assert response.status_code == 503


def test_intelligence_provider_failure_returns_502(monkeypatch):
    _clear_provider_env(monkeypatch)

    class BrokenService:
        def run(self, *args, **kwargs):
            raise RuntimeError("provider exploded")

    monkeypatch.setattr(app_gate5, "_service", lambda: BrokenService())
    response = CLIENT.post(
        "/intelligence/run",
        headers=_headers(),
        json={"module":"business-control","task":"review","prompt":"Review this workspace"},
    )
    assert response.status_code == 502


def test_autonomy_does_not_return_false_success_without_provider(monkeypatch):
    _clear_provider_env(monkeypatch)
    response = CLIENT.post(
        "/core/autonomy/run",
        headers=_headers(),
        json={"trigger":"manual","objective":"Review the CRM"},
    )
    assert response.status_code == 503
    detail = response.json()["detail"]
    assert detail["ai_complete"] is False
    assert "run_id" in detail


def test_autonomy_provider_failure_returns_502(monkeypatch):
    class BrokenService:
        def run(self, *args, **kwargs):
            raise RuntimeError("provider exploded")

    monkeypatch.setattr(app_gate12, "_service", lambda: BrokenService())
    response = CLIENT.post(
        "/core/autonomy/run",
        headers=_headers(),
        json={"trigger":"manual","objective":"Review the CRM"},
    )
    assert response.status_code == 502
    detail = response.json()["detail"]
    assert detail["ai_complete"] is False
    assert "run_id" in detail
