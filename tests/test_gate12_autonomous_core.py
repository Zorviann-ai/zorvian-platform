import os
import uuid

os.environ.setdefault("ZORVIAN_ENV", "test")
os.environ.setdefault("DEV_EXPOSE_TOKENS", "1")
os.environ.setdefault("ALLOW_LOCAL_BETA", "1")

from fastapi.testclient import TestClient
from app_gate12 import app
from app import db, hash_password, now


def owner_session():
    tenant_id = "tenant-" + uuid.uuid4().hex
    user_id = "user-" + uuid.uuid4().hex
    email = f"owner-{uuid.uuid4().hex[:10]}@example.test"
    c = db()
    c.execute("INSERT INTO tenants(id,name,created_at,slug,status,plan,owner_user_id) VALUES (?,?,?,?,?,?,?)", (tenant_id, "Autonomy Test", now(), "autonomy-"+uuid.uuid4().hex[:6], "active", "gate12", user_id))
    c.execute("INSERT INTO users(id,tenant_id,email,password_hash,role,created_at,display_name,email_verified,mfa_enabled,status,failed_attempts,password_changed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (user_id, tenant_id, email, hash_password("StrongAutonomy!Password123"), "owner", now(), "Owner", 1, 0, "active", 0, now()))
    c.commit(); c.close()
    client = TestClient(app)
    login = client.post("/auth/login", json={"email": email, "password": "StrongAutonomy!Password123"})
    assert login.status_code == 200
    return client, {"Authorization": "Bearer " + login.json()["token"]}, tenant_id


def test_autonomy_is_authenticated_and_tenant_safe():
    client = TestClient(app)
    assert client.get("/core/autonomy/status").status_code == 401
    c, h, tenant = owner_session()
    assert c.get("/core/autonomy/status", headers=h).status_code == 200
    assert c.get("/core/autonomy/status", headers=h).json()["autonomy"]["external_actions_require_approval"] is True


def test_core_creates_reversible_internal_followup_tasks():
    client, headers, tenant_id = owner_session()
    c = db(); cid = str(uuid.uuid4())
    c.execute("INSERT INTO contacts VALUES (?,?,?,?,?,?,?,?)", (cid, tenant_id, "Ada Customer", "ada@example.test", "Needs a quotation", "test", 82, now())); c.commit(); c.close()
    run = client.post("/core/autonomy/run", headers=headers, json={"trigger":"manual","objective":"Keep leads moving"})
    assert run.status_code == 200
    body = run.json(); assert body["actions"]
    c = db(); task = c.execute("SELECT * FROM tasks WHERE tenant_id=? AND title LIKE '%[contact:%'", (tenant_id,)).fetchone(); c.close()
    assert task is not None
    assert task["owner"] == "Zorvian Core"


def test_consequential_provider_action_requires_tenant_bound_approval():
    client, headers, _ = owner_session()
    denied = client.post("/core/providers/execute", headers=headers, json={"service":"email","operation":"send","payload":{"to":"x@example.test","subject":"x","text":"x"}})
    assert denied.status_code == 409
    approval = client.post("/core/providers/approvals", headers=headers, json={"service":"email","operation":"send","payload":{"to":"x@example.test"}})
    assert approval.status_code == 200
    aid = approval.json()["approval_id"]
    assert client.post(f"/core/providers/approvals/{aid}/approve", headers=headers).status_code == 200


def test_docker_runs_gate12():
    docker = open("Dockerfile", encoding="utf-8").read()
    assert "app_gate12.py provider_mesh.py" in docker
    assert "uvicorn app_gate12:app" in docker
