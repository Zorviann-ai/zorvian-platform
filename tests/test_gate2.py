import os
import tempfile

# Configure the application before import so tests never touch production data.
_fd, DB_PATH = tempfile.mkstemp(prefix="zorvian-gate2-", suffix=".db")
os.close(_fd)
os.environ["ZORVIAN_ENV"] = "test"
os.environ["SQLITE_PATH"] = DB_PATH
os.environ["DEV_EXPOSE_TOKENS"] = "1"
os.environ["GUARDIAN_HASH_PEPPER"] = "gate2-test-pepper-not-production"
os.environ["ALLOWED_ORIGINS"] = "https://caelomere.com,https://www.caelomere.com"

from fastapi.testclient import TestClient
from app import app

client = TestClient(app)


def register_verified(company, name, email, password):
    r = client.post("/auth/register", json={
        "company_name": company,
        "name": name,
        "email": email,
        "password": password,
    })
    assert r.status_code == 201, r.text
    token = r.json().get("verification_token")
    assert token
    v = client.post("/auth/verify-email", json={"token": token})
    assert v.status_code == 200, v.text
    l = client.post("/auth/login", json={"email": email, "password": password})
    assert l.status_code == 200, l.text
    return l.json()["token"]


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_gate2_account_login_guardian_and_logout():
    token = register_verified(
        "Northstar Logistics",
        "Alex Owner",
        "alex.owner@example.com",
        "A-secure-gate2-password-2026!",
    )

    me = client.get("/auth/me", headers=auth(token))
    assert me.status_code == 200, me.text
    data = me.json()
    assert data["role"] == "owner"
    assert data["workspace"]["name"] == "Northstar Logistics"

    guardian = client.get("/guardian/status", headers=auth(token))
    assert guardian.status_code == 200, guardian.text
    g = guardian.json()
    assert g["guardian"] == "active"
    assert g["tenant_isolation"] == "enforced"
    assert g["password_hashing"] == "argon2id"
    assert g["session_tokens"] == "hashed_at_rest"

    logout = client.post("/auth/logout", headers=auth(token), json={})
    assert logout.status_code == 200, logout.text
    assert client.get("/auth/me", headers=auth(token)).status_code == 401


def test_tenant_data_isolation():
    token_a = register_verified(
        "Tenant Alpha",
        "Alpha Owner",
        "alpha@example.com",
        "Alpha-tenant-secure-password-2026!",
    )
    token_b = register_verified(
        "Tenant Beta",
        "Beta Owner",
        "beta@example.com",
        "Beta-tenant-secure-password-2026!",
    )

    created = client.post("/contacts", headers=auth(token_a), json={
        "name": "Alpha Customer",
        "contact": "alpha.customer@example.com",
        "need": "private Alpha requirement",
        "source": "test",
    })
    assert created.status_code == 200, created.text

    a_contacts = client.get("/contacts", headers=auth(token_a))
    b_contacts = client.get("/contacts", headers=auth(token_b))
    assert a_contacts.status_code == 200
    assert b_contacts.status_code == 200
    assert len(a_contacts.json()) == 1
    assert a_contacts.json()[0]["name"] == "Alpha Customer"
    assert b_contacts.json() == []


def test_unverified_account_cannot_login():
    r = client.post("/auth/register", json={
        "company_name": "Verification Required Ltd",
        "name": "Verify Owner",
        "email": "verify.required@example.com",
        "password": "Verification-required-password-2026!",
    })
    assert r.status_code == 201
    login = client.post("/auth/login", json={
        "email": "verify.required@example.com",
        "password": "Verification-required-password-2026!",
    })
    assert login.status_code == 403


def teardown_module(module):
    try:
        os.unlink(DB_PATH)
    except FileNotFoundError:
        pass
