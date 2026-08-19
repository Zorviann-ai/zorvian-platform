import os
import tempfile
import uuid
from pathlib import Path

from deployment.readiness import readiness_report


def valid_env(name="staging", db_id="staging-db"):
    return {
        "ZORVIAN_ENV": name,
        "ZORVIAN_ENVIRONMENT_ID": name + "-environment",
        "ZORVIAN_DATABASE_ID": db_id,
        "SQLITE_PATH": "/data/zorvian/" + name + ".db",
        "GUARDIAN_HASH_PEPPER": "p" * 48,
        "ALLOWED_ORIGINS": "https://" + name + ".zorvian.co.uk",
        "SMTP_HOST": "smtp.example.test",
        "SMTP_USERNAME": "zorvian",
        "SMTP_PASSWORD": "not-a-real-secret",
        "SMTP_FROM": "test@example.test",
        "ZORVIAN_AI_ADAPTER_URL": "https://adapter.example.test/run",
        "ZORVIAN_AI_ADAPTER_KEY": "k" * 32,
    }


def test_readiness_fails_closed_when_configuration_is_missing():
    report = readiness_report({})
    assert report["ready"] is False
    assert all(item["passed"] is False for item in report["checks"])


def test_readiness_accepts_complete_isolated_configuration():
    report = readiness_report(valid_env())
    assert report["ready"] is True
    assert report["gate"] == 6


def test_ephemeral_database_paths_are_rejected():
    for path in ["/tmp/zorvian.db", "/app/zorvian.db", "zorvian.db"]:
        env = valid_env()
        env["SQLITE_PATH"] = path
        assert readiness_report(env)["ready"] is False


def test_staging_and_production_identifiers_must_be_distinct():
    staging = valid_env("staging", "zorvian-staging-db")
    production = valid_env("production", "zorvian-production-db")
    assert staging["ZORVIAN_ENVIRONMENT_ID"] != production["ZORVIAN_ENVIRONMENT_ID"]
    assert staging["ZORVIAN_DATABASE_ID"] != production["ZORVIAN_DATABASE_ID"]
    assert staging["SQLITE_PATH"] != production["SQLITE_PATH"]


def test_gate6_source_keeps_readiness_and_pilot_admin_only():
    source = Path("app_gate6.py").read_text(encoding="utf-8")
    assert source.count('require(u, "admin")') == 2
    assert '@app.get("/readiness")' in source
    assert '@app.post("/pilot/evidence")' in source
    assert "ZORVIAN_AI_ADAPTER_KEY" not in source


def test_persistent_sqlite_data_survives_new_connection():
    import sqlite3
    db_path = Path(tempfile.gettempdir()) / ("zorvian-gate6-" + uuid.uuid4().hex + ".db")
    try:
        first = sqlite3.connect(db_path)
        first.execute("CREATE TABLE pilot_evidence(id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL)")
        first.execute("INSERT INTO pilot_evidence VALUES (?, ?)", ("evidence-1", "tenant-a"))
        first.commit()
        first.close()
        second = sqlite3.connect(db_path)
        row = second.execute("SELECT tenant_id FROM pilot_evidence WHERE id=?", ("evidence-1",)).fetchone()
        second.close()
        assert row == ("tenant-a",)
    finally:
        if db_path.exists():
            db_path.unlink()
