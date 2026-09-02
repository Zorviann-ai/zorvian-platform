"""Isolate the full pytest suite from shared SQLite files and leaked process env.

Collection-time imports previously set RESEND_API_KEY / SMTP_* / SQLITE_PATH on
the process. Later tests then reused that state, including a module-level
app.DB snapshot. This conftest restores a safe baseline around every test.
"""
from __future__ import annotations

import base64
import os
import sqlite3
import sys
import tempfile

import pytest

_LEAKED_KEYS = (
    "RESEND_API_KEY",
    "RESEND_INBOUND_DOMAIN",
    "RESEND_WEBHOOK_SECRET",
    "SMTP_HOST",
    "SMTP_PASSWORD",
    "SMTP_USERNAME",
    "SMTP_FROM",
    "CONTROL_PLANE_FAIL_WRITE",
    "ZORVIAN_EXTERNAL_EXECUTION",
    "ALLOW_LOCAL_BETA",
)

_EMAIL_TEST_MARKERS = ("gate7_email", "gate7_operational", "test_gate7_")


def pytest_configure(config):
    fd, path = tempfile.mkstemp(prefix="zorvian-pytest-session-", suffix=".db")
    os.close(fd)
    os.environ["_ZORVIAN_PYTEST_SESSION_DB"] = path
    os.environ["SQLITE_PATH"] = path
    os.environ["ZORVIAN_ENV"] = os.environ.get("ZORVIAN_ENV") or "test"
    os.environ.pop("ZORVIAN_EXTERNAL_EXECUTION", None)


def _is_email_suite(nodeid: str) -> bool:
    return any(token in nodeid for token in _EMAIL_TEST_MARKERS)


@pytest.fixture(autouse=True)
def _isolate_zorvian_runtime(request, tmp_path):
    snapshot = {key: os.environ.get(key) for key in _LEAKED_KEYS}
    snapshot_sqlite = os.environ.get("SQLITE_PATH")
    snapshot_dev = os.environ.get("DEV_EXPOSE_TOKENS")

    nodeid = request.node.nodeid
    if not _is_email_suite(nodeid):
        for key in _LEAKED_KEYS:
            if key == "ALLOW_LOCAL_BETA" and any(tok in nodeid for tok in ("test_gate5_", "test_gate12_", "test_fix2_")):
                continue
            os.environ.pop(key, None)
    elif "test_gate7_operational_email" in nodeid:
        os.environ["RESEND_API_KEY"] = "re_test_only"
        os.environ["SMTP_FROM"] = "Caelomere <support@caelomere.com>"
        os.environ["RESEND_INBOUND_DOMAIN"] = "inbound.zorvian.test"
        key = getattr(request.module, "WEBHOOK_KEY", b"gate7-test-webhook-key-32-bytes!!")
        os.environ["RESEND_WEBHOOK_SECRET"] = "whsec_" + base64.b64encode(key).decode()
    elif "test_gate7_email_centre" in nodeid:
        os.environ["RESEND_API_KEY"] = "re_test"
        os.environ["SMTP_FROM"] = "Caelomere <support@caelomere.com>"
        os.environ["RESEND_INBOUND_DOMAIN"] = "inbound.zorvian.test"
        os.environ["RESEND_WEBHOOK_SECRET"] = "whsec_Z2F0ZTctdGVzdC13ZWJob29rLWtleQ=="

    os.environ["ZORVIAN_ENV"] = "test"
    if "DEV_EXPOSE_TOKENS" not in os.environ:
        os.environ["DEV_EXPOSE_TOKENS"] = "1"

    app_mod = sys.modules.get("app")
    module_db = getattr(request.module, "DB_PATH", None)
    if module_db:
        os.environ["SQLITE_PATH"] = str(module_db)
    elif not _is_email_suite(nodeid):
        os.environ["SQLITE_PATH"] = str(tmp_path / "zorvian-test.db")
    if app_mod is not None and hasattr(app_mod, "DB"):
        app_mod.DB = os.environ["SQLITE_PATH"]
        if hasattr(app_mod, "init_db"):
            app_mod.init_db()
    gate9 = sys.modules.get("app_gate9")
    if gate9 is not None and hasattr(gate9, "_ensure_email_tables"):
        gate9._ensure_email_tables()

    connections = []
    original_connect = sqlite3.connect

    def tracked_connect(*args, **kwargs):
        conn = original_connect(*args, **kwargs)
        connections.append(conn)
        return conn

    sqlite3.connect = tracked_connect
    try:
        yield
    finally:
        sqlite3.connect = original_connect
        for conn in connections:
            try:
                conn.close()
            except sqlite3.Error:
                pass
        for key in _LEAKED_KEYS:
            value = snapshot.get(key)
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        if snapshot_sqlite is None:
            os.environ.pop("SQLITE_PATH", None)
        else:
            os.environ["SQLITE_PATH"] = snapshot_sqlite
        if snapshot_dev is None:
            os.environ.pop("DEV_EXPOSE_TOKENS", None)
        else:
            os.environ["DEV_EXPOSE_TOKENS"] = snapshot_dev
        if app_mod is not None and hasattr(app_mod, "DB") and snapshot_sqlite:
            app_mod.DB = snapshot_sqlite
        os.environ.pop("ZORVIAN_EXTERNAL_EXECUTION", None)
