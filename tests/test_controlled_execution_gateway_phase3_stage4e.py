from __future__ import annotations

import os
import socket
import sqlite3
import threading

import pytest

from intelligence.execution import ensure_execution_schema
from intelligence.execution_adapters import get_adapter
from intelligence.execution_pilot_activation import (
    OWNER_IDS_ENV,
    SECURITY_IDS_ENV,
    ActivationDenied,
    activate_pilot,
    load_offline_platform_principal,
)
from intelligence.execution_pilot_ceremony import (
    CeremonyDenied,
    abort_ceremony,
    ceremony_default_off,
    execute_ceremony,
    issue_ceremony_confirmation,
    preflight_ceremony,
    read_confirmation_handoff,
    write_confirmation_handoff,
)
from intelligence.execution_production_webhook import PILOT_KEY_ID_ENV, PILOT_SECRET_ENV
from intelligence.execution_providers import ClosedProvider, get_provider

from tests.test_controlled_execution_gateway_phase3_stage4c1 import (
    OWNER,
    SEC,
    TENANT,
    _approve_both,
    _arm_secret,
    _challenge,
    _ready_pilot,
    owner,
    security,
)


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
        "ZORVIAN_WEBHOOK_PILOT_TENANT_ID", PILOT_SECRET_ENV, PILOT_KEY_ID_ENV,
        OWNER_IDS_ENV, SECURITY_IDS_ENV,
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


def _armed(c):
    prep = _ready_pilot(c)
    _arm_secret()
    _approve_both(c, prep["pilot_id"])
    challenge = _challenge(c, prep["pilot_id"])
    return prep, challenge


def test_merge_bootstrap_activates_nothing():
    c = conn()
    assert c.execute("SELECT COUNT(*) AS n FROM execution_pilot_activations").fetchone()["n"] == 0
    assert c.execute("SELECT COUNT(*) AS n FROM execution_live_grants WHERE enabled=1").fetchone()["n"] == 0
    assert ceremony_default_off()["production_provider"] == "ClosedProvider"


def test_default_provider_closed():
    assert isinstance(get_provider(get_adapter("webhook.post")), ClosedProvider)


def test_no_public_ceremony_routes():
    text = open("app_gate5.py").read()
    assert "/activate" not in text
    assert "/reconcile" not in text
    assert "/ceremony" not in text


def test_preflight_select_only_and_zero_network():
    c = conn()
    prep, _ = _armed(c)
    statements: list[str] = []

    def authorizer(action, arg1, *_a):
        statements.append((action, arg1 or ""))
        if action not in {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_TRANSACTION}:
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    traces: list[str] = []
    c.set_authorizer(authorizer)
    c.set_trace_callback(lambda s: traces.append(s))
    out = preflight_ceremony(c, pilot_id=prep["pilot_id"], owner=owner(), security=security())
    c.set_authorizer(None)
    c.set_trace_callback(None)
    assert out["ok"] is True
    assert out["activated"] is False
    assert out["webhook_submitted"] is False
    starts = [t.strip().split()[0].upper() for t in traces if t and t.strip()]
    for word in ("CREATE", "INSERT", "UPDATE", "DELETE", "ALTER", "DROP", "REPLACE"):
        assert word not in starts


def test_role_string_fabrication_denied():
    c = conn()
    prep, _ = _armed(c)
    with pytest.raises((CeremonyDenied, ActivationDenied)):
        load_offline_platform_principal(actor_id="forged", requested_role="platform_owner")
    forged = type("P", (), {"actor_id": OWNER, "role": "platform_owner", "source": "caller"})()
    with pytest.raises((CeremonyDenied, ActivationDenied)):
        preflight_ceremony(c, pilot_id=prep["pilot_id"], owner=forged, security=security())


def test_same_actor_both_roles_denied():
    c = conn()
    prep, _ = _armed(c)
    os.environ[SECURITY_IDS_ENV] = OWNER
    same = load_offline_platform_principal(actor_id=OWNER, requested_role="security_operator")
    with pytest.raises(CeremonyDenied, match="different"):
        preflight_ceremony(c, pilot_id=prep["pilot_id"], owner=owner(), security=same)


def test_caller_substitution_denied():
    c = conn()
    prep, challenge = _armed(c)
    conf = issue_ceremony_confirmation(c, pilot_id=prep["pilot_id"], owner=owner(), security=security())
    with pytest.raises(CeremonyDenied, match="substitutes"):
        execute_ceremony(
            c, pilot_id=prep["pilot_id"], owner=owner(), security=security(),
            challenge_nonce=challenge["nonce"], confirmation_token=conf["confirmation_token"],
            destination_hash="deadbeef",
        )


def test_stale_guardian_denied(monkeypatch):
    c = conn()
    prep, _ = _armed(c)
    c.execute("UPDATE guardian_assessments SET context_hash=?", ("tampered",))
    if c.in_transaction:
        c.commit()
    with pytest.raises((CeremonyDenied, ActivationDenied)):
        preflight_ceremony(c, pilot_id=prep["pilot_id"], owner=owner(), security=security())


def test_missing_binding_fields_denied():
    c = conn()
    prep, _ = _armed(c)
    c.execute("DELETE FROM execution_pilot_guardian_bindings")
    if c.in_transaction:
        c.commit()
    with pytest.raises((CeremonyDenied, ActivationDenied, TypeError)):
        preflight_ceremony(c, pilot_id=prep["pilot_id"], owner=owner(), security=security())


def test_challenge_expiry_and_same_pilot_replay_denied():
    c = conn()
    prep, challenge = _armed(c)
    c.execute("UPDATE execution_pilot_activation_challenges SET expires_at='2000-01-01T00:00:00+00:00'")
    if c.in_transaction:
        c.commit()
    with pytest.raises(CeremonyDenied, match="expired"):
        preflight_ceremony(c, pilot_id=prep["pilot_id"], owner=owner(), security=security())
    c2 = conn()
    prep2, challenge2 = _armed(c2)
    conf = issue_ceremony_confirmation(c2, pilot_id=prep2["pilot_id"], owner=owner(), security=security())
    execute_ceremony(
        c2, pilot_id=prep2["pilot_id"], owner=owner(), security=security(),
        challenge_nonce=challenge2["nonce"], confirmation_token=conf["confirmation_token"],
    )
    with pytest.raises((CeremonyDenied, ActivationDenied)):
        execute_ceremony(
            c2, pilot_id=prep2["pilot_id"], owner=owner(), security=security(),
            challenge_nonce=challenge2["nonce"], confirmation_token=conf["confirmation_token"],
        )


def test_cross_pilot_challenge_and_confirmation_denied():
    """Pilot A's challenge/confirmation must not activate Pilot B."""
    c = conn()
    prep_a, challenge_a = _armed(c)
    prep_b, challenge_b = _armed(c)
    assert prep_a["pilot_id"] != prep_b["pilot_id"]
    conf_a = issue_ceremony_confirmation(c, pilot_id=prep_a["pilot_id"], owner=owner(), security=security())
    with pytest.raises((CeremonyDenied, ActivationDenied)):
        execute_ceremony(
            c, pilot_id=prep_b["pilot_id"], owner=owner(), security=security(),
            challenge_nonce=challenge_a["nonce"], confirmation_token=conf_a["confirmation_token"],
        )
    _assert_no_partial(c, prep_a["pilot_id"])
    _assert_no_partial(c, prep_b["pilot_id"])
    assert c.execute(
        "SELECT consumed_at FROM execution_pilot_ceremony_confirmations WHERE pilot_id=?",
        (prep_a["pilot_id"],),
    ).fetchone()["consumed_at"] is None
    # B can still complete with its own credentials after the denied cross-pilot attempt.
    conf_b = issue_ceremony_confirmation(c, pilot_id=prep_b["pilot_id"], owner=owner(), security=security())
    out = execute_ceremony(
        c, pilot_id=prep_b["pilot_id"], owner=owner(), security=security(),
        challenge_nonce=challenge_b["nonce"], confirmation_token=conf_b["confirmation_token"],
    )
    assert out["activated"] is True
    assert c.execute(
        "SELECT COUNT(*) AS n FROM execution_pilot_activations WHERE pilot_id=? AND status='ACTIVE'",
        (prep_a["pilot_id"],),
    ).fetchone()["n"] == 0


def test_handoff_created_mode_0600(tmp_path):
    path = write_confirmation_handoff("handoff-token-value", str(tmp_path))
    assert os.stat(path).st_mode & 0o777 == 0o600
    assert os.path.isfile(path) and not os.path.islink(path)


def test_handoff_symlink_rejected(tmp_path):
    real = write_confirmation_handoff("secret-handoff-token", str(tmp_path))
    link = tmp_path / "handoff-link"
    link.symlink_to(real)
    with pytest.raises(CeremonyDenied, match="symlink|opened"):
        read_confirmation_handoff(str(link))
    assert os.path.exists(real)
    leaked = False
    try:
        read_confirmation_handoff(str(link))
    except CeremonyDenied as exc:
        leaked = "secret-handoff-token" in str(exc)
    assert leaked is False


def test_handoff_permissive_mode_rejected(tmp_path):
    path = write_confirmation_handoff("secret-handoff-token", str(tmp_path))
    os.chmod(path, 0o644)
    with pytest.raises(CeremonyDenied, match="0600"):
        read_confirmation_handoff(path)
    assert os.path.exists(path)
    with open(path, encoding="utf-8") as handle:
        assert handle.read() == "secret-handoff-token"


def test_handoff_single_use_deletion(tmp_path):
    path = write_confirmation_handoff("one-shot-token", str(tmp_path))
    assert read_confirmation_handoff(path) == "one-shot-token"
    assert not os.path.exists(path)
    with pytest.raises(CeremonyDenied):
        read_confirmation_handoff(path)


def test_yes_flag_is_not_confirmation():
    c = conn()
    prep, challenge = _armed(c)
    with pytest.raises(CeremonyDenied, match="single-use"):
        execute_ceremony(
            c, pilot_id=prep["pilot_id"], owner=owner(), security=security(),
            challenge_nonce=challenge["nonce"], confirmation_token="yes",
        )


def _assert_no_partial(c, pilot_id):
    assert c.execute("SELECT COUNT(*) AS n FROM execution_pilot_activations").fetchone()["n"] == 0
    assert c.execute("SELECT COUNT(*) AS n FROM execution_live_grants WHERE enabled=1").fetchone()["n"] == 0
    assert c.execute("SELECT COUNT(*) AS n FROM execution_destination_allowlist").fetchone()["n"] == 0
    assert c.execute("SELECT status FROM execution_pilot_preparations WHERE pilot_id=?", (pilot_id,)).fetchone()["status"] != "ACTIVE"
    assert c.execute("SELECT COUNT(*) AS n FROM execution_pilot_ceremony_receipts").fetchone()["n"] == 0
    assert c.execute("SELECT COUNT(*) AS n FROM execution_pilot_ceremony_confirmations WHERE consumed_at IS NOT NULL").fetchone()["n"] == 0
    assert c.execute("SELECT COUNT(*) AS n FROM execution_pilot_activation_challenges WHERE consumed_at IS NOT NULL").fetchone()["n"] == 0
    assert c.execute("SELECT COUNT(*) AS n FROM execution_pilot_ops_audit WHERE event='pilot_activated'").fetchone()["n"] == 0


def test_activation_rollback_leaves_zero_partial_state(monkeypatch):
    c = conn()
    prep, challenge = _armed(c)
    conf = issue_ceremony_confirmation(c, pilot_id=prep["pilot_id"], owner=owner(), security=security())

    def boom(*a, **k):
        raise sqlite3.OperationalError("injected")

    monkeypatch.setattr("intelligence.execution_pilot_ceremony.activate_pilot_locked", boom)
    with pytest.raises(sqlite3.OperationalError):
        execute_ceremony(
            c, pilot_id=prep["pilot_id"], owner=owner(), security=security(),
            challenge_nonce=challenge["nonce"], confirmation_token=conf["confirmation_token"],
        )
    _assert_no_partial(c, prep["pilot_id"])


def test_fail_after_confirmation_rolls_back(monkeypatch):
    import intelligence.execution_pilot_ceremony as ceremony
    c = conn()
    prep, challenge = _armed(c)
    conf = issue_ceremony_confirmation(c, pilot_id=prep["pilot_id"], owner=owner(), security=security())
    real = ceremony._consume_confirmation

    def wrap(*a, **k):
        real(*a, **k)
        raise RuntimeError("after-confirm")

    monkeypatch.setattr(ceremony, "_consume_confirmation", wrap)
    with pytest.raises(RuntimeError):
        execute_ceremony(
            c, pilot_id=prep["pilot_id"], owner=owner(), security=security(),
            challenge_nonce=challenge["nonce"], confirmation_token=conf["confirmation_token"],
        )
    _assert_no_partial(c, prep["pilot_id"])


def test_fail_after_activate_rolls_back(monkeypatch):
    import intelligence.execution_pilot_ceremony as ceremony
    c = conn()
    prep, challenge = _armed(c)
    conf = issue_ceremony_confirmation(c, pilot_id=prep["pilot_id"], owner=owner(), security=security())
    real = ceremony.activate_pilot_locked

    def wrap(*a, **k):
        real(*a, **k)
        raise RuntimeError("after-activate")

    monkeypatch.setattr(ceremony, "activate_pilot_locked", wrap)
    with pytest.raises(RuntimeError):
        execute_ceremony(
            c, pilot_id=prep["pilot_id"], owner=owner(), security=security(),
            challenge_nonce=challenge["nonce"], confirmation_token=conf["confirmation_token"],
        )
    _assert_no_partial(c, prep["pilot_id"])


def test_execute_activates_without_webhook():
    c = conn()
    prep, challenge = _armed(c)
    conf = issue_ceremony_confirmation(c, pilot_id=prep["pilot_id"], owner=owner(), security=security())
    out = execute_ceremony(
        c, pilot_id=prep["pilot_id"], owner=owner(), security=security(),
        challenge_nonce=challenge["nonce"], confirmation_token=conf["confirmation_token"],
    )
    assert out["activated"] is True
    assert out["webhook_submitted"] is False
    assert out["provider_calls"] == 0
    assert "secret" not in json_blob(out)
    assert os.environ[PILOT_SECRET_ENV] not in str(out)


def json_blob(payload):
    import json
    return json.dumps(payload)


def test_secret_never_in_db_or_output():
    c = conn()
    prep, challenge = _armed(c)
    secret = os.environ[PILOT_SECRET_ENV]
    conf = issue_ceremony_confirmation(c, pilot_id=prep["pilot_id"], owner=owner(), security=security())
    out = execute_ceremony(
        c, pilot_id=prep["pilot_id"], owner=owner(), security=security(),
        challenge_nonce=challenge["nonce"], confirmation_token=conf["confirmation_token"],
    )
    dump = " ".join(row[0] for row in c.execute("SELECT detail_json FROM execution_pilot_ceremony_receipts"))
    assert secret not in dump
    assert secret not in str(out)
    assert secret not in conf["confirmation_token"]


def test_transport_injection_does_not_submit():
    c = conn()
    prep, challenge = _armed(c)
    conf = issue_ceremony_confirmation(c, pilot_id=prep["pilot_id"], owner=owner(), security=security())
    with pytest.raises(CeremonyDenied, match="must not accept a transport"):
        execute_ceremony(
            c, pilot_id=prep["pilot_id"], owner=owner(), security=security(),
            challenge_nonce=challenge["nonce"], confirmation_token=conf["confirmation_token"],
            transport=object(),
        )
    _assert_no_partial(c, prep["pilot_id"])


def test_challenge_tenant_mismatch_denied():
    c = conn()
    prep, _ = _armed(c)
    c.execute("UPDATE execution_pilot_activation_challenges SET tenant_id=?", ("other-tenant",))
    if c.in_transaction:
        c.commit()
    with pytest.raises(CeremonyDenied, match="tenant"):
        preflight_ceremony(c, pilot_id=prep["pilot_id"], owner=owner(), security=security())


def test_cli_rejects_credential_argv():
    from intelligence.execution_pilot_ceremony_cli import main
    with pytest.raises(SystemExit):
        main(["execute", "--db", ":memory:", "--pilot-id", "p", "--owner-id", OWNER, "--confirmation", "x"])


def test_second_active_pilot_denied():
    c = conn()
    prep, challenge = _armed(c)
    conf = issue_ceremony_confirmation(c, pilot_id=prep["pilot_id"], owner=owner(), security=security())
    execute_ceremony(
        c, pilot_id=prep["pilot_id"], owner=owner(), security=security(),
        challenge_nonce=challenge["nonce"], confirmation_token=conf["confirmation_token"],
    )
    prep2 = _ready_pilot(c)
    _approve_both(c, prep2["pilot_id"])
    challenge2 = _challenge(c, prep2["pilot_id"])
    conf2 = issue_ceremony_confirmation(c, pilot_id=prep2["pilot_id"], owner=owner(), security=security())
    with pytest.raises((CeremonyDenied, ActivationDenied)):
        execute_ceremony(
            c, pilot_id=prep2["pilot_id"], owner=owner(), security=security(),
            challenge_nonce=challenge2["nonce"], confirmation_token=conf2["confirmation_token"],
        )


def test_concurrent_ceremony_one_winner():
    path = os.path.join(os.environ.get("TMPDIR", "/tmp"), "stage4e-ceremony.sqlite")
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    setup = sqlite3.connect(path)
    setup.row_factory = sqlite3.Row
    ensure_execution_schema(setup)
    if setup.in_transaction:
        setup.commit()
    prep, challenge = _armed(setup)
    conf = issue_ceremony_confirmation(setup, pilot_id=prep["pilot_id"], owner=owner(), security=security())
    setup.close()
    results: list[str] = []

    def worker():
        local = sqlite3.connect(path)
        local.row_factory = sqlite3.Row
        try:
            execute_ceremony(
                local, pilot_id=prep["pilot_id"], owner=owner(), security=security(),
                challenge_nonce=challenge["nonce"], confirmation_token=conf["confirmation_token"],
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
    assert results.count("win") == 1
    assert results.count("lose") == 1


def test_abort_isolated_idempotent():
    c = conn()
    prep, challenge = _armed(c)
    conf = issue_ceremony_confirmation(c, pilot_id=prep["pilot_id"], owner=owner(), security=security())
    execute_ceremony(
        c, pilot_id=prep["pilot_id"], owner=owner(), security=security(),
        challenge_nonce=challenge["nonce"], confirmation_token=conf["confirmation_token"],
    )
    first = abort_ceremony(c, pilot_id=prep["pilot_id"], principal=owner(), reason="drill")
    second = abort_ceremony(c, pilot_id=prep["pilot_id"], principal=owner(), reason="drill")
    assert first["status"] == "SUSPENDED"
    assert second["status"] == "SUSPENDED"
    assert first["evidence_preserved"] is True
    assert c.execute("SELECT COUNT(*) AS n FROM execution_pilot_activations WHERE pilot_id=?", (prep["pilot_id"],)).fetchone()["n"] == 1


def test_production_remains_off():
    assert ceremony_default_off()["external_execution"] is False
    assert ceremony_default_off()["activated"] is False


def test_receipt_keeps_hashes_and_ids():
    c = conn()
    prep, challenge = _armed(c)
    conf = issue_ceremony_confirmation(c, pilot_id=prep["pilot_id"], owner=owner(), security=security())
    out = execute_ceremony(
        c, pilot_id=prep["pilot_id"], owner=owner(), security=security(),
        challenge_nonce=challenge["nonce"], confirmation_token=conf["confirmation_token"],
    )
    for key in ("destination_hash", "manifest_hash", "confirmation_id", "challenge_id", "activation_id"):
        assert out.get(key)
    stored = c.execute("SELECT detail_json FROM execution_pilot_ceremony_receipts").fetchone()["detail_json"]
    assert "destination_hash" in stored
    assert "confirmation_id" in stored
    assert "confirmation_token" not in stored
    assert "nonce" not in stored


def test_commit_failure_rolls_back_everything(monkeypatch):
    import intelligence.execution_pilot_ceremony as ceremony
    c = conn()
    prep, challenge = _armed(c)
    conf = issue_ceremony_confirmation(c, pilot_id=prep["pilot_id"], owner=owner(), security=security())

    def boom(_c):
        raise sqlite3.OperationalError("commit-fail")

    monkeypatch.setattr(ceremony, "_commit_ceremony", boom)
    with pytest.raises(sqlite3.OperationalError):
        execute_ceremony(
            c, pilot_id=prep["pilot_id"], owner=owner(), security=security(),
            challenge_nonce=challenge["nonce"], confirmation_token=conf["confirmation_token"],
        )
    _assert_no_partial(c, prep["pilot_id"])


def test_evidence_changed_after_inspect_denied():
    c = conn()
    prep, challenge = _armed(c)
    conf = issue_ceremony_confirmation(c, pilot_id=prep["pilot_id"], owner=owner(), security=security())
    preflight_ceremony(c, pilot_id=prep["pilot_id"], owner=owner(), security=security())
    c.execute("UPDATE execution_pilot_activation_challenges SET guardian_context_hash=?", ("tampered",))
    if c.in_transaction:
        c.commit()
    with pytest.raises((CeremonyDenied, ActivationDenied)):
        execute_ceremony(
            c, pilot_id=prep["pilot_id"], owner=owner(), security=security(),
            challenge_nonce=challenge["nonce"], confirmation_token=conf["confirmation_token"],
        )
    _assert_no_partial(c, prep["pilot_id"])


def test_cli_issue_execute_handoff(monkeypatch, tmp_path):
    from intelligence.execution_pilot_ceremony_cli import main
    path = tmp_path / "cer.sqlite"
    c = sqlite3.connect(path)
    c.row_factory = sqlite3.Row
    ensure_execution_schema(c)
    if c.in_transaction:
        c.commit()
    prep, challenge = _armed(c)
    c.close()
    import io
    captured = io.StringIO()
    monkeypatch.setattr("sys.stdout", captured)
    main([
        "issue-confirmation", "--db", str(path), "--pilot-id", prep["pilot_id"],
        "--owner-id", OWNER, "--security-id", SEC, "--handoff-dir", str(tmp_path),
    ])
    import json
    issued = json.loads(captured.getvalue())
    assert "confirmation_token" not in issued
    handoff = issued["handoff"]
    assert os.path.exists(handoff)
    monkeypatch.setattr("intelligence.execution_pilot_ceremony_cli._prompt_secret", lambda label: challenge["nonce"])
    captured2 = io.StringIO()
    monkeypatch.setattr("sys.stdout", captured2)
    rc = main([
        "execute", "--db", str(path), "--pilot-id", prep["pilot_id"],
        "--owner-id", OWNER, "--security-id", SEC, "--handoff", handoff,
    ])
    assert rc == 0
    out = json.loads(captured2.getvalue())
    assert out["activated"] is True
    assert "confirmation_token" not in out
    assert not os.path.exists(handoff)
