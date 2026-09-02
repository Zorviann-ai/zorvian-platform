"""Phase 3 Stage 4E — sealed Caelomere production-pilot ceremony runner.

Merge, import, bootstrap, preflight and tests never activate a tenant,
install a secret, create a grant/allowlist or send a webhook.
There is no public HTTP ceremony route.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import stat
import uuid
from typing import Any

from intelligence.execution import _iso, _now, _parse_iso
from intelligence.execution_adapters import get_adapter
from intelligence.execution_pilot_activation import (
    ACTIVATION_ENV,
    MAX_CONCURRENT,
    MAX_RETRIES,
    MAX_SUCCESSES,
    MAX_WINDOW_MINUTES,
    ActivationDenied,
    PlatformPrincipal,
    _hash_nonce,
    _load_prep_any,
    _revalidate_for_ceremony,
    _require_principal,
    activate_pilot_locked,
    load_offline_platform_principal,
    suspend_pilot,
)
from intelligence.execution_pilot_ops import ACTION, ADAPTER_ID, _ops_audit
from intelligence.execution_production_webhook import PILOT_SECRET_ENV
from intelligence.execution_providers import get_provider
from intelligence.guardian import GUARDIAN_POLICY_VERSION, guardian_policy_hash

CONFIRM_TTL_MINUTES = 10
CEREMONY_MODE_PREFLIGHT = "preflight"
CEREMONY_MODE_EXECUTE = "execute"


class CeremonyDenied(ActivationDenied):
    """Fail-closed Stage 4E ceremony denial."""


def ensure_stage4e_schema(c: sqlite3.Connection) -> None:
    """Controlled bootstrap only. Never called from preflight."""
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS execution_pilot_ceremony_confirmations(
            confirmation_id TEXT PRIMARY KEY,
            pilot_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            context_hash TEXT NOT NULL,
            challenge_id TEXT NOT NULL,
            owner_actor_id TEXT NOT NULL,
            security_actor_id TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            consumed_at TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS execution_pilot_ceremony_receipts(
            receipt_id TEXT PRIMARY KEY,
            pilot_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            activation_id TEXT,
            status TEXT NOT NULL,
            mode TEXT NOT NULL,
            detail_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )


_REDACT_EXACT = {
    "secret", "nonce", "token", "confirmation_token", "confirmation",
    "authorization", "password", "payload", "destination", "signing_secret",
    "challenge_nonce",
}
_REDACT_KEEP = {
    "destination_hash", "confirmation_id", "manifest_hash", "guardian_context_hash",
    "policy_hash", "challenge_id", "activation_id", "receipt_id", "pilot_id",
    "tenant_id", "signing_key_id", "guardian_assessment_id",
}


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            low = str(key).lower()
            if low in _REDACT_KEEP:
                out[key] = _redact(item)
                continue
            if low in _REDACT_EXACT or low.endswith("_secret") or low.endswith("_token") or low.endswith("_nonce"):
                continue
            out[key] = _redact(item)
        return out
    if isinstance(value, str) and os.getenv(PILOT_SECRET_ENV) and os.getenv(PILOT_SECRET_ENV) in value:
        return "[redacted]"
    return value


def _commit_ceremony(c: sqlite3.Connection) -> None:
    """Single commit boundary so tests can inject a late failure."""
    c.commit()


def write_confirmation_handoff(token: str, directory: str) -> str:
    """Write the one-time confirmation to a 0600 file. Never log the token."""
    import tempfile
    handle = tempfile.NamedTemporaryFile(mode="w", prefix="caelomere-handoff-", dir=directory, delete=False)
    os.chmod(handle.name, 0o600)
    handle.write(token)
    handle.close()
    return handle.name


def read_confirmation_handoff(path: str) -> str:
    """Read a one-time confirmation from a caller-supplied path.

    The path must resolve to a regular file owned by the current UID with
    mode exactly 0600. Symlinks are rejected (O_NOFOLLOW when available).
    The token is never returned unless every check passes; the file is
    unlinked only after a successful validated read.
    """
    flags = os.O_RDONLY
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow:
        flags |= nofollow
    elif os.path.islink(path):
        raise CeremonyDenied("confirmation handoff must not be a symlink")

    fd = None
    try:
        fd = os.open(path, flags)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise CeremonyDenied("confirmation handoff must be a regular file")
        if info.st_uid != os.geteuid():
            raise CeremonyDenied("confirmation handoff owner mismatch")
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise CeremonyDenied("confirmation handoff mode must be 0600")
        raw = os.read(fd, info.st_size + 1)
    except CeremonyDenied:
        raise
    except OSError as exc:
        raise CeremonyDenied("confirmation handoff could not be opened") from exc
    finally:
        if fd is not None:
            os.close(fd)

    token = raw.decode("utf-8").strip()
    if not token:
        raise CeremonyDenied("confirmation handoff is empty")
    try:
        os.unlink(path)
    except OSError:
        pass
    return token


def _context_binding(evidence: dict[str, Any], *, challenge_id: str) -> str:
    prep = evidence["prep"]
    assessment = evidence.get("assessment") or {}
    payload = {
        "pilot_id": prep["pilot_id"],
        "tenant_id": prep["tenant_id"],
        "adapter_id": ADAPTER_ID,
        "action": ACTION,
        "destination_hash": prep["destination_hash"],
        "manifest_hash": prep["manifest_hash"],
        "guardian_assessment_id": assessment.get("guardian_assessment_id"),
        "guardian_context_hash": evidence.get("context_hash"),
        "policy_version": GUARDIAN_POLICY_VERSION,
        "policy_hash": evidence.get("policy_hash") or guardian_policy_hash(),
        "signing_key_id": prep["signing_key_id"],
        "owner_actor_id": evidence["owner_id"],
        "security_actor_id": evidence["security_id"],
        "challenge_id": challenge_id,
        "window_minutes": MAX_WINDOW_MINUTES,
        "max_successes": MAX_SUCCESSES,
        "max_concurrent": MAX_CONCURRENT,
        "max_retries": MAX_RETRIES,
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _hash_confirmation(token: str, context_hash: str) -> str:
    return hashlib.sha256(f"{token}:{context_hash}".encode("utf-8")).hexdigest()


def _require_distinct_principals(owner: PlatformPrincipal, security: PlatformPrincipal) -> None:
    _require_principal(owner, "platform_owner")
    _require_principal(security, "security_operator")
    if owner.actor_id == security.actor_id:
        raise CeremonyDenied("platform owner and security operator must be different actors")


def _open_challenge(c: sqlite3.Connection, pilot_id: str, evidence: dict[str, Any]):
    rows = c.execute(
        """SELECT * FROM execution_pilot_activation_challenges
           WHERE pilot_id=? ORDER BY created_at DESC""",
        (pilot_id,),
    ).fetchall()
    unused = [row for row in rows if not row["consumed_at"]]
    if not unused:
        raise CeremonyDenied("no unused activation challenge")
    if len(unused) != 1:
        raise CeremonyDenied("ambiguous unused activation challenges")
    row = unused[0]
    expires = _parse_iso(row["expires_at"])
    if expires is None or expires <= _now():
        raise CeremonyDenied("activation challenge is expired")
    if row["tenant_id"] != evidence["tenant_id"] or row["tenant_id"] != evidence["prep"]["tenant_id"]:
        raise CeremonyDenied("activation challenge tenant mismatch")
    if row["manifest_hash"] != evidence["prep"]["manifest_hash"]:
        raise CeremonyDenied("challenge manifest hash mismatch")
    if (row["guardian_context_hash"] or "") != evidence["context_hash"]:
        raise CeremonyDenied("challenge guardian context mismatch")
    if row["owner_actor_id"] != evidence["owner_id"] or row["security_actor_id"] != evidence["security_id"]:
        raise CeremonyDenied("challenge actors do not match stored platform approvals")
    return row


def _assert_no_caller_substitutes(**kwargs: Any) -> None:
    banned = {
        "tenant_id", "destination", "destination_hash", "manifest_hash",
        "adapter_id", "action", "signing_key_id", "policy_version", "policy_hash",
        "guardian_assessment_id", "guardian_context_hash", "window_minutes",
        "max_successes", "max_concurrent",
    }
    present = [key for key in banned if key in kwargs and kwargs[key] is not None]
    if present:
        raise CeremonyDenied("caller may not supply binding substitutes")


def preflight_ceremony(
    c: sqlite3.Connection,
    *,
    pilot_id: str,
    owner: PlatformPrincipal,
    security: PlatformPrincipal,
) -> dict[str, Any]:
    """SELECT-only. Incapable of activation or network access."""
    _require_distinct_principals(owner, security)
    if c.in_transaction:
        raise CeremonyDenied("open transaction exists")
    try:
        evidence = _revalidate_for_ceremony(c, pilot_id)
    except (ActivationDenied, TypeError, KeyError) as exc:
        raise CeremonyDenied(str(exc) or "stored ceremony evidence is incomplete") from exc
    if owner.actor_id != evidence["owner_id"] or security.actor_id != evidence["security_id"]:
        raise CeremonyDenied("principals do not match stored platform approvals")
    challenge = _open_challenge(c, pilot_id, evidence)
    act = c.execute("SELECT status FROM execution_pilot_activations WHERE pilot_id=?", (pilot_id,)).fetchone()
    if act is not None and act["status"] == "ACTIVE":
        raise CeremonyDenied("pilot is already ACTIVE")
    provider_name = type(get_provider(get_adapter(ADAPTER_ID))).__name__
    return {
        "mode": CEREMONY_MODE_PREFLIGHT,
        "ok": True,
        "pilot_id": pilot_id,
        "tenant_id": evidence["tenant_id"],
        "challenge_id": challenge["challenge_id"],
        "manifest_hash": evidence["prep"]["manifest_hash"],
        "destination_hash": evidence["prep"]["destination_hash"],
        "guardian_context_hash": evidence["context_hash"],
        "policy_version": GUARDIAN_POLICY_VERSION,
        "policy_hash": evidence["policy_hash"],
        "signing_key_id": evidence["prep"]["signing_key_id"],
        "activated": False,
        "webhook_submitted": False,
        "production_provider": provider_name,
        "secret_present": bool((os.getenv(PILOT_SECRET_ENV) or "").strip()),
    }


def issue_ceremony_confirmation(
    c: sqlite3.Connection,
    *,
    pilot_id: str,
    owner: PlatformPrincipal,
    security: PlatformPrincipal,
) -> dict[str, Any]:
    """Issue a short-lived, hash-only, single-use confirmation bound to stored evidence."""
    _require_distinct_principals(owner, security)
    if c.in_transaction:
        raise CeremonyDenied("open transaction exists")
    evidence = _revalidate_for_ceremony(c, pilot_id)
    if owner.actor_id != evidence["owner_id"] or security.actor_id != evidence["security_id"]:
        raise CeremonyDenied("principals do not match stored platform approvals")
    challenge = _open_challenge(c, pilot_id, evidence)
    context_hash = _context_binding(evidence, challenge_id=challenge["challenge_id"])
    token = secrets.token_urlsafe(32)
    token_hash = _hash_confirmation(token, context_hash)
    confirmation_id = str(uuid.uuid4())
    from datetime import timedelta
    expires_at = _iso(_now() + timedelta(minutes=CONFIRM_TTL_MINUTES))
    try:
        c.execute("BEGIN IMMEDIATE")
        c.execute(
            """INSERT INTO execution_pilot_ceremony_confirmations(
                confirmation_id,pilot_id,tenant_id,token_hash,context_hash,challenge_id,
                owner_actor_id,security_actor_id,expires_at,consumed_at,created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,NULL,?)""",
            (
                confirmation_id, pilot_id, evidence["tenant_id"], token_hash, context_hash,
                challenge["challenge_id"], owner.actor_id, security.actor_id, expires_at, _iso(),
            ),
        )
        _ops_audit(
            c, tenant_id=evidence["tenant_id"], actor_id=owner.actor_id,
            event="pilot_ceremony_confirmation_issued", pilot_id=pilot_id,
            detail={"confirmation_id": confirmation_id},
        )
        c.commit()
    except Exception:
        try:
            c.rollback()
        except sqlite3.Error:
            pass
        raise
    return {
        "confirmation_id": confirmation_id,
        "confirmation_token": token,
        "expires_at": expires_at,
        "activated": False,
        "webhook_submitted": False,
    }


def _consume_confirmation(
    c: sqlite3.Connection,
    *,
    pilot_id: str,
    token: str,
    evidence: dict[str, Any],
    challenge_id: str,
) -> str:
    context_hash = _context_binding(evidence, challenge_id=challenge_id)
    digest = _hash_confirmation(token, context_hash)
    row = c.execute(
        "SELECT * FROM execution_pilot_ceremony_confirmations WHERE token_hash=? AND pilot_id=?",
        (digest, pilot_id),
    ).fetchone()
    if row is None:
        raise CeremonyDenied("ceremony confirmation is invalid")
    if row["consumed_at"]:
        raise CeremonyDenied("ceremony confirmation has already been consumed")
    expires = _parse_iso(row["expires_at"])
    if expires is None or expires <= _now():
        raise CeremonyDenied("ceremony confirmation is expired")
    if row["context_hash"] != context_hash or row["challenge_id"] != challenge_id:
        raise CeremonyDenied("ceremony confirmation is not bound to current evidence")
    if row["owner_actor_id"] != evidence["owner_id"] or row["security_actor_id"] != evidence["security_id"]:
        raise CeremonyDenied("ceremony confirmation actors mismatch")
    marked = c.execute(
        """UPDATE execution_pilot_ceremony_confirmations
           SET consumed_at=? WHERE confirmation_id=? AND consumed_at IS NULL""",
        (_iso(), row["confirmation_id"]),
    ).rowcount
    if marked != 1:
        raise CeremonyDenied("ceremony confirmation could not be consumed")
    return row["confirmation_id"]


def execute_ceremony(
    c: sqlite3.Connection,
    *,
    pilot_id: str,
    owner: PlatformPrincipal,
    security: PlatformPrincipal,
    challenge_nonce: str,
    confirmation_token: str,
    transport: Any | None = None,
    **rejected: Any,
) -> dict[str, Any]:
    """Activate only after stored evidence and a bound single-use confirmation.

    Confirmation consumption, challenge consumption, grant, allowlist,
    ACTIVE status, audit and receipt share one BEGIN IMMEDIATE transaction.
    Does not submit a webhook.
    """
    _assert_no_caller_substitutes(**rejected)
    if transport is not None:
        raise CeremonyDenied("Stage 4E must not accept a transport or submit a webhook")
    _require_distinct_principals(owner, security)
    if not (confirmation_token or "").strip() or confirmation_token.strip().lower() in {"yes", "y", "true", "1", "confirm"}:
        raise CeremonyDenied("a random single-use ceremony confirmation is required")
    if not (challenge_nonce or "").strip():
        raise CeremonyDenied("stored activation challenge nonce is required")
    if c.in_transaction:
        raise CeremonyDenied("open transaction exists")
    try:
        c.execute("BEGIN IMMEDIATE")
        evidence = _revalidate_for_ceremony(c, pilot_id)
        if owner.actor_id != evidence["owner_id"] or security.actor_id != evidence["security_id"]:
            raise CeremonyDenied("principals do not match stored platform approvals")
        challenge = _open_challenge(c, pilot_id, evidence)
        confirmation_id = _consume_confirmation(
            c, pilot_id=pilot_id, token=confirmation_token, evidence=evidence,
            challenge_id=challenge["challenge_id"],
        )
        activation = activate_pilot_locked(
            c, pilot_id=pilot_id, principal=owner, challenge_nonce=challenge_nonce,
        )
        receipt = {
            "receipt_id": str(uuid.uuid4()),
            "mode": CEREMONY_MODE_EXECUTE,
            "pilot_id": pilot_id,
            "tenant_id": evidence["tenant_id"],
            "activation_id": activation.get("activation_id"),
            "status": activation.get("status") or "ACTIVE",
            "confirmation_id": confirmation_id,
            "challenge_id": challenge["challenge_id"],
            "manifest_hash": evidence["prep"]["manifest_hash"],
            "destination_hash": evidence["prep"]["destination_hash"],
            "guardian_context_hash": evidence["context_hash"],
            "policy_hash": evidence["policy_hash"],
            "activated": True,
            "webhook_submitted": False,
            "provider_calls": 0,
            "production_provider": type(get_provider(get_adapter(ADAPTER_ID))).__name__,
            "created_at": _iso(),
        }
        c.execute(
            """INSERT INTO execution_pilot_ceremony_receipts(
                receipt_id,pilot_id,tenant_id,activation_id,status,mode,detail_json,created_at
            ) VALUES (?,?,?,?,?,?,?,?)""",
            (
                receipt["receipt_id"], pilot_id, evidence["tenant_id"], receipt["activation_id"],
                receipt["status"], CEREMONY_MODE_EXECUTE, json.dumps(_redact(receipt)), receipt["created_at"],
            ),
        )
        _commit_ceremony(c)
    except sqlite3.IntegrityError as exc:
        try:
            c.rollback()
        except sqlite3.Error:
            pass
        raise CeremonyDenied("only one ACTIVE pilot is permitted per tenant and adapter") from exc
    except Exception as exc:
        try:
            c.rollback()
        except sqlite3.Error:
            pass
        secret = os.getenv(PILOT_SECRET_ENV) or ""
        if secret and secret in str(exc):
            raise CeremonyDenied("ceremony activation failed") from None
        raise
    return _redact(receipt)


def abort_ceremony(
    c: sqlite3.Connection,
    *,
    pilot_id: str,
    principal: PlatformPrincipal,
    reason: str = "operator-abort",
) -> dict[str, Any]:
    _require_principal(principal)
    out = suspend_pilot(c, pilot_id=pilot_id, principal=principal, reason=reason)
    out["aborted"] = True
    out["webhook_submitted"] = False
    out["evidence_preserved"] = True
    return _redact(out)


def ceremony_default_off() -> dict[str, Any]:
    return {
        "production_provider": type(get_provider(get_adapter(ADAPTER_ID))).__name__,
        "external_execution": bool((os.getenv("ZORVIAN_EXTERNAL_EXECUTION") or "").strip()),
        "activated": False,
        "webhook_submitted": False,
    }
