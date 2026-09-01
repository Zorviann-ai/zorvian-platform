"""Phase 3 Stage 1 — append-only receipts and evidence helpers.

Application APIs must not update or delete historical receipt rows.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from typing import Any

from intelligence.execution import _iso


def record_receipt(
    c: sqlite3.Connection,
    *,
    tenant_id: str,
    attempt_id: str,
    classification: str,
    payload_hash: str | None = None,
    destination_hash: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    receipt_id = str(uuid.uuid4())
    body = {
        "receipt_id": receipt_id,
        "tenant_id": tenant_id,
        "attempt_id": attempt_id,
        "classification": classification,
        "payload_hash": payload_hash,
        "destination_hash": destination_hash,
        "recorded_at": _iso(),
        "extra": extra or {},
    }
    c.execute(
        """INSERT INTO execution_receipts(
            id, tenant_id, attempt_id, classification, payload_hash, destination_hash, recorded_at, extra_json
        ) VALUES (?,?,?,?,?,?,?,?)""",
        (
            receipt_id,
            tenant_id,
            attempt_id,
            classification,
            payload_hash,
            destination_hash,
            body["recorded_at"],
            json.dumps(extra or {}),
        ),
    )
    return body


def load_receipt(c: sqlite3.Connection, receipt_id: str, tenant_id: str) -> dict[str, Any] | None:
    row = c.execute(
        "SELECT * FROM execution_receipts WHERE id=? AND tenant_id=?",
        (receipt_id, tenant_id),
    ).fetchone()
    if not row:
        return None
    return dict(row)


def list_receipts_for_attempt(c: sqlite3.Connection, attempt_id: str, tenant_id: str) -> list[dict[str, Any]]:
    rows = c.execute(
        "SELECT * FROM execution_receipts WHERE attempt_id=? AND tenant_id=? ORDER BY recorded_at ASC",
        (attempt_id, tenant_id),
    ).fetchall()
    return [dict(r) for r in rows]


def public_receipt(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "receipt_id": row.get("id") or row.get("receipt_id"),
        "attempt_id": row["attempt_id"],
        "classification": row["classification"],
        "payload_hash": row.get("payload_hash"),
        "destination_hash": row.get("destination_hash"),
        "recorded_at": row.get("recorded_at"),
    }
