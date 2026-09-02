"""Internal Caelomere Stage 4E operator CLI. Not an HTTP route.

Single-use challenge nonce and confirmation are read with getpass.
They are never accepted as command-line arguments.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sqlite3
import sys

from intelligence.execution_pilot_activation import load_offline_platform_principal
from intelligence.execution_pilot_ceremony import (
    abort_ceremony,
    execute_ceremony,
    issue_ceremony_confirmation,
    preflight_ceremony,
    read_confirmation_handoff,
    write_confirmation_handoff,
)
from intelligence.execution_production_webhook import PILOT_SECRET_ENV


def _connect(path: str) -> sqlite3.Connection:
    c = sqlite3.connect(path)
    c.row_factory = sqlite3.Row
    return c


def _dump(payload: dict) -> None:
    secret = os.getenv(PILOT_SECRET_ENV) or ""
    safe = dict(payload)
    safe.pop("confirmation_token", None)
    safe.pop("nonce", None)
    text = json.dumps(safe, sort_keys=True, indent=2)
    if secret:
        text = text.replace(secret, "[redacted]")
    print(text)


def _prompt_secret(label: str) -> str:
    return getpass.getpass(f"{label}: ")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="caelomere-ceremony", description="Internal Caelomere Stage 4E ceremony")
    parser.add_argument("mode", choices=["preflight", "issue-confirmation", "execute", "abort"])
    parser.add_argument("--db", required=True)
    parser.add_argument("--pilot-id", required=True)
    parser.add_argument("--owner-id", required=True)
    parser.add_argument("--security-id", default="")
    parser.add_argument("--reason", default="operator-abort")
    parser.add_argument("--handoff", default="", help="0600 one-time confirmation file")
    parser.add_argument("--handoff-dir", default="", help="directory for issued confirmation handoff")
    args = parser.parse_args(argv)
    raw = argv if argv is not None else sys.argv[1:]
    if "--challenge-nonce" in raw or "--confirmation" in raw:
        raise SystemExit("challenge nonce and confirmation must be entered privately, not as CLI arguments")
    owner = load_offline_platform_principal(actor_id=args.owner_id, requested_role="platform_owner")
    c = _connect(args.db)
    try:
        if args.mode == "preflight":
            security = load_offline_platform_principal(actor_id=args.security_id, requested_role="security_operator")
            _dump(preflight_ceremony(c, pilot_id=args.pilot_id, owner=owner, security=security))
        elif args.mode == "issue-confirmation":
            security = load_offline_platform_principal(actor_id=args.security_id, requested_role="security_operator")
            issued = issue_ceremony_confirmation(c, pilot_id=args.pilot_id, owner=owner, security=security)
            token = issued.pop("confirmation_token")
            directory = args.handoff_dir or os.environ.get("TMPDIR") or "/tmp"
            issued["handoff"] = write_confirmation_handoff(token, directory)
            _dump(issued)
        elif args.mode == "execute":
            security = load_offline_platform_principal(actor_id=args.security_id, requested_role="security_operator")
            nonce = _prompt_secret("activation challenge nonce")
            if args.handoff:
                confirmation = read_confirmation_handoff(args.handoff)
            else:
                confirmation = _prompt_secret("ceremony confirmation")
            _dump(
                execute_ceremony(
                    c,
                    pilot_id=args.pilot_id,
                    owner=owner,
                    security=security,
                    challenge_nonce=nonce,
                    confirmation_token=confirmation,
                )
            )
        else:
            _dump(abort_ceremony(c, pilot_id=args.pilot_id, principal=owner, reason=args.reason))
    finally:
        c.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
