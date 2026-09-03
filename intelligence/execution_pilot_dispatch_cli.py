"""Internal Caelomere Stage 4F operator CLI. Not an HTTP route."""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sqlite3
import sys

from intelligence.execution_pilot_activation import load_offline_platform_principal
from intelligence.execution_pilot_ceremony import read_confirmation_handoff, write_confirmation_handoff
from intelligence.execution_pilot_dispatch import (
    abort_dispatch,
    closeout_dispatch,
    dispatch_status,
    execute_once,
    issue_dispatch_confirmation,
    preflight_dispatch,
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="caelomere-dispatch")
    parser.add_argument("mode", choices=["preflight", "issue-dispatch-confirmation", "execute-once", "status", "closeout", "abort"])
    parser.add_argument("--db", required=True)
    parser.add_argument("--pilot-id", required=True)
    parser.add_argument("--plan-id", default="")
    parser.add_argument("--owner-id", required=True)
    parser.add_argument("--security-id", default="")
    parser.add_argument("--reason", default="operator-abort")
    parser.add_argument("--decision", default="")
    parser.add_argument("--handoff", default="")
    parser.add_argument("--handoff-dir", default="")
    args = parser.parse_args(argv)
    raw = argv if argv is not None else sys.argv[1:]
    if "--confirmation" in raw or "--challenge-nonce" in raw:
        raise SystemExit("confirmation must be entered privately, not as CLI arguments")
    owner = load_offline_platform_principal(actor_id=args.owner_id, requested_role="platform_owner")
    c = _connect(args.db)
    try:
        if args.mode == "preflight":
            security = load_offline_platform_principal(actor_id=args.security_id, requested_role="security_operator")
            _dump(preflight_dispatch(c, pilot_id=args.pilot_id, plan_id=args.plan_id, owner=owner, security=security))
        elif args.mode == "issue-dispatch-confirmation":
            security = load_offline_platform_principal(actor_id=args.security_id, requested_role="security_operator")
            issued = issue_dispatch_confirmation(c, pilot_id=args.pilot_id, plan_id=args.plan_id, owner=owner, security=security)
            token = issued.pop("confirmation_token")
            directory = args.handoff_dir or os.environ.get("TMPDIR") or "/tmp"
            issued["handoff"] = write_confirmation_handoff(token, directory)
            _dump(issued)
        elif args.mode == "execute-once":
            security = load_offline_platform_principal(actor_id=args.security_id, requested_role="security_operator")
            plan_token = getpass.getpass("plan confirmation: ")
            if args.handoff:
                confirmation = read_confirmation_handoff(args.handoff)
            else:
                confirmation = getpass.getpass("dispatch confirmation: ")
            _dump(
                execute_once(
                    c, pilot_id=args.pilot_id, plan_id=args.plan_id, owner=owner, security=security,
                    confirmation_token=confirmation, plan_confirmation_token=plan_token,
                )
            )
        elif args.mode == "status":
            _dump(dispatch_status(c, pilot_id=args.pilot_id, plan_id=args.plan_id, principal=owner))
        elif args.mode == "closeout":
            _dump(closeout_dispatch(c, pilot_id=args.pilot_id, plan_id=args.plan_id, principal=owner, decision=args.decision or None))
        else:
            _dump(abort_dispatch(c, pilot_id=args.pilot_id, principal=owner, reason=args.reason))
    finally:
        c.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
