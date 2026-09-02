# Caelomere Stage 4F — sealed one-shot production-pilot dispatch

Internal operator path for one previously approved and activated pilot
execution. Merge, deploy, import, bootstrap, preflight and tests activate
nobody and send no webhook.

## Modes

- `preflight` — default. SQLite SELECT-only. Cannot submit.
- `issue-dispatch-confirmation` — writes a 0600 handoff file only.
- `execute-once` — consumes confirmation, claims quota, closes grant/allowlist, then makes exactly one provider call through the existing Stage 4A path.
- `status` — SELECT-only redacted view.
- `closeout` — terminal authority removal; UNCERTAIN uses Stage 4C2 reconciliation.
- `abort` — suspends the exact pilot. Evidence is preserved.

There is no public `/dispatch`, `/activate`, `/reconcile` or `/ceremony` route.

## Authority

Tenant, destination, hashes, adapter, signing-key ID, policy and limits come
only from stored Stage 4B/4C/4E/Guardian/plan records. Caller substitutes are
rejected. Two distinct configured platform principals must approve the exact
dispatch context.

## Confirmation

A yes/no flag is not enough. Confirmation is random, hash-only, short-lived,
single-use and bound to pilot, activation, ceremony receipt, plan and hashes.

## Secret

Load only from `ZORVIAN_WEBHOOK_PILOT_SIGNING_SECRET`. Never accept it from
CLI arguments, stdin files other than the 0600 handoff, SQLite, API input or
logs.

## Closeout

After EXECUTED, FAILED or UNCERTAIN the exact grant stays disabled, the exact
allowlist stays removed, and the activation is no longer ACTIVE. UNCERTAIN
never retries automatically.
