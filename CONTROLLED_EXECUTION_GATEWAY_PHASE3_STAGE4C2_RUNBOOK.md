# Stage 4C2 — Production pilot runtime hardening and observability

Stage 4C2 sits on the merged Stage 4C1 ceremony. It does **not** activate a pilot,
install a secret, grant or allowlist, or enable `ZORVIAN_EXTERNAL_EXECUTION`.
There is no public `/activate` or `/reconcile` route. Stage 4D is not started.

## Defaults after merge

- `get_provider(webhook.post)` remains `ClosedProvider`
- `external_execution_enabled` remains false
- no HTTP activation or reconciliation route
- no seeded grants, allowlists or secrets
- observability is SELECT-only
- reconciliation never performs network I/O

## Runtime contract

After an internal Stage 4C1 ceremony (offline operator only):

1. Submit binds the exact ACTIVE activation: tenant, pilot, `webhook.post` /
   `post_webhook`, destination hash, manifest hash, Guardian assessment ID,
   context hash, policy version/hash, signing key ID, grant, allowlist, expiry,
   quota, kills and circuit.
2. `BEGIN IMMEDIATE` claims the one-shot slot before provider I/O.
3. Quota exhaustion disables the exact grant and deletes the exact allowlist row
   in the same transaction.
4. 2xx = EXECUTED, 4xx = FAILED, timeout/reset/5xx/malformed = UNCERTAIN.
   UNCERTAIN never retries. Stale SUBMITTING becomes UNCERTAIN without I/O.
5. Platform operators (`ZORVIAN_PLATFORM_OWNER_IDS` /
   `ZORVIAN_SECURITY_OPERATOR_IDS`) may list UNCERTAIN attempts, inspect
   redacted evidence, append a reconciliation decision and suspend the pilot.
6. `maintain_pilot_runtime()` is an idempotent closer. No scheduler is installed.

## Operator functions

- `observe_pilot_runtime(connection, principal=..., tenant_id=..., pilot_id=...)`
- `list_uncertain_attempts(...)`
- `inspect_attempt_redacted(...)`
- `record_reconciliation(..., decision=confirmed-success|confirmed-failure|unresolved)`
- `maintain_pilot_runtime(connection)`
