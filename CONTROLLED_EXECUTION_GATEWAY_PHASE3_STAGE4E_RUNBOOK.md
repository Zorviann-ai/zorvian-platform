# Caelomere Stage 4E — sealed production-pilot ceremony

Internal operator ceremony for a future one-shot production webhook canary.
Merge, deploy, import, bootstrap, preflight and tests activate nobody.

## Modes

- `preflight` — default. SQLite SELECT-only. No network. Cannot activate.
- `execute` — unavailable until Phase 1–4D evidence, two distinct configured platform principals, an unused Stage 4C1 challenge and a random single-use confirmation all match stored records.
- `abort` — fail-closes the exact pilot. Idempotent. Evidence is preserved.

There is no public `/activate`, `/reconcile` or `/ceremony` route.

## Authority

Platform owner and security operator are resolved from configured identities.
Caller-supplied role strings are rejected. The two actors must differ.
Tenant, destination, hashes, adapter, signing-key ID, policy and limits are taken only from stored Stage 4B/4C/Guardian records.

## Confirmation

A normal yes/no flag is not enough. Confirmation is random, stored hash-only, short-lived, single-use and bound to the complete ceremony context.

## Secret

Load only from `ZORVIAN_WEBHOOK_PILOT_SIGNING_SECRET`.
Never accept it from CLI arguments, stdin, files, SQLite, API input or logs.
Never print, persist or return it.

## Limits

30-minute window, one success, one concurrent submission, zero automatic retries, one ACTIVE pilot per tenant/adapter.

Activation does not submit the webhook. Submission remains a separate later operator decision.

## Abort

Suspend the activation, disable the exact grant, remove the exact allowlist, keep every audit/Guardian/receipt row.
