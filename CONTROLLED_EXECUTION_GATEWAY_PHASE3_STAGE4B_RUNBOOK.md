# Controlled Execution Gateway Phase 3 — Stage 4B Runbook

Stage 4B prepares one future internal `webhook.post` pilot. It does not activate that pilot.

## What Stage 4B does

- Read-only readiness assessment
- Two-person preparation (proposer ≠ approver)
- Hash-bound PREPARED manifest
- Fail-closed activation precheck (no activation)
- Emergency shutdown and observability
- Evidence-preserving kill switches

## What remains disabled

- `get_provider()` defaults to `ClosedProvider`
- `ZORVIAN_EXTERNAL_EXECUTION` stays unset
- `ZORVIAN_WEBHOOK_PILOT_ENABLED` stays unset
- No pilot tenant, grant, allowlist entry or signing secret is created by this stage
- No provider request is sent
- Stage 4C activation does not exist

## Two-person preparation

1. An owner/admin proposes a pilot bound to tenant, `webhook.post`, destination hash, suffix, key id, expiry and request cap.
2. A different owner/admin approves the same record.
3. Status remains `PREPARED`. It cannot become `ACTIVE` in Stage 4B.

## Inspect readiness

`GET /api/execution/pilot/readiness` (owner/admin).

The response lists PASS / FAIL / UNKNOWN checks. UNKNOWN or FAIL is a denial. Assessment never writes env, grants, allowlists, secrets, tickets or network.

## Future Stage 4C activation (not implemented)

Stage 4C would require a separate approved change that:

1. Re-runs readiness and precheck
2. Confirms two distinct people
3. Enables only the bound tenant/destination/key
4. Still fail-closes on mismatch

No Stage 4C route exists in this branch.

## Immediate shutdown

`POST /api/execution/pilot/shutdown` with a reason.

Tenant owner/admin shutdown independently:

- raises only that tenant's `webhook.post` kill switch
- marks that tenant's PREPARED pilots `SUSPENDED`
- records a revocation approval
- blocks new live claims for that tenant
- preserves attempts, receipts and audit

Global kill is not exposed on the tenant API. It remains an internal platform-operator action.

Confirm with `GET /api/execution/pilot/shutdown-status`.

## Uncertain outcome

Leave UNCERTAIN and SUBMITTING attempts in place. Do not retry automatically. Inspect receipts. Treat the destination as unknown until operator review.

## Rollback

1. Run shutdown.
2. Confirm `shutdown_effective`.
3. Confirm `ClosedProvider` is still the default provider.
4. Do not delete evidence.

Stage 1 disablement SQL remains available and does not drop history.

## Secret rotation

Rotation is an environment-only operation outside this stage. Store only a key id in the manifest. Never put the signing secret in SQLite or API responses. After rotation, precheck must fail until the manifest key id matches the live key id.

## Evidence preservation

Shutdown and expiry change status only. Attempts, receipts, approvals and ops audit rows remain.

## Proof Stage 4B activates nothing

- No code path sets status `ACTIVE`
- No route named activate exists
- Readiness and propose/approve do not call DNS or providers
- Default tests assert `ClosedProvider` and `external_execution_enabled=False`
- Merge/import inserts no grant, allowlist or secret
