# Stage 4C1 — Activation control plane (switched off)

Stage 4C1 builds the activation ceremony only. Merge does not activate a tenant,
destination, grant, allowlist, secret or execution switch. Stage 4C2 is not started.

## Defaults after merge

- `get_provider(webhook.post)` remains `ClosedProvider`
- `external_execution_enabled` remains false
- no HTTP `/activate` route
- no seeded grants or allowlist rows
- signing secret stays in process environment only

## Ceremony (offline / service)

1. Stage 4B prepare + tenant two-person approve + Guardian bind
2. Resolve `PlatformPrincipal` from `ZORVIAN_PLATFORM_OWNER_IDS` / `ZORVIAN_SECURITY_OPERATOR_IDS` (offline operator only)
3. `record_platform_approval` for each principal; approvals are bound to manifest + Guardian hashes
4. `issue_activation_challenge` — hash-only nonce, 10 minute TTL
5. `activate_pilot` with the nonce inside `BEGIN IMMEDIATE`
6. `suspend_pilot` to close the window

Issuing a challenge does not activate. Tenant owner/admin tokens cannot perform
platform activation. Callers cannot supply tenant, destination, hashes, adapter,
key or limits as authority.

## Hard limits

- webhook.post / one tenant / one destination / one key
- 30 minutes, 1 success, 1 concurrent, 0 retries
