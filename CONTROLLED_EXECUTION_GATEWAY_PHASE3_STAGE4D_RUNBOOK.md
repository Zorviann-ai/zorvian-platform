# Stage 4D — Production-pilot operational readiness

Stage 4D is an offline drill and evidence stage. Merging it activates nobody,
installs no secret, grant or allowlist, and sends no webhook.

## Prerequisites for a future pilot

- Stages 4A–4C2 merged and verified default-off
- Two named humans: platform owner and security operator
- Platform-owned HTTPS sink and environment-only signing secret
- Isolated SQLite for ceremony and drills, never the production path
- `ZORVIAN_EXTERNAL_EXECUTION` remains unset until a later authorised ceremony

## Named responsibilities

- Tenant owner / admin: propose and approve the preparation
- Platform owner: first platform approval and activation nonce
- Security operator: second platform approval and independent review
- On-call operator: shutdown, reconciliation and evidence export

## Two-person activation ceremony

Use the existing Stage 4C1 ceremony only. Stage 4D adds no activation route and
does not consume a challenge.

## Readiness checklist

Run `render_stage4d_readiness()` and `verify_deployment_default_off()`.
`activation_permitted` must remain false. Any FAIL blocks a future ceremony.

## Maximum pilot limits

- Window: 30 minutes
- Successes: 1
- Concurrent: 1
- Retries: 0
- Adapter: `webhook.post` / `post_webhook` only

## Monitoring

Use Stage 4C2 `observe_pilot_runtime()`. Views are redacted. Secrets, tokens,
payloads and full destinations must never appear.

## Immediate shutdown

Use `suspend_pilot()` with a configured `PlatformPrincipal`, then tenant
`emergency_shutdown()`. Global shutdown requires a platform role.

## Uncertain outcomes

Timeout, reset, 5xx and malformed responses stay UNCERTAIN and never retry.
Record reconciliation only for UNCERTAIN attempts.

## Reconciliation

`record_reconciliation()` is append-only, platform-principal only, and must
close the exact grant and allowlist.

## Evidence retention

Export `export_redacted_evidence()` to operator-controlled storage. Do not write
bundles into the production database automatically.

## Rollback

Disable process flags, raise the kill switch, suspend the pilot, and keep
receipts and audit rows.

## Abort conditions

- Missing or stale Guardian / platform evidence
- Production environment or production database path detected in a drill
- Any enabled grant or allowlist without an ACTIVE activation
- Any public `/activate` or `/reconcile` route
- Any default provider other than ClosedProvider

## Merge proof

Stage 4D bootstrap seeds no pilot, activation, grant, allowlist or secret.
`get_provider(webhook.post)` remains `ClosedProvider`.
