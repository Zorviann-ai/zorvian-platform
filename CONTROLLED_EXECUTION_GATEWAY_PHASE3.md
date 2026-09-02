# Controlled Execution Gateway Phase 3

**Stage 1 implemented on branch `core/controlled-execution-gateway-phase3-stage1`.**  
Base: `main` @ `d0e1112d3c41eb913b08b08ba27abecb83b49e54`.

External execution remains **disabled**. No provider request leaves the process. Stage 2 has not started.

## Database determination

The Python/Railway execution gateway uses **SQLite**.

Evidence:

- `app.py` defines `DB=os.getenv("SQLITE_PATH", .../zorvian.db)` and `db()` opens `sqlite3.connect(DB)`.
- `app_gate5.py` uses `from app import db as core_db` for tickets and plans.
- `intelligence/execution.py` and `intelligence/execution_adapters.py` type connections as `sqlite3.Connection` and call `CREATE TABLE IF NOT EXISTS`.
- Railway `Dockerfile` copies the Python app and `migrations/`; it does not run Wrangler/D1.
- Cloudflare D1 (`wrangler.toml`, `0001_initial.sql`) belongs to the JS Worker CRM path, not the Python ticket/plan store.

Phase 3 Stage 1 migrations are SQLite only: `migrations/0003_execution_gateway_phase3_stage1.sql`.

## Stage 1 scope

Foundations only:

- ProviderPort with `submit`/`cancel` fail-closed
- Configuration gates default deny
- Confirmation-token storage (hash only; no HTTP issuance)
- Shadow validation without ticket consume or network
- Webhook destination validation (no DNS, no connect)
- Append-only receipts and audit
- Operator status queries
- Reversible disablement that keeps evidence

Not in Stage 1: live grants enabled, pilot tenant, webhook/email/SMS/document/publication submit, website/auth/DNS/Worker changes.

## Gates (all default deny)

1. Process env `ZORVIAN_EXTERNAL_EXECUTION` missing/off
2. Global kill switch
3. Tenant/adapter kill switch
4. Tenant live grant (`enabled` default 0)
5. Adapter `live_execution_supported` (external adapters remain false)

Missing or uncertain configuration denies live evaluation.

## State machine

Allowed transitions only. Stage 1 public helpers may move `PREPARED → SHADOW_COMPLETE`. They must not enter `SUBMITTING` or later live states.

## Rollback

`migrations/0003_execution_gateway_phase3_stage1_down.sql` and `apply_phase3_disablement()` disable grants and raise a global kill switch. Attempts, receipts, shadow runs, tokens and audit rows are retained.

## Recommendation for later stages

First live candidate remains `webhook.post` to a platform-owned HTTPS sink, after Stage 2+ and a separate pilot approval.


Stage 2 sandbox, hardened destinations and ResolverPort added. Live submit remains disabled.
