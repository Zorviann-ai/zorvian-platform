# Controlled Execution Gateway Phase 3

**Stage 1 implemented on branch `core/controlled-execution-gateway-phase3-stage1`.**  
Base: `main` @ `d0e1112d3c41eb913b08b08ba27abecb83b49e54`.

**Stage 2 implemented on branch `core/controlled-execution-gateway-phase3-stage2`.**  
Base: `main` @ `a340878` / merge `ab245a0`.

**Stage 3 implemented on branch `core/controlled-execution-gateway-phase3-stage3-rebuild`.**  
Base: `main` @ `ab245a0538afd5703a6087a240575134bfb30cb1`.

External execution remains **disabled**. Production `get_provider` remains `ClosedProvider`.
There is no production grant, no public live endpoint, and no Stage 4 work.

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

## Stage 2 scope

Isolated webhook sandbox, hardened destinations and ResolverPort. Live submit remains disabled.

## Stage 3 scope

Internal-only isolated-CI webhook live lifecycle against a hermetic TLS CI sink.

- State machine and fail-closed transitions
- `BEGIN IMMEDIATE` atomic claim
- Atomic confirmation-token and execution-ticket consumption
- Deterministic idempotency
- At-most-one automatic provider submission
- Hermetic TLS CI sink
- Pinned validated IP with TLS hostname verification
- No redirects or environment proxy
- timeout / reset / 5xx → `UNCERTAIN` with no retry
- 4xx → `FAILED`
- verified 2xx → `EXECUTED`
- Crash and stale-`SUBMITTING` recovery without resubmission
- Cancellation late success → `EXECUTED_AFTER_CANCEL_REQUEST`
- Circuit breaker and atomic rate/concurrency limits
- Immutable receipts and evidence

Not in Stage 3: production grant, public live endpoint, website/auth/branding/DNS/D1/Worker/deployment changes, Stage 4.

## Gates (all default deny)

1. Process env `ZORVIAN_EXTERNAL_EXECUTION` missing/off
2. Global kill switch
3. Tenant/adapter kill switch
4. Tenant live grant (`enabled` default 0)
5. Adapter `live_execution_supported` (external adapters remain false)

Isolated CI uses a separate switch `ZORVIAN_ISOLATED_CI_EXECUTION` and an isolated grant. Turning the production switch on denies the isolated path.

Missing or uncertain configuration denies live evaluation.

## State machine

Allowed transitions only. Stage 1 public helpers may move `PREPARED → SHADOW_COMPLETE`. They must not enter `SUBMITTING` or later live states.

Stage 3 isolated submit may move `SHADOW_COMPLETE → SUBMITTING` and then to `EXECUTED`, `FAILED`, `UNCERTAIN`, or `CANCEL_REQUESTED`. Late success after cancel becomes `EXECUTED_AFTER_CANCEL_REQUEST`.

## Rollback

`migrations/0003_execution_gateway_phase3_stage1_down.sql` and `apply_phase3_disablement()` disable grants and raise a global kill switch. Attempts, receipts, shadow runs, tokens and audit rows are retained.

## Recommendation for later stages

## Stage 4A scope

Production-grade webhook pilot capability, switched off. Provider selection defaults to ClosedProvider. No pilot tenant, grant, destination or signing secret is created by merge or migration.

## Stage 4B scope

Operator-controlled readiness, two-person preparation, precheck, shutdown and observability. Status remains PREPARED until a separate Stage 4C1 ceremony.

## Stage 4C1 scope

Activation control plane only. No tenant is activated by merge. No HTTP activation route. ClosedProvider remains the default. Stage 4C2 is not started.

First live candidate remains `webhook.post` to a platform-owned HTTPS sink after a later Stage 4C2 ceremony.
