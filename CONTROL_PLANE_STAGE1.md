# Integration Stage 1 — Documents / Legal Correspondence (FIX)

Base: `aef618d59933184a37b1e4dd97c3c2985e387921`

Controlled action is **release** (`Released` / Approved for Dispatch).
No external delivery adapter runs. API records `delivery: not_performed`.
Do not describe this as Sent.

Event chain is **tamper-evident**, not immutable.

New tenants default to `org_type=general`, empty sectors, and unresolved jurisdiction.
Dockerfile copies `control_plane.py` and `migrations/` into the app_gate12 image. Entrypoint is unchanged.
Purpose and data classification are declared on the document.
Financial Intelligence is recorded `not_applicable` unless the tenant is a financial entity.
Human-authored documents store `produced_by=human`. Model-produced documents fail closed unless stored model ID, provider and version match an approved card.
`POST /documents` still accepts the original `{type, recipient, facts}` body. Purpose and data classification stay unresolved until declared; release is blocked until then.

`migrations/0002_control_plane_stage1.sql` creates control tables.
Document columns are declared in that file’s companion list `DOCUMENT_COLUMNS` and applied idempotently by `init_control_schema`.

Permissions:
- `/control/trace/{id}` — `approve`
- `/control/chain` — `admin`
- `/control/models` — `admin`
