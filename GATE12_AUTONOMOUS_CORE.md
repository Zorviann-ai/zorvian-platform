# Gate 12 — Autonomous Zorvian Core

Gate 12 extends the existing working CRM without replacing earlier gates.

## What is live in this build

- Authenticated, tenant-bound Core autonomy endpoints.
- Per-workspace autonomy policy: `observe`, `supervised`, or `active`.
- CRM snapshot of contacts, tasks, overdue work, bookings, campaigns, documents and video projects.
- Safe internal autonomy: the Core can create missing CRM follow-up tasks for unattended contacts.
- Every autonomous run and action is recorded for audit/review.
- The existing Zorvian intelligence router is invoked as `business-control` to assess CRM state and prioritise next work.
- Provider mesh merged into the Core authentication boundary. The browser never supplies a tenant id.
- Server-side provider status for AI, voice, messaging, email, travel, routing, video, audio, social and documents.
- Consequential external operations remain approval-gated.
- Initial live connector mappings retained for Resend email, HERE routing, HeyGen video and ElevenLabs voice discovery when credentials are configured.

## Main endpoints

- `GET /core/autonomy/status`
- `PATCH /core/autonomy/settings`
- `POST /core/autonomy/run`
- `GET /core/autonomy/runs`
- `GET /core/providers`
- `POST /core/providers/approvals`
- `POST /core/providers/approvals/{approval_id}/approve`
- `POST /core/providers/execute`

## Safety model

Internal reversible CRM housekeeping can be autonomous according to workspace policy. External actions such as sending, publishing, calling, booking, purchasing and final rendering require an approved, tenant-bound action token before execution.

## Deployment

The Docker entrypoint is now `app_gate12:app`. Gate 11 remains intact underneath it as the previous stable layer.
