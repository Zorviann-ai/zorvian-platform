# Zorvian Gate 7 — Controlled Pilot Production Readiness

Status: IMPLEMENTATION BRANCH
Base: Gate 6 verified registration and transactional email flow

## Objective
Move Zorvian from verified staging into a controlled pilot without weakening Guardian, tenant isolation, approval gates, or authentication controls.

## Release controls
- Production and staging remain separate environments.
- Production secrets must be configured only in the production environment and never committed to GitHub.
- `ZORVIAN_ENV=production` in production.
- `DEV_EXPOSE_TOKENS` must be disabled/false in production.
- `GUARDIAN_HASH_PEPPER` must be a unique production secret.
- `PUBLIC_APP_URL` must point to the production application URL.
- `ALLOWED_ORIGINS` must contain only approved Zorvian production origins.
- Transactional email must use the verified Resend HTTPS route and production sender/domain.
- Persistent database storage must be mounted and backed up before pilot users are admitted.

## Gate 7 acceptance tests
1. `/health` returns HTTP 200 in production.
2. Production registration creates a new isolated tenant/workspace.
3. Verification email is delivered and the one-time verification link verifies the account.
4. Unverified accounts cannot authenticate.
5. Verified account can sign in and `/auth/me` returns only its own tenant/workspace.
6. A second tenant cannot access the first tenant's contacts, tasks, bookings, documents, tenders, audit or Guardian data.
7. Role permissions reject unauthorised write/approve/admin operations.
8. Session logout revokes the token.
9. Password-reset email is delivered; reset invalidates existing sessions.
10. MFA setup/enable/login path is tested for a pilot administrator.
11. Guardian status is active and security/audit events are recorded.
12. Tender/document approval remains principal-controlled before external use.
13. Production restart preserves persistent account/workspace data.
14. Backup/restore procedure is verified before wider release.

## Controlled pilot policy
Pilot access is invite/approved-user only. No broad public launch is authorised by Gate 7. High-impact external actions remain approval-gated. Live integrations are enabled individually after credentials, permissions and rollback paths are verified.

## Rollback
If authentication, tenant isolation, persistent storage, email verification, Guardian controls or approval gating fail, stop pilot admission and roll production back to the last known-good deployment. Preserve database/backups and investigate in staging.

## Exit criterion
Gate 7 is sealed only after the production deployment and all applicable acceptance tests above have passed against the production environment. A successful GitHub commit or staging test alone does not seal Gate 7.
