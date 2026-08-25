# Caelomere Gate 2 Deployment

## Included
- Public organisation account creation
- Email verification flow
- Argon2id password hashing
- Hashed session tokens
- Login lockout and rate limiting
- TOTP authenticator MFA
- Password reset token flow
- Team invitations and roles
- Tenant-scoped data access
- Guardian security events and status
- Production CORS allowlist for caelomere.com
- Production API docs disabled
- Security headers

## Railway variables required before public onboarding
CAELOMERE_ENV=production
GUARDIAN_HASH_PEPPER=<long random secret>
ALLOWED_ORIGINS=https://caelomere.com,https://www.caelomere.com

For email verification/password reset/invitations:
SMTP_HOST=<provider SMTP host>
SMTP_PORT=465
SMTP_USERNAME=<mailbox username>
SMTP_PASSWORD=<mailbox/app password>
SMTP_FROM=<verified from address>
SMTP_TLS_MODE=ssl

## Persistence
The current Gate 2 build remains SQLite-compatible to avoid breaking the live Railway service during the security upgrade. Before live customer data is accepted, attach persistent storage (Railway volume) or migrate the database layer to PostgreSQL.

## Gate 2 release rule
Do not open self-service customer onboarding until email delivery and persistent storage have both been verified with a real test account.
