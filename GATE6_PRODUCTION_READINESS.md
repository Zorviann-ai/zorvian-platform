# Zorvian Gate 6 — Production Readiness and Controlled Pilot

## Objective
Prove that the Gate 5 connected system can operate safely with controlled real users, persistent data, isolated environments and auditable server-side intelligence before wider onboarding.

## Non-negotiable controls
- Staging and production use different environment and database identifiers.
- Production data is stored on an attached persistent volume or approved managed database.
- Real email verification is proven; development token exposure remains disabled.
- Provider credentials remain server-side and Guardian remains active.
- Consequential actions remain approval-gated.
- Pilot evidence contains no passwords, tokens, provider keys or private customer content.
- Public self-service onboarding stays closed until every readiness check passes.

## Completion criteria
1. Fail-closed readiness endpoint restricted to owner/admin roles.
2. Unique staging and production environment/database identifiers.
3. Persistent data survives application restart or redeployment.
4. Registration, email verification, login, logout and MFA verified with a controlled account.
5. Cross-tenant reads and writes rejected across business objects and intelligence calls.
6. Approved server-side AI adapter configured without exposing credentials to the browser.
7. Guardian, rate limits, audit events and human approval controls verified.
8. Gate 2–5 regression suites remain green.
9. Controlled pilot evidence generated from the deployed environment.
10. GitHub checks and both deployments pass before Gate 6 sign-off.

## Required deployment variables
- ZORVIAN_ENV=staging or production
- ZORVIAN_ENVIRONMENT_ID=<unique non-secret identifier>
- ZORVIAN_DATABASE_ID=<unique non-secret identifier>
- SQLITE_PATH=<attached persistent-volume absolute path>
- GUARDIAN_HASH_PEPPER=<minimum 32-character secret>
- ALLOWED_ORIGINS=<explicit HTTPS origins>
- SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD, SMTP_FROM
- ZORVIAN_AI_ADAPTER_URL, ZORVIAN_AI_ADAPTER_KEY

## Release rule
A code deployment is not a Gate 6 pass. Gate 6 passes only when the deployed environment returns ready=true, the controlled pilot succeeds, persistence is rechecked after restart, tenant-isolation tests pass and all GitHub checks are green.
