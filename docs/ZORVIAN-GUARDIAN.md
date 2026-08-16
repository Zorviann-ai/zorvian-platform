# Zorvian Guardian

Zorvian Guardian is the platform's automated test-generation and security-review gate.

## What it does

- Generates repository-aware security invariant tests from the current Worker source on every pull request.
- Runs those generated tests with Node's built-in test runner.
- Runs `npm audit` and fails on high/critical dependency findings.
- Runs GitHub CodeQL with the extended JavaScript/TypeScript security query suite.
- Publishes CodeQL findings into GitHub code scanning, where supported by the repository plan/settings.

## Current generated security invariants

Guardian checks that the application keeps these protections visible in source:

1. Session cookies remain `HttpOnly`, `Secure`, and `SameSite=Lax`.
2. Password hashing continues to use PBKDF2.
3. Registration keeps a minimum password-length check.
4. Server-side session authentication remains present.
5. `/api/ai/*` routes retain an authentication guard.
6. Database operations retain parameter binding.
7. Unhandled Worker failures return a generic error rather than raw exception details.

The generator is intentionally conservative: if a security-sensitive refactor removes or changes one of these controls, the pull request should fail until the new implementation is reviewed and the invariant is deliberately updated.

## Commands

```bash
npm run guardian:generate
npm run guardian:test
npm run guardian
```

## AI-assisted security review

CodeQL is the authoritative static-analysis gate. GitHub's code-scanning/Copilot security remediation features can then provide AI-assisted explanations and suggested fixes where they are enabled for the repository. Guardian does not grant an AI model write access to production code and does not automatically apply security fixes.

## Design principle

Security findings can block a merge. Automated remediation cannot merge itself. A human-reviewed pull request remains the control point for production changes.
