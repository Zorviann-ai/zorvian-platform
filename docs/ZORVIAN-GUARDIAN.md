# Zorvian Guardian

Zorvian Guardian is the platform's secure-development protection layer. Stage 1 is deliberately narrow: it protects the software-delivery path without granting itself production authority.

## Security constitution

Guardian follows five non-negotiable rules:

1. **Guardian may block, but not silently escalate.** It can fail CI or stop a release gate, but it must not grant itself broader permissions.
2. **Guardian does not self-merge.** Automated findings and suggested fixes require a human-reviewed pull request.
3. **Guardian does not perform destructive production actions.** No production deploys, data deletion, secret rotation, account changes, or permission changes are part of Stage 1.
4. **Security controls are fail-closed.** A missing, broken, or bypassed required security check is itself release-blocking.
5. **Exceptions are explicit and reviewable.** A security exception must document scope, owner, reason, compensating control, and expiry; silent bypasses are prohibited.

## Stage 1 controls

Guardian currently provides:

- repository-aware generated security invariant tests;
- a Node test-runner gate;
- repository secret-pattern scanning that does not print secret values;
- `npm audit` with high/critical dependency findings treated as blocking;
- GitHub CodeQL extended JavaScript/TypeScript analysis;
- minimal GitHub Actions permissions;
- documented branch and release protection requirements.

## Generated security invariants

Guardian checks that the application keeps these protections visible in source:

1. Session cookies remain `HttpOnly`, `Secure`, and `SameSite=Lax`.
2. Password hashing continues to use PBKDF2.
3. Registration keeps a minimum password-length check.
4. Server-side session authentication remains present.
5. `/api/ai/*` routes retain an authentication guard.
6. Database operations retain parameter binding.
7. Unhandled Worker failures return a generic error rather than raw exception details.

The generator is intentionally conservative: if a security-sensitive refactor removes or changes one of these controls, the pull request fails until the new implementation is reviewed and the invariant is deliberately updated.

## Secret scanning

`npm run guardian:secrets` scans repository text files for high-risk credential patterns including private keys, common provider tokens, and suspicious hard-coded secret assignments. It excludes generated/dependency directories and reports only file paths and finding classes, never the matched credential value.

Repository-host secret scanning should also be enabled when the GitHub plan/settings support it; Guardian's local scanner is a defense-in-depth control, not a replacement for provider-native secret protection.

## CodeQL

Guardian runs the extended JavaScript/TypeScript query suite. The analysis output is retained as SARIF even when repository-level GitHub code scanning is unavailable. When GitHub code scanning is enabled, the repository should upload SARIF and use security findings as a required review signal.

## Release-blocking criteria

A pull request or release must be blocked when any of the following is true:

- a generated security invariant fails;
- the secret scanner identifies likely committed credentials;
- `npm audit` reports a high or critical vulnerability without an approved, time-bounded exception;
- required CI/security jobs fail, are skipped unexpectedly, or cannot execute;
- a confirmed high/critical static-analysis finding is unresolved;
- authentication, authorization, tenant isolation, session security, parameterized data access, or generic error handling is weakened without explicit security review;
- a change introduces production write/destructive authority into Guardian Stage 1;
- branch protection would allow merging while required Guardian checks are failing.

Moderate/low findings are triaged rather than automatically ignored; risk can be raised by exploitability, exposure, or chained impact.

## Branch protection guidance

For `main`, configure GitHub branch/ruleset protection to:

- require pull requests before merge;
- require Guardian's security checks and the platform's existing build/test checks;
- require branches to be up to date before merge where practical;
- block force-pushes and branch deletion;
- prevent bypass of required checks except through an explicitly controlled break-glass process;
- require at least one human approval for security-sensitive or production-impacting changes.

Guardian documents these settings but does not change repository or organization permissions by itself.

## Commands

```bash
npm run guardian:generate
npm run guardian:test
npm run guardian:secrets
npm run guardian
```

## AI-assisted security review

Static analysis and deterministic checks are the security gate. AI-assisted explanations or remediation may help developers understand findings and propose changes, but AI-generated fixes receive no automatic production authority and may not merge themselves.

## Stage 1 completion gate

Stage 1 is review-ready only when:

1. generated security tests pass;
2. secret scanning passes;
3. high/critical dependency audit findings are remediated or covered by an explicit reviewed exception;
4. static analysis executes successfully and its results are reviewable;
5. CI is green on the Guardian pull request;
6. the constitution, release-blocking criteria, and branch-protection expectations are documented;
7. no Guardian change touches production or bypasses the separate Video development track.
