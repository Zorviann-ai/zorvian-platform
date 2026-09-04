# Portal Experience v1 — Phase 1B recovery candidate

Frozen visual shell served at `/portal/`.

Uses existing Worker session:

- `GET /api/me` with `credentials: include`
- unauthenticated visitors are sent to existing `/` sign-in
- Social Media requests use `POST /api/ai/social`
- host presentation remains local (Celeste / Cassian / Lin)

Recovery candidate. Not the lost SHA `90dcfd7`.
Not production. Do not merge or deploy from this note.
