# Zorvian Gate 7 — Operational Email

Gate 7 email is complete only when the following are implemented and tested:

- professional HTML email rendering with plain-text fallback
- branded Zorvian system emails
- client-branded outbound emails with discreet Powered by Zorvian Core footer
- authenticated tenant-scoped outbound sending
- inbound email receiving through a signed provider webhook
- reply-to thread routing
- tenant routing for direct inbound addresses
- contact association and creation for new inbound senders
- persisted email threads, messages and provider events
- tenant audit events for sent and received mail
- truthful integration status: connected only when outbound and inbound are configured
- Control Room status supplied through the existing integrations endpoint

## Production configuration

Outbound requires `RESEND_API_KEY` (or the existing compatible provider key) and `SMTP_FROM`.

Inbound additionally requires:

- `RESEND_INBOUND_DOMAIN`
- `RESEND_WEBHOOK_SECRET`
- a Resend webhook targeting `/webhooks/resend` with `email.received` enabled

No workspace is reported as fully connected until both outbound and inbound capability checks pass.
