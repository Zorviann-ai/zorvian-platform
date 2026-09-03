# Stage 4G — path monopoly and Phase 3 freeze

Merge, deploy, import and tests activate nobody and send no webhook.

## Rule

`execute_once` arms a one-use in-context ticket immediately before calling
`_claimed_production_submit`. The private engine consumes that ticket before
any claim mutation or provider I/O. There is no public arm function. Public
`submit_production_pilot()` always raises. HTTP `/live` only refuses.

## Abort

- `/live` or public submit reaches a provider
- the private engine is called outside `execute_once`
- default provider is not ClosedProvider
