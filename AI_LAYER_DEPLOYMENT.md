# AI layer deployment

The browser never receives model credentials. Configure one or more providers as
Railway service variables and redeploy the Core service.

## Primary provider

- `OPENAI_API_KEY` — server-side API key
- `OPENAI_MODEL` — optional; defaults to `gpt-5`

## Secondary provider

- `ANTHROPIC_API_KEY` — server-side API key
- `ANTHROPIC_MODEL` — optional; defaults to `claude-sonnet-4-5`

## Existing private adapter (optional)

- `ZORVIAN_AI_ADAPTER_URL`
- `ZORVIAN_AI_ADAPTER_KEY`
- `ZORVIAN_AI_MODEL`

## Fallback policy

`ALLOW_LOCAL_BETA=1` keeps the deterministic beta engine available when no remote
provider is configured. Set `ALLOW_LOCAL_BETA=0` in production if requests must fail
closed whenever every remote provider is unavailable.

After deployment, sign in and call `GET /intelligence/capabilities`. Production is
AI-connected only when `provider_mode` is `connected` and
`configured_provider_count` is at least `1`.

Never put provider keys in the website HTML, GitHub, screenshots or client-visible
configuration.
