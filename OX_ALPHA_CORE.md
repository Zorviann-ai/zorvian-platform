# Ox Alpha Core Integration

Ox Alpha is Zorvian's preferred reasoning engine for ordinary analysis and drafting. Zorvian Core continues to own identity, tenant isolation, business state, routing, Guardian policy, approval gates, audit and provider replacement.

## Required server secret

Set `OPENROUTER_API_KEY` in the Railway environment. Never place the key in GitHub, HTML or a browser-side variable.

Optional settings:

- `OX_ALPHA_MODEL=stealth/ox-alpha`
- `OX_ALPHA_MAX_TOKENS=4096` (hard-capped by the adapter at 16,384)
- `PUBLIC_APP_URL=https://zorvian.co.uk`

## Safety boundary

- Ox is selected first for normal reasoning, drafting and specialist analysis.
- Consequential work is not sent through Ox while the stealth provider is anonymous.
- External communications, submissions, commitments and destructive actions remain human approval-gated.
- Provider failures return a controlled `502`; credentials and raw provider errors are not returned to clients.
- Every successful run is recorded by Zorvian's existing tenant audit path.

## Deployment check

After the secret is configured in staging, authenticate and call `GET /intelligence/capabilities`. It must report `provider_mode: ox-alpha-primary`. Then run a non-sensitive test through `POST /intelligence/run` and verify the response provider is `ox-alpha` and an `intelligence_run` audit record exists.
