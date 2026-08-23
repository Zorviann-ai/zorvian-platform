# Zorvian Provider Mesh Backend v2

Deployable FastAPI provider gateway for the Zorvian master portal.

## Core controls
- Server-side approval enforcement for bookings, purchases, sends, publishing, calls, cancellations and final rendering.
- Tenant-scoped approvals, jobs and audit records.
- Provider registry with primary/fallback strategy.
- Health endpoint reports which provider connectors are actually credentialed.
- Provider keys remain server-side and are never exposed to the HTML.

## Run
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

## Front-end contract
- GET /health
- GET /v2/providers
- POST /v2/approvals
- POST /v2/approvals/{id}/approve
- POST /v2/execute
- GET /v2/jobs/{id}

For a high-risk operation, request approval for `<service>:<operation>`, approve it, then send that `approval_id` with `/v2/execute`.

## Provider strategy
- Intelligence: OpenAI primary; Anthropic fallback.
- Voice/SMS/WhatsApp: Twilio primary; Telnyx/Meta fallback.
- Email: Resend primary; SMTP fallback.
- Flights: Duffel primary; Amadeus fallback.
- Hotels: Duffel primary; Expedia Rapid fallback.
- Routing/traffic: HERE primary; TomTom fallback.
- Video/avatar: HeyGen primary; generative-video fallback.
- Audio/voice/dubbing: ElevenLabs primary; OpenAI audio fallback.
- Social: official/native platform APIs first.
- Guardian: Zorvian policy/audit layer with Cloudflare at the edge.

Missing credentials never produce a fake success. The connector returns `connector_ready` until a real credential is configured.
