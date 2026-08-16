# Zorvian Life & Culture Hub

The Life Hub is deliberately separated from the core business workflows so entertainment and discovery integrations cannot become a dependency for authentication, leads or the AI receptionist.

## Current live-safe integrations

- **Music:** Apple/iTunes Search catalogue discovery. No private credential is embedded in the browser.
- **Books:** Google Books public catalogue search.
- **Recipes:** TheMealDB official API for recipe discovery. Commercial/public deployment should use the service's appropriate supporter tier and attribution requirements.
- **Travel:** provider hand-off links are generated from a user brief. Zorvian does not invent live prices or availability.
- **Humour:** workplace-safe built-in content.

## Planned authenticated integrations

Sports and other commercial data providers must be connected through the Worker, never directly from browser JavaScript. Examples include a football/rugby provider and a cricket provider. Credentials belong in Cloudflare Worker secrets.

## Security rules

1. Never put provider API keys in `public/*`.
2. Store secrets with Wrangler/Cloudflare secrets.
3. Keep outbound provider hosts allowlisted in server-side adapters.
4. Validate and length-limit all user inputs.
5. Use authentication before accessing tenant-specific data.
6. Apply rate limits to expensive AI and third-party API routes.
7. Do not claim a booking, price, score or availability unless a live provider returned it.
8. Treat third-party content as untrusted input; never allow it to override Zorvian system instructions.
9. Keep the Life Hub optional so provider outages do not break the business platform.
10. Add security headers and restrictive CSP before exposing additional third-party embeds.

## Provider notes

The current page uses official APIs for catalogue-style discovery. It does not scrape third-party HTML pages. This reduces fragility and respects provider terms while leaving room for licensed live-data integrations later.
