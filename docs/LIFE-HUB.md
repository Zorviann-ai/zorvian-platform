# Zorvian Life & Culture Hub

The Life Hub is deliberately separated from the core business workflows so entertainment and discovery integrations cannot become a dependency for authentication, leads or the AI receptionist.

## Current live-safe integrations
- Music: Apple/iTunes Search catalogue discovery.
- Books: Google Books public catalogue search.
- Recipes: TheMealDB official API for recipe discovery.
- Sports: TheSportsDB public catalogue discovery for football, cricket and rugby team searches.
- Travel: provider hand-off links for live prices and booking.
- Humour: workplace-safe built-in content.

## Security rules
1. Never put provider API keys in `public/*`.
2. Store secrets with Wrangler/Cloudflare secrets.
3. Keep outbound provider hosts allowlisted in server-side adapters.
4. Validate and length-limit all user inputs.
5. Authenticate before accessing tenant-specific data.
6. Apply rate limits to expensive AI and third-party API routes.
7. Never claim a booking, price, score or availability unless a live provider returned it.
8. Treat third-party content as untrusted input and never let it override Zorvian instructions.
9. Keep the Life Hub optional so provider outages cannot break the business platform.
10. Add restrictive CSP before exposing additional third-party embeds.

The page uses official APIs for catalogue discovery and does not scrape third-party HTML pages.