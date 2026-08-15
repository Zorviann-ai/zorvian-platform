# Stage 1 — exact deployment

## 0. Cost gate
Local development is £0. Do not create a paid Cloudflare plan for Stage 1 local testing.

Important: Workers AI is configured **only for the production environment**. Local development does not call Workers AI and therefore does not incur AI usage charges.

## 1. Local test — £0
Requirements: Node.js 20.x and Apple's Command Line Tools.

From the project folder:

```bash
npm install
npm run db:local
npm run dev
```

Open the localhost URL printed by Wrangler. The local app uses a simulated D1 database and the AI endpoints use their safe fallback responses when no AI binding exists.

## 2. Production Cloudflare account — cost gate
Create/login to a Cloudflare account. **Do not choose a paid plan yet.**

Install Wrangler if needed:

```bash
npm install -g wrangler@4.11.0
wrangler login
```

## 3. Production database
Create the D1 database:

```bash
npx wrangler d1 create zorvian
```

Copy the returned `database_id` into BOTH `database_id` entries in `wrangler.toml`.

Initialize production schema:

```bash
npm run db:remote
```

## 4. Production AI — explicit cost gate
Workers AI is enabled only under `[env.production.ai]`.

Cloudflare states that Workers AI usage is billed even during local development when the AI binding is present. This project deliberately avoids that by keeping the binding out of local configuration.

Before enabling production AI, confirm the current Cloudflare Workers AI pricing/allowance in your account. Do not assume it is free.

## 5. Production deploy
Only after the database ID is set and the AI cost is understood:

```bash
npm run deploy
```

## 6. Production smoke test
Open the deployed URL and test:

- registration
- login
- logout
- client workspace isolation
- lead creation/listing
- `/api/health`

Do not put real customer data into the system until the Stage 2 security hardening is completed.
