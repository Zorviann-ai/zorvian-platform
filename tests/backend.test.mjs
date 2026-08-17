import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/backend-entry.js";

class FakeDB {
  constructor() {
    this.auditRows = [];
    this.leadInserts = [];
    this.sessionDeletes = [];
    this.selectedTenant = null;
    this.user = {
      id: "session-1",
      expires_at: "2099-01-01T00:00:00.000Z",
      user_id: "user-1",
      name: "Test User",
      email: "test@example.com",
      role: "client",
      tenant_id: "tenant-a",
      tenant_name: "Tenant A",
      tenant_slug: "tenant-a",
      website_url: null,
    };
  }

  prepare(sql) {
    const db = this;
    return {
      bind(...args) {
        return {
          async first() {
            if (/FROM sessions s\s+JOIN users u/i.test(sql)) {
              return args[0] === "session-1" ? db.user : null;
            }
            if (/SELECT id FROM users WHERE email/i.test(sql)) return null;
            if (/SELECT id FROM tenants WHERE slug/i.test(sql)) return null;
            if (/SELECT \* FROM users WHERE email/i.test(sql)) return null;
            return null;
          },
          async all() {
            if (/FROM leads WHERE tenant_id = \?/i.test(sql)) {
              db.selectedTenant = args[0];
              return {
                results: [{
                  id: "lead-a",
                  name: "Alice",
                  company: "Example Ltd",
                  email: "alice@example.com",
                  phone: null,
                  source: "website",
                  requirement: "Need equipment",
                  status: "new",
                  priority: "normal",
                  created_at: "2026-08-17T00:00:00Z",
                }],
              };
            }
            return { results: [] };
          },
          async run() {
            if (/INSERT INTO audit_logs/i.test(sql)) db.auditRows.push(args);
            if (/INSERT INTO leads/i.test(sql)) db.leadInserts.push(args);
            if (/DELETE FROM sessions WHERE id/i.test(sql)) db.sessionDeletes.push(args[0]);
            return { success: true };
          },
        };
      },
    };
  }

  async batch(statements) {
    return statements.map(() => ({ success: true }));
  }
}

function env({ ai = true, db = new FakeDB() } = {}) {
  return {
    DB: db,
    AI: ai ? {
      async run(_model, input) {
        const system = input?.messages?.[0]?.content || "";
        return { response: `Validated response for ${system}` };
      },
    } : undefined,
    ASSETS: { fetch: async () => new Response("asset", { status: 200 }) },
  };
}

function req(path, { method = "GET", body, authenticated = false, cookie } = {}) {
  const headers = new Headers();
  if (cookie) headers.set("Cookie", cookie);
  else if (authenticated) headers.set("Cookie", "zorvian_session=session-1");
  if (body !== undefined) headers.set("content-type", "application/json");
  return new Request(`https://zorvian.test${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : (typeof body === "string" ? body : JSON.stringify(body)),
  });
}

async function data(response) {
  return response.json();
}

test("health reflects required bindings", async () => {
  const ok = await worker.fetch(req("/api/health"), env());
  assert.equal(ok.status, 200);
  assert.equal((await data(ok)).ok, true);

  const missing = await worker.fetch(req("/api/health"), env({ ai: false, db: undefined }));
  assert.equal(missing.status, 503);
  const payload = await data(missing);
  assert.equal(payload.ok, false);
});

test("database-backed APIs report database outages as 503", async () => {
  const response = await worker.fetch(
    req("/api/me", { authenticated: true }),
    { AI: { run() {} }, ASSETS: { fetch: async () => new Response("asset") } },
  );
  assert.equal(response.status, 503);
  assert.equal((await data(response)).error, "database_unavailable");
});

test("valid sessions resolve user and tenant identity", async () => {
  const response = await worker.fetch(req("/api/me", { authenticated: true }), env());
  assert.equal(response.status, 200);
  const payload = await data(response);
  assert.equal(payload.authenticated, true);
  assert.equal(payload.user.id, "user-1");
  assert.equal(payload.tenant.id, "tenant-a");
});

test("unknown sessions do not authenticate", async () => {
  const response = await worker.fetch(req("/api/me", { cookie: "zorvian_session=missing" }), env());
  assert.equal(response.status, 200);
  assert.equal((await data(response)).authenticated, false);
});

test("logout deletes the current server session and expires the cookie", async () => {
  const database = new FakeDB();
  const response = await worker.fetch(
    req("/api/auth/logout", { method: "POST", authenticated: true }),
    env({ db: database }),
  );
  assert.equal(response.status, 200);
  assert.deepEqual(database.sessionDeletes, ["session-1"]);
  assert.match(response.headers.get("set-cookie") || "", /Max-Age=0/);
});

test("registration enforces required identity fields and password length", async () => {
  const response = await worker.fetch(
    req("/api/auth/register", { method: "POST", body: { name: "Alice", email: "alice@example.com", password: "short" } }),
    env(),
  );
  assert.equal(response.status, 400);
});

test("invalid login credentials return 401 without creating a session", async () => {
  const response = await worker.fetch(
    req("/api/auth/login", { method: "POST", body: { email: "missing@example.com", password: "not-a-real-password" } }),
    env(),
  );
  assert.equal(response.status, 401);
});

test("AI routes reject unsupported methods", async () => {
  const response = await worker.fetch(req("/api/ai/social", { authenticated: true }), env());
  assert.equal(response.status, 405);
  assert.equal(response.headers.get("Allow"), "POST");
});

test("JSON API routes return 400 for malformed bodies", async () => {
  for (const path of ["/api/auth/login", "/api/auth/register", "/api/leads", "/api/ai/social"]) {
    const response = await worker.fetch(req(path, { method: "POST", body: "{" , authenticated: true }), env());
    assert.equal(response.status, 400, path);
    assert.equal((await data(response)).error, "invalid_json", path);
  }
});

test("AI endpoints require an authenticated session", async () => {
  const response = await worker.fetch(req("/api/ai/social", { method: "POST", body: { message: "Create a post" } }), env());
  assert.equal(response.status, 401);
  assert.equal((await data(response)).error, "unauthorized");
});

test("all named AI tools are routable when authenticated", async () => {
  const tools = ["social", "marketing", "support", "quotes", "tasks", "intelligence", "command", "ask"];
  for (const tool of tools) {
    const database = new FakeDB();
    const response = await worker.fetch(
      req(`/api/ai/${tool}`, { method: "POST", body: { message: "Test business request" }, authenticated: true }),
      env({ db: database }),
    );
    assert.equal(response.status, 200, tool);
    const payload = await data(response);
    assert.equal(payload.ok, true, tool);
    assert.equal(payload.tool, tool, tool);
    assert.equal(payload.degraded, false, tool);
    assert.equal(database.auditRows.length, 1, `${tool} should be audited`);
  }
});

test("AI tools fail safely when Workers AI is unavailable", async () => {
  for (const tool of ["social", "marketing", "support", "quotes", "tasks", "intelligence", "command", "ask"]) {
    const database = new FakeDB();
    const response = await worker.fetch(
      req(`/api/ai/${tool}`, { method: "POST", body: { message: "Test request" }, authenticated: true }),
      env({ ai: false, db: database }),
    );
    assert.equal(response.status, 200, tool);
    const payload = await data(response);
    assert.equal(payload.ok, true, tool);
    assert.equal(payload.degraded, true, tool);
    assert.match(payload.reply, /temporarily unavailable/i, tool);
    assert.match(payload.reply, /not invented|not claim/i, tool);
    assert.equal(database.auditRows.length, 1, `${tool} fallback should be audited`);
  }
});

test("deterministic core assistants work without Workers AI", async () => {
  const cases = {
    receptionist: "My name is Alice. I need to hire a generator for two days starting Monday in Leeds. My email is alice@example.com.",
    calendar: "Arrange a 30 minute meeting with Alice next Monday at 10am at our Leeds office to discuss renewal. Alice's email is alice@example.com.",
    booking: "Prepare a booking for Alice. She needs to hire a generator for two days starting Monday in Leeds. Her email is alice@example.com.",
    leads: "I'm Alice from Example Ltd. We may need generators for around two weeks. Contact me at alice@example.com.",
  };

  for (const [tool, message] of Object.entries(cases)) {
    const database = new FakeDB();
    const response = await worker.fetch(
      req(`/api/ai/${tool}`, { method: "POST", body: { message }, authenticated: true }),
      env({ ai: false, db: database }),
    );
    assert.equal(response.status, 200, tool);
    const payload = await data(response);
    assert.equal(payload.ok, true, tool);
    assert.equal(payload.structured, true, tool);
    assert.equal(payload.degraded, false, tool);
    assert.ok(payload.reply.length > 80, tool);
    assert.equal(database.auditRows.length, 1, `${tool} should be audited`);
  }
});

test("lead reads are tenant scoped", async () => {
  const database = new FakeDB();
  const response = await worker.fetch(req("/api/leads", { authenticated: true }), env({ db: database }));
  assert.equal(response.status, 200);
  assert.equal(database.selectedTenant, "tenant-a");
  assert.equal((await data(response)).leads.length, 1);
});

test("lead writes bind the authenticated tenant and audit the change", async () => {
  const database = new FakeDB();
  const response = await worker.fetch(
    req("/api/leads", {
      method: "POST",
      authenticated: true,
      body: { name: "Alice", company: "Example Ltd", requirement: "Urgent generator hire" },
    }),
    env({ db: database }),
  );
  assert.equal(response.status, 201);
  assert.equal(database.leadInserts.length, 1);
  assert.equal(database.leadInserts[0][1], "tenant-a");
  assert.equal(database.auditRows.length, 1);
});
