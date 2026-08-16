const JSON_HEADERS = { "content-type": "application/json; charset=UTF-8" };
const AI_MODEL = "@cf/zai-org/glm-4.7-flash";

const uid = () => crypto.randomUUID();
const now = () => new Date().toISOString();

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...JSON_HEADERS, ...headers },
  });
}

function cookie(name, value, maxAge = 604800) {
  return `${name}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`;
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  const match = header.match(new RegExp(`(?:^|; )${name}=([^;]+)`));
  return match ? match[1] : null;
}

async function hash(password, salt = crypto.randomUUID()) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: new TextEncoder().encode(salt),
      iterations: 10000,
      hash: "SHA-256",
    },
    key,
    256
  );

  return salt + "$" + btoa(String.fromCharCode(...new Uint8Array(bits)));
}

async function verify(password, stored) {
  const [salt] = String(stored || "").split("$");
  if (!salt) return false;
  return (await hash(password, salt)) === stored;
}

async function getUser(request, env) {
  const sessionId = getCookie(request, "zorvian_session");
  if (!sessionId || !env.DB) return null;

  return env.DB.prepare(
    `SELECT
      s.id,
      s.expires_at,
      u.id AS user_id,
      u.name,
      u.email,
      u.role,
      u.tenant_id,
      t.name AS tenant_name,
      t.slug AS tenant_slug,
      t.website_url
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     LEFT JOIN tenants t ON t.id = u.tenant_id
     WHERE s.id = ? AND s.expires_at > ?`
  ).bind(sessionId, now()).first();
}

async function audit(env, user, action, details = {}) {
  if (!env.DB) return;
  await env.DB.prepare(
    `INSERT INTO audit_logs
      (id, tenant_id, user_id, action, details_json)
     VALUES (?, ?, ?, ?, ?)`
  ).bind(
    uid(),
    user?.tenant_id || null,
    user?.user_id || null,
    action,
    JSON.stringify(details)
  ).run();
}

const TOOL_PROMPTS = {
  receptionist: "You are Zorvian AI Receptionist. Qualify the customer's enquiry. Identify the customer's need, urgency, useful contact details, missing information, and the recommended next action. Never invent pricing, availability, bookings, or company policies. If a human needs to act, say exactly what they should do.",
  calendar: "You are Zorvian AI Calendar Assistant. Turn the request into a practical appointment or scheduling plan. Identify date, time, duration, attendees, location, conflicts or missing information. Do not claim that an appointment was actually booked.",
  booking: "You are Zorvian AI Booking Assistant. Prepare the information needed to make a booking, identify missing requirements, and produce a clear confirmation checklist. Never claim availability or a completed booking without a real booking integration.",
  leads: "You are Zorvian AI Lead Intelligence Assistant. Assess buying intent, urgency, opportunity quality, missing information and the best next sales action. Never invent facts.",
  social: "You are Zorvian AI Social Assistant. Create practical social content ideas, target audience, messaging angles, calls to action and a simple publishing plan based on the business objective.",
  marketing: "You are Zorvian AI Marketing Assistant. Turn the request into a practical campaign plan covering objective, audience, offer, messaging, channels, actions and measures. Do not invent performance results.",
  support: "You are Zorvian AI Customer Support Assistant. Draft a helpful customer response, identify the issue, required information, urgency and escalation path. Never invent company policies or refunds.",
  quotes: "You are Zorvian AI Sales and Quotes Assistant. Structure the customer's requirements, identify missing quote information and prepare a professional sales follow-up. Never invent prices, discounts or availability.",
  tasks: "You are Zorvian AI Task Assistant. Convert the request into clear priorities, tasks, owners if known, dependencies and deadlines. Do not claim tasks were completed.",
  intelligence: "You are Zorvian Business Intelligence Assistant. Analyse the supplied information, identify key findings, risks, opportunities, priorities and recommended actions. Distinguish facts from assumptions.",
  command: "You are Zorvian business control AI. Interpret business commands and return a concise action plan, required systems, risks and next steps. Never claim an external action was executed unless a real integration has done it.",
  ask: "You are Zorvian, a concise business AI assistant. Help the user understand, plan and execute business work. Give practical answers, identify missing information and never pretend an external action happened when it did not.",
};

function fallbackReply(tool, message) {
  const names = {
    receptionist: "I can qualify that enquiry, but I need the customer's requirements and any missing contact or timing details before a team member can act on it.",
    calendar: "I can prepare the scheduling plan. Please provide the preferred date, time, duration and attendees if they are not already included.",
    booking: "I can prepare the booking requirements. I will not claim availability or a completed booking until a booking system is connected.",
    leads: "I can assess the lead once the customer requirements, urgency and contact details are available.",
    social: "I can turn that objective into a practical social content plan with audience, messages and calls to action.",
    marketing: "I can turn that into a campaign plan covering audience, offer, messaging, channels and measures.",
    support: "I can prepare a customer response and escalation plan once the issue and required customer details are clear.",
    quotes: "I can structure the quote requirements, but pricing and availability must come from your actual business systems.",
    tasks: "I can turn the request into a prioritised task list with owners, dependencies and deadlines.",
    intelligence: "I can analyse the supplied business information and separate confirmed facts from assumptions.",
    command: "Action understood. I can prepare the plan, but I will not claim that an external system changed until an integration executes it.",
    ask: "I can help plan that business task. Tell me the objective, deadline and any constraints you need me to consider.",
  };
  return names[tool] || `I received your request: ${message.slice(0, 160)}`;
}

async function runAI(env, tool, message, context = {}) {
  const system = TOOL_PROMPTS[tool] || TOOL_PROMPTS.ask;

  if (!env.AI || typeof env.AI.run !== "function") {
    return fallbackReply(tool, message);
  }

  const result = await env.AI.run(AI_MODEL, {
    messages: [
      { role: "system", content: system },
      {
        role: "user",
        content: context && Object.keys(context).length
          ? `${message}\n\nContext:\n${JSON.stringify(context)}`
          : message,
      },
    ],
    max_tokens: 900,
    temperature: 0.25,
  });

  return result?.response || fallbackReply(tool, message);
}

async function handleAI(request, env, tool, user) {
  const body = await request.json();
  const message = String(body.message || body.command || "").trim().slice(0, 8000);

  if (!message) {
    return json({ error: "message_required" }, 400);
  }

  try {
    const reply = await runAI(env, tool, message, body.context || {});
    await audit(env, user, `ai.${tool}`, { tool, message: message.slice(0, 1000) });
    return json({ ok: true, tool, reply });
  } catch (error) {
    console.error("AI request failed", tool, error);
    return json({ error: "ai_unavailable", message: "The AI service could not complete this request. Please try again." }, 503);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      if (url.pathname === "/api/health" && request.method === "GET") {
        return json({
          ok: true,
          service: "zorvian-platform",
          aiConfigured: Boolean(env.AI),
          dbConfigured: Boolean(env.DB),
          time: now(),
        });
      }

      if (url.pathname === "/api/auth/register" && request.method === "POST") {
        if (!env.DB) return json({ error: "database_unavailable" }, 503);
        const body = await request.json();
        const name = String(body.name || "").trim();
        const email = String(body.email || "").trim().toLowerCase();
        const password = String(body.password || "");

        if (!name || !email || password.length < 10) {
          return json({ error: "Name, email and a password of at least 10 characters are required." }, 400);
        }

        const existing = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first();
        if (existing) return json({ error: "Account already exists." }, 409);

        const tenantId = uid();
        const userId = uid();
        const base = (body.business || name).toLowerCase().replace(/[^a-z0-9]+/g, "-").slice(0, 45) || tenantId.slice(0, 8);
        let slug = base;
        if (await env.DB.prepare("SELECT id FROM tenants WHERE slug = ?").bind(slug).first()) slug = `${base}-${tenantId.slice(0, 6)}`;

        await env.DB.batch([
          env.DB.prepare("INSERT INTO tenants (id,name,slug,website_url) VALUES (?,?,?,?)").bind(tenantId, body.business || name, slug, body.website_url || null),
          env.DB.prepare("INSERT INTO users (id,tenant_id,name,email,password_hash,role) VALUES (?,?,?,?,?,?)").bind(userId, tenantId, name, email, await hash(password), "client"),
        ]);

        const sessionId = uid();
        await env.DB.prepare("INSERT INTO sessions (id,user_id,expires_at) VALUES (?,?,?)").bind(sessionId, userId, new Date(Date.now() + 604800000).toISOString()).run();

        return json({ ok: true }, 200, { "Set-Cookie": cookie("zorvian_session", sessionId) });
      }

      if (url.pathname === "/api/auth/login" && request.method === "POST") {
        if (!env.DB) return json({ error: "database_unavailable" }, 503);
        const body = await request.json();
        const email = String(body.email || "").trim().toLowerCase();
        const password = String(body.password || "");
        const user = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
        if (!user || !(await verify(password, user.password_hash))) return json({ error: "Invalid email or password." }, 401);

        const sessionId = uid();
        await env.DB.prepare("INSERT INTO sessions (id,user_id,expires_at) VALUES (?,?,?)").bind(sessionId, user.id, new Date(Date.now() + 604800000).toISOString()).run();
        return json({ ok: true, user: { name: user.name, email: user.email, role: user.role } }, 200, { "Set-Cookie": cookie("zorvian_session", sessionId) });
      }

      if (url.pathname === "/api/auth/logout" && request.method === "POST") {
        const sessionId = getCookie(request, "zorvian_session");
        if (sessionId && env.DB) await env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(sessionId).run();
        return json({ ok: true }, 200, { "Set-Cookie": cookie("zorvian_session", "", 0) });
      }

      const user = await getUser(request, env);

      if (url.pathname === "/api/me" && request.method === "GET") {
        if (!user) return json({ authenticated: false });
        return json({
          authenticated: true,
          user: { id: user.user_id, name: user.name, email: user.email, role: user.role },
          tenant: { id: user.tenant_id, name: user.tenant_name, slug: user.tenant_slug, website_url: user.website_url },
        });
      }

      if (url.pathname.startsWith("/api/ai/")) {
        if (!user) return json({ error: "unauthorized" }, 401);
        const requestedTool = url.pathname.slice("/api/ai/".length).replace(/\/$/, "");
        const tool = requestedTool === "enquiry" ? "receptionist" : requestedTool === "ask" ? "ask" : requestedTool;
        const allowed = new Set(["receptionist","calendar","booking","leads","social","marketing","support","quotes","tasks","intelligence","command","ask"]);
        if (!allowed.has(tool)) return json({ error: "unknown_ai_tool" }, 404);
        return handleAI(request, env, tool, user);
      }

      if (!user) return json({ error: "unauthorized" }, 401);

      if (url.pathname === "/api/leads" && request.method === "GET") {
        const results = await env.DB.prepare(
          `SELECT id,name,company,email,phone,source,requirement,status,priority,created_at
           FROM leads WHERE tenant_id = ? ORDER BY datetime(created_at) DESC LIMIT 100`
        ).bind(user.tenant_id).all();
        return json({ leads: results.results });
      }

      if (url.pathname === "/api/leads" && request.method === "POST") {
        const body = await request.json();
        const leadId = uid();
        const priority = body.priority || (/urgent|today|asap|emergency/i.test(body.requirement || "") ? "urgent" : "normal");
        await env.DB.prepare(
          `INSERT INTO leads (id,tenant_id,name,company,email,phone,source,requirement,priority,metadata_json)
           VALUES (?,?,?,?,?,?,?,?,?,?)`
        ).bind(leadId, user.tenant_id, body.name || null, body.company || null, body.email || null, body.phone || null, body.source || "website", body.requirement || "", priority, JSON.stringify(body.metadata || {})).run();
        await audit(env, user, "lead.created", { leadId });
        return json({ ok: true, id: leadId, priority }, 201);
      }

      return env.ASSETS.fetch(request);
    } catch (error) {
      console.error("Worker request failed", error);
      return json({ error: "server_error" }, 500);
    }
  },
};
