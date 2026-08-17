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

async function secureEqual(left, right) {
  const encoder = new TextEncoder();
  const [leftDigest, rightDigest] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(String(left || ""))),
    crypto.subtle.digest("SHA-256", encoder.encode(String(right || ""))),
  ]);
  const a = new Uint8Array(leftDigest);
  const b = new Uint8Array(rightDigest);
  let difference = 0;
  for (let index = 0; index < a.length; index += 1) difference |= a[index] ^ b[index];
  return difference === 0;
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
  receptionist: `You are Zorvian AI Receptionist. Read the entire customer enquiry carefully and respond to the actual information provided.

Return these sections in this order:
1. Customer need
2. Details already provided
3. Urgency and timing
4. Contact details provided
5. Missing information
6. Recommended next action
7. Human handoff

Rules:
- Never ask for information that is already present in the enquiry.
- Clearly restate the important facts supplied by the customer, including name, company, location, requested service, duration, timing and contact details when provided.
- If a detail is missing, name only that missing detail.
- Do not invent pricing, availability, bookings, company policies or stock.
- If availability is requested, say it must be checked by the business unless a real availability system is connected.
- Make the response specific to this enquiry.
- If a human needs to act, state exactly what they should do next.`,
  calendar: "You are Zorvian AI Calendar Assistant. Turn the request into a practical appointment or scheduling plan. Identify date, time, duration, attendees, location, conflicts or missing information. Do not claim that an appointment was actually booked.",
  booking: "You are Zorvian AI Booking Assistant. Prepare the information needed to make a booking, identify missing requirements, and produce a clear confirmation checklist. Never claim availability or a completed booking without a real booking integration.",
  leads: "You are Zorvian AI Lead Intelligence Assistant. Assess buying intent, urgency, opportunity quality, missing information and the best next sales action. Never invent facts.",
  social: "You are Zorvian AI Social Assistant. Create practical social content ideas, target audience, messaging angles, calls to action and a simple publishing plan based on the business objective.",
  marketing: "You are Zorvian AI Marketing Assistant. Turn the request into a practical campaign plan covering objective, audience, offer, messaging, channels, actions and measures. Do not invent performance results.",
  support: "You are Zorvian AI Customer Support Assistant. Draft a helpful customer response, identify the issue, required information, urgency and escalation path. Never invent company policies or refunds.",
  quotes: "You are Zorvian AI Sales and Quotes Assistant. Structure the customer's requirements, identify missing quote information and prepare a professional sales follow-up. Never invent prices, discounts or availability.",
  tasks: "You are Zorvian AI Task Assistant. Convert the request into clear priorities, tasks, owners if known, dependencies and deadlines. Do not claim tasks were completed.",
  intelligence: "You are Zorvian Business Intelligence Assistant. Analyse the supplied information, identify key findings, risks, opportunities, priorities and recommended actions. Distinguish facts from assumptions.",
  route: `You are Zorvian Route Intelligence Assistant. Prepare a lawful operating plan for taxi or private hire, courier, multi-drop delivery, removals, freight or HGV work. Use only the supplied locations, vehicle limits and timing. Never invent distances, travel times, traffic, tolls, restrictions, road conditions or enforcement positions. State that live navigation, verified speed limits, fixed cameras and officially published enforcement zones require connected current routing data. Never identify, track or predict hidden or live police units or mobile enforcement vehicles, and never help a driver evade enforcement. Return journey profile, proposed stop order, vehicle and time-window risks, driver checklist, customer communications, missing information and next action. Distinguish a suggested plan from a route verified by a live mapping provider.`,
  documents: `You are Zorvian Business Document Studio. Draft polished letters, emails, proposals, tenders, policies, procedures, forms, reports, tables, chart briefs and contract drafts using only confirmed facts. Do not invent names, dates, prices, statistics, clauses, policies, signatures or approvals. Mark missing information with square-bracket placeholders. Put the usable draft first and a short review checklist second. Label contracts and regulated documents Draft for authorised review and require appropriate legal or professional review before issue, reliance or signature. For charts use only supplied values.`,
  command: "You are Zorvian business control AI. Interpret business commands and return a concise action plan, required systems, risks and next steps. Never claim an external action was executed unless a real integration has done it.",
  ask: "You are Zorvian, a concise business AI assistant. Help the user understand, plan and execute business work. Give practical answers, identify missing information and never pretend an external action happened when it did not.",
};

function extractReply(result) {
  return (
    result?.response ||
    result?.result?.response ||
    result?.output_text ||
    result?.result?.output_text ||
    result?.text ||
    result?.result?.text ||
    ""
  );
}

function firstMatch(pattern, text) {
  const match = text.match(pattern);
  return match ? match[1].trim() : "";
}

function receptionistFallback(message) {
  const text = message.replace(/\s+/g, " ").trim();
  const name = firstMatch(/(?:my name is|i am|i'm)\s+([A-Z][A-Za-z' -]{1,60}?)(?:\.|,|\s+i |\s+from |\s+and |\s+i run)/i, text);
  const company = firstMatch(/(?:i run|i own|i work for|from)\s+(?:a\s+)?(.+?)(?:\s+in\s+|\.\s+i need|\.\s+we need|\.\s+i'm|\.\s+we're)/i, text);
  const location = firstMatch(/(?:in|near)\s+([A-Z][A-Za-z -]{2,40})(?:\.|,|\s+i need|\s+and|\s+for)/i, text);
  const phone = firstMatch(/(?:phone|mobile|number|contact me at)\s*(?:is|:)?\s*(0\d[\d\s]{8,14})/i, text).replace(/\s+/g, " ");
  const duration = firstMatch(/(?:for|lasting)\s+(\d+(?:\.\d+)?\s*(?:day|days|week|weeks|hour|hours))/i, text);
  const timing = firstMatch(/(?:starting|from|on)\s+([^,.]+(?:next\s+)?(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday|week|month)[^,.]*)/i, text);
  const service = firstMatch(/(?:need to|want to|looking to)\s+(?:hire|rent|book|buy|arrange|order)\s+(.+?)(?:\s+for\s+\d|\s+starting|\s+on\s+|\.|$)/i, text);
  const need = service || firstMatch(/(?:need to|want to|looking to)\s+(.+?)(?:\.|$)/i, text) || "Customer requirement is present in the enquiry.";
  const hasAvailabilityQuestion = /available|availability|in stock|free/i.test(text);
  const missing = [];
  if (!location) missing.push("exact delivery or job location");
  if (!timing && !/next\s+(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)/i.test(text)) missing.push("confirmed start date/time");
  if (!/email/i.test(text) && !/@/.test(text)) missing.push("email address, if written confirmation is required");

  return [
    "Customer need",
    need,
    "",
    "Details already provided",
    name ? `Customer: ${name}` : "Customer name was not reliably extracted.",
    company ? `Business: ${company}` : "Business name was not reliably extracted.",
    location ? `Location: ${location}` : "Location was not clearly provided.",
    duration ? `Duration: ${duration}` : "Duration was not clearly provided.",
    "The original enquiry contains the full customer wording and remains the source of truth.",
    "",
    "Urgency and timing",
    timing ? `Requested timing: ${timing}` : "Timing needs confirmation.",
    /urgent|asap|immediately|today|emergency/i.test(text) ? "Urgency: high based on the customer's wording." : "Urgency: normal unless the business determines otherwise.",
    "",
    "Contact details provided",
    phone ? `Phone: ${phone}` : "Phone number was not clearly identified.",
    "",
    "Missing information",
    missing.length ? missing.map(item => `- ${item}`).join("\n") : "No obvious essential detail is missing from the supplied enquiry.",
    "",
    "Recommended next action",
    hasAvailabilityQuestion
      ? "Check real equipment/service availability for the requested period, then contact the customer with the result."
      : "Review the captured requirement and confirm any missing booking details before contacting the customer.",
    "",
    "Human handoff",
    "A team member should take over for availability confirmation and any commercial or booking commitment."
  ].join("\n");
}

function genericFallback(tool, message) {
  if (tool === "receptionist") return receptionistFallback(message);
  const labels = {
    calendar: "Calendar preparation",
    booking: "Booking preparation",
    leads: "Lead analysis",
    social: "Social media planning",
    marketing: "Marketing planning",
    support: "Customer support preparation",
    quotes: "Sales and quote preparation",
    tasks: "Task planning",
    intelligence: "Business intelligence analysis",
    command: "Business command planning",
    ask: "Business AI response",
  };
  return `${labels[tool] || "Business analysis"}\n\nThe AI model is temporarily unavailable, so Zorvian has safely retained the request without inventing an answer. Please retry once the AI service is available.`;
}

async function runAI(env, tool, message, context = {}) {
  const system = TOOL_PROMPTS[tool] || TOOL_PROMPTS.ask;
  const userContent = context && Object.keys(context).length
    ? `${message}\n\nContext:\n${JSON.stringify(context)}`
    : message;

  if (!env.AI || typeof env.AI.run !== "function") {
    return { reply: genericFallback(tool, message), degraded: true, reason: "binding_unavailable" };
  }

  let lastError = null;

  try {
    const result = await env.AI.run(AI_MODEL, {
      messages: [
        { role: "system", content: system },
        { role: "user", content: userContent },
      ],
      max_tokens: 900,
      temperature: 0.2,
    });
    const reply = extractReply(result);
    if (reply) return { reply, degraded: false };
    lastError = new Error("Workers AI returned no response text");
  } catch (error) {
    lastError = error;
  }

  try {
    const result = await env.AI.run(AI_MODEL, {
      prompt: `${system}\n\nCustomer/business request:\n${userContent}`,
      max_tokens: 900,
      temperature: 0.2,
    });
    const reply = extractReply(result);
    if (reply) return { reply, degraded: false };
    lastError = new Error("Workers AI prompt call returned no response text");
  } catch (error) {
    lastError = error;
  }

  console.error("AI inference failed; using safe fallback", tool, lastError);
  return { reply: genericFallback(tool, message), degraded: true, reason: "model_unavailable" };
}

async function handleAI(request, env, tool, user) {
  const body = await request.json();
  const message = String(body.message || body.command || "").trim().slice(0, 8000);

  if (!message) {
    return json({ error: "message_required" }, 400);
  }

  const result = await runAI(env, tool, message, body.context || {});

  try {
    await audit(env, user, `ai.${tool}`, { tool, message: message.slice(0, 1000), degraded: result.degraded });
  } catch (auditError) {
    console.error("AI audit logging failed", auditError);
  }

  return json({ ok: true, tool, reply: result.reply, degraded: result.degraded });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      if (url.pathname === "/api/health" && request.method === "GET") {
        const healthUser = await getUser(request, env);
        if (!healthUser) return json({ error: "unauthorized" }, 401);
        const aiConfigured = Boolean(env.AI && typeof env.AI.run === "function");
        const dbConfigured = Boolean(env.DB);
        return json({
          ok: true,
          service: "zorvian-platform",
          aiConfigured,
          dbConfigured,
          aiModel: AI_MODEL,
          time: now(),
        });
      }

      if (url.pathname === "/api/auth/register" && request.method === "POST") {
        if (!env.DB) return json({ error: "database_unavailable" }, 503);
        const body = await request.json();
        const inviteCode = String(body.invite_code || request.headers.get("X-Zorvian-Invite") || "");
        if (!env.REGISTRATION_SECRET || !(await secureEqual(inviteCode, env.REGISTRATION_SECRET))) {
          return json({ error: "registration_by_invitation_only" }, 403);
        }
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
        const allowed = new Set(["receptionist","calendar","booking","leads","social","marketing","support","quotes","tasks","intelligence","route","documents","command","ask"]);
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
