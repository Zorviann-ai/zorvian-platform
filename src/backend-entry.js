import coreWorker from "./entry.js";

const JSON_HEADERS = {
  "content-type": "application/json; charset=UTF-8",
  "cache-control": "no-store",
};

const AI_TOOLS = new Set([
  "receptionist", "calendar", "booking", "leads", "social", "marketing",
  "support", "quotes", "tasks", "intelligence", "command", "ask",
]);

const FALLBACK_LABELS = {
  social: "Social media planning",
  marketing: "Marketing planning",
  support: "Customer support preparation",
  quotes: "Sales and quote preparation",
  tasks: "Task planning",
  intelligence: "Business intelligence analysis",
  command: "Business command planning",
  ask: "Business AI response",
};

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...JSON_HEADERS, ...headers },
  });
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  const match = header.match(new RegExp(`(?:^|; )${name}=([^;]+)`));
  return match ? match[1] : null;
}

async function sessionUser(request, env) {
  const sessionId = getCookie(request, "zorvian_session");
  if (!sessionId || !env.DB) return null;
  return env.DB.prepare(
    `SELECT u.id AS user_id,u.tenant_id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=? AND s.expires_at>?`
  ).bind(sessionId, new Date().toISOString()).first();
}

async function auditAI(request, env, tool, response) {
  if (!env.DB || response.status !== 200) return;
  try {
    const user = await sessionUser(request, env);
    if (!user) return;
    const payload = await response.clone().json();
    await env.DB.prepare(
      `INSERT INTO audit_logs (id,tenant_id,user_id,action,details_json) VALUES (?,?,?,?,?)`
    ).bind(
      crypto.randomUUID(),
      user.tenant_id || null,
      user.user_id || null,
      `ai.${tool}`,
      JSON.stringify({ tool, degraded: Boolean(payload?.degraded) })
    ).run();
  } catch (error) {
    console.error("Backend AI audit logging failed", error);
  }
}

function safeFallback(tool) {
  const label = FALLBACK_LABELS[tool] || "Business analysis";
  return `${label}\n\nThe AI model is temporarily unavailable. Zorvian has not invented an answer or claimed that any external action occurred. Please retry when the AI service is available.`;
}

function needsDatabase(pathname) {
  return pathname === "/api/auth/register" ||
    pathname === "/api/auth/login" ||
    pathname === "/api/me" ||
    pathname === "/api/leads" ||
    pathname.startsWith("/api/ai/");
}

function expectsJsonBody(pathname, method) {
  if (method !== "POST") return false;
  return pathname === "/api/auth/register" ||
    pathname === "/api/auth/login" ||
    pathname === "/api/leads" ||
    pathname.startsWith("/api/ai/");
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/ai/") && request.method !== "POST") {
      return json({ error: "method_not_allowed" }, 405, { Allow: "POST" });
    }

    if (needsDatabase(url.pathname) && !env.DB) {
      return json({ error: "database_unavailable" }, 503);
    }

    if (expectsJsonBody(url.pathname, request.method)) {
      try {
        await request.clone().json();
      } catch {
        return json({ error: "invalid_json" }, 400);
      }
    }

    const response = await coreWorker.fetch(request, env, ctx);

    if (url.pathname.startsWith("/api/ai/") && request.method === "POST") {
      const requested = url.pathname.slice("/api/ai/".length).replace(/\/$/, "");
      const tool = requested === "enquiry" ? "receptionist" : requested;

      if (AI_TOOLS.has(tool) && response.status === 503 && FALLBACK_LABELS[tool]) {
        const fallback = json({
          ok: true,
          tool,
          reply: safeFallback(tool),
          degraded: true,
          structured: false,
        });
        await auditAI(request, env, tool, fallback);
        return fallback;
      }

      if (AI_TOOLS.has(tool)) await auditAI(request, env, tool, response);
    }

    return response;
  },
};
