import legacyWorker from "./worker.js";

const AI_MODEL = "@cf/zai-org/glm-4.7-flash";
const JSON_HEADERS = { "content-type": "application/json; charset=UTF-8", "cache-control": "no-store" };

const TOOL_PROMPTS = {
  receptionist: `You are Zorvian AI Receptionist. Read the entire customer enquiry and produce one finished business response.

Return exactly these seven sections and then STOP:
1. Customer need
2. Details already provided
3. Urgency and timing
4. Contact details provided
5. Missing information
6. Recommended next action
7. Human handoff

Rules:
- Use only facts stated in the customer's enquiry.
- Never ask for or label as missing information that is already provided.
- Do not infer urgency from the date alone. If the customer did not use urgent language, say urgency was not explicitly stated.
- Do not invent payment requirements, delivery requirements, policies, pricing, availability, stock, exact site details or other business requirements.
- If availability is requested, say availability must be checked by the business unless a real availability system is connected.
- For missing information, include only information genuinely needed to proceed and not supplied by the customer. If unsure whether something is required, do not list it as missing.
- The customer's original wording is the source of truth.
- Keep the answer concise and professional.
- Do not say "Thanks" or add a preamble.
- Do not continue after section 7. Do not write internal thoughts, drafting notes, "Wait", "I need to", or any self-correction.`,
  calendar: "You are Zorvian AI Calendar Assistant. Turn the request into a practical scheduling plan. Identify date, time, duration, attendees, location, conflicts and missing information. Never claim an appointment was actually created.",
  booking: "You are Zorvian AI Booking Assistant. Prepare the information required for a booking, identify missing requirements and produce a clear confirmation checklist. Never claim availability or a completed booking without a real integration.",
  leads: "You are Zorvian AI Lead Intelligence Assistant. Assess buying intent, urgency, opportunity quality, missing information and the best next sales action. Never invent facts.",
  social: "You are Zorvian AI Social Assistant. Create practical social content ideas, target audience, messaging, calls to action and a simple publishing plan based on the supplied objective.",
  marketing: "You are Zorvian AI Marketing Assistant. Create a practical campaign plan covering objective, audience, offer, messaging, channels, actions and measures. Do not invent performance results.",
  support: "You are Zorvian AI Customer Support Assistant. Draft a helpful response, identify the issue, required information, urgency and escalation path. Never invent company policies or refunds.",
  quotes: "You are Zorvian AI Sales and Quotes Assistant. Structure the customer's requirements, identify missing quote information and prepare a professional sales follow-up. Never invent prices, discounts or availability.",
  tasks: "You are Zorvian AI Task Assistant. Convert the request into priorities, tasks, owners if known, dependencies and deadlines. Do not claim tasks were completed.",
  intelligence: "You are Zorvian Business Intelligence Assistant. Analyse the supplied information, identify key findings, risks, opportunities, priorities and recommended actions. Distinguish facts from assumptions.",
  command: "You are Zorvian business control AI. Interpret the request and return a concise action plan, required systems, risks and next steps. Never claim an external action was executed unless a real integration did it.",
  ask: "You are Zorvian, a concise business AI assistant. Help the user understand, plan and execute business work. Give practical answers and never pretend an external action happened when it did not."
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  const match = header.match(new RegExp(`(?:^|; )${name}=([^;]+)`));
  return match ? match[1] : null;
}

async function getUser(request, env) {
  const sessionId = getCookie(request, "zorvian_session");
  if (!sessionId || !env.DB) return null;
  return env.DB.prepare(
    `SELECT s.id, s.expires_at, u.id AS user_id, u.name, u.email, u.role, u.tenant_id
     FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.id = ? AND s.expires_at > ?`
  ).bind(sessionId, new Date().toISOString()).first();
}

function extractReply(result) {
  const choice = result?.choices?.[0];
  return String(
    result?.response ||
    result?.result?.response ||
    result?.output_text ||
    result?.result?.output_text ||
    result?.text ||
    result?.result?.text ||
    choice?.message?.content ||
    choice?.text ||
    ""
  ).trim();
}

function cleanReply(reply, tool) {
  let text = String(reply || "")
    .replace(/\\n/g, "\n")
    .replace(/\\r/g, "")
    .replace(/\\{2,}/g, "")
    .trim();

  if (tool === "receptionist") {
    text = text.replace(/^Thanks[.!]?\s*/i, "");
    const runaway = text.search(/\n(?:Wait\b|I need to\b|Let me\b|Hold on\b|I should\b)/i);
    if (runaway >= 0) text = text.slice(0, runaway).trim();
  }

  return text;
}

async function runAI(env, tool, message) {
  if (!env.AI || typeof env.AI.run !== "function") {
    return { ok: false, error: "Workers AI binding is not available." };
  }

  const system = TOOL_PROMPTS[tool] || TOOL_PROMPTS.ask;
  const messages = [
    { role: "system", content: system },
    { role: "user", content: message }
  ];

  const generation = {
    messages,
    max_completion_tokens: tool === "receptionist" ? 520 : 700,
    temperature: 0.1,
    top_p: 0.8,
    repetition_penalty: 1.12,
    frequency_penalty: 0.35
  };

  try {
    const result = await env.AI.run(AI_MODEL, generation);
    const reply = cleanReply(extractReply(result), tool);
    if (reply) return { ok: true, reply, degraded: false };
    console.error("Workers AI returned no extractable text", JSON.stringify(result));
  } catch (error) {
    console.error("Workers AI chat inference failed", error);
  }

  try {
    const result = await env.AI.run(AI_MODEL, {
      prompt: `${system}\n\nCustomer/business request:\n${message}`,
      max_tokens: tool === "receptionist" ? 520 : 700,
      temperature: 0.1,
      top_p: 0.8,
      repetition_penalty: 1.12,
      frequency_penalty: 0.35
    });
    const reply = cleanReply(extractReply(result), tool);
    if (reply) return { ok: true, reply, degraded: false };
    console.error("Workers AI prompt call returned no extractable text", JSON.stringify(result));
  } catch (error) {
    console.error("Workers AI prompt inference failed", error);
  }

  return { ok: false, error: "The AI model did not return usable response text." };
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/api/health" && request.method === "GET") {
      const aiConfigured = Boolean(env.AI && typeof env.AI.run === "function");
      const dbConfigured = Boolean(env.DB);
      return json({
        ok: aiConfigured && dbConfigured,
        service: "zorvian-platform",
        aiConfigured,
        dbConfigured,
        aiModel: AI_MODEL,
        time: new Date().toISOString()
      }, aiConfigured && dbConfigured ? 200 : 503);
    }

    if (url.pathname.startsWith("/api/ai/") && request.method === "POST") {
      const user = await getUser(request, env);
      if (!user) return json({ error: "unauthorized" }, 401);

      const requestedTool = url.pathname.slice("/api/ai/".length).replace(/\/$/, "");
      const tool = requestedTool === "enquiry" ? "receptionist" : requestedTool;
      if (!TOOL_PROMPTS[tool]) return json({ error: "unknown_ai_tool" }, 404);

      let body;
      try { body = await request.json(); } catch { return json({ error: "invalid_json" }, 400); }
      const message = String(body.message || body.command || "").trim().slice(0, 8000);
      if (!message) return json({ error: "message_required" }, 400);

      const result = await runAI(env, tool, message);
      if (!result.ok) return json({ ok: false, tool, error: result.error }, 503);
      return json({ ok: true, tool, model: AI_MODEL, reply: result.reply, degraded: false });
    }

    return legacyWorker.fetch(request, env, ctx);
  }
};