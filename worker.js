const MODEL = "@cf/meta/llama-3.1-8b-instruct-fast";

const SYSTEM_PROMPT = `
You are Zorvian AI, a professional business operations assistant.

Your job is to help a business owner handle enquiries, appointments,
bookings, leads, marketing, customer support, quotes, sales and tasks.

Be concise, practical and commercially useful.

Never invent:
- prices
- availability
- appointments
- customer information
- stock
- delivery dates
- payment status
- calendar events
- integrations

If information is missing, clearly say what is missing.

When a human needs to make a decision or perform an action that the
system cannot actually perform, say so clearly and recommend the next step.

Do not claim that an action was completed unless the system actually
completed it.

Use headings and bullet points where useful.
`;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store"
    }
  });
}

function corsHeaders() {
  return {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "Content-Type"
  };
}

function responseJson(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...corsHeaders()
    }
  });
}

async function readBody(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

function clean(value, max = 8000) {
  return String(value ?? "").trim().slice(0, max);
}

async function askAI(env, message, context = "") {
  if (!env.AI || typeof env.AI.run !== "function") {
    throw new Error(
      "Workers AI is not available. Check that the AI binding is deployed."
    );
  }

  const userMessage = context
    ? `${context}\n\nCustomer/business information:\n${message}`
    : message;

  const result = await env.AI.run(MODEL, {
    messages: [
      {
        role: "system",
        content: SYSTEM_PROMPT
      },
      {
        role: "user",
        content: userMessage
      }
    ],
    max_tokens: 900,
    temperature: 0.35
  });

  return (
    result?.response ||
    result?.result?.response ||
    "No response was returned by the AI service."
  );
}

const TOOL_CONTEXT = {
  receptionist: `
You are operating as an AI receptionist.

Qualify the enquiry.
Identify:
1. Customer need
2. Urgency
3. Important details already provided
4. Missing information
5. Recommended next step
6. Whether a human should take over

Do not claim availability or pricing unless it was explicitly provided.
`,

  calendar: `
You are operating as an AI calendar assistant.

Determine:
1. What appointment or meeting is being requested
2. Date and time information
3. Duration
4. Attendees
5. Location or meeting method
6. Missing information
7. Suggested calendar entry
8. Recommended next step

Do not claim that an appointment has actually been created.
`,

  booking: `
You are operating as an AI booking assistant.

Determine:
1. What the customer wants to book
2. Requested date
3. Requested time
4. Duration
5. Location
6. Customer contact information
7. Special requirements
8. Missing information
9. Whether a human needs to confirm availability

Do not claim that a booking exists unless the system actually created one.
`,

  leads: `
You are operating as an AI sales lead assistant.

Assess:
1. Lead quality
2. Customer requirement
3. Buying intent
4. Urgency
5. Estimated opportunity
6. Missing information
7. Recommended follow-up
8. Suggested CRM notes
`,

  social: `
You are operating as an AI social media manager.

Create practical social media content.
Include:
- suggested post
- platform
- audience
- objective
- call to action
- suggested publishing timing

Do not claim that anything has actually been published.
`,

  marketing: `
You are operating as an AI marketing manager.

Create a practical campaign plan covering:
- objective
- audience
- offer
- campaign message
- channels
- content ideas
- call to action
- measurement
- next actions

Do not claim that campaigns have actually been launched.
`,

  support: `
You are operating as an AI customer support assistant.

Prepare a professional response.
Identify:
- issue
- customer sentiment
- urgency
- information needed
- recommended response
- whether human escalation is appropriate
`,

  quotes: `
You are operating as an AI quotes and sales assistant.

Prepare a quote or sales follow-up structure.
Identify:
- requested product/service
- quantities
- dates
- location
- customer requirement
- information required before pricing
- suggested sales follow-up

Never invent pricing.
`,

  tasks: `
You are operating as an AI operations assistant.

Turn the request into an actionable task plan.
Identify:
- priority
- owner
- deadline
- dependencies
- individual actions
- recommended next step
`,

  intelligence: `
You are operating as an AI business intelligence assistant.

Analyse the information provided.
Return:
- key facts
- important risks
- opportunities
- priorities
- recommended actions
- questions that need answering
`
};

async function handleAI(request, env, tool) {
  const body = await readBody(request);

  const message = clean(
    body.message ||
    body.command ||
    body.prompt ||
    body.enquiry
  );

  if (!message) {
    return responseJson(
      { error: "Please enter a message." },
      400
    );
  }

  const context =
    TOOL_CONTEXT[tool] ||
    `
You are Zorvian's general business AI assistant.

Understand the request and provide the most useful practical business
response possible.
`;

  try {
    const reply = await askAI(env, message, context);

    return responseJson({
      ok: true,
      tool,
      model: MODEL,
      reply
    });
  } catch (error) {
    console.error("AI error:", error);

    return responseJson(
      {
        ok: false,
        error:
          error?.message ||
          "The AI service could not process this request."
      },
      500
    );
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders()
      });
    }

    /*
     * Health endpoint.
     *
     * This is deliberately simple.
     * It gives us an objective answer as to whether the deployed Worker
     * actually has the AI binding.
     */
    if (url.pathname === "/api/health") {
      const aiAvailable =
        !!env.AI &&
        typeof env.AI.run === "function";

      return responseJson({
        ok: aiAvailable,
        service: "Zorvian AI",
        worker: "zorvian-platform",
        ai: aiAvailable,
        model: MODEL,
        timestamp: new Date().toISOString()
      });
    }

    if (url.pathname === "/api/ai/ask" && request.method === "POST") {
      return handleAI(request, env, "general");
    }

    if (
      url.pathname === "/api/ai/enquiry" &&
      request.method === "POST"
    ) {
      return handleAI(request, env, "receptionist");
    }

    if (
      url.pathname === "/api/ai/receptionist" &&
      request.method === "POST"
    ) {
      return handleAI(request, env, "receptionist");
    }

    if (
      url.pathname === "/api/ai/calendar" &&
      request.method === "POST"
    ) {
      return handleAI(request, env, "calendar");
    }

    if (
      url.pathname === "/api/ai/booking" &&
      request.method === "POST"
    ) {
      return handleAI(request, env, "booking");
    }

    if (
      url.pathname === "/api/ai/leads" &&
      request.method === "POST"
    ) {
      return handleAI(request, env, "leads");
    }

    if (
      url.pathname === "/api/ai/social" &&
      request.method === "POST"
    ) {
      return handleAI(request, env, "social");
    }

    if (
      url.pathname === "/api/ai/marketing" &&
      request.method === "POST"
    ) {
      return handleAI(request, env, "marketing");
    }

    if (
      url.pathname === "/api/ai/support" &&
      request.method === "POST"
    ) {
      return handleAI(request, env, "support");
    }

    if (
      url.pathname === "/api/ai/quotes" &&
      request.method === "POST"
    ) {
      return handleAI(request, env, "quotes");
    }

    if (
      url.pathname === "/api/ai/tasks" &&
      request.method === "POST"
    ) {
      return handleAI(request, env, "tasks");
    }

    if (
      url.pathname === "/api/ai/intelligence" &&
      request.method === "POST"
    ) {
      return handleAI(request, env, "intelligence");
    }

    if (
      url.pathname === "/api/ai/command" &&
      request.method === "POST"
    ) {
      return handleAI(request, env, "general");
    }

    /*
     * API requests that weren't recognised.
     */
    if (url.pathname.startsWith("/api/")) {
      return responseJson(
        {
          ok: false,
          error: "API endpoint not found."
        },
        404
      );
    }

    /*
     * Static website.
     */
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response(
      "Zorvian AI is running, but the static asset binding is unavailable.",
      {
        status: 500,
        headers: {
          "content-type": "text/plain; charset=utf-8"
        }
      }
    );
  }
};
