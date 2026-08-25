const OPENAI_ENDPOINT = 'https://api.openai.com/v1/responses';
const DEFAULT_OPENAI_MODEL = 'gpt-5-mini';
const DEFAULT_WORKERS_MODEL = '@cf/zai-org/glm-4.7-flash';

function outputText(result) {
  if (typeof result?.output_text === 'string' && result.output_text.trim()) return result.output_text.trim();
  const parts = [];
  for (const item of result?.output || []) {
    for (const content of item?.content || []) {
      if (content?.type === 'output_text' && typeof content.text === 'string') parts.push(content.text);
    }
  }
  return parts.join('\n').trim();
}

function workersText(result) {
  const choice = result?.choices?.[0];
  return String(result?.response || result?.result?.response || result?.output_text || result?.text || choice?.message?.content || choice?.text || '').trim();
}

export function providerStatus(env) {
  return {
    openai: { configured: Boolean(env.OPENAI_API_KEY), model: env.OPENAI_MODEL || DEFAULT_OPENAI_MODEL },
    workers_ai: { configured: Boolean(env.AI && typeof env.AI.run === 'function'), model: DEFAULT_WORKERS_MODEL },
    priority: env.OPENAI_API_KEY ? ['openai', 'workers_ai'] : ['workers_ai']
  };
}

async function runOpenAI(env, system, input, maxOutputTokens) {
  const response = await fetch(OPENAI_ENDPOINT, {
    method: 'POST',
    headers: { authorization: `Bearer ${env.OPENAI_API_KEY}`, 'content-type': 'application/json' },
    body: JSON.stringify({
      model: env.OPENAI_MODEL || DEFAULT_OPENAI_MODEL,
      instructions: system,
      input,
      max_output_tokens: maxOutputTokens,
      store: false
    })
  });
  if (!response.ok) throw new Error(`openai_http_${response.status}`);
  const result = await response.json();
  const text = outputText(result);
  if (!text) throw new Error('openai_empty_response');
  return { text, provider: 'openai', model: result.model || env.OPENAI_MODEL || DEFAULT_OPENAI_MODEL };
}

async function runWorkersAI(env, system, input, maxOutputTokens, temperature) {
  const result = await env.AI.run(DEFAULT_WORKERS_MODEL, {
    messages: [{ role: 'system', content: system }, { role: 'user', content: input }],
    max_completion_tokens: maxOutputTokens,
    temperature
  });
  const text = workersText(result);
  if (!text) throw new Error('workers_ai_empty_response');
  return { text, provider: 'workers_ai', model: DEFAULT_WORKERS_MODEL };
}

export async function generateAI(env, { system, input, maxOutputTokens = 900, temperature = 0.2 }) {
  const failures = [];
  if (env.OPENAI_API_KEY) {
    try { return await runOpenAI(env, system, input, maxOutputTokens); }
    catch (error) {
      failures.push(String(error?.message || error));
      console.error(JSON.stringify({ event: 'ai_provider_failed', provider: 'openai', error: failures.at(-1) }));
    }
  }
  if (env.AI && typeof env.AI.run === 'function') {
    try { return await runWorkersAI(env, system, input, maxOutputTokens, temperature); }
    catch (error) {
      failures.push(String(error?.message || error));
      console.error(JSON.stringify({ event: 'ai_provider_failed', provider: 'workers_ai', error: failures.at(-1) }));
    }
  }
  throw new Error(failures.length ? 'all_ai_providers_failed' : 'ai_not_configured');
}
