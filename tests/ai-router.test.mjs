import test from 'node:test';
import assert from 'node:assert/strict';
import { generateAI, providerStatus } from '../src/ai-router.js';

test('OpenAI Responses is the primary Core provider when its secret exists', async () => {
  const originalFetch = globalThis.fetch;
  let workersCalls = 0;
  globalThis.fetch = async (url, options) => {
    assert.equal(url, 'https://api.openai.com/v1/responses');
    assert.equal(options.headers.authorization, 'Bearer test-secret');
    const body = JSON.parse(options.body);
    assert.equal(body.store, false);
    assert.equal(body.model, 'gpt-5-mini');
    return new Response(JSON.stringify({ model: 'gpt-5-mini', output_text: 'OpenAI Core result' }), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  try {
    const result = await generateAI({ OPENAI_API_KEY: 'test-secret', AI: { run: async () => { workersCalls += 1; return { response: 'fallback' }; } } }, { system: 'system', input: 'input' });
    assert.equal(result.provider, 'openai');
    assert.equal(result.text, 'OpenAI Core result');
    assert.equal(workersCalls, 0);
  } finally { globalThis.fetch = originalFetch; }
});

test('Workers AI safely takes over when OpenAI is unavailable', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(null, { status: 503 });
  try {
    const result = await generateAI({ OPENAI_API_KEY: 'test-secret', AI: { run: async () => ({ response: 'Workers fallback result' }) } }, { system: 'system', input: 'input' });
    assert.equal(result.provider, 'workers_ai');
    assert.equal(result.text, 'Workers fallback result');
  } finally { globalThis.fetch = originalFetch; }
});

test('provider status reports configuration without exposing secrets', () => {
  const status = providerStatus({ OPENAI_API_KEY: 'must-not-leak', OPENAI_MODEL: 'gpt-5-mini', AI: { run() {} } });
  assert.equal(status.openai.configured, true);
  assert.equal(status.workers_ai.configured, true);
  assert.deepEqual(status.priority, ['openai', 'workers_ai']);
  assert.doesNotMatch(JSON.stringify(status), /must-not-leak/);
});
