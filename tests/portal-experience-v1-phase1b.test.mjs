import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';

const read = (rel) => fs.readFile(new URL(rel, import.meta.url), 'utf8');

test('portal reuses GET /api/me and does not invent authentication', async () => {
  const app = await read('../public/portal/js/app.js');
  const worker = await read('../src/worker.js');
  assert.match(app, /fetch\("\/api\/me"/);
  assert.match(app, /credentials:\s*"include"/);
  assert.match(app, /window\.location\.replace\("\/"\)/);
  assert.doesNotMatch(app, /\/api\/auth\/login/);
  assert.doesNotMatch(app, /\/api\/auth\/register/);
  assert.doesNotMatch(app, /\/portal\/v1\//);
  assert.match(worker, /pathname === "\/api\/me"/);
  assert.match(worker, /zorvian_session/);
  assert.match(worker, /authenticated: true/);
});

test('authenticated Social advisory uses POST /api/ai/social only', async () => {
  const app = await read('../public/portal/js/app.js');
  const entry = await read('../src/entry.js');
  assert.match(app, /fetch\("\/api\/ai\/social"/);
  assert.match(app, /method:\s*"POST"/);
  assert.match(app, /JSON\.stringify\(\{\s*message:/);
  assert.match(entry, /url\.pathname\.startsWith\("\/api\/ai\/"\)/);
  assert.match(entry, /const user=await getUser/);
  assert.match(entry, /if\(!user\)return json\(\{error:"unauthorized"\},401\)/);
  assert.match(entry, /social:/);
});

test('portal Social path does not call publish, schedule, approval or execution', async () => {
  const app = await read('../public/portal/js/app.js');
  for (const banned of [
    '/api/social/generate',
    '/api/social/items',
    '/approval',
    '/schedule',
    '/api/social/analytics',
    'execute_once',
    '/live',
    'submit_production_pilot',
    'submit_live',
    '/api/core/run',
    'HEYGEN',
    'ELEVENLABS'
  ]) {
    assert.equal(app.includes(banned), false, banned);
  }
});

test('presentation host catalog cannot alter role or tenant', async () => {
  const hosts = await read('../public/portal/js/hosts.js');
  assert.match(hosts, /layer:\s*"presentation"/);
  assert.match(hosts, /id:\s*"celeste"/);
  assert.match(hosts, /id:\s*"cassian"/);
  assert.match(hosts, /id:\s*"lin"/);
  assert.doesNotMatch(hosts, /\brole\b/);
  assert.doesNotMatch(hosts, /tenant/);
  assert.doesNotMatch(hosts, /permission/);
  assert.doesNotMatch(hosts, /execute_once/);
});

test('returned advisory reply is rendered into the Social workspace', async () => {
  const app = await read('../public/portal/js/app.js');
  assert.match(app, /openSocialAdvisory/);
  assert.match(app, /passagesFromReply/);
  assert.match(app, /workspaceBody\.innerHTML/);
  assert.match(app, /workspaceTitle\.textContent = "Social Media"/);
  assert.match(app, /document\.body\.classList\.add\("is-open"\)/);
});

test('failed or unknown session cannot POST /api/ai/social', async () => {
  const app = await read('../public/portal/js/app.js');
  assert.match(app, /sessionState !== "verified"/);
  assert.match(app, /if \(sessionState !== "verified" \|\| !sessionUser\) return null;/);
  assert.match(app, /I can’t verify your CAELOMERE session just now/);
  assert.match(app, /gateComposer\(false\)/);
  const socialFetchIndex = app.indexOf('fetch("/api/ai/social"');
  const guardIndex = app.indexOf('if (sessionState !== "verified" || !sessionUser) return null;');
  assert.ok(guardIndex !== -1 && socialFetchIndex !== -1 && guardIndex < socialFetchIndex);
});

test('unknown session keeps text input and Send usable for retry', async () => {
  const app = await read('../public/portal/js/app.js');
  const html = await read('../public/portal/index.html');
  assert.match(html, /id="requestInput"/);
  assert.match(html, /class="send" type="submit"/);
  assert.match(app, /function gateComposer\(verified\)/);
  assert.match(app, /input\.disabled = false;/);
  assert.doesNotMatch(app, /input\.disabled = !verified/);
  assert.match(app, /voiceBtn\.toggleAttribute\("disabled", !verified\)/);
});

test('retry re-runs GET /api/me before any Social advisory request', async () => {
  const app = await read('../public/portal/js/app.js');
  assert.match(app, /async function handleRequest/);
  assert.match(app, /if \(sessionState !== "verified"\) \{\s*const session = await loadSession\(\);/s);
  assert.match(app, /window\.location\.replace\("\/"\)/);
  assert.match(app, /sessionState = "verified"/);
  assert.match(app, /sessionState = "unknown"/);
  assert.match(app, /sessionState = "unauthenticated"/);
});

test('Portal Experience v1 visual baseline remains present', async () => {
  const html = await read('../public/portal/index.html');
  const css = await read('../public/portal/css/styles.css');
  assert.match(html, /CAELOMERE/);
  assert.match(html, /id="hostPortrait"/);
  assert.match(html, /id="requestInput"/);
  assert.match(html, /id="voiceBtn"/);
  assert.match(html, /Private environment/);
  assert.match(css, /prefers-reduced-motion:\s*reduce/);
  assert.match(css, /\.fascia/);
  assert.match(css, /\.celeste__portrait/);
});
