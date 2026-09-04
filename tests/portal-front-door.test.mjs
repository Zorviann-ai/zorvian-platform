import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';

const read = (rel) => fs.readFile(new URL(rel, import.meta.url), 'utf8');

test('preview root is Celeste-first and never serves the legacy dashboard directly', async () => {
  const platform = await read('../src/platform.js');
  const login = await read('../public/portal-login.html');

  assert.match(platform, /url\.pathname==='\/'\|\|url\.pathname==='\/index\.html'/);
  assert.match(platform, /hasValidPortalSession\(request,env\)/);
  assert.match(platform, /Response\.redirect\(new URL\('\/portal\/',url\),302\)/);
  assert.match(platform, /servePortalLogin\(request,env\)/);
  assert.match(login, /continue directly to Celeste/i);
  assert.match(login, /window\.location\.replace\('\/portal\/'\)/);
  assert.doesNotMatch(login, /Business Control dashboard.*tool-grid|tool-grid.*Business Control dashboard/s);
});

test('front-door session check reuses the existing host-only session cookie and D1 sessions table', async () => {
  const platform = await read('../src/platform.js');
  assert.match(platform, /getCookie\(request,'zorvian_session'\)/);
  assert.match(platform, /FROM sessions s JOIN users u ON u\.id=s\.user_id/);
  assert.match(platform, /s\.expires_at>\?/);
  assert.doesNotMatch(platform, /portal\/v1\/session|master key|bypass/i);
});

test('front-door login uses existing auth endpoints then confirms GET /api/me', async () => {
  const login = await read('../public/portal-login.html');
  assert.match(login, /fetch\('\/api\/auth\/login'/);
  assert.match(login, /credentials:'include'/);
  assert.match(login, /fetch\('\/api\/me'/);
  assert.match(login, /session\?\.authenticated!==true/);
  assert.match(login, /window\.location\.replace\('\/portal\/'\)/);
  assert.doesNotMatch(login, /register|activate-owner|execute_once|\/live|\/schedule|\/approval/);
});
