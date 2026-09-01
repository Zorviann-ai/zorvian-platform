import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';

test('password hashing is versioned and uses compatible work factors', async () => {
  const worker = await fs.readFile(new URL('../src/worker.js', import.meta.url), 'utf8');
  const reset = await fs.readFile(new URL('../src/auth-reset.js', import.meta.url), 'utf8');
  assert.match(worker, /PASSWORD_HASH_ITERATIONS = 210000/);
  assert.match(reset, /PASSWORD_HASH_ITERATIONS = 100000/);
  for (const source of [worker, reset]) {
    assert.match(source, /pbkdf2_sha256/);
  }
  assert.match(reset, /pbkdf2_sha256\$\$\{PASSWORD_HASH_ITERATIONS\}\$\$\{salt\}\$/);
  assert.match(worker, /const iterations = Number\(parts\[1\]\)/);
  assert.match(worker, /await hash\(password, parts\[2\], iterations\)/);
  assert.match(worker, /iterations: 10000/);
  assert.match(worker, /secureEqual\(candidate, legacy\)/);
});

test('password reset success offers a secure return to the portal login', async () => {
  const page = await fs.readFile(new URL('../public/reset-password.html', import.meta.url), 'utf8');
  assert.match(page, /id="enterCore"/);
  assert.match(page, /href="\/"/);
  assert.match(page, /ENTER CELESTIAL CORE/);
  assert.match(page, /enterCore\.hidden=false/);
});

test('password reset runtime failures are staged and returned as JSON', async () => {
  const reset = await fs.readFile(new URL('../src/auth-reset.js', import.meta.url), 'utf8');
  assert.match(reset, /let stage = "password_hash"/);
  assert.match(reset, /stage = "password_commit"/);
  assert.match(reset, /error: "password_reset_failed"/);
  assert.match(reset, /console\.error\("Password reset failed", stage, error\)/);
});

test('password reset page can reveal and hide both password fields', async () => {
  const page = await fs.readFile(new URL('../public/reset-password.html', import.meta.url), 'utf8');
  assert.match(page, /id="toggleVisibility"/);
  assert.match(page, /SHOW PASSWORD/);
  assert.match(page, /HIDE PASSWORD/);
  assert.match(page, /confirmPassword\.type=reveal\?'text':'password'/);
});

test('MCP bearer authentication is timing-safe and CORS is allowlisted', async () => {
  const source = await fs.readFile(new URL('../src/mcp.js', import.meta.url), 'utf8');
  assert.match(source, /async function secureEqual/);
  assert.match(source, /await authorized/);
  assert.match(source, /MCP_ALLOWED_ORIGINS/);
  assert.doesNotMatch(source, /access-control-allow-origin': '\*'/);
});

test('production entry adds baseline browser security headers and cookie-write origin checks', async () => {
  const source = await fs.readFile(new URL('../src/platform.js', import.meta.url), 'utf8');
  for (const header of ['x-content-type-options', 'x-frame-options', 'referrer-policy', 'permissions-policy', 'cross-origin-resource-policy']) {
    assert.ok(source.includes(header), header);
  }
  assert.match(source, /cross_site_request_blocked/);
});
