import { mkdir, readFile, writeFile } from 'node:fs/promises';

const sourcePaths = ['src/worker.js', 'src/entry.js'];
const sources = [];
for (const path of sourcePaths) {
  try {
    sources.push({ path, text: await readFile(path, 'utf8') });
  } catch {
    // A branch may legitimately not contain every source path.
  }
}

if (!sources.length) throw new Error('Guardian could not find application source files.');

const combined = sources.map((item) => item.text).join('\n');
const detected = {
  cookieHelper: /HttpOnly;\s*Secure;\s*SameSite=Lax/.test(combined),
  pbkdf2: /PBKDF2/.test(combined),
  minimumPassword: /password\.length\s*<\s*10/.test(combined),
  authLookup: /getUser\(request,\s*env\)/.test(combined),
  aiAuthGuard: /pathname\.startsWith\(["']\/api\/ai\/["']\)[\s\S]{0,700}!user/.test(combined),
  parameterBinding: /\.bind\(/.test(combined),
  safeServerError: /server_error/.test(combined),
};

const expectations = [
  ['Session cookies are HttpOnly, Secure and SameSite=Lax', 'cookieHelper'],
  ['Passwords are derived with PBKDF2', 'pbkdf2'],
  ['Registration enforces a minimum password length', 'minimumPassword'],
  ['Authenticated users are resolved from server-side sessions', 'authLookup'],
  ['AI API routes contain an authentication guard', 'aiAuthGuard'],
  ['Database operations use parameter binding', 'parameterBinding'],
  ['Unhandled errors return a generic server error', 'safeServerError'],
];

const generated = `import test from 'node:test';\nimport assert from 'node:assert/strict';\n\nconst detected = ${JSON.stringify(detected, null, 2)};\n\n${expectations.map(([name, key]) => `test(${JSON.stringify(name)}, () => { assert.equal(detected.${key}, true); });`).join('\n')}\n`;

await mkdir('.guardian', { recursive: true });
await writeFile('.guardian/security.generated.test.mjs', generated);

const failed = expectations.filter(([, key]) => !detected[key]).map(([name]) => name);
console.log(`Guardian generated ${expectations.length} security invariants from ${sources.length} source file(s).`);
if (failed.length) console.log(`Potential gaps detected: ${failed.join('; ')}`);
