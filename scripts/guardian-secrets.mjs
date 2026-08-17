import { readdir, readFile, stat } from 'node:fs/promises';
import { join, relative } from 'node:path';

const root = process.cwd();
const ignoredDirs = new Set(['.git', 'node_modules', '.wrangler', '.guardian', 'dist', 'coverage']);
const ignoredFiles = new Set(['package-lock.json']);
const maxBytes = 1024 * 1024;

const rules = [
  ['Private key material', /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/],
  ['AWS access key', /\bAKIA[0-9A-Z]{16}\b/],
  ['GitHub token', /\bgh[pousr]_[A-Za-z0-9_]{20,255}\b/],
  ['Slack token', /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/],
  ['Stripe live secret', /\bsk_live_[A-Za-z0-9]{16,}\b/],
  ['Generic high-risk secret assignment', /\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*["'][A-Za-z0-9_\-\/+=.]{20,}["']/i],
];

async function walk(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  const out = [];
  for (const entry of entries) {
    if (ignoredDirs.has(entry.name)) continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...await walk(full));
    else if (entry.isFile() && !ignoredFiles.has(entry.name)) out.push(full);
  }
  return out;
}

const findings = [];
for (const file of await walk(root)) {
  const info = await stat(file);
  if (info.size > maxBytes) continue;
  let text;
  try { text = await readFile(file, 'utf8'); } catch { continue; }
  if (text.includes('\u0000')) continue;
  for (const [name, pattern] of rules) {
    if (pattern.test(text)) findings.push(`${relative(root, file)}: ${name}`);
  }
}

if (findings.length) {
  console.error('Guardian secret scan blocked the change:');
  for (const finding of findings) console.error(`- ${finding}`);
  process.exit(1);
}

console.log('Guardian secret scan passed.');
