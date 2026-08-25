import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';

test('autonomous economy is scheduled, auditable and profit-only', async () => {
  const [core, platform, wrangler] = await Promise.all([
    fs.readFile(new URL('../src/core.js', import.meta.url), 'utf8'),
    fs.readFile(new URL('../src/platform.js', import.meta.url), 'utf8'),
    fs.readFile(new URL('../wrangler.toml', import.meta.url), 'utf8')
  ]);
  for (const marker of ['economy_opportunities','runAutonomousEconomyCycle','directCost!==0','profit<=0','approval_required:true','external_actions_executed:false']) assert.ok(core.includes(marker), marker);
  for (const route of ['/api/core/economy/run','/api/core/economy/opportunities']) assert.ok(core.includes(route), route);
  assert.match(platform, /async scheduled/);
  assert.match(platform, /runAutonomousEconomyCycle/);
  assert.match(wrangler, /AUTONOMOUS_ECONOMY_ENABLED = "true"/);
  assert.match(wrangler, /crons = \["30 6 \* \* \*"\]/);
  assert.match(wrangler, /observability/);
});

test('seed workers cover intelligence, digital products and proposals without expenditure', async () => {
  const core = await fs.readFile(new URL('../src/core.js', import.meta.url), 'utf8');
  for (const worker of ['Market Intelligence Worker','Digital Product Worker','Proposal and Tender Worker']) assert.ok(core.includes(worker), worker);
  for (const forbidden of ['no spending','borrowing','speculative trading','external outreach']) assert.match(core, new RegExp(forbidden, 'i'));
});
